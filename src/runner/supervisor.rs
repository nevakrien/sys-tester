use crate::graph::DirectedGraph;
use crate::index::IndexVec;
use foldhash::{HashMap, HashMapExt};
use std::collections::hash_map::Entry;
use std::io;
use std::mem;

use super::{AtomReq, ChildFile, ProcFileSpace, RunnerError, RunnerFault, ptrace};
use crate::CompiledSetup;
use crate::buffer::{PageBuffer, ProcessCopyError};
use std::os::fd::RawFd;

const CLONE_ARGS_SIZE_VER0: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessCreationOutcome {
    Created(libc::pid_t),
    /// The kernel rejected the process-creation syscall with this positive errno.
    Failed(libc::c_int),
    /// The supervisor rejected the process-creation syscall with this positive errno.
    Rejected(libc::c_int),
}

#[derive(Debug)]
enum ProcessCreationFlags {
    Flags(u64),
    Invalid(libc::c_int),
}

pub struct Supervisor<PF: ProcFileSpace> {
    pub buffer: PageBuffer,
    procs: HashMap<libc::pid_t, PF>,

    ready_atoms: HashMap<AtomReq, Vec<u32>>,
    wait_counts: IndexVec<u32, u32>, //MAX for already done
    info: CompiledSetup,
}

impl<PF: ProcFileSpace> Supervisor<PF> {
    pub fn new(info: CompiledSetup) -> Self {
        let mut ready_atoms: HashMap<_, Vec<_>> = HashMap::with_capacity(1024);
        let mut wait_counts = IndexVec::with_capacity(info.atoms.len());

        for id in 0..info.atoms.len() {
            let edges = info.before_graph.full_edges(id as u32);
            wait_counts.push(edges.len() as u32);

            if edges.len() != 0 {
                continue;
            }

            let Some(req) = AtomReq::new(&info.atoms[id].data) else {
                todo!("handle logs")
            };
            ready_atoms.entry(req).or_default().push(id as u32);
        }

        Self {
            buffer: PageBuffer::new(),
            procs: HashMap::with_capacity(1024),
            ready_atoms,
            wait_counts,
            info,
        }
    }

    pub fn mark_done(&mut self, id: u32) {
        for x in self.info.after_graph.edges(id) {
            debug_assert!(self.wait_counts[x] > 0);

            self.wait_counts[x] -= 1;
            if self.wait_counts[x] == 0 {
                let Some(req) = AtomReq::new(&self.info.atoms[x as usize].data) else {
                    todo!("handle logs")
                };
                self.ready_atoms.entry(req).or_default().push(x);
            }
        }

        self.wait_counts[id] = u32::MAX;
    }

    pub fn iter_undone(&self) -> impl Iterator<Item = u32> {
        self.wait_counts
            .iter()
            .enumerate()
            .filter_map(|(i, c)| if *c != u32::MAX { Some(i as u32) } else { None })
    }

    pub fn lookup_fd(&self, pid: libc::pid_t, fd: RawFd) -> Option<ChildFile> {
        self.procs.get(&pid)?.lookup_fd(fd)
    }

    pub fn register_process(&mut self, pid: libc::pid_t, files: PF) -> Result<(), RunnerError> {
        match self.procs.entry(pid) {
            Entry::Occupied(_) => Err(RunnerFault::ProcessAlreadyTracked(pid).into()),
            Entry::Vacant(entry) => {
                entry.insert(files);
                Ok(())
            }
        }
    }

    pub fn contains_process(&self, pid: libc::pid_t) -> bool {
        self.procs.contains_key(&pid)
    }

    /// Handle the next ptrace-intercepted fork, vfork, clone, or clone3 call.
    ///
    /// File-table sharing is rejected because each tracked process currently
    /// owns an independent `ProcFileSpace` snapshot.
    pub fn handle_process_creation(
        &mut self,
        pid: libc::pid_t,
    ) -> Result<ProcessCreationOutcome, RunnerError> {
        if !self.procs.contains_key(&pid) {
            return Err(RunnerFault::ProcessNotTracked(pid).into());
        }
        let stop = ptrace::wait_for_process_creation(pid)?;
        self.handle_process_creation_stop(stop)
    }

    /// Handle a pending process-creation ptrace stop without blocking for one.
    ///
    /// Event loops should use this method while also polling the seccomp
    /// listener so an earlier `USER_NOTIF` call cannot block the tracee before
    /// it reaches process creation.
    pub fn try_handle_process_creation(
        &mut self,
        pid: libc::pid_t,
    ) -> Result<Option<ProcessCreationOutcome>, RunnerError> {
        if !self.procs.contains_key(&pid) {
            return Err(RunnerFault::ProcessNotTracked(pid).into());
        }
        let Some(stop) = ptrace::try_wait_for_process_creation(pid)? else {
            return Ok(None);
        };
        self.handle_process_creation_stop(stop).map(Some)
    }

    fn handle_process_creation_stop(
        &mut self,
        stop: ptrace::ProcessCreationStop,
    ) -> Result<ProcessCreationOutcome, RunnerError> {
        let pid = stop.parent;
        let child_files = self
            .procs
            .get(&pid)
            .cloned()
            .ok_or(RunnerFault::ProcessNotTracked(pid))?;
        let flags = match self.process_creation_flags(&stop)? {
            ProcessCreationFlags::Flags(flags) => flags,
            ProcessCreationFlags::Invalid(error) => {
                ptrace::reject_process_creation(stop, error)?;
                return Ok(ProcessCreationOutcome::Rejected(error));
            }
        };
        if flags & libc::CLONE_FILES as u64 != 0 {
            ptrace::reject_process_creation(stop, libc::ENOTSUP)?;
            return Ok(ProcessCreationOutcome::Rejected(libc::ENOTSUP));
        }

        let parent_files = self
            .procs
            .get(&pid)
            .ok_or(RunnerFault::ProcessNotTracked(pid))?;
        let stop = match ptrace::continue_to_fork(stop, parent_files)? {
            ptrace::ProcessCreationResult::Created(stop) => stop,
            ptrace::ProcessCreationResult::Failed(error) => {
                return Ok(ProcessCreationOutcome::Failed(error));
            }
        };
        let child = stop.child;
        if let Err(error) = self.register_process(child, child_files) {
            let _ = ptrace::resume_fork(stop);
            return Err(error);
        }
        ptrace::resume_fork(stop)?;
        Ok(ProcessCreationOutcome::Created(child))
    }

    /// Reap one process-wide child exit without consuming ptrace fork stops.
    /// The returned PID is not necessarily present in this supervisor's table.
    pub fn reap_exited(&mut self) -> io::Result<Option<libc::pid_t>> {
        if let Some(pid) = ptrace::reap_exited()? {
            self.procs.remove(&pid);
            Ok(Some(pid))
        } else {
            Ok(None)
        }
    }

    pub fn get_task(&mut self, r: &AtomReq) -> Option<(u32, usize)> {
        let r = self.ready_atoms.get_mut(r)?;
        let total = r.len();
        //maybe first mix? problem for another day.
        Some((r.pop()?, total))
    }

    fn process_creation_flags(
        &mut self,
        stop: &ptrace::ProcessCreationStop,
    ) -> Result<ProcessCreationFlags, RunnerError> {
        let syscall = stop.syscall;
        if syscall == libc::SYS_fork || syscall == libc::SYS_vfork {
            return Ok(ProcessCreationFlags::Flags(0));
        }
        if syscall == libc::SYS_clone {
            return Ok(ProcessCreationFlags::Flags(stop.args[0]));
        }
        if syscall != libc::SYS_clone3 {
            return Err(RunnerFault::UnexpectedSyscall(syscall).into());
        }

        if stop.args[0] == 0 || stop.args[1] < CLONE_ARGS_SIZE_VER0 {
            return Ok(ProcessCreationFlags::Invalid(libc::EINVAL));
        }

        let bytes = match self.buffer.copy_from_process_bytes(
            stop.parent,
            stop.args[0],
            mem::size_of::<u64>(),
        ) {
            Ok(bytes) => bytes,
            Err(ProcessCopyError::Errno(error)) => {
                return Ok(ProcessCreationFlags::Invalid(error));
            }
            Err(ProcessCopyError::Io(error)) => return Err(error.into()),
        };
        let flags = u64::from_ne_bytes(bytes.try_into().expect("requested eight bytes"));
        Ok(ProcessCreationFlags::Flags(flags))
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, BorrowedFd};

    use super::*;
    use crate::TaskInfo;
    use crate::runner::Tracker;
    use crate::runner::test_support::{ChildGuard, spawn_target};
    use crate::seccomp_filters::X86_64_RANGE_FILE_ONLY;

    #[derive(Clone)]
    struct TestFileSpace(u32);

    impl ProcFileSpace for TestFileSpace {
        fn lookup_fd(&self, _fd: RawFd) -> Option<ChildFile> {
            None
        }

        fn respond_real(
            &mut self,
            _backing: BorrowedFd<'_>,
            _tracker: &Tracker,
            _req: &libc::seccomp_notif,
        ) -> io::Result<()> {
            unreachable!()
        }

        fn respond_mock(
            &mut self,
            _mock: crate::MockFd,
            _backing: BorrowedFd<'_>,
            _tracker: &Tracker,
            _req: &libc::seccomp_notif,
        ) -> io::Result<()> {
            unreachable!()
        }

        fn remove_file(&mut self, _fd: RawFd) -> Option<ChildFile> {
            None
        }
    }

    fn empty_supervisor() -> Supervisor<TestFileSpace> {
        Supervisor::new(TaskInfo::default().compile().expect("empty setup is valid"))
    }

    fn creation_stop(syscall: libc::c_long, pid: libc::pid_t) -> ptrace::ProcessCreationStop {
        ptrace::ProcessCreationStop {
            parent: pid,
            syscall,
            args: [0; 6],
        }
    }

    fn next_creation_stop(
        target: &crate::runner::test_support::SpawnedTarget,
    ) -> ptrace::ProcessCreationStop {
        loop {
            if let Some(stop) = ptrace::try_wait_for_process_creation(target.pid())
                .expect("failed to poll process creation")
            {
                return stop;
            }

            let mut pollfd = libc::pollfd {
                fd: target.tracker.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pollfd, 1, 10) };
            assert!(
                ready >= 0,
                "listener poll failed: {}",
                io::Error::last_os_error()
            );
            if ready > 0 {
                let req = target
                    .tracker
                    .recv()
                    .expect("failed to receive seccomp notification");
                target
                    .tracker
                    .continue_syscall(&req)
                    .expect("failed to continue syscall before process creation");
            }
        }
    }

    fn handle_next_creation(
        supervisor: &mut Supervisor<TestFileSpace>,
        target: &crate::runner::test_support::SpawnedTarget,
    ) -> ProcessCreationOutcome {
        supervisor
            .handle_process_creation_stop(next_creation_stop(target))
            .expect("failed to handle process creation")
    }

    #[test]
    fn registering_a_process_twice_is_a_supervisor_fault() {
        let mut supervisor = empty_supervisor();
        supervisor
            .register_process(17, TestFileSpace(1))
            .expect("first registration failed");

        let error = supervisor
            .register_process(17, TestFileSpace(2))
            .expect_err("duplicate registration succeeded");

        assert!(matches!(
            error,
            RunnerError::Fault(RunnerFault::ProcessAlreadyTracked(17))
        ));
        assert_eq!(supervisor.procs[&17].0, 1);
    }

    #[test]
    fn non_creation_syscall_is_a_supervisor_fault() {
        let mut supervisor = empty_supervisor();
        let stop = creation_stop(libc::SYS_openat, 17);

        let error = supervisor
            .process_creation_flags(&stop)
            .expect_err("openat was accepted as process creation");

        assert!(matches!(
            error,
            RunnerError::Fault(RunnerFault::UnexpectedSyscall(libc::SYS_openat))
        ));
    }

    #[test]
    fn clone3_with_an_undersized_argument_is_invalid() {
        let mut supervisor = empty_supervisor();
        let mut stop = creation_stop(libc::SYS_clone3, 17);
        stop.args[0] = 1;
        stop.args[1] = CLONE_ARGS_SIZE_VER0 - 1;

        assert!(matches!(
            supervisor.process_creation_flags(&stop),
            Ok(ProcessCreationFlags::Invalid(libc::EINVAL))
        ));
    }

    #[test]
    fn clone_files_is_rejected_explicitly() {
        let target = spawn_target(
            &X86_64_RANGE_FILE_ONLY,
            c"/proc/self/exe",
            &[
                c"--exact",
                c"model::tests::new_file_allocates_dense_mock_fds",
            ],
        );
        let mut supervisor = empty_supervisor();
        supervisor
            .register_process(target.pid(), TestFileSpace(42))
            .expect("parent registration failed");
        let outcome = handle_next_creation(&mut supervisor, &target);

        assert_eq!(outcome, ProcessCreationOutcome::Rejected(libc::ENOTSUP));
    }

    #[test]
    fn supervisor_tracks_the_file_table_inherited_across_fork() {
        let target = spawn_target(
            &X86_64_RANGE_FILE_ONLY,
            c"/bin/sh",
            &[c"-c", c"exec 2>/dev/null; true & wait"],
        );
        let parent = target.pid();
        let mut supervisor = empty_supervisor();
        supervisor
            .register_process(parent, TestFileSpace(42))
            .expect("parent registration failed");

        let ProcessCreationOutcome::Created(child) = handle_next_creation(&mut supervisor, &target)
        else {
            panic!("shell process creation was rejected");
        };
        let child_guard = ChildGuard::new(child);

        assert_eq!(supervisor.procs[&child].0, 42);

        loop {
            let req = target
                .tracker
                .recv()
                .expect("failed to receive inherited seccomp notification");
            if req.pid as libc::pid_t == child {
                target
                    .tracker
                    .respond_errno(&req, libc::ENOSYS)
                    .expect("failed to answer child notification");
                break;
            }

            target
                .tracker
                .continue_syscall(&req)
                .expect("failed to continue parent syscall");
        }

        drop(child_guard);
    }

    #[test]
    fn failed_process_creation_returns_without_a_fork_event() {
        let target = spawn_target(
            &X86_64_RANGE_FILE_ONLY,
            c"/proc/self/exe",
            &[
                c"--exact",
                c"model::tests::new_file_allocates_dense_mock_fds",
            ],
        );
        let mut supervisor = empty_supervisor();
        supervisor
            .register_process(target.pid(), TestFileSpace(42))
            .expect("parent registration failed");

        let mut stop = next_creation_stop(&target);
        ptrace::rewrite_as_failing_clone(&mut stop).expect("failed to rewrite stopped syscall");
        let outcome = supervisor
            .handle_process_creation_stop(stop)
            .expect("failed process creation was not handled");

        assert_eq!(outcome, ProcessCreationOutcome::Failed(libc::EINVAL));
    }
}
