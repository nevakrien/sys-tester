//! Ptrace and child-wait operations assume the runner owns process-wide child
//! supervision and may freely consume `waitpid`/`waitid` events. Embedders must
//! not concurrently wait for children behind the runner's back.
//!
//! Process-creation syscalls use `SECCOMP_RET_TRACE`. Their syscall-exit result
//! is authoritative: a positive result identifies the child and a negative
//! result is the kernel errno. Fork events are enabled only because they attach
//! and stop a new child atomically; attaching after the parent returns would
//! race with the child's inherited seccomp filter.

use std::io;
use std::ptr;

use super::{ProcFileSpace, RunnerError, RunnerFault, errno};

const TRACE_OPTIONS: libc::c_ulong = (libc::PTRACE_O_TRACESECCOMP
    | libc::PTRACE_O_TRACESYSGOOD
    | libc::PTRACE_O_TRACEFORK
    | libc::PTRACE_O_TRACEVFORK
    | libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_EXITKILL) as libc::c_ulong;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcessCreationStop {
    pub parent: libc::pid_t,
    pub syscall: libc::c_long,
    pub args: [u64; 6],
}

pub(crate) struct ForkStop {
    pub parent: libc::pid_t,
    pub child: libc::pid_t,
}

pub(crate) enum ProcessCreationResult {
    Created(ForkStop),
    Failed(libc::c_int),
}

pub(crate) fn seize(pid: libc::pid_t) -> io::Result<()> {
    ptrace(
        libc::PTRACE_SEIZE,
        pid,
        ptr::null_mut(),
        TRACE_OPTIONS as usize as *mut libc::c_void,
    )
}

/// Wait for a `SECCOMP_RET_TRACE` process-creation stop and capture its inputs.
pub(crate) fn wait_for_process_creation(
    parent: libc::pid_t,
) -> Result<ProcessCreationStop, RunnerError> {
    loop {
        let status = waitpid(parent, 0)?;
        if let Some(stop) = process_creation_stop(parent, status)? {
            return Ok(stop);
        }
    }
}

pub(crate) fn try_wait_for_process_creation(
    parent: libc::pid_t,
) -> Result<Option<ProcessCreationStop>, RunnerError> {
    loop {
        let Some(status) = try_waitpid(parent)? else {
            return Ok(None);
        };
        if let Some(stop) = process_creation_stop(parent, status)? {
            return Ok(Some(stop));
        }
    }
}

/// Execute a process-creation syscall through its syscall-exit stop.
///
/// The `ProcFileSpace` borrow is held until the kernel result is known. On a
/// successful call, ptrace has both the parent and atomically attached child
/// stopped. A failed syscall has no fork event and returns its errno directly.
pub(crate) fn continue_to_fork<PF: ProcFileSpace>(
    stop: ProcessCreationStop,
    _files: &PF,
) -> Result<ProcessCreationResult, RunnerError> {
    syscall(stop.parent, 0)?;
    let mut attached_child = None;

    loop {
        let status = waitpid(stop.parent, 0)?;
        ensure_stopped(stop.parent, status)?;
        let event = status >> 16;

        if is_fork_event(event) {
            let child = event_child(stop.parent)?;
            let child_status = waitpid(child, 0)?;
            ensure_stopped(child, child_status)?;
            attached_child = Some(child);
            syscall(stop.parent, 0)?;
            continue;
        }

        if event == 0 && libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
            let result = get_regs(stop.parent)?.rax as i64;
            if result < 0 {
                if attached_child.is_some() {
                    return Err(RunnerFault::ForkResultMismatch {
                        result,
                        event_child: attached_child,
                    }
                    .into());
                }
                resume(stop.parent, 0)?;
                return Ok(ProcessCreationResult::Failed((-result) as libc::c_int));
            }

            let child = libc::pid_t::try_from(result).ok().filter(|pid| *pid > 0);
            if child != attached_child {
                return Err(RunnerFault::ForkResultMismatch {
                    result,
                    event_child: attached_child,
                }
                .into());
            }
            return Ok(ProcessCreationResult::Created(ForkStop {
                parent: stop.parent,
                child: child.expect("positive result checked above"),
            }));
        }

        syscall(stop.parent, signal_to_deliver(status))?;
    }
}

/// Skip the stopped syscall and make it return `-error`.
pub(crate) fn reject_process_creation(
    stop: ProcessCreationStop,
    error: libc::c_int,
) -> Result<(), RunnerError> {
    let mut regs = get_regs(stop.parent)?;
    regs.orig_rax = (-1_i64) as u64;
    set_regs(stop.parent, &regs)?;
    syscall(stop.parent, 0)?;

    loop {
        let status = waitpid(stop.parent, 0)?;
        ensure_stopped(stop.parent, status)?;
        if status >> 16 == 0 && libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
            let mut regs = get_regs(stop.parent)?;
            regs.rax = (-(error as i64)) as u64;
            set_regs(stop.parent, &regs)?;
            resume(stop.parent, 0)?;
            return Ok(());
        }
        syscall(stop.parent, signal_to_deliver(status))?;
    }
}

#[cfg(test)]
pub(crate) fn rewrite_as_failing_clone(stop: &mut ProcessCreationStop) -> io::Result<()> {
    let mut regs = get_regs(stop.parent)?;
    regs.orig_rax = libc::SYS_clone as u64;
    regs.rdi = (libc::CLONE_SIGHAND | libc::SIGCHLD) as u64;
    regs.rsi = 0;
    set_regs(stop.parent, &regs)?;
    stop.syscall = libc::SYS_clone;
    stop.args = [regs.rdi, 0, 0, 0, 0, 0];
    Ok(())
}

pub(crate) fn resume_fork(stop: ForkStop) -> io::Result<()> {
    let child = resume(stop.child, 0);
    let parent = resume(stop.parent, 0);
    child.and(parent)
}

/// Reap one terminated child without consuming any ptrace-stop event.
pub(crate) fn reap_exited() -> io::Result<Option<libc::pid_t>> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        let result =
            unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOHANG) };
        if result == 0 {
            let pid = unsafe { info.si_pid() };
            return Ok((pid > 0).then_some(pid));
        }
        if errno::get() == libc::EINTR {
            continue;
        }
        if errno::get() == libc::ECHILD {
            return Ok(None);
        }
        return Err(io::Error::last_os_error());
    }
}

pub(crate) fn resume(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    ptrace(
        libc::PTRACE_CONT,
        pid,
        ptr::null_mut(),
        signal as usize as *mut libc::c_void,
    )
}

fn syscall(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    ptrace(
        libc::PTRACE_SYSCALL,
        pid,
        ptr::null_mut(),
        signal as usize as *mut libc::c_void,
    )
}

fn get_regs(pid: libc::pid_t) -> io::Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    ptrace(
        libc::PTRACE_GETREGS,
        pid,
        ptr::null_mut(),
        (&mut regs as *mut libc::user_regs_struct).cast(),
    )?;
    Ok(regs)
}

fn set_regs(pid: libc::pid_t, regs: &libc::user_regs_struct) -> io::Result<()> {
    ptrace(
        libc::PTRACE_SETREGS,
        pid,
        ptr::null_mut(),
        (regs as *const libc::user_regs_struct).cast_mut().cast(),
    )
}

fn event_child(parent: libc::pid_t) -> Result<libc::pid_t, RunnerError> {
    let mut child = 0 as libc::c_ulong;
    ptrace(
        libc::PTRACE_GETEVENTMSG,
        parent,
        ptr::null_mut(),
        (&mut child as *mut libc::c_ulong).cast(),
    )?;
    libc::pid_t::try_from(child).map_err(|_| RunnerFault::ChildPidOutOfRange(child).into())
}

fn is_fork_event(event: libc::c_int) -> bool {
    event == libc::PTRACE_EVENT_FORK
        || event == libc::PTRACE_EVENT_VFORK
        || event == libc::PTRACE_EVENT_CLONE
}

fn ensure_stopped(pid: libc::pid_t, status: libc::c_int) -> Result<(), RunnerError> {
    if libc::WIFSTOPPED(status) {
        Ok(())
    } else {
        Err(RunnerFault::UnexpectedWaitStatus { pid, status }.into())
    }
}

fn process_creation_stop(
    parent: libc::pid_t,
    status: libc::c_int,
) -> Result<Option<ProcessCreationStop>, RunnerError> {
    ensure_stopped(parent, status)?;
    if status >> 16 == libc::PTRACE_EVENT_SECCOMP {
        let regs = get_regs(parent)?;
        Ok(Some(ProcessCreationStop {
            parent,
            syscall: regs.orig_rax as libc::c_long,
            args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
        }))
    } else {
        resume(parent, signal_to_deliver(status))?;
        Ok(None)
    }
}

fn waitpid(pid: libc::pid_t, options: libc::c_int) -> io::Result<libc::c_int> {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, options | libc::__WALL) };
        if result == pid {
            return Ok(status);
        }
        if result < 0 && errno::get() == libc::EINTR {
            continue;
        }
        return Err(io::Error::last_os_error());
    }
}

fn try_waitpid(pid: libc::pid_t) -> io::Result<Option<libc::c_int>> {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
        if result == pid {
            return Ok(Some(status));
        }
        if result == 0 {
            return Ok(None);
        }
        if errno::get() == libc::EINTR {
            continue;
        }
        return Err(io::Error::last_os_error());
    }
}

fn signal_to_deliver(status: libc::c_int) -> libc::c_int {
    if status >> 16 == 0 {
        libc::WSTOPSIG(status)
    } else {
        0
    }
}

fn ptrace(
    request: libc::c_uint,
    pid: libc::pid_t,
    address: *mut libc::c_void,
    data: *mut libc::c_void,
) -> io::Result<()> {
    let result = unsafe { libc::ptrace(request, pid, address, data) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
