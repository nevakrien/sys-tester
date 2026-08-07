#![cfg(target_os = "linux")]

use std::fmt;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use super::{Tracker, errno, ptrace};

const STATE_EMPTY: u32 = 0;
const STATE_LISTENER_CREATED: u32 = 1;
const STATE_SPAWNED: u32 = 2;
const STATE_FAILED: u32 = 3;

const STARTUP_PENDING: u32 = 0;
const STARTUP_DONE: u32 = 1;

const TARGET_READY_BYTE: u8 = 0x52;
const TRACER_ATTACHED_BYTE: u8 = 0x41;
const TRANSFER_BYTE: u8 = 0x53;
const TARGET_STACK_SIZE: usize = 1024 * 1024;

pub type FdFactory<'a> = &'a mut dyn FnMut() -> Result<RawFd, libc::c_int>;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupStep {
    None = 0,
    Stdin = 1,
    Stdout = 2,
    Stderr = 3,
    CloseDescriptors = 4,
    CloneTarget = 5,
    NoNewPrivileges = 6,
    InstallSeccomp = 7,
    Exec = 8,
    TransferListener = 9,
    AttachTracer = 10,
}

impl StartupStep {
    fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::Stdin,
            2 => Self::Stdout,
            3 => Self::Stderr,
            4 => Self::CloseDescriptors,
            5 => Self::CloneTarget,
            6 => Self::NoNewPrivileges,
            7 => Self::InstallSeccomp,
            8 => Self::Exec,
            9 => Self::TransferListener,
            10 => Self::AttachTracer,
            _ => Self::None,
        }
    }
}

#[derive(Debug)]
pub struct SpawnError {
    pub step: StartupStep,
    pub errno: libc::c_int,
}

impl SpawnError {
    fn new(step: StartupStep, errno: libc::c_int) -> Self {
        Self {
            step,
            errno: errno::normalize(errno),
        }
    }

    pub fn io_error(&self) -> io::Error {
        io::Error::from_raw_os_error(self.errno)
    }
}

impl fmt::Display for SpawnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "process startup failed during {:?}: {}",
            self.step,
            self.io_error(),
        )
    }
}

impl std::error::Error for SpawnError {}

#[repr(C)]
struct SharedStartup {
    done: AtomicU32,
    state: AtomicU32,
    target_pid: AtomicI32,
    listener_fd: AtomicI32,
    error_step: AtomicU32,
    error_code: AtomicI32,
}

/// A reusable page of shared startup state.
///
/// `&mut StartupExchange` serializes launches that reuse this slot. The mapping
/// is inherited by the spawner and the temporary target launcher. It is removed
/// from the final target automatically by successful `execve()`.
pub struct StartupExchange {
    ptr: NonNull<SharedStartup>,
    map_len: usize,
}

impl StartupExchange {
    pub fn new() -> io::Result<Self> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(io::Error::last_os_error());
        }

        let map_len = page_size as usize;
        if mem::size_of::<SharedStartup>() > map_len {
            return Err(io::Error::other("SharedStartup does not fit in one page"));
        }

        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let ptr =
            NonNull::new(mapping.cast::<SharedStartup>()).expect("successful mmap returned null");
        unsafe {
            ptr.as_ptr().write(SharedStartup {
                done: AtomicU32::new(STARTUP_PENDING),
                state: AtomicU32::new(STATE_EMPTY),
                target_pid: AtomicI32::new(-1),
                listener_fd: AtomicI32::new(-1),
                error_step: AtomicU32::new(StartupStep::None as u32),
                error_code: AtomicI32::new(0),
            });
        }

        Ok(Self { ptr, map_len })
    }

    fn reset(&mut self) {
        let shared = unsafe { self.ptr.as_ref() };
        shared.done.store(STARTUP_PENDING, Ordering::Relaxed);
        shared.target_pid.store(-1, Ordering::Relaxed);
        shared.listener_fd.store(-1, Ordering::Relaxed);
        shared
            .error_step
            .store(StartupStep::None as u32, Ordering::Relaxed);
        shared.error_code.store(0, Ordering::Relaxed);
        shared.state.store(STATE_EMPTY, Ordering::Release);
    }

    fn as_ptr(&self) -> *mut SharedStartup {
        self.ptr.as_ptr()
    }

    fn shared(&self) -> &SharedStartup {
        unsafe { self.ptr.as_ref() }
    }
}

impl Drop for StartupExchange {
    fn drop(&mut self) {
        let result = unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.map_len) };
        debug_assert_eq!(result, 0);
    }
}

// The mapping may move between supervisor threads, but one launch at a time is
// enforced by `&mut StartupExchange`.
unsafe impl Send for StartupExchange {}

struct SpawnerArgs<'a> {
    shared: *mut SharedStartup,
    filter: &'a [libc::sock_filter],
    executable: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    spawner_socket: RawFd,
    stdin: Option<FdFactory<'a>>,
    stdout: Option<FdFactory<'a>>,
    stderr: Option<FdFactory<'a>>,
}

struct TargetArgs {
    shared: *mut SharedStartup,
    filter: *const libc::sock_filter,
    filter_len: usize,
    executable: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
}

/// Spawn a process under a seccomp user-notification filter.
///
/// The three optional callbacks execute in the forked spawner, before inherited
/// descriptors are closed. A successful callback returns ownership of an FD;
/// that FD is installed as stdin, stdout, or stderr respectively.
///
/// The call does not return until:
///
/// - stdio setup has completed;
/// - the target has installed seccomp;
/// - the target has successfully crossed `execve()`;
/// - ptrace has attached to the target;
/// - the listener FD has been transferred to this supervisor; and
/// - the temporary spawner has exited.
///
/// On success, returns a `Tracker` for the seccomp notification socket and the
/// PID of the process that owns the intercepted syscalls.
///
/// # Safety
///
/// - `executable` must point to a valid NUL-terminated pathname.
/// - `argv` and `envp` must point to valid NULL-terminated pointer arrays whose
///   strings remain valid until this function returns.
/// - The filter must allow `execve`, `exit`, and `exit_group` without user
///   notification. Notifying these launcher operations can deadlock startup.
/// - Each callback runs after `fork()` and must not panic or rely on a
///   process-global lock that another thread may have held at the instant of
///   fork.
/// - Callback errors must be positive errno values.
/// - A callback must return a newly owned FD and must not return 0, 1, 2, or an
///   inherited descriptor that remains owned elsewhere.
pub unsafe fn spawn_seccomp_target<'a>(
    exchange: &mut StartupExchange,
    filter: &'a [libc::sock_filter],
    executable: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    stdin: Option<FdFactory<'a>>,
    stdout: Option<FdFactory<'a>>,
    stderr: Option<FdFactory<'a>>,
) -> Result<(Tracker, libc::pid_t), SpawnError> {
    validate_inputs(filter, executable, argv, envp)?;
    exchange.reset();

    let [supervisor_socket, spawner_socket] = socket_pair()
        .map_err(|error| SpawnError::new(StartupStep::TransferListener, errno::from_io(&error)))?;

    let mut args = SpawnerArgs {
        shared: exchange.as_ptr(),
        filter,
        executable,
        argv,
        envp,
        spawner_socket: spawner_socket.as_raw_fd(),
        stdin,
        stdout,
        stderr,
    };

    let spawner_pid = unsafe { libc::fork() };
    if spawner_pid < 0 {
        return Err(SpawnError::new(StartupStep::CloneTarget, errno::get()));
    }

    if spawner_pid == 0 {
        let exit_code = unsafe { spawner_main(&mut args) };
        // This is the sole publication point from the spawner to the
        // supervisor. All shared startup fields are final before this store.
        unsafe { &*args.shared }
            .done
            .store(STARTUP_DONE, Ordering::Release);
        unsafe { libc::_exit(exit_code) };
    }

    drop(spawner_socket);

    let listener_result = (|| {
        let message = recv_control(supervisor_socket.as_raw_fd())
            .map_err(|error| SpawnError::new(StartupStep::TransferListener, error))?;
        if message != TARGET_READY_BYTE {
            return Err(SpawnError::new(StartupStep::TransferListener, libc::EPROTO));
        }

        let pid = exchange.shared().target_pid.load(Ordering::Acquire);
        if pid <= 0 {
            return Err(SpawnError::new(StartupStep::CloneTarget, libc::ECHILD));
        }
        ptrace::seize(pid)
            .map_err(|error| SpawnError::new(StartupStep::AttachTracer, errno::from_io(&error)))?;

        send_control(supervisor_socket.as_raw_fd(), TRACER_ATTACHED_BYTE)
            .map_err(|error| SpawnError::new(StartupStep::TransferListener, error))?;
        recv_fd(supervisor_socket.as_raw_fd())
            .map_err(|error| SpawnError::new(StartupStep::TransferListener, errno::from_io(&error)))
    })();
    if listener_result.is_err() {
        drop(supervisor_socket);
    }
    let wait_result = waitpid_nointr(spawner_pid);

    let shared = exchange.shared();
    let mut startup_done = false;
    let result = (|| {
        let status = wait_result
            .map_err(|error| SpawnError::new(StartupStep::CloneTarget, errno::from_io(&error)))?;

        if shared.done.load(Ordering::Acquire) != STARTUP_DONE {
            return Err(SpawnError::new(StartupStep::CloneTarget, libc::ECHILD));
        }
        startup_done = true;

        if let Err(error) = &listener_result
            && error.step == StartupStep::AttachTracer
        {
            return Err(SpawnError::new(error.step, error.errno));
        }

        if shared.state.load(Ordering::Relaxed) == STATE_FAILED {
            return Err(read_shared_error(shared));
        }

        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(SpawnError::new(StartupStep::CloneTarget, libc::ECHILD));
        }

        let listener = listener_result?;

        if shared.state.load(Ordering::Relaxed) != STATE_SPAWNED {
            return Err(SpawnError::new(StartupStep::CloneTarget, libc::EIO));
        }

        let pid = shared.target_pid.load(Ordering::Relaxed);
        if pid <= 0 {
            return Err(SpawnError::new(StartupStep::CloneTarget, libc::ECHILD));
        }

        Ok((Tracker::new(listener), pid))
    })();

    if result.is_err() && startup_done {
        terminate_and_reap_target(shared);
    }

    result
}

fn validate_inputs(
    filter: &[libc::sock_filter],
    executable: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> Result<(), SpawnError> {
    if filter.is_empty() || filter.len() > u16::MAX as usize {
        return Err(SpawnError::new(StartupStep::InstallSeccomp, libc::EINVAL));
    }
    if executable.is_null() || argv.is_null() || envp.is_null() {
        return Err(SpawnError::new(StartupStep::Exec, libc::EFAULT));
    }
    Ok(())
}

unsafe fn spawner_main(args: &mut SpawnerArgs<'_>) -> libc::c_int {
    let shared = unsafe { &*args.shared };

    if let Err(errno) = install_standard_stream(args.stdin.take(), libc::STDIN_FILENO) {
        record_failure(shared, StartupStep::Stdin, errno);
        return 127;
    }
    if let Err(errno) = install_standard_stream(args.stdout.take(), libc::STDOUT_FILENO) {
        record_failure(shared, StartupStep::Stdout, errno);
        return 127;
    }
    if let Err(errno) = install_standard_stream(args.stderr.take(), libc::STDERR_FILENO) {
        record_failure(shared, StartupStep::Stderr, errno);
        return 127;
    }

    if let Err(errno) = close_unwanted_fds(args.spawner_socket) {
        record_failure(shared, StartupStep::CloseDescriptors, errno);
        return 127;
    }

    let mut target_args = TargetArgs {
        shared: args.shared,
        filter: args.filter.as_ptr(),
        filter_len: args.filter.len(),
        executable: args.executable,
        argv: args.argv,
        envp: args.envp,
    };

    // CLONE_VFORK suspends this spawner until the target either successfully
    // execs or exits. CLONE_VM makes this genuine vfork-style execution on a
    // dedicated stack. CLONE_FILES is the mechanism that leaves the newly
    // created listener in the spawner's table after target exec unshares its
    // own table. CLONE_PARENT makes the final target a direct child of the
    // original supervisor.
    let target_pid = unsafe { clone_target(&mut target_args) };
    if target_pid < 0 {
        record_failure(shared, StartupStep::CloneTarget, errno::get());
        return 127;
    }
    shared.target_pid.store(target_pid, Ordering::Release);

    if shared.state.load(Ordering::Acquire) == STATE_FAILED {
        return 127;
    }

    if shared.state.load(Ordering::Acquire) != STATE_LISTENER_CREATED {
        record_failure(shared, StartupStep::Exec, libc::EIO);
        unsafe { libc::kill(target_pid, libc::SIGKILL) };
        return 127;
    }

    let listener = shared.listener_fd.load(Ordering::Relaxed);
    if listener < 0 {
        record_failure(shared, StartupStep::InstallSeccomp, libc::EBADF);
        unsafe { libc::kill(target_pid, libc::SIGKILL) };
        return 127;
    }

    if let Err(errno) = send_control(args.spawner_socket, TARGET_READY_BYTE) {
        record_failure(shared, StartupStep::TransferListener, errno);
        unsafe { libc::kill(target_pid, libc::SIGKILL) };
        return 127;
    }
    match recv_control(args.spawner_socket) {
        Ok(TRACER_ATTACHED_BYTE) => {}
        Ok(_) => {
            record_failure(shared, StartupStep::TransferListener, libc::EPROTO);
            unsafe { libc::kill(target_pid, libc::SIGKILL) };
            return 127;
        }
        Err(errno) => {
            record_failure(shared, StartupStep::TransferListener, errno);
            unsafe { libc::kill(target_pid, libc::SIGKILL) };
            return 127;
        }
    }

    if let Err(errno) = send_fd(args.spawner_socket, listener) {
        record_failure(shared, StartupStep::TransferListener, errno);
        unsafe { libc::kill(target_pid, libc::SIGKILL) };
        return 127;
    }

    shared.state.store(STATE_SPAWNED, Ordering::Relaxed);
    0
}

fn install_standard_stream(
    factory: Option<&mut dyn FnMut() -> Result<RawFd, libc::c_int>>,
    destination: RawFd,
) -> Result<(), libc::c_int> {
    let Some(factory) = factory else {
        return Ok(());
    };

    let source = factory().map_err(errno::normalize)?;
    if source < 0 {
        return Err(libc::EBADF);
    }

    // Requiring a newly owned non-stdio descriptor avoids ambiguous ownership
    // and accidental destruction of an inherited standard stream.
    if source <= libc::STDERR_FILENO {
        return Err(libc::EINVAL);
    }

    if unsafe { libc::dup2(source, destination) } < 0 {
        let errno = errno::get();
        unsafe { libc::close(source) };
        return Err(errno);
    }

    // dup2 clears FD_CLOEXEC on the destination, which is what stdio needs.
    unsafe { libc::close(source) };
    Ok(())
}

fn close_unwanted_fds(keep: RawFd) -> Result<(), libc::c_int> {
    if keep < 3 {
        return Err(libc::EINVAL);
    }

    if keep > 3 {
        close_range(3, (keep - 1) as u32)?;
    }
    close_range(keep as u32 + 1, u32::MAX)?;

    Ok(())
}

fn close_range(first: u32, last: u32) -> Result<(), libc::c_int> {
    loop {
        let result = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0_u32) };
        if result == 0 {
            return Ok(());
        }

        let errno = errno::get();
        if errno != libc::EINTR {
            return Err(errno);
        }
    }
}

extern "C" fn target_entry(argument: *mut libc::c_void) -> libc::c_int {
    let args = unsafe { &mut *argument.cast::<TargetArgs>() };
    let shared = unsafe { &*args.shared };

    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        publish_target_failure(shared, StartupStep::NoNewPrivileges, errno::get());
        unsafe { libc::_exit(127) };
    }

    let program = libc::sock_fprog {
        len: args.filter_len as libc::c_ushort,
        filter: args.filter.cast_mut(),
    };

    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &program,
        )
    };
    if listener < 0 {
        publish_target_failure(shared, StartupStep::InstallSeccomp, errno::get());
        unsafe { libc::_exit(127) };
    }

    shared
        .listener_fd
        .store(listener as RawFd, Ordering::Relaxed);
    shared
        .state
        .store(STATE_LISTENER_CREATED, Ordering::Release);

    unsafe {
        libc::execve(args.executable, args.argv, args.envp);
    }

    publish_target_failure(shared, StartupStep::Exec, errno::get());
    unsafe { libc::_exit(127) }
}

unsafe fn clone_target(args: &mut TargetArgs) -> libc::pid_t {
    let stack = unsafe {
        libc::mmap(
            ptr::null_mut(),
            TARGET_STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        )
    };
    if stack == libc::MAP_FAILED {
        return -1;
    }

    let stack_top = unsafe { stack.cast::<u8>().add(TARGET_STACK_SIZE) };
    let flags =
        libc::CLONE_VM | libc::CLONE_VFORK | libc::CLONE_FILES | libc::CLONE_PARENT | libc::SIGCHLD;

    let pid = unsafe {
        libc::clone(
            target_entry,
            stack_top.cast(),
            flags,
            (args as *mut TargetArgs).cast(),
        )
    };

    let saved_errno = errno::get();
    unsafe { libc::munmap(stack, TARGET_STACK_SIZE) };
    errno::set(saved_errno);
    pid
}

fn record_failure(shared: &SharedStartup, step: StartupStep, errno: libc::c_int) {
    shared.error_step.store(step as u32, Ordering::Relaxed);
    shared
        .error_code
        .store(errno::normalize(errno), Ordering::Relaxed);
    shared.state.store(STATE_FAILED, Ordering::Relaxed);
}

fn publish_target_failure(shared: &SharedStartup, step: StartupStep, errno: libc::c_int) {
    shared.error_step.store(step as u32, Ordering::Relaxed);
    shared
        .error_code
        .store(errno::normalize(errno), Ordering::Relaxed);
    shared.state.store(STATE_FAILED, Ordering::Release);
}

fn read_shared_error(shared: &SharedStartup) -> SpawnError {
    SpawnError::new(
        StartupStep::from_raw(shared.error_step.load(Ordering::Relaxed)),
        shared.error_code.load(Ordering::Relaxed),
    )
}

fn socket_pair() -> io::Result<[OwnedFd; 2]> {
    let mut sockets = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sockets.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe {
        [
            OwnedFd::from_raw_fd(sockets[0]),
            OwnedFd::from_raw_fd(sockets[1]),
        ]
    })
}

fn send_control(socket: RawFd, byte: u8) -> Result<(), libc::c_int> {
    loop {
        let result =
            unsafe { libc::send(socket, (&byte as *const u8).cast(), 1, libc::MSG_NOSIGNAL) };
        if result == 1 {
            return Ok(());
        }
        if result < 0 && errno::get() == libc::EINTR {
            continue;
        }
        return Err(if result < 0 { errno::get() } else { libc::EIO });
    }
}

fn recv_control(socket: RawFd) -> Result<u8, libc::c_int> {
    let mut byte = 0;
    loop {
        let result = unsafe { libc::recv(socket, (&mut byte as *mut u8).cast(), 1, 0) };
        if result == 1 {
            return Ok(byte);
        }
        if result < 0 && errno::get() == libc::EINTR {
            continue;
        }
        return Err(if result < 0 {
            errno::get()
        } else {
            libc::EPIPE
        });
    }
}

fn send_fd(socket: RawFd, descriptor: RawFd) -> Result<(), libc::c_int> {
    let mut byte = TRANSFER_BYTE;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };

    // usize storage supplies cmsghdr-compatible alignment without allocating in
    // the post-fork spawner.
    let required = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = [0usize; 8];
    if required > mem::size_of_val(&control) {
        return Err(libc::EOVERFLOW);
    }

    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = required;

    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(libc::EINVAL);
        }

        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as usize;
        ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
    }

    loop {
        let result = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
        if result == 1 {
            return Ok(());
        }
        if result < 0 {
            let errno = errno::get();
            if errno == libc::EINTR {
                continue;
            }
            return Err(errno);
        }
        return Err(libc::EIO);
    }
}

fn recv_fd(socket: RawFd) -> io::Result<OwnedFd> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };

    let required = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = [0usize; 8];
    if required > mem::size_of_val(&control) {
        return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
    }

    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = required;

    let count = loop {
        let count = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
        if count >= 0 {
            break count;
        }
        if errno::get() != libc::EINTR {
            return Err(io::Error::last_os_error());
        }
    };
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "spawner exited before transferring the listener",
        ));
    }
    let received = unsafe {
        let mut received = None;
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && (*header).cmsg_len >= libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as usize
            {
                let fd = ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>());
                if fd >= 0 {
                    received = Some(OwnedFd::from_raw_fd(fd));
                }
                break;
            }

            header = libc::CMSG_NXTHDR(&message, header);
        }
        received
    };

    if count != 1 || byte != TRANSFER_BYTE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid listener transfer message",
        ));
    }
    if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated listener transfer message",
        ));
    }

    received.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "listener transfer contained no SCM_RIGHTS descriptor",
        )
    })
}

fn terminate_and_reap_target(shared: &SharedStartup) {
    let pid = shared.target_pid.load(Ordering::Relaxed);
    if pid <= 0 {
        return;
    }

    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid || (result < 0 && errno::get() == libc::ECHILD) {
            return;
        }
        if result < 0 {
            if errno::get() == libc::EINTR {
                continue;
            }
            return;
        }
        break;
    }

    unsafe { libc::kill(pid, libc::SIGKILL) };
    let _ = waitpid_nointr(pid);
}

fn waitpid_nointr(pid: libc::pid_t) -> io::Result<libc::c_int> {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return Ok(status);
        }
        if result < 0 && errno::get() == libc::EINTR {
            continue;
        }
        return Err(io::Error::last_os_error());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::seccomp_filters::{X86_64_RANGE_FILE_ONLY, X86_64_RANGE_STRICT};

    use crate::runner::test_support::spawn_target;

    #[test]
    fn post_exec_openat_is_delivered_to_supervisor() {
        let target = spawn_target(&X86_64_RANGE_FILE_ONLY, c"/proc/self/exe", &[c"--help"]);
        let pid = target.pid();

        let notification = loop {
            let notification = target
                .tracker
                .recv()
                .expect("failed to receive seccomp notification");
            assert_eq!(notification.pid as libc::pid_t, pid);
            if notification.data.nr as libc::c_long == libc::SYS_openat {
                break notification;
            }

            target
                .tracker
                .continue_syscall(&notification)
                .expect("failed to continue startup notification");
        };

        target
            .tracker
            .respond_errno(&notification, libc::EPIPE)
            .expect("failed to respond to seccomp notification");
    }

    #[test]
    fn failed_exec_is_reported_and_reaped() {
        let mut exchange = StartupExchange::new().expect("startup exchange creation failed");
        let executable = c"/definitely/not/a/real/seccomp-test-executable";
        let argv = [executable.as_ptr(), ptr::null()];
        let envp = [ptr::null()];

        let result = unsafe {
            spawn_seccomp_target(
                &mut exchange,
                &X86_64_RANGE_STRICT,
                executable.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                None,
                None,
                None,
            )
        };
        let error = result
            .err()
            .expect("missing executable unexpectedly spawned");

        assert_eq!(error.step, StartupStep::Exec);
        assert_eq!(error.errno, libc::ENOENT);
        assert_eq!(exchange.shared().done.load(Ordering::Acquire), STARTUP_DONE);

        let target_pid = exchange.shared().target_pid.load(Ordering::Relaxed);
        assert!(target_pid > 0);

        let mut status = 0;
        let result = unsafe { libc::waitpid(target_pid, &mut status, libc::WNOHANG) };
        assert_eq!(result, -1);
        assert_eq!(errno::get(), libc::ECHILD);
    }

    #[test]
    fn spawner_failure_is_published_before_return() {
        let mut exchange = StartupExchange::new().expect("startup exchange creation failed");
        let executable = c"/proc/self/exe";
        let argv = [executable.as_ptr(), ptr::null()];
        let envp = [ptr::null()];
        let mut stdin = || Err(libc::EACCES);

        let result = unsafe {
            spawn_seccomp_target(
                &mut exchange,
                &X86_64_RANGE_STRICT,
                executable.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                Some(&mut stdin),
                None,
                None,
            )
        };
        let error = result.err().expect("stdin failure unexpectedly spawned");

        assert_eq!(error.step, StartupStep::Stdin);
        assert_eq!(error.errno, libc::EACCES);
        assert_eq!(exchange.shared().done.load(Ordering::Acquire), STARTUP_DONE);
        assert_eq!(exchange.shared().target_pid.load(Ordering::Relaxed), -1);
    }
}
