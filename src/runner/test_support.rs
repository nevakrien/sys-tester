use std::ffi::CStr;
use std::ptr;

use super::spawn::{StartupExchange, spawn_seccomp_target};
use super::{Tracker, errno};

pub(crate) struct ChildGuard(libc::pid_t);

impl ChildGuard {
    pub(crate) fn new(pid: libc::pid_t) -> Self {
        Self(pid)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        unsafe { libc::kill(self.0, libc::SIGKILL) };

        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(self.0, &mut status, 0) };
            if result == self.0 || (result < 0 && errno::get() != libc::EINTR) {
                return;
            }
        }
    }
}

pub(crate) struct SpawnedTarget {
    pub(crate) tracker: Tracker,
    guard: ChildGuard,
}

impl SpawnedTarget {
    pub(crate) fn pid(&self) -> libc::pid_t {
        self.guard.0
    }
}

pub(crate) fn spawn_target(
    filter: &[libc::sock_filter],
    executable: &CStr,
    arguments: &[&CStr],
) -> SpawnedTarget {
    let mut exchange = StartupExchange::new().expect("startup exchange creation failed");
    let argv: Vec<_> = std::iter::once(executable)
        .chain(arguments.iter().copied())
        .map(|argument| argument.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect();
    let envp = [ptr::null()];
    let mut stdout = || open_null();
    let mut stderr = || open_null();

    let (tracker, pid) = unsafe {
        spawn_seccomp_target(
            &mut exchange,
            filter,
            executable.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            None,
            Some(&mut stdout),
            Some(&mut stderr),
        )
    }
    .expect("target startup failed");

    SpawnedTarget {
        tracker,
        guard: ChildGuard::new(pid),
    }
}

fn open_null() -> Result<libc::c_int, libc::c_int> {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 { Err(errno::get()) } else { Ok(fd) }
}
