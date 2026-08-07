use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use super::errno;

pub struct Tracker {
    listener: OwnedFd,
}

impl Tracker {
    pub(crate) fn new(listener: OwnedFd) -> Self {
        Self { listener }
    }

    /// Block until a seccomp user-notification is available.
    ///
    /// EINTR of the supervisor itself is transparently retried.
    pub fn recv(&self) -> Result<libc::seccomp_notif, libc::c_int> {
        loop {
            // The kernel requires the structure to be zeroed before RECV.
            let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };

            let rc = unsafe {
                libc::ioctl(
                    self.listener.as_raw_fd(),
                    libc::SECCOMP_IOCTL_NOTIF_RECV,
                    &mut req,
                )
            };

            if rc == 0 {
                return Ok(req);
            }

            let error = errno::get();

            if error == libc::EINTR {
                continue;
            }

            return Err(error);
        }
    }

    /// Emulate successful completion of the syscall.
    pub fn respond(&self, req: &libc::seccomp_notif, value: i64) -> Result<(), libc::c_int> {
        let mut resp = libc::seccomp_notif_resp {
            id: req.id,
            val: value,
            error: 0,
            flags: 0,
        };

        self.send_response(&mut resp)
    }

    /// Emulate syscall failure.
    ///
    /// `error` is a normal positive errno value, e.g. libc::ENOENT.
    pub fn respond_errno(
        &self,
        req: &libc::seccomp_notif,
        error: libc::c_int,
    ) -> Result<(), libc::c_int> {
        let mut resp = libc::seccomp_notif_resp {
            id: req.id,
            val: 0,
            error: -errno::normalize(error),
            flags: 0,
        };

        self.send_response(&mut resp)
    }

    /// Tell the kernel to execute the intercepted syscall normally.
    pub fn continue_syscall(&self, req: &libc::seccomp_notif) -> Result<(), libc::c_int> {
        let mut resp = libc::seccomp_notif_resp {
            id: req.id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        };

        self.send_response(&mut resp)
    }

    /// Duplicate a supervisor FD into the notifying process.
    ///
    /// This DOES NOT answer the seccomp notification. The caller must
    /// subsequently call respond(), usually with the returned fd number.
    ///
    /// Works on Linux >= 5.9.
    pub fn add_fd(
        &self,
        req: &libc::seccomp_notif,
        src: BorrowedFd<'_>,
        cloexec: bool,
    ) -> Result<RawFd, libc::c_int> {
        let mut addfd = libc::seccomp_notif_addfd {
            id: req.id,
            flags: 0,
            srcfd: src.as_raw_fd() as u32,
            newfd: 0,
            newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
        };

        let rc = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ADDFD,
                &mut addfd,
            )
        };

        if rc < 0 { Err(errno::get()) } else { Ok(rc) }
    }

    /// Duplicate a supervisor FD into the notifying process and atomically
    /// use the allocated child FD as the syscall's return value.
    ///
    /// Requires Linux >= 5.14.
    pub fn add_fd_and_respond(
        &self,
        req: &libc::seccomp_notif,
        src: BorrowedFd<'_>,
        cloexec: bool,
    ) -> Result<RawFd, libc::c_int> {
        let mut addfd = libc::seccomp_notif_addfd {
            id: req.id,
            flags: libc::SECCOMP_ADDFD_FLAG_SEND as u32,
            srcfd: src.as_raw_fd() as u32,
            newfd: 0,
            newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
        };

        let rc = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ADDFD,
                &mut addfd,
            )
        };

        if rc < 0 { Err(errno::get()) } else { Ok(rc) }
    }

    /// Install the FD at a specific target FD number.
    ///
    /// This replaces an existing target FD with that number, if necessary.
    /// It does not answer the notification.
    pub fn add_fd_at(
        &self,
        req: &libc::seccomp_notif,
        src: BorrowedFd<'_>,
        target_fd: RawFd,
        cloexec: bool,
    ) -> Result<RawFd, libc::c_int> {
        debug_assert!(target_fd >= 0);

        let mut addfd = libc::seccomp_notif_addfd {
            id: req.id,
            flags: libc::SECCOMP_ADDFD_FLAG_SETFD as u32,
            srcfd: src.as_raw_fd() as u32,
            newfd: target_fd as u32,
            newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
        };

        let rc = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ADDFD,
                &mut addfd,
            )
        };

        if rc < 0 { Err(errno::get()) } else { Ok(rc) }
    }

    /// Check that the notification is still live.
    ///
    /// Particularly useful before doing operations involving req.pid.
    pub fn id_valid(&self, req: &libc::seccomp_notif) -> Result<(), libc::c_int> {
        let mut id = req.id;

        let rc = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
                &mut id,
            )
        };

        if rc < 0 { Err(errno::get()) } else { Ok(()) }
    }

    fn send_response(&self, resp: &mut libc::seccomp_notif_resp) -> Result<(), libc::c_int> {
        let rc = unsafe {
            libc::ioctl(
                self.listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                resp,
            )
        };

        if rc < 0 { Err(errno::get()) } else { Ok(()) }
    }
}

impl AsRawFd for Tracker {
    fn as_raw_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }
}
