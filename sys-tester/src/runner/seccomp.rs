use std::io;
use std::os::fd::RawFd;

use crate::seccomp_filters::X86_64_FINAL;

/// Installs the build-generated final filter and returns its notification listener.
///
/// Filter construction belongs to the build script. This runtime path only
/// passes generated classic BPF to the kernel and does not link libseccomp.
pub fn install_seccomp_filter() -> io::Result<RawFd> {
    install_filter(&X86_64_FINAL)
}

fn install_filter(filter: &'static [libc::sock_filter]) -> io::Result<RawFd> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    let program = libc::sock_fprog {
        len: filter.len().try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "seccomp filter is too large")
        })?,
        filter: filter.as_ptr().cast_mut(),
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
        Err(io::Error::last_os_error())
    } else {
        Ok(listener as RawFd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::c_void;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::fd::RawFd;
    use std::ptr;

    use crate::seccomp_filters::X86_64_BOOTSTRAP;

    // =========================================================================
    // Small general-purpose FD wrapper
    // =========================================================================

    struct Fd {
        raw: RawFd,
    }

    impl Fd {
        unsafe fn from_raw(raw: RawFd) -> Self {
            debug_assert!(raw >= 0);
            Self { raw }
        }

        fn raw(&self) -> RawFd {
            self.raw
        }

        /// Give ownership of the FD to someone else.
        fn into_raw(mut self) -> RawFd {
            let raw = self.raw;
            self.raw = -1;
            raw
        }
    }

    impl Drop for Fd {
        fn drop(&mut self) {
            if self.raw >= 0 {
                unsafe {
                    libc::close(self.raw);
                }
            }
        }
    }

    // =========================================================================
    // Notification request/response allocation
    // =========================================================================

    struct NotificationBuffers {
        request: libc::seccomp_notif,
        response: libc::seccomp_notif_resp,
    }

    impl NotificationBuffers {
        fn new() -> io::Result<Self> {
            Ok(unsafe { zeroed() })
        }

        fn receive(&mut self, listener: RawFd) -> io::Result<&libc::seccomp_notif> {
            self.request = unsafe { zeroed() };
            let result =
                unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_RECV, &mut self.request) };
            check_syscall(result)?;
            Ok(&self.request)
        }

        fn respond_errno(
            &mut self,
            listener: RawFd,
            notification_id: u64,
            errno: libc::c_int,
        ) -> io::Result<()> {
            self.response.id = notification_id;
            self.response.val = 0;
            self.response.error = -errno;
            self.response.flags = 0;

            let result =
                unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_SEND, &self.response) };
            check_syscall(result)
        }
    }

    fn check_syscall(result: libc::c_int) -> io::Result<()> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    // =========================================================================
    // Unix socket FD transfer
    // =========================================================================

    fn socket_pair() -> io::Result<(Fd, Fd)> {
        let mut sockets = [-1; 2];

        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sockets.as_mut_ptr(),
            )
        };

        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(unsafe { (Fd::from_raw(sockets[0]), Fd::from_raw(sockets[1])) })
    }

    /// Send one FD through a Unix-domain socket using SCM_RIGHTS.
    ///
    /// This function deliberately performs no heap allocation. That matters
    /// because it runs after the child has installed its restrictive filter.
    unsafe fn send_fd(socket: RawFd, fd: RawFd) -> io::Result<()> {
        let mut payload = [0_u8; 1];

        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast::<c_void>(),
            iov_len: payload.len(),
        };

        // One FD requires only a small control message. Keep extra room to
        // avoid relying on CMSG_SPACE being usable in an array-length constant.
        let mut control = [0_u8; 64];

        let mut message: libc::msghdr = unsafe { zeroed() };

        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast::<c_void>();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as usize };

        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };

        if header.is_null() {
            return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
        }

        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;

            ptr::write(libc::CMSG_DATA(header).cast::<libc::c_int>(), fd);
        }

        // Call the syscall directly so the operation is unambiguous under
        // seccomp.
        let result = unsafe {
            libc::syscall(
                libc::SYS_sendmsg,
                socket,
                &message as *const libc::msghdr,
                0,
            )
        };

        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn receive_fd(socket: RawFd) -> io::Result<Fd> {
        let mut payload = [0_u8; 1];

        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast::<c_void>(),
            iov_len: payload.len(),
        };

        let mut control = [0_u8; 64];

        let mut message: libc::msghdr = unsafe { zeroed() };

        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast::<c_void>();
        message.msg_controllen = control.len();

        let result = unsafe { libc::recvmsg(socket, &mut message, 0) };

        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "child closed the socket without sending an FD",
            ));
        }

        if message.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::other("SCM_RIGHTS control message was truncated"));
        }

        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };

        if header.is_null() {
            return Err(io::Error::other("message contained no control data"));
        }

        let valid_header = unsafe {
            (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && (*header).cmsg_len >= libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize
        };

        if !valid_header {
            return Err(io::Error::other("message did not contain an SCM_RIGHTS FD"));
        }

        let received = unsafe { ptr::read(libc::CMSG_DATA(header).cast::<libc::c_int>()) };

        if received < 0 {
            return Err(io::Error::other("received an invalid FD"));
        }

        Ok(unsafe { Fd::from_raw(received) })
    }

    // =========================================================================
    // Child setup
    // =========================================================================

    unsafe fn replace_standard_fds() -> io::Result<()> {
        let null_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };

        if null_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if unsafe { libc::dup2(null_fd, target) } < 0 {
                let error = io::Error::last_os_error();

                unsafe {
                    libc::close(null_fd);
                }

                return Err(error);
            }
        }

        if null_fd > libc::STDERR_FILENO {
            unsafe {
                libc::close(null_fd);
            }
        }

        Ok(())
    }

    /// Close all FDs >= 3 except for `keep`.
    ///
    /// This runs before seccomp is installed, so close_range itself does not
    /// need to be part of the sandbox policy.
    unsafe fn close_all_except(keep: RawFd) -> io::Result<()> {
        assert!(keep >= 3);

        if keep > 3 {
            let result =
                unsafe { libc::syscall(libc::SYS_close_range, 3_u32, (keep - 1) as u32, 0_u32) };

            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let result =
            unsafe { libc::syscall(libc::SYS_close_range, (keep + 1) as u32, u32::MAX, 0_u32) };

        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Install the test policy.
    ///
    /// sendmsg is the sole bootstrap exception. The child needs it once to
    /// transfer the listener FD to the parent.
    fn install_test_filter() -> io::Result<RawFd> {
        install_filter(&X86_64_BOOTSTRAP)
    }

    /// Exit without invoking Rust destructors or libc shutdown machinery.
    unsafe fn child_exit(status: libc::c_int) -> ! {
        unsafe {
            libc::syscall(libc::SYS_exit_group, status);
        }

        unreachable!()
    }

    // =========================================================================
    // Test
    // =========================================================================

    #[test]
    fn openat_is_delivered_to_parent() {
        let (parent_socket, child_socket) = socket_pair().expect("socketpair failed");

        let child_pid = unsafe { libc::fork() };

        assert!(
            child_pid >= 0,
            "fork failed: {}",
            io::Error::last_os_error(),
        );

        if child_pid == 0 {
            // Do not run ordinary Rust test-framework cleanup in this process.
            let parent_socket_fd = parent_socket.into_raw();
            let child_socket_fd = child_socket.into_raw();

            unsafe {
                libc::close(parent_socket_fd);

                if replace_standard_fds().is_err() {
                    child_exit(10);
                }

                if close_all_except(child_socket_fd).is_err() {
                    child_exit(11);
                }
            }

            // Construct the pathname before loading the filter. CString,
            // formatting, panic handling, and allocation must not run after
            // the restrictive filter is active.
            let path = c"/definitely/not/a/real/seccomp-test-file";

            let listener = match install_test_filter() {
                Ok(value) => value,
                Err(_) => unsafe {
                    child_exit(12);
                },
            };

            if unsafe { send_fd(child_socket_fd, listener) }.is_err() {
                unsafe {
                    child_exit(13);
                }
            }

            // This syscall should block and become visible to the parent.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    libc::O_RDONLY,
                    0,
                )
            };

            // Parent responds with -ENOENT, so openat must return -1 and set
            // errno to ENOENT.
            if result != -1 {
                unsafe {
                    child_exit(14);
                }
            }

            let errno = io::Error::last_os_error().raw_os_error();

            if errno != Some(libc::ENOENT) {
                unsafe {
                    child_exit(15);
                }
            }

            unsafe {
                child_exit(0);
            }
        }

        // Parent retains only its end of the bootstrap socket.
        drop(child_socket);

        let listener =
            receive_fd(parent_socket.raw()).expect("failed to receive seccomp listener FD");

        let mut buffers =
            NotificationBuffers::new().expect("failed to allocate notification buffers");

        let (notification_id, syscall_number, notifying_pid) = {
            let request = buffers
                .receive(listener.raw())
                .expect("failed to receive seccomp notification");

            (
                request.id,
                request.data.nr as libc::c_long,
                request.pid as libc::pid_t,
            )
        };

        assert_eq!(notifying_pid, child_pid);
        assert_eq!(syscall_number, libc::SYS_openat);

        buffers
            .respond_errno(listener.raw(), notification_id, libc::ENOENT)
            .expect("failed to respond to seccomp notification");

        let mut status = 0;

        let waited = unsafe { libc::waitpid(child_pid, &mut status, 0) };

        assert_eq!(
            waited,
            child_pid,
            "waitpid failed: {}",
            io::Error::last_os_error(),
        );

        assert!(
            libc::WIFEXITED(status),
            "child did not exit normally; wait status = {status:#x}",
        );

        assert_eq!(libc::WEXITSTATUS(status), 0, "child reported test failure",);
    }
}
