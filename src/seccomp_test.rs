use std::io;
use std::os::fd::RawFd;
use std::ptr::NonNull;

use libseccomp_sys::{
    scmp_filter_ctx,
    seccomp_init,
    seccomp_load,
    seccomp_notify_fd,
    seccomp_release,
    seccomp_rule_add_array,
    SCMP_ACT_ALLOW,
    SCMP_ACT_KILL_PROCESS,
    SCMP_ACT_NOTIFY,
};

pub struct FilterContext {
    ptr: NonNull<std::ffi::c_void>,
}

impl FilterContext {
    pub fn new(default_action: u32) -> io::Result<Self> {
        let ptr = unsafe { seccomp_init(default_action) };

        let ptr = NonNull::new(ptr)
            .ok_or_else(|| io::Error::other("seccomp_init failed"))?;

        Ok(Self { ptr })
    }

    pub fn as_raw(&self) -> scmp_filter_ctx {
        self.ptr.as_ptr()
    }

    pub fn add_rule(&mut self, syscall: libc::c_long, action: u32) -> io::Result<()> {
        // Use the array form because Rust cannot conveniently call the
        // variadic seccomp_rule_add() function.
        let result = unsafe {
            seccomp_rule_add_array(
                self.as_raw(),
                action,
                syscall as libc::c_int,
                0,
                std::ptr::null(),
            )
        };

        seccomp_result(result)
    }

    pub fn load(&mut self) -> io::Result<()> {
        let result = unsafe { seccomp_load(self.as_raw()) };
        seccomp_result(result)
    }

    pub fn notify_fd(&self) -> io::Result<RawFd> {
        let fd = unsafe { seccomp_notify_fd(self.as_raw()) };

        if fd < 0 {
            Err(io::Error::from_raw_os_error(-fd))
        } else {
            Ok(fd)
        }
    }
}

impl Drop for FilterContext {
    fn drop(&mut self) {
        unsafe {
            seccomp_release(self.as_raw());
        }
    }
}

/// Libseccomp returns zero for success and negative errno values for failure.
fn seccomp_result(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::from_raw_os_error(-result))
    } else {
        Ok(())
    }
}

/// Install this filter:
///
/// - open/openat/openat2/read/write/close -> USER_NOTIF
/// - exit/exit_group                     -> ALLOW
/// - everything else                    -> KILL_PROCESS
pub fn install_seccomp_filter() -> io::Result<(FilterContext, RawFd)> {
    let mut filter = FilterContext::new(SCMP_ACT_KILL_PROCESS)?;

    for syscall in [
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
    ] {
        filter.add_rule(syscall, SCMP_ACT_NOTIFY)?;
    }

    for syscall in [
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        filter.add_rule(syscall, SCMP_ACT_ALLOW)?;
    }

    filter.load()?;

    let listener = filter.notify_fd()?;

    Ok((filter, listener))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::c_void;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::fd::RawFd;
    use std::ptr;

    use libseccomp_sys::{
        seccomp_notif,
        seccomp_notif_resp,
        seccomp_notify_alloc,
        seccomp_notify_free,
        seccomp_notify_receive,
        seccomp_notify_respond,
        SCMP_ACT_ALLOW,
        SCMP_ACT_KILL_PROCESS,
        SCMP_ACT_NOTIFY,
    };

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

    /// Owns the correctly sized libseccomp notification buffers.
    ///
    /// These must be allocated through seccomp_notify_alloc(). Stack-allocating
    /// `seccomp_notif` directly can produce EOPNOTSUPP because the structure
    /// size expected by the running kernel may differ from the Rust binding.
    struct NotificationBuffers {
        request: *mut seccomp_notif,
        response: *mut seccomp_notif_resp,
    }

    impl NotificationBuffers {
        fn new() -> io::Result<Self> {
            let mut request = ptr::null_mut();
            let mut response = ptr::null_mut();

            let result = unsafe {
                seccomp_notify_alloc(&mut request, &mut response)
            };

            check_libseccomp(result)?;

            if request.is_null() || response.is_null() {
                unsafe {
                    seccomp_notify_free(request, response);
                }

                return Err(io::Error::other(
                    "seccomp_notify_alloc returned a null pointer",
                ));
            }

            Ok(Self {
                request,
                response,
            })
        }

        fn receive(&mut self, listener: RawFd) -> io::Result<&seccomp_notif> {
            let result = unsafe {
                seccomp_notify_receive(listener, self.request)
            };

            check_libseccomp(result)?;

            Ok(unsafe { &*self.request })
        }

        fn respond_errno(
            &mut self,
            listener: RawFd,
            notification_id: u64,
            errno: libc::c_int,
        ) -> io::Result<()> {
            let response = unsafe { &mut *self.response };

            response.id = notification_id;
            response.val = 0;
            response.error = -errno;
            response.flags = 0;

            let result = unsafe {
                seccomp_notify_respond(listener, self.response)
            };

            check_libseccomp(result)
        }
    }

    impl Drop for NotificationBuffers {
        fn drop(&mut self) {
            unsafe {
                seccomp_notify_free(self.request, self.response);
            }
        }
    }

    fn check_libseccomp(result: libc::c_int) -> io::Result<()> {
        if result < 0 {
            Err(io::Error::from_raw_os_error(-result))
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

        Ok(unsafe {
            (
                Fd::from_raw(sockets[0]),
                Fd::from_raw(sockets[1]),
            )
        })
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
            libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as usize;

        let header = unsafe {
            libc::CMSG_FIRSTHDR(&message)
        };

        if header.is_null() {
            return Err(io::Error::other(
                "CMSG_FIRSTHDR returned null",
            ));
        }

        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;

            ptr::write(
                libc::CMSG_DATA(header).cast::<libc::c_int>(),
                fd,
            );
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

        let result = unsafe {
            libc::recvmsg(socket, &mut message, 0)
        };

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
            return Err(io::Error::other(
                "SCM_RIGHTS control message was truncated",
            ));
        }

        let header = unsafe {
            libc::CMSG_FIRSTHDR(&message)
        };

        if header.is_null() {
            return Err(io::Error::other(
                "message contained no control data",
            ));
        }

        let valid_header = unsafe {
            (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && (*header).cmsg_len
                    >= libc::CMSG_LEN(
                        size_of::<libc::c_int>() as u32,
                    ) as usize
        };

        if !valid_header {
            return Err(io::Error::other(
                "message did not contain an SCM_RIGHTS FD",
            ));
        }

        let received = unsafe {
            ptr::read(
                libc::CMSG_DATA(header).cast::<libc::c_int>(),
            )
        };

        if received < 0 {
            return Err(io::Error::other(
                "received an invalid FD",
            ));
        }

        Ok(unsafe { Fd::from_raw(received) })
    }

    // =========================================================================
    // Child setup
    // =========================================================================

    unsafe fn replace_standard_fds() -> io::Result<()> {
        let null_fd = unsafe {
            libc::open(
                c"/dev/null".as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };

        if null_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        for target in [
            libc::STDIN_FILENO,
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
        ] {
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
            let result = unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    (keep - 1) as u32,
                    0_u32,
                )
            };

            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let result = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                (keep + 1) as u32,
                u32::MAX,
                0_u32,
            )
        };

        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Install the test policy.
    ///
    /// sendmsg is the sole bootstrap exception. The child needs it once to
    /// transfer the listener FD to the parent.
    fn install_test_filter() -> io::Result<(FilterContext, RawFd)> {
        let mut filter =
            FilterContext::new(SCMP_ACT_KILL_PROCESS)?;

        for syscall in [
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_openat2,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_close,
        ] {
            filter.add_rule(syscall, SCMP_ACT_NOTIFY)?;
        }

        for syscall in [
            libc::SYS_sendmsg,
            libc::SYS_exit,
            libc::SYS_exit_group,
        ] {
            filter.add_rule(syscall, SCMP_ACT_ALLOW)?;
        }

        filter.load()?;

        let listener = filter.notify_fd()?;

        Ok((filter, listener))
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
        let (parent_socket, child_socket) =
            socket_pair().expect("socketpair failed");

        let child_pid = unsafe {
            libc::fork()
        };

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

            let (filter, listener) = match install_test_filter() {
                Ok(value) => value,
                Err(_) => unsafe {
                    child_exit(12);
                },
            };

            // The filter context owns userspace allocations. Dropping it after
            // loading this policy might cause allocator syscalls such as
            // munmap, so deliberately leave it allocated until process exit.
            std::mem::forget(filter);

            if unsafe {
                send_fd(child_socket_fd, listener)
            }
            .is_err()
            {
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

        let listener = receive_fd(parent_socket.raw())
            .expect("failed to receive seccomp listener FD");

        let mut buffers = NotificationBuffers::new()
            .expect("failed to allocate notification buffers");

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
            .respond_errno(
                listener.raw(),
                notification_id,
                libc::ENOENT,
            )
            .expect("failed to respond to seccomp notification");

        let mut status = 0;

        let waited = unsafe {
            libc::waitpid(child_pid, &mut status, 0)
        };

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

        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child reported test failure",
        );
    }
}