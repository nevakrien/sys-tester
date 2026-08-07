use std::io;

#[inline]
pub(super) fn get() -> libc::c_int {
    // This runner is Linux-only.
    unsafe { *libc::__errno_location() }
}

#[inline]
pub(super) fn set(error: libc::c_int) {
    unsafe { *libc::__errno_location() = error };
}

pub(super) fn normalize(error: libc::c_int) -> libc::c_int {
    if error > 0 {
        error
    } else if error < 0 {
        -error
    } else {
        libc::EIO
    }
}

pub(super) fn from_io(error: &io::Error) -> libc::c_int {
    error.raw_os_error().unwrap_or(libc::EIO)
}
