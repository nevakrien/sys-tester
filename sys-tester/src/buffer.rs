use std::mem::transmute;
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::ptr::copy_nonoverlapping;
use std::{error, fmt, io};

pub const MAX_PATH: usize = libc::PATH_MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathTooLong;

impl fmt::Display for PathTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("path exceeds PATH_MAX")
    }
}

impl error::Error for PathTooLong {}

#[derive(Debug)]
pub enum ProcessCopyError {
    /// The supervised process supplied invalid syscall arguments.
    Errno(libc::c_int),
    /// Copying failed for a reason not attributable to those arguments.
    Io(io::Error),
}

impl fmt::Display for ProcessCopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Errno(errno) => io::Error::from_raw_os_error(*errno).fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl error::Error for ProcessCopyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Errno(_) => None,
            Self::Io(error) => Some(error),
        }
    }
}

#[repr(C, align(4096))]
struct Page {
    bytes: [MaybeUninit<u8>; MAX_PATH],
}

// This buffer is specifically for platforms where PATH_MAX is one page.
const _: () = assert!(size_of::<Page>() == MAX_PATH);
const _: () = assert!(align_of::<Page>() == MAX_PATH);

/// Page-aligned scratch storage that always owns at least one `PATH_MAX` page.
///
/// Path operations are restricted to the first page. General byte operations
/// grow the allocation in whole pages as needed.
pub struct PageBuffer {
    pages: Box<[Page]>,
    len: usize,
}

impl Default for PageBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for PageBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len) }
    }
}

impl DerefMut for PageBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len) }
    }
}

impl PageBuffer {
    pub fn new() -> Self {
        Self {
            pages: allocate_pages(1),
            len: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.pages.len() * MAX_PATH
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.pages.as_ptr().cast()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.pages.as_mut_ptr().cast()
    }

    pub fn truncate(&mut self, len: usize) {
        if len >= self.len {
            return;
        }

        unsafe {
            let bytes = self.as_mut_ptr().cast::<MaybeUninit<u8>>();
            for index in len..self.capacity() {
                bytes.add(index).write(MaybeUninit::uninit());
            }
        }
        self.len = len;
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }

    pub fn set_path(&mut self, path: &[u8]) -> Result<(), PathTooLong> {
        if path.len() > MAX_PATH {
            return Err(PathTooLong);
        }

        self.clear();
        unsafe {
            copy_nonoverlapping(path.as_ptr(), self.as_mut_ptr(), path.len());
        }
        self.len = path.len();
        Ok(())
    }

    pub fn set_bytes(&mut self, bytes: &[u8]) {
        self.clear();
        self.ensure_capacity(bytes.len());
        unsafe {
            copy_nonoverlapping(bytes.as_ptr(), self.as_mut_ptr(), bytes.len());
        }
        self.len = bytes.len();
    }

    /// Copies an explicitly sized pathname from another process.
    pub fn copy_from_process_path_with_len(
        &mut self,
        pid: libc::pid_t,
        address: u64,
        len: usize,
    ) -> Result<&[u8], ProcessCopyError> {
        if len > MAX_PATH {
            return Err(ProcessCopyError::Errno(libc::ENAMETOOLONG));
        }

        let mut result = Ok(());
        unsafe {
            self.write_path_with(|destination| {
                copy_process_memory(pid, address, destination, len, &mut result)
            });
        }
        result?;
        Ok(self)
    }

    /// Copies a NUL-terminated pathname from another process.
    ///
    /// The returned slice excludes the NUL. Linux reserves one byte of
    /// `PATH_MAX` for the terminator, so a missing NUL produces `ENAMETOOLONG`.
    pub fn copy_from_process_c_path(
        &mut self,
        pid: libc::pid_t,
        address: u64,
    ) -> Result<&[u8], ProcessCopyError> {
        self.clear();
        self.len = unsafe { read_process_c_path(pid, address, self.as_mut_ptr())? };
        Ok(self)
    }

    /// Copies exactly `len` bytes from another process.
    pub fn copy_from_process_bytes(
        &mut self,
        pid: libc::pid_t,
        address: u64,
        len: usize,
    ) -> Result<&[u8], ProcessCopyError> {
        let mut result = Ok(());
        unsafe {
            self.write_bytes_with(len, |destination| {
                copy_process_memory(pid, address, destination, len, &mut result)
            });
        }
        result?;
        Ok(self)
    }

    /// Writes a path into the first page of the buffer.
    ///
    /// # Safety
    ///
    /// The closure must initialize every byte before the returned length and
    /// must neither write nor return a length greater than [`MAX_PATH`].
    pub unsafe fn write_path_with(&mut self, write: impl FnOnce(*mut u8) -> usize) {
        self.clear();
        let len = write(self.as_mut_ptr());
        self.len = len;
    }

    /// Grows the buffer for `capacity` bytes, then writes general data into it.
    ///
    /// # Safety
    ///
    /// The closure must initialize every byte before the returned length and
    /// must neither write nor return a length greater than `capacity`.
    pub unsafe fn write_bytes_with(
        &mut self,
        capacity: usize,
        write: impl FnOnce(*mut u8) -> usize,
    ) {
        self.clear();
        self.ensure_capacity(capacity);
        let len = write(self.as_mut_ptr());
        self.len = len;
    }

    pub fn truncate_at_nul(&mut self) {
        if let Some(nul) = self.iter().position(|&byte| byte == 0) {
            self.truncate(nul);
        }
    }

    fn ensure_capacity(&mut self, capacity: usize) {
        if capacity <= self.capacity() {
            return;
        }

        let page_count = capacity.div_ceil(MAX_PATH);
        let mut pages = allocate_pages(page_count);
        unsafe {
            copy_nonoverlapping(self.as_ptr(), pages.as_mut_ptr().cast(), self.len);
        }
        self.pages = pages;
    }
}

fn copy_process_memory(
    pid: libc::pid_t,
    address: u64,
    destination: *mut u8,
    len: usize,
    result: &mut Result<(), ProcessCopyError>,
) -> usize {
    match unsafe { read_process_memory(pid, address, destination, len) } {
        Ok(read) => read,
        Err(error) => {
            *result = Err(error);
            0
        }
    }
}

unsafe fn read_process_memory(
    pid: libc::pid_t,
    address: u64,
    destination: *mut u8,
    len: usize,
) -> Result<usize, ProcessCopyError> {
    let mut copied = 0;

    while copied < len {
        let read = unsafe {
            read_process_memory_once(pid, address, destination.add(copied), copied, len - copied)?
        };
        copied += read;
    }

    Ok(copied)
}

unsafe fn read_process_c_path(
    pid: libc::pid_t,
    address: u64,
    destination: *mut u8,
) -> Result<usize, ProcessCopyError> {
    let mut copied = 0;

    while copied < MAX_PATH {
        let remote_address = usize::try_from(address)
            .ok()
            .and_then(|address| address.checked_add(copied))
            .ok_or(ProcessCopyError::Errno(libc::EFAULT))?;
        let page_remaining = MAX_PATH - remote_address % MAX_PATH;
        let len = page_remaining.min(MAX_PATH - copied);
        let read = unsafe {
            read_process_memory_once(pid, address, destination.add(copied), copied, len)?
        };
        let bytes = unsafe { std::slice::from_raw_parts(destination.add(copied), read) };

        if let Some(nul) = bytes.iter().position(|&byte| byte == 0) {
            return Ok(copied + nul);
        }
        copied += read;
    }

    Err(ProcessCopyError::Errno(libc::ENAMETOOLONG))
}

unsafe fn read_process_memory_once(
    pid: libc::pid_t,
    address: u64,
    destination: *mut u8,
    offset: usize,
    len: usize,
) -> Result<usize, ProcessCopyError> {
    let remote_address = usize::try_from(address)
        .ok()
        .and_then(|address| address.checked_add(offset))
        .filter(|address| address.checked_add(len).is_some())
        .ok_or(ProcessCopyError::Errno(libc::EFAULT))?;
    let local = libc::iovec {
        iov_base: destination.cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: remote_address as *mut libc::c_void,
        iov_len: len,
    };
    let read = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };

    if read < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EFAULT) {
            Err(ProcessCopyError::Errno(libc::EFAULT))
        } else {
            Err(ProcessCopyError::Io(error))
        }
    } else if read == 0 && len != 0 {
        Err(ProcessCopyError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "process_vm_readv copied no data",
        )))
    } else {
        Ok(read as usize)
    }
}

fn allocate_pages(count: usize) -> Box<[Page]> {
    let pages = Box::<[Page]>::new_uninit_slice(count);
    // Every bit pattern is valid because Page contains only MaybeUninit bytes.
    unsafe { transmute(pages) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_one_aligned_page() {
        let buffer = PageBuffer::new();

        assert_eq!(buffer.capacity(), MAX_PATH);
        assert_eq!((buffer.as_ptr() as usize) % MAX_PATH, 0);
        assert!(buffer.is_empty());
    }

    #[test]
    fn path_operations_stay_within_path_max() {
        let mut buffer = PageBuffer::new();

        buffer.set_path(b"some/path\0ignored").unwrap();
        assert_eq!(&*buffer, b"some/path\0ignored");

        buffer.truncate_at_nul();
        assert_eq!(&*buffer, b"some/path");

        buffer.truncate(4);
        assert_eq!(&*buffer, b"some");

        buffer.clear();
        assert!(buffer.is_empty());

        assert_eq!(buffer.set_path(&[0; MAX_PATH + 1]), Err(PathTooLong));
        assert!(buffer.is_empty());
    }

    #[test]
    fn general_operations_grow_in_aligned_pages() {
        let mut buffer = PageBuffer::new();
        let bytes = vec![42; MAX_PATH + 1];

        buffer.set_bytes(&bytes);

        assert_eq!(buffer.capacity(), MAX_PATH * 2);
        assert_eq!((buffer.as_ptr() as usize) % MAX_PATH, 0);
        assert_eq!(&*buffer, bytes);
    }

    #[test]
    fn closure_writes_have_distinct_path_and_byte_capacities() {
        let mut buffer = PageBuffer::new();

        unsafe {
            buffer.write_path_with(|destination| {
                copy_nonoverlapping(b"path".as_ptr(), destination, 4);
                4
            });
        }
        assert_eq!(&*buffer, b"path");

        unsafe {
            buffer.write_bytes_with(MAX_PATH + 8, |destination| {
                destination.write_bytes(7, MAX_PATH + 8);
                MAX_PATH + 8
            });
        }
        assert_eq!(buffer.capacity(), MAX_PATH * 2);
        assert_eq!(buffer.len(), MAX_PATH + 8);
        assert!(buffer.iter().all(|&byte| byte == 7));
    }

    #[cfg(not(miri))]
    mod process_copy {
        use super::*;

        #[test]
        fn copies_explicitly_sized_paths_and_bytes() {
            let path = b"path\0after";
            let bytes = vec![42; MAX_PATH + 1];
            let mut buffer = PageBuffer::new();
            let pid = unsafe { libc::getpid() };

            let copied = buffer
                .copy_from_process_path_with_len(pid, path.as_ptr() as u64, path.len())
                .unwrap();
            assert_eq!(copied, path);

            let copied = buffer
                .copy_from_process_bytes(pid, bytes.as_ptr() as u64, bytes.len())
                .unwrap();
            assert_eq!(copied, bytes);
        }

        #[test]
        fn rejects_an_explicit_path_larger_than_path_max() {
            let mut buffer = PageBuffer::new();
            let error = buffer
                .copy_from_process_path_with_len(unsafe { libc::getpid() }, 0, MAX_PATH + 1)
                .unwrap_err();

            assert!(matches!(error, ProcessCopyError::Errno(libc::ENAMETOOLONG)));
        }

        #[test]
        fn copies_c_paths_without_the_nul() {
            let path = b"some/path\0ignored";
            let mut buffer = PageBuffer::new();

            let copied = buffer
                .copy_from_process_c_path(unsafe { libc::getpid() }, path.as_ptr() as u64)
                .unwrap();

            assert_eq!(copied, b"some/path");
        }

        #[test]
        fn rejects_c_paths_without_a_nul_in_path_max() {
            let path = [b'x'; MAX_PATH];
            let mut buffer = PageBuffer::new();
            let error = buffer
                .copy_from_process_c_path(unsafe { libc::getpid() }, path.as_ptr() as u64)
                .unwrap_err();

            assert!(matches!(error, ProcessCopyError::Errno(libc::ENAMETOOLONG)));
        }

        #[test]
        fn reports_an_invalid_remote_address_as_caller_errno() {
            let mut buffer = PageBuffer::new();
            let error = buffer
                .copy_from_process_bytes(unsafe { libc::getpid() }, 0, 1)
                .unwrap_err();

            assert!(matches!(error, ProcessCopyError::Errno(libc::EFAULT)));
        }

        #[test]
        fn c_path_stops_before_the_next_unmapped_page() {
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    MAX_PATH * 2,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);

            let second_page = unsafe { mapping.cast::<u8>().add(MAX_PATH) };
            let path = b"path\0";
            let address = unsafe { second_page.sub(path.len()) };
            unsafe {
                copy_nonoverlapping(path.as_ptr(), address, path.len());
                assert_eq!(libc::munmap(second_page.cast(), MAX_PATH), 0);
            }

            let mut buffer = PageBuffer::new();
            let result = buffer.copy_from_process_c_path(unsafe { libc::getpid() }, address as u64);
            let unmap_result = unsafe { libc::munmap(mapping, MAX_PATH) };

            assert_eq!(unmap_result, 0);
            assert_eq!(result.unwrap(), b"path");
        }

        #[test]
        fn c_path_reports_an_unmapped_page_before_its_terminator() {
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    MAX_PATH * 2,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);

            let second_page = unsafe { mapping.cast::<u8>().add(MAX_PATH) };
            unsafe {
                second_page.sub(4).write_bytes(b'x', 4);
                assert_eq!(libc::munmap(second_page.cast(), MAX_PATH), 0);
            }

            let mut buffer = PageBuffer::new();
            let error = buffer
                .copy_from_process_c_path(unsafe { libc::getpid() }, unsafe { second_page.sub(4) }
                    as u64)
                .unwrap_err();
            let unmap_result = unsafe { libc::munmap(mapping, MAX_PATH) };

            assert_eq!(unmap_result, 0);
            assert!(matches!(error, ProcessCopyError::Errno(libc::EFAULT)));
        }

        #[test]
        fn preserves_unrelated_kernel_failures_as_io_errors() {
            let mut buffer = PageBuffer::new();
            let byte = 0_u8;
            let error = buffer
                .copy_from_process_bytes(-1, &byte as *const u8 as u64, 1)
                .unwrap_err();

            assert!(
                matches!(error, ProcessCopyError::Io(error) if error.raw_os_error() == Some(libc::ESRCH))
            );
        }

        #[test]
        fn accepts_the_longest_c_path() {
            let mut path = [b'x'; MAX_PATH];
            path[MAX_PATH - 1] = 0;
            let mut buffer = PageBuffer::new();
            let copied = buffer
                .copy_from_process_c_path(unsafe { libc::getpid() }, path.as_ptr() as u64)
                .unwrap();

            assert_eq!(copied.len(), MAX_PATH - 1);
            assert!(copied.iter().all(|&byte| byte == b'x'));
        }
    }
}
