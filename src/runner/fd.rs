use crate::MOCK_FD_BASE;
use foldhash::HashMap;
use std::io;
use std::os::fd::{BorrowedFd, RawFd};
use std::sync::Arc;

use crate::MockFd;
use crate::runner::Tracker;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildFile {
    Real,
    Mock(MockFd),
}

#[derive(Debug)]
pub struct CantAllocate;

/// Models the file table of one child process.
///
/// Changes require exclusive access. A syscall continued while shared access
/// is held must not be able to change the file table. Process creation keeps a
/// shared borrow until the kernel reports the fork result, synchronizing the
/// modeled snapshot with the kernel's file-table snapshot.
pub trait ProcFileSpace: Clone {
    fn lookup_fd(&self, fd: RawFd) -> Option<ChildFile>;

    /// Installs a real FD into the child, records it, and answers the
    /// intercepted syscall with the child FD.
    fn respond_real(
        &mut self,
        backing: BorrowedFd<'_>,
        tracker: &Tracker,
        req: &libc::seccomp_notif,
    ) -> io::Result<()>;

    /// Installs the backing FD for `mock` into the child, records it,
    /// and answers the intercepted syscall with the child FD.
    fn respond_mock(
        &mut self,
        mock: MockFd,
        backing: BorrowedFd<'_>,
        tracker: &Tracker,
        req: &libc::seccomp_notif,
    ) -> io::Result<()>;

    /// Removes a file from our records.
    fn remove_file(&mut self, fd: RawFd) -> Option<ChildFile>;
}

#[derive(Debug, Default, Clone)]
pub struct RangeFileSpace;

impl RangeFileSpace {
    #[inline]
    fn mock_fd(mock: MockFd) -> Result<RawFd, CantAllocate> {
        let fd = MOCK_FD_BASE
            .checked_add(mock.0 as u64)
            .ok_or(CantAllocate)?;

        RawFd::try_from(fd).map_err(|_| CantAllocate)
    }

    #[inline]
    fn decode_mock(fd: RawFd) -> Option<MockFd> {
        if fd < 0 {
            return None;
        }

        let fd = fd as u64;

        if fd < MOCK_FD_BASE {
            return None;
        }

        let mock = fd - MOCK_FD_BASE;
        let mock = u32::try_from(mock).ok()?;

        Some(MockFd(mock))
    }
}

impl ProcFileSpace for RangeFileSpace {
    fn lookup_fd(&self, fd: RawFd) -> Option<ChildFile> {
        if fd < 0 {
            return None;
        }

        match Self::decode_mock(fd) {
            Some(mock) => Some(ChildFile::Mock(mock)),
            None => Some(ChildFile::Real),
        }
    }

    fn respond_real(
        &mut self,
        backing: BorrowedFd<'_>,
        tracker: &Tracker,
        req: &libc::seccomp_notif,
    ) -> io::Result<()> {
        let fd = tracker
            .add_fd(req, backing, false)
            .map_err(io::Error::from_raw_os_error)?;

        // Real FDs must remain below the range reserved for mocks.
        if fd as u64 >= MOCK_FD_BASE {
            return tracker
                .respond_errno(req, libc::EMFILE)
                .map_err(io::Error::from_raw_os_error);
        }

        tracker
            .respond(req, fd as i64)
            .map_err(io::Error::from_raw_os_error)
    }

    fn respond_mock(
        &mut self,
        mock: MockFd,
        backing: BorrowedFd<'_>,
        tracker: &Tracker,
        req: &libc::seccomp_notif,
    ) -> io::Result<()> {
        let target_fd =
            Self::mock_fd(mock).map_err(|_| io::Error::from_raw_os_error(libc::EMFILE))?;

        tracker
            .add_fd_at(req, backing, target_fd, false)
            .map_err(io::Error::from_raw_os_error)?;

        tracker
            .respond(req, target_fd as i64)
            .map_err(io::Error::from_raw_os_error)
    }

    fn remove_file(&mut self, fd: RawFd) -> Option<ChildFile> {
        self.lookup_fd(fd)
    }
}

#[derive(Debug, Default, Clone)]
pub struct MappedFileSpace {
    files: Arc<HashMap<RawFd, ChildFile>>,
}

impl MappedFileSpace {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProcFileSpace for MappedFileSpace {
    fn lookup_fd(&self, fd: RawFd) -> Option<ChildFile> {
        self.files.get(&fd).copied()
    }

    fn respond_real(
        &mut self,
        backing: BorrowedFd<'_>,
        tracker: &Tracker,
        req: &libc::seccomp_notif,
    ) -> io::Result<()> {
        let fd = tracker
            .add_fd(req, backing, false)
            .map_err(io::Error::from_raw_os_error)?;

        Arc::make_mut(&mut self.files).insert(fd, ChildFile::Real);

        tracker
            .respond(req, fd as i64)
            .map_err(io::Error::from_raw_os_error)
    }

    fn respond_mock(
        &mut self,
        mock: MockFd,
        backing: BorrowedFd<'_>,
        tracker: &Tracker,
        req: &libc::seccomp_notif,
    ) -> io::Result<()> {
        let fd = tracker
            .add_fd(req, backing, false)
            .map_err(io::Error::from_raw_os_error)?;

        Arc::make_mut(&mut self.files).insert(fd, ChildFile::Mock(mock));

        tracker
            .respond(req, fd as i64)
            .map_err(io::Error::from_raw_os_error)
    }

    fn remove_file(&mut self, fd: RawFd) -> Option<ChildFile> {
        Arc::make_mut(&mut self.files).remove(&fd)
    }
}
