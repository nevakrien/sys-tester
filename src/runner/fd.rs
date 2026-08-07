use crate::MockFd;
use std::os::fd::RawFd;

pub enum ChildFile {
    Real,
    Mock(MockFd),
}

pub trait ProcFileSpace {
    fn lookup_fd(&self, fd: RawFd) -> Option<ChildFile>;
    fn add_mock(&mut self, mock: MockFd) -> RawFd;
    fn close_file(&mut self, fd: RawFd) -> bool;
}
