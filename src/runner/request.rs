use super::MockFd;
use crate::{AtomData, Text};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum AtomReq {
    Open(Text),
    Read(MockFd, usize),
    Write(MockFd, Text),
    Close(MockFd),
}

impl AtomReq {
    pub fn new(atom: &AtomData) -> Option<Self> {
        Some(match *atom {
            AtomData::Open(path) => Self::Open(path),
            AtomData::Read(open, _expected, size) => Self::Read(MockFd(open), size),
            AtomData::Write(open, text, _size) => Self::Write(MockFd(open), text),
            AtomData::Close(open) => Self::Close(MockFd(open)),
            AtomData::DebugName(_) => return None,
        })
    }
}
