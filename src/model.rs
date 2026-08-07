use crate::graph::VecGraph;
use foldhash::HashMap;
use std::net::SocketAddr;
use std::num::NonZero;

pub type Text = &'static str;
pub type ErrCode = Option<NonZero<u32>>;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct MockFd(pub u32);

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum ShutdownHow {
    Read,
    Write,
    Both,
}

#[derive(Debug, Clone, Copy)]
pub enum AtomData {
    Open(MockFd, Text),
    /// Creates an IPv4 or IPv6 TCP socket.
    TcpSocket(IpFamily),
    Bind(MockFd, SocketAddr),
    Listen(MockFd, i32),
    Connect(MockFd, SocketAddr),
    /// Accepts a connection and creates a new descriptor resource.
    Accept(MockFd),
    Shutdown(MockFd, ShutdownHow),

    Read(MockFd, Text, usize),  // text.len() <= size
    Write(MockFd, Text, usize), // size <= text.len()
    Close(MockFd),

    /// Gives a collection of atoms a name for clearer debug output.
    DebugName(Text),
}

#[derive(Debug, Clone, Copy)]
pub struct Atom {
    pub data: AtomData,
    pub error: ErrCode,
}

#[derive(Debug)]
pub enum Task {
    Atom(Atom),
    Ordered(Vec<u32>),
    Unordered(Vec<u32>),
}

#[derive(Debug, Default)]
pub struct TaskInfo {
    pub(crate) tasks: Vec<Task>,
    pub(crate) happens_before: HashMap<u32, Vec<u32>>,
    pub(crate) file_count: u32,
}

impl TaskInfo {
    pub fn new_file(&mut self) -> MockFd {
        let file = MockFd(self.file_count);
        self.file_count = self.file_count.checked_add(1).expect("too many files");
        file
    }
}

#[derive(Debug)]
pub struct CompiledSetup {
    pub(crate) atoms: Vec<Atom>,
    pub(crate) file_count: usize,
    /// Edges lead to atoms that execute after the source atom.
    pub(crate) after_graph: VecGraph<u32>,
    /// Edges lead to atoms that execute before the source atom.
    pub(crate) before_graph: VecGraph<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_file_allocates_dense_mock_fds() {
        let mut info = TaskInfo::default();

        assert_eq!(info.new_file(), MockFd(0));
        assert_eq!(info.new_file(), MockFd(1));
        assert_eq!(info.file_count, 2);
    }
}
