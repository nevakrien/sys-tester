use super::MockFd;
use crate::{AtomData, IpFamily, ShutdownHow, Text};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum AtomReq {
    Open(Text),
    TcpSocket(IpFamily),
    Bind(MockFd, SocketAddr),
    Listen(MockFd, i32),
    Connect(MockFd, SocketAddr),
    Accept(MockFd),
    Shutdown(MockFd, ShutdownHow),
    Read(MockFd, usize),
    Write(MockFd, Text),
    Close(MockFd),
}

impl AtomReq {
    pub fn new(atom: &AtomData) -> Option<Self> {
        Some(match *atom {
            AtomData::Open(_file, path) => Self::Open(path),
            AtomData::TcpSocket(family) => Self::TcpSocket(family),
            AtomData::Bind(socket, address) => Self::Bind(socket, address),
            AtomData::Listen(socket, backlog) => Self::Listen(socket, backlog),
            AtomData::Connect(socket, address) => Self::Connect(socket, address),
            AtomData::Accept(socket) => Self::Accept(socket),
            AtomData::Shutdown(socket, how) => Self::Shutdown(socket, how),
            AtomData::Read(open, _expected, size) => Self::Read(open, size),
            AtomData::Write(open, text, _size) => Self::Write(open, text),
            AtomData::Close(open) => Self::Close(open),
            AtomData::DebugName(_) => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_request_uses_path_while_atom_keeps_file() {
        assert_eq!(
            AtomReq::new(&AtomData::Open(MockFd(4), "/tmp/example")),
            Some(AtomReq::Open("/tmp/example"))
        );
    }

    #[test]
    fn converts_tcp_atoms_to_requests() {
        let address = SocketAddr::from(([127, 0, 0, 1], 8080));

        assert_eq!(
            AtomReq::new(&AtomData::TcpSocket(IpFamily::V4)),
            Some(AtomReq::TcpSocket(IpFamily::V4))
        );
        assert_eq!(
            AtomReq::new(&AtomData::Bind(MockFd(3), address)),
            Some(AtomReq::Bind(MockFd(3), address))
        );
        assert_eq!(
            AtomReq::new(&AtomData::Listen(MockFd(3), 128)),
            Some(AtomReq::Listen(MockFd(3), 128))
        );
        assert_eq!(
            AtomReq::new(&AtomData::Connect(MockFd(3), address)),
            Some(AtomReq::Connect(MockFd(3), address))
        );
        assert_eq!(
            AtomReq::new(&AtomData::Accept(MockFd(3))),
            Some(AtomReq::Accept(MockFd(3)))
        );
        assert_eq!(
            AtomReq::new(&AtomData::Shutdown(MockFd(3), ShutdownHow::Write)),
            Some(AtomReq::Shutdown(MockFd(3), ShutdownHow::Write))
        );
    }

    #[test]
    fn accepted_socket_can_be_used_as_a_descriptor_resource() {
        assert_eq!(
            AtomReq::new(&AtomData::Read(MockFd(7), "ping", 4)),
            Some(AtomReq::Read(MockFd(7), 4))
        );
    }
}
