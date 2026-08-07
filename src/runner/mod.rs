//! Process execution and syscall supervision.
//!
//! Seccomp, ptrace, process state, and FD state intentionally remain in this
//! crate because they cooperate on the same compiled test model.
pub mod spawn;

use crate::AtomData;
use crate::graph::DirectedGraph;
use crate::index::IndexVec;
use foldhash::HashMapExt;

use crate::CompiledSetup;
use crate::HashMap;
use crate::Text;
use crate::buffer::PageBuffer;
use std::os::fd::RawFd;
// use std::os::fd::OwnedFd;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct MockFd(pub u32);

pub enum ChildFile {
    Real,
    Mock(MockFd),
}

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
            AtomData::Open(path) => AtomReq::Open(path),

            AtomData::Read(open, _expected, size) => AtomReq::Read(MockFd(open), size),

            AtomData::Write(open, text, _size) => AtomReq::Write(MockFd(open), text),

            AtomData::Close(open) => AtomReq::Close(MockFd(open)),

            AtomData::DebugName(_) => return None,
        })
    }
}

pub trait ProcFileSpace {
    fn lookup_fd(&self, fd: RawFd) -> Option<ChildFile>;
    fn add_mock(&mut self, m: MockFd) -> RawFd;
    fn close_file(&mut self, r: RawFd) -> bool;
}

pub struct Supervisor<PF: ProcFileSpace> {
    pub buffer: PageBuffer,
    procs: HashMap<libc::pid_t, PF>,

    ready_atoms: HashMap<AtomReq, Vec<u32>>,
    wait_counts: IndexVec<u32, u32>, //MAX for already done
    info: CompiledSetup,
}

impl<PF: ProcFileSpace> Supervisor<PF> {
    pub fn new(info: CompiledSetup) -> Self {
        let mut ready_atoms: HashMap<_, Vec<_>> = HashMap::with_capacity(1024);
        let mut wait_counts = IndexVec::with_capacity(info.atoms.len());

        for id in 0..info.atoms.len() {
            let edges = info.before_graph.full_edges(id as u32);
            wait_counts.push(edges.len() as u32);

            if edges.len() != 0 {
                continue;
            }

            let Some(req) = AtomReq::new(&info.atoms[id].data) else {
                todo!("handle logs")
            };
            ready_atoms.entry(req).or_default().push(id as u32);
        }

        Self {
            buffer: PageBuffer::new(),
            procs: HashMap::with_capacity(1024),
            ready_atoms,
            wait_counts,
            info,
        }
    }

    pub fn mark_done(&mut self, id: u32) {
        for x in self.info.after_graph.edges(id) {
            debug_assert!(self.wait_counts[x] > 0);

            self.wait_counts[x] -= 1;
            if self.wait_counts[x] == 0 {
                let Some(req) = AtomReq::new(&self.info.atoms[x as usize].data) else {
                    todo!("handle logs")
                };
                self.ready_atoms.entry(req).or_default().push(x);
            }
        }

        self.wait_counts[id] = u32::MAX;
    }

    pub fn iter_undone(&self) -> impl Iterator<Item = u32> {
        self.wait_counts
            .iter()
            .enumerate()
            .filter_map(|(i, c)| if *c != u32::MAX { Some(i as u32) } else { None })
    }

    pub fn map_fd(&self, p: libc::pid_t, fd: RawFd) -> Option<ChildFile> {
        self.procs.get(&p)?.lookup_fd(fd)
    }
    pub fn get_task(&mut self, r: &AtomReq) -> Option<(u32, usize)> {
        let r = self.ready_atoms.get_mut(r)?;
        let total = r.len();
        //maybe first mix? problem for another day.
        Some((r.pop()?, total))
    }
}
