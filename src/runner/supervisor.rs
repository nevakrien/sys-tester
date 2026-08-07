use crate::graph::DirectedGraph;
use crate::index::IndexVec;
use foldhash::{HashMap, HashMapExt};

use super::{AtomReq, ChildFile, ProcFileSpace};
use crate::CompiledSetup;
use crate::buffer::PageBuffer;
use std::os::fd::RawFd;

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
