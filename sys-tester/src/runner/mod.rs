//! Process execution and syscall supervision.
//!
//! Seccomp, ptrace, process state, and FD state intentionally remain in this
//! crate because they cooperate on the same compiled test model.

pub mod seccomp;


use crate::Text;
use crate::HashMap;
use std::os::fd::RawFd;
// use std::os::fd::OwnedFd;
use crate::buffer::PathBuffer;

#[derive(Debug,Clone,Copy,Hash,Eq,PartialEq)]
pub struct MockFd(pub u32);

pub enum ChildFile {
	Real,
	Mock(MockFd)
}

#[derive(Debug, Clone, Copy,Hash,Eq,PartialEq)]
pub enum AtomReq {
    Open(Text),
    Read(MockFd,usize),
    Write(MockFd,Text),
    Close(MockFd),

}

pub trait ProcFileSpace {
	fn lookup_fd(&self,fd:RawFd)->Option<ChildFile>;
	fn add_mock(&mut self,m:MockFd)->RawFd;
	fn close_file(&mut self,r:RawFd)->bool;
}

pub struct Supervisor<PF:ProcFileSpace> {
	buf:PathBuffer,
	procs:HashMap<libc::pid_t,PF>,

	ready_atoms:HashMap<AtomReq,Vec<u32>>,
}


impl<PF: ProcFileSpace>  Supervisor<PF> {
	pub fn map_fd(&self,p:libc::pid_t,fd:RawFd)->Option<ChildFile> {
		self.procs.get(&p)?.lookup_fd(fd)
	}
	pub fn get_task(&mut self,r:&AtomReq)->Option<(u32,usize)>{
		let r = self.ready_atoms.get_mut(r)?;
		let total = r.len();
		//maybe first mix? problem for another day.
		Some((r.pop()?,total))
	}
}