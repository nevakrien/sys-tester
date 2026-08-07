//! Process execution and syscall supervision.
//!
//! Seccomp, ptrace, process state, and FD state intentionally remain in this
//! crate because they cooperate on the same compiled test model.

mod fd;
mod request;
pub mod spawn;
mod supervisor;

pub use fd::{ChildFile, MockFd, ProcFileSpace};
pub use request::AtomReq;
pub use supervisor::Supervisor;
