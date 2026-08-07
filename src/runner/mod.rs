//! Process execution and syscall supervision.
//!
//! Seccomp, ptrace, process state, and FD state intentionally remain in this
//! crate because they cooperate on the same compiled test model.

mod errno;
mod fd;
mod request;
mod socket;
pub mod spawn;
mod supervisor;

pub use crate::MockFd;
pub use fd::{ChildFile, ProcFileSpace};
pub use request::AtomReq;
pub use socket::Tracker;
pub use supervisor::Supervisor;
