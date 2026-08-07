//! Process execution and syscall supervision.
//!
//! Seccomp, ptrace, process state, and FD state intentionally remain in this
//! crate because they cooperate on the same compiled test model.

mod errno;
pub mod fd;
mod request;
mod supervisor;
pub mod spawn;
mod tracker;

pub use crate::MockFd;
pub use fd::{ChildFile, ProcFileSpace};
pub use request::AtomReq;
pub use tracker::Tracker;
pub use supervisor::Supervisor;
