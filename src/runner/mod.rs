//! Process execution and syscall supervision.
//!
//! Seccomp, ptrace, process state, and FD state intentionally remain in this
//! crate because they cooperate on the same compiled test model.

mod errno;
mod error;
pub mod fd;
mod ptrace;
mod request;
pub mod spawn;
mod supervisor;
#[cfg(test)]
mod test_support;
mod tracker;

pub use crate::MockFd;
pub use error::{RunnerError, RunnerFault};
pub use fd::{ChildFile, ProcFileSpace};
pub use request::AtomReq;
pub use supervisor::{ProcessCreationOutcome, Supervisor};
pub use tracker::Tracker;
