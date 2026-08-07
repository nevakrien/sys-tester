use std::{error, fmt, io};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerFault {
    ProcessAlreadyTracked(libc::pid_t),
    ProcessNotTracked(libc::pid_t),
    UnexpectedSyscall(libc::c_long),
    UnexpectedWaitStatus {
        pid: libc::pid_t,
        status: libc::c_int,
    },
    ChildPidOutOfRange(libc::c_ulong),
    ForkResultMismatch {
        result: i64,
        event_child: Option<libc::pid_t>,
    },
}

#[derive(Debug)]
pub enum RunnerError {
    Fault(RunnerFault),
    Io(io::Error),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fault(fault) => fault.fmt(formatter),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl error::Error for RunnerError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Fault(_) => None,
            Self::Io(error) => Some(error),
        }
    }
}

impl From<io::Error> for RunnerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<RunnerFault> for RunnerError {
    fn from(fault: RunnerFault) -> Self {
        Self::Fault(fault)
    }
}

impl fmt::Display for RunnerFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessAlreadyTracked(pid) => {
                write!(formatter, "process {pid} is already tracked")
            }
            Self::ProcessNotTracked(pid) => write!(formatter, "process {pid} is not tracked"),
            Self::UnexpectedSyscall(syscall) => {
                write!(formatter, "syscall {syscall} does not create a process")
            }
            Self::UnexpectedWaitStatus { pid, status } => {
                write!(
                    formatter,
                    "unexpected wait status {status:#x} for process {pid}"
                )
            }
            Self::ChildPidOutOfRange(pid) => {
                write!(formatter, "kernel returned out-of-range child PID {pid}")
            }
            Self::ForkResultMismatch {
                result,
                event_child,
            } => write!(
                formatter,
                "process-creation result {result} does not match ptrace child {event_child:?}"
            ),
        }
    }
}
