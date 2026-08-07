//! Compile the runner's static seccomp filters.
//!
//! libseccomp is only a build dependency. This script compiles several policy
//! variants into classic-BPF programs under Cargo's OUT_DIR. Runtime code embeds
//! those bytes and installs them through the raw seccomp API.
//!
//! # Design
//!
//! The BPF filter is not the final policy engine.
//!
//! It performs only two decisions:
//!
//! - `ALLOW`: this syscall is irrelevant enough to execute without involving
//!   the supervisor;
//! - `USER_NOTIF`: the supervisor must inspect it and decide what to do.
//!
//! We deliberately do not return automatic errno values for whole syscall
//! classes. A policy violation is usually better handled by the supervisor:
//!
//! - report exactly what happened;
//! - terminate the child immediately;
//! - mark the test as failed;
//! - optionally emulate or continue the call under a more permissive policy.
//!
//! All unclassified syscalls therefore default to USER_NOTIF. This also gives
//! forward compatibility with syscalls unknown to the build-time libseccomp.
//!
//! # Generated variants
//!
//! Two independent choices produce four filters.
//!
//! ## Descriptor classification
//!
//! `ReservedRange`:
//!
//! Supervisor-owned/mock FDs are allocated at or above `MOCK_FD_BASE`.
//! For syscalls whose first argument is the relevant FD:
//!
//!     fd < MOCK_FD_BASE  => ALLOW
//!     fd >= MOCK_FD_BASE => USER_NOTIF
//!
//! This gives ordinary kernel-backed descriptors a fast path.
//!
//! `AlwaysNotify`:
//!
//! FD numbers have no encoded meaning. Every relevant FD operation notifies,
//! and the supervisor looks up `(process, fd)` in its own descriptor map.
//!
//! ## Supervision scope
//!
//! `FileBehaviorOnly`:
//!
//! The target is assumed non-malicious and the test only cares about modeled
//! file/FD behavior. Known unrelated operations such as sending signals,
//! querying time, obtaining randomness, or changing process-local state are
//! allowed directly.
//!
//! `Strict`:
//!
//! Behavior outside the small process-runtime allowlist also notifies. The
//! supervisor can then reject it by killing the child and reporting a policy
//! violation. Strict mode does not encode rejection inside BPF and does not
//! attempt to guarantee deterministic execution; time, randomness, and host
//! information remain available in every policy.
//!
//! # Listener startup
//!
//! The supervisor owns a preallocated shared atomic startup slot.
//!
//! 1. It forks a per-target helper.
//! 2. The helper closes inherited FDs and configures stdin/stdout/stderr.
//! 3. The helper clones the launcher with CLONE_FILES.
//! 4. The launcher installs the filter with NEW_LISTENER.
//! 5. The listener FD immediately appears in the helper's shared FD table.
//! 6. The launcher publishes the listener's integer FD through shared memory.
//! 7. The launcher calls execve.
//!
//! Successful execve replaces the launcher's address space and unshares its FD
//! table. The helper retains the listener long enough to transfer it to the
//! supervisor with SCM_RIGHTS, then exits.
//!
//! No bootstrap filter or post-filter transfer syscall in the target is needed.
//!
//! # execve
//!
//! execve receives pointers to mutable userspace data: pathname, argv, envp,
//! and all strings and pointer arrays reachable through them.
//!
//! Seccomp BPF sees only the raw pointer values. A supervisor can copy and
//! inspect those values after receiving a notification, but authorizing the
//! syscall and returning CONTINUE is inherently TOCTOU-racy: another thread
//! may modify that memory before the kernel performs the continued execve.
//!
//! The trusted launcher necessarily performs one execve after installing the
//! final filter. Notifying merely to return CONTINUE provides no useful check,
//! so execve is explicitly allowed.
//!
//! This also permits later execve calls. They retain the same PID and seccomp
//! filter. If executable-image changes matter, ptrace exec events are a better
//! observation mechanism than pathname authorization through seccomp.
//!
//! execveat is not required by the launcher and therefore not automatically
//! allowed.
//!
//! # Polling
//!
//! poll/ppoll receive arrays of pollfd structures through pointers.
//! select/pselect receive descriptor bitsets through pointers.
//! Seccomp BPF cannot inspect those structures.
//!
//! epoll also needs semantic tracking: epoll_ctl registers watched descriptors,
//! and epoll_wait later reports readiness from that persistent state.
//!
//! Polling syscalls therefore always notify, regardless of FD strategy.
//!
//! # futex and mock FD values
//!
//! futex does not operate on an FD. Its first argument is a userspace address.
//! Nonsense numerical values assigned to mock FDs therefore do not affect it.
//!
//! futex can matter to deterministic scheduling, but for now it is treated as
//! ordinary process runtime machinery and allowed in every policy.
//!
//! # mmap
//!
//! Anonymous mmap is process-local memory allocation and is allowed.
//! File-backed mmap can bypass read/write interception and therefore notifies.
//!
//! The MAP_ANONYMOUS flag is passed by value, so this distinction can be made
//! safely inside BPF.
//!
//! # Unknown syscalls
//!
//! Every filter defaults to USER_NOTIF.
//!
//! Consequently, a syscall unknown to this build's libseccomp, or accidentally
//! omitted from all semantic groups, reaches the supervisor. The supervisor can
//! flag it and choose CONTINUE, emulation, failure, or immediate termination.

use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fs::File;
use std::mem::size_of;
use std::path::{Path, PathBuf};

use libseccomp::{ScmpAction, ScmpArch, ScmpFilterAttr, ScmpFilterContext, ScmpSyscall, scmp_cmp};

const ARCH: ScmpArch = ScmpArch::X8664;

/// First descriptor reserved for supervisor-owned/mock resources.
///
/// The runtime must verify that the target's RLIMIT_NOFILE permits allocation
/// in this range.
const MOCK_FD_BASE: u64 = 1 << 20;

#[derive(Debug, Clone, Copy)]
enum FdPolicy {
    ReservedRange,
    AlwaysNotify,
}

#[derive(Debug, Clone, Copy)]
enum ScopePolicy {
    /// Only modeled file/FD behavior is supervised.
    FileBehaviorOnly,

    /// Anything outside the essential runtime allowlist is supervised.
    Strict,
}

#[derive(Debug, Clone, Copy)]
struct Policy {
    file_name: &'static str,
    fd_policy: FdPolicy,
    scope: ScopePolicy,
}

const POLICIES: &[Policy] = &[
    Policy {
        file_name: "x86_64_range_file_only.bpf",
        fd_policy: FdPolicy::ReservedRange,
        scope: ScopePolicy::FileBehaviorOnly,
    },
    Policy {
        file_name: "x86_64_range_strict.bpf",
        fd_policy: FdPolicy::ReservedRange,
        scope: ScopePolicy::Strict,
    },
    Policy {
        file_name: "x86_64_mapped_file_only.bpf",
        fd_policy: FdPolicy::AlwaysNotify,
        scope: ScopePolicy::FileBehaviorOnly,
    },
    Policy {
        file_name: "x86_64_mapped_strict.bpf",
        fd_policy: FdPolicy::AlwaysNotify,
        scope: ScopePolicy::Strict,
    },
];

// =============================================================================
// Allowed in every policy
// =============================================================================

/// Normal process termination.
const PROCESS_EXIT: &[&str] = &["exit", "exit_group"];

/// Trusted transition from launcher to target.
const PROCESS_EXECUTION: &[&str] = &["execve"];

/// Local signal machinery.
///
/// Receiving a signal is not itself a syscall. These calls let handlers be
/// installed, masked, entered, and returned from normally.
const LOCAL_SIGNAL_STATE: &[&str] = &[
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "restart_syscall",
];

/// Basic process-local virtual-memory operations.
///
/// mmap is handled separately because file-backed mappings must notify.
const LOCAL_MEMORY: &[&str] = &["brk", "munmap", "mprotect", "mremap", "madvise"];

/// Thread runtime and userspace synchronization support.
const THREAD_RUNTIME: &[&str] = &[
    "arch_prctl",
    "set_tid_address",
    "set_robust_list",
    "get_robust_list",
    "rseq",
    "futex",
    "futex_waitv",
    "sched_yield",
];

/// Operations that expose nondeterministic environment state or make execution
/// depend on external timing.
///
/// Strict supervision is a sandboxing choice, not a determinism guarantee.
/// Programs can observe nondeterminism without syscalls as well, so these calls
/// are allowed in every policy. A future deterministic mode should be modeled
/// as a separate policy dimension and virtualize the relevant operations.
const NONDETERMINISTIC_ENVIRONMENT: &[&str] = &[
    // Time observation.
    "clock_gettime",
    "clock_getres",
    "gettimeofday",
    "time",
    "times",
    // Time-dependent waiting.
    "nanosleep",
    "clock_nanosleep",
    // Randomness.
    "getrandom",
    // Host and resource information.
    "uname",
    "sysinfo",
    "getrlimit",
    "getrusage",
];

// =============================================================================
// Allowed only when supervising file behavior
// =============================================================================

/// Process and credential identity queries.
const PROCESS_INFORMATION: &[&str] = &[
    "getpid",
    "getppid",
    "gettid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getresuid",
    "getresgid",
    "getgroups",
    "getpgrp",
    "getpgid",
    "getsid",
];

/// Operations that affect another process, thread, or process-group topology.
///
/// These are harmless to a file-only behavioral test when the target is trusted,
/// but strict mode must surface them to the supervisor.
const PROCESS_CHANGE: &[&str] = &[
    // Signal delivery.
    "kill",
    "tkill",
    "tgkill",
    "rt_sigqueueinfo",
    "rt_tgsigqueueinfo",
    "pidfd_send_signal",
    // Process-group/session changes.
    "setpgid",
    "setsid",
    // Scheduling and priority changes.
    "setpriority",
    "sched_setaffinity",
    "sched_setscheduler",
    "sched_setparam",
    "sched_setattr",
];

/// Process-local ABI and runtime configuration.
///
/// These are broad interfaces and should notify in strict mode.
const PROCESS_CONFIGURATION: &[&str] = &["prctl", "personality"];

// =============================================================================
// Always notified
// =============================================================================

/// Path-based filesystem access and mutation.
const FILESYSTEM_PATH_OPERATIONS: &[&str] = &[
    // Opening.
    "open",
    "openat",
    "openat2",
    "creat",
    // Removal and renaming.
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    // Directory operations.
    "mkdir",
    "mkdirat",
    "rmdir",
    "chdir",
    "fchdir",
    "getcwd",
    // Links.
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "readlink",
    "readlinkat",
    // Path metadata and permissions.
    "stat",
    "lstat",
    "newfstatat",
    "statx",
    "access",
    "faccessat",
    "faccessat2",
    "chmod",
    "fchmodat",
    "chown",
    "lchown",
    "fchownat",
    // Path-based size/time mutation.
    "truncate",
    "utime",
    "utimes",
    "utimensat",
];

/// Operations that create descriptors or alter descriptor-number topology.
///
/// These must remain visible so the runtime can preserve either the reserved FD
/// range or its explicit `(process, fd)` map.
const FD_TOPOLOGY: &[&str] = &[
    "dup",
    "dup2",
    "dup3",
    // Must be decoded by command. Some fcntl commands duplicate descriptors.
    "fcntl",
    "pipe",
    "pipe2",
    "close_range",
    "eventfd",
    "eventfd2",
    "signalfd",
    "signalfd4",
    "timerfd_create",
    "inotify_init",
    "inotify_init1",
    "memfd_create",
    "userfaultfd",
    "pidfd_open",
    "pidfd_getfd",
];

/// Socket creation and connection topology.
const NETWORK_TOPOLOGY: &[&str] = &[
    "socket",
    "socketpair",
    "accept",
    "accept4",
    "connect",
    "bind",
    "listen",
];

/// Process-tree creation.
///
/// clone3 arguments are hidden behind a pointer, so its exact meaning must be
/// decoded by the supervisor.
const PROCESS_TOPOLOGY: &[&str] = &["fork", "vfork", "clone", "clone3"];

/// Alternative execution mechanisms not required by trusted startup.
const SUPERVISED_EXECUTION: &[&str] = &["execveat"];

/// Broad interfaces whose meaning cannot be classified from one argument.
///
/// These require syscall-specific decoding in every supervision mode. In
/// particular, ioctl behavior depends on both the descriptor type and request,
/// while prlimit64 is either a query or a mutation depending on its pointers.
const GENERAL_CASE_OPERATIONS: &[&str] = &["ioctl", "prlimit64"];

/// Readiness APIs whose relevant descriptors cannot be classified by testing
/// syscall argument zero.
const POLL_AND_READINESS: &[&str] = &[
    "poll",
    "ppoll",
    "select",
    "pselect6",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
];

/// Multi-FD or stateful operations requiring dedicated handling.
const SPECIAL_FD_OPERATIONS: &[&str] = &[
    // Kernel-side transfer between descriptors.
    "sendfile",
    "splice",
    "tee",
    "vmsplice",
    "copy_file_range",
    // Special descriptor state.
    "inotify_add_watch",
    "inotify_rm_watch",
    "timerfd_settime",
    "timerfd_gettime",
    // Descriptor metadata/enumeration.
    "fstat",
    "fstatfs",
    "getdents",
    "getdents64",
];

/// Asynchronous I/O mechanisms that bypass the current syscall-by-syscall model.
///
/// These notify rather than automatically failing. The supervisor will normally
/// kill the child and report an unsupported operation.
const UNSUPPORTED_ASYNC_IO: &[&str] = &[
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "io_setup",
    "io_destroy",
    "io_submit",
    "io_cancel",
    "io_getevents",
    "io_pgetevents",
];

// =============================================================================
// FD-policy-dependent operations
// =============================================================================

/// File-like operations whose policy-relevant descriptor is argument zero.
const FD_FILE_OPERATIONS: &[&str] = &[
    // Byte I/O.
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "preadv",
    "pwritev",
    "preadv2",
    "pwritev2",
    // Position, size, and durability.
    "lseek",
    "fsync",
    "fdatasync",
    "ftruncate",
    // Descriptor lifetime.
    "close",
];

/// Socket operations whose policy-relevant descriptor is argument zero.
const FD_SOCKET_OPERATIONS: &[&str] = &[
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "sendmmsg",
    "recvmmsg",
    "shutdown",
    "getsockname",
    "getpeername",
    "getsockopt",
    "setsockopt",
];

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=build.rs");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Err("seccomp filters require a Linux target".into());
    }

    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64") {
        return Err("seccomp filters currently support only the x86-64 syscall ABI".into());
    }

    let output_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo did not provide OUT_DIR")?);

    for &policy in POLICIES {
        export_filter(&output_dir.join(policy.file_name), policy)?;
    }

    // Keep runtime allocation and BPF classification synchronized.
    std::fs::write(
        output_dir.join("seccomp_filter_config.rs"),
        format!(
            "/// First descriptor reserved for supervisor-owned resources.\n\
             pub const MOCK_FD_BASE: u64 = {MOCK_FD_BASE};\n"
        ),
    )?;

    Ok(())
}

fn export_filter(path: &Path, policy: Policy) -> Result<(), Box<dyn Error>> {
    // Every unknown or unclassified syscall reaches the supervisor.
    let default_action = ScmpAction::Notify;

    let mut context = ScmpFilterContext::new(default_action)?;
    context.set_filter_attr(ScmpFilterAttr::CtlOptimize, 2)?;

    let mut explicit = HashSet::new();

    // Always-safe runtime groups.
    add_group(&mut context, &mut explicit, ScmpAction::Allow, PROCESS_EXIT)?;
    add_group(
        &mut context,
        &mut explicit,
        ScmpAction::Allow,
        PROCESS_EXECUTION,
    )?;
    add_group(
        &mut context,
        &mut explicit,
        ScmpAction::Allow,
        LOCAL_SIGNAL_STATE,
    )?;
    add_group(&mut context, &mut explicit, ScmpAction::Allow, LOCAL_MEMORY)?;
    add_group(
        &mut context,
        &mut explicit,
        ScmpAction::Allow,
        THREAD_RUNTIME,
    )?;
    add_group(
        &mut context,
        &mut explicit,
        ScmpAction::Allow,
        NONDETERMINISTIC_ENVIRONMENT,
    )?;

    // File-only mode deliberately ignores unrelated trusted behavior.
    if matches!(policy.scope, ScopePolicy::FileBehaviorOnly) {
        add_group(
            &mut context,
            &mut explicit,
            ScmpAction::Allow,
            PROCESS_INFORMATION,
        )?;
        add_group(
            &mut context,
            &mut explicit,
            ScmpAction::Allow,
            PROCESS_CHANGE,
        )?;
        add_group(
            &mut context,
            &mut explicit,
            ScmpAction::Allow,
            PROCESS_CONFIGURATION,
        )?;
    }

    // In strict mode these groups simply retain the USER_NOTIF fallback.
    // The supervisor decides whether to continue, emulate, or terminate.

    add_mmap_rules(&mut context, &mut explicit)?;
    add_fd_arg0_rules(
        &mut context,
        &mut explicit,
        policy.fd_policy,
        FD_FILE_OPERATIONS,
    )?;
    add_fd_arg0_rules(
        &mut context,
        &mut explicit,
        policy.fd_policy,
        FD_SOCKET_OPERATIONS,
    )?;

    // These arrays intentionally receive no explicit rule because Notify is
    // already the default. Listing them still documents the modeled categories
    // and lets us validate that they do not overlap with allowed groups.
    register_notify_groups(
        &mut explicit,
        &[
            FILESYSTEM_PATH_OPERATIONS,
            FD_TOPOLOGY,
            NETWORK_TOPOLOGY,
            PROCESS_TOPOLOGY,
            SUPERVISED_EXECUTION,
            GENERAL_CASE_OPERATIONS,
            POLL_AND_READINESS,
            SPECIAL_FD_OPERATIONS,
            UNSUPPORTED_ASYNC_IO,
        ],
    )?;

    let file = File::create(path)?;
    context.export_bpf(&file)?;

    let byte_len = file.metadata()?.len();
    let instruction_size = size_of::<libc::sock_filter>() as u64;

    if byte_len == 0 || byte_len % instruction_size != 0 {
        return Err(format!(
            "libseccomp emitted an invalid sock_filter stream for {}",
            path.display(),
        )
        .into());
    }

    println!(
        "cargo::warning=generated {}: {} bytes / {} instructions",
        path.display(),
        byte_len,
        byte_len / instruction_size,
    );

    Ok(())
}

fn add_mmap_rules(
    context: &mut ScmpFilterContext,
    explicit: &mut HashSet<&'static str>,
) -> Result<(), Box<dyn Error>> {
    register(explicit, "mmap")?;

    let mmap = resolve_required("mmap")?;
    let anonymous = libc::MAP_ANONYMOUS as u64;

    // mmap(addr, len, prot, flags, fd, offset)
    //
    // Anonymous mappings are local allocation. Everything else falls through
    // to the filter's Notify default.
    context.add_rule_conditional_exact(
        ScmpAction::Allow,
        mmap,
        &[scmp_cmp!($arg3 & anonymous == anonymous)],
    )?;

    Ok(())
}

fn add_fd_arg0_rules(
    context: &mut ScmpFilterContext,
    explicit: &mut HashSet<&'static str>,
    policy: FdPolicy,
    operations: &'static [&'static str],
) -> Result<(), Box<dyn Error>> {
    match policy {
        FdPolicy::AlwaysNotify => {
            // Notify is the default. Register the group only for overlap
            // validation and documentation.
            register_group(explicit, operations)?;
        }

        FdPolicy::ReservedRange => {
            for &name in operations {
                register(explicit, name)?;

                let Some(syscall) = resolve_optional(name) else {
                    warn_unknown(name);
                    continue;
                };

                // Ordinary descriptors bypass the supervisor. Reserved/mock
                // descriptors fall through to USER_NOTIF.
                context.add_rule_conditional_exact(
                    ScmpAction::Allow,
                    syscall,
                    &[scmp_cmp!($arg0 < MOCK_FD_BASE)],
                )?;
            }
        }
    }

    Ok(())
}

fn add_group(
    context: &mut ScmpFilterContext,
    explicit: &mut HashSet<&'static str>,
    action: ScmpAction,
    names: &'static [&'static str],
) -> Result<(), Box<dyn Error>> {
    register_group(explicit, names)?;

    for &name in names {
        let Some(syscall) = resolve_optional(name) else {
            warn_unknown(name);
            continue;
        };

        context.add_rule_exact(action, syscall)?;
    }

    Ok(())
}

fn register_notify_groups(
    explicit: &mut HashSet<&'static str>,
    groups: &[&'static [&'static str]],
) -> Result<(), Box<dyn Error>> {
    for &group in groups {
        register_group(explicit, group)?;
    }

    Ok(())
}

fn register_group(
    explicit: &mut HashSet<&'static str>,
    names: &'static [&'static str],
) -> Result<(), Box<dyn Error>> {
    for &name in names {
        register(explicit, name)?;
    }

    Ok(())
}

fn register(
    explicit: &mut HashSet<&'static str>,
    name: &'static str,
) -> Result<(), Box<dyn Error>> {
    if !explicit.insert(name) {
        return Err(format!("syscall {name:?} appears in more than one semantic group").into());
    }

    Ok(())
}

fn resolve_required(name: &str) -> Result<ScmpSyscall, Box<dyn Error>> {
    Ok(ScmpSyscall::from_name_by_arch(name, ARCH)?)
}

/// Optional resolution is intentional.
///
/// If the build-time libseccomp does not recognize a newer syscall, no explicit
/// rule is emitted and the syscall reaches the USER_NOTIF fallback.
fn resolve_optional(name: &str) -> Option<ScmpSyscall> {
    ScmpSyscall::from_name_by_arch(name, ARCH).ok()
}

fn warn_unknown(name: &str) {
    println!(
        "cargo::warning=build-time libseccomp does not recognize syscall \
         {name:?}; leaving it to USER_NOTIF"
    );
}
