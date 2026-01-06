//! Seccomp syscall filtering for sandboxed execution.
//!
//! This module provides seccomp profiles for restricting syscalls during
//! build processes. Based on patterns from youki and Docker's default profile.
//!
//! # Security Model
//!
//! The default build profile allows most syscalls needed for compiling code
//! while blocking dangerous ones like:
//! - Kernel module operations
//! - Raw network socket creation
//! - System administration operations
//! - Virtualization operations

use oci_spec::runtime::{
    Arch as LinuxArch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder,
};

/// Create a default seccomp profile for build operations.
///
/// This profile is designed to be permissive enough for most build tools
/// (compilers, linkers, package managers) while blocking dangerous operations.
///
/// # Blocked Syscalls
///
/// - `kexec_load`, `kexec_file_load` - Kernel replacement
/// - `init_module`, `finit_module`, `delete_module` - Kernel modules
/// - `acct` - Process accounting
/// - `mount`, `umount2`, `pivot_root` - Filesystem namespace (unless in sandbox)
/// - `reboot` - System reboot
/// - `setns` - Namespace switching (could escape sandbox)
/// - `unshare` - Creating new namespaces (could elevate privileges)
/// - `kcmp`, `process_vm_*` - Process introspection
/// - `ptrace` - Process tracing (unless debugging)
/// - `keyctl`, `add_key`, `request_key` - Kernel keyring
/// - `iopl`, `ioperm` - I/O port access
/// - `swapon`, `swapoff` - Swap management
/// - `settimeofday`, `clock_settime` - Time modification
/// - `personality` - Process execution domain (can enable compat modes)
///
/// # Architecture
///
/// Supports x86_64 and aarch64 (ARM64).
#[must_use]
pub fn default_build_profile() -> LinuxSeccomp {
    // Block dangerous syscalls by default, allow everything else
    LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActAllow)
        .default_errno_ret(1u32) // EPERM
        .architectures(vec![LinuxArch::ScmpArchX8664, LinuxArch::ScmpArchAarch64])
        .syscalls(vec![
            // Kernel module operations - BLOCK
            LinuxSyscallBuilder::default()
                .names(vec![
                    "init_module".to_string(),
                    "finit_module".to_string(),
                    "delete_module".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // Kernel replacement - BLOCK
            LinuxSyscallBuilder::default()
                .names(vec![
                    "kexec_load".to_string(),
                    "kexec_file_load".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // System administration - BLOCK
            LinuxSyscallBuilder::default()
                .names(vec![
                    "reboot".to_string(),
                    "acct".to_string(),
                    "swapon".to_string(),
                    "swapoff".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // Time modification - BLOCK
            LinuxSyscallBuilder::default()
                .names(vec![
                    "settimeofday".to_string(),
                    "clock_settime".to_string(),
                    "clock_adjtime".to_string(),
                    "adjtimex".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // Namespace manipulation - BLOCK (sandbox escapes)
            // SECURITY: Both setns and unshare must be blocked to prevent
            // sandbox escapes. A malicious build could call unshare(CLONE_NEWUSER)
            // to create a user namespace with full capabilities, then mount
            // arbitrary filesystems. See CVE-2022-0492 for similar attack.
            LinuxSyscallBuilder::default()
                .names(vec!["setns".to_string(), "unshare".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // Mount operations - BLOCK (filesystem escape)
            LinuxSyscallBuilder::default()
                .names(vec![
                    "mount".to_string(),
                    "umount".to_string(),
                    "umount2".to_string(),
                    "pivot_root".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // Ptrace - BLOCK (debugging/introspection escape)
            LinuxSyscallBuilder::default()
                .names(vec!["ptrace".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // I/O port access - BLOCK
            LinuxSyscallBuilder::default()
                .names(vec!["iopl".to_string(), "ioperm".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // Kernel keyring - BLOCK
            LinuxSyscallBuilder::default()
                .names(vec![
                    "add_key".to_string(),
                    "request_key".to_string(),
                    "keyctl".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // Process introspection - BLOCK
            LinuxSyscallBuilder::default()
                .names(vec![
                    "kcmp".to_string(),
                    "process_vm_readv".to_string(),
                    "process_vm_writev".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // Execution domain - BLOCK (security boundary bypass)
            LinuxSyscallBuilder::default()
                .names(vec!["personality".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // Virtualization - BLOCK
            LinuxSyscallBuilder::default()
                .names(vec![
                    "create_module".to_string(),
                    "get_kernel_syms".to_string(),
                    "query_module".to_string(),
                    "uselib".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // SECURITY: userfaultfd - BLOCK (CVE-2022-29582, use-after-free exploits)
            // Can be used to pause threads at precise moments for race conditions
            LinuxSyscallBuilder::default()
                .names(vec!["userfaultfd".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // SECURITY: perf_event_open - BLOCK (information disclosure, side channels)
            // Can leak kernel memory layout and timing information
            LinuxSyscallBuilder::default()
                .names(vec!["perf_event_open".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // SECURITY: bpf - BLOCK (eBPF can escape sandbox)
            // eBPF programs can read kernel memory and bypass seccomp
            LinuxSyscallBuilder::default()
                .names(vec!["bpf".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // SECURITY: open_by_handle_at - BLOCK (CVE-2014-0038, file handle abuse)
            // Can access files outside mount namespace by handle
            LinuxSyscallBuilder::default()
                .names(vec![
                    "open_by_handle_at".to_string(),
                    "name_to_handle_at".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // SECURITY: move_pages - BLOCK (NUMA memory manipulation)
            // Can be used for side-channel attacks on memory
            LinuxSyscallBuilder::default()
                .names(vec![
                    "move_pages".to_string(),
                    "mbind".to_string(),
                    "migrate_pages".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // SECURITY: Terminal/console manipulation - BLOCK
            // Can affect host terminal
            LinuxSyscallBuilder::default()
                .names(vec!["vhangup".to_string(), "syslog".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // SECURITY: Lookup DCOOKIE - BLOCK (kernel pointer leak)
            LinuxSyscallBuilder::default()
                .names(vec!["lookup_dcookie".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
            // SECURITY: Clock operations - BLOCK
            // Can affect system timekeeping
            LinuxSyscallBuilder::default()
                .names(vec!["clock_settime".to_string(), "ntp_adjtime".to_string()])
                .action(LinuxSeccompAction::ScmpActErrno)
                .errno_ret(1u32)
                .build()
                .unwrap(),
        ])
        .build()
        .unwrap()
}

/// Create a strict seccomp profile that only allows essential syscalls.
///
/// This is more restrictive than the default and should only be used
/// for highly constrained environments. Most builds will fail with this.
#[must_use]
pub fn strict_profile() -> LinuxSeccomp {
    // Default deny, only allow specific syscalls
    LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActErrno)
        .default_errno_ret(1u32)
        .architectures(vec![LinuxArch::ScmpArchX8664, LinuxArch::ScmpArchAarch64])
        .syscalls(vec![
            // Essential I/O
            LinuxSyscallBuilder::default()
                .names(vec![
                    "read".to_string(),
                    "write".to_string(),
                    "open".to_string(),
                    "openat".to_string(),
                    "close".to_string(),
                    "stat".to_string(),
                    "fstat".to_string(),
                    "lstat".to_string(),
                    "lseek".to_string(),
                    "mmap".to_string(),
                    "mprotect".to_string(),
                    "munmap".to_string(),
                    "brk".to_string(),
                    "pread64".to_string(),
                    "pwrite64".to_string(),
                    "readv".to_string(),
                    "writev".to_string(),
                    "access".to_string(),
                    "faccessat".to_string(),
                    "faccessat2".to_string(),
                    "dup".to_string(),
                    "dup2".to_string(),
                    "dup3".to_string(),
                    "fcntl".to_string(),
                    "flock".to_string(),
                    "fsync".to_string(),
                    "fdatasync".to_string(),
                    "truncate".to_string(),
                    "ftruncate".to_string(),
                    "getdents".to_string(),
                    "getdents64".to_string(),
                    "getcwd".to_string(),
                    "chdir".to_string(),
                    "fchdir".to_string(),
                    "readlink".to_string(),
                    "readlinkat".to_string(),
                    "statfs".to_string(),
                    "fstatfs".to_string(),
                    "statx".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Process management
            LinuxSyscallBuilder::default()
                .names(vec![
                    "fork".to_string(),
                    "vfork".to_string(),
                    "clone".to_string(),
                    "clone3".to_string(),
                    "execve".to_string(),
                    "execveat".to_string(),
                    "exit".to_string(),
                    "exit_group".to_string(),
                    "wait4".to_string(),
                    "waitid".to_string(),
                    "getpid".to_string(),
                    "getppid".to_string(),
                    "gettid".to_string(),
                    "getuid".to_string(),
                    "geteuid".to_string(),
                    "getgid".to_string(),
                    "getegid".to_string(),
                    "getgroups".to_string(),
                    "setpgid".to_string(),
                    "getpgid".to_string(),
                    "getpgrp".to_string(),
                    "setsid".to_string(),
                    "getsid".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Signals
            LinuxSyscallBuilder::default()
                .names(vec![
                    "kill".to_string(),
                    "tgkill".to_string(),
                    "rt_sigaction".to_string(),
                    "rt_sigprocmask".to_string(),
                    "rt_sigreturn".to_string(),
                    "sigaltstack".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Time
            LinuxSyscallBuilder::default()
                .names(vec![
                    "clock_gettime".to_string(),
                    "clock_getres".to_string(),
                    "gettimeofday".to_string(),
                    "nanosleep".to_string(),
                    "clock_nanosleep".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Memory
            LinuxSyscallBuilder::default()
                .names(vec![
                    "madvise".to_string(),
                    "mremap".to_string(),
                    "mincore".to_string(),
                    "mlock".to_string(),
                    "munlock".to_string(),
                    "mlockall".to_string(),
                    "munlockall".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Polling/select
            LinuxSyscallBuilder::default()
                .names(vec![
                    "poll".to_string(),
                    "ppoll".to_string(),
                    "select".to_string(),
                    "pselect6".to_string(),
                    "epoll_create".to_string(),
                    "epoll_create1".to_string(),
                    "epoll_ctl".to_string(),
                    "epoll_wait".to_string(),
                    "epoll_pwait".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Pipes/sockets (local only)
            LinuxSyscallBuilder::default()
                .names(vec![
                    "pipe".to_string(),
                    "pipe2".to_string(),
                    "socketpair".to_string(),
                    "eventfd".to_string(),
                    "eventfd2".to_string(),
                    "signalfd".to_string(),
                    "signalfd4".to_string(),
                    "timerfd_create".to_string(),
                    "timerfd_settime".to_string(),
                    "timerfd_gettime".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Futex (needed for threading)
            LinuxSyscallBuilder::default()
                .names(vec![
                    "futex".to_string(),
                    "get_robust_list".to_string(),
                    "set_robust_list".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Threading
            LinuxSyscallBuilder::default()
                .names(vec![
                    "set_tid_address".to_string(),
                    "arch_prctl".to_string(),
                    "prctl".to_string(),
                    "sched_yield".to_string(),
                    "sched_getaffinity".to_string(),
                    "sched_setaffinity".to_string(),
                    "rseq".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Resource limits
            LinuxSyscallBuilder::default()
                .names(vec![
                    "getrlimit".to_string(),
                    "prlimit64".to_string(),
                    "getrusage".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
            // Misc
            LinuxSyscallBuilder::default()
                .names(vec![
                    "uname".to_string(),
                    "sysinfo".to_string(),
                    "getrandom".to_string(),
                ])
                .action(LinuxSeccompAction::ScmpActAllow)
                .build()
                .unwrap(),
        ])
        .build()
        .unwrap()
}

/// Seccomp profile level for sandboxed execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SeccompLevel {
    /// No seccomp filtering (not recommended).
    None,
    /// Default profile - blocks dangerous syscalls, allows most others.
    #[default]
    Default,
    /// Strict profile - only allows essential syscalls (may break builds).
    Strict,
}

impl SeccompLevel {
    /// Get the seccomp profile for this level.
    #[must_use]
    pub fn profile(&self) -> Option<LinuxSeccomp> {
        match self {
            Self::None => None,
            Self::Default => Some(default_build_profile()),
            Self::Strict => Some(strict_profile()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_profile_creation() {
        let profile = default_build_profile();
        assert_eq!(profile.default_action(), LinuxSeccompAction::ScmpActAllow);
        assert!(!profile.syscalls().as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_strict_profile_creation() {
        let profile = strict_profile();
        assert_eq!(profile.default_action(), LinuxSeccompAction::ScmpActErrno);
        assert!(!profile.syscalls().as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_seccomp_level_default() {
        let level = SeccompLevel::default();
        assert_eq!(level, SeccompLevel::Default);
        assert!(level.profile().is_some());
    }

    #[test]
    fn test_seccomp_level_none() {
        let level = SeccompLevel::None;
        assert!(level.profile().is_none());
    }
}
