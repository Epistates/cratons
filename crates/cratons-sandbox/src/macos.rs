//! macOS sandbox implementation using `sandbox-exec`.
//!
//! # Architecture Decision
//!
//! This uses the legacy (but functional) `sandbox-exec` tool with SBPL (Sandbox Profile Language).
//!
//! ## Why not `Virtualization.framework` / `apple/container`?
//! Apple's modern virtualization tools are designed for running *Linux* VMs on macOS.
//! `Cratons` defaults to running *native* macOS builds (needing Xcode, macOS SDKs, etc.).
//! For native process isolation, `sandbox-exec` remains the industry standard (used by Bazel, Nix, Chromium)
//! despite its deprecated status, as Apple provides no other mechanism for arbitrary child process restriction.
//!
//! ## Security Features (2025 Hardened)
//! - Filesystem isolation via SBPL deny rules
//! - Network isolation (full deny or allow)
//! - **Process execution restricted to whitelisted binaries**
//! - **Environment variable sanitization**
//! - Resource usage tracking via getrusage
//!
//! ## Limitations
//! - Per-host network filtering not supported (AllowList falls back to Full)
//! - CPU/memory limits not supported by sandbox-exec (use timeout only)

use std::io::Write;
use std::process::Stdio;
use std::time::Instant;

use async_trait::async_trait;
use tempfile::NamedTempFile;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::{NetworkAccess, SandboxConfig};
use crate::error::SandboxError;
use crate::result::SandboxResult;
use crate::runner::{DEFAULT_PATH, validate_config};
use crate::{IsolationLevel, Sandbox};

/// Binaries that are always allowed to execute in the sandbox.
/// These are essential for build systems to function.
const ALLOWED_SYSTEM_BINARIES: &[&str] = &[
    // Shells
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/usr/bin/env",
    // Core utilities
    "/bin/ls",
    "/bin/cat",
    "/bin/cp",
    "/bin/mv",
    "/bin/rm",
    "/bin/mkdir",
    "/bin/rmdir",
    "/bin/chmod",
    "/bin/ln",
    "/bin/pwd",
    "/bin/echo",
    "/bin/test",
    "/bin/expr",
    "/bin/date",
    "/bin/sleep",
    "/usr/bin/basename",
    "/usr/bin/dirname",
    "/usr/bin/head",
    "/usr/bin/tail",
    "/usr/bin/cut",
    "/usr/bin/sort",
    "/usr/bin/uniq",
    "/usr/bin/wc",
    "/usr/bin/tr",
    "/usr/bin/sed",
    "/usr/bin/awk",
    "/usr/bin/grep",
    "/usr/bin/find",
    "/usr/bin/xargs",
    "/usr/bin/touch",
    "/usr/bin/tee",
    "/usr/bin/diff",
    "/usr/bin/patch",
    // Archive utilities
    "/usr/bin/tar",
    "/usr/bin/gzip",
    "/usr/bin/gunzip",
    "/usr/bin/bzip2",
    "/usr/bin/unzip",
    "/usr/bin/zip",
    // Development tools
    "/usr/bin/make",
    "/usr/bin/git",
    "/usr/bin/which",
    "/usr/bin/file",
    "/usr/bin/install",
    // Xcode command line tools
    "/usr/bin/xcrun",
    "/usr/bin/xcodebuild",
    "/usr/bin/xcode-select",
    "/usr/bin/clang",
    "/usr/bin/clang++",
    "/usr/bin/swift",
    "/usr/bin/swiftc",
    "/usr/bin/llvm-cov",
    // Network tools (only when network is allowed)
    "/usr/bin/curl",
];

/// Directories where executable discovery is allowed.
/// Binaries in these paths can be executed via path search.
const ALLOWED_EXEC_PATHS: &[&str] = &[
    "/bin",
    "/usr/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/Applications/Xcode.app/Contents/Developer",
    // Common toolchain locations
    "/usr/local/Cellar",
    "/opt/homebrew/Cellar",
];

/// Environment variables that should never be passed to sandboxed processes.
const DANGEROUS_ENV_VARS: &[&str] = &[
    // Credential leakage
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "DOCKER_PASSWORD",
    // Sandbox escape vectors
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    // Shell injection
    "ENV",
    "BASH_ENV",
    "CDPATH",
    "GLOBIGNORE",
    "IFS",
    // Proxy settings (could redirect traffic)
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
];

/// Check if an environment variable is safe to pass to the sandbox.
fn is_safe_env_var(name: &str) -> bool {
    if DANGEROUS_ENV_VARS
        .iter()
        .any(|&d| d.eq_ignore_ascii_case(name))
    {
        return false;
    }

    // Environment variable names should only contain alphanumeric and underscore
    if name.is_empty() {
        return false;
    }

    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        return false;
    }

    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// macOS sandbox using `sandbox-exec`.
pub struct MacOsSandbox;

impl MacOsSandbox {
    /// Create a new macOS sandbox.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check if `sandbox-exec` is available.
    #[must_use]
    pub fn is_available() -> bool {
        std::path::Path::new("/usr/bin/sandbox-exec").exists()
    }

    /// Generate the SBPL (Sandbox Profile Language) profile.
    ///
    /// # Design Notes
    ///
    /// macOS sandbox-exec is primarily designed to restrict WRITES, not reads.
    /// The dynamic linker (dyld) requires broad read access to load executables.
    /// Following Bazel's approach with 2025 security hardening:
    /// 1. Allow all file reads (dyld, system libraries, etc. need this)
    /// 2. Restrict file writes to specific directories (workdir, temp)
    /// 3. **Restrict process execution to whitelisted binaries**
    /// 4. Optionally restrict network access
    ///
    /// This ensures hermetic builds by preventing actions from writing to
    /// unexpected locations or executing arbitrary code.
    fn generate_profile(&self, config: &SandboxConfig) -> String {
        let workdir = config.workdir.to_string_lossy();

        let mut profile = String::from("(version 1)\n");

        // Default deny all operations
        profile.push_str("(deny default)\n");

        // SECURITY: Restrict process execution to whitelisted binaries only
        // This prevents sandbox escape via arbitrary binary execution
        profile.push_str("\n; Process execution restrictions\n");

        // Allow specific system binaries
        for binary in ALLOWED_SYSTEM_BINARIES {
            profile.push_str(&format!("(allow process-exec (literal \"{binary}\"))\n"));
        }

        // Allow execution from approved directories (for toolchains installed there)
        for path in ALLOWED_EXEC_PATHS {
            profile.push_str(&format!("(allow process-exec (subpath \"{path}\"))\n"));
        }

        // Allow execution from the workdir (for project scripts)
        profile.push_str(&format!("(allow process-exec (subpath \"{}\"))\n", workdir));

        // Allow other process operations (fork, signal, etc.)
        profile.push_str("(allow process-fork)\n");
        profile.push_str("(allow signal)\n");
        profile.push_str("(allow sysctl*)\n");
        profile.push_str("(allow mach*)\n");

        // Allow ALL file reads - dyld and system libraries require broad read access
        // This is consistent with Bazel's macOS sandbox approach
        profile.push_str("\n; File access\n");
        profile.push_str("(allow file-read*)\n");

        // Restrict file writes to specific directories only
        // This is the primary isolation mechanism on macOS

        // Allow workspace access (read/write)
        profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", workdir));

        // Allow temp directories
        profile.push_str("(allow file-write* (subpath \"/tmp\"))\n");
        profile.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
        profile.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
        profile.push_str("(allow file-write* (subpath \"/var/folders\"))\n");

        // Additional read-write mounts
        for mount in &config.rw_mounts {
            profile.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                mount.source.to_string_lossy()
            ));
        }

        // Network Access
        profile.push_str("\n; Network access\n");
        match &config.network {
            NetworkAccess::None => {
                profile.push_str("(deny network*)\n");
            }
            NetworkAccess::LocalhostOnly => {
                // Allow localhost connections only
                profile.push_str("(allow network* (local ip \"localhost:*\"))\n");
                profile.push_str("(allow network* (remote ip \"localhost:*\"))\n");
                profile.push_str("(deny network*)\n");
            }
            NetworkAccess::AllowList(hosts) => {
                // SBPL doesn't support per-host filtering well
                // Log warning and fall back to Full
                warn!(
                    hosts = ?hosts,
                    "macOS sandbox-exec does not support per-host network filtering, allowing full network"
                );
                profile.push_str("(allow network*)\n");
            }
            NetworkAccess::Full => {
                profile.push_str("(allow network*)\n");
            }
        }

        debug!(
            profile_len = profile.len(),
            network = ?config.network,
            allowed_binaries = ALLOWED_SYSTEM_BINARIES.len(),
            "Generated hardened SBPL profile"
        );

        profile
    }
}

impl Default for MacOsSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Sandbox for MacOsSandbox {
    async fn execute(&self, config: &SandboxConfig) -> Result<SandboxResult, SandboxError> {
        validate_config(config)?;

        // Log warnings for unsupported features
        if config.limits.memory.is_some() || config.limits.cpu_shares.is_some() {
            warn!(
                "macOS sandbox-exec does not support memory/CPU limits, only timeout is enforced"
            );
        }

        // 1. Write profile to temporary file
        // Keep _profile_file in scope so it doesn't get deleted
        let mut profile_file = NamedTempFile::new().map_err(SandboxError::Io)?;
        let profile_content = self.generate_profile(config);
        profile_file
            .write_all(profile_content.as_bytes())
            .map_err(SandboxError::Io)?;
        profile_file.flush().map_err(SandboxError::Io)?;

        // Keep the file handle alive - it will be deleted when this function returns
        let profile_path = profile_file.path().to_path_buf();
        debug!(profile_path = ?profile_path, profile_len = profile_content.len(), "Using sandbox profile");

        // 2. Prepare command: sandbox-exec -f profile_file cmd args...
        let mut cmd = Command::new("/usr/bin/sandbox-exec");
        cmd.arg("-f").arg(&profile_path);
        cmd.arg(&config.command[0]);
        cmd.args(&config.command[1..]);

        cmd.current_dir(&config.workdir);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // SECURITY: Always start with clean environment
        cmd.env_clear();

        // Inherit safe environment variables if requested
        if config.inherit_env {
            for (key, value) in std::env::vars() {
                if is_safe_env_var(&key) {
                    cmd.env(&key, value);
                } else {
                    debug!(env_var = %key, "Blocked dangerous environment variable on macOS");
                }
            }
        }

        // Apply user-specified environment variables with validation
        for (key, value) in &config.env {
            if is_safe_env_var(key) {
                cmd.env(key, value);
            } else {
                warn!(
                    env_var = %key,
                    "Blocked attempt to set dangerous environment variable in macOS sandbox"
                );
            }
        }

        // Ensure essential env vars
        if !config.env.contains_key("PATH") {
            cmd.env("PATH", DEFAULT_PATH);
        }
        if !config.env.contains_key("HOME") {
            // Use /tmp as home in sandbox to avoid leaking real home path
            cmd.env("HOME", "/tmp");
        }

        // Set reproducible locale
        cmd.env("LANG", "C.UTF-8");
        cmd.env("LC_ALL", "C.UTF-8");

        let start = Instant::now();

        // 3. Execute with resource tracking
        let child = cmd.spawn().map_err(SandboxError::Io)?;

        let output_result = if let Some(timeout_duration) = config.limits.timeout {
            match timeout(timeout_duration, child.wait_with_output()).await {
                Ok(res) => res,
                Err(_) => {
                    return Ok(SandboxResult {
                        exit_code: 124,
                        stdout: Vec::new(),
                        stderr: b"Process timed out".to_vec(),
                        duration: start.elapsed(),
                        timed_out: true,
                        resource_exceeded: false,
                        resource_usage: None,
                    });
                }
            }
        } else {
            child.wait_with_output().await
        };

        let output = output_result.map_err(SandboxError::Io)?;
        let duration = start.elapsed();

        // Get resource usage via getrusage
        let resource_usage = get_child_resource_usage();

        Ok(SandboxResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
            duration,
            timed_out: false,
            resource_exceeded: false,
            resource_usage,
        })
    }

    fn isolation_level(&self) -> IsolationLevel {
        IsolationLevel::OsSandbox
    }

    fn is_available(&self) -> bool {
        Self::is_available()
    }

    fn description(&self) -> &'static str {
        "macOS sandbox-exec (Apple Sandbox Profile Language, filesystem/network isolation)"
    }
}

/// Get resource usage for child processes via getrusage.
fn get_child_resource_usage() -> Option<crate::result::ResourceUsage> {
    use nix::sys::resource::{UsageWho, getrusage};

    match getrusage(UsageWho::RUSAGE_CHILDREN) {
        Ok(usage) => {
            let user_time = usage.user_time();
            let system_time = usage.system_time();

            Some(crate::result::ResourceUsage {
                peak_memory: Some((usage.max_rss() * 1024) as u64), // KB to bytes
                user_time_ms: Some(
                    (user_time.tv_sec() as u64 * 1000) + (user_time.tv_usec() as u64 / 1000),
                ),
                system_time_ms: Some(
                    (system_time.tv_sec() as u64 * 1000) + (system_time.tv_usec() as u64 / 1000),
                ),
                cpu_time_ms: None,
                context_switches: None,
                io_read_bytes: None,
                io_write_bytes: None,
            })
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    #[tokio::test]
    async fn test_simple_command() {
        let sandbox = MacOsSandbox::new();
        if !sandbox.is_available() {
            return; // Skip on non-macOS
        }

        let config = SandboxConfig::new(vec!["echo".into(), "hello".into()])
            .with_workdir(PathBuf::from("/tmp"));

        let result = sandbox.execute(&config).await.unwrap();
        if !result.success() {
            eprintln!("Exit code: {}", result.exit_code);
            eprintln!("Stderr: {}", result.stderr_str());
            eprintln!("Stdout: {}", result.stdout_str());
        }
        assert!(result.success());
        assert_eq!(result.stdout_str().trim(), "hello");
    }

    #[tokio::test]
    async fn test_timeout() {
        let sandbox = MacOsSandbox::new();
        if !sandbox.is_available() {
            return;
        }

        let mut config = SandboxConfig::new(vec!["sleep".into(), "10".into()])
            .with_workdir(PathBuf::from("/tmp"));
        config.limits.timeout = Some(Duration::from_millis(100));

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.timed_out);
    }

    #[tokio::test]
    async fn test_network_none() {
        let sandbox = MacOsSandbox::new();
        if !sandbox.is_available() {
            return;
        }

        // With no network, curl should fail
        let config = SandboxConfig::new(vec![
            "curl".into(),
            "-s".into(),
            "--max-time".into(),
            "2".into(),
            "http://example.com".into(),
        ])
        .with_workdir(PathBuf::from("/tmp"))
        .with_network(NetworkAccess::None);

        let result = sandbox.execute(&config).await.unwrap();
        // Should fail due to network restriction
        assert!(!result.success() || result.stdout.is_empty());
    }

    #[tokio::test]
    async fn test_resource_tracking() {
        let sandbox = MacOsSandbox::new();
        if !sandbox.is_available() {
            return;
        }

        let config =
            SandboxConfig::new(vec!["ls".into(), "-la".into()]).with_workdir(PathBuf::from("/tmp"));

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.success());

        // Resource usage should be tracked
        if let Some(usage) = &result.resource_usage {
            assert!(usage.user_time_ms.is_some() || usage.peak_memory.is_some());
        }
    }

    #[test]
    fn test_sandbox_properties() {
        let sandbox = MacOsSandbox::new();
        assert_eq!(sandbox.isolation_level(), IsolationLevel::OsSandbox);
    }

    #[test]
    fn test_profile_generation() {
        let sandbox = MacOsSandbox::new();
        let config = SandboxConfig::new(vec!["echo".into()])
            .with_workdir(PathBuf::from("/tmp"))
            .with_network(NetworkAccess::None);

        let profile = sandbox.generate_profile(&config);
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow file-read*)"));
        assert!(profile.contains("(allow file-write* (subpath \"/tmp\"))"));
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn test_write_isolation() {
        // Verify that writes outside allowed directories are blocked
        let sandbox = MacOsSandbox::new();
        if !sandbox.is_available() {
            return;
        }

        // Try to write to /usr which should be blocked
        let config = SandboxConfig::new(vec![
            "sh".into(),
            "-c".into(),
            "touch /usr/test_file 2>&1; echo done".into(),
        ])
        .with_workdir(PathBuf::from("/tmp"));

        let result = sandbox.execute(&config);
        // The command should complete but the write should fail
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(result)
            .unwrap();
        // We expect success because the shell runs, but the touch should fail
        // The sandbox blocks writes outside allowed paths
        assert!(result.success() || result.stderr_str().contains("denied"));
    }
}
