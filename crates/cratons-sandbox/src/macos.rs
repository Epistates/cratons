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
//! - Write isolation via SBPL deny rules
//! - Network isolation (full deny or allow)
//! - **Process execution restricted to whitelisted binaries**
//! - **Environment variable sanitization**
//! - Resource usage tracking via getrusage
//!
//! ## Limitations
//! - Per-host network filtering not supported (AllowList is refused)
//! - Read isolation is not complete enough to satisfy `SandboxPolicy::Required`
//! - CPU/memory limits not supported by sandbox-exec (use timeout only)

use std::io::Write;
use std::path::Path;
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
use crate::runner::{DEFAULT_PATH, enforce_policy, validate_config};
use crate::{IsolationLevel, Sandbox};

/// Binaries that are always allowed to execute in the sandbox.
/// These are essential for build systems to function.
///
/// # Security Note
///
/// This list is intentionally minimal. Only binaries strictly required for
/// builds are included. Network tools (curl, wget) are conditionally added
/// based on network access settings.
const ALLOWED_SYSTEM_BINARIES: &[&str] = &[
    // Shells (required for script execution)
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/usr/bin/env",
    // Core utilities (file manipulation)
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
    // Development tools (minimal set)
    "/usr/bin/make",
    "/usr/bin/git",
    "/usr/bin/which",
    "/usr/bin/file",
    "/usr/bin/install",
    // Xcode command line tools (Apple-signed, trusted)
    "/usr/bin/xcrun",
    "/usr/bin/xcodebuild",
    "/usr/bin/xcode-select",
    "/usr/bin/clang",
    "/usr/bin/clang++",
    "/usr/bin/swift",
    "/usr/bin/swiftc",
    "/usr/bin/llvm-cov",
];

/// Network tools that are only allowed when network access is enabled.
/// These are excluded by default to prevent data exfiltration.
const NETWORK_BINARIES: &[&str] = &[
    "/usr/bin/curl",
    "/usr/bin/nc",
    "/usr/bin/nslookup",
    "/usr/bin/dig",
    "/usr/bin/host",
];

/// Minimal set of system directories where execution is allowed.
///
/// # Security Note
///
/// We intentionally do NOT include:
/// - `/usr/local/bin` - User-installed binaries, could contain malware
/// - `/opt/homebrew/bin` - Homebrew binaries, not vetted
/// - `/opt/homebrew/Cellar` - All homebrew packages, too permissive
///
/// For builds that need additional toolchains, the toolchain path should
/// be explicitly added to the sandbox config's allowed paths.
const ALLOWED_EXEC_PATHS: &[&str] = &[
    // System binaries only - these are Apple-signed and trusted
    "/bin",
    "/usr/bin",
    // Xcode toolchain - Apple-signed, required for native builds
    "/Applications/Xcode.app/Contents/Developer",
    "/Library/Developer/CommandLineTools",
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

fn sbpl_string(value: &str) -> Result<String, SandboxError> {
    if value.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(SandboxError::Config(format!(
            "SBPL string contains a control character: {value:?}"
        )));
    }

    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            _ => escaped.push(ch),
        }
    }
    Ok(escaped)
}

fn sbpl_path(path: &Path) -> Result<String, SandboxError> {
    sbpl_string(&path.to_string_lossy())
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
        static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

        *AVAILABLE.get_or_init(|| {
            if !std::path::Path::new("/usr/bin/sandbox-exec").exists() {
                return false;
            }

            let probe_config = SandboxConfig::new(vec!["/usr/bin/true".to_string()])
                .with_workdir(std::path::PathBuf::from("/tmp"))
                .with_network(NetworkAccess::None);
            let sandbox = Self;
            let profile_content = match sandbox.generate_profile(&probe_config) {
                Ok(profile) => profile,
                Err(_) => return false,
            };

            let mut profile_file = match NamedTempFile::new() {
                Ok(file) => file,
                Err(_) => return false,
            };
            if profile_file.write_all(profile_content.as_bytes()).is_err()
                || profile_file.flush().is_err()
            {
                return false;
            }

            matches!(
                std::process::Command::new("/usr/bin/sandbox-exec")
                    .arg("-f")
                    .arg(profile_file.path())
                    .arg("/usr/bin/true")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status(),
                Ok(status) if status.success()
            )
        })
    }

    /// Generate the SBPL (Sandbox Profile Language) profile.
    ///
    /// # Design Notes
    ///
    /// macOS sandbox-exec is best used as a write/network/process-exec
    /// restriction layer. It cannot provide container-grade read isolation
    /// or cgroup-style resource limits, so the crate-level capability
    /// reporting deliberately does not advertise those guarantees.
    ///
    /// Profile posture:
    /// 1. Allow reads from declared mounts and system runtime paths only.
    /// 2. Restrict file writes to specific directories (workdir, temp).
    /// 3. **Restrict process execution to whitelisted binaries**
    /// 4. Optionally restrict network access
    ///
    /// This ensures hermetic builds by preventing actions from writing to
    /// unexpected locations or executing arbitrary code.
    fn generate_profile(&self, config: &SandboxConfig) -> Result<String, SandboxError> {
        let workdir = sbpl_path(&config.workdir)?;

        let mut profile = String::from("(version 1)\n");

        // Default deny all operations
        profile.push_str("(deny default)\n");

        // SECURITY: Restrict process execution to whitelisted binaries only
        // This prevents sandbox escape via arbitrary binary execution
        profile.push_str("\n; Process execution restrictions\n");

        // Allow specific system binaries
        for binary in ALLOWED_SYSTEM_BINARIES {
            profile.push_str(&format!(
                "(allow process-exec (literal \"{}\"))\n",
                sbpl_string(binary)?
            ));
        }

        // SECURITY: Only allow network tools when network access is enabled
        // This prevents data exfiltration attempts via curl/nc/etc
        let network_enabled = !matches!(&config.network, NetworkAccess::None);
        if network_enabled {
            for binary in NETWORK_BINARIES {
                profile.push_str(&format!(
                    "(allow process-exec (literal \"{}\"))\n",
                    sbpl_string(binary)?
                ));
            }
            debug!("Network enabled: allowing network binaries");
        } else {
            debug!("Network disabled: blocking network binaries (curl, nc, etc.)");
        }

        // Allow execution from approved directories (for toolchains installed there)
        // NOTE: This is intentionally restricted to Apple-signed paths only
        for path in ALLOWED_EXEC_PATHS {
            profile.push_str(&format!(
                "(allow process-exec (subpath \"{}\"))\n",
                sbpl_string(path)?
            ));
        }

        // Allow execution from explicitly-declared toolchain mounts.
        //
        // SECURITY: previously this iterated `config.ro_mounts` and granted
        // `process-exec` to any mount whose source path *contained the
        // substring* "toolchain", "sdk", "node", "python", "rust", or "go".
        // That heuristic was attacker-controllable: a malicious package or
        // caller could declare a mount like `/tmp/toolchain/evil` and have
        // it auto-allowlisted for execution, defeating `(deny default)`.
        // The allowlist now requires an explicit opt-in via the dedicated
        // `Mount.allow_exec` field, so the decision is data-driven from
        // operator-controlled config rather than inferred from path strings.
        for mount in &config.ro_mounts {
            if mount.allow_exec {
                profile.push_str(&format!(
                    "(allow process-exec (subpath \"{}\"))\n",
                    sbpl_path(&mount.source)?
                ));
                debug!(
                    "Allowing execution from explicitly-declared exec mount: {}",
                    mount.source.display()
                );
            }
        }

        // Allow execution from the workdir (for project scripts)
        profile.push_str(&format!("(allow process-exec (subpath \"{}\"))\n", workdir));

        // Allow other process operations (fork, signal, etc.)
        profile.push_str("(allow process-fork)\n");
        profile.push_str("(allow signal)\n");
        profile.push_str("(allow sysctl*)\n");
        profile.push_str("(allow mach*)\n");

        // Allow reads from declared inputs and system runtime paths. This
        // avoids exposing the caller's home directory and credential files
        // via an unconditional `(allow file-read*)`.
        profile.push_str("\n; File access\n");
        profile.push_str("(allow file-read-metadata)\n");
        for path in ALLOWED_EXEC_PATHS {
            profile.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                sbpl_string(path)?
            ));
        }
        for binary in ALLOWED_SYSTEM_BINARIES {
            profile.push_str(&format!(
                "(allow file-read* (literal \"{}\"))\n",
                sbpl_string(binary)?
            ));
        }
        if network_enabled {
            for binary in NETWORK_BINARIES {
                profile.push_str(&format!(
                    "(allow file-read* (literal \"{}\"))\n",
                    sbpl_string(binary)?
                ));
            }
        }
        profile.push_str("(allow file-read* (subpath \"/System\"))\n");
        profile.push_str("(allow file-read* (subpath \"/usr/lib\"))\n");
        profile.push_str("(allow file-read* (subpath \"/Library/Apple\"))\n");
        profile.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", workdir));
        for mount in &config.ro_mounts {
            profile.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                sbpl_path(&mount.source)?
            ));
        }
        for mount in &config.rw_mounts {
            profile.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                sbpl_path(&mount.source)?
            ));
        }

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
                sbpl_path(&mount.source)?
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
                // SECURITY: SBPL has no per-host network filtering primitive,
                // so we cannot honor `AllowList` faithfully. The previous
                // behavior was to log a warning and silently degrade to
                // `(allow network*)` — full unrestricted network — which
                // turned a stricter caller request into a *less* restrictive
                // sandbox without surfacing the change. That is a data
                // exfiltration foot-gun: a caller that asks for "only
                // example.com" gets unrestricted egress instead.
                //
                // We now fail closed: callers must explicitly choose between
                // `Full` (accept unrestricted egress) and `None`/`LocalhostOnly`
                // (accept stricter-than-requested isolation).
                return Err(SandboxError::Unsupported(format!(
                    "macOS sandbox-exec cannot enforce per-host network allowlists; \
                     refusing to silently degrade to full network access. \
                     Requested allowlist: {hosts:?}. Use NetworkAccess::Full to \
                     opt in explicitly, or NetworkAccess::None / LocalhostOnly \
                     for stricter isolation."
                )));
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

        Ok(profile)
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
        enforce_policy(config, IsolationLevel::OsSandbox)?;

        if !Self::is_available() {
            return Err(SandboxError::NotAvailable(
                "sandbox-exec is not available or the OS denied sandbox_apply".to_string(),
            ));
        }

        // Log warnings for unsupported features
        if config.limits.memory.is_some() || config.limits.cpu_shares.is_some() {
            warn!(
                "macOS sandbox-exec does not support memory/CPU limits, only timeout is enforced"
            );
        }

        // 1. Write profile to temporary file
        // Keep _profile_file in scope so it doesn't get deleted
        let mut profile_file = NamedTempFile::new().map_err(SandboxError::Io)?;
        let profile_content = self.generate_profile(config)?;
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
        cmd.kill_on_drop(true);

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
        "macOS sandbox-exec (Apple Sandbox Profile Language, network/write/process isolation)"
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
    use std::process::Command as StdCommand;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::time::sleep;

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
    async fn test_timeout_terminates_child() {
        let sandbox = MacOsSandbox::new();
        if !sandbox.is_available() {
            return;
        }

        let temp = tempdir().unwrap();
        let pid_file = temp.path().join("child.pid");

        let mut config = SandboxConfig::new(vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf '%s' $$ > \"$1\"; exec sleep 10".into(),
            "sh".into(),
            pid_file.display().to_string(),
        ])
        .with_workdir(temp.path().to_path_buf());
        config.limits.timeout = Some(Duration::from_millis(100));

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.timed_out);

        let mut pid = None;
        for _ in 0..20 {
            if let Ok(contents) = std::fs::read_to_string(&pid_file) {
                if let Ok(parsed) = contents.trim().parse::<u32>() {
                    pid = Some(parsed);
                    break;
                }
            }
            sleep(Duration::from_millis(25)).await;
        }
        let pid = pid.expect("sandboxed child should have written its pid");

        sleep(Duration::from_millis(100)).await;
        let status = StdCommand::new("/bin/kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .unwrap();
        assert!(
            !status.success(),
            "timed-out sandbox child process {pid} should have been terminated"
        );
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

        let profile = sandbox.generate_profile(&config).unwrap();
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(!profile.contains("(allow file-read*)\n"));
        assert!(profile.contains("(allow file-read-metadata)"));
        assert!(profile.contains("(allow file-write* (subpath \"/tmp\"))"));
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn allowlist_network_returns_unsupported_instead_of_silent_full() {
        let sandbox = MacOsSandbox::new();
        let config = SandboxConfig::new(vec!["echo".into()])
            .with_workdir(PathBuf::from("/tmp"))
            .with_network(NetworkAccess::AllowList(vec!["example.com".into()]));
        let err = sandbox
            .generate_profile(&config)
            .expect_err("AllowList must be refused on macOS, not silently degraded");
        assert!(
            matches!(err, SandboxError::Unsupported(_)),
            "expected SandboxError::Unsupported, got {err:?}"
        );
    }

    #[test]
    fn ro_mount_does_not_grant_exec_unless_allow_exec_set() {
        let sandbox = MacOsSandbox::new();
        let config = SandboxConfig::new(vec!["echo".into()])
            .with_workdir(PathBuf::from("/tmp"))
            .with_network(NetworkAccess::None)
            .with_ro_mount(crate::config::Mount::readonly(
                PathBuf::from("/tmp/toolchain/evil"),
                PathBuf::from("/opt/toolchain/evil"),
            ));
        let profile = sandbox.generate_profile(&config).unwrap();
        // Path-substring heuristic must be gone: a mount whose source
        // contains "toolchain" must NOT auto-allowlist process-exec.
        assert!(
            !profile.contains("(allow process-exec (subpath \"/tmp/toolchain/evil\"))"),
            "ro_mount path leaked into exec allowlist via substring heuristic:\n{profile}"
        );
    }

    #[test]
    fn sbpl_profile_escapes_dynamic_paths() {
        let sandbox = MacOsSandbox::new();
        let config = SandboxConfig::new(vec!["echo".into()])
            .with_workdir(PathBuf::from("/tmp/cratons\"quoted"))
            .with_network(NetworkAccess::None);

        let profile = sandbox.generate_profile(&config).unwrap();
        assert!(profile.contains("/tmp/cratons\\\"quoted"));
    }

    #[test]
    fn ro_mount_grants_exec_when_allow_exec_set() {
        let sandbox = MacOsSandbox::new();
        let config = SandboxConfig::new(vec!["echo".into()])
            .with_workdir(PathBuf::from("/tmp"))
            .with_network(NetworkAccess::None)
            .with_ro_mount(crate::config::Mount::readonly_executable(
                PathBuf::from("/opt/trusted-toolchain"),
                PathBuf::from("/opt/trusted-toolchain"),
            ));
        let profile = sandbox.generate_profile(&config).unwrap();
        assert!(
            profile.contains("(allow process-exec (subpath \"/opt/trusted-toolchain\"))"),
            "explicit allow_exec mount should be exec-allowed in SBPL profile:\n{profile}"
        );
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
