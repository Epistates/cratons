//! Linux sandbox implementation using youki's libcontainer.
//!
//! # Architecture
//!
//! This provides full OCI container isolation using `libcontainer`.
//! It replaces the previous `unshare` CLI implementation for SOTA security.
//!
//! Features:
//! - Full OCI Spec generation
//! - Seccomp filtering (via `seccomp` module)
//! - Namespace isolation (User, Pid, Mount, Network, IPC, UTS)
//! - Cgroup resource limits (where available)

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::linux::LinuxSyscall;
use nix::sys::resource::{UsageWho, getrusage};
use nix::unistd::pipe;
use tokio::time::timeout;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::SandboxConfig;
use crate::error::SandboxError;
use crate::result::{ResourceUsage, SandboxResult};
use crate::runner::validate_config;
use crate::spec::OciSpecGenerator;
use crate::{IsolationLevel, Sandbox};

/// Linux container-based sandbox using libcontainer.
pub struct LinuxSandbox {
    /// Root directory for container state
    state_dir: PathBuf,
    /// Whether to use user namespaces (rootless mode)
    rootless: bool,
}

impl LinuxSandbox {
    /// Create a new Linux sandbox.
    #[must_use]
    pub fn new() -> Self {
        let state_dir = dirs::runtime_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("cratons")
            .join("containers");

        Self {
            state_dir,
            rootless: !nix::unistd::geteuid().is_root(),
        }
    }

    /// Check if container isolation is available.
    #[must_use]
    pub fn is_container_available() -> bool {
        // We rely on kernel features, not CLI tools now
        Path::new("/proc/self/ns/user").exists()
            && Path::new("/proc/self/ns/mnt").exists()
            && Path::new("/proc/self/ns/pid").exists()
    }

    /// Execute command in isolated container using libcontainer.
    async fn execute_container(
        &self,
        config: &SandboxConfig,
    ) -> Result<SandboxResult, SandboxError> {
        let container_id = format!("cratons-{}", Uuid::new_v4());
        let bundle_dir = self.state_dir.join(&container_id);

        // Ensure state dir exists
        fs::create_dir_all(&bundle_dir).map_err(SandboxError::Io)?;

        // 1. Validate requirements
        let rootfs = config.rootfs.as_ref().ok_or_else(|| {
            SandboxError::SandboxUnavailable(
                "Rootfs is required for Linux container execution".to_string(),
            )
        })?;

        if !rootfs.exists() {
            return Err(SandboxError::SandboxUnavailable(format!(
                "Rootfs path does not exist: {}",
                rootfs.display()
            )));
        }

        // 2. Generate OCI Spec
        let spec = OciSpecGenerator::generate(config, rootfs)
            .map_err(|e| SandboxError::SandboxUnavailable(e.to_string()))?;

        // 3. Write config.json
        let spec_json = serde_json::to_string_pretty(&spec).map_err(|e| {
            SandboxError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        fs::write(bundle_dir.join("config.json"), spec_json).map_err(SandboxError::Io)?;

        // 4. Set up output capture files
        // We use files instead of pipes for simplicity with libcontainer
        let stdout_path = bundle_dir.join("stdout.log");
        let stderr_path = bundle_dir.join("stderr.log");

        // Create the output files
        File::create(&stdout_path).map_err(SandboxError::Io)?;
        File::create(&stderr_path).map_err(SandboxError::Io)?;

        // 5. Create and Start Container
        let syscall = LinuxSyscall::default();
        let mut container = ContainerBuilder::new(container_id.clone(), syscall)
            .with_root_path(&self.state_dir)
            .map_err(|e| {
                SandboxError::SandboxUnavailable(format!("Failed to build container: {}", e))
            })?
            .as_init(&bundle_dir)
            .with_systemd(false)
            .build()
            .map_err(|e| {
                SandboxError::SandboxUnavailable(format!("Failed to create container: {}", e))
            })?;

        let start = Instant::now();

        container.start().map_err(|e| {
            SandboxError::SandboxUnavailable(format!("Failed to start container: {}", e))
        })?;

        // 6. Wait for completion with timeout
        let timeout_duration = config
            .limits
            .as_ref()
            .and_then(|l| l.timeout_secs)
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(3600)); // Default 1 hour timeout

        let state_dir = self.state_dir.clone();
        let container_id_clone = container_id.clone();

        // Run the blocking wait in a spawn_blocking task with timeout
        let wait_result = timeout(
            timeout_duration,
            tokio::task::spawn_blocking(move || container.wait()),
        )
        .await;

        let (status, timed_out) = match wait_result {
            Ok(Ok(Ok(exit_code))) => (exit_code, false),
            Ok(Ok(Err(e))) => {
                return Err(SandboxError::SandboxUnavailable(format!(
                    "Failed to wait on container: {}",
                    e
                )));
            }
            Ok(Err(e)) => {
                return Err(SandboxError::SandboxUnavailable(format!(
                    "Task join error: {}",
                    e
                )));
            }
            Err(_) => {
                // Timeout occurred - kill the container
                warn!(
                    "Container {} timed out after {:?}",
                    container_id_clone, timeout_duration
                );

                // Try to kill the container
                let syscall = LinuxSyscall::default();
                if let Ok(mut container) =
                    ContainerBuilder::new(container_id_clone.clone(), syscall)
                        .with_root_path(&state_dir)
                        .and_then(|b| b.as_init(&bundle_dir).with_systemd(false).build())
                {
                    let _ = container.kill(nix::sys::signal::Signal::SIGKILL, true);
                    let _ = container.delete(true);
                }
                (-1, true)
            }
        };

        let duration = start.elapsed();

        // 7. Read captured output
        let stdout = fs::read(&stdout_path).unwrap_or_default();
        let stderr = fs::read(&stderr_path).unwrap_or_default();

        // 8. Cleanup
        let syscall = LinuxSyscall::default();
        if let Ok(mut container) = ContainerBuilder::new(container_id.clone(), syscall)
            .with_root_path(&self.state_dir)
            .and_then(|b| b.as_init(&bundle_dir).with_systemd(false).build())
        {
            let _ = container.delete(true);
        }
        let _ = fs::remove_dir_all(&bundle_dir);

        // 9. Collect Resource Usage
        let resource_usage = get_child_resource_usage();

        Ok(SandboxResult {
            exit_code: status,
            stdout,
            stderr,
            duration,
            timed_out,
            resource_exceeded: false,
            resource_usage,
        })
    }
}

impl Default for LinuxSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Sandbox for LinuxSandbox {
    async fn execute(&self, config: &SandboxConfig) -> Result<SandboxResult, SandboxError> {
        validate_config(config)?;
        self.execute_container(config).await
    }

    fn isolation_level(&self) -> IsolationLevel {
        IsolationLevel::Container
    }

    fn is_available(&self) -> bool {
        Self::is_container_available()
    }

    fn description(&self) -> &'static str {
        if self.rootless {
            "Linux OCI Container (Rootless, libcontainer)"
        } else {
            "Linux OCI Container (Root, libcontainer)"
        }
    }
}

/// Blocklist of environment variables that should never be passed to sandboxed processes.
///
/// These variables could be used to escape the sandbox or leak sensitive information.
/// Reference: <https://www.elttam.com/blog/env/>
const BLOCKED_ENV_VARS: &[&str] = &[
    // Credential leaks
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "DOCKER_AUTH_CONFIG",
    // Dynamic linker sandbox escapes (Linux)
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_HWCAP_MASK",
    "LD_ORIGIN_PATH",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "LD_VERBOSE",
    "LD_WARN",
    "LD_BIND_NOW",
    "LD_BIND_NOT",
    // Dynamic linker sandbox escapes (macOS)
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_IMAGE_SUFFIX",
    "DYLD_PRINT_TO_FILE",
    // Glibc exploitation vectors
    "GCONV_PATH",           // Character conversion path hijacking
    "MALLOC_CHECK_",        // Memory allocation debugging - can leak info
    "MALLOC_TRACE",         // Memory allocation tracing - can write files
    "GLIBC_TUNABLES",       // Glibc tuning - various exploits
    "HOSTALIASES",          // Hostname resolution hijacking
    "LOCALDOMAIN",          // DNS domain hijacking
    "RES_OPTIONS",          // Resolver options manipulation
    "RESOLV_HOST_CONF",     // Resolver config hijacking
    // Locale/internationalization hijacking
    "NLSPATH",              // Message catalog path hijacking
    "LOCPATH",              // Locale data path hijacking
    "LANGUAGE",             // Locale fallback chain
    "LC_ALL",               // Can override all locale settings
    // Terminal/filesystem path hijacking
    "TERMINFO",             // Terminal info database path
    "TERMINFO_DIRS",        // Terminal info search dirs
    "TERMCAP",              // Terminal capabilities database
    "TZDIR",                // Timezone directory hijacking
    "TMPDIR",               // Temporary directory (can redirect writes)
    "TMP",                  // Temporary directory (Windows compat)
    "TEMP",                 // Temporary directory (Windows compat)
    // Code injection - scripting languages
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "RUBYOPT",
    "RUBYLIB",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "NODE_REPL_HISTORY",
    // Java exploitation
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    // Shell and privilege escalation
    "SHELL",
    "BASH_ENV",
    "ENV",                  // POSIX shell startup file
    "CDPATH",               // Can redirect cd commands
    "GLOBIGNORE",           // Affects glob expansion
    "SHELLOPTS",            // Shell options
    "BASHOPTS",             // Bash options
    "PS4",                  // Debug prompt - can execute code
    "PROMPT_COMMAND",       // Bash prompt hook - code execution
    "IFS",                  // Internal field separator manipulation
    // Sudo/privilege context
    "SUDO_COMMAND",
    "SUDO_USER",
    "SUDO_UID",
    "SUDO_GID",
    "SUDO_ASKPASS",
    "TERM_PROGRAM",
    // Network proxy (could exfiltrate data)
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "ftp_proxy",
    "FTP_PROXY",
    // Git exploitation
    "GIT_ASKPASS",
    "GIT_SSH_COMMAND",
    "GIT_PROXY_COMMAND",
    "GIT_CONFIG_GLOBAL",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    // Miscellaneous dangerous vars
    "LD_PROFILE",           // Can write profiling data
    "EDITOR",               // Could be exploited in some contexts
    "VISUAL",               // Alternative editor variable
    "PAGER",                // Pager command execution
    "BROWSER",              // Browser command execution
    "LESSOPEN",             // Less preprocessor - code execution
    "LESSCLOSE",            // Less postprocessor - code execution
];

/// Check if an environment variable is safe to pass to sandboxed processes.
///
/// Returns `true` if the variable is safe, `false` if it should be blocked.
#[must_use]
pub fn is_safe_env_var(name: &str) -> bool {
    // Block known dangerous variables
    if BLOCKED_ENV_VARS
        .iter()
        .any(|&blocked| blocked.eq_ignore_ascii_case(name))
    {
        return false;
    }

    // Block any variable starting with dangerous prefixes
    let name_upper = name.to_uppercase();
    let dangerous_prefixes = [
        "LD_",
        "DYLD_",
        "_JAVA_OPTIONS",
        "JAVA_TOOL_OPTIONS",
        "CRATONS_", // Internal vars (block from inheriting into sandbox)
    ];

    for prefix in dangerous_prefixes {
        if name_upper.starts_with(prefix) {
            return false;
        }
    }

    true
}

/// Get resource usage for child processes via getrusage.
fn get_child_resource_usage() -> Option<ResourceUsage> {
    match getrusage(UsageWho::RUSAGE_CHILDREN) {
        Ok(usage) => {
            let user_time = usage.user_time();
            let system_time = usage.system_time();

            Some(ResourceUsage {
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
        Err(e) => {
            debug!("Failed to get child resource usage: {}", e);
            None
        }
    }
}
