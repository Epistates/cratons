//! Sandbox configuration types.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration for sandbox execution.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Command to execute (program and arguments).
    pub command: Vec<String>,

    /// Working directory for the command.
    pub workdir: PathBuf,

    /// Environment variables.
    pub env: HashMap<String, String>,

    /// Read-only mounts: (host_path, container_path).
    pub ro_mounts: Vec<Mount>,

    /// Read-write mounts: (host_path, container_path).
    pub rw_mounts: Vec<Mount>,

    /// Network access policy.
    pub network: NetworkAccess,

    /// Resource limits.
    pub limits: ResourceLimits,

    /// User/group to run as (Linux).
    pub user: Option<SandboxUser>,

    /// Whether to inherit the current environment.
    pub inherit_env: bool,

    /// Stdin data to provide to the process.
    pub stdin: Option<Vec<u8>>,

    /// Root filesystem for the container.
    pub rootfs: Option<PathBuf>,

    /// Hard isolation requirements.
    ///
    /// When a field is `true`, a backend that cannot satisfy that property
    /// must refuse with `SandboxError::Unsupported` rather than silently
    /// degrading. This is how callers express "I will not run untrusted code
    /// without filesystem isolation" rather than relying on the caller to
    /// inspect `IsolationLevel::has_filesystem_isolation()` themselves.
    pub policy: SandboxPolicy,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            workdir: PathBuf::from("."),
            env: HashMap::new(),
            ro_mounts: Vec::new(),
            rw_mounts: Vec::new(),
            network: NetworkAccess::None,
            limits: ResourceLimits::default(),
            user: None,
            inherit_env: false,
            stdin: None,
            rootfs: None,
            policy: SandboxPolicy::default(),
        }
    }
}

/// Caller-declared isolation requirements that a backend must satisfy.
///
/// Set fields to `true` to make the backend refuse rather than silently
/// degrade. Default is "best effort" — every field is `false`, matching
/// the historical behaviour where callers chose isolation by selecting an
/// `IsolationLevel`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// When `true`, the backend must provide filesystem isolation
    /// (`IsolationLevel::has_filesystem_isolation()`). macOS sandbox-exec
    /// does not satisfy this and will return `SandboxError::Unsupported`.
    pub require_filesystem_isolation: bool,

    /// When `true`, the backend must provide network isolation strong enough
    /// to enforce `NetworkAccess::None` or `LocalhostOnly`.
    pub require_network_isolation: bool,

    /// When `true`, the backend must enforce CPU/memory resource limits.
    /// macOS sandbox-exec and Windows Job Objects (without containers)
    /// cannot satisfy this.
    pub require_resource_limits: bool,
}

impl SandboxConfig {
    /// Create a new sandbox configuration for a command.
    #[must_use]
    pub fn new(command: Vec<String>) -> Self {
        Self {
            command,
            ..Default::default()
        }
    }

    /// Set the root filesystem.
    #[must_use]
    pub fn with_rootfs(mut self, rootfs: PathBuf) -> Self {
        self.rootfs = Some(rootfs);
        self
    }

    /// Set the working directory.
    #[must_use]
    pub fn with_workdir(mut self, workdir: PathBuf) -> Self {
        self.workdir = workdir;
        self
    }

    /// Add an environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add multiple environment variables.
    #[must_use]
    pub fn with_envs(mut self, envs: HashMap<String, String>) -> Self {
        self.env.extend(envs);
        self
    }

    /// Add a read-only mount.
    #[must_use]
    pub fn with_ro_mount(mut self, mount: Mount) -> Self {
        self.ro_mounts.push(mount);
        self
    }

    /// Add a read-write mount.
    #[must_use]
    pub fn with_rw_mount(mut self, mount: Mount) -> Self {
        self.rw_mounts.push(mount);
        self
    }

    /// Set the network access policy.
    #[must_use]
    pub fn with_network(mut self, network: NetworkAccess) -> Self {
        self.network = network;
        self
    }

    /// Set resource limits.
    #[must_use]
    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Inherit the current environment.
    #[must_use]
    pub fn inherit_env(mut self) -> Self {
        self.inherit_env = true;
        self
    }

    /// Set the hard-isolation policy. Backends that cannot satisfy the
    /// declared requirements must refuse rather than degrade.
    #[must_use]
    pub fn with_policy(mut self, policy: SandboxPolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// A filesystem mount for the sandbox.
#[derive(Debug, Clone)]
pub struct Mount {
    /// Path on the host.
    pub source: PathBuf,
    /// Path inside the sandbox.
    pub target: PathBuf,
    /// Whether this mount is read-only.
    pub readonly: bool,
    /// Whether binaries inside this mount may be `exec`'d by the sandboxed
    /// process. Defaults to `false` so that data mounts and untrusted
    /// content cannot be used to escape an exec allowlist (macOS SBPL,
    /// Linux noexec policies). Set to `true` only for explicitly trusted
    /// toolchain mounts.
    pub allow_exec: bool,
}

impl Mount {
    /// Create a new read-only mount. `allow_exec` defaults to `false`.
    #[must_use]
    pub fn readonly(source: PathBuf, target: PathBuf) -> Self {
        Self {
            source,
            target,
            readonly: true,
            allow_exec: false,
        }
    }

    /// Create a new read-only toolchain mount whose contents are
    /// explicitly trusted to be executed by the sandboxed process.
    #[must_use]
    pub fn readonly_executable(source: PathBuf, target: PathBuf) -> Self {
        Self {
            source,
            target,
            readonly: true,
            allow_exec: true,
        }
    }

    /// Create a new read-write mount.
    #[must_use]
    pub fn readwrite(source: PathBuf, target: PathBuf) -> Self {
        Self {
            source,
            target,
            readonly: false,
            allow_exec: false,
        }
    }

    /// Create a bind mount (same path on host and sandbox).
    #[must_use]
    pub fn bind(path: PathBuf, readonly: bool) -> Self {
        Self {
            source: path.clone(),
            target: path,
            readonly,
            allow_exec: false,
        }
    }
}

/// Network access policy for the sandbox.
///
/// ## Platform Support
///
/// | Mode | Linux | macOS | Windows |
/// |------|-------|-------|---------|
/// | `None` | Full | Full | Partial |
/// | `LocalhostOnly` | Full | Full | Partial |
/// | `AllowList` | Full (iptables) | Refused (use `Full` or `LocalhostOnly`) | Not supported |
/// | `Full` | Full | Full | Full |
///
/// On macOS, per-host filtering is not supported by the sandbox-exec SBPL.
/// Use the two-phase approach: fetch with full network, build with no network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAccess {
    /// No network access (fully isolated).
    #[default]
    None,
    /// Allow only localhost/loopback connections (127.0.0.1, ::1).
    /// Useful for local tooling, databases, or services.
    LocalhostOnly,
    /// Allow access to specific hosts only.
    /// Note: macOS sandbox-exec cannot enforce this; the macOS backend
    /// returns `SandboxError::Unsupported` rather than silently
    /// degrading to a less-restrictive policy.
    AllowList(Vec<String>),
    /// Full network access.
    Full,
}

impl NetworkAccess {
    /// Check if any network access is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Check if localhost connections are allowed.
    #[must_use]
    pub fn allows_localhost(&self) -> bool {
        matches!(self, Self::LocalhostOnly | Self::AllowList(_) | Self::Full)
    }

    /// Check if a specific host is allowed.
    #[must_use]
    pub fn allows_host(&self, host: &str) -> bool {
        match self {
            Self::None => false,
            Self::LocalhostOnly => {
                host == "localhost"
                    || host == "127.0.0.1"
                    || host == "::1"
                    || host.starts_with("127.")
            }
            Self::AllowList(hosts) => {
                // Localhost is always allowed in AllowList mode
                if host == "localhost" || host == "127.0.0.1" || host == "::1" {
                    return true;
                }
                hosts.iter().any(|h| h == host || host.ends_with(h))
            }
            Self::Full => true,
        }
    }
}

/// Resource limits for sandbox execution.
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    /// Memory limit in bytes.
    pub memory: Option<u64>,

    /// CPU shares (relative weight, 1024 = 1 CPU).
    pub cpu_shares: Option<u64>,

    /// CPU quota (microseconds per period).
    pub cpu_quota: Option<u64>,

    /// CPU period (default 100000 = 100ms).
    pub cpu_period: Option<u64>,

    /// Maximum number of processes/threads.
    pub pids: Option<u64>,

    /// Maximum file size in bytes.
    pub fsize: Option<u64>,

    /// Maximum number of open files.
    pub nofile: Option<u64>,

    /// Execution timeout.
    pub timeout: Option<Duration>,
}

impl ResourceLimits {
    /// Create restrictive limits suitable for post-install scripts.
    #[must_use]
    pub fn for_post_install() -> Self {
        Self {
            memory: Some(512 * 1024 * 1024),         // 512 MB
            cpu_shares: Some(512),                   // Half a CPU
            pids: Some(100),                         // Max 100 processes
            nofile: Some(1024),                      // Max 1024 open files
            timeout: Some(Duration::from_secs(300)), // 5 minute timeout
            ..Default::default()
        }
    }

    /// Create limits suitable for builds.
    #[must_use]
    pub fn for_build() -> Self {
        Self {
            memory: Some(4 * 1024 * 1024 * 1024),     // 4 GB
            pids: Some(1000),                         // Max 1000 processes
            timeout: Some(Duration::from_secs(3600)), // 1 hour timeout
            ..Default::default()
        }
    }

    /// Create unlimited resource limits.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::default()
    }
}

/// User/group specification for sandbox execution.
#[derive(Debug, Clone)]
pub struct SandboxUser {
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Additional group IDs.
    pub additional_gids: Vec<u32>,
}

impl SandboxUser {
    /// Create from numeric IDs.
    #[must_use]
    pub fn from_ids(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            additional_gids: Vec::new(),
        }
    }

    /// Use nobody user (65534).
    #[must_use]
    pub fn nobody() -> Self {
        Self::from_ids(65534, 65534)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_builder() {
        let config = SandboxConfig::new(vec!["echo".into(), "hello".into()])
            .with_workdir(PathBuf::from("/tmp"))
            .with_env("FOO", "bar")
            .with_network(NetworkAccess::None)
            .inherit_env();

        assert_eq!(config.command, vec!["echo", "hello"]);
        assert_eq!(config.workdir, PathBuf::from("/tmp"));
        assert_eq!(config.env.get("FOO"), Some(&"bar".to_string()));
        assert!(config.inherit_env);
    }

    #[test]
    fn test_network_access() {
        // None
        assert!(!NetworkAccess::None.is_allowed());
        assert!(!NetworkAccess::None.allows_localhost());
        assert!(!NetworkAccess::None.allows_host("localhost"));

        // LocalhostOnly
        assert!(NetworkAccess::LocalhostOnly.is_allowed());
        assert!(NetworkAccess::LocalhostOnly.allows_localhost());
        assert!(NetworkAccess::LocalhostOnly.allows_host("localhost"));
        assert!(NetworkAccess::LocalhostOnly.allows_host("127.0.0.1"));
        assert!(NetworkAccess::LocalhostOnly.allows_host("::1"));
        assert!(!NetworkAccess::LocalhostOnly.allows_host("example.com"));

        // AllowList
        let allowlist = NetworkAccess::AllowList(vec!["registry.npmjs.org".into()]);
        assert!(allowlist.is_allowed());
        assert!(allowlist.allows_localhost());
        assert!(allowlist.allows_host("localhost"));
        assert!(allowlist.allows_host("registry.npmjs.org"));
        assert!(!allowlist.allows_host("evil.com"));

        // Full
        assert!(NetworkAccess::Full.is_allowed());
        assert!(NetworkAccess::Full.allows_localhost());
        assert!(NetworkAccess::Full.allows_host("anything.com"));
    }

    #[test]
    fn test_resource_limits() {
        let limits = ResourceLimits::for_post_install();
        assert!(limits.memory.is_some());
        assert!(limits.timeout.is_some());

        let unlimited = ResourceLimits::unlimited();
        assert!(unlimited.memory.is_none());
    }

    #[test]
    fn test_mount() {
        let ro = Mount::readonly(PathBuf::from("/src"), PathBuf::from("/dst"));
        assert!(ro.readonly);

        let rw = Mount::readwrite(PathBuf::from("/src"), PathBuf::from("/dst"));
        assert!(!rw.readonly);

        let bind = Mount::bind(PathBuf::from("/path"), true);
        assert_eq!(bind.source, bind.target);
    }
}
