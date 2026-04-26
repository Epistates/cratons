//! Linux sandbox implementation using an OCI runtime (`crun` or `runc`).
//!
//! The backend generates a hardened OCI bundle and delegates execution to a
//! host-installed OCI runtime. This avoids linking CRIU/libcontainer into
//! cratons itself while retaining namespace, cgroup, and seccomp isolation.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::config::SandboxConfig;
use crate::error::SandboxError;
use crate::result::SandboxResult;
use crate::{IsolationLevel, Sandbox};

/// Linux OCI-runtime sandbox.
pub struct LinuxSandbox {
    inner: crate::container::ContainerSandbox,
    rootless: bool,
}

impl LinuxSandbox {
    /// Create a new Linux sandbox.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: crate::container::ContainerSandbox::new(),
            rootless: !nix::unistd::geteuid().is_root(),
        }
    }

    /// Check if Linux container isolation is available.
    #[must_use]
    pub fn is_container_available() -> bool {
        Path::new("/proc/self/ns/user").exists()
            && Path::new("/proc/self/ns/mnt").exists()
            && Path::new("/proc/self/ns/pid").exists()
            && which::which("crun")
                .or_else(|_| which::which("runc"))
                .is_ok()
    }

    /// Return the default rootfs path for Linux container execution.
    ///
    /// Operators can set `CRATONS_SANDBOX_ROOTFS` to a minimal, patched,
    /// read-only root filesystem containing `/bin/sh` and required runtime
    /// libraries. If unset, cratons probes the conventional managed path.
    #[must_use]
    pub fn default_rootfs() -> Option<PathBuf> {
        if let Ok(path) = std::env::var("CRATONS_SANDBOX_ROOTFS") {
            let path = PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
            return None;
        }

        let path = PathBuf::from("/var/lib/cratons/rootfs");
        path.exists().then_some(path)
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
        let config_with_default_rootfs;
        let config = if config.rootfs.is_some() {
            config
        } else if let Some(rootfs) = Self::default_rootfs() {
            config_with_default_rootfs = config.clone().with_rootfs(rootfs);
            &config_with_default_rootfs
        } else {
            return Err(SandboxError::NotAvailable(
                "Linux OCI sandbox requires a trusted rootfs. Set CRATONS_SANDBOX_ROOTFS \
                 or install one at /var/lib/cratons/rootfs."
                    .to_string(),
            ));
        };

        self.inner.execute(config).await
    }

    fn isolation_level(&self) -> IsolationLevel {
        IsolationLevel::Container
    }

    fn is_available(&self) -> bool {
        Self::is_container_available()
    }

    fn description(&self) -> &'static str {
        if self.rootless {
            "Linux OCI Container (rootless, crun/runc)"
        } else {
            "Linux OCI Container (root, crun/runc)"
        }
    }
}

/// Environment variables that should never be passed to sandboxed processes.
const BLOCKED_ENV_VARS: &[&str] = &[
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
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "GCONV_PATH",
    "MALLOC_CHECK_",
    "MALLOC_TRACE",
    "GLIBC_TUNABLES",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "RESOLV_HOST_CONF",
    "NLSPATH",
    "LOCPATH",
    "LANGUAGE",
    "LC_ALL",
    "TERMINFO",
    "TERMINFO_DIRS",
    "TERMCAP",
    "TZDIR",
    "TMPDIR",
    "TMP",
    "TEMP",
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
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    "SHELL",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "GLOBIGNORE",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "PROMPT_COMMAND",
    "IFS",
    "SUDO_COMMAND",
    "SUDO_USER",
    "SUDO_UID",
    "SUDO_GID",
    "SUDO_ASKPASS",
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "ftp_proxy",
    "FTP_PROXY",
    "GIT_ASKPASS",
    "GIT_SSH_COMMAND",
    "GIT_PROXY_COMMAND",
    "GIT_CONFIG_GLOBAL",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "BROWSER",
    "LESSOPEN",
    "LESSCLOSE",
];

/// Check if an environment variable is safe to pass to sandboxed processes.
#[must_use]
pub fn is_safe_env_var(name: &str) -> bool {
    if BLOCKED_ENV_VARS
        .iter()
        .any(|&blocked| blocked.eq_ignore_ascii_case(name))
    {
        return false;
    }

    let name_upper = name.to_uppercase();
    let dangerous_prefixes = [
        "LD_",
        "DYLD_",
        "_JAVA_OPTIONS",
        "JAVA_TOOL_OPTIONS",
        "CRATONS_",
    ];

    !dangerous_prefixes
        .iter()
        .any(|prefix| name_upper.starts_with(prefix))
}
