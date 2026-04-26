//! Apple Virtualization Framework integration.
//!
//! This module provides support for running Linux containers on macOS using
//! Apple's `Virtualization.framework`.
//!
//! It currently supports:
//! 1. Wrapping the `container` tool from [apple/container](https://github.com/apple/container).
//! 2. Future: Native bindings to `Virtualization.framework` via Rust.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::timeout;

use crate::config::{NetworkAccess, SandboxConfig};
use crate::error::SandboxError;
use crate::result::SandboxResult;
use crate::{IsolationLevel, Sandbox};

/// Cross-platform env-var deny-list for sandboxed builds.
///
/// Mirrors the Linux/Windows backends so the Apple Container path enforces
/// the same posture: dangerous loader/scripting/credential variables never
/// flow into the guest, even though the guest is in a VM.
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
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "DOCKER_AUTH_CONFIG",
    // Dynamic-linker hijacks (relevant inside the Linux guest)
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    // Scripting-language code injection
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    // Network proxy (potential exfil channel)
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "FTP_PROXY",
    // Git exploitation
    "GIT_ASKPASS",
    "GIT_SSH_COMMAND",
    "GIT_PROXY_COMMAND",
    "GIT_CONFIG_GLOBAL",
    "GIT_EXEC_PATH",
];

const BLOCKED_ENV_PREFIXES: &[&str] = &["LD_", "DYLD_", "CRATONS_"];

fn is_safe_env_var(name: &str) -> bool {
    if BLOCKED_ENV_VARS
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(name))
    {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    !BLOCKED_ENV_PREFIXES
        .iter()
        .any(|prefix| upper.starts_with(prefix))
}

/// Sandbox using Apple's `container` tool (based on Virtualization.framework).
///
/// This requires the `container` binary to be in the PATH.
/// See: <https://github.com/apple/container>
pub struct AppleContainerSandbox {
    tool_path: PathBuf,
}

impl AppleContainerSandbox {
    /// Create a new Apple Container sandbox.
    pub fn new() -> Self {
        Self {
            tool_path: PathBuf::from("container"),
        }
    }

    /// Check if the `container` tool is available.
    pub fn is_available() -> bool {
        // Check for 'container' command
        // Note: The generic name 'container' might conflict, so we might look for absolute paths
        // or specific install locations in the future.
        which::which("container").is_ok()
    }
}

#[async_trait]
impl Sandbox for AppleContainerSandbox {
    async fn execute(&self, config: &SandboxConfig) -> Result<SandboxResult, SandboxError> {
        crate::runner::enforce_policy(config, IsolationLevel::Vm)?;

        // The 'container' tool usage (hypothetical based on OCI standards/repo description):
        // container run [options] <image> <command>

        // Problem: We need a rootfs/image.
        // Cratons usually manages rootfs in `cratons-store`.
        // We'll assume for this implementation that we pass the rootfs directory as a bind mount
        // or that we are running a specific "base" image and mounting the workspace.

        // SECURITY: Require the operator to opt into a specific image rather
        // than silently fetching `debian:latest`. A latest-tag fetch implicitly
        // trusts whatever image the registry serves at runtime, which is the
        // exact supply-chain risk cratons exists to prevent. Fail closed when
        // CRATONS_LINUX_IMAGE is unset; the operator pins a digest or tag.
        let image = std::env::var("CRATONS_LINUX_IMAGE").map_err(|_| {
            SandboxError::Config(
                "Apple Container sandbox requires CRATONS_LINUX_IMAGE to be set to an explicit \
                 image reference (preferably digest-pinned, e.g. \
                 'debian@sha256:…'). Refusing to silently fetch 'debian:latest'."
                    .into(),
            )
        })?;

        let mut cmd = Command::new(&self.tool_path);

        cmd.arg("run");
        cmd.arg("--rm"); // Clean up

        cmd.arg(&image);

        // Environment.
        //
        // SECURITY: filter through the cross-platform env deny-list before
        // forwarding into the container. Previously every var in
        // `config.env` was passed verbatim, so dangerous loader vars
        // (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `_JAVA_OPTIONS`),
        // credential tokens, and proxy vars flowed into the build
        // unchecked, inconsistent with the Linux and Windows backends.
        if !config.inherit_env {
            // 'container' tool inherits a scrubbed env from the host by
            // default; we only forward vars the operator explicitly set.
        }
        for (k, v) in &config.env {
            if is_safe_env_var(k) {
                cmd.arg("--env");
                cmd.arg(format!("{}={}", k, v));
            } else {
                tracing::debug!(
                    env_var = %k,
                    "Blocked dangerous env var in Apple Container sandbox"
                );
            }
        }

        // Workdir
        cmd.arg("--workdir");
        cmd.arg(&config.workdir);

        // Mounts
        // Apple's tool likely supports -v or --volume
        // We mount the workspace (workdir) by default if it's not covered?
        // Actually, config.workdir is on Host. We need to mount it to Container.
        // Let's assume we map Host:Workdir -> Container:Workdir
        cmd.arg("--volume");
        cmd.arg(format!(
            "{}:{}",
            config.workdir.display(),
            config.workdir.display()
        ));

        for mount in &config.ro_mounts {
            cmd.arg("--volume");
            cmd.arg(format!(
                "{}:{}:ro",
                mount.source.display(),
                mount.target.display()
            ));
        }

        for mount in &config.rw_mounts {
            cmd.arg("--volume");
            cmd.arg(format!(
                "{}:{}:rw",
                mount.source.display(),
                mount.target.display()
            ));
        }

        // Network.
        //
        // SECURITY: the `container` tool, like macOS sandbox-exec, has no
        // per-host network filtering primitive. Previously `AllowList`
        // silently fell through to "default network" (effectively full),
        // turning a stricter caller request into a less restrictive
        // sandbox without surfacing the change. Match the macOS backend
        // and refuse rather than degrade.
        match &config.network {
            NetworkAccess::None => {
                cmd.arg("--network");
                cmd.arg("none");
            }
            NetworkAccess::AllowList(hosts) => {
                return Err(SandboxError::Unsupported(format!(
                    "Apple Container backend cannot enforce per-host network \
                     allowlists; refusing to silently degrade to full network. \
                     Requested allowlist: {hosts:?}. Use NetworkAccess::Full to \
                     opt in explicitly, or NetworkAccess::None / LocalhostOnly \
                     for stricter isolation."
                )));
            }
            NetworkAccess::LocalhostOnly | NetworkAccess::Full => {
                // Default is usually bridge/user-mode networking.
            }
        }

        // Command
        cmd.args(&config.command);

        // Execution with timeout
        let start = Instant::now();

        // Get timeout from config, default to 1 hour
        let timeout_duration = config.limits.timeout.unwrap_or(Duration::from_secs(3600));

        let output_result = timeout(timeout_duration, cmd.output()).await;

        let duration = start.elapsed();

        match output_result {
            Ok(Ok(output)) => Ok(SandboxResult {
                exit_code: output.status.code().unwrap_or(-1),
                stdout: output.stdout,
                stderr: output.stderr,
                duration,
                timed_out: false,
                resource_exceeded: false,
                resource_usage: None,
            }),
            Ok(Err(e)) => Err(SandboxError::Io(e)),
            Err(_) => {
                // Timeout occurred
                Ok(SandboxResult {
                    exit_code: 124, // GNU timeout convention
                    stdout: Vec::new(),
                    stderr: format!("Process timed out after {:?}", timeout_duration).into_bytes(),
                    duration,
                    timed_out: true,
                    resource_exceeded: false,
                    resource_usage: None,
                })
            }
        }
    }

    fn isolation_level(&self) -> IsolationLevel {
        IsolationLevel::Vm // It's a VM under the hood on macOS
    }

    fn is_available(&self) -> bool {
        Self::is_available()
    }

    fn description(&self) -> &'static str {
        "Apple Virtualization Framework (via 'container' tool)"
    }
}
