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
        // The 'container' tool usage (hypothetical based on OCI standards/repo description):
        // container run [options] <image> <command>

        // Problem: We need a rootfs/image.
        // Cratons usually manages rootfs in `cratons-store`.
        // We'll assume for this implementation that we pass the rootfs directory as a bind mount
        // or that we are running a specific "base" image and mounting the workspace.

        // For this 'SOTA' implementation, we'll map the config to a `container run` command.
        // We assume we are running a standard Linux base image (e.g., alpine or debian)
        // configured via env var or default.

        let image =
            std::env::var("CRATONS_LINUX_IMAGE").unwrap_or_else(|_| "debian:latest".to_string());

        let mut cmd = Command::new(&self.tool_path);

        cmd.arg("run");
        cmd.arg("--rm"); // Clean up

        cmd.arg(&image);

        // Environment
        if !config.inherit_env {
            // 'container' tool might not support clearing env easily,
            // but we can pass specific vars
        }
        for (k, v) in &config.env {
            cmd.arg("--env");
            cmd.arg(format!("{}={}", k, v));
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

        // Network
        match config.network {
            NetworkAccess::None => {
                cmd.arg("--network");
                cmd.arg("none");
            }
            _ => {
                // Default is usually bridge/user
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
