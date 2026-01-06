//! Common command execution utilities for sandbox implementations.
//!
//! This module provides DRY utilities shared across all sandbox implementations:
//! - Command building with environment setup
//! - Timeout handling
//! - Resource usage tracking (via rusage on Unix, Job Objects on Windows)
//! - Process spawning and output collection

use std::io;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::process::Command as TokioCommand;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::SandboxConfig;
use crate::error::SandboxError;
use crate::result::{ResourceUsage, SandboxResult};

/// Default PATH for sandboxed processes.
#[cfg(unix)]
pub const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

#[cfg(windows)]
pub const DEFAULT_PATH: &str = r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem";

/// Build a tokio Command from SandboxConfig.
///
/// This handles all the common setup:
/// - Working directory
/// - Stdio configuration
/// - Environment variables (with optional clearing)
/// - Default PATH and HOME setup
pub fn build_command(config: &SandboxConfig) -> TokioCommand {
    let program = &config.command[0];
    let args = &config.command[1..];

    let mut cmd = TokioCommand::new(program);
    cmd.args(args);
    cmd.current_dir(&config.workdir);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Environment handling
    if !config.inherit_env {
        cmd.env_clear();
    }

    for (key, value) in &config.env {
        cmd.env(key, value);
    }

    // Ensure essential environment variables
    setup_default_env(&mut cmd, config);

    cmd
}

/// Set up default environment variables if not already specified.
fn setup_default_env(cmd: &mut TokioCommand, config: &SandboxConfig) {
    if !config.env.contains_key("PATH") && !config.inherit_env {
        cmd.env("PATH", DEFAULT_PATH);
    }

    if !config.env.contains_key("HOME") && !config.inherit_env {
        if let Some(home) = dirs::home_dir() {
            cmd.env("HOME", home);
        }
    }

    // Set TERM for proper terminal handling
    if !config.env.contains_key("TERM") && !config.inherit_env {
        cmd.env("TERM", "xterm-256color");
    }
}

/// Execute a command with timeout and resource tracking.
///
/// This is the core execution function used by most sandbox implementations.
/// It handles:
/// - Spawning the process
/// - Timeout enforcement
/// - Output collection
/// - Resource usage tracking (where available)
pub async fn execute_command(
    mut cmd: TokioCommand,
    timeout_duration: Option<Duration>,
) -> Result<ExecutionOutput, SandboxError> {
    let start = Instant::now();

    // Execute with optional timeout
    let output = if let Some(timeout_dur) = timeout_duration {
        match timeout(timeout_dur, cmd.output()).await {
            Ok(result) => result.map_err(|e| map_io_error(e, &cmd))?,
            Err(_elapsed) => {
                debug!(timeout = ?timeout_dur, "Process timed out");
                return Ok(ExecutionOutput::timeout(start.elapsed()));
            }
        }
    } else {
        cmd.output().await.map_err(|e| map_io_error(e, &cmd))?
    };

    let duration = start.elapsed();

    Ok(ExecutionOutput {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
        stderr: output.stderr,
        duration,
        timed_out: false,
    })
}

/// Execute a command with resource usage tracking (Unix only).
///
/// This provides resource tracking via getrusage after child completion.
#[cfg(unix)]
pub async fn execute_command_with_rusage(
    mut cmd: TokioCommand,
    timeout_duration: Option<Duration>,
) -> Result<(ExecutionOutput, Option<ResourceUsage>), SandboxError> {
    use std::os::unix::process::ExitStatusExt;

    let start = Instant::now();

    // Spawn the child
    let child = cmd.spawn().map_err(|e| map_io_error(e, &cmd))?;

    // Wait with optional timeout
    let wait_result = if let Some(timeout_dur) = timeout_duration {
        match timeout(timeout_dur, child.wait_with_output()).await {
            Ok(result) => result.map_err(SandboxError::Io)?,
            Err(_elapsed) => {
                // Note: The child process may still be running, but we can't kill it
                // after wait_with_output times out because tokio drops the child.
                // The process will be orphaned and eventually cleaned up by init.
                debug!(timeout = ?timeout_dur, "Process timed out");
                return Ok((ExecutionOutput::timeout(start.elapsed()), None));
            }
        }
    } else {
        child.wait_with_output().await.map_err(SandboxError::Io)?
    };

    let duration = start.elapsed();

    // Get resource usage via getrusage (accumulates stats for all children)
    let resource_usage = get_child_resource_usage();

    let exit_code = wait_result.status.code().unwrap_or_else(|| {
        // If no exit code, check for signal
        wait_result
            .status
            .signal()
            .map(|sig| 128 + sig)
            .unwrap_or(-1)
    });

    let output = ExecutionOutput {
        exit_code,
        stdout: wait_result.stdout,
        stderr: wait_result.stderr,
        duration,
        timed_out: false,
    };

    Ok((output, resource_usage))
}

/// Get resource usage for child processes (Unix).
///
/// Uses nix's safe getrusage wrapper to avoid unsafe code.
#[cfg(unix)]
fn get_child_resource_usage() -> Option<ResourceUsage> {
    use nix::sys::resource::{UsageWho, getrusage};

    match getrusage(UsageWho::RUSAGE_CHILDREN) {
        Ok(usage) => {
            // Convert nix's Usage to our ResourceUsage
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
                cpu_time_ms: None, // Will be computed from user + system if needed
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

/// Output from command execution.
#[derive(Debug)]
pub struct ExecutionOutput {
    /// Exit code
    pub exit_code: i32,
    /// Standard output
    pub stdout: Vec<u8>,
    /// Standard error
    pub stderr: Vec<u8>,
    /// Execution duration
    pub duration: Duration,
    /// Whether the process timed out
    pub timed_out: bool,
}

impl ExecutionOutput {
    /// Create a timeout result.
    pub fn timeout(duration: Duration) -> Self {
        Self {
            exit_code: 124, // GNU timeout convention
            stdout: Vec::new(),
            stderr: b"Process timed out".to_vec(),
            duration,
            timed_out: true,
        }
    }

    /// Convert to SandboxResult.
    pub fn into_sandbox_result(self, resource_usage: Option<ResourceUsage>) -> SandboxResult {
        SandboxResult {
            exit_code: self.exit_code,
            stdout: self.stdout,
            stderr: self.stderr,
            duration: self.duration,
            timed_out: self.timed_out,
            resource_exceeded: false,
            resource_usage,
        }
    }
}

/// Map IO errors to more specific sandbox errors.
fn map_io_error(e: io::Error, _cmd: &TokioCommand) -> SandboxError {
    if e.kind() == io::ErrorKind::NotFound {
        SandboxError::CommandNotFound("command not found".into())
    } else if e.kind() == io::ErrorKind::PermissionDenied {
        SandboxError::PermissionDenied("permission denied".into())
    } else {
        SandboxError::Io(e)
    }
}

/// Validate sandbox configuration.
pub fn validate_config(config: &SandboxConfig) -> Result<(), SandboxError> {
    if config.command.is_empty() {
        return Err(SandboxError::Config("No command specified".into()));
    }

    if config.command[0].is_empty() {
        return Err(SandboxError::Config("Empty command program".into()));
    }

    if !config.workdir.is_absolute() {
        warn!(
            workdir = ?config.workdir,
            "Working directory is relative, this may cause issues"
        );
    }

    Ok(())
}

/// Log warnings about unsupported features.
pub fn log_unsupported_features(config: &SandboxConfig, sandbox_name: &str) {
    use crate::config::NetworkAccess;

    if !matches!(config.network, NetworkAccess::Full) {
        debug!(
            sandbox = sandbox_name,
            network = ?config.network,
            "Network isolation requested"
        );
    }

    if !config.ro_mounts.is_empty() {
        debug!(
            sandbox = sandbox_name,
            mount_count = config.ro_mounts.len(),
            "Read-only mounts configured"
        );
    }

    if !config.rw_mounts.is_empty() {
        debug!(
            sandbox = sandbox_name,
            mount_count = config.rw_mounts.len(),
            "Read-write mounts configured"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_build_command() {
        let config = SandboxConfig::new(vec!["echo".into(), "hello".into()])
            .with_workdir(PathBuf::from("/tmp"))
            .with_env("FOO", "bar");

        let cmd = build_command(&config);
        // Command is built, actual execution tested elsewhere
        let _ = cmd;
    }

    #[test]
    fn test_validate_config() {
        // Empty command
        let config = SandboxConfig::default();
        assert!(validate_config(&config).is_err());

        // Valid command
        let config = SandboxConfig::new(vec!["echo".into()]);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_execution_output_timeout() {
        let output = ExecutionOutput::timeout(Duration::from_secs(1));
        assert!(output.timed_out);
        assert_eq!(output.exit_code, 124);
    }
}
