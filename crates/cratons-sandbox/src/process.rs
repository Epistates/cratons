//! Process-based sandbox (fallback for unsupported platforms).
//!
//! This provides minimal isolation by:
//! - Setting a restricted environment
//! - Changing the working directory
//! - Capturing output
//!
//! It does NOT provide:
//! - Filesystem isolation
//! - Network isolation
//! - Resource limits (except timeout)

use async_trait::async_trait;

use crate::config::SandboxConfig;
use crate::error::SandboxError;
use crate::result::SandboxResult;
#[cfg(not(unix))]
use crate::runner::execute_command;
use crate::runner::{build_command, validate_config};
use crate::{IsolationLevel, Sandbox};

/// A minimal sandbox using process isolation only.
///
/// This is the fallback when no platform-specific sandbox is available.
pub struct ProcessSandbox {
    // No state needed
}

impl ProcessSandbox {
    /// Create a new process sandbox.
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for ProcessSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Sandbox for ProcessSandbox {
    async fn execute(&self, config: &SandboxConfig) -> Result<SandboxResult, SandboxError> {
        validate_config(config)?;

        // Use rusage for resource tracking on Unix
        #[cfg(unix)]
        {
            let cmd = build_command(config);
            let (output, resource_usage) =
                crate::runner::execute_command_with_rusage(cmd, config.limits.timeout).await?;
            return Ok(output.into_sandbox_result(resource_usage));
        }

        // Non-Unix: basic execution without resource tracking
        #[cfg(not(unix))]
        {
            let cmd = build_command(config);
            let output = execute_command(cmd, config.limits.timeout).await?;
            Ok(output.into_sandbox_result(None))
        }
    }

    fn isolation_level(&self) -> IsolationLevel {
        IsolationLevel::Process
    }

    fn is_available(&self) -> bool {
        true // Always available
    }

    fn description(&self) -> &'static str {
        "Process isolation (minimal, no filesystem or network isolation)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    #[tokio::test]
    async fn test_simple_command() {
        let sandbox = ProcessSandbox::new();
        let config = SandboxConfig::new(vec!["echo".into(), "hello".into()])
            .with_workdir(PathBuf::from("/tmp"));

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.success());
        assert_eq!(result.stdout_str().trim(), "hello");
    }

    #[tokio::test]
    async fn test_command_failure() {
        let sandbox = ProcessSandbox::new();
        let config = SandboxConfig::new(vec!["false".into()]);

        let result = sandbox.execute(&config).await.unwrap();
        assert!(!result.success());
        assert_ne!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn test_timeout() {
        let sandbox = ProcessSandbox::new();
        let mut config = SandboxConfig::new(vec!["sleep".into(), "10".into()]);
        config.limits.timeout = Some(Duration::from_millis(100));

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.timed_out);
        assert!(!result.success());
    }

    #[tokio::test]
    async fn test_environment() {
        let sandbox = ProcessSandbox::new();
        let config = SandboxConfig::new(vec!["sh".into(), "-c".into(), "echo $FOO".into()])
            .with_env("FOO", "bar");

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.success());
        assert_eq!(result.stdout_str().trim(), "bar");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_resource_tracking() {
        let sandbox = ProcessSandbox::new();
        let config =
            SandboxConfig::new(vec!["ls".into(), "-la".into()]).with_workdir(PathBuf::from("/tmp"));

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.success());

        // On Unix, resource usage should be tracked
        if let Some(usage) = &result.resource_usage {
            // At least some metrics should be available
            assert!(usage.user_time_ms.is_some() || usage.peak_memory.is_some());
        }
    }

    #[test]
    fn test_sandbox_properties() {
        let sandbox = ProcessSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.isolation_level(), IsolationLevel::Process);
    }
}
