//! Sandbox execution result types.

use std::time::Duration;

/// Result of a sandbox execution.
#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Exit code of the process.
    pub exit_code: i32,

    /// Standard output.
    pub stdout: Vec<u8>,

    /// Standard error.
    pub stderr: Vec<u8>,

    /// Execution duration.
    pub duration: Duration,

    /// Whether the process was killed due to timeout.
    pub timed_out: bool,

    /// Whether the process was killed due to resource limits.
    pub resource_exceeded: bool,

    /// Resource usage statistics (if available).
    pub resource_usage: Option<ResourceUsage>,
}

impl SandboxResult {
    /// Check if the execution was successful (exit code 0).
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == 0 && !self.timed_out && !self.resource_exceeded
    }

    /// Get stdout as a string (lossy UTF-8 conversion).
    #[must_use]
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Get stderr as a string (lossy UTF-8 conversion).
    #[must_use]
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Get combined output (stdout + stderr).
    #[must_use]
    pub fn combined_output(&self) -> Vec<u8> {
        let mut combined = self.stdout.clone();
        combined.extend_from_slice(&self.stderr);
        combined
    }

    /// Get combined output as a string.
    #[must_use]
    pub fn combined_output_str(&self) -> String {
        String::from_utf8_lossy(&self.combined_output()).into_owned()
    }
}

impl Default for SandboxResult {
    fn default() -> Self {
        Self {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration: Duration::ZERO,
            timed_out: false,
            resource_exceeded: false,
            resource_usage: None,
        }
    }
}

/// Resource usage statistics.
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Peak memory usage in bytes.
    pub peak_memory: Option<u64>,

    /// CPU time in milliseconds.
    pub cpu_time_ms: Option<u64>,

    /// User CPU time in milliseconds.
    pub user_time_ms: Option<u64>,

    /// System CPU time in milliseconds.
    pub system_time_ms: Option<u64>,

    /// Number of context switches.
    pub context_switches: Option<u64>,

    /// I/O bytes read.
    pub io_read_bytes: Option<u64>,

    /// I/O bytes written.
    pub io_write_bytes: Option<u64>,
}

impl ResourceUsage {
    /// Create from nix Usage struct (Unix).
    #[cfg(unix)]
    pub fn from_nix_usage(usage: &nix::sys::resource::Usage) -> Self {
        let user_time = usage.user_time();
        let system_time = usage.system_time();

        Self {
            peak_memory: Some((usage.max_rss() * 1024) as u64), // KB to bytes
            user_time_ms: Some(
                (user_time.tv_sec() as u64 * 1000) + (user_time.tv_usec() as u64 / 1000),
            ),
            system_time_ms: Some(
                (system_time.tv_sec() as u64 * 1000) + (system_time.tv_usec() as u64 / 1000),
            ),
            cpu_time_ms: None,      // Computed from user + system
            context_switches: None, // Not exposed by nix Usage
            io_read_bytes: None,
            io_write_bytes: None,
        }
    }

    /// Compute total CPU time from user and system time.
    pub fn with_computed_cpu_time(mut self) -> Self {
        if let (Some(user), Some(sys)) = (self.user_time_ms, self.system_time_ms) {
            self.cpu_time_ms = Some(user + sys);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_result_success() {
        let result = SandboxResult::default();
        assert!(result.success());

        let failed = SandboxResult {
            exit_code: 1,
            ..Default::default()
        };
        assert!(!failed.success());

        let timed_out = SandboxResult {
            timed_out: true,
            ..Default::default()
        };
        assert!(!timed_out.success());
    }

    #[test]
    fn test_output_conversion() {
        let result = SandboxResult {
            stdout: b"hello\n".to_vec(),
            stderr: b"world\n".to_vec(),
            ..Default::default()
        };

        assert_eq!(result.stdout_str(), "hello\n");
        assert_eq!(result.stderr_str(), "world\n");
        assert_eq!(result.combined_output_str(), "hello\nworld\n");
    }
}
