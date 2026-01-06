//! Sandbox error types.

use std::io;
use std::path::PathBuf;

/// Errors that can occur during sandbox operations.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Command not found.
    #[error("Command not found: {0}")]
    CommandNotFound(String),

    /// Command execution failed.
    #[error("Command failed with exit code {code}: {message}")]
    CommandFailed {
        /// Exit code.
        code: i32,
        /// Error message.
        message: String,
    },

    /// Timeout exceeded.
    #[error("Execution timeout exceeded after {0:?}")]
    Timeout(std::time::Duration),

    /// Resource limit exceeded.
    #[error("Resource limit exceeded: {0}")]
    ResourceExceeded(String),

    /// Mount error.
    #[error("Failed to mount {src:?} to {dest:?}: {message}")]
    MountFailed {
        /// Source path.
        src: PathBuf,
        /// Target path.
        dest: PathBuf,
        /// Error message.
        message: String,
    },

    /// Network isolation error.
    #[error("Network isolation error: {0}")]
    NetworkIsolation(String),

    /// Container runtime error.
    #[error("Container runtime error: {0}")]
    ContainerRuntime(String),

    /// Sandbox not available on this platform.
    #[error("Sandbox not available: {0}")]
    NotAvailable(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Permission denied.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Signal received.
    #[error("Process killed by signal: {0}")]
    Signal(i32),

    /// Internal error.
    #[error("Internal sandbox error: {0}")]
    Internal(String),
}

impl SandboxError {
    /// Create a command failed error.
    #[must_use]
    pub fn command_failed(code: i32, message: impl Into<String>) -> Self {
        Self::CommandFailed {
            code,
            message: message.into(),
        }
    }

    /// Create a mount failed error.
    #[must_use]
    pub fn mount_failed(src: PathBuf, dest: PathBuf, message: impl Into<String>) -> Self {
        Self::MountFailed {
            src,
            dest,
            message: message.into(),
        }
    }

    /// Check if this error indicates a timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    /// Check if this error indicates a resource limit was exceeded.
    #[must_use]
    pub fn is_resource_limit(&self) -> bool {
        matches!(self, Self::ResourceExceeded(_))
    }

    /// Get the exit code if this was a command failure.
    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        match self {
            Self::CommandFailed { code, .. } => Some(*code),
            Self::Signal(sig) => Some(128 + sig),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_properties() {
        let timeout = SandboxError::Timeout(std::time::Duration::from_secs(30));
        assert!(timeout.is_timeout());
        assert!(!timeout.is_resource_limit());

        let resource = SandboxError::ResourceExceeded("memory".into());
        assert!(!resource.is_timeout());
        assert!(resource.is_resource_limit());
    }

    #[test]
    fn test_exit_code() {
        let failed = SandboxError::command_failed(1, "failed");
        assert_eq!(failed.exit_code(), Some(1));

        let signal = SandboxError::Signal(9);
        assert_eq!(signal.exit_code(), Some(137)); // 128 + 9

        let io_err = SandboxError::Io(io::Error::new(io::ErrorKind::Other, "test"));
        assert_eq!(io_err.exit_code(), None);
    }
}
