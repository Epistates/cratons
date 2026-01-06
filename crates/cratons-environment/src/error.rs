//! Environment error types.

use std::io;
use std::path::PathBuf;

/// Errors that can occur during environment operations.
#[derive(Debug, thiserror::Error)]
pub enum EnvironmentError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Environment not found.
    #[error("Environment not found at {0}")]
    NotFound(PathBuf),

    /// Toolchain not installed.
    #[error("Toolchain not installed: {0} {1}")]
    ToolchainNotInstalled(String, String),

    /// Invalid environment structure.
    #[error("Invalid environment structure: {0}")]
    InvalidStructure(String),

    /// Activation failed.
    #[error("Failed to generate activation script: {0}")]
    ActivationFailed(String),

    /// Store error.
    #[error("Store error: {0}")]
    Store(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Sandbox execution error.
    #[error("Sandbox error: {0}")]
    SandboxError(String),

    /// Command execution failed.
    #[error("Command failed: {0}")]
    CommandFailed(String),
}

impl From<cratons_core::CratonsError> for EnvironmentError {
    fn from(err: cratons_core::CratonsError) -> Self {
        Self::Store(err.to_string())
    }
}
