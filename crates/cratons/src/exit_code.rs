//! CLI exit codes for semantic error handling.
//!
//! Exit codes follow common Unix conventions where possible:
//! - 0: Success
//! - 1: General error
//! - 2: Usage/argument error (handled by clap)
//! - 10-19: Build/install errors
//! - 20-29: Network/connectivity errors
//! - 30-39: Security/audit errors
//!
//! # Usage
//!
//! ```ignore
//! use cratons::exit_code::ExitCode;
//!
//! fn main() {
//!     let result = run();
//!     std::process::exit(ExitCode::from_result(&result).into());
//! }
//! ```

use cratons_core::CratonsError;

/// Exit codes for the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Command completed successfully
    Success = 0,
    /// General/unknown error
    GeneralError = 1,
    /// Build failed
    BuildFailed = 10,
    /// Install failed
    InstallFailed = 11,
    /// Dependency resolution failed
    ResolutionFailed = 12,
    /// Lockfile error (corrupt, stale, etc.)
    LockfileError = 13,
    /// Manifest error (parse, validation)
    ManifestError = 14,
    /// Network/connectivity error
    NetworkError = 20,
    /// Authentication/authorization error
    AuthError = 21,
    /// Security audit found vulnerabilities
    AuditFailed = 30,
    /// Verification failed (signature, checksum)
    VerificationFailed = 31,
    /// Configuration error
    ConfigError = 40,
    /// Store/cache error
    StoreError = 41,
    /// Workspace error
    WorkspaceError = 42,
    /// Container/sandbox error
    ContainerError = 50,
}

impl ExitCode {
    /// Determine exit code from a CratonsError.
    #[must_use]
    pub fn from_error(error: &CratonsError) -> Self {
        match error {
            CratonsError::BuildFailed(_) => Self::BuildFailed,
            CratonsError::DependencyResolution(_) => Self::ResolutionFailed,
            CratonsError::DependencyCycle(_) => Self::ResolutionFailed,
            CratonsError::UnsatisfiableDependency { .. } => Self::ResolutionFailed,
            CratonsError::NoSatisfyingVersion { .. } => Self::ResolutionFailed,
            CratonsError::Lockfile(_) => Self::LockfileError,
            CratonsError::ManifestNotFound => Self::ManifestError,
            CratonsError::Manifest(_) => Self::ManifestError,
            CratonsError::Network(_) => Self::NetworkError,
            CratonsError::Registry { .. } => Self::NetworkError,
            CratonsError::Vulnerability(_) => Self::AuditFailed,
            CratonsError::Verification(_) => Self::VerificationFailed,
            CratonsError::ChecksumMismatch { .. } => Self::VerificationFailed,
            CratonsError::Config(_) => Self::ConfigError,
            CratonsError::Workspace(_) => Self::WorkspaceError,
            CratonsError::Container(_) => Self::ContainerError,
            _ => Self::GeneralError,
        }
    }

    /// Determine exit code from a Result.
    #[must_use]
    pub fn from_result<T>(result: &Result<T, miette::Report>) -> Self {
        match result {
            Ok(_) => Self::Success,
            Err(report) => {
                // Try to downcast to CratonsError
                if let Some(me) = report.downcast_ref::<CratonsError>() {
                    Self::from_error(me)
                } else {
                    Self::GeneralError
                }
            }
        }
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code as i32
    }
}

impl std::fmt::Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let desc = match self {
            Self::Success => "Success",
            Self::GeneralError => "General error",
            Self::BuildFailed => "Build failed",
            Self::InstallFailed => "Install failed",
            Self::ResolutionFailed => "Dependency resolution failed",
            Self::LockfileError => "Lockfile error",
            Self::ManifestError => "Manifest error",
            Self::NetworkError => "Network error",
            Self::AuthError => "Authentication error",
            Self::AuditFailed => "Security audit failed",
            Self::VerificationFailed => "Verification failed",
            Self::ConfigError => "Configuration error",
            Self::StoreError => "Store error",
            Self::WorkspaceError => "Workspace error",
            Self::ContainerError => "Container error",
        };
        write!(f, "{} (exit code {})", desc, *self as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_values() {
        assert_eq!(ExitCode::Success as i32, 0);
        assert_eq!(ExitCode::GeneralError as i32, 1);
        assert_eq!(ExitCode::BuildFailed as i32, 10);
        assert_eq!(ExitCode::NetworkError as i32, 20);
        assert_eq!(ExitCode::AuditFailed as i32, 30);
    }

    #[test]
    fn test_from_error() {
        let build_err = CratonsError::BuildFailed("test".into());
        assert_eq!(ExitCode::from_error(&build_err), ExitCode::BuildFailed);

        let network_err = CratonsError::Network("test".into());
        assert_eq!(ExitCode::from_error(&network_err), ExitCode::NetworkError);

        let resolution_err = CratonsError::DependencyResolution("test".into());
        assert_eq!(
            ExitCode::from_error(&resolution_err),
            ExitCode::ResolutionFailed
        );
    }

    #[test]
    fn test_display() {
        assert!(ExitCode::Success.to_string().contains("Success"));
        assert!(ExitCode::BuildFailed.to_string().contains("10"));
    }
}
