//! Error types for Cratons.
//!
//! This module provides error types following youki's patterns:
//! - `CratonsError` is the main error enum
//! - `IoError` provides wrapped I/O errors with path context
//! - All errors use `thiserror` for derive-based error messages

use std::path::PathBuf;
use thiserror::Error;

/// A wrapped I/O error with additional path context.
///
/// This provides more informative error messages by including
/// the path that caused the error and the operation being performed.
#[derive(Error, Debug)]
pub enum IoError {
    /// Failed to open a file
    #[error("failed to open '{path}': {err}")]
    Open {
        /// The underlying I/O error
        err: std::io::Error,
        /// The path that couldn't be opened
        path: PathBuf,
    },

    /// Failed to write to a file
    #[error("failed to write to '{path}': {err}")]
    Write {
        /// The underlying I/O error
        err: std::io::Error,
        /// The path that couldn't be written to
        path: PathBuf,
    },

    /// Failed to read from a file
    #[error("failed to read '{path}': {err}")]
    Read {
        /// The underlying I/O error
        err: std::io::Error,
        /// The path that couldn't be read
        path: PathBuf,
    },

    /// Failed to create a directory
    #[error("failed to create directory '{path}': {err}")]
    CreateDir {
        /// The underlying I/O error
        err: std::io::Error,
        /// The path where directory creation failed
        path: PathBuf,
    },

    /// Failed to remove a file or directory
    #[error("failed to remove '{path}': {err}")]
    Remove {
        /// The underlying I/O error
        err: std::io::Error,
        /// The path that couldn't be removed
        path: PathBuf,
    },

    /// Failed to copy a file
    #[error("failed to copy '{src}' to '{dst}': {err}")]
    Copy {
        /// The underlying I/O error
        err: std::io::Error,
        /// The source path
        src: PathBuf,
        /// The destination path
        dst: PathBuf,
    },

    /// Failed to create a symlink
    #[error("failed to create symlink from '{src}' to '{dst}': {err}")]
    Symlink {
        /// The underlying I/O error
        err: std::io::Error,
        /// The source path
        src: PathBuf,
        /// The destination path
        dst: PathBuf,
    },

    /// Other I/O error with path context
    #[error("I/O error at '{path}': {err}")]
    Other {
        /// The underlying I/O error
        err: std::io::Error,
        /// The path where the error occurred
        path: PathBuf,
    },
}

impl IoError {
    /// Get the underlying `std::io::Error`.
    #[must_use]
    pub fn inner(&self) -> &std::io::Error {
        match self {
            Self::Open { err, .. } => err,
            Self::Write { err, .. } => err,
            Self::Read { err, .. } => err,
            Self::CreateDir { err, .. } => err,
            Self::Remove { err, .. } => err,
            Self::Copy { err, .. } => err,
            Self::Symlink { err, .. } => err,
            Self::Other { err, .. } => err,
        }
    }

    /// Get the error kind.
    #[must_use]
    pub fn kind(&self) -> std::io::ErrorKind {
        self.inner().kind()
    }
}

/// The main error type for Cratons operations.
#[derive(Error, Debug)]
pub enum CratonsError {
    /// I/O error without path context (prefer IoError when path is available)
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// I/O error with path context
    #[error(transparent)]
    IoWithContext(#[from] IoError),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// TOML parsing error
    #[error("TOML parse error: {0}")]
    TomlParse(String),

    /// Invalid hash format
    #[error("Invalid hash: {0}")]
    InvalidHash(String),

    /// Invalid version format (simple)
    #[error("Invalid version: {0}")]
    InvalidVersionSimple(String),

    /// Invalid version format (with details)
    #[error("Invalid version '{version}': {message}")]
    InvalidVersion {
        /// The invalid version string
        version: String,
        /// Details about why it's invalid
        message: String,
    },

    /// Invalid package name
    #[error("Invalid package name: {message}")]
    InvalidPackage {
        /// Details about why the package name is invalid
        message: String,
    },

    /// Invalid path
    #[error("Invalid path '{path}': {message}")]
    InvalidPath {
        /// The invalid path
        path: String,
        /// Details about why the path is invalid
        message: String,
    },

    /// Invalid configuration
    #[error("Invalid configuration: {message}")]
    InvalidConfig {
        /// Details about the configuration error
        message: String,
    },

    /// Package not found
    #[error("Package not found: {0}")]
    PackageNotFound(String),

    /// Version not found
    #[error("Version {version} not found for package {package}")]
    VersionNotFound {
        /// The package name
        package: String,
        /// The requested version
        version: String,
    },

    /// No version satisfies constraints
    #[error("No version of {package} satisfies: {constraint}")]
    NoSatisfyingVersion {
        /// The package name
        package: String,
        /// The version constraint that couldn't be satisfied
        constraint: String,
    },

    /// Dependency cycle detected
    #[error("Dependency cycle detected: {0}")]
    DependencyCycle(String),

    /// Registry error
    #[error("Registry error for {registry}: {message}")]
    Registry {
        /// The registry name or URL
        registry: String,
        /// Error message from the registry
        message: String,
    },

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Build error
    #[error("Build failed: {0}")]
    BuildFailed(String),

    /// Container error
    #[error("Container error: {0}")]
    Container(String),

    /// Checksum mismatch
    #[error("Checksum mismatch for {package}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        /// The package name
        package: String,
        /// The expected checksum
        expected: String,
        /// The actual checksum computed
        actual: String,
    },

    /// Manifest error
    #[error("Manifest error: {0}")]
    Manifest(String),

    /// Lockfile error
    #[error("Lockfile error: {0}")]
    Lockfile(String),

    /// Workspace error
    #[error("Workspace error: {0}")]
    Workspace(String),

    /// Security vulnerability detected
    #[error("Security vulnerability: {0}")]
    Vulnerability(String),

    /// Manifest not found
    #[error("Manifest not found")]
    ManifestNotFound,

    /// Dependency resolution error
    #[error("Dependency resolution failed: {0}")]
    DependencyResolution(String),

    /// Unsatisfiable dependency
    #[error("Cannot satisfy dependency {package} {constraint}: {reason}")]
    UnsatisfiableDependency {
        /// The package name
        package: String,
        /// The version constraint
        constraint: String,
        /// The reason it can't be satisfied
        reason: String,
    },

    /// Invalid ecosystem
    #[error("Unknown ecosystem: {0}")]
    UnknownEcosystem(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Directory traversal error
    #[error("Directory traversal error: {0}")]
    WalkDir(String),

    /// Verification error (signature, checksum, or certificate)
    #[error("Verification error: {0}")]
    Verification(String),
}

impl From<walkdir::Error> for CratonsError {
    fn from(err: walkdir::Error) -> Self {
        Self::WalkDir(err.to_string())
    }
}

/// Convenience Result type for Cratons operations.
pub type Result<T> = std::result::Result<T, CratonsError>;
