//! Error types for credential management.

use thiserror::Error;

/// Errors that can occur during credential operations.
#[derive(Debug, Error)]
pub enum Error {
    /// No writable credential store is available.
    #[error("No writable credential store available")]
    NoWritableStore,

    /// Keychain access error.
    #[error("Keychain error: {0}")]
    Keychain(#[from] keyring::Error),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Encryption error.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption error.
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Invalid credential format.
    #[error("Invalid credential format: {0}")]
    InvalidFormat(String),

    /// Credential not found.
    #[error("Credential not found: {0}")]
    NotFound(String),

    /// Environment variable not set.
    #[error("Environment variable not set: {0}")]
    EnvNotSet(String),

    /// Base64 decoding error.
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}
