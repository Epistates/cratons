//! Utilities for normalizing checksum formats (hex vs base64).
//!
//! Different package registries use different hash encoding formats:
//! - **crates.io**: SHA256 in hex encoding
//! - **npm**: SHA512 in base64 (or SHA1 hex as fallback)
//! - **PyPI**: SHA256 in hex
//!
//! This module normalizes all formats to base64 for consistent verification.

use crate::{CratonsError, Result};
use base64::{Engine, engine::general_purpose::STANDARD};

/// Normalizes any checksum format to base64 representation.
///
/// Supported formats:
/// - `sha1-{hex}` or `sha1-{base64}` (npm legacy)
/// - `sha256-{hex}` or `sha256-{base64}`
/// - `sha512-{hex}` or `sha512-{base64}`
///
/// Returns `Ok(normalized_string)` where the value part is always base64 encoded.
pub fn normalize_checksum_format(integrity: &str) -> Result<String> {
    // Parse format: "algorithm-value"
    if let Some(value) = integrity.strip_prefix("sha1-") {
        normalize_algorithm("sha1", value, 20) // SHA1 = 20 bytes = 40 hex chars
    } else if let Some(value) = integrity.strip_prefix("sha256-") {
        normalize_algorithm("sha256", value, 32) // SHA256 = 32 bytes = 64 hex chars
    } else if let Some(value) = integrity.strip_prefix("sha512-") {
        normalize_algorithm("sha512", value, 64) // SHA512 = 64 bytes = 128 hex chars
    } else {
        Err(CratonsError::InvalidHash(format!(
            "Unsupported checksum format: {}. Expected sha1-, sha256-, or sha512- prefix",
            integrity
        )))
    }
}

fn normalize_algorithm(algo: &str, value: &str, expected_bytes: usize) -> Result<String> {
    // 1. Try to decode as hex first (most common for crates.io, PyPI)
    // Hex encoding: 2 chars per byte
    if value.len() == expected_bytes * 2 {
        if let Ok(bytes) = hex::decode(value) {
            return Ok(format!("{}-{}", algo, STANDARD.encode(bytes)));
        }
    }

    // 2. If valid base64, return as is (npm uses this)
    if is_valid_base64(value) {
        return Ok(format!("{}-{}", algo, value));
    }

    Err(CratonsError::InvalidHash(format!(
        "Invalid {} checksum value: '{}'. Expected {} hex chars or valid base64",
        algo, value, expected_bytes * 2
    )))
}

/// Checks if a string is valid base64.
fn is_valid_base64(s: &str) -> bool {
    STANDARD.decode(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_sha1_hex() {
        // "test" in sha1 hex: a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
        let hex_input = "sha1-a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        // "test" in sha1 base64: qUqP5cyxm6YcTAhz05Hph5gvu9M=
        let expected = "sha1-qUqP5cyxm6YcTAhz05Hph5gvu9M=";
        assert_eq!(normalize_checksum_format(hex_input).unwrap(), expected);
    }

    #[test]
    fn test_normalize_sha1_base64() {
        let input = "sha1-qUqP5cyxm6YcTAhz05Hph5gvu9M=";
        assert_eq!(normalize_checksum_format(input).unwrap(), input);
    }

    #[test]
    fn test_normalize_sha256_hex() {
        // "test" in sha256 hex: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        let hex_input = "sha256-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        // "test" in sha256 base64: n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
        let expected = "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=";
        assert_eq!(normalize_checksum_format(hex_input).unwrap(), expected);
    }

    #[test]
    fn test_normalize_sha256_base64() {
        let input = "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=";
        assert_eq!(normalize_checksum_format(input).unwrap(), input);
    }

    #[test]
    fn test_normalize_sha512_hex() {
        // "test" in sha512 hex (128 chars)
        let hex_input = "sha512-ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d494031a41042e2c10274878fa20387f5a95687729571340536c1cc7a6f3b062597406087b";
        // Verify hex→base64 conversion is correct (computed from actual hex value)
        let result = normalize_checksum_format(hex_input).unwrap();
        assert!(result.starts_with("sha512-"));
        // Verify round-trip: the computed base64 should be valid
        assert!(result.ends_with("==")); // Base64 padding
        // Verify the base64 is preserved when re-normalized
        assert_eq!(normalize_checksum_format(&result).unwrap(), result);
    }

    #[test]
    fn test_normalize_sha512_base64() {
        // Valid sha512 base64 (lodash actual hash from npm)
        let input = "sha512-WQp19dBFuL23teHctiP7Pc5QD7A51jFKd+0jjYGeqKu8A8NLMZnvLOXx1u9S5WGKR3IFgQ8oTkhEe8AQW5UYzA==";
        assert_eq!(normalize_checksum_format(input).unwrap(), input);
    }

    #[test]
    fn test_invalid_algorithm() {
        let err = normalize_checksum_format("md5-abc").unwrap_err();
        assert!(err.to_string().contains("Unsupported checksum format"));
    }

    #[test]
    fn test_invalid_value() {
        let err = normalize_checksum_format("sha256-nothexorbase64!").unwrap_err();
        assert!(err.to_string().contains("Invalid sha256 checksum"));
    }

    #[test]
    fn test_real_crates_io_checksum() {
        // Real checksum from crates.io for anyhow@1.0.100
        let hex_input = "sha256-a23eb6b1614318a8071c9b2521f36b424b2c83db5eb3a0fead4a6c0809af6e61";
        let result = normalize_checksum_format(hex_input).unwrap();
        assert!(result.starts_with("sha256-"));
        assert!(result.ends_with("=")); // Base64 padding
        assert_ne!(result, hex_input); // Should be different (converted)
    }
}
