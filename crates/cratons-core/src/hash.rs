//! Content hashing utilities.
//!
//! Cratons uses content-addressable storage, where artifacts are identified
//! by the cryptographic hash of their contents. This module provides
//! the hashing infrastructure.
//!
//! # Security
//!
//! All hash comparisons use constant-time operations to prevent timing attacks.
//! See: <https://codahale.com/a-lesson-in-timing-attacks/>

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use subtle::ConstantTimeEq;

use crate::error::{CratonsError, Result};

/// Constant-time byte slice comparison.
///
/// # Security
///
/// This function compares two byte slices in constant time, meaning the time
/// taken is independent of where the slices differ. This prevents timing attacks
/// where an attacker can infer information about secret data by measuring
/// comparison time.
///
/// # Returns
///
/// `true` if the slices are equal (same length and same contents), `false` otherwise.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Length check is not constant-time, but length differences are not
    // typically a security concern for hash comparison (hashes are fixed-length)
    if a.len() != b.len() {
        return false;
    }
    // Use subtle crate for constant-time comparison
    a.ct_eq(b).into()
}

/// Supported hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// SHA-256 (used for compatibility with existing registries)
    Sha256,
    /// SHA-512 (used for npm integrity and some registries)
    Sha512,
    /// Blake3 (used for internal storage - faster)
    #[default]
    Blake3,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha512 => write!(f, "sha512"),
            Self::Blake3 => write!(f, "blake3"),
        }
    }
}

impl std::str::FromStr for HashAlgorithm {
    type Err = CratonsError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "sha256" | "sha-256" => Ok(Self::Sha256),
            "sha512" | "sha-512" => Ok(Self::Sha512),
            "blake3" => Ok(Self::Blake3),
            _ => Err(CratonsError::InvalidHash(format!(
                "Unknown algorithm: {s}"
            ))),
        }
    }
}

/// A content hash with its algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash {
    /// The hash algorithm used
    pub algorithm: HashAlgorithm,
    /// The hex-encoded hash value
    pub value: String,
}

impl ContentHash {
    /// Create a new content hash.
    #[must_use]
    pub fn new(algorithm: HashAlgorithm, value: String) -> Self {
        Self { algorithm, value }
    }

    /// Create a SHA-256 hash.
    #[must_use]
    pub fn sha256(value: String) -> Self {
        Self::new(HashAlgorithm::Sha256, value)
    }

    /// Create a SHA-512 hash.
    #[must_use]
    pub fn sha512(value: String) -> Self {
        Self::new(HashAlgorithm::Sha512, value)
    }

    /// Create a Blake3 hash.
    #[must_use]
    pub fn blake3(value: String) -> Self {
        Self::new(HashAlgorithm::Blake3, value)
    }

    /// Parse a hash string in the format "algorithm:value" or just "value" (assumes Blake3).
    pub fn parse(s: &str) -> Result<Self> {
        if let Some((algo, value)) = s.split_once(':') {
            let algorithm = algo.parse()?;
            Ok(Self::new(algorithm, value.to_string()))
        } else {
            // Default to Blake3 for bare hashes
            Ok(Self::blake3(s.to_string()))
        }
    }

    /// Get the short form of the hash (first 12 characters).
    #[must_use]
    pub fn short(&self) -> &str {
        &self.value[..self.value.len().min(12)]
    }

    /// Get the prefix for content-addressable storage (first 2 characters).
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.value[..2.min(self.value.len())]
    }

    /// Verify that this hash matches the given data.
    ///
    /// # Security
    ///
    /// Uses constant-time comparison to prevent timing attacks. An attacker
    /// cannot determine how many bytes of a hash match by measuring response time.
    pub fn verify(&self, data: &[u8]) -> Result<bool> {
        use sha2::Sha512;

        let computed = match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            HashAlgorithm::Blake3 => {
                let hash = blake3::hash(data);
                hash.to_hex().to_string()
            }
        };

        // SECURITY: Use constant-time comparison to prevent timing attacks.
        // Variable-time string comparison would leak information about how many
        // bytes of the hash match, enabling attackers to forge hashes incrementally.
        Ok(constant_time_eq(computed.as_bytes(), self.value.as_bytes()))
    }

    /// Constant-time equality check for hash verification.
    ///
    /// Returns true only if both slices are exactly equal, without leaking
    /// timing information about where they differ.
    #[inline]
    pub fn constant_time_verify(&self, other: &ContentHash) -> bool {
        self.algorithm == other.algorithm
            && constant_time_eq(self.value.as_bytes(), other.value.as_bytes())
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.value)
    }
}

/// The inner hasher state, using an enum to ensure type safety.
enum HasherInner {
    Sha256(Sha256),
    Sha512(sha2::Sha512),
    Blake3(blake3::Hasher),
}

/// A streaming hasher that can process data incrementally.
pub struct Hasher {
    inner: HasherInner,
}

impl Hasher {
    /// Create a new hasher with the specified algorithm.
    #[must_use]
    pub fn new(algorithm: HashAlgorithm) -> Self {
        use sha2::Sha512;
        let inner = match algorithm {
            HashAlgorithm::Sha256 => HasherInner::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => HasherInner::Sha512(Sha512::new()),
            HashAlgorithm::Blake3 => HasherInner::Blake3(blake3::Hasher::new()),
        };
        Self { inner }
    }

    /// Create a new Blake3 hasher (default, fastest).
    #[must_use]
    pub fn blake3() -> Self {
        Self::new(HashAlgorithm::Blake3)
    }

    /// Create a new SHA-256 hasher.
    #[must_use]
    pub fn sha256() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }

    /// Create a new SHA-512 hasher.
    #[must_use]
    pub fn sha512() -> Self {
        Self::new(HashAlgorithm::Sha512)
    }

    /// Get the algorithm being used.
    #[must_use]
    pub fn algorithm(&self) -> HashAlgorithm {
        match &self.inner {
            HasherInner::Sha256(_) => HashAlgorithm::Sha256,
            HasherInner::Sha512(_) => HashAlgorithm::Sha512,
            HasherInner::Blake3(_) => HashAlgorithm::Blake3,
        }
    }

    /// Update the hash with more data.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.inner {
            HasherInner::Sha256(hasher) => hasher.update(data),
            HasherInner::Sha512(hasher) => hasher.update(data),
            HasherInner::Blake3(hasher) => {
                hasher.update(data);
            }
        }
    }

    /// Finalize the hash and return the result.
    #[must_use]
    pub fn finalize(self) -> ContentHash {
        match self.inner {
            HasherInner::Sha256(hasher) => {
                let result = hasher.finalize();
                ContentHash::new(HashAlgorithm::Sha256, hex::encode(result))
            }
            HasherInner::Sha512(hasher) => {
                let result = hasher.finalize();
                ContentHash::new(HashAlgorithm::Sha512, hex::encode(result))
            }
            HasherInner::Blake3(hasher) => {
                let result = hasher.finalize();
                ContentHash::new(HashAlgorithm::Blake3, result.to_hex().to_string())
            }
        }
    }

    /// Hash data in one shot.
    #[must_use]
    pub fn hash_bytes(algorithm: HashAlgorithm, data: &[u8]) -> ContentHash {
        let mut hasher = Self::new(algorithm);
        hasher.update(data);
        hasher.finalize()
    }

    /// Hash a file.
    pub fn hash_file(algorithm: HashAlgorithm, path: &Path) -> Result<ContentHash> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Self::new(algorithm);
        // L-03: Use heap-allocated Vec instead of stack-allocated array
        // to avoid stack overflow on platforms with small default stack size
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer on heap

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize())
    }

    /// Hash a directory recursively (sorted for determinism).
    pub fn hash_directory(algorithm: HashAlgorithm, path: &Path) -> Result<ContentHash> {
        use walkdir::WalkDir;

        let mut entries: Vec<_> = WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
            .collect();

        // Sort for deterministic ordering
        entries.sort_by(|a, b| a.path().cmp(b.path()));

        let mut hasher = Self::new(algorithm);

        for entry in entries {
            // Include relative path in hash for structure
            let relative = entry
                .path()
                .strip_prefix(path)
                .map_err(|e| CratonsError::Io(std::io::Error::other(e.to_string())))?;
            hasher.update(relative.to_string_lossy().as_bytes());
            hasher.update(b"\0");

            // Hash file contents
            let file_hash = Self::hash_file(algorithm, entry.path())?;
            hasher.update(file_hash.value.as_bytes());
            hasher.update(b"\0");
        }

        Ok(hasher.finalize())
    }
}

impl Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let hash = Hasher::hash_bytes(HashAlgorithm::Blake3, b"hello world");
        assert_eq!(hash.algorithm, HashAlgorithm::Blake3);
        assert_eq!(hash.value.len(), 64); // Blake3 produces 256-bit hash
    }

    #[test]
    fn test_sha256_hash() {
        let hash = Hasher::hash_bytes(HashAlgorithm::Sha256, b"hello world");
        assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
        // Known SHA-256 of "hello world"
        assert_eq!(
            hash.value,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hash_parse() {
        let hash = ContentHash::parse("sha256:abc123").unwrap();
        assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
        assert_eq!(hash.value, "abc123");

        let hash = ContentHash::parse("abc123").unwrap();
        assert_eq!(hash.algorithm, HashAlgorithm::Blake3);
        assert_eq!(hash.value, "abc123");
    }

    #[test]
    fn test_hash_verify() {
        let data = b"test data";
        let hash = Hasher::hash_bytes(HashAlgorithm::Blake3, data);
        assert!(hash.verify(data).unwrap());
        assert!(!hash.verify(b"wrong data").unwrap());
    }
}
