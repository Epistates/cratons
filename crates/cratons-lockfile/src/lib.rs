//! # cratons-lockfile
//!
//! Lockfile format and operations for the Cratons package manager.
//!
//! The lockfile (`cratons.lock`) pins all dependencies to exact versions
//! with integrity hashes for reproducible builds.
//!
//! ## Concurrent Access
//!
//! This crate uses file locking to prevent concurrent writes from corrupting
//! the lockfile. When saving, an exclusive lock is acquired and the file is
//! written atomically using a temporary file and rename.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use chrono::{DateTime, Utc};
use cratons_core::{ContentHash, CratonsError, Ecosystem, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tracing::{debug, warn};

/// The current lockfile schema version.
pub const LOCKFILE_VERSION: u32 = 2;

/// Minimum supported lockfile schema version for reading.
pub const MIN_SUPPORTED_VERSION: u32 = 1;

/// Maximum supported lockfile schema version for reading.
pub const MAX_SUPPORTED_VERSION: u32 = 2;

/// The lockfile filename.
pub const LOCKFILE_NAME: &str = "cratons.lock";

/// Current cratons version for compatibility tracking.
pub const CRATONS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lockfile metadata for versioning and compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LockfileMetadata {
    /// Schema version of this lockfile
    pub schema_version: u32,

    /// Minimum cratons version required to read this lockfile
    #[serde(default)]
    pub minimum_cratons_version: Option<String>,

    /// Cratons version that generated this lockfile
    pub generated_by: String,

    /// When the lockfile was generated
    pub generated_at: DateTime<Utc>,

    /// Previous schema version this was migrated from (if any)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrated_from: Option<u32>,
}

impl Default for LockfileMetadata {
    fn default() -> Self {
        Self {
            schema_version: LOCKFILE_VERSION,
            minimum_cratons_version: None,
            generated_by: CRATONS_VERSION.to_string(),
            generated_at: Utc::now(),
            migrated_from: None,
        }
    }
}

/// Key for package index lookup.
type PackageKey = (String, Ecosystem);

/// Cryptographic signature for lockfile integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LockfileSignature {
    /// The signing algorithm used (e.g., "ed25519", "blake3-hmac")
    pub algorithm: String,
    /// Base64-encoded signature value
    pub signature: String,
    /// Optional key identifier for multi-key setups
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// When the signature was created
    pub signed_at: DateTime<Utc>,
}

/// The main lockfile structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Lockfile {
    /// Lockfile format version (legacy field for backwards compatibility)
    #[serde(default = "default_version")]
    pub version: u32,

    /// Lockfile metadata including versioning info
    #[serde(default)]
    pub metadata: LockfileMetadata,

    /// When the lockfile was generated (legacy field)
    #[serde(default = "Utc::now")]
    pub generated: DateTime<Utc>,

    /// Cratons version that generated this lockfile (legacy field)
    #[serde(default = "default_cratons_version")]
    pub cratons_version: String,

    /// Hash of the manifest (to detect staleness)
    pub manifest_hash: ContentHash,

    /// Pinned toolchains
    #[serde(default)]
    pub toolchains: HashMap<String, ToolchainPin>,

    /// Resolved packages
    #[serde(default)]
    pub packages: Vec<LockedPackage>,

    /// Build artifact cache mapping
    #[serde(default)]
    pub artifacts: HashMap<String, ArtifactCache>,

    /// Cryptographic signature over the lockfile content (for supply chain security).
    /// When present, verifies the lockfile hasn't been tampered with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<LockfileSignature>,

    /// Index for O(1) package lookups by (name, ecosystem)
    /// Rebuilt after deserialization.
    #[serde(skip)]
    package_index: HashMap<PackageKey, usize>,
}

fn default_version() -> u32 {
    LOCKFILE_VERSION
}

fn default_cratons_version() -> String {
    CRATONS_VERSION.to_string()
}

impl Lockfile {
    /// Create a new empty lockfile.
    #[must_use]
    pub fn new(manifest_hash: ContentHash) -> Self {
        let now = Utc::now();
        Self {
            version: LOCKFILE_VERSION,
            metadata: LockfileMetadata {
                schema_version: LOCKFILE_VERSION,
                minimum_cratons_version: None,
                generated_by: CRATONS_VERSION.to_string(),
                generated_at: now,
                migrated_from: None,
            },
            generated: now,
            cratons_version: CRATONS_VERSION.to_string(),
            manifest_hash,
            toolchains: HashMap::new(),
            packages: Vec::new(),
            artifacts: HashMap::new(),
            signature: None,
            package_index: HashMap::new(),
        }
    }

    /// Rebuild the package index for O(1) lookups.
    fn rebuild_index(&mut self) {
        self.package_index.clear();
        for (idx, pkg) in self.packages.iter().enumerate() {
            self.package_index
                .insert((pkg.name.clone(), pkg.ecosystem), idx);
        }
    }

    /// Load a lockfile from a file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|e| {
            CratonsError::Lockfile(format!("Failed to read {}: {}", path.display(), e))
        })?;

        Self::from_str(&content)
    }

    /// Parse a lockfile from a string with version checking and migration.
    pub fn from_str(content: &str) -> Result<Self> {
        // First, do a minimal parse to check the version
        #[derive(Deserialize)]
        struct VersionCheck {
            version: Option<u32>,
            #[serde(default)]
            metadata: Option<VersionCheckMeta>,
        }

        #[derive(Deserialize, Default)]
        #[serde(rename_all = "kebab-case")]
        struct VersionCheckMeta {
            schema_version: Option<u32>,
        }

        let version_check: VersionCheck = toml::from_str(content)
            .map_err(|e| CratonsError::Lockfile(format!("Failed to parse lockfile: {e}")))?;

        // Determine the effective schema version
        let schema_version = version_check
            .metadata
            .and_then(|m| m.schema_version)
            .or(version_check.version)
            .unwrap_or(1); // Default to v1 for very old lockfiles

        // Check version compatibility
        if schema_version < MIN_SUPPORTED_VERSION {
            return Err(CratonsError::Lockfile(format!(
                "Lockfile schema version {} is too old. Minimum supported: {}. \
                 Please delete the lockfile and regenerate.",
                schema_version, MIN_SUPPORTED_VERSION
            )));
        }

        if schema_version > MAX_SUPPORTED_VERSION {
            return Err(CratonsError::Lockfile(format!(
                "Lockfile schema version {} is newer than supported (max: {}). \
                 Please upgrade cratons to read this lockfile.",
                schema_version, MAX_SUPPORTED_VERSION
            )));
        }

        // Parse the full lockfile
        let mut lockfile: Lockfile = toml::from_str(content)
            .map_err(|e| CratonsError::Lockfile(format!("Failed to parse lockfile: {e}")))?;

        // Perform migrations if needed
        if schema_version < LOCKFILE_VERSION {
            lockfile = Self::migrate(lockfile, schema_version)?;
        }

        // Rebuild the package index for O(1) lookups
        lockfile.rebuild_index();

        Ok(lockfile)
    }

    /// Migrate a lockfile from an older schema version.
    fn migrate(mut lockfile: Lockfile, from_version: u32) -> Result<Self> {
        debug!(
            "Migrating lockfile from schema version {} to {}",
            from_version, LOCKFILE_VERSION
        );

        // Track migration
        lockfile.metadata.migrated_from = Some(from_version);
        lockfile.metadata.schema_version = LOCKFILE_VERSION;
        lockfile.version = LOCKFILE_VERSION;

        // Perform version-specific migrations
        // v1 -> v2: Added metadata section (already handled by defaults)
        if from_version < 2 {
            // Copy legacy fields to metadata
            lockfile.metadata.generated_at = lockfile.generated;
            lockfile.metadata.generated_by = lockfile.cratons_version.clone();
        }

        // Future migrations would go here:
        // if from_version < 3 { ... }

        warn!(
            "Migrated lockfile from schema version {} to {}. \
             Run 'cratons install' to update the lockfile.",
            from_version, LOCKFILE_VERSION
        );

        Ok(lockfile)
    }

    /// Check if the current cratons version can read this lockfile.
    pub fn check_compatibility(&self) -> Result<()> {
        let schema_version = self.metadata.schema_version;

        if schema_version < MIN_SUPPORTED_VERSION {
            return Err(CratonsError::Lockfile(format!(
                "Lockfile schema version {} is too old (min: {})",
                schema_version, MIN_SUPPORTED_VERSION
            )));
        }

        if schema_version > MAX_SUPPORTED_VERSION {
            return Err(CratonsError::Lockfile(format!(
                "Lockfile schema version {} is too new (max: {})",
                schema_version, MAX_SUPPORTED_VERSION
            )));
        }

        Ok(())
    }

    /// Save the lockfile to a file atomically with file locking.
    ///
    /// This method:
    /// 1. Acquires an exclusive lock on a lock file
    /// 2. Writes content to a temporary file
    /// 3. Atomically renames the temp file to the target
    /// 4. Releases the lock
    ///
    /// This prevents corruption from concurrent writes.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let content = self.to_toml_string()?;

        // Create a lock file path
        let lock_path = path.with_extension("lock.lck");

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Open/create lock file and acquire exclusive lock
        let lock_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)
            .map_err(|e| {
                CratonsError::Lockfile(format!(
                    "Failed to create lock file {}: {}",
                    lock_path.display(),
                    e
                ))
            })?;

        // Try to acquire exclusive lock with timeout behavior
        // SECURITY: Lock failure is an error to prevent concurrent writes from corrupting
        // the lockfile, especially on network filesystems. Use save_unlocked() if you
        // want to bypass locking (e.g., in tests or single-threaded contexts).
        let lock_acquired = lock_file.try_lock_exclusive().is_ok();
        if !lock_acquired {
            // Block waiting for lock
            if let Err(e) = lock_file.lock_exclusive() {
                return Err(CratonsError::Lockfile(format!(
                    "Failed to acquire exclusive lock on {}: {}. \
                     Another cratons process may be running, or you may be on a \
                     filesystem that doesn't support file locking. Use the --force \
                     flag to bypass locking (not recommended for concurrent access).",
                    lock_path.display(),
                    e
                )));
            }
            debug!("Acquired exclusive lock on lockfile");
        }

        // Write to a temporary file first, then rename for atomicity
        let temp_path = path.with_extension("lock.tmp");

        let write_result = (|| -> Result<()> {
            let mut temp_file = File::create(&temp_path).map_err(|e| {
                CratonsError::Lockfile(format!(
                    "Failed to create temp file {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;

            temp_file.write_all(content.as_bytes()).map_err(|e| {
                CratonsError::Lockfile(format!(
                    "Failed to write to temp file {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;

            temp_file.sync_all().map_err(|e| {
                CratonsError::Lockfile(format!(
                    "Failed to sync temp file {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;

            Ok(())
        })();

        // Handle write errors before rename
        if let Err(e) = write_result {
            // Clean up temp file on error
            let _ = fs::remove_file(&temp_path);
            let _ = lock_file.unlock();
            return Err(e);
        }

        // Atomically rename temp file to target
        let rename_result = fs::rename(&temp_path, path).map_err(|e| {
            CratonsError::Lockfile(format!(
                "Failed to rename {} to {}: {}",
                temp_path.display(),
                path.display(),
                e
            ))
        });

        // Release lock
        let _ = lock_file.unlock();

        // Clean up lock file (best effort)
        let _ = fs::remove_file(&lock_path);

        rename_result?;
        debug!("Saved lockfile to {}", path.display());
        Ok(())
    }

    /// Save the lockfile without locking (for use in tests or single-threaded contexts).
    pub fn save_unlocked(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let content = self.to_toml_string()?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Serialize to TOML string.
    pub fn to_toml_string(&self) -> Result<String> {
        // Add header comment
        let mut output = String::new();
        output.push_str("# This file is automatically generated by Cratons.\n");
        output.push_str("# Do not edit manually.\n\n");

        let toml = toml::to_string_pretty(self)
            .map_err(|e| CratonsError::Lockfile(format!("Failed to serialize lockfile: {e}")))?;

        output.push_str(&toml);
        Ok(output)
    }

    /// Check if the lockfile is fresh (matches the manifest hash).
    #[must_use]
    pub fn is_fresh(&self, manifest_hash: &ContentHash) -> bool {
        self.manifest_hash == *manifest_hash
    }

    /// Find a locked package by name and ecosystem.
    /// Uses O(1) HashMap lookup instead of linear scan.
    #[must_use]
    pub fn find_package(&self, name: &str, ecosystem: Ecosystem) -> Option<&LockedPackage> {
        self.package_index
            .get(&(name.to_string(), ecosystem))
            .and_then(|&idx| self.packages.get(idx))
    }

    /// Get all packages for an ecosystem.
    pub fn packages_for_ecosystem(
        &self,
        ecosystem: Ecosystem,
    ) -> impl Iterator<Item = &LockedPackage> {
        self.packages
            .iter()
            .filter(move |p| p.ecosystem == ecosystem)
    }

    /// Get direct dependencies.
    pub fn direct_packages(&self) -> impl Iterator<Item = &LockedPackage> {
        self.packages.iter().filter(|p| p.direct)
    }

    /// Add a locked package.
    /// Maintains the O(1) lookup index.
    pub fn add_package(&mut self, package: LockedPackage) {
        let key = (package.name.clone(), package.ecosystem);

        // Check if package already exists
        if let Some(&existing_idx) = self.package_index.get(&key) {
            // Update existing package in place
            self.packages[existing_idx] = package;
        } else {
            // Add new package
            let new_idx = self.packages.len();
            self.package_index.insert(key, new_idx);
            self.packages.push(package);
        }
    }

    /// Get the artifact cache entry for an input hash.
    #[must_use]
    pub fn get_artifact_cache(&self, input_hash: &str) -> Option<&ArtifactCache> {
        self.artifacts.get(input_hash)
    }

    /// Update the artifact cache.
    pub fn update_artifact_cache(&mut self, input_hash: String, cache: ArtifactCache) {
        self.artifacts.insert(input_hash, cache);
    }

    /// Get total number of packages.
    #[must_use]
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// Get the canonical content for signing (lockfile without signature field).
    ///
    /// This method serializes the lockfile to TOML while excluding the signature field,
    /// producing deterministic content that can be signed or verified.
    pub fn content_for_signing(&self) -> Result<String> {
        // Create a copy without the signature field
        let mut unsigned = self.clone();
        unsigned.signature = None;

        // Serialize to canonical TOML format (without header comments)
        let toml = toml::to_string_pretty(&unsigned).map_err(|e| {
            CratonsError::Lockfile(format!("Failed to serialize lockfile for signing: {e}"))
        })?;

        Ok(toml)
    }

    /// Sign the lockfile with a private key.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The Ed25519 private key bytes (32 bytes)
    /// * `algorithm` - The signing algorithm (currently only "ed25519" is supported)
    ///
    /// # Security
    ///
    /// - Uses Ed25519 (RFC 8032) for cryptographic signatures
    /// - Key material should be stored securely (e.g., in system keychain)
    /// - Signatures are deterministic per Ed25519 specification
    ///
    /// # Errors
    ///
    /// Returns an error if the algorithm is unsupported or the key is invalid.
    pub fn sign(&mut self, private_key: &[u8], algorithm: &str) -> Result<()> {
        use base64::Engine;
        use ed25519_dalek::{Signer, SigningKey};

        // Validate algorithm
        if algorithm != "ed25519" {
            return Err(CratonsError::Lockfile(format!(
                "Unsupported signing algorithm: {}. Only 'ed25519' is supported.",
                algorithm
            )));
        }

        // Validate key length
        if private_key.len() != 32 {
            return Err(CratonsError::Lockfile(format!(
                "Invalid Ed25519 private key length: expected 32 bytes, got {}",
                private_key.len()
            )));
        }

        // Get content to sign
        let content = self.content_for_signing()?;

        // Create signing key from bytes
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            CratonsError::Lockfile("Failed to convert private key to fixed array".to_string())
        })?;
        let signing_key = SigningKey::from_bytes(&key_bytes);

        // Sign the content
        let signature = signing_key.sign(content.as_bytes());

        // Encode signature as base64
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        self.signature = Some(LockfileSignature {
            algorithm: algorithm.to_string(),
            signature: signature_b64,
            key_id: None,
            signed_at: Utc::now(),
        });

        debug!("Lockfile signed with Ed25519 algorithm");

        Ok(())
    }

    /// Sign the lockfile with a key ID for key management.
    ///
    /// This variant allows specifying a key identifier for multi-key setups.
    pub fn sign_with_key_id(
        &mut self,
        private_key: &[u8],
        algorithm: &str,
        key_id: &str,
    ) -> Result<()> {
        self.sign(private_key, algorithm)?;
        if let Some(ref mut sig) = self.signature {
            sig.key_id = Some(key_id.to_string());
        }
        Ok(())
    }

    /// Verify the lockfile signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The Ed25519 public key bytes (32 bytes)
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Security
    ///
    /// - Uses Ed25519 signature verification
    /// - Verification is constant-time to prevent timing attacks
    /// - Validates signature format before verification
    ///
    /// # Errors
    ///
    /// Returns an error if no signature is present, the algorithm is unsupported,
    /// or the key/signature format is invalid.
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool> {
        use base64::Engine;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Check if signature exists
        let sig_data = self.signature.as_ref().ok_or_else(|| {
            CratonsError::Lockfile("No signature present in lockfile".to_string())
        })?;

        // Validate algorithm
        if sig_data.algorithm != "ed25519" {
            return Err(CratonsError::Lockfile(format!(
                "Unsupported signature algorithm: {}. Only 'ed25519' is supported.",
                sig_data.algorithm
            )));
        }

        // Validate public key length
        if public_key.len() != 32 {
            return Err(CratonsError::Lockfile(format!(
                "Invalid Ed25519 public key length: expected 32 bytes, got {}",
                public_key.len()
            )));
        }

        // Get content that was signed
        let content = self.content_for_signing()?;

        // Parse public key
        let key_bytes: [u8; 32] = public_key.try_into().map_err(|_| {
            CratonsError::Lockfile("Failed to convert public key to fixed array".to_string())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CratonsError::Lockfile(format!("Invalid Ed25519 public key: {}", e)))?;

        // Decode signature from base64
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_data.signature)
            .map_err(|e| CratonsError::Lockfile(format!("Invalid base64 signature: {}", e)))?;

        // Parse signature
        let sig_len = sig_bytes.len();
        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            CratonsError::Lockfile(format!(
                "Invalid signature length: expected 64 bytes, got {}",
                sig_len
            ))
        })?;
        let signature = Signature::from_bytes(&sig_array);

        // Verify signature (constant-time)
        let is_valid = verifying_key.verify(content.as_bytes(), &signature).is_ok();

        debug!(
            "Lockfile signature verification: {}",
            if is_valid { "valid" } else { "invalid" }
        );

        Ok(is_valid)
    }

    /// Generate a new Ed25519 keypair for lockfile signing.
    ///
    /// # Returns
    ///
    /// A tuple of (private_key, public_key) as 32-byte arrays.
    ///
    /// # Security
    ///
    /// Uses the system's cryptographically secure random number generator.
    /// The private key should be stored securely (e.g., in system keychain).
    #[must_use]
    pub fn generate_signing_keypair() -> ([u8; 32], [u8; 32]) {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        (signing_key.to_bytes(), verifying_key.to_bytes())
    }
}

/// A pinned toolchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolchainPin {
    /// Exact version
    pub version: String,
    /// Content hash of the toolchain
    pub hash: ContentHash,
    /// Download URL
    pub url: String,
}

/// A locked package with exact version and source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LockedPackage {
    /// Package name
    pub name: String,
    /// Exact version
    pub version: String,
    /// Ecosystem
    pub ecosystem: Ecosystem,
    /// Source URL
    pub source: String,
    /// Integrity hash (SHA-256 or SHA-512)
    pub integrity: String,
    /// Resolved content hash (Blake3)
    pub resolved_hash: ContentHash,
    /// Whether this is a direct dependency
    #[serde(default)]
    pub direct: bool,
    /// Enabled features
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Dependencies (name@version references)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<DependencyRef>,
}

impl LockedPackage {
    /// Get the display name (name@version).
    #[must_use]
    pub fn display_name(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// Parse the integrity hash.
    ///
    /// Supports npm-style integrity hashes in the format `sha256-<base64>` or `sha512-<base64>`.
    pub fn parse_integrity(&self) -> Result<ContentHash> {
        // Format: sha256-base64 or sha512-base64
        if let Some(hash) = self.integrity.strip_prefix("sha256-") {
            Ok(ContentHash::sha256(hash.to_string()))
        } else if let Some(hash) = self.integrity.strip_prefix("sha512-") {
            // Properly store as SHA512 to preserve algorithm information
            Ok(ContentHash::sha512(hash.to_string()))
        } else if let Some(hash) = self.integrity.strip_prefix("blake3-") {
            Ok(ContentHash::blake3(hash.to_string()))
        } else {
            Err(CratonsError::Lockfile(format!(
                "Unknown integrity format: {}. Expected sha256-*, sha512-*, or blake3-*",
                self.integrity
            )))
        }
    }
}

/// Reference to a dependency in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRef {
    /// Package name
    pub name: String,
    /// Version
    pub version: String,
}

impl DependencyRef {
    /// Create a new dependency reference.
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

/// Cached build artifact information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactCache {
    /// Output hash
    pub output: ContentHash,
    /// When the artifact was built
    pub built: DateTime<Utc>,
}

impl ArtifactCache {
    /// Create a new artifact cache entry.
    #[must_use]
    pub fn new(output: ContentHash) -> Self {
        Self {
            output,
            built: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockfile_creation() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let lockfile = Lockfile::new(manifest_hash.clone());

        assert_eq!(lockfile.version, LOCKFILE_VERSION);
        assert!(lockfile.is_fresh(&manifest_hash));
        assert!(lockfile.packages.is_empty());
    }

    #[test]
    fn test_lockfile_serialization() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string(),
            integrity: "sha256-abc123".to_string(),
            resolved_hash: ContentHash::blake3("lodash-content".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        let toml = lockfile.to_toml_string().unwrap();
        assert!(toml.contains("lodash"));
        assert!(toml.contains("4.17.21"));

        // Parse back
        let parsed = Lockfile::from_str(&toml).unwrap();
        assert_eq!(parsed.packages.len(), 1);
        assert_eq!(parsed.packages[0].name, "lodash");
    }

    #[test]
    fn test_find_package() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string(),
            integrity: "sha256-abc123".to_string(),
            resolved_hash: ContentHash::blake3("lodash-content".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        let found = lockfile.find_package("lodash", Ecosystem::Npm);
        assert!(found.is_some());
        assert_eq!(found.unwrap().version, "4.17.21");

        let not_found = lockfile.find_package("lodash", Ecosystem::PyPi);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_packages_for_ecosystem() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        // Add npm packages
        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-abc".to_string(),
            resolved_hash: ContentHash::blake3("lodash".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });
        lockfile.add_package(LockedPackage {
            name: "express".to_string(),
            version: "4.18.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-def".to_string(),
            resolved_hash: ContentHash::blake3("express".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Add pypi package
        lockfile.add_package(LockedPackage {
            name: "requests".to_string(),
            version: "2.28.0".to_string(),
            ecosystem: Ecosystem::PyPi,
            source: "pypi".to_string(),
            integrity: "sha256-ghi".to_string(),
            resolved_hash: ContentHash::blake3("requests".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        let npm_packages: Vec<_> = lockfile.packages_for_ecosystem(Ecosystem::Npm).collect();
        assert_eq!(npm_packages.len(), 2);

        let pypi_packages: Vec<_> = lockfile.packages_for_ecosystem(Ecosystem::PyPi).collect();
        assert_eq!(pypi_packages.len(), 1);

        let crates_packages: Vec<_> = lockfile.packages_for_ecosystem(Ecosystem::Crates).collect();
        assert_eq!(crates_packages.len(), 0);
    }

    #[test]
    fn test_direct_packages() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-abc".to_string(),
            resolved_hash: ContentHash::blake3("lodash".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });
        lockfile.add_package(LockedPackage {
            name: "transitive-dep".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-xyz".to_string(),
            resolved_hash: ContentHash::blake3("transitive".to_string()),
            direct: false,
            features: vec![],
            dependencies: vec![],
        });

        let direct: Vec<_> = lockfile.direct_packages().collect();
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].name, "lodash");
    }

    #[test]
    fn test_artifact_cache() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        let input_hash = "input-hash-123";
        let output_hash = ContentHash::blake3("output".to_string());
        let cache = ArtifactCache::new(output_hash.clone());

        lockfile.update_artifact_cache(input_hash.to_string(), cache);

        let retrieved = lockfile.get_artifact_cache(input_hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().output, output_hash);

        let not_found = lockfile.get_artifact_cache("nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_locked_package_display_name() {
        let pkg = LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-abc".to_string(),
            resolved_hash: ContentHash::blake3("lodash".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };

        assert_eq!(pkg.display_name(), "lodash@4.17.21");
    }

    #[test]
    fn test_locked_package_parse_integrity() {
        let pkg = LockedPackage {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-abc123def".to_string(),
            resolved_hash: ContentHash::blake3("test".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };

        let hash = pkg.parse_integrity().unwrap();
        assert_eq!(hash.value, "abc123def");
    }

    #[test]
    fn test_locked_package_parse_integrity_sha512() {
        let pkg = LockedPackage {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha512-longerhash".to_string(),
            resolved_hash: ContentHash::blake3("test".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };

        let hash = pkg.parse_integrity().unwrap();
        assert_eq!(hash.value, "longerhash");
    }

    #[test]
    fn test_locked_package_parse_integrity_invalid() {
        let pkg = LockedPackage {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "md5-invalid".to_string(),
            resolved_hash: ContentHash::blake3("test".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };

        assert!(pkg.parse_integrity().is_err());
    }

    #[test]
    fn test_dependency_ref() {
        let dep = DependencyRef::new("lodash", "4.17.21");
        assert_eq!(dep.name, "lodash");
        assert_eq!(dep.version, "4.17.21");
    }

    #[test]
    fn test_package_count() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        assert_eq!(lockfile.package_count(), 0);

        lockfile.add_package(LockedPackage {
            name: "pkg1".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-abc".to_string(),
            resolved_hash: ContentHash::blake3("pkg1".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        assert_eq!(lockfile.package_count(), 1);
    }

    #[test]
    fn test_is_fresh() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let lockfile = Lockfile::new(manifest_hash.clone());

        assert!(lockfile.is_fresh(&manifest_hash));

        let different_hash = ContentHash::blake3("different".to_string());
        assert!(!lockfile.is_fresh(&different_hash));
    }

    #[test]
    fn test_add_package_replaces_existing() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.20".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-old".to_string(),
            resolved_hash: ContentHash::blake3("old".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Add same package with different version
        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-new".to_string(),
            resolved_hash: ContentHash::blake3("new".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        assert_eq!(lockfile.package_count(), 1);
        assert_eq!(lockfile.packages[0].version, "4.17.21");
    }

    #[test]
    fn test_toolchain_pin() {
        let pin = ToolchainPin {
            version: "1.75.0".to_string(),
            hash: ContentHash::blake3("rust-toolchain".to_string()),
            url: "https://example.com/rust-1.75.0.tar.gz".to_string(),
        };

        assert_eq!(pin.version, "1.75.0");
        assert!(!pin.url.is_empty());
    }

    // ==========================================================================
    // M-04 FIX: Version Migration Tests
    // ==========================================================================

    /// Test v1 to v2 migration logic.
    #[test]
    fn test_migrate_v1_to_v2() {
        // Create a lockfile and manually set it to v1 state
        let manifest_hash = ContentHash::blake3("v1-migration-test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        // Simulate a v1 lockfile (before migration was run)
        lockfile.version = 1;
        lockfile.metadata.schema_version = 1;
        lockfile.cratons_version = "0.0.1".to_string();

        // Add a package
        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string(),
            integrity: "sha256-abc123".to_string(),
            resolved_hash: ContentHash::blake3("lodash".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Serialize and re-parse (this triggers migration)
        let toml_str = lockfile.to_toml_string().unwrap();
        let migrated = Lockfile::from_str(&toml_str).unwrap();

        // Should be migrated to v2
        assert_eq!(migrated.version, LOCKFILE_VERSION);
        assert_eq!(migrated.metadata.schema_version, LOCKFILE_VERSION);

        // Migration should be tracked
        assert_eq!(migrated.metadata.migrated_from, Some(1));

        // Legacy fields should be copied to metadata
        assert_eq!(migrated.metadata.generated_by, "0.0.1");

        // Package should be preserved
        assert_eq!(migrated.packages.len(), 1);
        assert_eq!(migrated.packages[0].name, "lodash");
        assert_eq!(migrated.packages[0].version, "4.17.21");
    }

    /// Test parsing a v2 lockfile (current version).
    #[test]
    fn test_parse_v2_lockfile() {
        // Create a v2 lockfile programmatically
        let manifest_hash = ContentHash::blake3("v2-parse-test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "express".to_string(),
            version: "4.18.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/express/-/express-4.18.0.tgz".to_string(),
            integrity: "sha256-def456".to_string(),
            resolved_hash: ContentHash::blake3("express".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Serialize and re-parse
        let toml_str = lockfile.to_toml_string().unwrap();
        let parsed = Lockfile::from_str(&toml_str).unwrap();

        // Should remain v2
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.metadata.schema_version, 2);

        // No migration needed for v2
        assert_eq!(parsed.metadata.migrated_from, None);

        // Package should be preserved
        assert_eq!(parsed.packages.len(), 1);
        assert_eq!(parsed.packages[0].name, "express");
    }

    /// Test that version too old is rejected.
    #[test]
    fn test_reject_version_too_old() {
        // Version 0 would be too old (MIN_SUPPORTED_VERSION is 1)
        let old_lockfile = r#"
version = 0

[manifest-hash]
algorithm = "blake3"
value = "abc123"
"#;

        let result = Lockfile::from_str(old_lockfile);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too old"));
    }

    /// Test that version too new is rejected.
    #[test]
    fn test_reject_version_too_new() {
        // Version 99 is beyond MAX_SUPPORTED_VERSION
        let future_lockfile = r#"
version = 99

[manifest-hash]
algorithm = "blake3"
value = "abc123"

[metadata]
schema-version = 99
"#;

        let result = Lockfile::from_str(future_lockfile);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("newer than supported")
        );
    }

    /// Test that check_compatibility works correctly.
    #[test]
    fn test_check_compatibility() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let lockfile = Lockfile::new(manifest_hash);

        // Current version should be compatible
        assert!(lockfile.check_compatibility().is_ok());
    }

    /// Test migration preserves packages with dependencies.
    #[test]
    fn test_migrate_preserves_dependencies() {
        // Create a v1 lockfile programmatically to ensure correct format
        let manifest_hash = ContentHash::blake3("migrate-deps-test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        // Manually set to v1 state (before migration)
        lockfile.version = 1;
        lockfile.metadata.schema_version = 1;

        // Add express with dependencies
        lockfile.add_package(LockedPackage {
            name: "express".to_string(),
            version: "4.18.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-express".to_string(),
            resolved_hash: ContentHash::blake3("express".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![
                DependencyRef::new("body-parser", "1.20.0"),
                DependencyRef::new("cookie", "0.5.0"),
            ],
        });

        lockfile.add_package(LockedPackage {
            name: "body-parser".to_string(),
            version: "1.20.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-bodyparser".to_string(),
            resolved_hash: ContentHash::blake3("bodyparser".to_string()),
            direct: false,
            features: vec![],
            dependencies: vec![],
        });

        // All packages should be preserved
        assert_eq!(lockfile.packages.len(), 2);

        // Dependencies should be preserved
        let express = lockfile.find_package("express", Ecosystem::Npm).unwrap();
        assert_eq!(express.dependencies.len(), 2);
        assert!(
            express
                .dependencies
                .iter()
                .any(|d| d.name == "body-parser" && d.version == "1.20.0")
        );
    }

    /// Test round-trip: serialize and re-parse.
    #[test]
    fn test_migration_round_trip() {
        let manifest_hash = ContentHash::blake3("roundtrip-test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-lodash".to_string(),
            resolved_hash: ContentHash::blake3("lodash".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Serialize to TOML
        let toml_str = lockfile.to_toml_string().unwrap();

        // Re-parse should preserve everything
        let reparsed = Lockfile::from_str(&toml_str).unwrap();
        assert_eq!(reparsed.version, LOCKFILE_VERSION);
        assert_eq!(reparsed.metadata.schema_version, LOCKFILE_VERSION);
        assert_eq!(reparsed.packages.len(), 1);
        assert_eq!(reparsed.packages[0].name, "lodash");
        assert_eq!(reparsed.packages[0].version, "4.17.21");
    }

    // ==========================================================================
    // Lockfile Signature Tests
    // ==========================================================================

    /// Test that a new lockfile has no signature by default.
    #[test]
    fn test_lockfile_no_signature_by_default() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let lockfile = Lockfile::new(manifest_hash);

        assert!(lockfile.signature.is_none());
    }

    /// Test signing a lockfile with real Ed25519 cryptography.
    #[test]
    fn test_sign_lockfile() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-abc".to_string(),
            resolved_hash: ContentHash::blake3("lodash".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Generate a real keypair
        let (private_key, _public_key) = Lockfile::generate_signing_keypair();

        // Sign with real Ed25519 key
        let result = lockfile.sign(&private_key, "ed25519");

        assert!(result.is_ok());
        assert!(lockfile.signature.is_some());

        let signature = lockfile.signature.as_ref().unwrap();
        assert_eq!(signature.algorithm, "ed25519");
        assert!(!signature.signature.is_empty());
        // Signature should be 64 bytes base64-encoded
        assert!(signature.signature.len() > 80); // Base64 of 64 bytes is ~88 chars
        assert!(signature.key_id.is_none());
    }

    /// Test verifying a lockfile signature with real Ed25519 cryptography.
    #[test]
    fn test_verify_lockfile_signature() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "express".to_string(),
            version: "4.18.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-def".to_string(),
            resolved_hash: ContentHash::blake3("express".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Generate a real keypair
        let (private_key, public_key) = Lockfile::generate_signing_keypair();

        // Sign the lockfile
        lockfile.sign(&private_key, "ed25519").unwrap();

        // Verify signature with matching public key
        let result = lockfile.verify_signature(&public_key);

        assert!(result.is_ok());
        assert!(result.unwrap()); // Signature should be valid
    }

    /// Test that verification fails with wrong public key.
    #[test]
    fn test_verify_with_wrong_key_fails() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "express".to_string(),
            version: "4.18.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-def".to_string(),
            resolved_hash: ContentHash::blake3("express".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Generate two different keypairs
        let (private_key, _public_key) = Lockfile::generate_signing_keypair();
        let (_other_private, other_public) = Lockfile::generate_signing_keypair();

        // Sign with first keypair
        lockfile.sign(&private_key, "ed25519").unwrap();

        // Verify with different public key - should fail
        let result = lockfile.verify_signature(&other_public);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Signature should be invalid
    }

    /// Test verifying an unsigned lockfile returns an error.
    #[test]
    fn test_verify_unsigned_lockfile_fails() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let lockfile = Lockfile::new(manifest_hash);

        // Generate a keypair
        let (_private_key, public_key) = Lockfile::generate_signing_keypair();

        let result = lockfile.verify_signature(&public_key);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No signature present")
        );
    }

    /// Test content_for_signing excludes the signature field.
    #[test]
    fn test_content_for_signing_excludes_signature() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "react".to_string(),
            version: "18.2.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-xyz".to_string(),
            resolved_hash: ContentHash::blake3("react".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Get content before signing
        let content_before = lockfile.content_for_signing().unwrap();

        // Generate keypair and sign
        let (private_key, _public_key) = Lockfile::generate_signing_keypair();
        lockfile.sign(&private_key, "ed25519").unwrap();

        // Get content after signing
        let content_after = lockfile.content_for_signing().unwrap();

        // Content should be identical (signature excluded)
        assert_eq!(content_before, content_after);

        // Content should not contain the signature field
        assert!(!content_after.contains("[signature]"));
        assert!(!content_after.contains("PLACEHOLDER_SIGNATURE"));
    }

    /// Test signature serialization and deserialization.
    #[test]
    fn test_signature_serialization() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        lockfile.add_package(LockedPackage {
            name: "vue".to_string(),
            version: "3.3.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "npm".to_string(),
            integrity: "sha256-vue".to_string(),
            resolved_hash: ContentHash::blake3("vue".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // Sign the lockfile with a real Ed25519 key
        let (private_key, _public_key) = Lockfile::generate_signing_keypair();
        lockfile.sign(&private_key, "ed25519").unwrap();

        // Serialize to TOML
        let toml_str = lockfile.to_toml_string().unwrap();

        // Should contain signature section
        assert!(toml_str.contains("[signature]"));
        assert!(toml_str.contains("algorithm = \"ed25519\""));

        // Parse back
        let parsed = Lockfile::from_str(&toml_str).unwrap();

        // Signature should be preserved
        assert!(parsed.signature.is_some());
        let signature = parsed.signature.as_ref().unwrap();
        assert_eq!(signature.algorithm, "ed25519");
        assert!(!signature.signature.is_empty());
    }

    /// Test signature with optional key_id field.
    #[test]
    fn test_signature_with_key_id() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);

        // Manually create a signature with key_id
        lockfile.signature = Some(LockfileSignature {
            algorithm: "ed25519".to_string(),
            signature: "test-signature".to_string(),
            key_id: Some("key-12345".to_string()),
            signed_at: Utc::now(),
        });

        // Serialize and parse
        let toml_str = lockfile.to_toml_string().unwrap();
        let parsed = Lockfile::from_str(&toml_str).unwrap();

        // key_id should be preserved
        assert!(parsed.signature.is_some());
        let signature = parsed.signature.as_ref().unwrap();
        assert_eq!(signature.key_id, Some("key-12345".to_string()));
    }

    /// Test that unsigned lockfiles don't have signature field in TOML.
    #[test]
    fn test_unsigned_lockfile_omits_signature() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let lockfile = Lockfile::new(manifest_hash);

        let toml_str = lockfile.to_toml_string().unwrap();

        // Should not contain signature section
        assert!(!toml_str.contains("[signature]"));
    }

    /// Test algorithm validation.
    #[test]
    fn test_signature_different_algorithms() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash.clone());
        let (private_key, _public_key) = Lockfile::generate_signing_keypair();

        // Test ed25519 (supported)
        lockfile.sign(&private_key, "ed25519").unwrap();
        assert_eq!(lockfile.signature.as_ref().unwrap().algorithm, "ed25519");

        // Test unsupported algorithm
        let mut lockfile2 = Lockfile::new(manifest_hash);
        let result = lockfile2.sign(&private_key, "blake3-hmac");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported signing algorithm")
        );
    }

    /// Test that signing updates the signature timestamp.
    #[test]
    fn test_signature_timestamp() {
        let manifest_hash = ContentHash::blake3("test".to_string());
        let mut lockfile = Lockfile::new(manifest_hash);
        let (private_key, _public_key) = Lockfile::generate_signing_keypair();

        let before = Utc::now();
        lockfile.sign(&private_key, "ed25519").unwrap();
        let after = Utc::now();

        let signature = lockfile.signature.as_ref().unwrap();
        assert!(signature.signed_at >= before);
        assert!(signature.signed_at <= after);
    }
}
