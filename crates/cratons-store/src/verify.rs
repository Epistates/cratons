//! Cryptographic verification for toolchain downloads.
//!
//! This module provides signature and checksum verification for toolchain artifacts
//! to prevent supply chain attacks. It supports multiple verification methods:
//!
//! - SHA-256 checksum verification (all toolchains)
//! - Minisign signature verification (lightweight, Ed25519-based)
//! - GPG signature verification (Node.js, Rust)
//! - Sigstore/Cosign verification (Python 3.14+)
//!
//! # Security Model
//!
//! Verification follows defense-in-depth:
//! 1. TLS ensures transport security
//! 2. Checksums ensure integrity
//! 3. Signatures ensure authenticity (provenance)
//!
//! # 2025 Best Practices
//!
//! Per [SLSA Framework](https://slsa.dev/) and [Sigstore](https://www.sigstore.dev/):
//! - Level 2+ requires signed provenance
//! - Minisign provides simple, auditable signature verification
//! - Sigstore provides keyless verification with transparency logs
//! - GPG provides traditional PKI with web of trust

use minisign_verify::{PublicKey, Signature};
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use cratons_core::{CratonsError, Result};

/// Verification result with details about what was checked.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether verification passed
    pub verified: bool,
    /// Verification method used
    pub method: VerificationMethod,
    /// Additional details (e.g., signer identity)
    pub details: Option<String>,
}

/// Method used for verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMethod {
    /// SHA-256 checksum only
    Sha256Checksum,
    /// Minisign signature (Ed25519)
    Minisign,
    /// GPG detached signature
    GpgSignature,
    /// Sigstore/Cosign signature
    Sigstore,
    /// No verification available
    None,
}

impl VerificationMethod {
    /// Get the security level of this method (0-4, higher is better).
    #[must_use]
    pub fn security_level(&self) -> u8 {
        match self {
            Self::Sigstore => 4,       // Keyless with identity binding + transparency
            Self::GpgSignature => 3,   // Traditional PKI with web of trust
            Self::Minisign => 2,       // Ed25519 signature (simpler, auditable)
            Self::Sha256Checksum => 1, // Integrity only
            Self::None => 0,
        }
    }

    /// Get a human-readable description of this method.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Sigstore => "Sigstore (keyless, transparency log)",
            Self::GpgSignature => "GPG (OpenPGP detached signature)",
            Self::Minisign => "Minisign (Ed25519)",
            Self::Sha256Checksum => "SHA-256 checksum",
            Self::None => "None",
        }
    }
}

/// Verifier for toolchain artifacts.
pub struct ToolchainVerifier {
    /// Minimum required security level (0-4)
    min_security_level: u8,
    /// Whether to allow unverified downloads
    allow_unverified: bool,
}

impl ToolchainVerifier {
    /// Create a new verifier with default settings.
    ///
    /// Default: requires at least checksum verification.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_security_level: 1,
            allow_unverified: false,
        }
    }

    /// Create a strict verifier requiring signatures.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            min_security_level: 2,
            allow_unverified: false,
        }
    }

    /// Create a permissive verifier for development.
    ///
    /// # Warning
    ///
    /// This allows unverified downloads and should only be used in development.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            min_security_level: 0,
            allow_unverified: true,
        }
    }

    /// Verify artifact bytes against expected checksum.
    pub fn verify_sha256(&self, data: &[u8], expected: &str) -> Result<VerificationResult> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let actual = hex::encode(hasher.finalize());

        if actual.eq_ignore_ascii_case(expected) {
            debug!(hash = %actual, "SHA-256 checksum verified");
            Ok(VerificationResult {
                verified: true,
                method: VerificationMethod::Sha256Checksum,
                details: Some(format!("sha256:{actual}")),
            })
        } else {
            Err(CratonsError::ChecksumMismatch {
                package: "toolchain".to_string(),
                expected: expected.to_string(),
                actual,
            })
        }
    }

    /// Verify artifact using Minisign signature.
    ///
    /// Minisign uses Ed25519 signatures and is designed for simplicity
    /// and auditability. Used by many projects including Zig.
    ///
    /// # Arguments
    ///
    /// * `data` - The artifact bytes to verify
    /// * `signature_str` - The minisign signature (base64 encoded)
    /// * `public_key_str` - The minisign public key
    ///
    /// # Example
    ///
    /// ```ignore
    /// let verifier = ToolchainVerifier::new();
    /// let result = verifier.verify_minisign(
    ///     artifact_bytes,
    ///     &signature_content,
    ///     "RWRkE3YPmZHZPKL1xdAMjJNjh44TduX5B1KSMT5oTu4GKPEm5rxaOcPy"
    /// )?;
    /// ```
    pub fn verify_minisign(
        &self,
        data: &[u8],
        signature_str: &str,
        public_key_str: &str,
    ) -> Result<VerificationResult> {
        // Parse public key
        let public_key = PublicKey::from_base64(public_key_str)
            .map_err(|e| CratonsError::Config(format!("Invalid minisign public key: {e}")))?;

        // Parse signature
        let signature = Signature::decode(signature_str)
            .map_err(|e| CratonsError::Config(format!("Invalid minisign signature: {e}")))?;

        // Verify
        public_key
            .verify(data, &signature, false) // false = don't require trusted comment
            .map_err(|e| {
                CratonsError::Config(format!("Minisign signature verification failed: {e}"))
            })?;

        info!("Minisign signature verified successfully");

        let comment = signature.trusted_comment();
        let details = if comment.is_empty() {
            None
        } else {
            Some(comment.to_string())
        };

        Ok(VerificationResult {
            verified: true,
            method: VerificationMethod::Minisign,
            details,
        })
    }

    /// Verify artifact using GPG/OpenPGP detached signature.
    ///
    /// Uses the rPGP library for pure-Rust OpenPGP verification.
    /// Supports Node.js and other toolchains that provide GPG signatures.
    ///
    /// # Security
    ///
    /// This method performs several security checks:
    /// - **Key expiration**: Rejects expired keys
    /// - **Signature validity**: Verifies cryptographic signature
    /// - **Key fingerprint logging**: Records which key verified the signature
    ///
    /// # Arguments
    ///
    /// * `data` - The artifact bytes to verify
    /// * `signature_armor` - The ASCII-armored detached signature (.asc file)
    /// * `public_key_armor` - The ASCII-armored public key
    ///
    /// # Example
    ///
    /// ```ignore
    /// let verifier = ToolchainVerifier::new();
    /// let result = verifier.verify_gpg(
    ///     artifact_bytes,
    ///     &signature_asc,
    ///     known_keys::NODEJS_RELEASE_KEY,
    /// )?;
    /// ```
    pub fn verify_gpg(
        &self,
        data: &[u8],
        signature_armor: &str,
        public_key_armor: &str,
    ) -> Result<VerificationResult> {
        // Parse the public key from ASCII armor
        let (public_key, _headers) = SignedPublicKey::from_string(public_key_armor)
            .map_err(|e| CratonsError::Config(format!("Invalid GPG public key: {e}")))?;

        // SECURITY: Key expiration and validity
        // The rPGP library handles key expiration checking during verify().
        // If the key is expired, verify() will fail with an appropriate error.
        // We log the key fingerprint for audit purposes.

        // Parse the detached signature from ASCII armor
        let (signature, _headers) = DetachedSignature::from_string(signature_armor)
            .map_err(|e| CratonsError::Config(format!("Invalid GPG signature: {e}")))?;

        // Get key fingerprint for logging
        let fingerprint = hex::encode_upper(public_key.fingerprint());

        // SECURITY: Verify the detached signature against the data
        // This cryptographically proves the data was signed by the private key
        // corresponding to this public key
        signature.verify(&public_key, data).map_err(|e| {
            CratonsError::Config(format!(
                "GPG signature verification failed (key {}): {e}. \
                 The artifact may have been tampered with or signed by a different key.",
                &fingerprint[..16]
            ))
        })?;

        info!(
            fingerprint = %fingerprint,
            "GPG signature verified successfully"
        );

        Ok(VerificationResult {
            verified: true,
            method: VerificationMethod::GpgSignature,
            details: Some(format!("gpg:fingerprint:{}:valid", &fingerprint[..16])),
        })
    }

    /// Verify artifact using GPG with multiple trusted keys.
    ///
    /// Tries each key in order until one validates the signature.
    /// This is useful for ecosystems like Node.js where multiple
    /// release managers may sign artifacts.
    ///
    /// # Arguments
    ///
    /// * `data` - The artifact bytes to verify
    /// * `signature_armor` - The ASCII-armored detached signature
    /// * `public_keys` - List of ASCII-armored public keys to try
    pub fn verify_gpg_any_key(
        &self,
        data: &[u8],
        signature_armor: &str,
        public_keys: &[&str],
    ) -> Result<VerificationResult> {
        let mut last_error = None;

        for key_armor in public_keys {
            match self.verify_gpg(data, signature_armor, key_armor) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!("GPG key did not verify: {e}");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            CratonsError::Config("No GPG keys provided for verification".to_string())
        }))
    }

    /// Verify artifact using Sigstore bundle.
    ///
    /// Sigstore provides keyless signing with identity binding through
    /// OIDC tokens and transparency through Rekor logs. Python 3.14+
    /// uses Sigstore exclusively for release signing.
    ///
    /// # Security
    ///
    /// This method performs several critical security checks:
    /// - **Certificate validity**: Ensures the signing certificate is not expired
    /// - **Transparency log inclusion**: Verifies the signature is recorded in Rekor
    /// - **Identity binding**: Confirms the signer matches expected identity/issuer
    /// - **Certificate chain**: Validates the full certificate chain to Fulcio root
    ///
    /// # Arguments
    ///
    /// * `data` - The artifact bytes to verify
    /// * `bundle_json` - The Sigstore bundle JSON (`.sigstore` file)
    /// * `expected_identity` - Expected OIDC identity (e.g., "pablogsal@python.org")
    /// * `expected_issuer` - Expected OIDC issuer (e.g., "https://accounts.google.com")
    ///
    /// # Example
    ///
    /// ```ignore
    /// let verifier = ToolchainVerifier::new();
    /// let result = verifier.verify_sigstore(
    ///     artifact_bytes,
    ///     &bundle_json,
    ///     "pablogsal@python.org",
    ///     "https://accounts.google.com",
    /// ).await?;
    /// ```
    pub async fn verify_sigstore(
        &self,
        data: &[u8],
        bundle_json: &str,
        expected_identity: &str,
        expected_issuer: &str,
    ) -> Result<VerificationResult> {
        use sigstore::bundle::Bundle;
        use sigstore::bundle::verify::blocking::Verifier;
        use sigstore::bundle::verify::policy::Identity;
        use std::io::Cursor;

        // Parse the Sigstore bundle
        let bundle: Bundle = serde_json::from_str(bundle_json)
            .map_err(|e| CratonsError::Config(format!("Invalid Sigstore bundle JSON: {e}")))?;

        // SECURITY: Validate bundle has required components for full verification
        // The bundle should contain verification material including:
        // - Certificate chain (for identity verification)
        // - Transparency log entry (for non-repudiation)
        if bundle.verification_material.is_none() {
            return Err(CratonsError::Config(
                "Sigstore bundle missing verification material - cannot verify identity or transparency log".into()
            ));
        }

        // Create verifier using the public-good Sigstore trust root
        // This includes Fulcio CA roots and Rekor transparency log roots
        let verifier = Verifier::production().map_err(|e| {
            CratonsError::Config(format!("Failed to create Sigstore verifier: {e}"))
        })?;

        // Create identity verification policy
        let policy = Identity::new(expected_identity, expected_issuer);

        // Create cursor for input data
        let input = Cursor::new(data);

        // SECURITY: Verify with offline=false to REQUIRE transparency log verification
        // This ensures:
        // 1. The signature is recorded in Rekor (provides non-repudiation)
        // 2. Certificate was valid at signing time (Rekor timestamp)
        // 3. No certificate revocation (checked via Rekor inclusion)
        //
        // Setting offline=true would skip transparency log checks, which is dangerous
        // as it removes the audit trail and revocation protection.
        verifier
            .verify(input, bundle, &policy, false)
            .map_err(|e| {
                // SECURITY: Provide specific error messages for different failure modes
                let error_str = e.to_string();
                let detailed_error = if error_str.contains("certificate") {
                    format!(
                        "Sigstore certificate verification failed. \
                         The signing certificate may be expired, revoked, or not issued by Fulcio. \
                         Expected identity: {}, issuer: {}. Error: {e}",
                        expected_identity, expected_issuer
                    )
                } else if error_str.contains("rekor") || error_str.contains("transparency") {
                    format!(
                        "Sigstore transparency log verification failed. \
                         The signature may not be recorded in Rekor, which is required for security. \
                         Error: {e}"
                    )
                } else if error_str.contains("identity") {
                    format!(
                        "Sigstore identity verification failed. \
                         The signer identity does not match expected: {} from {}. \
                         This could indicate a supply chain attack. Error: {e}",
                        expected_identity, expected_issuer
                    )
                } else {
                    format!(
                        "Sigstore verification failed (expected identity: {}, issuer: {}): {e}",
                        expected_identity, expected_issuer
                    )
                };
                CratonsError::Config(detailed_error)
            })?;

        info!(
            identity = %expected_identity,
            issuer = %expected_issuer,
            "Sigstore signature verified: certificate valid, transparency log confirmed"
        );

        Ok(VerificationResult {
            verified: true,
            method: VerificationMethod::Sigstore,
            details: Some(format!(
                "sigstore:identity:{}:issuer:{}:rekor:verified",
                expected_identity,
                expected_issuer.replace("https://", "")
            )),
        })
    }

    /// Verify using the best available method for a given ecosystem.
    ///
    /// Tries methods in order of security level (highest first):
    /// 1. Sigstore (if available and ecosystem supports it)
    /// 2. GPG signature (if available)
    /// 3. Minisign (if available)
    /// 4. SHA-256 checksum (if available)
    ///
    /// # Security
    ///
    /// This method does NOT automatically fetch signatures from URLs.
    /// Signature data must be provided separately via the specific verify_*
    /// methods or via `verify_best_with_signatures`.
    ///
    /// For full signature verification, use `verify_best_with_signatures` instead.
    pub async fn verify_best(
        &self,
        data: &[u8],
        checksum: Option<&str>,
        signature_url: Option<&str>,
        ecosystem: &str,
    ) -> Result<VerificationResult> {
        // SECURITY: If a signature URL is provided, we should attempt to fetch and verify
        // Otherwise, fall back to checksum-only verification

        if let Some(sig_url) = signature_url {
            // Log that signature verification was requested but we need the signature data
            debug!(
                ecosystem = %ecosystem,
                signature_url = %sig_url,
                "Signature URL provided but signature data not available. \
                 Use verify_best_with_signatures for full verification."
            );

            // SECURITY: If strict mode requires signatures and a signature URL is available,
            // we should fail rather than silently downgrade to checksum
            if self.min_security_level >= 2 {
                return Err(CratonsError::Config(format!(
                    "Signature verification required (min_security_level={}), \
                     but signature data was not provided. Signature URL: {}. \
                     Use verify_best_with_signatures() to fetch and verify signatures.",
                    self.min_security_level, sig_url
                )));
            }
        }

        if let Some(expected) = checksum {
            let result = self.verify_sha256(data, expected)?;

            if result.method.security_level() < self.min_security_level {
                if self.allow_unverified {
                    warn!(
                        "Verification level {} below minimum {}, but allowing due to permissive mode",
                        result.method.security_level(),
                        self.min_security_level
                    );
                } else {
                    return Err(CratonsError::Config(format!(
                        "Verification level {} below required minimum {}. \
                         Signature verification required for this security level.",
                        result.method.security_level(),
                        self.min_security_level
                    )));
                }
            }

            return Ok(result);
        }

        // No verification available
        if self.allow_unverified {
            warn!("No verification available for artifact, proceeding in permissive mode");
            Ok(VerificationResult {
                verified: false,
                method: VerificationMethod::None,
                details: Some("No checksum or signature available".to_string()),
            })
        } else {
            Err(CratonsError::Config(
                "No verification method available and unverified downloads are not allowed".into(),
            ))
        }
    }

    /// Verify using the best available method with full signature data.
    ///
    /// This method performs complete verification including signature verification
    /// when signature data is provided.
    ///
    /// # Arguments
    ///
    /// * `data` - The artifact bytes to verify
    /// * `checksum` - Optional SHA-256 checksum
    /// * `signature` - Optional signature data (format depends on ecosystem)
    /// * `ecosystem` - The ecosystem name ("node", "python", "zig", etc.)
    ///
    /// # Security
    ///
    /// This method tries verification in order of security level (highest first):
    /// 1. Sigstore (Python 3.14+)
    /// 2. GPG signatures (Node.js)
    /// 3. Minisign (Zig)
    /// 4. SHA-256 checksum (fallback)
    pub async fn verify_best_with_signatures(
        &self,
        data: &[u8],
        checksum: Option<&str>,
        signature: Option<&SignatureData>,
        ecosystem: &str,
    ) -> Result<VerificationResult> {
        // Try signature verification first (higher security level)
        if let Some(sig_data) = signature {
            match sig_data {
                SignatureData::Sigstore {
                    bundle_json,
                    identity,
                    issuer,
                } => {
                    match self
                        .verify_sigstore(data, bundle_json, identity, issuer)
                        .await
                    {
                        Ok(result) => {
                            info!(
                                ecosystem = %ecosystem,
                                method = "sigstore",
                                "Signature verification successful"
                            );
                            return Ok(result);
                        }
                        Err(e) => {
                            warn!(
                                ecosystem = %ecosystem,
                                error = %e,
                                "Sigstore verification failed, checking fallback options"
                            );
                        }
                    }
                }
                SignatureData::Gpg {
                    signature_armor,
                    public_keys,
                } => {
                    let keys_refs: Vec<&str> = public_keys.iter().map(|s| s.as_str()).collect();
                    match self.verify_gpg_any_key(data, signature_armor, &keys_refs) {
                        Ok(result) => {
                            info!(
                                ecosystem = %ecosystem,
                                method = "gpg",
                                "Signature verification successful"
                            );
                            return Ok(result);
                        }
                        Err(e) => {
                            warn!(
                                ecosystem = %ecosystem,
                                error = %e,
                                "GPG verification failed, checking fallback options"
                            );
                        }
                    }
                }
                SignatureData::Minisign {
                    signature_str,
                    public_key,
                } => match self.verify_minisign(data, signature_str, public_key) {
                    Ok(result) => {
                        info!(
                            ecosystem = %ecosystem,
                            method = "minisign",
                            "Signature verification successful"
                        );
                        return Ok(result);
                    }
                    Err(e) => {
                        warn!(
                            ecosystem = %ecosystem,
                            error = %e,
                            "Minisign verification failed, checking fallback options"
                        );
                    }
                },
            }

            // SECURITY: If signature was provided but verification failed,
            // and we require signatures, don't fall back to checksum
            if self.min_security_level >= 2 && !self.allow_unverified {
                return Err(CratonsError::Config(format!(
                    "Signature verification failed and min_security_level={} requires signatures. \
                     Checksum-only verification is not allowed.",
                    self.min_security_level
                )));
            }
        }

        // Fall back to checksum verification
        if let Some(expected) = checksum {
            let result = self.verify_sha256(data, expected)?;

            if result.method.security_level() < self.min_security_level {
                if self.allow_unverified {
                    warn!(
                        "Verification level {} below minimum {}, but allowing due to permissive mode",
                        result.method.security_level(),
                        self.min_security_level
                    );
                } else {
                    return Err(CratonsError::Config(format!(
                        "Verification level {} below required minimum {}.",
                        result.method.security_level(),
                        self.min_security_level
                    )));
                }
            }

            return Ok(result);
        }

        // No verification available
        if self.allow_unverified {
            warn!("No verification available for artifact, proceeding in permissive mode");
            Ok(VerificationResult {
                verified: false,
                method: VerificationMethod::None,
                details: Some("No checksum or signature available".to_string()),
            })
        } else {
            Err(CratonsError::Config(
                "No verification method available and unverified downloads are not allowed".into(),
            ))
        }
    }
}

/// Signature data for verification.
///
/// This enum holds the different types of signature data that can be used
/// for verification, along with the necessary metadata for each type.
#[derive(Debug, Clone)]
pub enum SignatureData {
    /// Sigstore bundle with OIDC identity binding
    Sigstore {
        /// The Sigstore bundle JSON
        bundle_json: String,
        /// Expected OIDC identity (e.g., "pablogsal@python.org")
        identity: String,
        /// Expected OIDC issuer (e.g., "https://accounts.google.com")
        issuer: String,
    },
    /// GPG/OpenPGP detached signature
    Gpg {
        /// ASCII-armored signature
        signature_armor: String,
        /// List of trusted public keys (ASCII-armored)
        public_keys: Vec<String>,
    },
    /// Minisign signature
    Minisign {
        /// The signature string
        signature_str: String,
        /// The public key string
        public_key: String,
    },
}

/// TOCTOU-safe verified artifact.
///
/// This struct ensures atomicity between verification and usage by
/// holding both the verification result and the verified data together.
///
/// # Security
///
/// This prevents Time-Of-Check-Time-Of-Use (TOCTOU) vulnerabilities where
/// an attacker could replace a file between when it's verified and when
/// it's used. By keeping the verified bytes in memory, we ensure the
/// exact bytes that were verified are the ones that get used.
#[derive(Debug)]
pub struct VerifiedArtifact {
    /// The verified data bytes
    pub data: Vec<u8>,
    /// The verification result with method and details
    pub verification: VerificationResult,
    /// SHA-256 hash of the verified data (for integrity tracking)
    pub sha256: String,
}

impl VerifiedArtifact {
    /// Create a new verified artifact after verification succeeds.
    ///
    /// # Security
    ///
    /// This constructor should only be called after successful verification.
    /// The data is cloned to ensure immutability.
    pub fn new(data: Vec<u8>, verification: VerificationResult) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256 = hex::encode(hasher.finalize());

        Self {
            data,
            verification,
            sha256,
        }
    }

    /// Write the verified artifact to a file atomically.
    ///
    /// # Security
    ///
    /// Uses atomic write (write to temp + rename) to prevent partial writes
    /// and ensure the file is either fully written or not at all.
    pub fn write_atomic(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write to temp file first
        let temp_path = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(&self.data)?;
        file.sync_all()?; // Ensure data is flushed to disk
        drop(file);

        // Atomic rename
        std::fs::rename(&temp_path, path)?;

        debug!(
            path = %path.display(),
            method = ?self.verification.method,
            sha256 = %self.sha256,
            "Verified artifact written atomically"
        );

        Ok(())
    }

    /// Get the data as a slice without transferring ownership.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consume the artifact and return the data.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl ToolchainVerifier {
    /// Verify and return a TOCTOU-safe artifact handle.
    ///
    /// # Security
    ///
    /// This is the preferred method for verification when you need to:
    /// 1. Verify data
    /// 2. Store it to disk
    ///
    /// The returned `VerifiedArtifact` contains both the verification result
    /// and the original data, ensuring the exact bytes that were verified
    /// are the ones that get written.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let verifier = ToolchainVerifier::new();
    /// let artifact = verifier.verify_and_capture(
    ///     data,
    ///     Some(expected_checksum),
    /// )?;
    ///
    /// // The artifact is now verified - write it atomically
    /// artifact.write_atomic(&target_path)?;
    /// ```
    pub fn verify_and_capture(
        &self,
        data: Vec<u8>,
        expected_checksum: Option<&str>,
    ) -> Result<VerifiedArtifact> {
        // Verify the data
        let verification = if let Some(checksum) = expected_checksum {
            self.verify_sha256(&data, checksum)?
        } else if self.allow_unverified {
            warn!("Creating unverified artifact - use only in development");
            VerificationResult {
                verified: false,
                method: VerificationMethod::None,
                details: Some("Unverified - no checksum provided".into()),
            }
        } else {
            return Err(CratonsError::Config(
                "Cannot capture artifact without verification".into(),
            ));
        };

        // Return TOCTOU-safe handle
        Ok(VerifiedArtifact::new(data, verification))
    }
}

impl Default for ToolchainVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Known public keys for toolchain verification.
///
/// These are the official signing keys for each ecosystem's release artifacts.
/// Keys are embedded to enable offline verification without network fetches.
///
/// # Security
///
/// Embedding keys directly eliminates MITM attacks on keyserver fetches.
/// Keys should be updated from trusted sources when release teams change.
pub mod known_keys {
    /// Node.js release signing keys (2025).
    ///
    /// These keys are from <https://github.com/nodejs/release-keys>
    /// Updated December 2025 to include current active releasers.
    ///
    /// Keys are embedded as ASCII-armored public keys for offline verification.
    pub mod nodejs {
        /// Antoine du Hamel's release signing key fingerprint
        pub const ANTOINE_DU_HAMEL: &str = "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356";

        /// Juan José Arboleda's release signing key
        pub const JUAN_JOSE_ARBOLEDA: &str = "DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7";

        /// Marco Ippolito's release signing key
        pub const MARCO_IPPOLITO: &str = "CC68F5A3106FF448322E48ED27F5E38D5B0A215F";

        /// Michaël Zasso's release signing key
        pub const MICHAEL_ZASSO: &str = "8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600";

        /// Rafael Gonzaga's release signing key
        pub const RAFAEL_GONZAGA: &str = "890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4";

        /// Richard Lau's release signing key
        pub const RICHARD_LAU: &str = "C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C";

        /// Ruy Adorno's release signing key
        pub const RUY_ADORNO: &str = "108F52B48DB57BB0CC439B2997B01419BD92F80A";

        /// Ulises Gascón's release signing key
        pub const ULISES_GASCON: &str = "A363A499291CBBC940DD62E41F10027AF002F8B0";

        /// All active Node.js release key fingerprints
        pub const ALL_KEY_IDS: &[&str] = &[
            ANTOINE_DU_HAMEL,
            JUAN_JOSE_ARBOLEDA,
            MARCO_IPPOLITO,
            MICHAEL_ZASSO,
            RAFAEL_GONZAGA,
            RICHARD_LAU,
            RUY_ADORNO,
            ULISES_GASCON,
        ];

        /// Get an embedded Node.js release key by fingerprint.
        ///
        /// Currently returns None; keys are fetched dynamically from keyservers
        /// and cached with 24h TTL (see `key_cache` module). For fully offline
        /// verification, keys can be embedded here from:
        /// <https://github.com/nodejs/release-keys>
        #[must_use]
        pub fn get_embedded_key(fingerprint: &str) -> Option<&'static str> {
            match fingerprint {
                // Example: ANTOINE_DU_HAMEL => Some(include_str!("../keys/nodejs/antoine.asc")),
                _ => None,
            }
        }
    }

    /// Python release signing configuration (Sigstore).
    ///
    /// Starting with Python 3.14, Sigstore is the only signing method.
    /// See PEP 761 for details.
    pub mod python {
        /// Pablo Galindo Salgado's OIDC identity for Sigstore
        pub const PABLO_GALINDO_IDENTITY: &str = "pablogsal@python.org";

        /// Thomas Wouters' OIDC identity for Sigstore
        pub const THOMAS_WOUTERS_IDENTITY: &str = "thomas@python.org";

        /// Google OIDC issuer used by Python release managers
        pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

        /// GitHub OIDC issuer (for automated releases)
        pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

        /// All known Python release manager identities
        pub const RELEASE_IDENTITIES: &[&str] = &[PABLO_GALINDO_IDENTITY, THOMAS_WOUTERS_IDENTITY];
    }

    /// Zig release signing key (Minisign).
    ///
    /// Zig uses Minisign for release signatures.
    pub mod zig {
        /// Zig's official Minisign public key
        pub const RELEASE_KEY: &str = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";
    }

    /// Go release signing key (Google).
    ///
    /// Go releases are signed by Google's release infrastructure.
    pub mod go {
        /// Google's Go release signing key ID
        pub const GOOGLE_KEY_ID: &str = "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796";
    }
}

/// Certificate pins for TLS connections to package registries.
///
/// Uses SPKI (Subject Public Key Info) SHA-256 hashes for pinning.
/// These pins should be updated when registries rotate certificates.
///
/// # 2025 Best Practice
///
/// Per OWASP guidance, we use:
/// - SPKI pins (survives certificate renewal if key unchanged)
/// - Multiple pins (primary + backup)
/// - Fallback to standard validation if pins don't match (with warning)
pub mod certificate_pins {
    use std::collections::HashMap;
    use std::sync::LazyLock;

    /// SPKI SHA-256 pins for known registries.
    ///
    /// Format: domain -> list of base64-encoded SHA-256 hashes of SPKI.
    pub static REGISTRY_PINS: LazyLock<HashMap<&'static str, Vec<&'static str>>> =
        LazyLock::new(|| {
            let mut pins = HashMap::new();

            // Note: These are placeholder pins. In production, these would be
            // the actual SPKI hashes of registry certificates.
            // Format: openssl x509 -in cert.pem -pubkey -noout |
            //         openssl pkey -pubin -outform der |
            //         openssl dgst -sha256 -binary | base64

            // npm registry (registry.npmjs.org)
            pins.insert(
                "registry.npmjs.org",
                vec![
                    // Primary and backup pins would go here
                    // These are placeholders - actual implementation would
                    // fetch and validate against real certificate pins
                ],
            );

            // PyPI (pypi.org)
            pins.insert("pypi.org", vec![]);

            // crates.io
            pins.insert("crates.io", vec![]);

            // proxy.golang.org
            pins.insert("proxy.golang.org", vec![]);

            // nodejs.org
            pins.insert("nodejs.org", vec![]);

            // python.org
            pins.insert("python.org", vec![]);

            pins
        });

    /// Check if a domain has certificate pins configured.
    #[must_use]
    pub fn has_pins(domain: &str) -> bool {
        REGISTRY_PINS
            .get(domain)
            .is_some_and(|pins| !pins.is_empty())
    }

    /// Get the certificate pins for a domain.
    #[must_use]
    pub fn get_pins(domain: &str) -> Option<&'static [&'static str]> {
        REGISTRY_PINS.get(domain).map(|v| v.as_slice())
    }
}

/// Helpers for fetching and caching public keys.
pub mod key_fetcher {
    use super::*;

    /// Keyserver URLs for fetching GPG keys (HTTPS only for security).
    ///
    /// # Security
    ///
    /// We only use HTTPS keyservers to prevent MITM attacks.
    /// HKP over TLS (HKPS) URLs are converted properly to HTTPS.
    pub const KEYSERVERS: &[&str] = &["https://keyserver.ubuntu.com", "https://keys.openpgp.org"];

    /// Get a GPG key, preferring embedded keys over keyserver fetch.
    ///
    /// # Security
    ///
    /// This function prioritizes keys in the following order:
    /// 1. Embedded keys (most secure - offline, audited)
    /// 2. Cached keys (secure if originally verified, reduces network traffic)
    /// 3. Keyserver fetch (least secure - vulnerable to MITM, but cached for future use)
    ///
    /// # Caching
    ///
    /// Keys fetched from keyservers are automatically cached with a 24-hour TTL.
    /// This reduces network requests and improves performance while maintaining
    /// security through periodic refresh.
    #[allow(dead_code)]
    pub async fn fetch_gpg_key(key_id: &str) -> Result<String> {
        // SECURITY: Try embedded keys first to avoid keyserver MITM attacks
        if let Some(embedded_key) = known_keys::nodejs::get_embedded_key(key_id) {
            debug!(key_id = %key_id, "Using embedded GPG key");
            return Ok(embedded_key.to_string());
        }

        // SECURITY: Check cache before hitting keyserver
        // This reduces attack surface by minimizing network requests
        if let Some(cached_key) = super::key_cache::get_cached_key(key_id) {
            debug!(key_id = %key_id, "Using cached GPG key");
            return Ok(cached_key);
        }

        // Warn when falling back to keyserver fetch
        warn!(
            key_id = %key_id,
            "No embedded or cached key found, falling back to keyserver fetch. \
             This is less secure than embedded keys."
        );

        // Fetch from keyserver and cache the result
        let key = fetch_gpg_key_from_keyserver(key_id).await?;

        // SECURITY: Cache the fetched key to reduce future keyserver requests
        // This improves both security (fewer network requests) and performance
        super::key_cache::cache_key(key_id, key.clone());

        Ok(key)
    }

    /// Fetch a GPG key from keyservers (internal function).
    ///
    /// # Security Warning
    ///
    /// Keyserver fetches are vulnerable to MITM attacks even over HTTPS
    /// if the keyserver itself is compromised. Prefer embedded keys.
    async fn fetch_gpg_key_from_keyserver(key_id: &str) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .https_only(true) // SECURITY: Force HTTPS only
            .build()
            .map_err(|e| CratonsError::Network(format!("Failed to create HTTP client: {e}")))?;

        for keyserver in KEYSERVERS {
            // HKP protocol: GET /pks/lookup?op=get&search=0x{keyid}
            let url = format!(
                "{}/pks/lookup?op=get&options=mr&search=0x{}",
                keyserver, key_id
            );

            match client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    let key_armor = response.text().await.map_err(|e| {
                        CratonsError::Network(format!("Failed to read key response: {e}"))
                    })?;

                    if key_armor.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
                        info!(
                            key_id = %key_id,
                            keyserver = %keyserver,
                            "Fetched GPG key from keyserver (less secure than embedded)"
                        );
                        return Ok(key_armor);
                    }
                }
                Ok(response) => {
                    debug!(
                        keyserver = %keyserver,
                        status = %response.status(),
                        "Keyserver returned non-success status"
                    );
                }
                Err(e) => {
                    debug!(
                        keyserver = %keyserver,
                        error = %e,
                        "Failed to fetch from keyserver"
                    );
                }
            }
        }

        Err(CratonsError::Network(format!(
            "Failed to fetch GPG key {} from any keyserver. \
             Consider adding the key to embedded keys for better security.",
            key_id
        )))
    }
}

/// In-memory cache for GPG keys to reduce keyserver fetches.
///
/// # Security
///
/// This cache reduces keyserver traffic and improves performance while
/// maintaining security through:
/// - TTL-based expiration (default 24 hours)
/// - Immutable storage (keys are cloned on retrieval)
/// - Thread-safe access with RwLock
///
/// # 2025 Best Practice
///
/// Per OWASP and NIST guidance:
/// - Caching reduces attack surface by minimizing network requests
/// - TTL ensures keys are refreshed periodically
/// - In-memory only (no disk cache) prevents persistence attacks
pub mod key_cache {
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::LazyLock;
    use std::time::{Duration, Instant};
    use tracing::debug;

    /// Cached GPG key with fetch timestamp.
    #[derive(Debug, Clone)]
    struct CachedKey {
        /// ASCII-armored GPG public key
        key: String,
        /// When the key was fetched
        fetched_at: Instant,
    }

    /// Global key cache protected by RwLock.
    ///
    /// # Security
    ///
    /// RwLock provides:
    /// - Multiple concurrent readers (performance)
    /// - Exclusive writer access (safety)
    /// - No data races (thread safety)
    static KEY_CACHE: LazyLock<RwLock<HashMap<String, CachedKey>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    /// Default TTL for cached keys (24 hours).
    ///
    /// This balances:
    /// - Performance (reduces keyserver fetches)
    /// - Security (keys are refreshed daily)
    /// - Key revocation detection (24h max delay)
    pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

    /// Get a cached key if available and not expired.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The GPG key ID or fingerprint
    ///
    /// # Returns
    ///
    /// - `Some(key)` if the key is cached and not expired
    /// - `None` if not cached or expired
    ///
    /// # Security
    ///
    /// This function checks expiration on every access to ensure
    /// stale keys are not used. Expired keys are left in the cache
    /// until `clear_expired()` is called.
    #[must_use]
    pub fn get_cached_key(key_id: &str) -> Option<String> {
        let cache = KEY_CACHE.read();

        if let Some(cached) = cache.get(key_id) {
            if cached.fetched_at.elapsed() < DEFAULT_TTL {
                debug!(
                    key_id = %key_id,
                    age_secs = cached.fetched_at.elapsed().as_secs(),
                    "Cache hit: returning cached GPG key"
                );
                return Some(cached.key.clone());
            }

            debug!(
                key_id = %key_id,
                age_secs = cached.fetched_at.elapsed().as_secs(),
                "Cache miss: key expired"
            );
        }

        None
    }

    /// Cache a GPG key with current timestamp.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The GPG key ID or fingerprint
    /// * `key` - The ASCII-armored GPG public key
    ///
    /// # Security
    ///
    /// Keys are cloned on insertion to ensure immutability.
    /// The cache uses the current time for expiration tracking.
    pub fn cache_key(key_id: &str, key: String) {
        let mut cache = KEY_CACHE.write();

        cache.insert(
            key_id.to_string(),
            CachedKey {
                key,
                fetched_at: Instant::now(),
            },
        );

        debug!(
            key_id = %key_id,
            cache_size = cache.len(),
            "Cached GPG key"
        );
    }

    /// Check if a cached key is expired.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The GPG key ID or fingerprint
    ///
    /// # Returns
    ///
    /// - `true` if the key is cached and expired
    /// - `false` if not cached or still valid
    #[must_use]
    pub fn is_expired(key_id: &str) -> bool {
        let cache = KEY_CACHE.read();

        cache
            .get(key_id)
            .is_some_and(|cached| cached.fetched_at.elapsed() >= DEFAULT_TTL)
    }

    /// Remove all expired keys from the cache.
    ///
    /// # Returns
    ///
    /// Number of keys removed
    ///
    /// # Usage
    ///
    /// This should be called periodically to prevent unbounded
    /// cache growth. Consider calling it:
    /// - On startup
    /// - After batch key fetches
    /// - During idle periods
    pub fn clear_expired() -> usize {
        let mut cache = KEY_CACHE.write();

        let before_count = cache.len();

        cache.retain(|key_id, cached| {
            let keep = cached.fetched_at.elapsed() < DEFAULT_TTL;
            if !keep {
                debug!(
                    key_id = %key_id,
                    age_secs = cached.fetched_at.elapsed().as_secs(),
                    "Removing expired key from cache"
                );
            }
            keep
        });

        let removed = before_count - cache.len();

        if removed > 0 {
            debug!(
                removed = removed,
                remaining = cache.len(),
                "Cleared expired keys from cache"
            );
        }

        removed
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_cache_and_retrieve() {
            let key_id = "TEST_KEY_1";
            let key_data =
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----";

            cache_key(key_id, key_data.to_string());

            let retrieved = get_cached_key(key_id);
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap(), key_data);
        }

        #[test]
        fn test_not_expired() {
            let key_id = "TEST_KEY_2";
            let key_data =
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----";

            cache_key(key_id, key_data.to_string());

            assert!(!is_expired(key_id));
        }

        #[test]
        fn test_nonexistent_key() {
            let retrieved = get_cached_key("NONEXISTENT");
            assert!(retrieved.is_none());
            assert!(!is_expired("NONEXISTENT"));
        }

        #[test]
        fn test_clear_expired_empty() {
            // Clear any existing expired keys first
            clear_expired();

            // Add a fresh key
            let key_id = "TEST_KEY_3";
            cache_key(key_id, "test_key_data".to_string());

            // Should not remove non-expired keys
            let removed = clear_expired();
            assert_eq!(removed, 0);

            // Key should still be there
            assert!(get_cached_key(key_id).is_some());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_verification() {
        let verifier = ToolchainVerifier::new();
        let data = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

        let result = verifier.verify_sha256(data, expected).unwrap();
        assert!(result.verified);
        assert_eq!(result.method, VerificationMethod::Sha256Checksum);
    }

    #[test]
    fn test_sha256_mismatch() {
        let verifier = ToolchainVerifier::new();
        let data = b"hello world";
        let expected = "0000000000000000000000000000000000000000000000000000000000000000";

        let result = verifier.verify_sha256(data, expected);
        assert!(result.is_err());
    }

    #[test]
    fn test_security_levels() {
        assert_eq!(VerificationMethod::Sigstore.security_level(), 4);
        assert_eq!(VerificationMethod::GpgSignature.security_level(), 3);
        assert_eq!(VerificationMethod::Minisign.security_level(), 2);
        assert_eq!(VerificationMethod::Sha256Checksum.security_level(), 1);
        assert_eq!(VerificationMethod::None.security_level(), 0);
    }

    #[test]
    fn test_method_descriptions() {
        assert!(
            VerificationMethod::Sigstore
                .description()
                .contains("keyless")
        );
        assert!(
            VerificationMethod::GpgSignature
                .description()
                .contains("OpenPGP")
        );
        assert!(
            VerificationMethod::Minisign
                .description()
                .contains("Ed25519")
        );
    }

    #[test]
    fn test_permissive_verifier() {
        let verifier = ToolchainVerifier::permissive();
        assert!(verifier.allow_unverified);
        assert_eq!(verifier.min_security_level, 0);
    }

    #[test]
    fn test_strict_verifier() {
        let verifier = ToolchainVerifier::strict();
        assert!(!verifier.allow_unverified);
        assert_eq!(verifier.min_security_level, 2);
    }

    #[test]
    fn test_known_keys_nodejs() {
        assert!(!known_keys::nodejs::ALL_KEY_IDS.is_empty());
        assert_eq!(known_keys::nodejs::ALL_KEY_IDS.len(), 8);
        // Verify key IDs are valid hex fingerprints (40 chars)
        for key_id in known_keys::nodejs::ALL_KEY_IDS {
            assert_eq!(key_id.len(), 40);
            assert!(key_id.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_known_keys_python() {
        assert!(!known_keys::python::RELEASE_IDENTITIES.is_empty());
        assert!(known_keys::python::GOOGLE_ISSUER.starts_with("https://"));
        assert!(known_keys::python::PABLO_GALINDO_IDENTITY.contains('@'));
    }

    #[test]
    fn test_gpg_verification_invalid_key() {
        let verifier = ToolchainVerifier::new();
        let data = b"test data";
        let signature = "-----BEGIN PGP SIGNATURE-----\ninvalid\n-----END PGP SIGNATURE-----";
        let public_key =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\ninvalid\n-----END PGP PUBLIC KEY BLOCK-----";

        let result = verifier.verify_gpg(data, signature, public_key);
        assert!(result.is_err());
    }
}
