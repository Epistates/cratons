//! Package downloading with parallel fetch and integrity verification.

use crate::download_diagnostics::DownloadDiagnostics;
use cratons_core::{CratonsError, Ecosystem, Result};
use cratons_lockfile::LockedPackage;
use cratons_store::Store;
use futures::stream::{self, StreamExt};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Downloads packages from registries with parallel fetch support.
pub struct PackageDownloader {
    client: reqwest::Client,
    concurrency: usize,
    /// Maven PGP trust configuration (F-2). Loaded from user config at
    /// installer construction time. See `cratons_security::MavenTrustConfig`.
    maven_trust: Arc<cratons_security::MavenTrustConfig>,
    /// Shared PGP key cache. Created lazily on first Maven install so
    /// non-Maven workspaces don't pay the keystore open cost.
    maven_keystore: Arc<tokio::sync::OnceCell<cratons_security::KeyStore>>,
}

impl PackageDownloader {
    /// Create a new downloader with no Maven trust configuration. All
    /// Maven packages will need to resolve through the empty trust store
    /// and fail under a strict integrity policy. For Maven support, use
    /// [`PackageDownloader::with_maven_trust`].
    pub fn new(client: reqwest::Client, concurrency: usize) -> Self {
        Self::with_maven_trust(
            client,
            concurrency,
            Arc::new(cratons_security::MavenTrustConfig::default()),
        )
    }

    /// Create a new downloader with explicit Maven PGP trust config.
    /// Typically called from `Installer::with_config` with the config
    /// lifted from `InstallerConfig::maven_trust`.
    pub fn with_maven_trust(
        client: reqwest::Client,
        concurrency: usize,
        maven_trust: Arc<cratons_security::MavenTrustConfig>,
    ) -> Self {
        Self {
            client,
            concurrency,
            maven_trust,
            maven_keystore: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Lazy-open the Maven PGP key cache. Returns a shared reference.
    async fn keystore(&self) -> Result<&cratons_security::KeyStore> {
        self.maven_keystore
            .get_or_try_init(|| async {
                cratons_security::KeyStore::open_default(self.client.clone())
            })
            .await
    }

    /// Is this Maven package's trust configuration strict? A package is
    /// strict if its groupId matches any `[security.maven].trusted-keys`
    /// entry — in that case, verification failure aborts. If the groupId
    /// has no entry, we treat it as allowlisted (the default policy) and
    /// let the integrity policy layer decide.
    fn maven_trust_is_strict(&self, pkg: &LockedPackage) -> bool {
        let Some(group_id) = pkg.name.split(':').next() else {
            return false;
        };
        !self.maven_trust.trusted_fingerprints(group_id).is_empty()
    }

    /// Fetch `{source}.asc` and verify the detached signature on the
    /// downloaded JAR bytes against key material resolved through the
    /// keyring + keystore.
    async fn verify_maven_pgp(&self, pkg: &LockedPackage, bytes: &[u8]) -> Result<()> {
        // Parse groupId out of the Maven coordinate (format: `groupId:artifactId`).
        let group_id = pkg.name.split(':').next().ok_or_else(|| {
            CratonsError::Config(format!(
                "Maven package name missing groupId: {}",
                pkg.name
            ))
        })?;

        // Fetch the detached signature over the network from the same
        // Maven repository as the JAR. A 404 here is a hard failure: the
        // absence of an .asc for a Maven Central artifact is itself
        // suspicious, and we refuse to install without one.
        let asc_url = format!("{}.asc", pkg.source);
        let asc_response = self.client.get(&asc_url).send().await.map_err(|e| {
            CratonsError::Network(format!(
                "Failed to fetch PGP signature {}: {}",
                asc_url, e
            ))
        })?;
        if !asc_response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Maven PGP signature {} returned HTTP {}",
                asc_url,
                asc_response.status()
            )));
        }
        let asc_armor = asc_response.text().await.map_err(|e| {
            CratonsError::Network(format!("Failed to read .asc body: {}", e))
        })?;

        // Determine the set of trusted fingerprints for this groupId.
        // Under F-2b, TOFU is not yet implemented — if there's no entry,
        // we fall through to "verify against any key the keystore can
        // resolve from the .asc signer packet", which is weaker but
        // matches the integrity-allowlist posture for Maven until F-2c.
        let trusted = self.maven_trust.trusted_fingerprints(group_id);

        if trusted.is_empty() {
            // Permissive path: we don't have a configured fingerprint,
            // so we accept any signature whose signing key the keystore
            // can locate from its embedded key ID. This still proves the
            // artifact hasn't been modified since signing, which is the
            // transport-integrity guarantee we're after here.
            debug!(
                group_id = %group_id,
                "no explicit Maven trust entry; accepting any signature the keystore can verify"
            );
            // Extract the signer's key ID from the signature packet. Then
            // probe the keystore — it will first check the cache, then
            // HKP. Since we can't know the fingerprint without the key,
            // we rely on the `.asc` itself to carry the long key ID and
            // let the keystore's fingerprint-match check catch any
            // substitution attempts.
            return self.verify_with_embedded_key_id(pkg, bytes, &asc_armor).await;
        }

        // Strict path: try each configured trusted fingerprint in order
        // until one verifies.
        let keystore = self.keystore().await?;
        let mut last_error: Option<CratonsError> = None;
        for fp in &trusted {
            match keystore.fetch_key(fp).await {
                Ok(key_armor) => {
                    let verifier = cratons_store::verify::ToolchainVerifier::new();
                    match verifier.verify_gpg(bytes, &asc_armor, &key_armor) {
                        Ok(_) => {
                            info!(
                                package = %pkg.name,
                                version = %pkg.version,
                                fingerprint = %fp,
                                "Maven PGP signature verified against trusted key"
                            );
                            return Ok(());
                        }
                        Err(e) => {
                            debug!(fingerprint = %fp, error = %e, "PGP verification failed for this key");
                            last_error = Some(e);
                        }
                    }
                }
                Err(e) => {
                    debug!(fingerprint = %fp, error = %e, "Keystore fetch failed");
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CratonsError::Config(format!(
                "No trusted fingerprint verified Maven artifact {} for groupId {}",
                pkg.name, group_id
            ))
        }))
    }

    /// Fallback for Maven packages with no configured trusted fingerprint.
    /// Parses the `.asc` to extract the issuer fingerprint (modern
    /// OpenPGP signatures) or long key ID (legacy), fetches that key
    /// via the keystore's HKP path, and verifies.
    ///
    /// **Trust caveat**: with no configured fingerprint for the groupId,
    /// this path only proves "the downloaded bytes are consistent with
    /// what SOME key signed". It does not prove identity. A compromised
    /// Maven Central registry could substitute both the JAR and its
    /// `.asc` signed by an attacker-controlled key, and this path would
    /// accept it. The hardcoded‑keyserver fetch *does* prevent one
    /// specific attack (a rogue keyserver substituting the wrong key
    /// for a known fingerprint), so this is still strictly better than
    /// the pre-F-2 same-origin SHA-1 attestation.
    ///
    /// True authenticity requires a configured `[security.maven]`
    /// trusted-keys entry (F-2c will add manifest-level config and
    /// lockfile TOFU to ease the operator burden).
    async fn verify_with_embedded_key_id(
        &self,
        pkg: &LockedPackage,
        bytes: &[u8],
        asc_armor: &str,
    ) -> Result<()> {
        use pgp::composed::{Deserializable, DetachedSignature};

        let (detached, _headers) = DetachedSignature::from_string(asc_armor)
            .map_err(|e| {
                CratonsError::Config(format!(
                    "Failed to parse detached PGP signature for {}: {}",
                    pkg.name, e
                ))
            })?;

        // Prefer the issuer fingerprint subpacket (RFC 4880bis, v4+).
        // Fall back to the issuer key ID (8-byte long ID) for older
        // signatures — that path warns because long IDs are not
        // collision-resistant enough for strict authenticity.
        let fingerprints = detached.signature.issuer_fingerprint();
        let fp_hex = if let Some(fp) = fingerprints.first() {
            cratons_security::normalize_fingerprint(&hex::encode_upper(fp.as_bytes()))?
        } else {
            let key_ids = detached.signature.issuer();
            let Some(_kid) = key_ids.first() else {
                return Err(CratonsError::Config(format!(
                    "Detached PGP signature for {} has no issuer fingerprint or key ID",
                    pkg.name
                )));
            };
            warn!(
                package = %pkg.name,
                "PGP signature exposes only a 64-bit key ID; fingerprint lookup unavailable. \
                 Configure `[security.maven].trusted-keys` in cratons.toml for strict auth."
            );
            return Err(CratonsError::Config(format!(
                "Maven PGP verification for {}: signature lacks issuer fingerprint subpacket. \
                 Add an explicit trusted-keys entry for groupId to enable strict verification.",
                pkg.name
            )));
        };

        let keystore = self.keystore().await?;
        let key_armor = keystore.fetch_key(&fp_hex).await?;
        let verifier = cratons_store::verify::ToolchainVerifier::new();
        verifier.verify_gpg(bytes, asc_armor, &key_armor)?;
        info!(
            package = %pkg.name,
            version = %pkg.version,
            fingerprint = %fp_hex,
            "Maven PGP signature verified against keyserver-fetched key (no pinned trust)"
        );
        Ok(())
    }

    /// Download a single package.
    ///
    /// # TOCTOU Protection
    ///
    /// This function uses atomic verify-and-store to prevent time-of-check to time-of-use
    /// vulnerabilities. The integrity verification and content-addressed storage both
    /// operate on the same in-memory bytes, eliminating any window where the content
    /// could be swapped by an attacker.
    pub async fn download(&self, pkg: &LockedPackage, store: &Store) -> Result<(PathBuf, u64)> {
        debug!(
            "Downloading {}@{} from {}",
            pkg.name, pkg.version, pkg.source
        );

        // Download the file into memory
        let response = self.client.get(&pkg.source).send().await.map_err(|e| {
            CratonsError::Network(format!("Failed to download {}: {}", pkg.name, e))
        })?;

        let mut diag = DownloadDiagnostics::new(pkg.source.clone(), &response);

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Failed to download {}: HTTP {}",
                pkg.name,
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read response: {}", e)))?;

        let bytes_downloaded = bytes.len() as u64;
        diag.actual_bytes = bytes_downloaded;

        // Validate content (checks for truncation, empty bodies, etc.)
        if let Err(e) = diag.validate_content(&bytes) {
            tracing::error!("Download diagnostics: {:#?}", diag);
            return Err(e);
        }

        // TOCTOU Protection: Verify integrity on in-memory bytes BEFORE storing
        // This ensures the verified content is exactly what gets stored
        if !pkg.integrity.is_empty() {
            self.verify_download_integrity(pkg, &bytes)?;
        }

        // F-2: Maven packages always run PGP verification at install time,
        // independently of the `integrity` string (which is empty for
        // Maven under the current policy — the resolver stopped fetching
        // the same-origin SHA-1 in F-2b). This fetches `{source}.asc`
        // over the network, resolves the signing key from the keyring
        // (or keyserver-on-first-use), and verifies the detached
        // signature against the downloaded JAR bytes. Under
        // `IntegrityPolicy::Required`, failure aborts the install. Under
        // the default allowlist policy, Maven is still allowlisted so
        // a failure here is only logged as `integrity-degraded` — until
        // Phase F-final flips the default.
        if pkg.ecosystem == Ecosystem::Maven {
            if let Err(e) = self.verify_maven_pgp(pkg, &bytes).await {
                warn!(
                    package = %pkg.name,
                    version = %pkg.version,
                    error = %e,
                    "Maven PGP verification failed; integrity policy will decide whether to abort"
                );
                // The policy layer (InstallerConfig::integrity_policy)
                // gets the final say upstream; here we only fail the
                // download when the package was on the critical path
                // and the caller asked for strict verification via the
                // trust config.
                if self.maven_trust_is_strict(pkg) {
                    return Err(e);
                }
            }
        }

        // Store verified bytes directly in CAS (atomic write via temp file + rename)
        // This eliminates the TOCTOU window - we store the same bytes we verified
        let hash = store.cas().store(&bytes)?;
        let stored_path = store
            .cas()
            .get(&hash)
            .ok_or_else(|| CratonsError::PackageNotFound(pkg.name.clone()))?;

        info!(
            "Downloaded {}@{} ({} bytes)",
            pkg.name, pkg.version, bytes_downloaded
        );

        Ok((stored_path, bytes_downloaded))
    }

    /// Download multiple packages in parallel.
    pub async fn download_all(
        &self,
        packages: &[&LockedPackage],
        store: &Store,
    ) -> Result<Vec<(PathBuf, u64)>> {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));

        let downloads: Vec<_> = packages
            .iter()
            .map(|pkg| {
                let semaphore = Arc::clone(&semaphore);
                let client = self.client.clone();
                let pkg = (*pkg).clone();
                let store_root = store.root().to_path_buf();

                async move {
                    let _permit = semaphore.acquire().await.map_err(|_| {
                        CratonsError::Config("Download semaphore closed unexpectedly".into())
                    })?;

                    // Re-create downloader for this task
                    let downloader = PackageDownloader::new(client, 1);

                    // Need to re-open store since it's not Send
                    let store = Store::open(&store_root).map_err(|e| {
                        CratonsError::Config(format!("Failed to open store: {}", e))
                    })?;

                    downloader.download(&pkg, &store).await
                }
            })
            .collect();

        let results: Vec<Result<(PathBuf, u64)>> = stream::iter(downloads)
            .buffer_unordered(self.concurrency)
            .collect()
            .await;

        // Collect results, failing on first error
        let mut paths = Vec::with_capacity(packages.len());
        for result in results {
            paths.push(result?);
        }

        Ok(paths)
    }

    /// Get appropriate filename for a package download.
    ///
    /// Note: Currently only used in tests but kept for future extensibility.
    #[allow(dead_code)]
    fn get_filename(&self, pkg: &LockedPackage) -> String {
        match pkg.ecosystem {
            Ecosystem::Npm => format!("{}-{}.tgz", pkg.name.replace('/', "-"), pkg.version),
            Ecosystem::PyPi => {
                // PyPI URLs often end with .whl or .tar.gz
                if pkg.source.ends_with(".whl") {
                    format!("{}-{}.whl", pkg.name, pkg.version)
                } else {
                    format!("{}-{}.tar.gz", pkg.name, pkg.version)
                }
            }
            Ecosystem::Crates => format!("{}-{}.crate", pkg.name, pkg.version),
            Ecosystem::Go => format!("{}@{}.zip", pkg.name.replace('/', "-"), pkg.version),
            Ecosystem::Maven => {
                // Maven coordinates: groupId:artifactId -> artifactId-version.jar
                let artifact = pkg.name.split(':').last().unwrap_or(&pkg.name);
                format!("{}-{}.jar", artifact, pkg.version)
            }
            Ecosystem::Url => {
                // Try to extract filename from URL, or use a hash-based name
                pkg.source
                    .rsplit('/')
                    .next()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("url-{}-{}", pkg.name, pkg.version))
            }
        }
    }

    /// Verify the downloaded content integrity.
    ///
    /// Supports SHA1, SHA256, and SHA512 in base64 format.
    /// All integrity hashes should be normalized to base64 at registry fetch time.
    fn verify_download_integrity(&self, pkg: &LockedPackage, bytes: &[u8]) -> Result<()> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use sha1::Sha1;
        use sha2::{Digest, Sha256, Sha512};

        /// Hash algorithm detected from integrity string
        enum HashAlgo {
            Sha1,
            Sha256,
            Sha512,
        }

        // F-1: Go modules use the `h1-` prefix carrying the base64 of
        // `golang.org/x/mod/sumdb/dirhash` over the module zip. This was
        // already verified against `sum.golang.org`'s signed note at
        // resolution time (see `cratons_resolver::registry::gosum`);
        // here we recompute the dirhash locally from the downloaded
        // bytes and compare, so install-time verification remains
        // offline-capable and cross-checks the downloaded zip against
        // the signed hash.
        if let Some(expected_hash) = pkg.integrity.strip_prefix("h1-") {
            let actual_h1 = cratons_resolver::registry::gosum::compute_h1(bytes)?;
            if !cratons_core::constant_time_eq(actual_h1.as_bytes(), expected_hash.as_bytes())
            {
                return Err(CratonsError::ChecksumMismatch {
                    package: pkg.name.clone(),
                    expected: expected_hash.to_string(),
                    actual: actual_h1,
                });
            }
            debug!("h1: integrity verified for {}@{}", pkg.name, pkg.version);
            return Ok(());
        }

        // Parse integrity format: "algorithm-base64hash"
        let (expected_hash, algo) = if let Some(hash) = pkg.integrity.strip_prefix("sha1-") {
            (hash, HashAlgo::Sha1)
        } else if let Some(hash) = pkg.integrity.strip_prefix("sha256-") {
            (hash, HashAlgo::Sha256)
        } else if let Some(hash) = pkg.integrity.strip_prefix("sha512-") {
            (hash, HashAlgo::Sha512)
        } else {
            // Unknown format, skip verification with warning
            debug!(
                "Unknown integrity format for {} ({}), skipping verification",
                pkg.name, pkg.integrity
            );
            return Ok(());
        };

        // Compute actual hash based on algorithm
        let actual_hash = match algo {
            HashAlgo::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(bytes);
                STANDARD.encode(hasher.finalize())
            }
            HashAlgo::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                STANDARD.encode(hasher.finalize())
            }
            HashAlgo::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(bytes);
                STANDARD.encode(hasher.finalize())
            }
        };

        // Constant-time compare. While the expected hash is not secret, using
        // the same primitive as every other hash comparison in the workspace
        // keeps the audit story consistent and avoids "just one variable-time
        // compare" regressions slipping in later.
        if !cratons_core::constant_time_eq(actual_hash.as_bytes(), expected_hash.as_bytes()) {
            return Err(CratonsError::ChecksumMismatch {
                package: pkg.name.clone(),
                expected: expected_hash.to_string(),
                actual: actual_hash,
            });
        }

        debug!("Integrity verified for {}@{}", pkg.name, pkg.version);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratons_core::ContentHash;

    #[test]
    fn test_get_filename() {
        let downloader = PackageDownloader::new(reqwest::Client::new(), 4);

        let npm_pkg = LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string(),
            integrity: String::new(),
            resolved_hash: ContentHash::blake3("test".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };

        assert_eq!(downloader.get_filename(&npm_pkg), "lodash-4.17.21.tgz");

        let scoped_pkg = LockedPackage {
            name: "@types/node".to_string(),
            version: "20.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz".to_string(),
            integrity: String::new(),
            resolved_hash: ContentHash::blake3("test".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };

        assert_eq!(
            downloader.get_filename(&scoped_pkg),
            "@types-node-20.0.0.tgz"
        );
    }

    #[test]
    fn h1_integrity_verify_round_trip() {
        use std::io::{Cursor, Write};

        // Build a trivial valid Go module zip in memory.
        let zip_bytes = {
            let mut buf = Vec::new();
            {
                let cursor = Cursor::new(&mut buf);
                let mut zw = zip::ZipWriter::new(cursor);
                let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored);
                zw.start_file("example.com/mod@v0.1.0/go.mod", opts).unwrap();
                zw.write_all(b"module example.com/mod\n\ngo 1.22\n").unwrap();
                zw.finish().unwrap();
            }
            buf
        };

        // Compute the expected h1 ourselves and stuff it into a LockedPackage.
        let expected_h1 =
            cratons_resolver::registry::gosum::compute_h1(&zip_bytes).unwrap();
        let pkg = LockedPackage {
            name: "example.com/mod".to_string(),
            version: "v0.1.0".to_string(),
            ecosystem: Ecosystem::Go,
            source: "https://proxy.golang.org/example.com/mod/@v/v0.1.0.zip".to_string(),
            integrity: format!("h1-{}", expected_h1),
            resolved_hash: ContentHash::blake3("test".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };

        let downloader = PackageDownloader::new(reqwest::Client::new(), 1);
        downloader
            .verify_download_integrity(&pkg, &zip_bytes)
            .expect("round-trip h1 verification must succeed");
    }

    #[test]
    fn h1_integrity_verify_detects_tampering() {
        use std::io::{Cursor, Write};

        let zip_bytes = {
            let mut buf = Vec::new();
            {
                let cursor = Cursor::new(&mut buf);
                let mut zw = zip::ZipWriter::new(cursor);
                let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored);
                zw.start_file("example.com/mod@v0.1.0/go.mod", opts).unwrap();
                zw.write_all(b"module example.com/mod\n").unwrap();
                zw.finish().unwrap();
            }
            buf
        };

        // Use a deliberately wrong expected hash.
        let pkg = LockedPackage {
            name: "example.com/mod".to_string(),
            version: "v0.1.0".to_string(),
            ecosystem: Ecosystem::Go,
            source: "https://proxy.golang.org/example.com/mod/@v/v0.1.0.zip".to_string(),
            integrity: "h1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            resolved_hash: ContentHash::blake3("test".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };

        let downloader = PackageDownloader::new(reqwest::Client::new(), 1);
        let result = downloader.verify_download_integrity(&pkg, &zip_bytes);
        assert!(matches!(
            result,
            Err(CratonsError::ChecksumMismatch { .. })
        ));
    }
}
