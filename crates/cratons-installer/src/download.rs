//! Package downloading with parallel fetch and integrity verification.

use crate::download_diagnostics::DownloadDiagnostics;
use cratons_core::{ContentHash, CratonsError, Ecosystem, Result};
use cratons_lockfile::LockedPackage;
use cratons_store::Store;
use futures::stream::{self, StreamExt};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Hard upper bound for one package artifact download.
///
/// Most registry artifacts are far smaller. The cap prevents a malicious
/// registry, mirror, or proxy from forcing the installer to buffer unbounded
/// response bodies in memory before integrity verification can run.
const MAX_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Per-download result carrying the stored artifact path, byte count,
/// and any PGP trust-on-first-use pin that should be recorded into the
/// lockfile after the install completes.
///
/// The pin is `None` for:
/// - non-Maven packages,
/// - Maven packages with an explicit project/user keyring entry
///   (strict-verified, no new pin needed),
/// - Maven packages that matched an existing lockfile TOFU pin (no
///   change needed).
///
/// It is `Some((group_id, fingerprint))` for the first successful
/// install of a groupId under `FirstInstallPolicy::{Warn, Allow}`.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    /// Final on-disk path of the stored artifact (in the CAS).
    pub path: PathBuf,
    /// Blake3 CAS hash of the stored archive.
    pub content_hash: ContentHash,
    /// Number of bytes downloaded over the network.
    pub bytes_downloaded: u64,
    /// Optional TOFU pin: `(group_id, fingerprint)`.
    pub tofu_pin: Option<(String, String)>,
}

/// Downloads packages from registries with parallel fetch support.
pub struct PackageDownloader {
    client: reqwest::Client,
    concurrency: usize,
    /// Maven PGP trust configuration (F-2). Loaded from user/project
    /// config at installer construction time. See
    /// `cratons_security::MavenTrustConfig`.
    maven_trust: Arc<cratons_security::MavenTrustConfig>,
    /// Shared PGP key cache. Created lazily on first Maven install so
    /// non-Maven workspaces don't pay the keystore open cost.
    maven_keystore: Arc<tokio::sync::OnceCell<cratons_security::KeyStore>>,
    /// Snapshot of the lockfile's `[pgp-trust]` table at the start of
    /// the install (F-2c). Read-only; new pins flow back up via
    /// `DownloadResult.tofu_pin`.
    pgp_trust_snapshot: Arc<BTreeMap<String, String>>,
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
            pgp_trust_snapshot: Arc::new(BTreeMap::new()),
        }
    }

    /// Construct a per-install downloader handle with a fresh PGP
    /// trust snapshot cloned from the lockfile. Called by
    /// `Installer::install` at the start of every install. The returned
    /// handle shares the Arc'd HTTP client, maven_trust, and maven
    /// keystore with the parent downloader but carries its own
    /// `pgp_trust_snapshot`.
    pub(crate) fn with_lockfile_trust(&self, snapshot: Arc<BTreeMap<String, String>>) -> Self {
        Self {
            client: self.client.clone(),
            concurrency: self.concurrency,
            maven_trust: Arc::clone(&self.maven_trust),
            maven_keystore: Arc::clone(&self.maven_keystore),
            pgp_trust_snapshot: snapshot,
        }
    }

    /// Lazy-open the Maven PGP key cache. Returns a shared reference.
    async fn keystore(&self) -> Result<&cratons_security::KeyStore> {
        self.maven_keystore
            .get_or_try_init(|| async {
                cratons_security::KeyStore::open_with_keyservers(
                    self.client.clone(),
                    self.maven_trust.effective_keyservers(),
                )
            })
            .await
    }

    /// Fetch `{source}.asc` and verify the detached signature on the
    /// downloaded JAR bytes against key material resolved through the
    /// keyring + lockfile TOFU + keystore.
    ///
    /// Returns `Ok(Some((group_id, fingerprint)))` when verification
    /// succeeded under the first-install TOFU path and the caller should
    /// record a new lockfile pin. Returns `Ok(None)` when verification
    /// succeeded against an already-trusted fingerprint (either from
    /// the keyring or an existing lockfile pin).
    async fn verify_maven_pgp(
        &self,
        pkg: &LockedPackage,
        bytes: &[u8],
    ) -> Result<Option<(String, String)>> {
        // Parse groupId out of the Maven coordinate (format: `groupId:artifactId`).
        let group_id = pkg.name.split(':').next().ok_or_else(|| {
            CratonsError::Config(format!("Maven package name missing groupId: {}", pkg.name))
        })?;

        // Fetch the detached signature over the network from the same
        // Maven repository as the JAR. A 404 here is a hard failure: the
        // absence of an .asc for a Maven Central artifact is itself
        // suspicious, and we refuse to install without one.
        let asc_url = format!("{}.asc", pkg.source);
        let asc_response = self.client.get(&asc_url).send().await.map_err(|e| {
            CratonsError::Network(format!("Failed to fetch PGP signature {}: {}", asc_url, e))
        })?;
        if !asc_response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Maven PGP signature {} returned HTTP {}",
                asc_url,
                asc_response.status()
            )));
        }
        let asc_armor = asc_response
            .text()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read .asc body: {}", e)))?;

        // ------------------------------------------------------------
        // Trust ladder: project/user keyring → lockfile TOFU → policy
        // ------------------------------------------------------------

        // 1. Explicit project/user keyring entry — strict.
        let configured = self.maven_trust.trusted_fingerprints(group_id);
        if !configured.is_empty() {
            self.verify_against_fingerprints(pkg, bytes, &asc_armor, &configured)
                .await?;
            return Ok(None); // no new pin — already in config
        }

        // 2. Existing lockfile TOFU pin — strict against the pinned fingerprint.
        if let Some(pinned) = self.pgp_trust_snapshot.get(group_id) {
            let pinned_ref = pinned.as_str();
            self.verify_against_fingerprints(pkg, bytes, &asc_armor, &[pinned_ref])
                .await?;
            return Ok(None); // no new pin — already recorded in lockfile
        }

        // 3. First install. Dispatch on the first-install policy, with
        //    `CRATONS_CI=1` upgrading `Warn` to `Deny`.
        let policy = self.effective_first_install_policy();
        match policy {
            cratons_security::FirstInstallPolicy::Deny => Err(CratonsError::Config(format!(
                "Maven groupId '{}' has no configured trusted key and no TOFU pin, \
                 and first-install policy is Deny. Add an entry to \
                 `[security.maven].trusted-keys` in cratons.toml, or run \
                 interactively (without CRATONS_CI=1) to record a TOFU pin.",
                group_id
            ))),
            cratons_security::FirstInstallPolicy::Warn
            | cratons_security::FirstInstallPolicy::Allow => {
                let fp = self
                    .verify_and_extract_fingerprint(pkg, bytes, &asc_armor)
                    .await?;
                if matches!(policy, cratons_security::FirstInstallPolicy::Warn) {
                    warn!(
                        package = %pkg.name,
                        version = %pkg.version,
                        group_id = %group_id,
                        fingerprint = %fp,
                        tag = "pgp-tofu-pinned",
                        "first-install TOFU: recording Maven signing fingerprint in lockfile"
                    );
                } else {
                    debug!(
                        package = %pkg.name,
                        group_id = %group_id,
                        fingerprint = %fp,
                        "first-install TOFU (Allow): recording fingerprint silently"
                    );
                }
                Ok(Some((group_id.to_string(), fp)))
            }
        }
    }

    /// Verify the `.asc` against one or more candidate fingerprints,
    /// returning `Ok(())` on the first that verifies. Collects the
    /// last failure for error reporting.
    async fn verify_against_fingerprints(
        &self,
        pkg: &LockedPackage,
        bytes: &[u8],
        asc_armor: &str,
        fingerprints: &[&str],
    ) -> Result<()> {
        let keystore = self.keystore().await?;
        let mut last_error: Option<CratonsError> = None;
        for fp in fingerprints {
            match keystore.fetch_key(fp).await {
                Ok(key_armor) => {
                    let verifier = cratons_store::verify::ToolchainVerifier::new();
                    match verifier.verify_gpg(bytes, asc_armor, &key_armor) {
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
                "No trusted fingerprint verified Maven artifact {}",
                pkg.name
            ))
        }))
    }

    /// First-install path: extract the issuer fingerprint from the
    /// `.asc`, fetch the key via the keystore, verify the signature.
    /// Returns the verified fingerprint on success so the caller can
    /// record a TOFU pin.
    async fn verify_and_extract_fingerprint(
        &self,
        pkg: &LockedPackage,
        bytes: &[u8],
        asc_armor: &str,
    ) -> Result<String> {
        use pgp::composed::{Deserializable, DetachedSignature};

        let (detached, _headers) = DetachedSignature::from_string(asc_armor).map_err(|e| {
            CratonsError::Config(format!(
                "Failed to parse detached PGP signature for {}: {}",
                pkg.name, e
            ))
        })?;

        // Prefer the issuer fingerprint subpacket (RFC 4880bis, v4+).
        // Reject signatures that only carry a long key ID — 64 bits is
        // not collision-resistant enough for a TOFU pin.
        let fingerprints = detached.signature.issuer_fingerprint();
        let Some(fp) = fingerprints.first() else {
            return Err(CratonsError::Config(format!(
                "Maven PGP signature for {} lacks an issuer-fingerprint subpacket. \
                 Add a `[security.maven].trusted-keys` entry for this groupId to \
                 install strictly, or upgrade the publisher to a modern GPG.",
                pkg.name
            )));
        };
        let fp_hex = cratons_security::normalize_fingerprint(&hex::encode_upper(fp.as_bytes()))?;

        let keystore = self.keystore().await?;
        let key_armor = keystore.fetch_key(&fp_hex).await?;
        let verifier = cratons_store::verify::ToolchainVerifier::new();
        verifier.verify_gpg(bytes, asc_armor, &key_armor)?;
        info!(
            package = %pkg.name,
            version = %pkg.version,
            fingerprint = %fp_hex,
            "Maven PGP signature verified against keyserver-fetched key (TOFU path)"
        );
        Ok(fp_hex)
    }

    /// Compute the effective first-install policy, applying the
    /// `CRATONS_CI=1` environment override that promotes `Warn` to
    /// `Deny` for non-interactive automation.
    fn effective_first_install_policy(&self) -> cratons_security::FirstInstallPolicy {
        let base = self.maven_trust.first_install;
        if matches!(base, cratons_security::FirstInstallPolicy::Warn)
            && std::env::var("CRATONS_CI").ok().as_deref() == Some("1")
        {
            return cratons_security::FirstInstallPolicy::Deny;
        }
        base
    }

    /// Download a single package.
    ///
    /// # TOCTOU Protection
    ///
    /// This function uses atomic verify-and-store to prevent time-of-check to time-of-use
    /// vulnerabilities. The integrity verification and content-addressed storage both
    /// operate on the same in-memory bytes, eliminating any window where the content
    /// could be swapped by an attacker.
    pub async fn download(&self, pkg: &LockedPackage, store: &Store) -> Result<DownloadResult> {
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

        if let Some(content_length) = response.content_length() {
            if content_length > MAX_DOWNLOAD_BYTES {
                return Err(CratonsError::Network(format!(
                    "Refusing to download {}: Content-Length {} exceeds maximum {} bytes",
                    pkg.name, content_length, MAX_DOWNLOAD_BYTES
                )));
            }
        }

        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|e| CratonsError::Network(format!("Failed to read response: {}", e)))?;
            let next_len = bytes.len() as u64 + chunk.len() as u64;
            if next_len > MAX_DOWNLOAD_BYTES {
                return Err(CratonsError::Network(format!(
                    "Refusing to download {}: response exceeded maximum {} bytes",
                    pkg.name, MAX_DOWNLOAD_BYTES
                )));
            }
            bytes.extend_from_slice(&chunk);
        }

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

        // F-2 + F-2c: Maven packages run PGP verification at install
        // time. Trust ladder (first match wins, all paths strict):
        //
        // 1. `[security.maven].trusted-keys` in project/user config
        // 2. `[pgp-trust]` lockfile TOFU pin
        // 3. First-install policy — Deny aborts, Warn/Allow verify
        //    against the signature's embedded fingerprint and record
        //    a new TOFU pin for the caller to persist.
        //
        // Any failure along the trust ladder is a hard error, even
        // when `maven_trust_is_strict` returns false — there is no
        // "permissive fallback" path anymore. This is the F-2c
        // behavior change vs. F-2b.
        let mut tofu_pin = None;
        if pkg.ecosystem == Ecosystem::Maven {
            match self.verify_maven_pgp(pkg, &bytes).await {
                Ok(pin) => {
                    tofu_pin = pin;
                }
                Err(e) => {
                    warn!(
                        package = %pkg.name,
                        version = %pkg.version,
                        error = %e,
                        "Maven PGP verification failed"
                    );
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

        Ok(DownloadResult {
            path: stored_path,
            content_hash: hash,
            bytes_downloaded,
            tofu_pin,
        })
    }

    /// Download multiple packages in parallel.
    ///
    /// Each parallel download task receives a clone of the shared
    /// `maven_trust` and `pgp_trust_snapshot` so all tasks see the
    /// same TOFU baseline. New pins flow back via
    /// `DownloadResult.tofu_pin` and are aggregated by the caller.
    pub async fn download_all(
        &self,
        packages: &[&LockedPackage],
        store: &Store,
    ) -> Result<Vec<DownloadResult>> {
        let concurrency = self.concurrency.max(1);

        let downloads: Vec<_> = packages
            .iter()
            .map(|pkg| {
                let client = self.client.clone();
                let pkg = (*pkg).clone();
                let store_root = store.root().to_path_buf();
                let maven_trust = Arc::clone(&self.maven_trust);
                let pgp_snapshot = Arc::clone(&self.pgp_trust_snapshot);
                let keystore = Arc::clone(&self.maven_keystore);

                async move {
                    // Re-create downloader for this task, preserving the
                    // F-2c trust state.
                    let downloader = PackageDownloader {
                        client,
                        concurrency: 1,
                        maven_trust,
                        maven_keystore: keystore,
                        pgp_trust_snapshot: pgp_snapshot,
                    };

                    // Need to re-open store since it's not Send
                    let store = Store::open(&store_root).map_err(|e| {
                        CratonsError::Config(format!("Failed to open store: {}", e))
                    })?;

                    downloader.download(&pkg, &store).await
                }
            })
            .collect();

        let results: Vec<Result<DownloadResult>> = stream::iter(downloads)
            // `buffered` preserves input order while still executing up to
            // `concurrency` downloads at a time. The installer zips this Vec
            // back against the input package slice, so completion-order
            // collection would corrupt package/result association.
            .buffered(concurrency)
            .collect()
            .await;

        // Collect results, failing on first error
        let mut out = Vec::with_capacity(packages.len());
        for result in results {
            out.push(result?);
        }

        Ok(out)
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
    pub(crate) fn verify_download_integrity(
        &self,
        pkg: &LockedPackage,
        bytes: &[u8],
    ) -> Result<()> {
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
            if !cratons_core::constant_time_eq(actual_h1.as_bytes(), expected_hash.as_bytes()) {
                return Err(CratonsError::ChecksumMismatch {
                    package: pkg.name.clone(),
                    expected: expected_hash.to_string(),
                    actual: actual_h1,
                });
            }
            debug!("h1: integrity verified for {}@{}", pkg.name, pkg.version);
            return Ok(());
        }

        // Parse integrity format: "algorithm-base64hash".
        //
        // SECURITY: an unknown prefix MUST be a hard error. Silently accepting
        // an unrecognized algorithm allows an attacker who controls the
        // lockfile `integrity` field (e.g. via a mirror substitution or a
        // malicious PR) to bypass verification entirely by setting a bogus
        // prefix like `md5-...` or `crc32-...`. The caller has already
        // gated on `!pkg.integrity.is_empty()`, so reaching this branch
        // means a non-empty but unsupported value was supplied.
        let (expected_hash, algo) = if let Some(hash) = pkg.integrity.strip_prefix("sha1-") {
            (hash, HashAlgo::Sha1)
        } else if let Some(hash) = pkg.integrity.strip_prefix("sha256-") {
            (hash, HashAlgo::Sha256)
        } else if let Some(hash) = pkg.integrity.strip_prefix("sha512-") {
            (hash, HashAlgo::Sha512)
        } else {
            return Err(CratonsError::InvalidHash(format!(
                "unsupported integrity algorithm for {}@{}: {:?} (expected sha256-, sha512-, sha1-, or h1-)",
                pkg.name, pkg.version, pkg.integrity
            )));
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
            resolved_hash: Some(ContentHash::blake3("test".to_string())),
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
            resolved_hash: Some(ContentHash::blake3("test".to_string())),
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
                zw.start_file("example.com/mod@v0.1.0/go.mod", opts)
                    .unwrap();
                zw.write_all(b"module example.com/mod\n\ngo 1.22\n")
                    .unwrap();
                zw.finish().unwrap();
            }
            buf
        };

        // Compute the expected h1 ourselves and stuff it into a LockedPackage.
        let expected_h1 = cratons_resolver::registry::gosum::compute_h1(&zip_bytes).unwrap();
        let pkg = LockedPackage {
            name: "example.com/mod".to_string(),
            version: "v0.1.0".to_string(),
            ecosystem: Ecosystem::Go,
            source: "https://proxy.golang.org/example.com/mod/@v/v0.1.0.zip".to_string(),
            integrity: format!("h1-{}", expected_h1),
            resolved_hash: Some(ContentHash::blake3("test".to_string())),
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
                zw.start_file("example.com/mod@v0.1.0/go.mod", opts)
                    .unwrap();
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
            resolved_hash: Some(ContentHash::blake3("test".to_string())),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };

        let downloader = PackageDownloader::new(reqwest::Client::new(), 1);
        let result = downloader.verify_download_integrity(&pkg, &zip_bytes);
        assert!(matches!(result, Err(CratonsError::ChecksumMismatch { .. })));
    }
}
