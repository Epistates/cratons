//! Package downloading with parallel fetch and integrity verification.

use crate::download_diagnostics::DownloadDiagnostics;
use cratons_core::{CratonsError, Ecosystem, Result};
use cratons_lockfile::LockedPackage;
use cratons_store::Store;
use futures::stream::{self, StreamExt};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, info};

/// Downloads packages from registries with parallel fetch support.
pub struct PackageDownloader {
    client: reqwest::Client,
    concurrency: usize,
}

impl PackageDownloader {
    /// Create a new downloader.
    pub fn new(client: reqwest::Client, concurrency: usize) -> Self {
        Self {
            client,
            concurrency,
        }
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

        // Compare (constant-time comparison would be better but not critical here
        // since we're comparing computed vs expected, not secrets)
        if actual_hash != expected_hash {
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
}
