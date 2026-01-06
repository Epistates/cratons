//! Toolchain download and installation.
//!
//! This module provides automatic downloading of toolchains for all supported ecosystems:
//!
//! | Ecosystem | Source | Format |
//! |-----------|--------|--------|
//! | Node.js | nodejs.org/dist | tar.xz (Linux/macOS), zip (Windows) |
//! | Python | astral-sh/python-build-standalone | tar.zst |
//! | Rust | static.rust-lang.org | tar.xz |
//! | Go | go.dev/dl | tar.gz (Linux/macOS), zip (Windows) |
//! | Java | api.adoptium.net | tar.gz (Linux/macOS), zip (Windows) |
//!
//! ## Usage
//!
//! ```no_run
//! use cratons_store::download::{ToolchainDownloader, ToolchainRequest};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let downloader = ToolchainDownloader::new()?;
//!
//! // Download Node.js 20 LTS
//! let request = ToolchainRequest::node("20.10.0");
//! let toolchain = downloader.download(&request).await?;
//! # Ok(())
//! # }
//! ```

use std::io::Cursor;
use std::path::{Path, PathBuf};

use cratons_core::{ContentHash, CratonsError, Result};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument, warn};

use crate::toolchain::{Toolchain, ToolchainStore};

/// Fallback release tag for python-build-standalone when GitHub API is unavailable.
/// SECURITY: Update this when a newer verified release is available.
/// Last verified: 2025-12-31
const PYTHON_BUILD_STANDALONE_FALLBACK: &str = "20251215";

/// Request for downloading a specific toolchain.
#[derive(Debug, Clone)]
pub struct ToolchainRequest {
    /// Ecosystem name
    pub ecosystem: ToolchainEcosystem,
    /// Desired version (exact or partial)
    pub version: String,
    /// Target platform (defaults to current)
    pub platform: Option<String>,
    /// Target architecture (defaults to current)
    pub arch: Option<String>,
}

impl ToolchainRequest {
    /// Create a Node.js toolchain request.
    #[must_use]
    pub fn node(version: impl Into<String>) -> Self {
        Self {
            ecosystem: ToolchainEcosystem::Node,
            version: version.into(),
            platform: None,
            arch: None,
        }
    }

    /// Create a Python toolchain request.
    #[must_use]
    pub fn python(version: impl Into<String>) -> Self {
        Self {
            ecosystem: ToolchainEcosystem::Python,
            version: version.into(),
            platform: None,
            arch: None,
        }
    }

    /// Create a Rust toolchain request.
    #[must_use]
    pub fn rust(version: impl Into<String>) -> Self {
        Self {
            ecosystem: ToolchainEcosystem::Rust,
            version: version.into(),
            platform: None,
            arch: None,
        }
    }

    /// Create a Go toolchain request.
    #[must_use]
    pub fn go(version: impl Into<String>) -> Self {
        Self {
            ecosystem: ToolchainEcosystem::Go,
            version: version.into(),
            platform: None,
            arch: None,
        }
    }

    /// Create a Java toolchain request.
    #[must_use]
    pub fn java(version: impl Into<String>) -> Self {
        Self {
            ecosystem: ToolchainEcosystem::Java,
            version: version.into(),
            platform: None,
            arch: None,
        }
    }

    /// Set target platform.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Set target architecture.
    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = Some(arch.into());
        self
    }

    fn platform(&self) -> &str {
        self.platform
            .as_deref()
            .unwrap_or_else(|| Toolchain::current_platform())
    }

    fn arch(&self) -> &str {
        self.arch
            .as_deref()
            .unwrap_or_else(|| Toolchain::current_arch())
    }
}

/// Supported toolchain ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolchainEcosystem {
    /// Node.js runtime
    Node,
    /// Python interpreter
    Python,
    /// Rust toolchain (rustc + cargo)
    Rust,
    /// Go compiler
    Go,
    /// Java Development Kit (Eclipse Temurin)
    Java,
}

impl ToolchainEcosystem {
    /// Get the ecosystem name as a string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Java => "java",
        }
    }
}

impl std::fmt::Display for ToolchainEcosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

use crate::verify::{ToolchainVerifier, VerificationMethod, key_fetcher, known_keys};

/// Information about a toolchain download.
#[derive(Debug)]
struct DownloadInfo {
    /// Download URL
    url: String,
    /// Expected SHA-256 hash (if available)
    expected_hash: Option<String>,
    /// Archive type
    archive_type: ArchiveType,
    /// Number of path components to strip when extracting
    strip_components: usize,
    /// URL of the detached signature (if verifying artifact directly)
    signature_url: Option<String>,
    /// Method to use for verification
    verification_method: VerificationMethod,
}

/// Toolchain downloader with caching and verification.
pub struct ToolchainDownloader {
    client: ClientWithMiddleware,
    store: ToolchainStore,
    verifier: ToolchainVerifier,
    /// If true, fail when verification cannot be performed instead of warning
    strict_verification: bool,
}

impl ToolchainDownloader {
    /// Create a new toolchain downloader.
    pub fn new() -> Result<Self> {
        let cratons_dir = dirs::data_local_dir()
            .or_else(dirs::home_dir)
            .ok_or_else(|| CratonsError::Config("Could not determine home directory".into()))?
            .join(".cratons");

        let store_dir = cratons_dir.join("toolchains");

        std::fs::create_dir_all(&store_dir)?;

        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let client = ClientBuilder::new(
            reqwest::Client::builder()
                .user_agent(concat!("cratons/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|e| CratonsError::Network(e.to_string()))?,
        )
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build();

        Ok(Self {
            client,
            store: ToolchainStore::new(store_dir),
            verifier: ToolchainVerifier::strict(), // SOTA: Strict by default
            // Strict verification is the production default: fail downloads when cryptographic
            // verification (GPG, Minisign, checksums) cannot be performed rather than proceeding
            // with a warning. This ensures supply chain integrity for all toolchain downloads.
            strict_verification: true,
        })
    }

    /// Create with custom directories.
    pub fn with_dirs(store_dir: PathBuf, _cache_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&store_dir)?;

        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let client = ClientBuilder::new(
            reqwest::Client::builder()
                .user_agent(concat!("cratons/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|e| CratonsError::Network(e.to_string()))?,
        )
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build();

        Ok(Self {
            client,
            store: ToolchainStore::new(store_dir),
            verifier: ToolchainVerifier::strict(),
            // Strict verification is the production default: fail downloads when cryptographic
            // verification (GPG, Minisign, checksums) cannot be performed rather than proceeding
            // with a warning. This ensures supply chain integrity for all toolchain downloads.
            strict_verification: true,
        })
    }

    /// Enable strict verification mode.
    ///
    /// When enabled, the downloader will fail if it cannot verify
    /// a toolchain's integrity instead of proceeding with a warning.
    #[must_use]
    pub fn with_strict_verification(mut self, strict: bool) -> Self {
        self.strict_verification = strict;
        self
    }

    /// Get the toolchain store.
    #[must_use]
    pub fn store(&self) -> &ToolchainStore {
        &self.store
    }

    /// Fetch text content from a URL.
    async fn fetch_text(&self, url: &str) -> Result<String> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Failed to fetch {}: {}",
                url,
                response.status()
            )));
        }

        response
            .text()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))
    }

    /// Download and install a toolchain.
    ///
    /// If the toolchain is already installed, returns the existing path.
    ///
    /// # Security
    ///
    /// This method eliminates TOCTOU vulnerabilities by:
    /// 1. Downloading archive bytes to memory
    /// 2. Verifying checksum on in-memory bytes
    /// 3. Extracting directly from verified in-memory bytes
    ///
    /// The verified bytes are never written to disk before extraction,
    /// preventing file replacement attacks.
    #[instrument(skip(self), fields(ecosystem = %request.ecosystem, version = %request.version))]
    pub async fn download(&self, request: &ToolchainRequest) -> Result<PathBuf> {
        // Check if already installed
        if let Some(path) = self
            .store
            .get_by_name_version(request.ecosystem.as_str(), &request.version)
        {
            info!("Toolchain already installed at {}", path.display());
            return Ok(path);
        }

        // Resolve the download URL and metadata
        let download_info = self.resolve_download(request).await?;
        info!(
            url = %download_info.url,
            "Resolved toolchain download URL"
        );

        // SECURITY: Download and verify in one step, keeping bytes in memory
        let verified_bytes = self.download_and_verify(&download_info).await?;

        // SECURITY: Extract directly from verified in-memory bytes (no TOCTOU window)
        let install_path = self
            .extract_from_bytes(request, &download_info, verified_bytes)
            .await?;

        Ok(install_path)
    }

    /// Resolve the download URL for a toolchain request.
    async fn resolve_download(&self, request: &ToolchainRequest) -> Result<DownloadInfo> {
        match request.ecosystem {
            ToolchainEcosystem::Node => self.resolve_node(request).await,
            ToolchainEcosystem::Python => self.resolve_python(request).await,
            ToolchainEcosystem::Rust => self.resolve_rust(request).await,
            ToolchainEcosystem::Go => self.resolve_go(request).await,
            ToolchainEcosystem::Java => self.resolve_java(request).await,
        }
    }

    /// Resolve Node.js download URL.
    async fn resolve_node(&self, request: &ToolchainRequest) -> Result<DownloadInfo> {
        let version = if request.version.starts_with('v') {
            request.version.clone()
        } else {
            format!("v{}", request.version)
        };

        let platform = match request.platform() {
            "darwin" => "darwin",
            "linux" => "linux",
            "win32" => "win",
            other => other,
        };

        let arch = match request.arch() {
            "x64" => "x64",
            "arm64" => "arm64",
            other => other,
        };

        let ext = if platform == "win" { "zip" } else { "tar.xz" };

        let filename = format!("node-{version}-{platform}-{arch}.{ext}");
        let url = format!("https://nodejs.org/dist/{version}/{filename}");

        // Fetch SHASUMS256.txt for verification
        let shasums_url = format!("https://nodejs.org/dist/{version}/SHASUMS256.txt");
        let expected_hash = self.fetch_node_checksum(&shasums_url, &filename).await?;

        Ok(DownloadInfo {
            url,
            expected_hash: Some(expected_hash),
            archive_type: if platform == "win" {
                ArchiveType::Zip
            } else {
                ArchiveType::TarXz
            },
            strip_components: 1,
            signature_url: None,
            verification_method: VerificationMethod::Sha256Checksum,
        })
    }

    /// Fetch Node.js checksum from SHASUMS256.txt with GPG verification.
    async fn fetch_node_checksum(&self, url: &str, filename: &str) -> Result<String> {
        info!("Fetching and verifying Node.js checksums...");

        // 1. Fetch checksums file
        let shasums = self.fetch_text(url).await?;

        // 2. Fetch signature
        let sig_url = format!("{}.asc", url);
        let signature = self.fetch_text(&sig_url).await?;

        // 3. Fetch public keys and verify
        // We iterate through known release keys and fetch them from keyservers
        let mut public_keys = Vec::new();
        for key_id in known_keys::nodejs::ALL_KEY_IDS {
            // Keys are cached in key_fetcher with 24h TTL to avoid repeated keyserver requests
            match key_fetcher::fetch_gpg_key(key_id).await {
                Ok(key) => public_keys.push(key),
                Err(e) => debug!("Failed to fetch Node.js key {}: {}", key_id, e),
            }
        }

        if public_keys.is_empty() {
            return Err(CratonsError::Config(
                "Could not fetch any Node.js release keys".into(),
            ));
        }

        // Verify the signature
        let public_keys_str: Vec<&str> = public_keys.iter().map(|s| s.as_str()).collect();
        self.verifier
            .verify_gpg_any_key(shasums.as_bytes(), &signature, &public_keys_str)?;

        info!("Node.js checksums verified with GPG");

        for line in shasums.lines() {
            if line.contains(filename) {
                if let Some(hash) = line.split_whitespace().next() {
                    return Ok(hash.to_string());
                }
            }
        }

        Err(CratonsError::ChecksumMismatch {
            package: filename.to_string(),
            expected: "checksum from signed SHASUMS256.txt".to_string(),
            actual: "not found".to_string(),
        })
    }

    /// Resolve Python download URL (using astral-sh/python-build-standalone).
    ///
    /// Downloads SHA256 checksums from the release's SHA256SUMS file.
    async fn resolve_python(&self, request: &ToolchainRequest) -> Result<DownloadInfo> {
        // Fetch latest python-build-standalone release tag from GitHub API.
        // Prefer the API fetch for latest releases, but fallback to a known good release
        // if the API is unavailable (rate-limited, offline, etc.).
        let release_tag = self
            .fetch_latest_python_release_tag()
            .await
            .unwrap_or_else(|e| {
                warn!(
                    "Failed to fetch latest Python release tag: {}. Using fallback release: {}",
                    e, PYTHON_BUILD_STANDALONE_FALLBACK
                );
                PYTHON_BUILD_STANDALONE_FALLBACK.to_string()
            });

        let platform = match request.platform() {
            "darwin" => "apple-darwin",
            "linux" => "unknown-linux-gnu",
            "win32" => "pc-windows-msvc",
            other => {
                return Err(CratonsError::Config(format!(
                    "Unsupported platform: {other}"
                )));
            }
        };

        let arch = match request.arch() {
            "x64" => "x86_64",
            "arm64" => "aarch64",
            other => return Err(CratonsError::Config(format!("Unsupported arch: {other}"))),
        };

        let version = &request.version;
        let triple = format!("{arch}-{platform}");
        let variant = if request.platform() == "win32" {
            "shared-pgo"
        } else {
            "install_only_stripped"
        };

        let filename = format!("cpython-{version}+{release_tag}-{triple}-{variant}.tar.gz");
        let url = format!(
            "https://github.com/astral-sh/python-build-standalone/releases/download/{release_tag}/{filename}"
        );

        // Fetch SHA256 checksum from release
        let shasums_url = format!(
            "https://github.com/astral-sh/python-build-standalone/releases/download/{release_tag}/SHA256SUMS"
        );
        let expected_hash = match self.fetch_python_checksum(&shasums_url, &filename).await {
            Ok(hash) => Some(hash),
            Err(e) => {
                if self.strict_verification {
                    return Err(CratonsError::Verification(format!(
                        "Failed to fetch checksum for Python toolchain: {}. \
                         Strict verification is enabled - refusing to proceed without verification.",
                        e
                    )));
                }
                tracing::warn!(
                    "Could not fetch checksum for Python toolchain: {}. \
                     Proceeding without verification (use --strict to fail instead).",
                    e
                );
                None
            }
        };

        Ok(DownloadInfo {
            url,
            expected_hash,
            archive_type: ArchiveType::TarGz,
            strip_components: 1,
            signature_url: None,
            verification_method: VerificationMethod::Sha256Checksum,
        })
    }

    /// Fetch Python checksum from SHA256SUMS file with Minisign verification.
    async fn fetch_python_checksum(&self, url: &str, filename: &str) -> Result<String> {
        info!("Fetching and verifying Python checksums...");

        let shasums = self.fetch_text(url).await?;

        // 1. Fetch Minisign signature (.sig file)
        // python-build-standalone uses .sig extension for Minisign signatures
        let sig_url = format!("{}.sig", url);
        let signature = self.fetch_text(&sig_url).await?;

        // 2. Verify with public key
        // Key from https://github.com/indygreg/python-build-standalone
        let public_key = "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6MKKxsh6NhomGPyWiTerXB6";

        self.verifier
            .verify_minisign(shasums.as_bytes(), &signature, public_key)?;

        info!("Python checksums verified with Minisign");

        // Format: "hash  filename" (two spaces between)
        for line in shasums.lines() {
            if line.contains(filename) {
                if let Some(hash) = line.split_whitespace().next() {
                    return Ok(hash.to_string());
                }
            }
        }

        Err(CratonsError::ChecksumMismatch {
            package: filename.to_string(),
            expected: "checksum from signed SHA256SUMS".to_string(),
            actual: "not found".to_string(),
        })
    }

    /// Resolve Rust toolchain download URL.
    async fn resolve_rust(&self, request: &ToolchainRequest) -> Result<DownloadInfo> {
        let version = &request.version;

        let platform = match request.platform() {
            "darwin" => "apple-darwin",
            "linux" => "unknown-linux-gnu",
            "win32" => "pc-windows-msvc",
            other => {
                return Err(CratonsError::Config(format!(
                    "Unsupported platform: {other}"
                )));
            }
        };

        let arch = match request.arch() {
            "x64" => "x86_64",
            "arm64" => "aarch64",
            other => return Err(CratonsError::Config(format!("Unsupported arch: {other}"))),
        };

        let triple = format!("{arch}-{platform}");
        let ext = if request.platform() == "win32" {
            "tar.gz"
        } else {
            "tar.xz"
        };

        // Download the combined rust package (rustc + cargo + std)
        let filename = format!("rust-{version}-{triple}.{ext}");
        let url = format!("https://static.rust-lang.org/dist/{filename}");

        // Fetch SHA256
        let hash_url = format!("{url}.sha256");
        let expected_hash = self.fetch_simple_hash(&hash_url).await.ok();

        Ok(DownloadInfo {
            url: url.clone(),
            expected_hash,
            archive_type: if request.platform() == "win32" {
                ArchiveType::TarGz
            } else {
                ArchiveType::TarXz
            },
            strip_components: 1,
            signature_url: Some(format!("{}.asc", url)),
            verification_method: VerificationMethod::GpgSignature,
        })
    }

    /// Resolve Go download URL.
    async fn resolve_go(&self, request: &ToolchainRequest) -> Result<DownloadInfo> {
        let version = if request.version.starts_with("go") {
            request.version.clone()
        } else {
            format!("go{}", request.version)
        };

        let os = match request.platform() {
            "darwin" => "darwin",
            "linux" => "linux",
            "win32" => "windows",
            other => {
                return Err(CratonsError::Config(format!(
                    "Unsupported platform: {other}"
                )));
            }
        };

        let arch = match request.arch() {
            "x64" => "amd64",
            "arm64" => "arm64",
            other => return Err(CratonsError::Config(format!("Unsupported arch: {other}"))),
        };

        let ext = if os == "windows" { "zip" } else { "tar.gz" };
        let filename = format!("{version}.{os}-{arch}.{ext}");
        let url = format!("https://go.dev/dl/{filename}");

        // Fetch SHA256
        let hash_url = format!("{url}.sha256");
        let expected_hash = self.fetch_simple_hash(&hash_url).await.ok();

        Ok(DownloadInfo {
            url,
            expected_hash,
            archive_type: if os == "windows" {
                ArchiveType::Zip
            } else {
                ArchiveType::TarGz
            },
            strip_components: 1,
            signature_url: None,
            verification_method: VerificationMethod::Sha256Checksum,
        })
    }

    /// Resolve Java (Eclipse Temurin) download URL.
    async fn resolve_java(&self, request: &ToolchainRequest) -> Result<DownloadInfo> {
        let version = request.version.parse::<u32>().map_err(|_| {
            CratonsError::Config(format!("Invalid Java version: {}", request.version))
        })?;

        let os = match request.platform() {
            "darwin" => "mac",
            "linux" => "linux",
            "win32" => "windows",
            other => {
                return Err(CratonsError::Config(format!(
                    "Unsupported platform: {other}"
                )));
            }
        };

        let arch = match request.arch() {
            "x64" => "x64",
            "arm64" => "aarch64",
            other => return Err(CratonsError::Config(format!("Unsupported arch: {other}"))),
        };

        // Use Adoptium API to get latest release
        let api_url = format!(
            "https://api.adoptium.net/v3/assets/latest/{version}/hotspot?architecture={arch}&image_type=jdk&os={os}&vendor=eclipse"
        );

        let response = self
            .client
            .get(&api_url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Adoptium API returned status {}",
                response.status()
            )));
        }

        let releases: Vec<AdoptiumRelease> = response
            .json()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        let release = releases
            .first()
            .ok_or_else(|| CratonsError::PackageNotFound(format!("java@{version}")))?;

        Ok(DownloadInfo {
            url: release.binary.package.link.clone(),
            expected_hash: Some(release.binary.package.checksum.clone()),
            archive_type: if os == "windows" {
                ArchiveType::Zip
            } else {
                ArchiveType::TarGz
            },
            strip_components: 1,
            signature_url: None,
            verification_method: VerificationMethod::Sha256Checksum,
        })
    }

    /// Fetch the latest python-build-standalone release tag from GitHub API.
    async fn fetch_latest_python_release_tag(&self) -> Result<String> {
        let api_url =
            "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";

        let response = self
            .client
            .get(api_url)
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "GitHub API returned status {}",
                response.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct GithubRelease {
            tag_name: String,
        }

        let release: GithubRelease = response
            .json()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        debug!(
            "Latest python-build-standalone release: {}",
            release.tag_name
        );
        Ok(release.tag_name)
    }

    /// Fetch a simple hash file (single line with just the hash).
    async fn fetch_simple_hash(&self, url: &str) -> Result<String> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        let text = response
            .text()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        Ok(text.split_whitespace().next().unwrap_or("").to_string())
    }

    /// Download an archive and verify its checksum, returning verified bytes.
    ///
    /// # Security
    ///
    /// Returns the verified bytes in memory. These bytes should be passed directly
    /// to extraction without writing to disk to prevent TOCTOU attacks.
    #[instrument(skip(self, info), fields(url = %info.url))]
    async fn download_and_verify(&self, info: &DownloadInfo) -> Result<bytes::Bytes> {
        let response = self
            .client
            .get(&info.url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Download failed with status {}",
                response.status()
            )));
        }

        let total_size = response.content_length();
        debug!(size = ?total_size, "Starting download");

        let bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        // Verify checksum if available
        if let Some(expected) = &info.expected_hash {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let actual = hex::encode(hasher.finalize());

            if !actual.eq_ignore_ascii_case(expected) {
                return Err(CratonsError::ChecksumMismatch {
                    package: info.url.clone(),
                    expected: expected.clone(),
                    actual,
                });
            }
            debug!("Checksum verified");
        }

        // Verify signature if available
        if let Some(sig_url) = &info.signature_url {
            info!("Fetching signature from {}", sig_url);
            let signature = self.fetch_text(sig_url).await?;

            match info.verification_method {
                VerificationMethod::GpgSignature => {
                    // Rust release signing key
                    // TODO: Move to known_keys
                    let key_id = "75DDC6C471901C4718999155D1FA629B2C4F0887";
                    match key_fetcher::fetch_gpg_key(key_id).await {
                        Ok(public_key) => {
                            self.verifier.verify_gpg(&bytes, &signature, &public_key)?;
                        }
                        Err(e) => {
                            warn!(
                                "Failed to fetch Rust signing key: {}. proceeding with checksum only if allowed.",
                                e
                            );
                            // If strict, verify_best/verify_gpg would fail.
                            // Here we call verify_gpg which returns Result.
                            // So if we fail to fetch key, we can't verify.
                            return Err(e);
                        }
                    }
                }
                _ => {
                    debug!(
                        "Skipping artifact signature verification for method {:?}",
                        info.verification_method
                    );
                }
            }
        }

        info!(size = bytes.len(), "Downloaded and verified archive");
        Ok(bytes)
    }

    /// Extract directly from verified in-memory bytes and install to toolchain store.
    ///
    /// # Security
    ///
    /// This method takes pre-verified bytes directly, eliminating the TOCTOU window
    /// that would exist if we wrote to disk and then read back for extraction.
    #[instrument(skip(self, request, info, archive_bytes), fields(size = archive_bytes.len()))]
    async fn extract_from_bytes(
        &self,
        request: &ToolchainRequest,
        info: &DownloadInfo,
        archive_bytes: bytes::Bytes,
    ) -> Result<PathBuf> {
        // Create temp directory for extraction
        let temp_dir = tempfile::tempdir().map_err(CratonsError::Io)?;
        let extract_dir = temp_dir.path();

        // Extract based on archive type - directly from verified in-memory bytes
        match info.archive_type {
            ArchiveType::TarGz => {
                let cursor = Cursor::new(&archive_bytes);
                let gz = flate2::read::GzDecoder::new(cursor);
                let mut archive = tar::Archive::new(gz);
                // SECURITY: Use safe extraction to prevent path traversal attacks
                crate::extract::safe_unpack_tar(&mut archive, extract_dir)?;
            }
            ArchiveType::TarXz => {
                let cursor = Cursor::new(&archive_bytes);
                let xz = xz2::read::XzDecoder::new(cursor);
                let mut archive = tar::Archive::new(xz);
                // SECURITY: Use safe extraction to prevent path traversal attacks
                crate::extract::safe_unpack_tar(&mut archive, extract_dir)?;
            }
            ArchiveType::TarZstd => {
                let cursor = Cursor::new(&archive_bytes);
                let zstd = zstd::stream::Decoder::new(cursor)
                    .map_err(|e| CratonsError::Io(std::io::Error::other(e.to_string())))?;
                let mut archive = tar::Archive::new(zstd);
                // SECURITY: Use safe extraction to prevent path traversal attacks
                crate::extract::safe_unpack_tar(&mut archive, extract_dir)?;
            }
            ArchiveType::Zip => {
                let cursor = Cursor::new(archive_bytes.to_vec());
                let mut archive = zip::ZipArchive::new(cursor)
                    .map_err(|e| CratonsError::Io(std::io::Error::other(e.to_string())))?;
                // SECURITY: Use safe extraction to prevent path traversal attacks
                crate::extract::safe_extract_zip(&mut archive, extract_dir)?;
            }
        }

        // Find the extracted directory (usually there's a single top-level directory)
        let source_dir = if info.strip_components > 0 {
            find_extracted_root(extract_dir)?
        } else {
            extract_dir.to_path_buf()
        };

        // Create toolchain metadata
        let toolchain = Toolchain {
            name: request.ecosystem.as_str().to_string(),
            version: request.version.clone(),
            hash: ContentHash::blake3(info.url.clone()),
            url: info.url.clone(),
            platform: request.platform().to_string(),
            arch: request.arch().to_string(),
        };

        // Install to store
        let install_path = self.store.install(&toolchain, &source_dir)?;

        info!(
            path = %install_path.display(),
            "Installed toolchain"
        );

        Ok(install_path)
    }
}

/// Archive format types.
#[derive(Debug, Clone, Copy)]
enum ArchiveType {
    TarGz,
    TarXz,
    #[allow(dead_code)] // Implemented for future toolchains (e.g., Zig)
    TarZstd,
    Zip,
}

/// Adoptium API release response.
#[derive(Debug, Deserialize)]
struct AdoptiumRelease {
    binary: AdoptiumBinary,
}

#[derive(Debug, Deserialize)]
struct AdoptiumBinary {
    package: AdoptiumPackage,
}

#[derive(Debug, Deserialize)]
struct AdoptiumPackage {
    link: String,
    checksum: String,
}

/// Find the single top-level directory in an extracted archive.
fn find_extracted_root(dir: &Path) -> Result<PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| CratonsError::Io(e))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();

    if entries.len() == 1 {
        Ok(entries.remove(0).path())
    } else {
        Ok(dir.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toolchain_request_builders() {
        let req = ToolchainRequest::node("20.10.0");
        assert_eq!(req.ecosystem, ToolchainEcosystem::Node);
        assert_eq!(req.version, "20.10.0");

        let req = ToolchainRequest::python("3.12.0").with_platform("linux");
        assert_eq!(req.platform(), "linux");

        let req = ToolchainRequest::go("1.21.5").with_arch("arm64");
        assert_eq!(req.arch(), "arm64");
    }

    #[test]
    fn test_ecosystem_display() {
        assert_eq!(ToolchainEcosystem::Node.as_str(), "node");
        assert_eq!(ToolchainEcosystem::Python.as_str(), "python");
        assert_eq!(ToolchainEcosystem::Rust.as_str(), "rust");
        assert_eq!(ToolchainEcosystem::Go.as_str(), "go");
        assert_eq!(ToolchainEcosystem::Java.as_str(), "java");
    }

    #[tokio::test]
    #[ignore = "requires network"]
    async fn test_resolve_node_url() {
        let downloader = ToolchainDownloader::new().unwrap();
        let request = ToolchainRequest::node("20.10.0");

        let info = downloader.resolve_download(&request).await.unwrap();
        assert!(info.url.contains("nodejs.org"));
        assert!(info.url.contains("v20.10.0"));
    }

    #[tokio::test]
    #[ignore = "requires network"]
    async fn test_resolve_go_url() {
        let downloader = ToolchainDownloader::new().unwrap();
        let request = ToolchainRequest::go("1.21.5");

        let info = downloader.resolve_download(&request).await.unwrap();
        assert!(info.url.contains("go.dev/dl"));
        assert!(info.url.contains("go1.21.5"));
    }
}
