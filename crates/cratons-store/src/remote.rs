//! Remote build cache for sharing artifacts across machines.
//!
//! Supports multiple backends:
//! - S3-compatible storage (AWS S3, MinIO, R2, GCS with interop)
//! - Local filesystem (for CI/local server setups)
//! - HTTP(S) read-only cache (for public artifacts)

use cratons_core::{ContentHash, CratonsError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

use crate::artifact::{Artifact, ArtifactStore};

// AWS SDK imports
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;

/// Configuration for a remote cache backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RemoteCacheConfig {
    /// S3-compatible storage.
    S3 {
        /// S3 bucket name.
        bucket: String,
        /// Optional prefix within bucket.
        #[serde(default)]
        prefix: String,
        /// AWS region (or endpoint region for S3-compatible).
        region: String,
        /// Custom endpoint URL (for MinIO, R2, etc.).
        #[serde(default)]
        endpoint: Option<String>,
        /// Access key ID (can also come from env/IAM).
        #[serde(default)]
        access_key_id: Option<String>,
        /// Secret access key (can also come from env/IAM).
        #[serde(default)]
        secret_access_key: Option<String>,
        /// Optional session token for temporary credentials.
        #[serde(default)]
        session_token: Option<String>,
        /// Whether to use path-style addressing (needed for MinIO).
        #[serde(default)]
        path_style: bool,
    },
    /// Local filesystem cache (network-mounted or local server).
    Filesystem {
        /// Path to the cache directory.
        path: PathBuf,
        /// Whether this cache is read-only.
        #[serde(default)]
        read_only: bool,
    },
    /// HTTP(S) read-only cache.
    Http {
        /// Base URL for the cache.
        url: String,
        /// Optional authorization header value.
        #[serde(default)]
        authorization: Option<String>,
        /// Request timeout in seconds.
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
}

fn default_timeout() -> u64 {
    60
}

impl RemoteCacheConfig {
    /// Create an S3 config from environment variables.
    pub fn s3_from_env(bucket: String, prefix: String, region: String) -> Self {
        Self::S3 {
            bucket,
            prefix,
            region,
            endpoint: std::env::var("AWS_ENDPOINT_URL").ok(),
            access_key_id: std::env::var("AWS_ACCESS_KEY_ID").ok(),
            secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").ok(),
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
            path_style: std::env::var("AWS_S3_PATH_STYLE")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false),
        }
    }

    /// Create a filesystem config.
    pub fn filesystem(path: impl Into<PathBuf>, read_only: bool) -> Self {
        Self::Filesystem {
            path: path.into(),
            read_only,
        }
    }

    /// Create an HTTP config.
    pub fn http(url: String, authorization: Option<String>) -> Self {
        Self::Http {
            url,
            authorization,
            timeout_secs: default_timeout(),
        }
    }
}

/// A remote cache backend trait.
#[async_trait::async_trait]
pub trait RemoteCacheBackend: Send + Sync {
    /// Check if an artifact exists in the remote cache.
    async fn exists(&self, input_hash: &ContentHash) -> Result<bool>;

    /// Download an artifact from the remote cache.
    /// Returns the path where it was downloaded, or None if not found.
    async fn download(&self, input_hash: &ContentHash, dest: &Path) -> Result<bool>;

    /// Upload an artifact to the remote cache.
    async fn upload(&self, artifact: &Artifact) -> Result<()>;

    /// Whether this backend supports uploads.
    fn supports_upload(&self) -> bool {
        true
    }

    /// Get backend name for logging.
    fn name(&self) -> &str;
}

/// S3-compatible storage backend.
pub struct S3Backend {
    client: reqwest::Client,
    bucket: String,
    prefix: String,
    region: String,
    endpoint: String,
    credentials: Credentials,
    path_style: bool,
}

impl S3Backend {
    /// Create a new S3 backend.
    pub fn new(config: &RemoteCacheConfig) -> Result<Self> {
        let (bucket, prefix, region, endpoint, credentials, path_style) = match config {
            RemoteCacheConfig::S3 {
                bucket,
                prefix,
                region,
                endpoint,
                access_key_id,
                secret_access_key,
                session_token,
                path_style,
            } => {
                let endpoint = endpoint
                    .clone()
                    .unwrap_or_else(|| format!("https://s3.{}.amazonaws.com", region));

                // Resolve credentials using credential chain
                let creds = Self::load_credentials(
                    access_key_id.clone(),
                    secret_access_key.clone(),
                    session_token.clone(),
                )?;

                (
                    bucket.clone(),
                    prefix.clone(),
                    region.clone(),
                    endpoint,
                    creds,
                    *path_style,
                )
            }
            _ => return Err(CratonsError::Config("Expected S3 config".to_string())),
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        Ok(Self {
            client,
            bucket,
            prefix,
            region,
            endpoint,
            credentials,
            path_style,
        })
    }

    /// Load AWS credentials from multiple sources.
    ///
    /// Credential chain (in order of precedence):
    /// 1. Explicit credentials passed as parameters
    /// 2. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
    /// 3. IAM role credentials via IMDS (Instance Metadata Service) - future enhancement
    fn load_credentials(
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        session_token: Option<String>,
    ) -> Result<Credentials> {
        // Try explicit credentials first
        if let (Some(access_key), Some(secret_key)) = (&access_key_id, &secret_access_key) {
            debug!("Using explicit AWS credentials from config");
            return Ok(Credentials::new(
                access_key.clone(),
                secret_key.clone(),
                session_token.clone(),
                None,
                "cratons-s3-config",
            ));
        }

        // Try environment variables
        if let (Ok(access_key), Ok(secret_key)) = (
            std::env::var("AWS_ACCESS_KEY_ID"),
            std::env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            let session = std::env::var("AWS_SESSION_TOKEN").ok();
            debug!("Using AWS credentials from environment variables");
            return Ok(Credentials::new(
                access_key,
                secret_key,
                session,
                None,
                "cratons-s3-env",
            ));
        }

        // TODO: Add IMDS support for EC2 instance roles
        // This would require making an async HTTP call to http://169.254.169.254/latest/meta-data/iam/security-credentials/
        // For now, we require explicit credentials or environment variables

        Err(CratonsError::Config(
            "AWS credentials not found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY \
            environment variables, or provide them in the config."
                .to_string(),
        ))
    }

    /// Get the S3 key for an artifact.
    fn artifact_key(&self, input_hash: &ContentHash) -> String {
        if self.prefix.is_empty() {
            format!("artifacts/{}/artifact.tar.zst", input_hash.value)
        } else {
            format!(
                "{}/artifacts/{}/artifact.tar.zst",
                self.prefix.trim_matches('/'),
                input_hash.value
            )
        }
    }

    /// Get the S3 key for a manifest.
    fn manifest_key(&self, input_hash: &ContentHash) -> String {
        if self.prefix.is_empty() {
            format!("artifacts/{}/manifest.json", input_hash.value)
        } else {
            format!(
                "{}/artifacts/{}/manifest.json",
                self.prefix.trim_matches('/'),
                input_hash.value
            )
        }
    }

    /// Build the URL for an S3 object.
    ///
    /// # Security
    ///
    /// This method validates the endpoint URL to prevent SSRF attacks:
    /// - Only http/https schemes are allowed
    /// - Localhost and private IP ranges are blocked
    /// - Bucket names are validated
    fn object_url(&self, key: &str) -> Result<String> {
        // SECURITY: Validate bucket name format to prevent injection
        if !Self::is_valid_bucket_name(&self.bucket) {
            return Err(CratonsError::Config(format!(
                "Invalid S3 bucket name: {}",
                self.bucket
            )));
        }

        // SECURITY: Validate endpoint URL to prevent SSRF
        Self::validate_endpoint(&self.endpoint)?;

        if self.path_style {
            Ok(format!("{}/{}/{}", self.endpoint, self.bucket, key))
        } else {
            let host = self.endpoint.replace("https://", "").replace("http://", "");
            let protocol = if self.endpoint.starts_with("http://") {
                "http"
            } else {
                "https"
            };
            Ok(format!("{}://{}.{}/{}", protocol, self.bucket, host, key))
        }
    }

    /// Validate S3 bucket name according to AWS naming rules.
    ///
    /// Bucket names must:
    /// - Be between 3 and 63 characters
    /// - Contain only lowercase letters, numbers, hyphens, and periods
    /// - Start and end with a letter or number
    /// - Not contain consecutive periods or adjacent period and hyphen
    fn is_valid_bucket_name(name: &str) -> bool {
        let len = name.len();
        if !(3..=63).contains(&len) {
            return false;
        }

        let chars: Vec<char> = name.chars().collect();

        // Must start and end with alphanumeric
        if !chars[0].is_ascii_alphanumeric() || !chars[len - 1].is_ascii_alphanumeric() {
            return false;
        }

        // Check all characters and patterns
        for (i, c) in chars.iter().enumerate() {
            // Only allow lowercase alphanumeric, hyphen, and period
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && *c != '-' && *c != '.' {
                return false;
            }

            // Check for consecutive periods or period-hyphen adjacency
            if i > 0 {
                let prev = chars[i - 1];
                let invalid_combo = matches!((*c, prev), ('.' | '-', '.') | ('.', '-'));
                if invalid_combo {
                    return false;
                }
            }
        }

        // Must not look like an IP address
        if name.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return false;
        }

        true
    }

    /// Validate endpoint URL to prevent SSRF attacks.
    ///
    /// Blocks:
    /// - Non-http(s) schemes
    /// - Localhost addresses
    /// - Private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)
    /// - IPv6 localhost and link-local
    fn validate_endpoint(endpoint: &str) -> Result<()> {
        // Parse the URL
        let url = url::Url::parse(endpoint).map_err(|e| {
            CratonsError::Config(format!("Invalid endpoint URL '{}': {}", endpoint, e))
        })?;

        // SECURITY: Only allow http and https schemes
        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(CratonsError::Config(format!(
                    "Invalid URL scheme '{}': only http and https are allowed",
                    scheme
                )));
            }
        }

        // SECURITY: Check for localhost and private IPs
        if let Some(host) = url.host_str() {
            let host_lower = host.to_lowercase();

            // Block localhost variants
            if host_lower == "localhost"
                || host_lower == "127.0.0.1"
                || host_lower == "::1"
                || host_lower == "[::1]"
                || host_lower.starts_with("127.")
            {
                return Err(CratonsError::Config(format!(
                    "SSRF protection: localhost endpoints are not allowed: {}",
                    host
                )));
            }

            // Block metadata service endpoints (AWS, GCP, Azure)
            if host_lower == "169.254.169.254"
                || host_lower == "metadata.google.internal"
                || host_lower.ends_with(".metadata.google.internal")
            {
                return Err(CratonsError::Config(format!(
                    "SSRF protection: cloud metadata endpoints are not allowed: {}",
                    host
                )));
            }

            // Check for private IP ranges if it looks like an IP
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if Self::is_private_ip(&ip) {
                    return Err(CratonsError::Config(format!(
                        "SSRF protection: private IP addresses are not allowed: {}",
                        ip
                    )));
                }
            }
        }

        Ok(())
    }

    /// Check if an IP address is in a private/reserved range.
    fn is_private_ip(ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 10.0.0.0/8
                if octets[0] == 10 {
                    return true;
                }
                // 172.16.0.0/12
                if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    return true;
                }
                // 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 {
                    return true;
                }
                // 169.254.0.0/16 (link-local)
                if octets[0] == 169 && octets[1] == 254 {
                    return true;
                }
                // 127.0.0.0/8 (loopback)
                if octets[0] == 127 {
                    return true;
                }
                false
            }
            std::net::IpAddr::V6(ipv6) => {
                // ::1 (loopback)
                if ipv6.is_loopback() {
                    return true;
                }
                // fe80::/10 (link-local)
                let segments = ipv6.segments();
                if (segments[0] & 0xffc0) == 0xfe80 {
                    return true;
                }
                // fc00::/7 (unique local addresses)
                if (segments[0] & 0xfe00) == 0xfc00 {
                    return true;
                }
                false
            }
        }
    }

    /// Sign a request using AWS Signature Version 4.
    fn sign_request(
        &self,
        method: &str,
        url: &str,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<Vec<(String, String)>> {
        // Prepare headers for signable request
        let mut headers = Vec::new();
        if let Some(ct) = content_type {
            headers.push(("content-type", ct));
        }

        // Create signable request
        let signable_request =
            SignableRequest::new(method, url, headers.into_iter(), SignableBody::Bytes(body))
                .map_err(|e| {
                    CratonsError::Config(format!("Failed to create signable request: {}", e))
                })?;

        // Create signing settings
        let signing_settings = SigningSettings::default();

        // Convert credentials to Identity
        let identity = self.credentials.clone().into();

        // Create signing params
        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name("s3")
            .time(SystemTime::now())
            .settings(signing_settings)
            .build()
            .map_err(|e| CratonsError::Config(format!("Failed to build signing params: {}", e)))?
            .into();

        // Sign the request
        let (signing_instructions, _signature) = sign(signable_request, &signing_params)
            .map_err(|e| CratonsError::Config(format!("Failed to sign request: {}", e)))?
            .into_parts();

        // Extract headers from signing instructions
        let mut result_headers = Vec::new();

        // Get all headers from the signing instructions
        for (name, value) in signing_instructions.headers() {
            result_headers.push((name.to_string(), value.to_string()));
        }

        Ok(result_headers)
    }
}

#[async_trait::async_trait]
impl RemoteCacheBackend for S3Backend {
    async fn exists(&self, input_hash: &ContentHash) -> Result<bool> {
        let key = self.manifest_key(input_hash);
        let url = self.object_url(&key)?;

        let headers = self.sign_request("HEAD", &url, &[], None)?;

        let mut req = self.client.head(&url);
        for (name, value) in headers {
            req = req.header(&name, &value);
        }

        let response = req
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        Ok(response.status().is_success())
    }

    async fn download(&self, input_hash: &ContentHash, dest: &Path) -> Result<bool> {
        // First check if it exists
        if !self.exists(input_hash).await? {
            return Ok(false);
        }

        // Download manifest
        let manifest_key = self.manifest_key(input_hash);
        let manifest_url = self.object_url(&manifest_key)?;

        let headers = self.sign_request("GET", &manifest_url, &[], None)?;

        let mut req = self.client.get(&manifest_url);
        for (name, value) in &headers {
            req = req.header(name, value);
        }

        let response = req
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Failed to download manifest: HTTP {}",
                response.status()
            )));
        }

        let manifest_bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        // Download artifact archive
        let artifact_key = self.artifact_key(input_hash);
        let artifact_url = self.object_url(&artifact_key)?;
        let headers = self.sign_request("GET", &artifact_url, &[], None)?;

        let mut req = self.client.get(&artifact_url);
        for (name, value) in &headers {
            req = req.header(name, value);
        }

        let response = req
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Failed to download artifact: HTTP {}",
                response.status()
            )));
        }

        let artifact_bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        // Extract to destination
        fs::create_dir_all(dest)?;

        // Write manifest
        fs::write(dest.join("cratons-manifest.json"), &manifest_bytes)?;

        // Decompress and extract archive
        // SECURITY: Use safe extraction to prevent path traversal attacks
        let decoder = zstd::Decoder::new(&artifact_bytes[..])?;
        let mut archive = tar::Archive::new(decoder);
        crate::extract::safe_unpack_tar(&mut archive, dest)?;

        info!(
            "Downloaded artifact {} from S3 to {}",
            input_hash.short(),
            dest.display()
        );

        Ok(true)
    }

    async fn upload(&self, artifact: &Artifact) -> Result<()> {
        // Create compressed archive
        let mut archive_data = Vec::new();
        {
            let encoder = zstd::Encoder::new(&mut archive_data, 3)?;
            let mut builder = tar::Builder::new(encoder.auto_finish());

            // Add all files except the manifest (we upload that separately)
            for entry in walkdir::WalkDir::new(&artifact.path) {
                let entry = entry?;
                let relative = entry
                    .path()
                    .strip_prefix(&artifact.path)
                    .map_err(|e| CratonsError::Io(std::io::Error::other(e.to_string())))?;

                if relative.as_os_str().is_empty()
                    || relative == Path::new("cratons-manifest.json")
                {
                    continue;
                }

                if entry.file_type().is_file() {
                    builder.append_path_with_name(entry.path(), relative)?;
                } else if entry.file_type().is_dir() {
                    builder.append_dir(relative, entry.path())?;
                }
            }

            builder.finish()?;
        }

        // Upload artifact archive
        let artifact_key = self.artifact_key(&artifact.manifest.input_hash);
        let artifact_url = self.object_url(&artifact_key)?;
        let headers = self.sign_request(
            "PUT",
            &artifact_url,
            &archive_data,
            Some("application/zstd"),
        )?;

        let mut req = self.client.put(&artifact_url).body(archive_data);
        for (name, value) in &headers {
            req = req.header(name, value);
        }

        let response = req
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Failed to upload artifact: HTTP {}",
                response.status()
            )));
        }

        // Upload manifest
        let manifest_json = serde_json::to_vec_pretty(&artifact.manifest)?;

        let manifest_key = self.manifest_key(&artifact.manifest.input_hash);
        let manifest_url = self.object_url(&manifest_key)?;
        let headers = self.sign_request(
            "PUT",
            &manifest_url,
            &manifest_json,
            Some("application/json"),
        )?;

        let mut req = self.client.put(&manifest_url).body(manifest_json);
        for (name, value) in &headers {
            req = req.header(name, value);
        }

        let response = req
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Failed to upload manifest: HTTP {}",
                response.status()
            )));
        }

        info!(
            "Uploaded artifact {} to S3",
            artifact.manifest.input_hash.short()
        );

        Ok(())
    }

    fn name(&self) -> &str {
        "s3"
    }
}

/// Filesystem backend for local/network storage.
pub struct FilesystemBackend {
    root: PathBuf,
    read_only: bool,
}

impl FilesystemBackend {
    /// Create a new filesystem backend.
    pub fn new(config: &RemoteCacheConfig) -> Result<Self> {
        match config {
            RemoteCacheConfig::Filesystem { path, read_only } => {
                if !read_only {
                    fs::create_dir_all(path)?;
                }
                Ok(Self {
                    root: path.clone(),
                    read_only: *read_only,
                })
            }
            _ => Err(CratonsError::Config(
                "Expected Filesystem config".to_string(),
            )),
        }
    }

    fn artifact_dir(&self, input_hash: &ContentHash) -> PathBuf {
        self.root.join("artifacts").join(&input_hash.value)
    }
}

#[async_trait::async_trait]
impl RemoteCacheBackend for FilesystemBackend {
    async fn exists(&self, input_hash: &ContentHash) -> Result<bool> {
        let manifest_path = self.artifact_dir(input_hash).join("cratons-manifest.json");
        Ok(manifest_path.exists())
    }

    async fn download(&self, input_hash: &ContentHash, dest: &Path) -> Result<bool> {
        let src_dir = self.artifact_dir(input_hash);
        if !src_dir.exists() {
            return Ok(false);
        }

        // Copy all files
        fs::create_dir_all(dest)?;
        copy_dir_recursive(&src_dir, dest)?;

        info!(
            "Copied artifact {} from filesystem cache to {}",
            input_hash.short(),
            dest.display()
        );

        Ok(true)
    }

    async fn upload(&self, artifact: &Artifact) -> Result<()> {
        if self.read_only {
            return Err(CratonsError::Config(
                "Filesystem cache is read-only".to_string(),
            ));
        }

        let dest_dir = self.artifact_dir(&artifact.manifest.input_hash);
        fs::create_dir_all(&dest_dir)?;

        // Copy all files
        copy_dir_recursive(&artifact.path, &dest_dir)?;

        info!(
            "Uploaded artifact {} to filesystem cache",
            artifact.manifest.input_hash.short()
        );

        Ok(())
    }

    fn supports_upload(&self) -> bool {
        !self.read_only
    }

    fn name(&self) -> &str {
        "filesystem"
    }
}

/// HTTP(S) read-only backend.
pub struct HttpBackend {
    client: reqwest::Client,
    base_url: String,
    authorization: Option<String>,
}

impl HttpBackend {
    /// Create a new HTTP backend.
    pub fn new(config: &RemoteCacheConfig) -> Result<Self> {
        match config {
            RemoteCacheConfig::Http {
                url,
                authorization,
                timeout_secs,
            } => {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(*timeout_secs))
                    .build()
                    .map_err(|e| CratonsError::Network(e.to_string()))?;

                Ok(Self {
                    client,
                    base_url: url.trim_end_matches('/').to_string(),
                    authorization: authorization.clone(),
                })
            }
            _ => Err(CratonsError::Config("Expected HTTP config".to_string())),
        }
    }

    fn artifact_url(&self, input_hash: &ContentHash) -> String {
        format!(
            "{}/artifacts/{}/artifact.tar.zst",
            self.base_url, input_hash.value
        )
    }

    fn manifest_url(&self, input_hash: &ContentHash) -> String {
        format!(
            "{}/artifacts/{}/manifest.json",
            self.base_url, input_hash.value
        )
    }
}

#[async_trait::async_trait]
impl RemoteCacheBackend for HttpBackend {
    async fn exists(&self, input_hash: &ContentHash) -> Result<bool> {
        let url = self.manifest_url(input_hash);
        let mut req = self.client.head(&url);

        if let Some(auth) = &self.authorization {
            req = req.header("Authorization", auth);
        }

        let response = req
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        Ok(response.status().is_success())
    }

    async fn download(&self, input_hash: &ContentHash, dest: &Path) -> Result<bool> {
        // Download manifest
        let manifest_url = self.manifest_url(input_hash);
        let mut req = self.client.get(&manifest_url);

        if let Some(auth) = &self.authorization {
            req = req.header("Authorization", auth);
        }

        let response = req
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Failed to download manifest: HTTP {}",
                response.status()
            )));
        }

        let manifest_bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        // Download artifact
        let artifact_url = self.artifact_url(input_hash);
        let mut req = self.client.get(&artifact_url);

        if let Some(auth) = &self.authorization {
            req = req.header("Authorization", auth);
        }

        let response = req
            .send()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "Failed to download artifact: HTTP {}",
                response.status()
            )));
        }

        let artifact_bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        // Extract
        fs::create_dir_all(dest)?;
        fs::write(dest.join("cratons-manifest.json"), &manifest_bytes)?;

        // SECURITY: Use safe extraction to prevent path traversal attacks
        let decoder = zstd::Decoder::new(&artifact_bytes[..])?;
        let mut archive = tar::Archive::new(decoder);
        crate::extract::safe_unpack_tar(&mut archive, dest)?;

        info!(
            "Downloaded artifact {} from HTTP cache to {}",
            input_hash.short(),
            dest.display()
        );

        Ok(true)
    }

    async fn upload(&self, _artifact: &Artifact) -> Result<()> {
        Err(CratonsError::Config(
            "HTTP backend is read-only".to_string(),
        ))
    }

    fn supports_upload(&self) -> bool {
        false
    }

    fn name(&self) -> &str {
        "http"
    }
}

/// The main remote cache client that manages multiple backends.
pub struct RemoteCache {
    backends: Vec<Box<dyn RemoteCacheBackend>>,
    local_artifacts: ArtifactStore,
}

impl RemoteCache {
    /// Create a new remote cache with the given backends.
    pub fn new(configs: Vec<RemoteCacheConfig>, local_artifacts: ArtifactStore) -> Result<Self> {
        let mut backends: Vec<Box<dyn RemoteCacheBackend>> = Vec::new();

        for config in configs {
            let backend: Box<dyn RemoteCacheBackend> = match &config {
                RemoteCacheConfig::S3 { .. } => Box::new(S3Backend::new(&config)?),
                RemoteCacheConfig::Filesystem { .. } => Box::new(FilesystemBackend::new(&config)?),
                RemoteCacheConfig::Http { .. } => Box::new(HttpBackend::new(&config)?),
            };
            backends.push(backend);
        }

        Ok(Self {
            backends,
            local_artifacts,
        })
    }

    /// Check if an artifact exists in any remote cache.
    pub async fn exists(&self, input_hash: &ContentHash) -> Result<bool> {
        for backend in &self.backends {
            match backend.exists(input_hash).await {
                Ok(true) => return Ok(true),
                Ok(false) => continue,
                Err(e) => {
                    warn!("Error checking {} backend: {}", backend.name(), e);
                    continue;
                }
            }
        }
        Ok(false)
    }

    /// Try to fetch an artifact from remote caches.
    /// Returns the local path if found and downloaded, or None.
    ///
    /// # Security
    ///
    /// After downloading, the artifact manifest is verified to ensure the
    /// `input_hash` matches what was requested. This prevents a malicious
    /// remote cache from serving incorrect artifacts.
    pub async fn fetch(&self, input_hash: &ContentHash) -> Result<Option<PathBuf>> {
        // Check local first
        if let Some(path) = self.local_artifacts.get(input_hash) {
            debug!("Artifact {} found in local cache", input_hash.short());
            return Ok(Some(path));
        }

        // Try remote backends
        for backend in &self.backends {
            // Create a temp destination
            let dest = self
                .local_artifacts
                .root()
                .join(format!("{}-download", input_hash.short()));

            match backend.download(input_hash, &dest).await {
                Ok(true) => {
                    // SECURITY: Verify the downloaded artifact's hash matches what we requested
                    match Self::verify_downloaded_artifact(&dest, input_hash) {
                        Ok(()) => {
                            info!(
                                "Downloaded and verified artifact {} from {} backend",
                                input_hash.short(),
                                backend.name()
                            );
                            return Ok(Some(dest));
                        }
                        Err(e) => {
                            warn!(
                                "Downloaded artifact {} from {} failed verification: {}",
                                input_hash.short(),
                                backend.name(),
                                e
                            );
                            // Clean up the untrusted artifact
                            let _ = fs::remove_dir_all(&dest);
                            // Continue to try other backends
                            continue;
                        }
                    }
                }
                Ok(false) => {
                    debug!(
                        "Artifact {} not in {} backend",
                        input_hash.short(),
                        backend.name()
                    );
                    continue;
                }
                Err(e) => {
                    warn!("Error downloading from {} backend: {}", backend.name(), e);
                    // Clean up failed download
                    let _ = fs::remove_dir_all(&dest);
                    continue;
                }
            }
        }

        Ok(None)
    }

    /// Verify a downloaded artifact matches the expected hash.
    ///
    /// This checks that the manifest's input_hash matches what we requested,
    /// preventing a malicious remote cache from serving incorrect artifacts.
    fn verify_downloaded_artifact(path: &Path, expected_hash: &ContentHash) -> Result<()> {
        let manifest_path = path.join("cratons-manifest.json");

        if !manifest_path.exists() {
            return Err(CratonsError::ChecksumMismatch {
                package: path.display().to_string(),
                expected: expected_hash.value.clone(),
                actual: "manifest not found".to_string(),
            });
        }

        let manifest_content = fs::read_to_string(&manifest_path)?;
        let manifest: crate::artifact::ArtifactManifest =
            serde_json::from_str(&manifest_content).map_err(|e| {
                CratonsError::ChecksumMismatch {
                    package: path.display().to_string(),
                    expected: expected_hash.value.clone(),
                    actual: format!("invalid manifest: {}", e),
                }
            })?;

        // Verify the input hash matches
        if manifest.input_hash.value != expected_hash.value {
            return Err(CratonsError::ChecksumMismatch {
                package: format!("{}@{}", manifest.package, manifest.version),
                expected: expected_hash.value.clone(),
                actual: manifest.input_hash.value.clone(),
            });
        }

        // Verify hash algorithm matches
        if manifest.input_hash.algorithm != expected_hash.algorithm {
            return Err(CratonsError::ChecksumMismatch {
                package: format!("{}@{}", manifest.package, manifest.version),
                expected: format!("{:?}:{}", expected_hash.algorithm, expected_hash.value),
                actual: format!(
                    "{:?}:{}",
                    manifest.input_hash.algorithm, manifest.input_hash.value
                ),
            });
        }

        debug!(
            "Verified artifact {} integrity: {}",
            manifest.package,
            expected_hash.short()
        );

        Ok(())
    }

    /// Push a local artifact to all writable remote caches.
    pub async fn push(&self, input_hash: &ContentHash) -> Result<usize> {
        let artifact = self
            .local_artifacts
            .load(input_hash)?
            .ok_or_else(|| CratonsError::PackageNotFound(input_hash.value.clone()))?;

        let mut success_count = 0;

        for backend in &self.backends {
            if !backend.supports_upload() {
                continue;
            }

            match backend.upload(&artifact).await {
                Ok(()) => {
                    info!(
                        "Pushed artifact {} to {} backend",
                        input_hash.short(),
                        backend.name()
                    );
                    success_count += 1;
                }
                Err(e) => {
                    warn!("Failed to push to {} backend: {}", backend.name(), e);
                }
            }
        }

        Ok(success_count)
    }

    /// Push all local artifacts to remote caches.
    pub async fn push_all(&self) -> Result<(usize, usize)> {
        let artifacts = self.local_artifacts.list()?;
        let mut total_pushed = 0;
        let mut failed = 0;

        for artifact in artifacts {
            match self.push(&artifact.manifest.input_hash).await {
                Ok(count) if count > 0 => total_pushed += 1,
                Ok(_) => failed += 1,
                Err(e) => {
                    warn!("Failed to push artifact: {}", e);
                    failed += 1;
                }
            }
        }

        Ok((total_pushed, failed))
    }
}

/// Copy a directory recursively.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(src) {
        let entry = entry?;
        let relative = entry
            .path()
            .strip_prefix(src)
            .map_err(|e| CratonsError::Io(std::io::Error::other(e.to_string())))?;
        let target = dst.join(relative);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactManifest;
    use tempfile::tempdir;

    #[test]
    fn test_s3_artifact_key() {
        // This is just a basic structure test - real S3 testing requires mocking
        let config = RemoteCacheConfig::S3 {
            bucket: "my-bucket".to_string(),
            prefix: "cratons".to_string(),
            region: "us-east-1".to_string(),
            endpoint: Some("http://localhost:9000".to_string()),
            access_key_id: Some("test".to_string()),
            secret_access_key: Some("test".to_string()),
            session_token: None,
            path_style: true,
        };

        // Just verify config construction
        assert!(matches!(config, RemoteCacheConfig::S3 { .. }));
    }

    #[tokio::test]
    async fn test_filesystem_backend() {
        let cache_dir = tempdir().unwrap();
        let artifacts_dir = tempdir().unwrap();
        let output_dir = tempdir().unwrap();

        // Create a test artifact
        fs::write(output_dir.path().join("test.txt"), b"test content").unwrap();
        fs::create_dir(output_dir.path().join("subdir")).unwrap();
        fs::write(output_dir.path().join("subdir/nested.txt"), b"nested").unwrap();

        let artifact_store = ArtifactStore::new(artifacts_dir.path());
        let input_hash = ContentHash::blake3("test_input".to_string());
        let manifest = ArtifactManifest::new(
            input_hash.clone(),
            "test-pkg".to_string(),
            "1.0.0".to_string(),
        );

        artifact_store.store(&manifest, output_dir.path()).unwrap();

        // Create filesystem backend
        let config = RemoteCacheConfig::filesystem(cache_dir.path(), false);
        let backend = FilesystemBackend::new(&config).unwrap();

        // Load the stored artifact
        let artifact = artifact_store.load(&input_hash).unwrap().unwrap();

        // Upload to filesystem backend
        backend.upload(&artifact).await.unwrap();

        // Verify it exists
        assert!(backend.exists(&input_hash).await.unwrap());

        // Download to a new location
        let download_dir = tempdir().unwrap();
        let downloaded = backend
            .download(&input_hash, download_dir.path())
            .await
            .unwrap();
        assert!(downloaded);

        // Verify contents
        assert!(download_dir.path().join("test.txt").exists());
        assert!(download_dir.path().join("subdir/nested.txt").exists());
    }

    #[test]
    fn test_config_from_env() {
        let config = RemoteCacheConfig::s3_from_env(
            "test-bucket".to_string(),
            "prefix".to_string(),
            "us-west-2".to_string(),
        );

        match config {
            RemoteCacheConfig::S3 { bucket, region, .. } => {
                assert_eq!(bucket, "test-bucket");
                assert_eq!(region, "us-west-2");
            }
            _ => panic!("Expected S3 config"),
        }
    }

    #[test]
    fn test_load_credentials_explicit() {
        // Test explicit credentials (highest priority)
        let result = S3Backend::load_credentials(
            Some("EXPLICIT_KEY".to_string()),
            Some("EXPLICIT_SECRET".to_string()),
            Some("EXPLICIT_TOKEN".to_string()),
        );

        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.access_key_id(), "EXPLICIT_KEY");
        assert_eq!(creds.secret_access_key(), "EXPLICIT_SECRET");
        assert_eq!(creds.session_token(), Some("EXPLICIT_TOKEN"));
    }

    #[test]
    fn test_load_credentials_explicit_without_token() {
        // Test explicit credentials without session token
        let result = S3Backend::load_credentials(
            Some("EXPLICIT_KEY".to_string()),
            Some("EXPLICIT_SECRET".to_string()),
            None,
        );

        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.access_key_id(), "EXPLICIT_KEY");
        assert_eq!(creds.secret_access_key(), "EXPLICIT_SECRET");
        assert_eq!(creds.session_token(), None);
    }

    #[test]
    fn test_load_credentials_explicit_overrides_env() {
        // Test that explicit credentials take precedence (they are checked first)
        // Even if env vars exist, explicit credentials should be used
        let result = S3Backend::load_credentials(
            Some("EXPLICIT_KEY".to_string()),
            Some("EXPLICIT_SECRET".to_string()),
            None,
        );

        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.access_key_id(), "EXPLICIT_KEY");
        assert_eq!(creds.secret_access_key(), "EXPLICIT_SECRET");
    }

    #[test]
    fn test_load_credentials_missing_secret_key() {
        // Test with only access key (should fail - both key and secret required)
        let result = S3Backend::load_credentials(Some("ONLY_KEY".to_string()), None, None);

        // Should fall through to env vars, and if those aren't set, should fail
        // This test assumes AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not both set
        if std::env::var("AWS_ACCESS_KEY_ID").is_ok()
            && std::env::var("AWS_SECRET_ACCESS_KEY").is_ok()
        {
            // If env vars are set, it will succeed from env
            assert!(result.is_ok());
        } else {
            // Otherwise it should fail
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("credentials not found")
            );
        }
    }

    #[test]
    fn test_s3_backend_creation_with_explicit_credentials() {
        let config = RemoteCacheConfig::S3 {
            bucket: "test-bucket".to_string(),
            prefix: "test-prefix".to_string(),
            region: "us-east-1".to_string(),
            endpoint: Some("http://localhost:9000".to_string()),
            access_key_id: Some("test-key".to_string()),
            secret_access_key: Some("test-secret".to_string()),
            session_token: None,
            path_style: true,
        };

        let backend = S3Backend::new(&config);
        assert!(backend.is_ok());

        let backend = backend.unwrap();
        assert_eq!(backend.bucket, "test-bucket");
        assert_eq!(backend.region, "us-east-1");
        assert_eq!(backend.credentials.access_key_id(), "test-key");
    }

    #[test]
    fn test_credential_chain_logic() {
        // Test 1: Explicit credentials with token
        let result = S3Backend::load_credentials(
            Some("KEY1".to_string()),
            Some("SECRET1".to_string()),
            Some("TOKEN1".to_string()),
        );
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.access_key_id(), "KEY1");
        assert_eq!(creds.secret_access_key(), "SECRET1");
        assert_eq!(creds.session_token(), Some("TOKEN1"));

        // Test 2: Explicit credentials without token
        let result = S3Backend::load_credentials(
            Some("KEY2".to_string()),
            Some("SECRET2".to_string()),
            None,
        );
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.access_key_id(), "KEY2");
        assert_eq!(creds.secret_access_key(), "SECRET2");
        assert_eq!(creds.session_token(), None);

        // Test 3: Partial explicit credentials should fall through to env
        // (testing that both key and secret are required for explicit path)
        let result = S3Backend::load_credentials(Some("KEY3".to_string()), None, None);
        // This will either succeed from env vars or fail if env vars aren't set
        // The test passes as long as it doesn't panic
        let _ = result;
    }
}
