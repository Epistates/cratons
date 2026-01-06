//! Mock implementations for testing.
//!
//! Provides mock registries, remote caches, and WireMock helpers for
//! testing network interactions without hitting real services.

use cratons_core::{ContentHash, Ecosystem, CratonsError, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, path_regex},
};

/// A mock registry implementation for testing.
///
/// Stores package metadata in-memory and provides a simple API for
/// querying and adding packages.
///
/// # Example
///
/// ```rust
/// use cratons_test_fixtures::mocks::MockRegistry;
/// use cratons_core::{Ecosystem, PackageId, Version};
///
/// let mut registry = MockRegistry::new(Ecosystem::Npm);
/// registry.add_package("lodash", "4.17.21", r#"{"name": "lodash"}"#);
///
/// let metadata = registry.get_package("lodash", Some("4.17.21")).unwrap();
/// assert!(metadata.contains("lodash"));
/// ```
#[derive(Debug, Clone)]
pub struct MockRegistry {
    ecosystem: Ecosystem,
    packages: Arc<Mutex<HashMap<String, HashMap<String, String>>>>,
    request_count: Arc<Mutex<usize>>,
}

impl MockRegistry {
    /// Create a new mock registry for the given ecosystem.
    #[must_use]
    pub fn new(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            packages: Arc::new(Mutex::new(HashMap::new())),
            request_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Add a package to the registry.
    pub fn add_package(&mut self, name: &str, version: &str, metadata: &str) {
        let mut packages = self.packages.lock().unwrap();
        packages
            .entry(name.to_string())
            .or_insert_with(HashMap::new)
            .insert(version.to_string(), metadata.to_string());
    }

    /// Get package metadata.
    pub fn get_package(&self, name: &str, version: Option<&str>) -> Result<String> {
        let mut count = self.request_count.lock().unwrap();
        *count += 1;

        let packages = self.packages.lock().unwrap();
        let versions = packages
            .get(name)
            .ok_or_else(|| CratonsError::PackageNotFound(name.to_string()))?;

        if let Some(v) = version {
            versions
                .get(v)
                .cloned()
                .ok_or_else(|| CratonsError::VersionNotFound {
                    package: name.to_string(),
                    version: v.to_string(),
                })
        } else {
            // Return the latest version
            versions
                .values()
                .last()
                .cloned()
                .ok_or_else(|| CratonsError::PackageNotFound(format!("No versions for {name}")))
        }
    }

    /// List all versions of a package.
    pub fn list_versions(&self, name: &str) -> Result<Vec<String>> {
        let packages = self.packages.lock().unwrap();
        packages
            .get(name)
            .map(|versions| versions.keys().cloned().collect())
            .ok_or_else(|| CratonsError::PackageNotFound(name.to_string()))
    }

    /// Get the number of requests made to this registry.
    #[must_use]
    pub fn request_count(&self) -> usize {
        *self.request_count.lock().unwrap()
    }

    /// Reset the request counter.
    pub fn reset_counter(&mut self) {
        let mut count = self.request_count.lock().unwrap();
        *count = 0;
    }

    /// Check if a package exists.
    #[must_use]
    pub fn has_package(&self, name: &str) -> bool {
        self.packages.lock().unwrap().contains_key(name)
    }

    /// Get the ecosystem this registry serves.
    #[must_use]
    pub fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }
}

impl Default for MockRegistry {
    fn default() -> Self {
        Self::new(Ecosystem::Npm)
    }
}

/// A mock remote cache implementation for testing.
///
/// Simulates a content-addressable cache where artifacts can be stored
/// and retrieved by their content hash.
///
/// # Example
///
/// ```rust
/// use cratons_test_fixtures::mocks::MockRemoteCache;
/// use cratons_core::ContentHash;
///
/// let mut cache = MockRemoteCache::new();
/// let hash = ContentHash::blake3("test-content".to_string());
/// cache.put(hash.clone(), b"test data".to_vec());
///
/// let data = cache.get(&hash).unwrap();
/// assert_eq!(data, b"test data");
/// ```
#[derive(Debug, Clone)]
pub struct MockRemoteCache {
    storage: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    hit_count: Arc<Mutex<usize>>,
    miss_count: Arc<Mutex<usize>>,
}

impl MockRemoteCache {
    /// Create a new mock remote cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(HashMap::new())),
            hit_count: Arc::new(Mutex::new(0)),
            miss_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Store data in the cache.
    pub fn put(&mut self, hash: ContentHash, data: Vec<u8>) {
        let mut storage = self.storage.lock().unwrap();
        storage.insert(hash.value, data);
    }

    /// Retrieve data from the cache.
    pub fn get(&self, hash: &ContentHash) -> Result<Vec<u8>> {
        let storage = self.storage.lock().unwrap();

        if let Some(data) = storage.get(&hash.value) {
            let mut hit_count = self.hit_count.lock().unwrap();
            *hit_count += 1;
            Ok(data.clone())
        } else {
            let mut miss_count = self.miss_count.lock().unwrap();
            *miss_count += 1;
            Err(CratonsError::PackageNotFound(format!(
                "Cache miss: {}",
                hash.short()
            )))
        }
    }

    /// Check if the cache contains data for a given hash.
    #[must_use]
    pub fn contains(&self, hash: &ContentHash) -> bool {
        self.storage.lock().unwrap().contains_key(&hash.value)
    }

    /// Get the number of cache hits.
    #[must_use]
    pub fn hit_count(&self) -> usize {
        *self.hit_count.lock().unwrap()
    }

    /// Get the number of cache misses.
    #[must_use]
    pub fn miss_count(&self) -> usize {
        *self.miss_count.lock().unwrap()
    }

    /// Get the cache hit rate as a percentage.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hit_count();
        let misses = self.miss_count();
        let total = hits + misses;

        if total == 0 {
            0.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }

    /// Clear all cached data.
    pub fn clear(&mut self) {
        self.storage.lock().unwrap().clear();
    }

    /// Get the size of the cache (number of entries).
    #[must_use]
    pub fn len(&self) -> usize {
        self.storage.lock().unwrap().len()
    }

    /// Check if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        *self.hit_count.lock().unwrap() = 0;
        *self.miss_count.lock().unwrap() = 0;
    }
}

impl Default for MockRemoteCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Extension trait for WireMock to provide helper methods for common registry mocking scenarios.
#[allow(async_fn_in_trait)] // Test-only trait, not used across crate boundaries
pub trait WireMockExt {
    /// Mount an npm package metadata endpoint.
    async fn mock_npm_package(&self, name: &str, version: &str, metadata: serde_json::Value);

    /// Mount an npm package tarball download endpoint.
    async fn mock_npm_tarball(&self, name: &str, version: &str, data: Vec<u8>);

    /// Mount a PyPI package metadata endpoint.
    async fn mock_pypi_package(&self, name: &str, version: &str, metadata: serde_json::Value);

    /// Mount a PyPI wheel download endpoint.
    async fn mock_pypi_wheel(&self, name: &str, version: &str, data: Vec<u8>);

    /// Mount a crates.io metadata endpoint.
    async fn mock_crates_metadata(&self, name: &str, version: &str, metadata: serde_json::Value);

    /// Mount a crates.io download endpoint.
    async fn mock_crates_download(&self, name: &str, version: &str, data: Vec<u8>);

    /// Mount a 404 Not Found response.
    async fn mock_not_found(&self, path_pattern: &str);

    /// Mount a 429 Rate Limit response.
    async fn mock_rate_limit(&self, path_pattern: &str);

    /// Mount a 500 Internal Server Error response.
    async fn mock_server_error(&self, path_pattern: &str);
}

impl WireMockExt for MockServer {
    async fn mock_npm_package(&self, name: &str, version: &str, metadata: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(self)
            .await;

        // Also mock versioned endpoint
        Mock::given(method("GET"))
            .and(path(format!("/{name}/{version}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(self)
            .await;
    }

    async fn mock_npm_tarball(&self, name: &str, version: &str, data: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(format!("/{name}/-/{name}-{version}.tgz")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(data)
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(self)
            .await;
    }

    async fn mock_pypi_package(&self, name: &str, version: &str, metadata: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!("/pypi/{name}/json")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .mount(self)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/pypi/{name}/{version}/json")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(self)
            .await;
    }

    async fn mock_pypi_wheel(&self, name: &str, version: &str, data: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path_regex(format!(
                r"/packages/.+/{name}-{version}.*\.whl$"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(data)
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(self)
            .await;
    }

    async fn mock_crates_metadata(&self, name: &str, _version: &str, metadata: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/crates/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(self)
            .await;
    }

    async fn mock_crates_download(&self, name: &str, version: &str, data: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/crates/{name}/{version}/download")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(data)
                    .insert_header("content-type", "application/octet-stream"),
            )
            .mount(self)
            .await;
    }

    async fn mock_not_found(&self, path_pattern: &str) {
        Mock::given(method("GET"))
            .and(path_regex(path_pattern))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": "Not Found",
                "message": "The requested resource was not found"
            })))
            .mount(self)
            .await;
    }

    async fn mock_rate_limit(&self, path_pattern: &str) {
        Mock::given(method("GET"))
            .and(path_regex(path_pattern))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(serde_json::json!({
                        "error": "Too Many Requests",
                        "message": "Rate limit exceeded",
                        "retry_after": 60
                    }))
                    .insert_header("retry-after", "60"),
            )
            .mount(self)
            .await;
    }

    async fn mock_server_error(&self, path_pattern: &str) {
        Mock::given(method("GET"))
            .and(path_regex(path_pattern))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred"
            })))
            .mount(self)
            .await;
    }
}

/// Helper to create a mock registry server with pre-configured endpoints.
pub struct MockRegistryServer {
    server: MockServer,
    ecosystem: Ecosystem,
}

impl MockRegistryServer {
    /// Create a new mock registry server.
    pub async fn new(ecosystem: Ecosystem) -> Self {
        let server = MockServer::start().await;
        Self { server, ecosystem }
    }

    /// Get the base URL of the mock server.
    #[must_use]
    pub fn url(&self) -> String {
        self.server.uri()
    }

    /// Get the ecosystem this server mocks.
    #[must_use]
    pub fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    /// Add a package to the mock registry.
    pub async fn add_package(&self, name: &str, version: &str, metadata: serde_json::Value) {
        match self.ecosystem {
            Ecosystem::Npm => {
                self.server.mock_npm_package(name, version, metadata).await;
            }
            Ecosystem::PyPi => {
                self.server.mock_pypi_package(name, version, metadata).await;
            }
            Ecosystem::Crates => {
                self.server
                    .mock_crates_metadata(name, version, metadata)
                    .await;
            }
            _ => {}
        }
    }

    /// Verify that all expected requests were received.
    pub async fn verify(&self) {
        // WireMock automatically verifies expectations on drop
    }

    /// Get the underlying MockServer for advanced usage.
    #[must_use]
    pub fn server(&self) -> &MockServer {
        &self.server
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_registry() {
        let mut registry = MockRegistry::new(Ecosystem::Npm);
        registry.add_package("lodash", "4.17.21", r#"{"name": "lodash"}"#);

        assert!(registry.has_package("lodash"));
        assert!(!registry.has_package("nonexistent"));

        let metadata = registry.get_package("lodash", Some("4.17.21")).unwrap();
        assert!(metadata.contains("lodash"));

        assert_eq!(registry.request_count(), 1);

        let versions = registry.list_versions("lodash").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0], "4.17.21");
    }

    #[test]
    fn test_mock_registry_missing_package() {
        let registry = MockRegistry::new(Ecosystem::Npm);
        let result = registry.get_package("nonexistent", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_remote_cache() {
        let mut cache = MockRemoteCache::new();
        let hash = ContentHash::blake3("test".to_string());
        let data = b"test data".to_vec();

        cache.put(hash.clone(), data.clone());

        assert!(cache.contains(&hash));
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        let retrieved = cache.get(&hash).unwrap();
        assert_eq!(retrieved, data);

        assert_eq!(cache.hit_count(), 1);
        assert_eq!(cache.miss_count(), 0);
        assert_eq!(cache.hit_rate(), 100.0);

        let missing = ContentHash::blake3("missing".to_string());
        let result = cache.get(&missing);
        assert!(result.is_err());
        assert_eq!(cache.miss_count(), 1);
    }

    #[test]
    fn test_mock_cache_hit_rate() {
        let mut cache = MockRemoteCache::new();
        let hash1 = ContentHash::blake3("test1".to_string());
        let hash2 = ContentHash::blake3("test2".to_string());

        cache.put(hash1.clone(), b"data1".to_vec());

        let _ = cache.get(&hash1); // hit
        let _ = cache.get(&hash2); // miss
        let _ = cache.get(&hash1); // hit

        assert_eq!(cache.hit_count(), 2);
        assert_eq!(cache.miss_count(), 1);
        assert!((cache.hit_rate() - 66.67).abs() < 0.1);
    }

    #[test]
    fn test_mock_cache_clear() {
        let mut cache = MockRemoteCache::new();
        let hash = ContentHash::blake3("test".to_string());

        cache.put(hash.clone(), b"data".to_vec());
        assert_eq!(cache.len(), 1);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn test_wiremock_npm() {
        let server = MockServer::start().await;
        let metadata = serde_json::json!({
            "name": "test-package",
            "version": "1.0.0"
        });

        server
            .mock_npm_package("test-package", "1.0.0", metadata)
            .await;

        // In a real test, you'd make an HTTP request here and verify the response
    }

    #[tokio::test]
    async fn test_mock_registry_server() {
        let server = MockRegistryServer::new(Ecosystem::Npm).await;
        let metadata = serde_json::json!({
            "name": "lodash",
            "version": "4.17.21"
        });

        server.add_package("lodash", "4.17.21", metadata).await;

        assert_eq!(server.ecosystem(), Ecosystem::Npm);
        assert!(!server.url().is_empty());
    }
}
