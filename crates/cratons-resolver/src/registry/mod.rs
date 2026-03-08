//! Registry client interfaces and implementations.
//!
//! This module provides HTTP clients for fetching package metadata and
//! downloading artifacts from various package registries.
//!
//! ## Offline Mode
//!
//! When `offline` is true, the registry will:
//! - Serve cached version lists and metadata if available
//! - Return errors only if cached data is not available
//!
//! ## Caching Behavior
//!
//! In online mode:
//! - Check cache first for fresh data (within TTL)
//! - Fetch from network if cache miss or stale
//! - Cache successful responses for future use
//!
//! In offline mode:
//! - Return cached data regardless of TTL
//! - Error if no cached data exists

mod crates;
mod go;
mod maven;
mod npm;
pub mod policy;
mod pypi;

pub use self::crates::CratesIoClient;
pub use go::GoProxyClient;
pub use maven::MavenClient;
pub use npm::NpmClient;
pub use policy::{RegistryPolicy, RegistryPolicyConfig};
pub use pypi::PyPiClient;

use async_trait::async_trait;
use cratons_core::{CratonsError, Ecosystem, Result};
use cratons_store::{CachedMetadata, RegistryCache};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Metadata about a peer dependency (npm peerDependenciesMeta).
///
/// This struct captures npm v7+ semantics for peer dependency handling.
/// When `optional` is true, the peer dependency won't fail resolution if missing.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerDependencyMeta {
    /// Whether this peer dependency is optional.
    /// Optional peer deps don't fail resolution if missing (npm v7+ behavior).
    #[serde(default)]
    pub optional: bool,
}

/// Metadata for a package version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// Package name
    pub name: String,
    /// Version
    pub version: String,
    /// Download URL
    pub dist_url: String,
    /// Integrity hash (algorithm:base64 format)
    pub integrity: String,
    /// Dependencies (name -> version requirement)
    pub dependencies: BTreeMap<String, String>,
    /// Optional dependencies
    pub optional_dependencies: BTreeMap<String, String>,
    /// Peer dependencies (npm-specific)
    pub peer_dependencies: BTreeMap<String, String>,
    /// Peer dependency metadata (npm peerDependenciesMeta).
    /// Maps peer dependency name to its metadata (e.g., optional: true).
    #[serde(default)]
    pub peer_dependencies_meta: BTreeMap<String, PeerDependencyMeta>,
    /// Dev dependencies
    pub dev_dependencies: BTreeMap<String, String>,
    /// Bundled dependencies (npm bundledDependencies/bundleDependencies).
    /// These are included in the package tarball and should be skipped from resolution.
    #[serde(default)]
    pub bundled_dependencies: Vec<String>,
    /// Features/extras available (list of feature names)
    pub features: Vec<String>,
    /// Feature definitions: feature_name -> [enabled_features_or_deps]
    /// For Rust crates: maps feature names to what they enable
    /// Example: "full" => ["derive", "parsing", "printing"]
    #[serde(default)]
    pub feature_definitions: BTreeMap<String, Vec<String>>,
}

impl PackageMetadata {
    /// Create new package metadata with required fields.
    pub fn new(name: String, version: String, dist_url: String, integrity: String) -> Self {
        Self {
            name,
            version,
            dist_url,
            integrity,
            dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
            peer_dependencies_meta: BTreeMap::new(),
            dev_dependencies: BTreeMap::new(),
            bundled_dependencies: Vec::new(),
            features: Vec::new(),
            feature_definitions: BTreeMap::new(),
        }
    }
}

/// Trait for registry clients.
#[async_trait]
pub trait RegistryClient: Send + Sync {
    /// Get the ecosystem this registry serves.
    fn ecosystem(&self) -> Ecosystem;

    /// Get the base registry URL for policy evaluation.
    fn registry_url(&self) -> &str;

    /// Fetch available versions for a package.
    async fn fetch_versions(&self, name: &str) -> Result<Vec<String>>;

    /// Fetch metadata for a specific version.
    async fn fetch_metadata(&self, name: &str, version: &str) -> Result<PackageMetadata>;

    /// Download a package tarball/archive.
    async fn download(&self, name: &str, version: &str) -> Result<Vec<u8>>;

    /// Search for packages (optional, not all registries support this).
    async fn search(&self, _query: &str, _limit: usize) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

/// A combined registry client that routes to ecosystem-specific clients.
pub struct Registry {
    clients: BTreeMap<Ecosystem, Arc<dyn RegistryClient>>,
    http_client: reqwest::Client,
    cache: Option<RegistryCache>,
    offline: bool,
    /// Rate limiter to prevent registry bans (10 requests per second with burst of 20)
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    /// Optional registry access policy for domain-level access control
    policy: Option<RegistryPolicy>,
}

/// Builder for configuring a Registry.
pub struct RegistryBuilder {
    offline: bool,
    cache: Option<RegistryCache>,
    root_certificates: Vec<reqwest::Certificate>,
    policy: Option<RegistryPolicy>,
}

impl RegistryBuilder {
    /// Create a new RegistryBuilder.
    pub fn new() -> Self {
        Self {
            offline: false,
            cache: None,
            root_certificates: Vec::new(),
            policy: None,
        }
    }

    /// Set offline mode.
    pub fn offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Set the registry cache.
    pub fn cache(mut self, cache: RegistryCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the registry access policy.
    pub fn policy(mut self, policy: RegistryPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Add a custom root certificate (PEM format).
    ///
    /// This is crucial for enterprise environments with private CAs or proxies.
    pub fn add_root_certificate(mut self, cert: reqwest::Certificate) -> Self {
        self.root_certificates.push(cert);
        self
    }

    /// Build the Registry.
    pub fn build(self) -> Result<Registry> {
        let mut client_builder = reqwest::Client::builder()
            .user_agent(concat!("cratons/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .pool_max_idle_per_host(10);

        // Add custom root certificates
        for cert in self.root_certificates {
            client_builder = client_builder.add_root_certificate(cert);
        }

        let http_client = client_builder
            .build()
            .map_err(|e| CratonsError::Network(e.to_string()))?;

        // Create rate limiter: 10 requests/second with burst of 20
        let rate_limiter = Arc::new(RateLimiter::direct(
            Quota::per_second(NonZeroU32::new(10).unwrap())
                .allow_burst(NonZeroU32::new(20).unwrap()),
        ));

        let mut registry = Registry {
            clients: BTreeMap::new(),
            http_client: http_client.clone(),
            cache: self.cache,
            offline: self.offline,
            rate_limiter,
            policy: self.policy,
        };

        // Register default clients
        registry.add_client(Arc::new(NpmClient::new(http_client.clone())));
        registry.add_client(Arc::new(PyPiClient::new(http_client.clone())));
        registry.add_client(Arc::new(CratesIoClient::new(http_client.clone())));
        registry.add_client(Arc::new(GoProxyClient::new(http_client.clone())));
        registry.add_client(Arc::new(MavenClient::new(http_client)));

        Ok(registry)
    }
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// Create a new registry with default clients for all ecosystems.
    pub fn with_defaults(offline: bool) -> Result<Self> {
        Self::builder().offline(offline).build()
    }

    /// Create a new registry with default clients and an optional cache directory.
    pub fn with_defaults_and_cache(offline: bool, cache_dir: Option<&Path>) -> Result<Self> {
        let mut builder = Self::builder().offline(offline);
        if let Some(dir) = cache_dir {
            builder = builder.cache(RegistryCache::new(dir)?);
        }
        builder.build()
    }

    /// Create a new RegistryBuilder.
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::new()
    }

    /// Create an empty registry (for testing or custom setups).
    #[must_use]
    pub fn new(offline: bool) -> Self {
        Self::builder().offline(offline).build().unwrap()
    }

    /// Create an empty registry with a cache directory.
    pub fn new_with_cache(offline: bool, cache_dir: &Path) -> Result<Self> {
        Self::builder()
            .offline(offline)
            .cache(RegistryCache::new(cache_dir)?)
            .build()
    }

    /// Set or replace the registry cache.
    pub fn set_cache(&mut self, cache: RegistryCache) {
        self.cache = Some(cache);
    }

    /// Get the registry cache, if configured.
    #[must_use]
    pub fn cache(&self) -> Option<&RegistryCache> {
        self.cache.as_ref()
    }

    /// Add a client for an ecosystem.
    pub fn add_client(&mut self, client: Arc<dyn RegistryClient>) {
        self.clients.insert(client.ecosystem(), client);
    }

    /// Get the client for an ecosystem.
    #[must_use]
    pub fn client(&self, ecosystem: Ecosystem) -> Option<Arc<dyn RegistryClient>> {
        self.clients.get(&ecosystem).cloned()
    }

    /// Get the shared HTTP client.
    #[must_use]
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Check if the registry has any clients registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Get the number of registered clients.
    #[must_use]
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Check registry access policy for the given ecosystem and operation.
    fn check_policy(
        &self,
        ecosystem: Ecosystem,
        operation: policy::RegistryOperation,
    ) -> Result<()> {
        if let Some(ref policy) = self.policy {
            if !policy.has_rules() {
                return Ok(());
            }
            if let Some(client) = self.client(ecosystem) {
                let url = client.registry_url();
                if let Some(domain) = policy::extract_domain(url) {
                    policy.check(&domain, operation).map_err(|reason| {
                        CratonsError::RegistryAccessDenied {
                            registry: domain,
                            reason,
                        }
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Fetch versions from the appropriate registry.
    ///
    /// In offline mode, returns cached versions or an error if not cached.
    /// In online mode, uses cache if fresh, otherwise fetches from network and caches.
    pub async fn fetch_versions(&self, ecosystem: Ecosystem, name: &str) -> Result<Vec<String>> {
        self.check_policy(ecosystem, policy::RegistryOperation::Read)?;
        // Try cache first
        if let Some(cache) = &self.cache {
            // In offline mode, return cached data regardless of freshness
            if self.offline {
                if let Some(versions) = cache.get_versions(ecosystem, name) {
                    info!("Offline: using cached versions for {}:{}", ecosystem, name);
                    return Ok(versions);
                }
                // No cache available in offline mode - this is an error
                return Err(CratonsError::Network(format!(
                    "Offline mode: No cached versions for {}:{} - run online first to populate cache",
                    ecosystem, name
                )));
            }

            // Online mode: check if cache is fresh
            if cache.is_versions_fresh(ecosystem, name) {
                if let Some(versions) = cache.get_versions(ecosystem, name) {
                    debug!("Cache hit for {}:{} versions", ecosystem, name);
                    return Ok(versions);
                }
            }
        } else if self.offline {
            // Offline mode but no cache configured
            return Err(CratonsError::Network(format!(
                "Offline mode: No cache configured, cannot fetch versions for {}:{}",
                ecosystem, name
            )));
        }

        // Wait for rate limiter before making network request
        self.wait_for_rate_limit().await;

        // Fetch from network
        let client = self
            .client(ecosystem)
            .ok_or_else(|| CratonsError::Registry {
                registry: ecosystem.to_string(),
                message: "No client registered for ecosystem".to_string(),
            })?;

        let versions = client.fetch_versions(name).await?;

        // Cache the result
        if let Some(cache) = &self.cache {
            if let Err(e) = cache.put_versions(ecosystem, name, versions.clone()) {
                warn!("Failed to cache versions for {}:{}: {}", ecosystem, name, e);
            }
        }

        Ok(versions)
    }

    /// Fetch metadata from the appropriate registry.
    ///
    /// In offline mode, returns cached metadata or an error if not cached.
    /// In online mode, uses cache if fresh, otherwise fetches from network and caches.
    pub async fn fetch_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<PackageMetadata> {
        self.check_policy(ecosystem, policy::RegistryOperation::Read)?;

        // Try cache first
        if let Some(cache) = &self.cache {
            // In offline mode, return cached data regardless of freshness
            if self.offline {
                if let Some(cached) = cache.get_metadata(ecosystem, name, version) {
                    info!(
                        "Offline: using cached metadata for {}:{}@{}",
                        ecosystem, name, version
                    );
                    return Ok(cached_to_metadata(cached));
                }
                // No cache available in offline mode - this is an error
                return Err(CratonsError::Network(format!(
                    "Offline mode: No cached metadata for {}:{}@{} - run online first to populate cache",
                    ecosystem, name, version
                )));
            }

            // Online mode: check if cache is fresh
            if cache.is_metadata_fresh(ecosystem, name, version) {
                if let Some(cached) = cache.get_metadata(ecosystem, name, version) {
                    debug!("Cache hit for {}:{}@{} metadata", ecosystem, name, version);
                    return Ok(cached_to_metadata(cached));
                }
            }
        } else if self.offline {
            // Offline mode but no cache configured
            return Err(CratonsError::Network(format!(
                "Offline mode: No cache configured, cannot fetch metadata for {}:{}@{}",
                ecosystem, name, version
            )));
        }

        // Wait for rate limiter before making network request
        self.wait_for_rate_limit().await;

        // Fetch from network
        let client = self
            .client(ecosystem)
            .ok_or_else(|| CratonsError::Registry {
                registry: ecosystem.to_string(),
                message: "No client registered for ecosystem".to_string(),
            })?;

        let metadata = client.fetch_metadata(name, version).await?;

        // Cache the result
        if let Some(cache) = &self.cache {
            let cached = metadata_to_cached(&metadata, ecosystem);
            if let Err(e) = cache.put_metadata(cached) {
                warn!(
                    "Failed to cache metadata for {}:{}@{}: {}",
                    ecosystem, name, version, e
                );
            }
        }

        Ok(metadata)
    }

    /// Download from the appropriate registry.
    ///
    /// Note: Downloads are not cached here - they go to the content-addressable store.
    /// In offline mode, downloads fail - the installer should check CAS first.
    pub async fn download(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<Vec<u8>> {
        self.check_policy(ecosystem, policy::RegistryOperation::Download)?;

        if self.offline {
            return Err(CratonsError::Network(format!(
                "Offline mode: Cannot download {}:{}@{} - check content-addressable store",
                ecosystem, name, version
            )));
        }

        // Wait for rate limiter before making network request
        self.wait_for_rate_limit().await;

        let client = self
            .client(ecosystem)
            .ok_or_else(|| CratonsError::Registry {
                registry: ecosystem.to_string(),
                message: "No client registered for ecosystem".to_string(),
            })?;
        client.download(name, version).await
    }

    /// Check if running in offline mode.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.offline
    }

    /// Wait for rate limiter before making a request.
    async fn wait_for_rate_limit(&self) {
        self.rate_limiter.until_ready().await;
    }
}

/// Convert CachedMetadata to PackageMetadata.
fn cached_to_metadata(cached: CachedMetadata) -> PackageMetadata {
    PackageMetadata {
        name: cached.name,
        version: cached.version,
        dist_url: cached.dist_url,
        integrity: cached.integrity,
        // Convert HashMap to BTreeMap for deterministic ordering
        dependencies: cached.dependencies.into_iter().collect(),
        optional_dependencies: cached.optional_dependencies.into_iter().collect(),
        peer_dependencies: cached.peer_dependencies.into_iter().collect(),
        peer_dependencies_meta: cached
            .peer_dependencies_meta
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    PeerDependencyMeta {
                        optional: v.optional,
                    },
                )
            })
            .collect(),
        dev_dependencies: cached.dev_dependencies.into_iter().collect(),
        bundled_dependencies: cached.bundled_dependencies,
        features: cached.features,
        feature_definitions: BTreeMap::new(), // Cache doesn't store feature definitions
    }
}

/// Convert PackageMetadata to CachedMetadata.
fn metadata_to_cached(metadata: &PackageMetadata, ecosystem: Ecosystem) -> CachedMetadata {
    use cratons_store::CachedPeerDepMeta;
    CachedMetadata {
        name: metadata.name.clone(),
        version: metadata.version.clone(),
        ecosystem: ecosystem.to_string(),
        dist_url: metadata.dist_url.clone(),
        integrity: metadata.integrity.clone(),
        // Convert BTreeMap to HashMap for cache storage
        dependencies: metadata
            .dependencies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        optional_dependencies: metadata
            .optional_dependencies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        peer_dependencies: metadata
            .peer_dependencies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        peer_dependencies_meta: metadata
            .peer_dependencies_meta
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    CachedPeerDepMeta {
                        optional: v.optional,
                    },
                )
            })
            .collect(),
        dev_dependencies: metadata
            .dev_dependencies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        bundled_dependencies: metadata.bundled_dependencies.clone(),
        features: metadata.features.clone(),
        cached_at: std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new(false)
    }
}

/// Mock registry client for testing.
#[cfg(test)]
pub struct MockRegistry {
    ecosystem: Ecosystem,
    packages: BTreeMap<String, Vec<String>>,
}

#[cfg(test)]
#[allow(dead_code)]
impl MockRegistry {
    /// Create a new mock registry for the given ecosystem.
    pub fn new(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            packages: BTreeMap::new(),
        }
    }

    /// Add a package with the given versions to the mock registry.
    pub fn add_package(&mut self, name: &str, versions: Vec<&str>) {
        self.packages.insert(
            name.to_string(),
            versions.into_iter().map(String::from).collect(),
        );
    }
}

#[cfg(test)]
#[async_trait]
impl RegistryClient for MockRegistry {
    fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    fn registry_url(&self) -> &str {
        "https://mock.registry.test"
    }

    async fn fetch_versions(&self, name: &str) -> Result<Vec<String>> {
        Ok(self.packages.get(name).cloned().unwrap_or_default())
    }

    async fn fetch_metadata(&self, name: &str, version: &str) -> Result<PackageMetadata> {
        Ok(PackageMetadata::new(
            name.to_string(),
            version.to_string(),
            format!("https://example.com/{name}/{version}.tgz"),
            "sha256-mock".to_string(),
        ))
    }

    async fn download(&self, _name: &str, _version: &str) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_offline_mode_with_cache() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("cache");

        // First, fetch online and populate cache
        let mut registry = Registry::new_with_cache(false, &cache_path).unwrap();
        let mut mock = MockRegistry::new(Ecosystem::Npm);
        mock.add_package("lodash", vec!["4.17.21", "4.17.20"]);
        registry.add_client(Arc::new(mock));

        // Fetch versions online - should cache
        let versions = registry
            .fetch_versions(Ecosystem::Npm, "lodash")
            .await
            .unwrap();
        assert_eq!(versions, vec!["4.17.21", "4.17.20"]);

        // Fetch metadata online - should cache
        let metadata = registry
            .fetch_metadata(Ecosystem::Npm, "lodash", "4.17.21")
            .await
            .unwrap();
        assert_eq!(metadata.name, "lodash");
        assert_eq!(metadata.version, "4.17.21");

        // Now create an offline registry with the same cache
        let mut offline_registry = Registry::new_with_cache(true, &cache_path).unwrap();
        let offline_mock = MockRegistry::new(Ecosystem::Npm);
        // Note: Mock is empty, but cache should serve
        offline_registry.add_client(Arc::new(offline_mock));

        // Should serve from cache
        let cached_versions = offline_registry
            .fetch_versions(Ecosystem::Npm, "lodash")
            .await
            .unwrap();
        assert_eq!(cached_versions, vec!["4.17.21", "4.17.20"]);

        let cached_metadata = offline_registry
            .fetch_metadata(Ecosystem::Npm, "lodash", "4.17.21")
            .await
            .unwrap();
        assert_eq!(cached_metadata.name, "lodash");
    }

    #[tokio::test]
    async fn test_offline_mode_no_cache_errors() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("cache");

        // Create offline registry with empty cache
        let mut offline_registry = Registry::new_with_cache(true, &cache_path).unwrap();
        let mock = MockRegistry::new(Ecosystem::Npm);
        offline_registry.add_client(Arc::new(mock));

        // Should fail with helpful message
        let result = offline_registry
            .fetch_versions(Ecosystem::Npm, "lodash")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Offline mode"));
        assert!(err.contains("No cached versions"));
    }

    #[tokio::test]
    async fn test_online_mode_caches_results() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("cache");

        let mut registry = Registry::new_with_cache(false, &cache_path).unwrap();
        let mut mock = MockRegistry::new(Ecosystem::Npm);
        mock.add_package("express", vec!["4.18.2"]);
        registry.add_client(Arc::new(mock));

        // Fetch should cache
        let _versions = registry
            .fetch_versions(Ecosystem::Npm, "express")
            .await
            .unwrap();

        // Verify cache was populated
        let cache = registry.cache().unwrap();
        assert!(cache.get_versions(Ecosystem::Npm, "express").is_some());
    }

    #[test]
    fn test_is_offline() {
        let online_registry = Registry::new(false);
        assert!(!online_registry.is_offline());

        let offline_registry = Registry::new(true);
        assert!(offline_registry.is_offline());
    }
}
