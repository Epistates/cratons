//! Integration tests using WireMock.

use async_trait::async_trait;
use cratons_core::{Ecosystem, Result};
use cratons_manifest::Manifest;
use cratons_resolver::Resolver;
use cratons_resolver::registry::{PackageMetadata, RegistryClient};
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Mock client that uses wiremock
struct MockWiremockClient {
    base_url: String,
    client: reqwest::Client,
}

impl MockWiremockClient {
    fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl RegistryClient for MockWiremockClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    async fn fetch_versions(&self, name: &str) -> Result<Vec<String>> {
        let url = format!("{}/{}/versions", self.base_url, name);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| cratons_core::CratonsError::Network(e.to_string()))?;
        let versions: Vec<String> = response
            .json()
            .await
            .map_err(|e| cratons_core::CratonsError::Network(e.to_string()))?;
        Ok(versions)
    }

    async fn fetch_metadata(&self, name: &str, version: &str) -> Result<PackageMetadata> {
        let url = format!("{}/{}/{}/metadata", self.base_url, name, version);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| cratons_core::CratonsError::Network(e.to_string()))?;
        let metadata: PackageMetadata = response
            .json()
            .await
            .map_err(|e| cratons_core::CratonsError::Network(e.to_string()))?;
        Ok(metadata)
    }

    async fn download(&self, _name: &str, _version: &str) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    async fn search(&self, _query: &str, _limit: usize) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

#[tokio::test]
async fn test_resolver_with_wiremock() {
    // Start wiremock server
    let mock_server = MockServer::start().await;

    // Mock versions response
    Mock::given(method("GET"))
        .and(path("/test-pkg/versions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(vec!["1.0.0", "1.1.0"]))
        .mount(&mock_server)
        .await;

    // Mock metadata response for 1.0.0
    let metadata_1_0_0 = PackageMetadata {
        name: "test-pkg".to_string(),
        version: "1.0.0".to_string(),
        dist_url: "http://example.com/dist".to_string(),
        integrity: "sha256-123".to_string(),
        dependencies: std::collections::BTreeMap::new(),
        optional_dependencies: std::collections::BTreeMap::new(),
        peer_dependencies: std::collections::BTreeMap::new(),
        peer_dependencies_meta: std::collections::BTreeMap::new(),
        dev_dependencies: std::collections::BTreeMap::new(),
        bundled_dependencies: vec![],
        features: vec![],
        feature_definitions: std::collections::BTreeMap::new(),
    };

    Mock::given(method("GET"))
        .and(path("/test-pkg/1.0.0/metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_1_0_0))
        .mount(&mock_server)
        .await;

    // Setup resolver with mock client
    let mut resolver = Resolver::new(false);
    let client = Arc::new(MockWiremockClient::new(mock_server.uri()));
    resolver.add_registry(client);

    // Create manifest
    let manifest_str = r#"
        [package]
        name = "app"
        version = "0.0.1"

        [dependencies.npm]
        test-pkg = "=1.0.0"
    "#;
    let manifest = Manifest::from_str(manifest_str).unwrap();

    // Resolve
    let resolution = resolver.resolve(&manifest).await.unwrap();

    // Verify
    assert_eq!(resolution.package_count(), 1);
    let pkg = resolution.packages.first().unwrap();
    assert_eq!(pkg.name, "test-pkg");
    assert_eq!(pkg.version, "1.0.0");
    assert_eq!(pkg.ecosystem, Ecosystem::Npm);
}

#[tokio::test]
async fn test_resolution_strategy_override() {
    use cratons_core::ResolutionStrategy;

    // Start wiremock server
    let mock_server = MockServer::start().await;

    // Mock versions response
    Mock::given(method("GET"))
        .and(path("/test-pkg/versions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(vec!["1.0.0", "1.1.0"]))
        .mount(&mock_server)
        .await;

    // Mock metadata response for 1.0.0 (Minimal)
    let metadata_1_0_0 = PackageMetadata {
        name: "test-pkg".to_string(),
        version: "1.0.0".to_string(),
        dist_url: "http://example.com/dist".to_string(),
        integrity: "sha256-123".to_string(),
        dependencies: std::collections::BTreeMap::new(),
        optional_dependencies: std::collections::BTreeMap::new(),
        peer_dependencies: std::collections::BTreeMap::new(),
        peer_dependencies_meta: std::collections::BTreeMap::new(),
        dev_dependencies: std::collections::BTreeMap::new(),
        bundled_dependencies: vec![],
        features: vec![],
        feature_definitions: std::collections::BTreeMap::new(),
    };

    Mock::given(method("GET"))
        .and(path("/test-pkg/1.0.0/metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_1_0_0))
        .mount(&mock_server)
        .await;

    // Setup resolver with mock client
    let mut resolver = Resolver::new(false);
    let client = Arc::new(MockWiremockClient::new(mock_server.uri()));
    resolver.add_registry(client);

    // Create manifest with override
    let mut manifest = Manifest::default();
    manifest.package.name = "app".to_string();
    manifest.package.version = "0.0.1".to_string();

    // Add dependency
    let mut deps = cratons_manifest::Dependencies::default();
    deps.npm.insert(
        "test-pkg".to_string(),
        cratons_manifest::Dependency::Version(">=1.0.0".to_string()),
    );
    manifest.dependencies = deps;

    // Add override
    manifest
        .resolution
        .insert(Ecosystem::Npm, ResolutionStrategy::Minimal);

    // Resolve
    let resolution = resolver.resolve(&manifest).await.unwrap();

    // Verify
    assert_eq!(resolution.package_count(), 1);
    let pkg = resolution.packages.first().unwrap();
    assert_eq!(pkg.name, "test-pkg");
    assert_eq!(pkg.version, "1.0.0"); // Minimal should pick 1.0.0, even though 1.1.0 is available
}
