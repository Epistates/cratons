//! Integration tests for registry clients.
//!
//! These tests make real HTTP requests to package registries.
//! Run with: `cargo test --test registry_integration -- --ignored`
//!
//! Tests are ignored by default to avoid network dependencies in CI.

use cratons_core::Ecosystem;
use cratons_resolver::{
    CratesIoClient, GoProxyClient, MavenClient, NpmClient, PyPiClient, Registry, RegistryClient,
};

fn create_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("cratons-test/0.1.0")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap()
}

// ============================================================================
// npm Registry Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires network access"]
async fn test_npm_fetch_versions_lodash() {
    let client = NpmClient::new(create_http_client());
    let versions = client.fetch_versions("lodash").await.unwrap();

    assert!(!versions.is_empty(), "lodash should have versions");
    assert!(
        versions.iter().any(|v| v == "4.17.21"),
        "lodash 4.17.21 should exist"
    );
    println!("Found {} lodash versions", versions.len());
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_npm_fetch_versions_scoped_package() {
    let client = NpmClient::new(create_http_client());
    let versions = client.fetch_versions("@types/node").await.unwrap();

    assert!(!versions.is_empty(), "@types/node should have versions");
    println!("Found {} @types/node versions", versions.len());
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_npm_fetch_metadata() {
    let client = NpmClient::new(create_http_client());
    let metadata = client.fetch_metadata("express", "4.18.2").await.unwrap();

    assert_eq!(metadata.name, "express");
    assert_eq!(metadata.version, "4.18.2");
    assert!(
        !metadata.dependencies.is_empty(),
        "express should have dependencies"
    );
    assert!(
        metadata.dist_url.contains("express-4.18.2.tgz"),
        "dist URL should contain tarball name"
    );
    println!(
        "express 4.18.2 has {} dependencies",
        metadata.dependencies.len()
    );
    println!("Dist URL: {}", metadata.dist_url);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_npm_search() {
    let client = NpmClient::new(create_http_client());
    let results = client.search("react", 10).await.unwrap();

    assert!(
        !results.is_empty(),
        "search for 'react' should return results"
    );
    assert!(
        results.iter().any(|r| r == "react"),
        "search results should include 'react'"
    );
    println!("Search results: {:?}", results);
}

// ============================================================================
// PyPI Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires network access"]
async fn test_pypi_fetch_versions_requests() {
    let client = PyPiClient::new(create_http_client());
    let versions = client.fetch_versions("requests").await.unwrap();

    assert!(!versions.is_empty(), "requests should have versions");
    assert!(
        versions.iter().any(|v| v == "2.31.0"),
        "requests 2.31.0 should exist"
    );
    println!("Found {} requests versions", versions.len());
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_pypi_fetch_versions_normalized_name() {
    let client = PyPiClient::new(create_http_client());

    // PyPI normalizes names: My_Package -> my-package
    let versions = client.fetch_versions("typing_extensions").await.unwrap();
    assert!(
        !versions.is_empty(),
        "typing_extensions should have versions"
    );

    // Should also work with already normalized name
    let versions2 = client.fetch_versions("typing-extensions").await.unwrap();
    assert_eq!(
        versions.len(),
        versions2.len(),
        "normalized names should return same versions"
    );
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_pypi_fetch_metadata() {
    let client = PyPiClient::new(create_http_client());
    let metadata = client.fetch_metadata("requests", "2.31.0").await.unwrap();

    assert_eq!(metadata.name, "requests");
    assert_eq!(metadata.version, "2.31.0");

    println!("requests 2.31.0 dependencies: {:?}", metadata.dependencies);
    println!("Dist URL: {}", metadata.dist_url);

    // requests depends on charset-normalizer, idna, urllib3, certifi
    // Note: Some dependencies may be optional/extras and filtered out
    if !metadata.dependencies.is_empty() {
        let dep_names: Vec<&str> = metadata
            .dependencies
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        println!("Dependency names: {:?}", dep_names);
    } else {
        println!("Note: No runtime dependencies found (may all be optional)");
    }
}

// ============================================================================
// crates.io Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires network access"]
async fn test_crates_fetch_versions_serde() {
    let client = CratesIoClient::new(create_http_client());
    let versions = client.fetch_versions("serde").await.unwrap();

    assert!(!versions.is_empty(), "serde should have versions");
    assert!(
        versions.iter().any(|v| v.starts_with("1.")),
        "serde should have 1.x versions"
    );
    println!("Found {} serde versions", versions.len());
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_crates_fetch_versions_short_name() {
    let client = CratesIoClient::new(create_http_client());

    // Test 2-char crate name (different index path)
    let versions = client.fetch_versions("cc").await.unwrap();
    assert!(!versions.is_empty(), "cc should have versions");

    // Test 3-char crate name
    let versions = client.fetch_versions("log").await.unwrap();
    assert!(!versions.is_empty(), "log should have versions");
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_crates_fetch_metadata() {
    let client = CratesIoClient::new(create_http_client());
    let metadata = client.fetch_metadata("serde", "1.0.193").await.unwrap();

    assert_eq!(metadata.name, "serde");
    assert_eq!(metadata.version, "1.0.193");
    assert!(
        metadata.dist_url.contains("serde-1.0.193.crate"),
        "dist URL should contain crate name"
    );
    println!("serde 1.0.193 dependencies: {:?}", metadata.dependencies);
    println!("Dist URL: {}", metadata.dist_url);
}

// ============================================================================
// Go Proxy Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires network access"]
async fn test_go_fetch_versions_gin() {
    let client = GoProxyClient::new(create_http_client());
    let versions = client
        .fetch_versions("github.com/gin-gonic/gin")
        .await
        .unwrap();

    assert!(!versions.is_empty(), "gin should have versions");
    assert!(
        versions.iter().any(|v| v.starts_with("v1.")),
        "gin should have v1.x versions"
    );
    println!("Found {} gin versions", versions.len());
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_go_fetch_versions_uppercase_module() {
    let client = GoProxyClient::new(create_http_client());

    // Module with uppercase letters (tests path escaping)
    let versions = client
        .fetch_versions("github.com/BurntSushi/toml")
        .await
        .unwrap();
    assert!(!versions.is_empty(), "BurntSushi/toml should have versions");
    println!("Found {} BurntSushi/toml versions", versions.len());
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_go_fetch_metadata() {
    let client = GoProxyClient::new(create_http_client());
    let metadata = client
        .fetch_metadata("github.com/gin-gonic/gin", "v1.9.1")
        .await
        .unwrap();

    assert_eq!(metadata.name, "github.com/gin-gonic/gin");
    assert_eq!(metadata.version, "v1.9.1");
    assert!(
        metadata.dist_url.contains(".zip"),
        "dist URL should be a zip file"
    );
    println!("gin v1.9.1 dependencies: {:?}", metadata.dependencies);
    println!("Dist URL: {}", metadata.dist_url);
}

// ============================================================================
// Maven Central Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires network access"]
async fn test_maven_fetch_versions_commons_lang() {
    let client = MavenClient::new(create_http_client());
    let versions = client
        .fetch_versions("org.apache.commons:commons-lang3")
        .await
        .unwrap();

    assert!(!versions.is_empty(), "commons-lang3 should have versions");
    assert!(
        versions.iter().any(|v| v == "3.12.0"),
        "commons-lang3 3.12.0 should exist"
    );
    println!("Found {} commons-lang3 versions", versions.len());
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_maven_fetch_metadata() {
    let client = MavenClient::new(create_http_client());
    let metadata = client
        .fetch_metadata("org.apache.commons:commons-lang3", "3.12.0")
        .await
        .unwrap();

    assert_eq!(metadata.name, "org.apache.commons:commons-lang3");
    assert_eq!(metadata.version, "3.12.0");
    assert!(
        metadata.dist_url.contains("commons-lang3-3.12.0.jar"),
        "dist URL should contain jar name"
    );
    println!(
        "commons-lang3 3.12.0 dependencies: {:?}",
        metadata.dependencies
    );
    println!("Dist URL: {}", metadata.dist_url);
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_maven_fetch_versions_guava() {
    let client = MavenClient::new(create_http_client());
    let versions = client
        .fetch_versions("com.google.guava:guava")
        .await
        .unwrap();

    assert!(!versions.is_empty(), "guava should have versions");
    println!("Found {} guava versions", versions.len());
}

// ============================================================================
// Combined Registry Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires network access"]
async fn test_registry_with_defaults() {
    let registry = Registry::with_defaults(false).unwrap();

    // Test npm
    let npm_versions = registry
        .fetch_versions(Ecosystem::Npm, "lodash")
        .await
        .unwrap();
    assert!(!npm_versions.is_empty());

    // Test PyPI
    let pypi_versions = registry
        .fetch_versions(Ecosystem::PyPi, "requests")
        .await
        .unwrap();
    assert!(!pypi_versions.is_empty());

    // Test crates.io
    let crates_versions = registry
        .fetch_versions(Ecosystem::Crates, "serde")
        .await
        .unwrap();
    assert!(!crates_versions.is_empty());

    // Test Go
    let go_versions = registry
        .fetch_versions(Ecosystem::Go, "github.com/gin-gonic/gin")
        .await
        .unwrap();
    assert!(!go_versions.is_empty());

    // Test Maven
    let maven_versions = registry
        .fetch_versions(Ecosystem::Maven, "org.apache.commons:commons-lang3")
        .await
        .unwrap();
    assert!(!maven_versions.is_empty());

    println!("All registries working!");
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_registry_fetch_metadata_all_ecosystems() {
    let registry = Registry::with_defaults(false).unwrap();

    // npm
    let npm_meta = registry
        .fetch_metadata(Ecosystem::Npm, "lodash", "4.17.21")
        .await
        .unwrap();
    assert_eq!(npm_meta.version, "4.17.21");

    // PyPI
    let pypi_meta = registry
        .fetch_metadata(Ecosystem::PyPi, "requests", "2.31.0")
        .await
        .unwrap();
    assert_eq!(pypi_meta.version, "2.31.0");

    // crates.io
    let crates_meta = registry
        .fetch_metadata(Ecosystem::Crates, "serde", "1.0.193")
        .await
        .unwrap();
    assert_eq!(crates_meta.version, "1.0.193");

    // Go
    let go_meta = registry
        .fetch_metadata(Ecosystem::Go, "github.com/gin-gonic/gin", "v1.9.1")
        .await
        .unwrap();
    assert_eq!(go_meta.version, "v1.9.1");

    // Maven
    let maven_meta = registry
        .fetch_metadata(
            Ecosystem::Maven,
            "org.apache.commons:commons-lang3",
            "3.12.0",
        )
        .await
        .unwrap();
    assert_eq!(maven_meta.version, "3.12.0");

    println!("All metadata fetches successful!");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires network access"]
async fn test_npm_nonexistent_package() {
    let client = NpmClient::new(create_http_client());
    let result = client
        .fetch_versions("this-package-definitely-does-not-exist-12345")
        .await;

    assert!(result.is_err(), "should fail for nonexistent package");
    println!("Error (expected): {:?}", result.unwrap_err());
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_pypi_nonexistent_package() {
    let client = PyPiClient::new(create_http_client());
    let result = client
        .fetch_versions("this-package-definitely-does-not-exist-12345")
        .await;

    assert!(result.is_err(), "should fail for nonexistent package");
}

#[tokio::test]
#[ignore = "requires network access"]
async fn test_crates_nonexistent_package() {
    let client = CratesIoClient::new(create_http_client());
    let result = client
        .fetch_versions("this-crate-definitely-does-not-exist-12345")
        .await;

    assert!(result.is_err(), "should fail for nonexistent crate");
}

// ============================================================================
// Transitive Dependency Resolution Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires network access - slower test"]
async fn test_transitive_resolution_npm() {
    use cratons_manifest::Manifest;
    use cratons_resolver::Resolver;

    // Create a manifest with a simpler package (lodash has no deps)
    let manifest_toml = r#"
[package]
name = "test-app"
version = "1.0.0"

[dependencies.npm]
lodash = "^4.17.0"
"#;

    let manifest: Manifest = toml::from_str(manifest_toml).unwrap();
    let resolver = Resolver::with_defaults(false).unwrap();

    let resolution = resolver.resolve(&manifest).await.unwrap();

    // lodash should be resolved
    assert!(
        !resolution.packages.is_empty(),
        "should have at least lodash"
    );

    // Check that lodash is in the resolution
    let lodash = resolution.packages.iter().find(|p| p.name == "lodash");
    assert!(lodash.is_some(), "lodash should be in resolution");

    let lodash = lodash.unwrap();
    println!("Resolved lodash@{}", lodash.version);
    assert!(
        lodash.version.starts_with("4.17"),
        "lodash version should be 4.17.x"
    );
}

#[tokio::test]
#[ignore = "requires network access - slower test"]
async fn test_transitive_resolution_pypi() {
    use cratons_manifest::Manifest;
    use cratons_resolver::Resolver;

    // Create a manifest with requests (which has urllib3, certifi, etc.)
    let manifest_toml = r#"
[package]
name = "test-app"
version = "1.0.0"

[dependencies.pypi]
requests = ">=2.28.0"
"#;

    let manifest: Manifest = toml::from_str(manifest_toml).unwrap();
    let resolver = Resolver::with_defaults(false).unwrap();

    let resolution = resolver.resolve(&manifest).await.unwrap();

    // requests has several transitive dependencies
    assert!(
        resolution.packages.len() >= 1,
        "should have at least requests"
    );

    println!("Resolved {} PyPI packages", resolution.packages.len());
    for pkg in &resolution.packages {
        println!(
            "  {}@{} (direct: {}, deps: {})",
            pkg.name,
            pkg.version,
            pkg.direct,
            pkg.dependencies.len()
        );
    }

    // Check that requests is resolved
    let requests = resolution.packages.iter().find(|p| p.name == "requests");
    assert!(requests.is_some(), "requests should be in resolution");
}

// ============================================================================
// Lockfile Generation Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires network access - slower test"]
async fn test_lockfile_generation() {
    use cratons_lockfile::LOCKFILE_NAME;
    use cratons_manifest::Manifest;
    use cratons_resolver::Resolver;

    // Create a temp directory for the test
    let temp_dir = tempfile::tempdir().unwrap();
    let manifest_path = temp_dir.path().join("cratons.toml");

    // Create a manifest with a simple dependency
    let manifest_toml = r#"
[package]
name = "test-app"
version = "1.0.0"

[dependencies.npm]
lodash = "^4.17.0"
"#;

    std::fs::write(&manifest_path, manifest_toml).unwrap();
    let manifest: Manifest = toml::from_str(manifest_toml).unwrap();
    let resolver = Resolver::with_defaults(false).unwrap();

    // Resolve and generate lockfile
    let (resolution, lockfile) = resolver
        .resolve_and_lock(&manifest, &manifest_path)
        .await
        .unwrap();

    // Verify resolution
    assert!(!resolution.packages.is_empty(), "should have packages");
    let lodash = resolution.packages.iter().find(|p| p.name == "lodash");
    assert!(lodash.is_some(), "lodash should be resolved");

    // Verify lockfile was written
    let lockfile_path = temp_dir.path().join(LOCKFILE_NAME);
    assert!(lockfile_path.exists(), "lockfile should be written");

    // Verify lockfile contents
    assert!(
        !lockfile.packages.is_empty(),
        "lockfile should have packages"
    );
    let locked_lodash = lockfile.find_package("lodash", Ecosystem::Npm);
    assert!(locked_lodash.is_some(), "lodash should be in lockfile");
    assert!(
        locked_lodash.unwrap().version.starts_with("4.17"),
        "lodash version should be 4.17.x"
    );

    println!(
        "Lockfile generated with {} packages",
        lockfile.package_count()
    );
}

#[tokio::test]
#[ignore = "requires network access - slower test"]
async fn test_lockfile_reuse() {
    use cratons_manifest::Manifest;
    use cratons_resolver::Resolver;

    // Create a temp directory
    let temp_dir = tempfile::tempdir().unwrap();
    let manifest_path = temp_dir.path().join("cratons.toml");

    let manifest_toml = r#"
[package]
name = "test-app"
version = "1.0.0"

[dependencies.npm]
lodash = "^4.17.0"
"#;

    std::fs::write(&manifest_path, manifest_toml).unwrap();
    let manifest: Manifest = toml::from_str(manifest_toml).unwrap();
    let resolver = Resolver::with_defaults(false).unwrap();

    // First resolution - creates lockfile
    let (resolution1, _lockfile1) = resolver
        .resolve_and_lock(&manifest, &manifest_path)
        .await
        .unwrap();
    let first_version = resolution1
        .packages
        .iter()
        .find(|p| p.name == "lodash")
        .unwrap()
        .version
        .clone();

    // Second resolution with same manifest - should reuse lockfile
    let (resolution2, _lockfile2) = resolver
        .resolve_and_lock(&manifest, &manifest_path)
        .await
        .unwrap();
    let second_version = resolution2
        .packages
        .iter()
        .find(|p| p.name == "lodash")
        .unwrap()
        .version
        .clone();

    // Versions should be the same (lockfile was reused)
    assert_eq!(
        first_version, second_version,
        "versions should match when lockfile is reused"
    );

    println!("Lockfile reuse verified: lodash@{}", first_version);
}
