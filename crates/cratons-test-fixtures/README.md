# cratons-test-fixtures

Comprehensive test fixtures, builders, mocks, and property-based testing utilities for the Cratons package manager.

## Overview

This crate provides a complete suite of testing utilities designed to make it easy to write robust tests for Cratons's package management functionality. It includes:

- **Builder patterns** for creating test data structures with fluent APIs
- **Pre-configured fixtures** for common test scenarios across multiple ecosystems
- **Mock implementations** of registries and remote caches
- **WireMock helpers** for HTTP testing
- **Property-based testing strategies** using proptest

## Features

### Builders

Create complex test data with readable, fluent APIs:

```rust
use cratons_test_fixtures::builders::ManifestBuilder;

let manifest = ManifestBuilder::new("my-app")
    .version("1.0.0")
    .description("A test application")
    .npm_dependency("lodash", "^4.17.0")
    .pypi_dependency("requests", ">=2.28.0")
    .node_version("20.10.0")
    .build();
```

Available builders:
- `ManifestBuilder` - Build test manifests with dependencies and environment configs
- `LockfileBuilder` - Build lockfiles with locked packages
- `PackageSpecBuilder` - Build package specifications with version requirements
- `PackageBuilder` - Build package metadata
- `DependencyGraphBuilder` - Build dependency graphs for MVS testing

### Fixtures

Pre-configured test data for common scenarios:

```rust
use cratons_test_fixtures::fixtures::{manifests, lockfiles, packages};

// Get a simple Node.js manifest
let manifest = manifests::simple_nodejs();

// Get a lockfile with npm packages
let lockfile = lockfiles::simple_npm();

// Get sample package metadata
let metadata = packages::npm_lodash_spec();
```

Available fixture modules:
- `manifests` - Sample manifests (minimal, Node.js, Python, Rust, polyglot, workspace)
- `lockfiles` - Sample lockfiles (empty, simple, complex, polyglot)
- `packages` - Sample package IDs and specs
- `registry_responses` - JSON responses for registry mocking

### Mocks

In-memory mock implementations for testing without network:

```rust
use cratons_test_fixtures::mocks::MockRegistry;
use cratons_core::Ecosystem;

let mut registry = MockRegistry::new(Ecosystem::Npm);
registry.add_package("lodash", "4.17.21", r#"{"name": "lodash"}"#);

let metadata = registry.get_package("lodash", Some("4.17.21")).unwrap();
assert_eq!(registry.request_count(), 1);
```

Available mocks:
- `MockRegistry` - In-memory package registry
- `MockRemoteCache` - Content-addressable cache with hit/miss tracking
- `WireMockExt` - Extension trait for MockServer with registry-specific helpers

### WireMock Integration

Helpers for testing HTTP interactions:

```rust
use cratons_test_fixtures::mocks::WireMockExt;
use wiremock::MockServer;

#[tokio::test]
async fn test_npm_registry() {
    let server = MockServer::start().await;

    server.mock_npm_package("lodash", "4.17.21", serde_json::json!({
        "name": "lodash",
        "version": "4.17.21"
    })).await;

    // Make requests to server.uri()
}
```

Available WireMock helpers:
- `mock_npm_package()` - Mock npm package metadata endpoint
- `mock_npm_tarball()` - Mock npm tarball download
- `mock_pypi_package()` - Mock PyPI package metadata
- `mock_pypi_wheel()` - Mock PyPI wheel download
- `mock_crates_metadata()` - Mock crates.io metadata
- `mock_crates_download()` - Mock crates.io download
- `mock_not_found()` - Mock 404 responses
- `mock_rate_limit()` - Mock 429 rate limit responses
- `mock_server_error()` - Mock 500 errors

### Property-Based Testing

Generate random valid test data using proptest:

```rust
use cratons_test_fixtures::proptest::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_package_id_roundtrip(id in package_id_strategy()) {
        let string = id.to_string();
        assert!(string.contains(':'));
    }
}
```

Available strategies:
- `ecosystem_strategy()` - Random ecosystems
- `version_strategy()` - Random versions
- `version_req_strategy()` - Random version requirements
- `package_id_strategy()` - Random package IDs
- `package_spec_strategy()` - Random package specs
- `locked_package_strategy()` - Random locked packages
- `lockfile_strategy()` - Random lockfiles
- `manifest_strategy()` - Random manifests
- `dependency_graph_strategy()` - Random dependency graphs

## Usage Examples

### Testing Package Resolution

```rust
use cratons_test_fixtures::builders::DependencyGraphBuilder;
use cratons_core::Ecosystem;

#[test]
fn test_diamond_dependency_resolution() {
    // Create a diamond dependency graph
    let graph = DependencyGraphBuilder::diamond(Ecosystem::Npm);

    // Run your resolver against the graph
    assert_eq!(graph.node_count(), 5);
}
```

### Testing Registry Interactions

```rust
use cratons_test_fixtures::mocks::MockRegistryServer;
use cratons_core::Ecosystem;

#[tokio::test]
async fn test_registry_client() {
    let server = MockRegistryServer::new(Ecosystem::Npm).await;

    server.add_package("lodash", "4.17.21", serde_json::json!({
        "name": "lodash",
        "version": "4.17.21"
    })).await;

    // Test your registry client against server.url()
}
```

### Testing with Property-Based Tests

```rust
use cratons_test_fixtures::proptest::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_lockfile_serialization(lockfile in lockfile_strategy()) {
        let toml = lockfile.to_toml_string().unwrap();
        let parsed = Lockfile::from_str(&toml).unwrap();
        assert_eq!(parsed.packages.len(), lockfile.packages.len());
    }
}
```

## Dependencies

This crate bundles several testing libraries for convenience:

- `proptest` - Property-based testing framework
- `fake` - Fake data generation
- `wiremock` - HTTP mocking
- `tempfile` - Temporary file and directory creation
- `tokio` - Async runtime for testing

All are re-exported from the root for easy access:

```rust
use cratons_test_fixtures::{proptest, fake, wiremock, tempfile};
```

## Best Practices

1. **Use builders for complex objects** - They provide clear, self-documenting test setup
2. **Use fixtures for common scenarios** - Don't recreate standard test data
3. **Use mocks for unit tests** - Avoid network calls in unit tests
4. **Use WireMock for integration tests** - Test actual HTTP interactions
5. **Use property tests for invariants** - Validate properties across many inputs

## Contributing

When adding new test utilities:

1. Follow the existing patterns (builders, fixtures, mocks, strategies)
2. Add comprehensive documentation and examples
3. Include tests for the test utilities themselves
4. Update this README with usage examples

## License

MIT OR Apache-2.0
