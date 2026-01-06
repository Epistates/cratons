# cratons-resolver

Dependency resolution and registry clients for the Cratons package manager.

## Overview

This crate provides:

- **Minimal Version Selection (MVS)** dependency resolution
- **Registry clients** for npm, PyPI, crates.io, Go proxy, and Maven Central
- **Transitive dependency resolution** with cycle detection
- **Lockfile integration** for deterministic builds

## Dependency Resolution

### Basic Resolution

```rust
use cratons_resolver::{Resolver, resolve};
use cratons_manifest::Manifest;

// Simple API
let manifest = Manifest::load("cratons.toml")?;
let resolution = resolve(&manifest).await?;

println!("Resolved {} packages", resolution.package_count());
for pkg in &resolution.packages {
    println!("  {}@{} ({})", pkg.name, pkg.version, pkg.ecosystem);
}
```

### Resolution with Lockfile

```rust
use cratons_resolver::{Resolver, resolve_and_lock};
use cratons_manifest::Manifest;
use std::path::Path;

let manifest = Manifest::load("cratons.toml")?;
let manifest_path = Path::new("cratons.toml");

// Resolve and generate/update lockfile
let (resolution, lockfile) = resolve_and_lock(&manifest, manifest_path).await?;

// Lockfile is automatically saved to cratons.lock
println!("Resolved {} packages", resolution.package_count());
```

### Custom Resolver

```rust
use cratons_resolver::Resolver;
use cratons_manifest::Manifest;

let resolver = Resolver::with_defaults()?;

// Resolve from manifest
let manifest = Manifest::load("cratons.toml")?;
let resolution = resolver.resolve(&manifest).await?;

// Resolve with existing lockfile
let lockfile = Lockfile::load("cratons.lock")?;
let resolution = resolver.resolve_with_lockfile(&manifest, &lockfile).await?;
```

## Registry Clients

### npm Registry

```rust
use cratons_resolver::{NpmClient, RegistryClient};

let client = NpmClient::new(reqwest::Client::new());

// Fetch available versions
let versions = client.fetch_versions("lodash").await?;

// Fetch specific version metadata
let metadata = client.fetch_metadata("lodash", "4.17.21").await?;
println!("Tarball: {}", metadata.dist_url);
println!("Integrity: {}", metadata.integrity);

// Search packages
let results = client.search("react", 10).await?;
```

### PyPI

```rust
use cratons_resolver::{PyPiClient, RegistryClient};

let client = PyPiClient::new(reqwest::Client::new());

// Handles name normalization (typing_extensions -> typing-extensions)
let versions = client.fetch_versions("typing_extensions").await?;
let metadata = client.fetch_metadata("requests", "2.31.0").await?;
```

### crates.io

```rust
use cratons_resolver::{CratesIoClient, RegistryClient};

let client = CratesIoClient::new(reqwest::Client::new());

// Uses sparse index for efficient lookups
let versions = client.fetch_versions("serde").await?;
let metadata = client.fetch_metadata("serde", "1.0.193").await?;
```

### Go Module Proxy

```rust
use cratons_resolver::{GoProxyClient, RegistryClient};

let client = GoProxyClient::new(reqwest::Client::new());

// Full module paths
let versions = client.fetch_versions("github.com/gin-gonic/gin").await?;
let metadata = client.fetch_metadata("github.com/gin-gonic/gin", "v1.9.1").await?;

// Handles uppercase escaping (BurntSushi -> !burnt!sushi)
let versions = client.fetch_versions("github.com/BurntSushi/toml").await?;
```

### Maven Central

```rust
use cratons_resolver::{MavenClient, RegistryClient};

let client = MavenClient::new(reqwest::Client::new());

// Format: groupId:artifactId
let versions = client.fetch_versions("org.apache.commons:commons-lang3").await?;
let metadata = client.fetch_metadata("com.google.guava:guava", "32.1.3-jre").await?;
```

### Combined Registry

```rust
use cratons_resolver::Registry;
use cratons_core::Ecosystem;

let registry = Registry::with_defaults()?;

// Fetch from any ecosystem
let npm_versions = registry.fetch_versions(Ecosystem::Npm, "lodash").await?;
let pypi_versions = registry.fetch_versions(Ecosystem::PyPi, "requests").await?;
let crates_versions = registry.fetch_versions(Ecosystem::Crates, "serde").await?;
```

## Resolution Algorithm

Cratons uses a **hybrid resolution strategy** that adapts to each ecosystem:

### MVS (Minimal Version Selection) — Go, Rust
For ecosystems designed around minimal versioning:

1. Collect all version requirements for each package
2. Select the **minimum** version that satisfies all constraints
3. Recursively resolve transitive dependencies
4. Apply MVS globally to handle conflicts

**Benefits:** Deterministic, predictable upgrades, reduced bloat.

### PubGrub (SAT-based) — npm, Python

For ecosystems with complex constraints (ranges, conflicts, optionals):

1. Model dependencies as Boolean satisfiability constraints
2. Use **PubGrub** algorithm to find a satisfying assignment
3. Handle backtracking when conflicts are detected
4. Select maximum satisfying versions (ecosystem convention)

**Benefits:** Correct handling of complex constraints, conflict detection.

### Resolution Strategy Per Ecosystem

| Ecosystem | Strategy | Rationale |
|-----------|----------|-----------|
| Go | MVS | Go modules expect minimal versions |
| Rust/Cargo | MVS | Cargo convention, deterministic |
| npm | MaxSatisfying + PubGrub | npm packages expect latest patches |
| Python/PyPI | MaxSatisfying + PubGrub | Complex markers, extras |
| Maven | MVS | Enterprise reproducibility |

See `mvs.rs` for the MVS implementation and `sat.rs` for the PubGrub integration.

## Package Metadata

```rust
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub dist_url: String,              // Download URL
    pub integrity: String,             // Integrity hash
    pub dependencies: HashMap<String, String>,
    pub optional_dependencies: HashMap<String, String>,
    pub peer_dependencies: HashMap<String, String>,
    pub dev_dependencies: HashMap<String, String>,
    pub features: Vec<String>,         // Cargo features, pip extras
}
```

## Resolution Result

```rust
pub struct Resolution {
    pub packages: Vec<ResolvedPackage>,
    pub graph: DependencyGraph,
}

pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub source: String,
    pub integrity: String,
    pub resolved_hash: ContentHash,
    pub direct: bool,
    pub features: Vec<String>,
    pub dependencies: Vec<(String, String)>,
}
```

## Lockfile Generation

```rust
use cratons_resolver::compute_manifest_hash;
use cratons_manifest::Manifest;

let manifest = Manifest::load("cratons.toml")?;

// Compute hash for freshness checking
let hash = compute_manifest_hash(&manifest);

// Convert resolution to lockfile
let lockfile = resolution.to_lockfile(hash);
lockfile.save("cratons.lock")?;
```

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
