# cratons-core

Core types, traits, and utilities for the Cratons package manager.

## Overview

This crate provides the foundational types and abstractions used throughout the Cratons ecosystem, including:

- **Ecosystem definitions**: npm, PyPI, crates.io, Go, Maven
- **Version handling**: Semver, PEP 440, Maven versioning
- **Content hashing**: SHA-256, Blake3 with verification
- **Package specifications**: Parsing and formatting package identifiers
- **Error types**: Unified error handling across crates

## Key Types

### Ecosystem

```rust
use cratons_core::Ecosystem;

let ecosystem = Ecosystem::Npm;
println!("Registry: {}", ecosystem.default_registry());
// Output: Registry: https://registry.npmjs.org
```

Supported ecosystems:
- `Ecosystem::Npm` - npm registry
- `Ecosystem::PyPi` - Python Package Index
- `Ecosystem::Crates` - crates.io
- `Ecosystem::Go` - Go module proxy
- `Ecosystem::Maven` - Maven Central

### Version & VersionReq

Multi-ecosystem version handling with proper comparison semantics:

```rust
use cratons_core::{Version, VersionReq, Ecosystem};

// Parse versions for specific ecosystems
let semver = Version::parse("1.2.3", Ecosystem::Npm)?;
let pep440 = Version::parse("2.28.0", Ecosystem::PyPi)?;
let maven = Version::parse("3.12.0-SNAPSHOT", Ecosystem::Maven)?;

// Version requirements
let req = VersionReq::parse("^1.0.0", Ecosystem::Npm)?;
assert!(req.matches(&semver));

// PEP 440 specifiers
let pyreq = VersionReq::parse(">=2.0,<3.0", Ecosystem::PyPi)?;
```

### ContentHash

Content-addressable hashing with integrity verification:

```rust
use cratons_core::{ContentHash, Hasher, HashAlgorithm};

// Hash bytes
let hash = Hasher::hash_bytes(HashAlgorithm::Blake3, b"content");

// Hash files
let file_hash = Hasher::hash_file(HashAlgorithm::Blake3, "path/to/file")?;

// Hash directories
let dir_hash = Hasher::hash_directory(HashAlgorithm::Blake3, "path/to/dir")?;

// Verify integrity
hash.verify(b"content")?;
```

### PackageSpec

Package specification parsing:

```rust
use cratons_core::PackageSpec;

// Parse package specifications
let spec: PackageSpec = "lodash@^4.17.0".parse()?;
let scoped: PackageSpec = "@types/node@^20.0.0".parse()?;
let go_mod: PackageSpec = "github.com/gin-gonic/gin@v1.9.0".parse()?;
```

## Error Handling

All crate operations use `cratons_core::Result<T>` with `CratonsError`:

```rust
use cratons_core::{CratonsError, Result};

fn my_function() -> Result<()> {
    // Operations that may fail return CratonsError
    Err(CratonsError::PackageNotFound("lodash".to_string()))
}
```

Error variants include:
- `PackageNotFound` - Package doesn't exist in registry
- `VersionNotFound` - Specific version not available
- `NoSatisfyingVersion` - No version matches constraints
- `InvalidHash` - Hash verification failed
- `Network` - Network operation failed
- `Registry` - Registry-specific error

## Feature Flags

This crate has no optional features; all functionality is included by default.

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
