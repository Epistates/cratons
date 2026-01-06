# cratons-manifest

Manifest parsing and manipulation for the Cratons package manager.

## Overview

This crate handles parsing, validation, and manipulation of `cratons.toml` manifest files. It supports:

- Package metadata
- Multi-ecosystem dependencies
- Build configuration
- Environment variables
- Workspace definitions

## Manifest Format

```toml
[package]
name = "my-app"
version = "1.0.0"
description = "My application"
authors = ["Alice <alice@example.com>"]
license = "MIT"
repository = "https://github.com/example/my-app"

[dependencies.npm]
lodash = "^4.17.0"
express = { version = "^4.18.0", optional = true }

[dependencies.pypi]
requests = ">=2.28.0"
flask = { version = "^3.0.0", extras = ["async"] }

[dependencies.crates]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }

[dependencies.go]
"github.com/gin-gonic/gin" = "v1.9.0"

[dependencies.maven]
"org.apache.commons:commons-lang3" = "3.12.0"

[dev-dependencies.npm]
jest = "^29.0.0"

# M-19 FIX: Optional Dependencies Documentation
# There are TWO ways to specify optional dependencies:
#
# Method 1 (PREFERRED): Use optional flag in regular dependencies
# This keeps related dependencies together and is the Cargo convention
[dependencies.npm]
express = { version = "^4.18.0", optional = true }

# Method 2 (ALTERNATIVE): Use optional-dependencies section
# This groups all optionals but separates them from their related deps
[optional-dependencies.npm]
socket-io = "^4.0.0"

[build-dependencies.crates]
cc = "1.0"

[build]
script = "./build.sh"
env = { NODE_ENV = "production" }

[environment]
node = "20.x"
python = "3.11"
rust = "1.75"

[workspace]
members = ["packages/*"]
```

## Usage

### Loading a Manifest

```rust
use cratons_manifest::Manifest;

// Find and load manifest from current directory
let (manifest, path) = Manifest::find_and_load(".")?;

// Load from specific path
let manifest = Manifest::load("path/to/cratons.toml")?;

// Parse from string
let manifest: Manifest = toml::from_str(content)?;
```

### Accessing Dependencies

```rust
use cratons_manifest::Manifest;
use cratons_core::Ecosystem;

let manifest = Manifest::load("cratons.toml")?;

// Get dependencies for a specific ecosystem
for (name, dep) in manifest.dependencies.for_ecosystem(Ecosystem::Npm) {
    println!("{}: {}", name, dep.version().unwrap_or("*"));
}

// Check if a dependency exists
if let Some(dep) = manifest.dependencies.get("lodash", Ecosystem::Npm) {
    println!("Found lodash: {:?}", dep);
}

// Iterate all dependencies
for (name, dep, ecosystem) in manifest.dependencies.iter() {
    println!("[{}] {}: {:?}", ecosystem, name, dep);
}
```

### Dependency Types

```rust
use cratons_manifest::Dependency;

// Simple version constraint
let simple = Dependency::Simple("^1.0.0".to_string());

// Detailed dependency with options
let detailed = Dependency::Detailed {
    version: Some("^1.0.0".to_string()),
    features: vec!["derive".to_string()],
    optional: false,
    git: None,
    branch: None,
    tag: None,
    path: None,
};

// Git dependency
let git_dep = Dependency::Detailed {
    version: None,
    git: Some("https://github.com/example/repo".to_string()),
    branch: Some("main".to_string()),
    ..Default::default()
};
```

### Build Configuration

```rust
let manifest = Manifest::load("cratons.toml")?;

if let Some(build) = &manifest.build {
    println!("Build script: {}", build.script);

    for (key, value) in &build.env {
        println!("ENV: {}={}", key, value);
    }
}
```

### Environment/Toolchains

```rust
let manifest = Manifest::load("cratons.toml")?;

for (name, version) in manifest.environment.toolchains() {
    println!("Toolchain: {} @ {}", name, version);
}
```

## Workspace Support

```rust
use cratons_manifest::Manifest;

let manifest = Manifest::load("cratons.toml")?;

if let Some(workspace) = &manifest.workspace {
    for member in &workspace.members {
        println!("Workspace member: {}", member);
    }
}
```

## Validation

The manifest is validated during parsing:

- Package name must be valid
- Version must be parseable
- Dependencies must have valid version constraints
- No circular workspace references

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
