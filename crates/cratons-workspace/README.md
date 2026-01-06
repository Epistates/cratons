# cratons-workspace

Monorepo and workspace support for the Cratons package manager.

## Overview

This crate provides workspace/monorepo functionality, enabling:

- **Multi-Package Workspaces**: Manage multiple packages in a single repository
- **Shared Dependencies**: Common dependency versions across packages
- **Cross-Package Dependencies**: Local package references
- **Filtered Commands**: Run commands on specific packages
- **Topological Ordering**: Build packages in dependency order

## Workspace Configuration

### Root Manifest

```toml
# cratons.toml (workspace root)
[workspace]
members = [
    "packages/*",
    "apps/web",
    "apps/api",
]

# Exclude specific directories
exclude = [
    "packages/deprecated-*",
]

# Shared dependency versions
[workspace.dependencies.npm]
lodash = "^4.17.0"
express = "^4.18.0"

[workspace.dependencies.crates]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
```

### Member Package

```toml
# packages/my-lib/cratons.toml
[package]
name = "my-lib"
version = "1.0.0"

[dependencies.npm]
# Use workspace version
lodash = { workspace = true }

# Override workspace version
express = "^4.17.0"

# Reference sibling package
[dependencies.workspace]
my-other-lib = { path = "../my-other-lib" }
```

## Usage

### Loading a Workspace

```rust
use cratons_workspace::Workspace;
use std::path::Path;

// Load from current directory
let workspace = Workspace::load(Path::new("."))?;

// Or from specific path
let workspace = Workspace::load(Path::new("path/to/workspace"))?;

println!("Found {} packages", workspace.packages().len());
```

### Iterating Packages

```rust
use cratons_workspace::Workspace;
use std::path::Path;

let workspace = Workspace::load(Path::new("."))?;

// All packages
for package in workspace.packages() {
    println!("{}: {}", package.name(), package.version());
}

// Filter by pattern
for package in workspace.packages_matching("packages/*") {
    println!("Package: {}", package.name());
}

// Get specific package
if let Some(pkg) = workspace.get_package("my-lib") {
    println!("Found: {}@{}", pkg.name(), pkg.version());
}
```

### Topological Order

Build packages in dependency order:

```rust
use cratons_workspace::Workspace;

let workspace = Workspace::discover(".")?;

// Get packages in build order (dependencies first)
for package in workspace.topological_order()? {
    println!("Build: {}", package.name());
}

// Reverse order (dependents first, for cleanup)
for package in workspace.reverse_topological_order()? {
    println!("Clean: {}", package.name());
}
```

### Dependency Graph

```rust
use cratons_workspace::Workspace;

let workspace = Workspace::discover(".")?;

// Get package dependencies within workspace
let deps = workspace.internal_dependencies("my-lib");
for dep in deps {
    println!("my-lib depends on: {}", dep.name());
}

// Get packages that depend on a package
let dependents = workspace.dependents("my-lib");
for dep in dependents {
    println!("{} depends on my-lib", dep.name());
}
```

### Filtered Operations

```rust
use cratons_workspace::{Workspace, PackageFilter};

let workspace = Workspace::discover(".")?;

// Filter by path pattern
let filter = PackageFilter::Pattern("packages/*".to_string());
for pkg in workspace.filter(filter) {
    println!("{}", pkg.name());
}

// Filter by changed files (git)
let filter = PackageFilter::Changed { since: "main".to_string() };
for pkg in workspace.filter(filter) {
    println!("Changed: {}", pkg.name());
}

// Filter by name
let filter = PackageFilter::Names(vec!["pkg-a".to_string(), "pkg-b".to_string()]);
```

## Shared Dependencies

### Workspace Dependencies

```toml
# Workspace root
[workspace.dependencies.npm]
lodash = "^4.17.0"
```

```toml
# Member package - inherits version from workspace
[dependencies.npm]
lodash = { workspace = true }
```

### Overriding Workspace Versions

```toml
# Member package - uses different version
[dependencies.npm]
lodash = "^4.16.0"  # Overrides workspace version
```

## Cross-Package References

### Path Dependencies

```toml
[dependencies.workspace]
my-lib = { path = "../my-lib" }
```

### Automatic Linking

```rust
use cratons_workspace::Workspace;

let workspace = Workspace::discover(".")?;

// Link all internal dependencies
workspace.link_internal_deps()?;

// This creates symlinks/references between packages
// so they use local versions during development
```

## Package Discovery

```rust
use cratons_workspace::Workspace;

// Glob pattern expansion
let workspace = Workspace::discover(".")?;

// Discovers packages matching:
// - packages/*
// - apps/web
// - apps/api
// Excludes:
// - packages/deprecated-*
```

## Workspace Commands

Run commands across packages:

```rust
use cratons_workspace::{Workspace, CommandRunner};

let workspace = Workspace::discover(".")?;
let runner = CommandRunner::new(&workspace);

// Run on all packages
runner.run_all("npm test").await?;

// Run on filtered packages
runner.run_matching("packages/*", "npm build").await?;

// Run in topological order
runner.run_ordered("npm build").await?;

// Run in parallel (respecting dependencies)
runner.run_parallel("npm test", 4).await?;
```

## Types

### WorkspacePackage

```rust
pub struct WorkspacePackage {
    /// Package manifest
    pub manifest: Manifest,

    /// Path to package directory
    pub path: PathBuf,

    /// Path relative to workspace root
    pub relative_path: PathBuf,
}

impl WorkspacePackage {
    pub fn name(&self) -> &str;
    pub fn version(&self) -> &str;
    pub fn dependencies(&self) -> &Dependencies;
}
```

### PackageFilter

```rust
pub enum PackageFilter {
    /// All packages
    All,

    /// Match by glob pattern
    Pattern(String),

    /// Match by package names
    Names(Vec<String>),

    /// Packages changed since git ref
    Changed { since: String },

    /// Packages and their dependents
    Affected { packages: Vec<String> },
}
```

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
