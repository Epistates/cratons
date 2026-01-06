# cratons-installer

Hermetic package installation for the Cratons package manager.

## Overview

`cratons-installer` provides isolated, reproducible package installation with:

- **Parallel Downloads** - Concurrent package fetching with configurable concurrency limits
- **Integrity Verification** - SHA-256/SHA-512/Blake3 checksum validation
- **Content-Addressable Storage** - Automatic deduplication via the cratons store
- **Ecosystem-Specific Linking** - Proper directory structures for npm, PyPI, crates.io, Go, and Maven
- **Post-Install Scripts** - Lifecycle script execution with optional container isolation

## Supported Ecosystems

| Ecosystem | Archive Format | Installation Directory |
|-----------|---------------|----------------------|
| npm | `.tgz` | `node_modules/` |
| PyPI | `.whl`, `.tar.gz` | `.venv/lib/python/site-packages/` |
| crates.io | `.crate` | `~/.cargo/registry/cache/` |
| Go | `.zip` | `$GOPATH/pkg/mod/` |
| Maven | `.jar` | `~/.m2/repository/` |
| URL | auto-detect | `.cratons/url-deps/` |

## Usage

### Basic Installation

```rust
use cratons_installer::install;
use cratons_lockfile::Lockfile;
use std::path::Path;

// Load lockfile and install all packages
let lockfile = Lockfile::load("cratons.lock")?;
let result = install(&lockfile, Path::new(".")).await?;

println!("Installed {} packages in {:.2}s",
    result.packages_installed,
    result.duration_secs);
```

### Custom Configuration

```rust
use cratons_installer::{Installer, InstallerConfig, LinkStrategy};
use cratons_store::Store;

// Configure installation
let config = InstallerConfig {
    concurrency: 16,           // Parallel download limit
    run_scripts: true,         // Run npm lifecycle scripts
    isolate_scripts: true,     // Container isolation (Linux)
    skip_integrity: false,     // Never skip in production!
    link_strategy: LinkStrategy::Symlink,
    ecosystems: None,          // Install all ecosystems
};

let store = Store::open_default()?;
let installer = Installer::with_config(&store, config);
let result = installer.install(&lockfile, &project_dir).await?;
```

### Selective Installation

```rust
use cratons_core::Ecosystem;

// Only install npm packages
let config = InstallerConfig {
    ecosystems: Some(vec![Ecosystem::Npm]),
    ..Default::default()
};
```

## Link Strategies

The installer supports three strategies for linking packages from the content-addressable store:

### Symlink (Default)
```rust
LinkStrategy::Symlink
```
- Most space-efficient
- Fastest installation
- Requires filesystem symlink support

### Hard Link
```rust
LinkStrategy::HardLink
```
- Space-efficient within same filesystem
- No special permissions required
- Falls back to copy for cross-device links

### Copy
```rust
LinkStrategy::Copy
```
- Most compatible
- Uses the most disk space
- Works on all filesystems

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                       Installer                             │
│  ┌──────────────────┐  ┌────────────────┐  ┌────────────┐  │
│  │ PackageDownloader│  │ PackageExtractor│  │PackageLinker│  │
│  │                  │  │                 │  │            │  │
│  │ - Parallel fetch │  │ - npm tarball   │  │ - Symlinks │  │
│  │ - Integrity check│  │ - PyPI wheel/tar│  │ - Hardlinks│  │
│  │ - CAS storage    │  │ - Rust crate    │  │ - Copies   │  │
│  └─────────┬────────┘  │ - Go zip        │  └──────▲─────┘  │
│            │           │ - Maven jar     │         │        │
│            ▼           └────────┬────────┘         │        │
│  ┌──────────────────────────────▼──────────────────┘        │
│  │            Content-Addressable Store                     │
│  └──────────────────────────────────────────────────────────┘
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              PostInstallRunner                        │  │
│  │  - npm lifecycle scripts (preinstall/install/post)   │  │
│  │  - node-gyp native compilation                       │  │
│  │  - Optional container isolation                      │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

## Installation Result

The installation returns detailed metrics:

```rust
pub struct InstallResult {
    pub packages_installed: usize,   // Total packages
    pub packages_cached: usize,      // From local cache
    pub packages_downloaded: usize,  // Fetched from registry
    pub bytes_downloaded: u64,       // Network transfer
    pub duration_secs: f64,          // Total time
    pub ecosystems: HashMap<Ecosystem, EcosystemResult>,
    pub warnings: Vec<String>,
}
```

## Post-Install Scripts

For npm packages, the installer executes lifecycle scripts in order:

1. `preinstall` - Before package installation
2. `install` - Main installation hook
3. `postinstall` - After package installation

Native modules with `binding.gyp` trigger automatic `node-gyp rebuild`.

### Container Isolation (Linux)

When `isolate_scripts: true`, scripts run in isolated containers with:
- Read-only root filesystem (except package directory)
- No network access
- Limited capabilities
- Restricted resource usage

This protects against malicious post-install scripts.

## Error Handling

The installer provides detailed error types:

- `CratonsError::Network` - Download failures
- `CratonsError::ChecksumMismatch` - Integrity verification failed
- `CratonsError::BuildFailed` - Post-install script errors
- `CratonsError::Io` - Filesystem operations

## Performance

- **Deduplication**: Same package content stored once via CAS
- **Parallel Downloads**: Configurable concurrent connections
- **Cache First**: Always checks local cache before downloading
- **Streaming**: Archives extracted directly without full buffering

## License

MIT - See LICENSE in repository root.
