# cratons-builder

Hermetic build execution for the Cratons package manager.

## Overview

This crate provides isolated, reproducible build execution using OCI containers (via youki). Features include:

- **Container Isolation**: Builds run in isolated OCI containers
- **Reproducible Environments**: Controlled filesystem, network, and resources
- **Content-Addressable Caching**: Build outputs cached by input hash
- **Remote Cache Integration**: Share build artifacts across machines
- **Cross-Platform**: Full isolation on Linux, fallback mode on macOS/Windows

## Build Execution

### Basic Build

```rust
use cratons_builder::{BuildExecutor, BuildConfig, ToolchainSpec};
use cratons_store::Store;

let store = Store::open_default()?;
let executor = BuildExecutor::new(&store);

let config = BuildConfig::new("my-package", "1.0.0")
    .script("npm install && npm run build")
    .workdir("/app")
    .env("NODE_ENV", "production")
    .memory_limit(2 * 1024 * 1024 * 1024)  // 2GB
    .cpu_limit(2.0)
    .add_toolchain(ToolchainSpec::new("node", "20.10.0"));

let result = executor.build(&config, Path::new("./src")).await?;

println!("Build completed in {:.2}s", result.duration_secs);
println!("Output hash: {}", result.output_hash);
println!("Cached: {}", result.cached);
```

### Build with Remote Cache

```rust
use cratons_builder::BuildExecutor;
use cratons_store::{Store, RemoteCache, RemoteCacheConfig};
use std::sync::Arc;

let store = Store::open_default()?;
let artifacts = store.artifacts();

// Configure S3 remote cache
let remote_config = RemoteCacheConfig::s3_from_env(
    "build-cache".to_string(),
    "cratons".to_string(),
    "us-east-1".to_string(),
);

let remote_cache = Arc::new(RemoteCache::new(vec![remote_config], artifacts)?);

let executor = BuildExecutor::new(&store)
    .with_remote_cache(remote_cache)
    .with_push_to_remote(true);  // Push successful builds

let result = executor.build(&config, source_dir).await?;
// Checks: local cache -> remote cache -> build -> push to remote
```

## Build Configuration

### BuildConfig

```rust
use cratons_builder::{BuildConfig, ToolchainSpec};

let config = BuildConfig::new("package-name", "1.0.0")
    // Build script (required)
    .script("npm run build")

    // Working directory inside container
    .workdir("/workspace")

    // Environment variables
    .env("NODE_ENV", "production")
    .env("CI", "true")

    // Resource limits
    .memory_limit(4 * 1024 * 1024 * 1024)  // 4GB
    .cpu_limit(4.0)  // 4 CPU cores

    // Required toolchains
    .add_toolchain(ToolchainSpec::new("node", "20.10.0"))
    .add_toolchain(ToolchainSpec::new("python", "3.11"))

    // Output patterns
    .add_output("dist/**/*")
    .add_output("build/**/*");
```

### Input Hashing

Build caching uses a deterministic input hash computed from:

```rust
let config = BuildConfig::new("my-pkg", "1.0.0")
    .script("npm run build")
    .env("NODE_ENV", "production");

// Deterministic hash based on:
// - Package name and version
// - Build script
// - Environment variables (sorted)
// - Toolchain versions
let input_hash = config.input_hash();
println!("Input hash: {}", input_hash);
```

## Build Results

```rust
pub struct BuildResult {
    /// Hash of all inputs (for cache key)
    pub input_hash: ContentHash,

    /// Hash of build outputs
    pub output_hash: ContentHash,

    /// Path to build outputs
    pub output_path: PathBuf,

    /// Build duration in seconds
    pub duration_secs: f64,

    /// Whether result came from cache
    pub cached: bool,
}
```

## Container Isolation

On Linux, builds run in isolated OCI containers with:

- **Filesystem**: Read-only rootfs with writable output directory
- **Network**: No network access during build
- **Resources**: Configurable CPU and memory limits
- **Processes**: Isolated PID namespace
- **Users**: Non-root user inside container

```rust
// Container limits
let config = BuildConfig::new("pkg", "1.0.0")
    .script("make")
    .memory_limit(2 * 1024 * 1024 * 1024)  // 2GB hard limit
    .cpu_limit(2.0);  // 2 CPU cores max
```

## Rootfs Building

The build environment is constructed from:

```rust
use cratons_builder::RootfsBuilder;

let rootfs = RootfsBuilder::new(&store)
    .build(&config, source_dir, work_dir)
    .await?;

// Rootfs contains:
// - Base OS layer (minimal Alpine/Debian)
// - Installed toolchains
// - Source files (read-only)
// - Build dependencies
```

## OCI Spec Generation

```rust
use cratons_builder::OciSpecBuilder;

let spec = OciSpecBuilder::new()
    .workdir("/app")
    .script("npm run build")
    .env(&config.env)
    .memory_limit(config.memory_limit)
    .cpu_limit(config.cpu_limit)
    .output_dir(&output_dir)
    .build()?;

// Generates OCI runtime spec (config.json)
```

## Platform Support

| Platform | Isolation Level | Notes |
|----------|-----------------|-------|
| Linux | Full (OCI containers) | Uses youki runtime |
| macOS | Process-only | No container isolation |
| Windows | Process-only | No container isolation |

On non-Linux platforms, builds run in a subprocess with reduced isolation (no filesystem/network isolation).

## Caching Behavior

1. **Local Cache Check**: Check if output exists for input hash
2. **Remote Cache Check**: If configured, check remote backends
3. **Build Execution**: Run build in container
4. **Local Cache Store**: Store output with input hash as key
5. **Remote Cache Push**: If configured, push to remote backends

```rust
// Cache flow:
// Local hit -> return immediately
// Remote hit -> download, store locally, return
// Miss -> build -> store locally -> push to remote
```

## Error Handling

```rust
use cratons_core::CratonsError;

match executor.build(&config, source_dir).await {
    Ok(result) => println!("Success: {}", result.output_hash),
    Err(CratonsError::BuildFailed(msg)) => eprintln!("Build failed: {}", msg),
    Err(CratonsError::Container(msg)) => eprintln!("Container error: {}", msg),
    Err(e) => eprintln!("Error: {}", e),
}
```

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
