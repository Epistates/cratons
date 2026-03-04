# cratons-store

Content-addressable storage and remote cache for the Cratons package manager.

## Overview

This crate provides:

- **Content-Addressable Storage (CAS)**: Deduplicated storage using Blake3 hashes
- **Artifact Store**: Build artifact management with manifests
- **Remote Cache**: S3, filesystem, and HTTP cache backends
- **Toolchain Management**: Language runtime installation and management
- **Linking Strategies**: Symlinks, hard links, and copy modes
- **Garbage Collection**: Automatic cleanup of unreferenced content

## Content-Addressable Storage

### Basic Operations

```rust
use cratons_store::cas::ContentAddressableStore;

let cas = ContentAddressableStore::new("/path/to/store")?;

// Store content (returns Blake3 hash)
let hash = cas.store_bytes(b"file content")?;

// Store a file
let hash = cas.store_file("path/to/file")?;

// Retrieve content
if let Some(content) = cas.retrieve(&hash)? {
    println!("Content: {:?}", content);
}

// Get path to stored content
if let Some(path) = cas.get_path(&hash) {
    println!("Stored at: {}", path.display());
}

// Verify integrity
cas.verify(&hash)?;
```

### Directory Storage

```rust
use cratons_store::cas::ContentAddressableStore;

let cas = ContentAddressableStore::new("/path/to/store")?;

// Store entire directory
let hash = cas.store_directory("path/to/dir")?;

// The directory is stored as a tree of hashes
println!("Directory hash: {}", hash);
```

## Artifact Store

Build artifacts with metadata and manifests:

```rust
use cratons_store::artifact::{ArtifactStore, ArtifactManifest};
use cratons_core::ContentHash;

let store = ArtifactStore::new("/path/to/artifacts");

// Create artifact manifest
let manifest = ArtifactManifest::new(
    ContentHash::blake3("input-hash".to_string()),
    "my-package".to_string(),
    "1.0.0".to_string(),
);

// Store build output
let hash = store.store(&manifest, "path/to/output")?;

// Load artifact
if let Some(artifact) = store.load(&hash)? {
    println!("Package: {}@{}", artifact.manifest.package, artifact.manifest.version);
    println!("Built at: {}", artifact.manifest.built_at);
}

// List all artifacts
for artifact in store.list()? {
    println!("{}: {}", artifact.manifest.package, artifact.manifest.input_hash);
}
```

## Remote Cache

### S3-Compatible Storage

```rust
use cratons_store::remote::{RemoteCache, RemoteCacheConfig};
use cratons_store::artifact::ArtifactStore;

let config = RemoteCacheConfig::S3 {
    bucket: "my-build-cache".to_string(),
    prefix: "cratons".to_string(),
    region: "us-east-1".to_string(),
    endpoint: None,  // Uses AWS S3
    access_key_id: None,  // Uses env vars
    secret_access_key: None,
    session_token: None,
    path_style: false,
};

let artifacts = ArtifactStore::new("/local/artifacts");
let cache = RemoteCache::new(vec![config], artifacts)?;

// Check if artifact exists remotely
let exists = cache.exists(&input_hash).await?;

// Fetch from remote (downloads if not local)
if let Some(path) = cache.fetch(&input_hash).await? {
    println!("Artifact at: {}", path.display());
}

// Push to all writable remotes
let count = cache.push(&input_hash).await?;
println!("Pushed to {} backends", count);
```

### Filesystem Cache

```rust
use cratons_store::remote::RemoteCacheConfig;

// For local/network-mounted storage
let config = RemoteCacheConfig::Filesystem {
    path: "/shared/cache".into(),
    read_only: false,
};
```

### HTTP Read-Only Cache

```rust
use cratons_store::remote::RemoteCacheConfig;

// For public artifact servers
let config = RemoteCacheConfig::Http {
    url: "https://cache.example.com".to_string(),
    authorization: Some("Bearer token".to_string()),
    timeout_secs: 60,
};
```

### Configuration from Environment

```rust
use cratons_store::remote::RemoteCacheConfig;

// S3 config from AWS environment variables
let config = RemoteCacheConfig::s3_from_env(
    "my-bucket".to_string(),
    "prefix".to_string(),
    "us-east-1".to_string(),
);
// Reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_ENDPOINT_URL, etc.
```

## Toolchain Management

```rust
use cratons_store::toolchain::ToolchainStore;

let store = ToolchainStore::new("/path/to/toolchains")?;

// Install a toolchain
store.install("node", "20.10.0", "https://nodejs.org/dist/...").await?;

// Get installed path
if let Some(path) = store.get("node", "20.10.0") {
    println!("Node installed at: {}", path.display());
}

// List installed versions
for version in store.list("node")? {
    println!("node@{}", version);
}

// Remove a version
store.remove("node", "18.0.0")?;
```

## Verification (verify.rs)

Multi-level verification framework for supply chain security:

```rust
use cratons_store::verify::{ToolchainVerifier, VerificationMethod};

// Default verifier (requires checksum)
let verifier = ToolchainVerifier::new();

// Strict verifier (requires signature)
let verifier = ToolchainVerifier::strict();

// SHA-256 checksum verification
let result = verifier.verify_sha256(data, "abc123...")?;
assert!(result.verified);
assert_eq!(result.method, VerificationMethod::Sha256Checksum);

// Minisign (Ed25519) signature verification
let result = verifier.verify_minisign(
    data,
    &signature_content,
    "RWRkE3YPmZHZPKL1xdAMjJNjh44TduX5B1KSMT5oTu4GKPEm5rxaOcPy"
)?;
assert!(result.verified);
assert_eq!(result.method, VerificationMethod::Minisign);
```

### Security Levels

| Level | Method | Description |
|-------|--------|-------------|
| 0 | None | No verification |
| 1 | SHA-256 | Checksum integrity |
| 2 | Minisign | Ed25519 signature (Zig) |
| 3 | GPG | OpenPGP detached signature (Node.js) |
| 4 | Sigstore | Keyless verification (Python 3.14+) |

### GPG Verification (Node.js, etc.)

```rust
use cratons_store::verify::{ToolchainVerifier, VerificationMethod};

let verifier = ToolchainVerifier::new();

// Verify with single key
let result = verifier.verify_gpg(
    artifact_bytes,
    &signature_asc,      // ASCII-armored .asc file
    &public_key_armor,   // ASCII-armored public key
)?;

// Verify with multiple trusted keys (Node.js has multiple release managers)
let result = verifier.verify_gpg_any_key(
    artifact_bytes,
    &signature_asc,
    &[key1, key2, key3],
)?;
```

### Sigstore Verification (Python 3.14+)

```rust
use cratons_store::verify::{ToolchainVerifier, known_keys};

let verifier = ToolchainVerifier::new();

// Verify Python release with Sigstore bundle
let result = verifier.verify_sigstore(
    artifact_bytes,
    &bundle_json,  // .sigstore file contents
    known_keys::python::PABLO_GALINDO_IDENTITY,
    known_keys::python::GOOGLE_ISSUER,
).await?;
```

## Linking Strategies

```rust
use cratons_store::link::{Linker, LinkStrategy};

let linker = Linker::new(LinkStrategy::Symlink);

// Create link to CAS content
linker.link(&cas_path, &target_path)?;

// Copy if links not supported
let linker = Linker::new(LinkStrategy::Copy);
linker.link(&source, &dest)?;

// Hard links (same filesystem)
let linker = Linker::new(LinkStrategy::HardLink);
linker.link(&source, &dest)?;
```

## Garbage Collection

```rust
use cratons_store::gc::{GarbageCollector, GcConfig};

let gc = GarbageCollector::new(store_path, GcConfig::default());

// Collect unreferenced content
let stats = gc.collect()?;
println!("Freed {} bytes in {} objects", stats.bytes_freed, stats.objects_removed);

// Dry run
let stats = gc.dry_run()?;
println!("Would free {} bytes", stats.bytes_freed);
```

**Note**: Garbage collection uses file locking to prevent race conditions. Artifacts in use by other processes are safely skipped.

## Store Configuration

```rust
use cratons_store::{Store, StoreConfig};

// Open with default config
let store = Store::open_default()?;

// Custom configuration
let config = StoreConfig {
    root: "/custom/path".into(),
    link_strategy: LinkStrategy::HardLink,
    gc_threshold_bytes: 10 * 1024 * 1024 * 1024,  // 10GB
};
let store = Store::open(config)?;
```

## Security (January 2026)

The store has been hardened following a comprehensive security audit:

### Content-Addressable Storage
- **Atomic Writes**: Uses temp files with exclusive locking to prevent corruption during concurrent writes
- **Integrity Verification**: Blake3 hashes verified on both store and retrieve operations

### Remote Cache
- **SSRF Protection**: S3 endpoints are validated to block:
  - Localhost and loopback addresses (127.0.0.0/8, ::1)
  - AWS metadata endpoints (169.254.169.254)
  - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Non-HTTP(S) schemes (file://, ftp://, etc.)
- **Hash Re-verification**: Downloaded artifacts are re-verified against expected hash after download
- **Bucket Name Validation**: S3 bucket names validated per AWS naming rules (3-63 chars, lowercase, no consecutive dots)

### Garbage Collection
- **File Locking**: Artifacts are locked before deletion to prevent race conditions
- **Graceful Skip**: Artifacts in use by other processes are safely skipped

### Cryptographic Verification
- **Multi-key GPG**: Supports "any key matches" for ecosystems with multiple release signers
- **Sigstore**: Keyless verification with OIDC identity binding for Python 3.14+
- **Minisign**: Ed25519 signature verification for modern toolchains (Zig)

## Directory Structure

```
~/.cratons/
├── store/
│   ├── cas/           # Content-addressable storage
│   │   ├── ab/        # First 2 chars of hash
│   │   │   └── ab1234.../  # Full hash
│   │   └── cd/
│   │       └── cd5678.../
│   └── artifacts/     # Build artifacts with manifests
│       └── {input_hash}/
│           ├── cratons-manifest.json
│           └── output/
├── toolchains/        # Installed language runtimes
│   ├── node/
│   │   └── 20.10.0/
│   └── python/
│       └── 3.11.6/
└── config.toml        # Store configuration
```

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
