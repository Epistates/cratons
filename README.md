# Cratons

A language-agnostic package manager with **hermetic builds**, **content-addressable storage**, and **unified dependency management** across ecosystems. Designed for enterprise scale and security.

## SOTA Features (2025)

- **Hybrid Resolver (MVS + SAT)**: Combines the determinism of Minimal Version Selection (Go/Cargo) with the constraint-solving power of **PubGrub** (NPM/Python/Dart), seamlessly resolving dependencies across diverse ecosystems in a single graph.
- **OCI-Compliant Sandboxing**: Builds run in true, unprivileged containers using `libcontainer` (youki core) with strict **Seccomp** filtering, **Namespace** isolation (User, Pid, Net, Mount), and resource limits.
- **Defense-in-Depth Supply Chain Security**:
    - **Sigstore** verification for Python 3.14+ (Keyless, OIDC identity binding).
    - **GPG** verification for Node.js and Rust (Web of Trust).
    - **Minisign** verification for modern toolchains.
    - TOCTOU-free in-memory artifact verification.
- **OpenTelemetry Observability**: Built-in OTLP export support for distributed tracing of build pipelines.

## Features

- **Multi-Ecosystem Support**: npm, PyPI, crates.io, Go modules, and Maven Central
- **Hermetic Builds**: Isolated container-based builds using OCI runtime concepts
- **Hermetic Environments**: venv-compatible environments that work with existing tools
- **Cross-Platform Sandboxing**: Linux containers, macOS sandbox-exec, Windows Job Objects
- **Content-Addressable Storage**: Blake3 hashing for deduplication and integrity
- **Remote Build Cache**: S3-compatible, filesystem, and HTTP cache backends
- **Unified Manifest**: Single `cratons.toml` for all ecosystems

## Quick Start

```bash
# Install cratons
cargo install --path crates/cratons

# Initialize a new project
cratons init

# Add dependencies
cratons add lodash@npm           # npm package
cratons add requests@pypi        # Python package
cratons add serde@crates         # Rust crate
cratons add github.com/gin-gonic/gin@go  # Go module

# Install all dependencies
cratons install

# Activate the hermetic environment
source .cratons/activate

# Or start a shell with the environment
cratons shell

# Run scripts in the hermetic environment
cratons run build
```

## Manifest Format

```toml
[package]
name = "my-app"
version = "1.0.0"

[environment]
node = "20.10.0"
python = "3.12.0"

[dependencies.npm]
lodash = "^4.17.0"
express = "^4.18.0"

[dependencies.pypi]
requests = ">=2.28.0"
flask = "^3.0.0"

[dependencies.crates]
serde = { version = "1.0", features = ["derive"] }
tokio = "1.0"

[dependencies.go]
"github.com/gin-gonic/gin" = "v1.9.0"

[dependencies.maven]
"org.apache.commons:commons-lang3" = "3.12.0"

[scripts]
dev = "npm run dev"
build = "npm run build"
test = "pytest"
```

## Architecture

```
crates/
├── cratons/             # CLI application
├── cratons-core/        # Core types, traits, and utilities
├── cratons-manifest/    # Manifest parsing (cratons.toml)
├── cratons-lockfile/    # Lockfile management (cratons.lock)
├── cratons-resolver/    # Hybrid dependency resolution (MVS + PubGrub) & registry clients
├── cratons-store/       # Content-addressable storage & remote cache
├── cratons-builder/     # Hermetic build execution
├── cratons-installer/   # Package installation with integrity verification
├── cratons-environment/ # Hermetic environment management
├── cratons-sandbox/     # Cross-platform sandboxed execution (OCI/libcontainer)
├── cratons-workspace/   # Monorepo/workspace support
└── cratons-security/    # Vulnerability auditing & policy
```

## Key Concepts

### Hermetic Environments

Cratons creates isolated, reproducible environments that:
- Are compatible with existing tools (IDEs, linters, etc.)
- Don't require system-level changes
- Support multiple shells (bash, fish, PowerShell)
- Can be activated manually or via `cratons shell`

### Cross-Platform Sandboxing

Cratons provides sandboxed execution with graceful degradation:

| Platform | Isolation Level | Technology |
|----------|-----------------|------------|
| Linux    | Container       | Namespaces, cgroups, seccomp (libcontainer) |
| macOS    | OS Sandbox      | sandbox-exec with SBPL profiles |
| Windows  | Process         | Job Objects (resource limits only) |
| Fallback | Process         | Minimal isolation |

**Security Hardening**:
- Linux: Seccomp syscall filtering blocks dangerous syscalls (`unshare`, `mount`, `ptrace`, etc.)
- macOS: Strict executable whitelist (~50 system binaries), network binaries blocked unless network enabled
- All platforms: 100+ dangerous environment variables blocked (glibc exploitation, credential leakage, locale hijacking)

### Hybrid Resolution

Cratons uses **MVS** for Go/Rust to ensure deterministic upgrades, and **PubGrub (SAT)** for NPM/Python to correctly handle complex version constraints.

### Content-Addressable Storage

All packages are stored by their content hash (Blake3), enabling:
- Automatic deduplication
- Integrity verification
- Efficient caching

### Hermetic Builds

Builds run in isolated containers with:
- Controlled filesystem access
- Reproducible environments
- Resource limits (CPU, memory)
- No network access during build

## CLI Commands

```bash
cratons init           # Initialize a new project
cratons add <pkg>      # Add a dependency
cratons remove <pkg>   # Remove a dependency
cratons install        # Install all dependencies
cratons update         # Update dependencies
cratons build          # Build the project
cratons run <script>   # Run a script in hermetic environment
cratons shell          # Start shell with hermetic environment
cratons tree           # Show dependency tree
cratons why <pkg>      # Explain why a package is installed
cratons outdated       # Show outdated dependencies
cratons audit          # Run security audit
cratons gc             # Garbage collect unused artifacts
cratons store info     # Show store information
cratons cache push     # Push to remote cache
cratons cache fetch    # Fetch from remote cache
cratons workspace list # List workspace members
cratons workspace graph # Show workspace dependency graph
```

## Configuration

### Remote Cache

```toml
# ~/.config/cratons/config.toml
[cache.remote]
type = "s3"
bucket = "my-build-cache"
region = "us-east-1"
prefix = "cratons"

# Or filesystem cache
[cache.remote]
type = "filesystem"
path = "/shared/cache"
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CRATONS_HOME` | Cratons data directory (default: `~/.cratons`) |
| `CRATONS_CACHE_DIR` | Cache directory override |
| `CRATONS_CACHE_URL` | Remote cache URL (`s3://bucket/prefix`, `https://...`, or path) |
| `CRATONS_CACHE_TOKEN` | Auth token for HTTP remote cache |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Endpoint for OpenTelemetry traces (e.g., `http://localhost:4317`) |
| `AWS_ACCESS_KEY_ID` | S3 access key for remote cache |
| `AWS_SECRET_ACCESS_KEY` | S3 secret key for remote cache |
| `AWS_REGION` | AWS region for S3 cache (default: `us-east-1`) |

## Development

```bash
# Run tests
cargo test --workspace

# Run integration tests (requires network)
cargo test --workspace -- --ignored

# Build release
cargo build --release

# Check all crates
cargo check --workspace
```

## Project Status

Cratons is in active R&D. Current status:

- [x] Core types and traits
- [x] Manifest parsing (cratons.toml)
- [x] Lockfile management
- [x] Registry clients (npm, PyPI, crates.io, Go, Maven)
- [x] Hybrid dependency resolution (MVS + SAT)
- [x] Content-addressable storage
- [x] Package installation with integrity verification
- [x] Hermetic environment management
- [x] Cross-platform sandboxing (OCI/libcontainer on Linux)
- [x] Activation scripts (bash, fish, PowerShell)
- [x] CLI with run/shell commands
- [x] Build execution with sandboxing
- [x] Remote cache (S3, filesystem, HTTP)
- [x] Security auditing with vulnerability detection
- [x] Toolchain management (download & verify: Sigstore/GPG)
- [x] Workspace/monorepo support (glob patterns, topological ordering, filtering)

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.