# cratons

Command-line interface for the Cratons package manager.

## Installation

```bash
# From source
cargo install --path .

# Or build release
cargo build --release
```

## Commands

### Project Initialization

```bash
# Create new project with cratons.toml
cratons init

# Initialize in specific directory
cratons init ./my-project
```

### Dependency Management

```bash
# Add dependencies
cratons add lodash                    # Auto-detect ecosystem
cratons add lodash@npm                # Explicitly npm
cratons add requests@pypi             # Python package
cratons add serde@crates              # Rust crate
cratons add github.com/gin-gonic/gin@go  # Go module
cratons add org.apache.commons:commons-lang3@maven  # Maven

# Add with version constraint
cratons add lodash@npm:^4.17.0

# Add dev dependency
cratons add jest@npm --dev

# Add build dependency
cratons add cc@crates --build

# Remove dependencies
cratons remove lodash
```

### Installation

```bash
# Install all dependencies
cratons install

# Install with frozen lockfile (CI mode)
cratons install --frozen

# Force re-resolution
cratons install --force
```

### Building

```bash
# Run build script from manifest
cratons build

# Build with verbose output
cratons build -v

# Build specific package (workspace)
cratons build -p my-package

# Clean build artifacts
cratons clean
```

### Running Scripts

```bash
# Run script defined in manifest
cratons run test
cratons run build
cratons run dev

# Pass arguments to script
cratons run test -- --coverage
```

### Dependency Tree

```bash
# Show dependency tree
cratons tree

# Show all dependencies (including transitive)
cratons tree --all

# Limit depth
cratons tree --depth 2

# Show specific ecosystem
cratons tree --ecosystem npm
```

### Security Auditing

```bash
# Audit dependencies for vulnerabilities
cratons audit

# Fail on high severity
cratons audit --fail-on high

# JSON output
cratons audit --format json
```

### Cache Management

```bash
# Show remote cache info
cratons cache info

# Configure remote cache
cratons cache config --backend s3 --url s3://my-bucket/cratons-cache

# Fetch artifact from remote cache
cratons cache fetch <hash>

# Push artifacts to remote cache
cratons cache push --all        # Push all artifacts
cratons cache push --hash <h>   # Push specific artifact

# Clean local store (garbage collection)
cratons gc --keep-days 30
```

### Workspace Commands

```bash
# Run command in all packages
cratons ws run npm test

# Run in specific packages
cratons ws run npm build --filter "packages/*"

# List workspace packages
cratons ws list

# Show dependency graph
cratons ws graph
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CRATONS_HOME` | Data directory | `~/.cratons` |
| `CRATONS_CACHE_DIR` | Cache directory | `$CRATONS_HOME/cache` |
| `CRATONS_LOG` | Log level | `info` |
| `CRATONS_NO_COLOR` | Disable colors | - |
| `AWS_*` | S3 remote cache | - |

### Config File

```toml
# ~/.config/cratons/config.toml

[cache]
# Local cache directory
dir = "~/.cratons/cache"

[cache.remote]
type = "s3"
bucket = "my-cache"
region = "us-east-1"
prefix = "cratons"

[network]
# Registry timeout in seconds
timeout = 30

# Concurrent downloads
concurrency = 4

[build]
# Default memory limit
memory_limit = "4GB"

# Default CPU limit
cpu_limit = 4
```

## Output Formats

### Default (Human-Readable)

```
$ cratons install
Resolving dependencies...
  Added lodash@4.17.21 (npm)
  Added express@4.18.2 (npm)
  Added body-parser@1.20.2 (npm)

Installed 3 packages in 1.23s
```

### JSON

```bash
$ cratons tree --format json
{
  "packages": [
    {
      "name": "lodash",
      "version": "4.17.21",
      "ecosystem": "npm",
      "dependencies": []
    }
  ]
}
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Dependency resolution failed |
| 3 | Build failed |
| 4 | Audit found vulnerabilities |
| 5 | Network error |

## Shell Completions

```bash
# Bash
cratons completions bash > /etc/bash_completion.d/cratons

# Zsh
cratons completions zsh > ~/.zfunc/_cratons

# Fish
cratons completions fish > ~/.config/fish/completions/cratons.fish
```

## Examples

### Basic Workflow

```bash
# Start new project
mkdir my-app && cd my-app
cratons init

# Add dependencies
cratons add express@npm
cratons add lodash@npm

# Install
cratons install

# Check for vulnerabilities
cratons audit

# Build
cratons build
```

### CI/CD Integration

```bash
#!/bin/bash
set -e

# Install with frozen lockfile
cratons install --frozen

# Audit (fail on high severity)
cratons audit --fail-on high

# Build
cratons build

# Push artifacts to cache
cratons cache push
```

### Monorepo Workflow

```bash
# Initialize workspace
cratons init --workspace

# Add shared dependency
cratons add typescript@npm

# Build all packages in order
cratons ws run npm build

# Test changed packages only
cratons ws run npm test --filter changed
```

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
