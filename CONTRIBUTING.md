# Contributing to Cratons

Thank you for your interest in contributing to Cratons! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Architecture Overview](#architecture-overview)

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- **Rust**: 1.85+ (edition 2024)
- **Git**: For version control
- **Platform-specific**:
  - Linux: For full container sandbox testing
  - macOS: For sandbox-exec testing
  - Windows: For Job Objects testing

### Quick Start

```bash
# Clone the repository
git clone https://github.com/rnpm/cratons.git
cd cratons

# Build the project
cargo build --workspace

# Run tests
cargo test --workspace

# Run with debug logging
RUST_LOG=debug cargo run -- --help
```

## Development Setup

### Recommended Tools

```bash
# Install development tools
cargo install cargo-watch    # Auto-rebuild on changes
cargo install cargo-nextest  # Faster test runner
cargo install cargo-llvm-cov # Code coverage
cargo install cargo-audit    # Security audit
cargo install cargo-deny     # License and dependency checks
```

### IDE Setup

**VS Code** (recommended):
```json
{
  "rust-analyzer.cargo.features": "all",
  "rust-analyzer.check.command": "clippy"
}
```

**IntelliJ/CLion**: Install the Rust plugin and enable Clippy integration.

### Environment Variables

```bash
# Enable debug logging
export RUST_LOG=cratons=debug

# Enable backtrace on panics
export RUST_BACKTRACE=1

# For testing sandbox features
export CRATONS_TEST_SANDBOX=1
```

## Making Changes

### Branching Strategy

- `main`: Stable, release-ready code
- `feature/*`: New features
- `fix/*`: Bug fixes
- `docs/*`: Documentation only

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `security`: Security fixes

Examples:
```
feat(sandbox): add LocalhostOnly network mode for macOS

fix(resolver): handle empty version constraints correctly

docs(readme): update installation instructions
```

### Error Messages

Follow youki conventions:
- Lowercase, no trailing period
- Include context (file paths, package names)
- Use `thiserror` for typed errors

```rust
// Good
#[error("failed to parse manifest at {path}")]
ManifestParse { path: PathBuf, #[source] source: toml::de::Error },

// Bad
#[error("Failed to parse manifest.")]
ManifestParse(String),
```

## Testing

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p cratons-sandbox

# With coverage
cargo llvm-cov --workspace --html

# Integration tests (may require privileges)
cargo test --workspace -- --ignored
```

### Test Categories

1. **Unit Tests**: In-module tests with `#[cfg(test)]`
2. **Integration Tests**: Cross-crate tests in `tests/`
3. **Platform Tests**: Platform-specific with `#[cfg(target_os = "...")]`

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_behavior() {
        // Arrange
        let input = create_test_input();

        // Act
        let result = function_under_test(input);

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value, expected_value);
    }

    #[tokio::test]
    async fn test_async_operation() {
        // For async code
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_specific() {
        // Platform-specific tests
    }
}
```

## Submitting Changes

### Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes
4. **Test** thoroughly
5. **Push** to your fork
6. **Open** a pull request

### PR Checklist

- [ ] Code compiles without warnings (`cargo build --workspace`)
- [ ] All tests pass (`cargo test --workspace`)
- [ ] Clippy is happy (`cargo clippy --workspace -- -D warnings`)
- [ ] Code is formatted (`cargo fmt --check`)
- [ ] Documentation is updated if needed
- [ ] CHANGELOG.md is updated for user-facing changes
- [ ] Commit messages follow conventions

### PR Description Template

```markdown
## Summary
Brief description of changes.

## Changes
- List of specific changes

## Testing
How were these changes tested?

## Related Issues
Closes #123
```

## Coding Standards

### Rust Style

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` defaults
- Enable all Clippy lints (pedantic, nursery)

### Documentation

- All public items need doc comments
- Use `///` for item docs, `//!` for module docs
- Include examples in doc comments

```rust
/// Executes a command in a sandboxed environment.
///
/// # Arguments
///
/// * `config` - Sandbox configuration including command and mounts
///
/// # Returns
///
/// Returns `SandboxResult` with exit code, stdout, and stderr.
///
/// # Errors
///
/// Returns `SandboxError` if:
/// - Command is empty
/// - Sandbox initialization fails
/// - Timeout is exceeded
///
/// # Example
///
/// ```no_run
/// let result = sandbox.execute(&config).await?;
/// assert!(result.success());
/// ```
pub async fn execute(&self, config: &SandboxConfig) -> Result<SandboxResult, SandboxError>
```

### Lints

Our `Cargo.toml` enforces:

```toml
[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "warn"

[workspace.lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
cargo = "warn"
```

### Dependencies

Before adding a dependency:
1. Check if it's necessary (can stdlib do it?)
2. Verify it's actively maintained
3. Check for security advisories
4. Prefer pure Rust over C bindings
5. Consider binary size impact

## Architecture Overview

```
cratons/                    # Workspace root
├── crates/
│   ├── cratons/           # CLI binary
│   ├── cratons-core/      # Shared types (Ecosystem, ContentHash, etc.)
│   ├── cratons-manifest/  # cratons.toml parsing
│   ├── cratons-lockfile/  # cratons.lock management
│   ├── cratons-resolver/  # Dependency resolution (MVS)
│   ├── cratons-store/     # Content-addressable storage
│   ├── cratons-builder/   # Build execution
│   ├── cratons-installer/ # Package installation
│   ├── cratons-sandbox/   # Cross-platform sandboxing
│   ├── cratons-environment/ # Hermetic environments
│   ├── cratons-workspace/ # Monorepo support
│   └── cratons-security/  # Auditing and SBOM
└── docs/               # Documentation
```

### Key Design Decisions

1. **Hybrid Resolution (MVS + PubGrub)**: MVS for Go/Rust ecosystems, PubGrub (SAT) for npm/Python
2. **Content-Addressed**: Blake3 hashing for deduplication
3. **Hermetic**: No network during builds
4. **Multi-Ecosystem**: npm, PyPI, crates.io, Go, Maven

See [CRATONS_DESIGN_PLAN.md](CRATONS_DESIGN_PLAN.md) for detailed architecture.

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/rnpm/cratons/discussions)
- **Bugs**: Open an [Issue](https://github.com/rnpm/cratons/issues)
- **Security**: See [SECURITY.md](SECURITY.md)

## Recognition

Contributors are recognized in:
- Release notes
- CHANGELOG.md
- GitHub contributors page

Thank you for contributing!
