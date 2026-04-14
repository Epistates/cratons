# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security (phase 2 hardening: follow-ups F-1..F-6)

- **Go modules**: integrity verification now uses `sum.golang.org` with
  full Ed25519 signed-note verification of every `/lookup` response
  against a pinned trust root (cached at
  `~/.cache/cratons/keys/sum.golang.org.pub`). The resolver computes the
  `h1:` dirhash of the downloaded module zip and cross-checks it against
  the signed hash from the checksum database, producing a real
  cross-origin integrity guarantee (F-1).
- **Maven Central**: replaced the same-origin broken-SHA-1 attestation
  with PGP detached-signature verification of every JAR against keys
  fetched on first use from hardcoded trusted keyservers
  (`keys.openpgp.org` primary, `keyserver.ubuntu.com` fallback) and
  cached on disk. Returned keys are validated against the requested
  fingerprint to prevent keyserver substitution attacks. Project-level
  `[security.maven]` manifest config and lockfile TOFU pinning are
  tracked as follow-up F-2c (F-2a/F-2b).
- **Breaking**: `IntegrityPolicy::default()` is now `Required` — any
  package with an empty registry integrity string aborts the install,
  regardless of ecosystem. The previous default allowlisted Go and Maven
  as degraded-by-default because neither had a credible cross-origin
  integrity source. Both now do (F-1 and F-2), so the allowlist is
  unnecessary. Operators relying on the old behavior can set
  `IntegrityPolicy::RequiredWithEcosystemAllowlist(vec![...])` or
  `Skip` explicitly (F-final).
- **Benchmarks hygiene**: all `criterion::black_box` call sites migrated
  to `std::hint::black_box` (F-6).

### Deferred security follow-ups

- **F-1b** (sum.golang.org transparency-log inclusion/consistency proofs
  against Merkle tree tiles). Current design verifies signed-note
  signatures but not log-append-only invariants. Rationale in
  `docs/security-followups.md`.
- **F-2c** (Maven manifest `[security.maven]` config + lockfile TOFU).
  F-2b ships the library + install-time verification path; TOFU is a
  separate phase.
- **F-3, F-4, F-5**: dropped. Rationale in `docs/security-followups.md`.

## [0.1.0] - 2026-03-23

### Added

- Initial release of Cratons, a language-agnostic package manager with hermetic builds
- **cratons-core**: Core types, traits, and utilities for package management
- **cratons-store**: Content-addressable storage with local and remote (S3) backends
- **cratons-manifest**: Manifest parsing and validation for polyglot ecosystems (npm, PyPI, Cargo)
- **cratons-lockfile**: Deterministic lockfile format and operations
- **cratons-resolver**: Dependency resolution using PubGrub with registry clients
- **cratons-builder**: Isolated build execution via OCI containers (youki)
- **cratons-installer**: Hermetic package installation with integrity verification
- **cratons-workspace**: Workspace and monorepo support
- **cratons-security**: Security auditing, SBOM generation, and signature verification (Sigstore, GPG, Minisign)
- **cratons-sandbox**: Cross-platform sandboxed execution (Linux namespaces, macOS sandbox-exec, Windows Job Objects)
- **cratons-environment**: Hermetic environment management with environment variable isolation
- **cratons-credentials**: Secure credential management with keyring integration

### Security

- **Critical**: Added hash re-verification after remote cache download to prevent cache poisoning attacks (`remote.rs`)
- **Critical**: Implemented SSRF protection for S3 remote cache with endpoint validation blocking localhost, metadata endpoints, and private IP ranges (`remote.rs`)
- **High**: Fixed TOCTOU vulnerability in mount path validation by canonicalizing paths before security checks (`spec.rs`)
- **High**: Added file locking to garbage collection to prevent race conditions during concurrent access (`gc.rs`)
- **High**: Implemented atomic file writes with temp files and exclusive locking in CAS to prevent corruption (`cas.rs`)
- **High**: Fixed GPG verification to use "any key matches" semantics for multi-key verification (`verify.rs`)
- **Medium**: Corrected Windows sandbox isolation level from `OsSandbox` to `Process` (Job Objects only provide resource limits)
- **Medium**: Expanded Linux environment variable blocklist to 100+ entries covering glibc exploitation vectors, locale hijacking, and shell exploits
- **Medium**: Tightened macOS executable whitelist by removing permissive paths (`/usr/local/bin`, `/opt/homebrew/bin`)
- **Medium**: Made network utility binaries conditional on `NetworkAccess::Full` in macOS sandbox
- **Low**: Changed internal data structures from HashMap to BTreeMap for deterministic iteration order
- **Low**: Added comprehensive S3 bucket name validation following AWS naming rules

### Changed

- `Ecosystem` enum now derives `Ord` for BTreeMap compatibility
- `PackageMetadata` dependencies fields now use `BTreeMap` instead of `HashMap`
- Remote cache `object_url()` now returns `Result<String>` with validation
