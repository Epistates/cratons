//! # cratons-resolver
//!
//! Dependency resolution using Minimal Version Selection (MVS).
//!
//! This crate implements the resolution algorithm inspired by Go modules
//! and Cargo, selecting the minimum version that satisfies all constraints.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod features;
pub mod graph;
pub mod markers;
pub mod mvs;
pub mod registry;
pub mod sat;

pub use graph::{DependencyEdge, DependencyGraph, DependencyKind};
pub use markers::{MarkerEvaluator, ParsedPythonDep, PythonEnvironmentConfig};
pub use mvs::Resolver;
pub use registry::{
    CratesIoClient, GoProxyClient, MavenClient, NpmClient, PackageMetadata, PyPiClient, Registry,
    RegistryClient,
};

use cratons_core::{ContentHash, Ecosystem, HashAlgorithm, Hasher, Result};
use cratons_lockfile::Lockfile;
use cratons_manifest::Manifest;
use std::path::Path;

/// Resolve dependencies from a manifest.
pub async fn resolve(manifest: &Manifest) -> Result<Resolution> {
    let resolver = Resolver::with_defaults(false)?;
    resolver.resolve(manifest).await
}

/// Resolve dependencies, respecting an existing lockfile.
pub async fn resolve_with_lockfile(manifest: &Manifest, lockfile: &Lockfile) -> Result<Resolution> {
    let resolver = Resolver::with_defaults(false)?;
    resolver.resolve_with_lockfile(manifest, lockfile).await
}

/// Resolve dependencies and generate a lockfile.
///
/// This is the primary API for dependency resolution with lockfile generation.
/// It will:
/// 1. Load existing lockfile if present
/// 2. Check if manifest has changed (using content hash)
/// 3. Either reuse locked versions or re-resolve
/// 4. Generate and save the lockfile
pub async fn resolve_and_lock(
    manifest: &Manifest,
    manifest_path: &Path,
) -> Result<(Resolution, Lockfile)> {
    let resolver = Resolver::with_defaults(false)?;
    resolver.resolve_and_lock(manifest, manifest_path).await
}

/// Compute the content hash of a manifest for lockfile freshness checking.
///
/// This hash includes all configuration that affects resolution:
/// - Regular dependencies
/// - Dev dependencies
/// - Optional dependencies
/// - Dependency overrides
/// - Resolution strategy settings
#[must_use]
pub fn compute_manifest_hash(manifest: &Manifest) -> ContentHash {
    // Hash a canonical representation of all dependencies and configuration
    let mut hash_input = String::new();

    // Regular dependencies
    hash_input.push_str("dependencies:\n");
    for ecosystem in Ecosystem::all() {
        let deps = manifest.dependencies.for_ecosystem(*ecosystem);
        let mut sorted_deps: Vec<_> = deps.iter().collect();
        sorted_deps.sort_by_key(|(name, _)| *name);
        for (name, dep) in sorted_deps {
            hash_input.push_str(&format!(
                "{}:{}:{}\n",
                ecosystem,
                name,
                dep.version().unwrap_or("*")
            ));
        }
    }

    // Environment
    hash_input.push_str("environment:\n");
    if let Some(v) = &manifest.environment.node { hash_input.push_str(&format!("node:{}\n", v)); }
    if let Some(v) = &manifest.environment.python { hash_input.push_str(&format!("python:{}\n", v)); }
    if let Some(v) = &manifest.environment.rust { hash_input.push_str(&format!("rust:{}\n", v)); }
    if let Some(v) = &manifest.environment.go { hash_input.push_str(&format!("go:{}\n", v)); }
    if let Some(v) = &manifest.environment.java { hash_input.push_str(&format!("java:{}\n", v)); }

    hash_input.push_str("system:\n");
    for sys in &manifest.environment.system {
        hash_input.push_str(&format!("{}\n", sys));
    }

    hash_input.push_str("env-vars:\n");
    let mut sorted_vars: Vec<_> = manifest.environment.vars.iter().collect();
    sorted_vars.sort_by_key(|(k, _)| *k);
    for (k, v) in sorted_vars {
        hash_input.push_str(&format!("{}:{}\n", k, v));
    }

    // Build Dependencies
    hash_input.push_str("build-dependencies:\n");
    for ecosystem in Ecosystem::all() {
        let deps = manifest.build.dependencies.for_ecosystem(*ecosystem);
        let mut sorted_deps: Vec<_> = deps.iter().collect();
        sorted_deps.sort_by_key(|(name, _)| *name);
        for (name, dep) in sorted_deps {
            hash_input.push_str(&format!(
                "{}:{}:{}\n",
                ecosystem,
                name,
                dep.version().unwrap_or("*")
            ));
        }
    }

    // Dev dependencies
    hash_input.push_str("dev-dependencies:\n");
    for ecosystem in Ecosystem::all() {
        let deps = manifest.dev_dependencies.for_ecosystem(*ecosystem);
        let mut sorted_deps: Vec<_> = deps.iter().collect();
        sorted_deps.sort_by_key(|(name, _)| *name);
        for (name, dep) in sorted_deps {
            hash_input.push_str(&format!(
                "{}:{}:{}\n",
                ecosystem,
                name,
                dep.version().unwrap_or("*")
            ));
        }
    }

    // Optional dependencies
    hash_input.push_str("optional-dependencies:\n");
    for ecosystem in Ecosystem::all() {
        let deps = manifest.optional_dependencies.for_ecosystem(*ecosystem);
        let mut sorted_deps: Vec<_> = deps.iter().collect();
        sorted_deps.sort_by_key(|(name, _)| *name);
        for (name, dep) in sorted_deps {
            hash_input.push_str(&format!(
                "{}:{}:{}\n",
                ecosystem,
                name,
                dep.version().unwrap_or("*")
            ));
        }
    }

    // Overrides
    hash_input.push_str("overrides:\n");
    for ecosystem in Ecosystem::all() {
        let deps = manifest.overrides.for_ecosystem(*ecosystem);
        let mut sorted_deps: Vec<_> = deps.iter().collect();
        sorted_deps.sort_by_key(|(name, _)| *name);
        for (name, dep) in sorted_deps {
            hash_input.push_str(&format!(
                "{}:{}:{}\n",
                ecosystem,
                name,
                dep.version().unwrap_or("*")
            ));
        }
    }

    // Resolution strategy
    hash_input.push_str("resolution:\n");
    let mut sorted_resolution: Vec<_> = manifest.resolution.iter().collect();
    sorted_resolution.sort_by_key(|(eco, _)| eco.to_string());
    for (ecosystem, strategy) in sorted_resolution {
        hash_input.push_str(&format!("{}:{:?}\n", ecosystem, strategy));
    }

    Hasher::hash_bytes(HashAlgorithm::Blake3, hash_input.as_bytes())
}

/// The result of dependency resolution.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// Resolved packages grouped by ecosystem
    pub packages: Vec<ResolvedPackage>,
    /// The dependency graph
    pub graph: DependencyGraph,
}

impl Resolution {
    /// Create a new empty resolution.
    #[must_use]
    pub fn new() -> Self {
        Self {
            packages: Vec::new(),
            graph: DependencyGraph::new(),
        }
    }

    /// Get all packages for an ecosystem.
    pub fn packages_for(&self, ecosystem: Ecosystem) -> impl Iterator<Item = &ResolvedPackage> {
        self.packages
            .iter()
            .filter(move |p| p.ecosystem == ecosystem)
    }

    /// Get the total number of resolved packages.
    #[must_use]
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// Convert to a lockfile.
    pub fn to_lockfile(&self, manifest_hash: cratons_core::ContentHash) -> Lockfile {
        let mut lockfile = Lockfile::new(manifest_hash);

        for pkg in &self.packages {
            lockfile.add_package(cratons_lockfile::LockedPackage {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                ecosystem: pkg.ecosystem,
                source: pkg.source.clone(),
                integrity: pkg.integrity.clone(),
                resolved_hash: pkg.resolved_hash.clone(),
                direct: pkg.direct,
                features: pkg.features.clone(),
                dependencies: pkg
                    .dependencies
                    .iter()
                    .map(|(n, v)| cratons_lockfile::DependencyRef::new(n.clone(), v.clone()))
                    .collect(),
            });
        }

        lockfile
    }
}

impl Default for Resolution {
    fn default() -> Self {
        Self::new()
    }
}

/// A resolved package.
#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    /// Package name
    pub name: String,
    /// Resolved version
    pub version: String,
    /// Ecosystem
    pub ecosystem: Ecosystem,
    /// Source URL
    pub source: String,
    /// Integrity hash
    pub integrity: String,
    /// Resolved content hash
    pub resolved_hash: cratons_core::ContentHash,
    /// Whether this is a direct dependency
    pub direct: bool,
    /// Enabled features
    pub features: Vec<String>,
    /// Dependencies (name, version)
    pub dependencies: Vec<(String, String)>,
}
