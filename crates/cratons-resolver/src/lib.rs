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
    let mut hash_input = serde_json::to_value(manifest)
        .expect("manifest serialization for freshness hashing should not fail");
    sort_json_objects(&mut hash_input);
    let hash_input = serde_json::to_vec(&hash_input)
        .expect("manifest canonical serialization for freshness hashing should not fail");
    Hasher::hash_bytes(HashAlgorithm::Blake3, &hash_input)
}

fn sort_json_objects(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                sort_json_objects(value);
            }

            let mut entries = map
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));

            map.clear();
            for (key, value) in entries {
                map.insert(key, value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                sort_json_objects(value);
            }
        }
        _ => {}
    }
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
    /// Resolved archive content hash, if the archive has been downloaded into CAS.
    pub resolved_hash: Option<cratons_core::ContentHash>,
    /// Whether this is a direct dependency
    pub direct: bool,
    /// Enabled features
    pub features: Vec<String>,
    /// Dependencies (name, version)
    pub dependencies: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratons_manifest::dependency::DetailedDependency;
    use cratons_manifest::{Dependency, Manifest};

    fn url_dep(url: &str, sha256: &str) -> Dependency {
        Dependency::Detailed(DetailedDependency {
            url: Some(url.to_string()),
            sha256: Some(sha256.to_string()),
            ..DetailedDependency::default()
        })
    }

    #[test]
    fn manifest_hash_changes_when_url_checksum_changes() {
        let mut manifest_a = Manifest::default();
        manifest_a.dependencies.url.insert(
            "asset".to_string(),
            url_dep(
                "https://example.com/pkg.tgz",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );

        let mut manifest_b = manifest_a.clone();
        manifest_b.dependencies.url.insert(
            "asset".to_string(),
            url_dep(
                "https://example.com/pkg.tgz",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        );

        assert_ne!(
            compute_manifest_hash(&manifest_a),
            compute_manifest_hash(&manifest_b)
        );
    }

    #[test]
    fn manifest_hash_is_independent_of_map_insertion_order() {
        let mut manifest_a = Manifest::default();
        manifest_a.dependencies.npm.insert(
            "left-pad".to_string(),
            Dependency::Version("^1.3.0".to_string()),
        );
        manifest_a.dependencies.npm.insert(
            "lodash".to_string(),
            Dependency::Version("^4.17.21".to_string()),
        );
        manifest_a
            .environment
            .vars
            .insert("NODE_ENV".to_string(), "production".to_string());
        manifest_a
            .environment
            .vars
            .insert("TZ".to_string(), "UTC".to_string());

        let mut manifest_b = Manifest::default();
        manifest_b
            .environment
            .vars
            .insert("TZ".to_string(), "UTC".to_string());
        manifest_b
            .environment
            .vars
            .insert("NODE_ENV".to_string(), "production".to_string());
        manifest_b.dependencies.npm.insert(
            "lodash".to_string(),
            Dependency::Version("^4.17.21".to_string()),
        );
        manifest_b.dependencies.npm.insert(
            "left-pad".to_string(),
            Dependency::Version("^1.3.0".to_string()),
        );

        assert_eq!(
            compute_manifest_hash(&manifest_a),
            compute_manifest_hash(&manifest_b)
        );
    }

    #[tokio::test]
    async fn url_dependencies_resolve_without_registry_and_without_fake_hash() {
        let mut manifest = Manifest::default();
        manifest.dependencies.url.insert(
            "asset".to_string(),
            url_dep(
                "https://example.com/pkg.tgz",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );

        let resolver = Resolver::with_defaults(false).unwrap();
        let resolution = resolver.resolve(&manifest).await.unwrap();
        let pkg = resolution
            .packages
            .iter()
            .find(|pkg| pkg.ecosystem == Ecosystem::Url && pkg.name == "asset")
            .expect("url package should resolve");

        assert_eq!(pkg.source, "https://example.com/pkg.tgz");
        assert!(pkg.integrity.starts_with("sha256-"));
        assert!(pkg.resolved_hash.is_none());
    }
}
