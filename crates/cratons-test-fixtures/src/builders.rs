//! Builder pattern implementations for test data structures.
//!
//! Provides fluent APIs for constructing test manifests, lockfiles, packages,
//! and dependency graphs with sensible defaults.

use cratons_core::{ContentHash, Ecosystem, PackageId, PackageSpec, Version, VersionReq};
use cratons_lockfile::{DependencyRef, LockedPackage, Lockfile, ToolchainPin};
use cratons_manifest::{Dependency, Manifest};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

/// Builder for creating test `Manifest` instances.
///
/// # Example
///
/// ```rust
/// use cratons_test_fixtures::builders::ManifestBuilder;
/// use cratons_core::Ecosystem;
///
/// let manifest = ManifestBuilder::new("my-app")
///     .version("1.0.0")
///     .description("A test application")
///     .npm_dependency("lodash", "^4.17.0")
///     .pypi_dependency("requests", ">=2.28.0")
///     .node_version("20.10.0")
///     .build();
/// ```
pub struct ManifestBuilder {
    manifest: Manifest,
}

impl ManifestBuilder {
    /// Create a new manifest builder with the given package name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let mut manifest = Manifest::default();
        manifest.package.name = name.into();
        Self { manifest }
    }

    /// Set the package version.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.manifest.package.version = version.into();
        self
    }

    /// Set the package description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.manifest.package.description = description.into();
        self
    }

    /// Set the package authors.
    #[must_use]
    pub fn authors(mut self, authors: Vec<String>) -> Self {
        self.manifest.package.authors = authors;
        self
    }

    /// Add an npm dependency.
    #[must_use]
    pub fn npm_dependency(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        let dep = Dependency::Version(version.into());
        self.manifest.dependencies.npm.insert(name.into(), dep);
        self
    }

    /// Add a PyPI dependency.
    #[must_use]
    pub fn pypi_dependency(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        let dep = Dependency::Version(version.into());
        self.manifest.dependencies.pypi.insert(name.into(), dep);
        self
    }

    /// Add a crates.io dependency.
    #[must_use]
    pub fn crate_dependency(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        let dep = Dependency::Version(version.into());
        self.manifest.dependencies.crates.insert(name.into(), dep);
        self
    }

    /// Add a dependency with custom ecosystem.
    #[must_use]
    pub fn dependency(
        mut self,
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        let dep = Dependency::Version(version.into());

        match ecosystem {
            Ecosystem::Npm => {
                self.manifest.dependencies.npm.insert(name.into(), dep);
            }
            Ecosystem::PyPi => {
                self.manifest.dependencies.pypi.insert(name.into(), dep);
            }
            Ecosystem::Crates => {
                self.manifest.dependencies.crates.insert(name.into(), dep);
            }
            Ecosystem::Go => {
                self.manifest.dependencies.go.insert(name.into(), dep);
            }
            Ecosystem::Maven => {
                self.manifest.dependencies.maven.insert(name.into(), dep);
            }
            Ecosystem::Url => {}
        }
        self
    }

    /// Add a dev dependency.
    #[must_use]
    pub fn dev_dependency(
        mut self,
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        let dep = Dependency::Version(version.into());

        match ecosystem {
            Ecosystem::Npm => {
                self.manifest.dev_dependencies.npm.insert(name.into(), dep);
            }
            Ecosystem::PyPi => {
                self.manifest.dev_dependencies.pypi.insert(name.into(), dep);
            }
            Ecosystem::Crates => {
                self.manifest
                    .dev_dependencies
                    .crates
                    .insert(name.into(), dep);
            }
            Ecosystem::Go => {
                self.manifest.dev_dependencies.go.insert(name.into(), dep);
            }
            Ecosystem::Maven => {
                self.manifest
                    .dev_dependencies
                    .maven
                    .insert(name.into(), dep);
            }
            Ecosystem::Url => {}
        }
        self
    }

    /// Set Node.js version requirement.
    #[must_use]
    pub fn node_version(mut self, version: impl Into<String>) -> Self {
        self.manifest.environment.node = Some(version.into());
        self
    }

    /// Set Python version requirement.
    #[must_use]
    pub fn python_version(mut self, version: impl Into<String>) -> Self {
        self.manifest.environment.python = Some(version.into());
        self
    }

    /// Set Rust version requirement.
    #[must_use]
    pub fn rust_version(mut self, version: impl Into<String>) -> Self {
        self.manifest.environment.rust = Some(version.into());
        self
    }

    /// Add a script.
    #[must_use]
    pub fn script(mut self, name: impl Into<String>, command: impl Into<String>) -> Self {
        self.manifest.scripts.insert(name.into(), command.into());
        self
    }

    /// Build the manifest.
    #[must_use]
    pub fn build(self) -> Manifest {
        self.manifest
    }
}

/// Builder for creating test `Lockfile` instances.
///
/// # Example
///
/// ```rust
/// use cratons_test_fixtures::builders::LockfileBuilder;
/// use cratons_core::{ContentHash, Ecosystem};
///
/// let lockfile = LockfileBuilder::new()
///     .npm_package("lodash", "4.17.21", "sha256-abc123")
///     .pypi_package("requests", "2.28.0", "sha256-def456")
///     .build();
/// ```
pub struct LockfileBuilder {
    lockfile: Lockfile,
}

impl LockfileBuilder {
    /// Create a new lockfile builder.
    #[must_use]
    pub fn new() -> Self {
        Self::with_manifest_hash(ContentHash::blake3("test-manifest".to_string()))
    }

    /// Create a new lockfile builder with a specific manifest hash.
    #[must_use]
    pub fn with_manifest_hash(hash: ContentHash) -> Self {
        Self {
            lockfile: Lockfile::new(hash),
        }
    }

    /// Add a locked package.
    #[must_use]
    pub fn package(mut self, package: LockedPackage) -> Self {
        self.lockfile.add_package(package);
        self
    }

    /// Add an npm package.
    #[must_use]
    pub fn npm_package(
        self,
        name: impl Into<String>,
        version: impl Into<String>,
        integrity: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let version = version.into();
        let pkg = LockedPackage {
            name: name.clone(),
            version: version.clone(),
            ecosystem: Ecosystem::Npm,
            source: format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
            integrity: integrity.into(),
            resolved_hash: ContentHash::blake3(format!("{name}-{version}")),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };
        self.package(pkg)
    }

    /// Add a PyPI package.
    #[must_use]
    pub fn pypi_package(
        self,
        name: impl Into<String>,
        version: impl Into<String>,
        integrity: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let version = version.into();
        let pkg = LockedPackage {
            name: name.clone(),
            version: version.clone(),
            ecosystem: Ecosystem::PyPi,
            source: format!("https://pypi.org/simple/{name}/{name}-{version}.whl"),
            integrity: integrity.into(),
            resolved_hash: ContentHash::blake3(format!("{name}-{version}")),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };
        self.package(pkg)
    }

    /// Add a crates.io package.
    #[must_use]
    pub fn crate_package(
        self,
        name: impl Into<String>,
        version: impl Into<String>,
        integrity: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let version = version.into();
        let pkg = LockedPackage {
            name: name.clone(),
            version: version.clone(),
            ecosystem: Ecosystem::Crates,
            source: format!("https://crates.io/api/v1/crates/{name}/{version}/download"),
            integrity: integrity.into(),
            resolved_hash: ContentHash::blake3(format!("{name}-{version}")),
            direct: true,
            features: vec![],
            dependencies: vec![],
        };
        self.package(pkg)
    }

    /// Add package dependencies.
    #[must_use]
    pub fn with_dependencies(
        mut self,
        name: &str,
        ecosystem: Ecosystem,
        deps: Vec<(&str, &str)>,
    ) -> Self {
        if let Some(pkg) = self
            .lockfile
            .packages
            .iter_mut()
            .find(|p| p.name == name && p.ecosystem == ecosystem)
        {
            pkg.dependencies = deps
                .into_iter()
                .map(|(n, v)| DependencyRef::new(n, v))
                .collect();
        }
        self
    }

    /// Add a toolchain pin.
    #[must_use]
    pub fn toolchain(
        mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        let version_str = version.into();
        let pin = ToolchainPin {
            version: version_str.clone(),
            hash: ContentHash::blake3(format!("toolchain-{version_str}")),
            url: url.into(),
        };
        self.lockfile.toolchains.insert(name.into(), pin);
        self
    }

    /// Build the lockfile.
    #[must_use]
    pub fn build(self) -> Lockfile {
        self.lockfile
    }
}

impl Default for LockfileBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating test `PackageSpec` instances.
///
/// # Example
///
/// ```rust
/// use cratons_test_fixtures::builders::PackageSpecBuilder;
/// use cratons_core::Ecosystem;
///
/// let spec = PackageSpecBuilder::new(Ecosystem::Npm, "lodash")
///     .version("^4.17.0")
///     .features(vec!["es6".to_string()])
///     .optional()
///     .build();
/// ```
pub struct PackageSpecBuilder {
    spec: PackageSpec,
}

impl PackageSpecBuilder {
    /// Create a new package spec builder.
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>) -> Self {
        let id = PackageId::new(ecosystem, name);
        Self {
            spec: PackageSpec::new(id, VersionReq::Any),
        }
    }

    /// Set the version requirement.
    pub fn version(mut self, version: &str) -> Self {
        let ecosystem = self.spec.id.ecosystem;
        self.spec.version_req = VersionReq::parse(version, ecosystem).unwrap_or(VersionReq::Any);
        self
    }

    /// Set features.
    #[must_use]
    pub fn features(mut self, features: Vec<String>) -> Self {
        self.spec.features = features;
        self
    }

    /// Mark as optional.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.spec.optional = true;
        self
    }

    /// Set git source.
    #[must_use]
    pub fn git(mut self, url: impl Into<String>) -> Self {
        self.spec.git = Some(url.into());
        self
    }

    /// Set git revision.
    #[must_use]
    pub fn rev(mut self, rev: impl Into<String>) -> Self {
        self.spec.rev = Some(rev.into());
        self
    }

    /// Build the package spec.
    #[must_use]
    pub fn build(self) -> PackageSpec {
        self.spec
    }
}

/// Builder for creating test package metadata.
pub struct PackageBuilder {
    id: PackageId,
    version: Option<Version>,
    source: Option<String>,
    integrity: Option<ContentHash>,
    features: Vec<String>,
    dependencies: Vec<PackageId>,
}

impl PackageBuilder {
    /// Create a new package builder.
    #[must_use]
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>) -> Self {
        Self {
            id: PackageId::new(ecosystem, name),
            version: None,
            source: None,
            integrity: None,
            features: vec![],
            dependencies: vec![],
        }
    }

    /// Set the version.
    pub fn version(mut self, version: &str) -> Self {
        self.version = Some(Version::parse(version, self.id.ecosystem).unwrap());
        self
    }

    /// Set the source URL.
    #[must_use]
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Set the integrity hash.
    #[must_use]
    pub fn integrity(mut self, hash: ContentHash) -> Self {
        self.integrity = Some(hash);
        self
    }

    /// Add features.
    #[must_use]
    pub fn features(mut self, features: Vec<String>) -> Self {
        self.features = features;
        self
    }

    /// Add a dependency.
    #[must_use]
    pub fn dependency(mut self, dep: PackageId) -> Self {
        self.dependencies.push(dep);
        self
    }

    /// Build as a `LockedPackage`.
    #[must_use]
    pub fn build_locked(self) -> LockedPackage {
        let version = self
            .version
            .unwrap_or_else(|| Version::parse("1.0.0", self.id.ecosystem).unwrap());
        let name = self.id.name.clone();
        let source = self
            .source
            .unwrap_or_else(|| format!("https://registry.example.com/{}/{}", name, version));
        let integrity = self
            .integrity
            .map(|h| format!("{}:{}", h.algorithm, h.value))
            .unwrap_or_else(|| "sha256-test".to_string());

        LockedPackage {
            name: self.id.name,
            version: version.to_string(),
            ecosystem: self.id.ecosystem,
            source,
            integrity,
            resolved_hash: ContentHash::blake3(format!("{}-{}", name, version)),
            direct: true,
            features: self.features,
            dependencies: self
                .dependencies
                .into_iter()
                .map(|id| DependencyRef::new(id.name, "1.0.0"))
                .collect(),
        }
    }
}

/// Builder for creating test dependency graphs for MVS (Minimal Version Selection) testing.
///
/// Creates a directed graph where nodes are packages and edges represent dependencies.
///
/// # Example
///
/// ```rust
/// use cratons_test_fixtures::builders::DependencyGraphBuilder;
/// use cratons_core::Ecosystem;
///
/// let graph = DependencyGraphBuilder::new()
///     .package(Ecosystem::Npm, "lodash", "4.17.21")
///     .package(Ecosystem::Npm, "express", "4.18.0")
///     .depends_on("express", "lodash", "^4.17.0")
///     .build();
/// ```
pub struct DependencyGraphBuilder {
    graph: DiGraph<PackageNode, DependencyEdge>,
    nodes: HashMap<String, NodeIndex>,
}

/// A node in the dependency graph representing a package.
#[derive(Debug, Clone)]
pub struct PackageNode {
    /// Package ecosystem
    pub ecosystem: Ecosystem,
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
}

/// An edge in the dependency graph representing a dependency relationship.
#[derive(Debug, Clone)]
pub struct DependencyEdge {
    /// Version requirement
    pub version_req: String,
}

impl DependencyGraphBuilder {
    /// Create a new dependency graph builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            nodes: HashMap::new(),
        }
    }

    /// Add a package to the graph.
    #[must_use]
    pub fn package(
        mut self,
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let node = PackageNode {
            ecosystem,
            name: name.clone(),
            version: version.into(),
        };
        let idx = self.graph.add_node(node);
        self.nodes.insert(name, idx);
        self
    }

    /// Add a dependency relationship between two packages.
    pub fn depends_on(mut self, from: &str, to: &str, version_req: impl Into<String>) -> Self {
        if let (Some(&from_idx), Some(&to_idx)) = (self.nodes.get(from), self.nodes.get(to)) {
            let edge = DependencyEdge {
                version_req: version_req.into(),
            };
            self.graph.add_edge(from_idx, to_idx, edge);
        }
        self
    }

    /// Build the dependency graph.
    #[must_use]
    pub fn build(self) -> DiGraph<PackageNode, DependencyEdge> {
        self.graph
    }

    /// Get a reference to the graph (for inspection during building).
    #[must_use]
    pub fn graph(&self) -> &DiGraph<PackageNode, DependencyEdge> {
        &self.graph
    }

    /// Create a diamond dependency scenario for testing.
    ///
    /// Creates: A -> B -> D
    ///          A -> C -> D
    /// Where B and C may depend on different versions of D.
    #[must_use]
    pub fn diamond(ecosystem: Ecosystem) -> DiGraph<PackageNode, DependencyEdge> {
        Self::new()
            .package(ecosystem, "a", "1.0.0")
            .package(ecosystem, "b", "1.0.0")
            .package(ecosystem, "c", "1.0.0")
            .package(ecosystem, "d-v1", "1.0.0")
            .package(ecosystem, "d-v2", "2.0.0")
            .depends_on("a", "b", "^1.0.0")
            .depends_on("a", "c", "^1.0.0")
            .depends_on("b", "d-v1", "^1.0.0")
            .depends_on("c", "d-v2", "^2.0.0")
            .build()
    }

    /// Create a deep dependency chain for testing.
    ///
    /// Creates: A -> B -> C -> D -> E
    #[must_use]
    pub fn chain(ecosystem: Ecosystem, depth: usize) -> DiGraph<PackageNode, DependencyEdge> {
        let mut builder = Self::new();
        let packages: Vec<String> = (0..depth)
            .map(|i| format!("pkg-{}", (b'a' + i as u8) as char))
            .collect();

        for pkg in &packages {
            builder = builder.package(ecosystem, pkg, "1.0.0");
        }

        for i in 0..packages.len() - 1 {
            builder = builder.depends_on(&packages[i], &packages[i + 1], "^1.0.0");
        }

        builder.build()
    }

    /// Create a wide dependency fan-out for testing.
    ///
    /// Creates: A -> [B1, B2, B3, ...]
    #[must_use]
    pub fn fanout(ecosystem: Ecosystem, width: usize) -> DiGraph<PackageNode, DependencyEdge> {
        let mut builder = Self::new().package(ecosystem, "root", "1.0.0");

        for i in 0..width {
            let dep_name = format!("dep-{i}");
            builder = builder
                .package(ecosystem, &dep_name, "1.0.0")
                .depends_on("root", &dep_name, "^1.0.0");
        }

        builder.build()
    }
}

impl Default for DependencyGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_builder() {
        let manifest = ManifestBuilder::new("test-app")
            .version("1.0.0")
            .description("A test application")
            .npm_dependency("lodash", "^4.17.0")
            .node_version("20.10.0")
            .build();

        assert_eq!(manifest.package.name, "test-app");
        assert_eq!(manifest.package.version, "1.0.0");
        assert!(manifest.dependencies.npm.contains_key("lodash"));
        assert_eq!(manifest.environment.node, Some("20.10.0".to_string()));
    }

    #[test]
    fn test_lockfile_builder() {
        let lockfile = LockfileBuilder::new()
            .npm_package("lodash", "4.17.21", "sha256-abc123")
            .build();

        assert_eq!(lockfile.packages.len(), 1);
        assert_eq!(lockfile.packages[0].name, "lodash");
        assert_eq!(lockfile.packages[0].ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn test_package_spec_builder() {
        let spec = PackageSpecBuilder::new(Ecosystem::Npm, "lodash")
            .version("^4.17.0")
            .features(vec!["es6".to_string()])
            .optional()
            .build();

        assert_eq!(spec.id.name, "lodash");
        assert_eq!(spec.features, vec!["es6"]);
        assert!(spec.optional);
    }

    #[test]
    fn test_dependency_graph_builder() {
        let graph = DependencyGraphBuilder::new()
            .package(Ecosystem::Npm, "a", "1.0.0")
            .package(Ecosystem::Npm, "b", "1.0.0")
            .depends_on("a", "b", "^1.0.0")
            .build();

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_diamond_dependency() {
        let graph = DependencyGraphBuilder::diamond(Ecosystem::Npm);
        assert_eq!(graph.node_count(), 5); // a, b, c, d-v1, d-v2
        assert_eq!(graph.edge_count(), 4); // a->b, a->c, b->d-v1, c->d-v2
    }

    #[test]
    fn test_chain_dependency() {
        let graph = DependencyGraphBuilder::chain(Ecosystem::Npm, 5);
        assert_eq!(graph.node_count(), 5);
        assert_eq!(graph.edge_count(), 4);
    }

    #[test]
    fn test_fanout_dependency() {
        let graph = DependencyGraphBuilder::fanout(Ecosystem::Npm, 10);
        assert_eq!(graph.node_count(), 11); // root + 10 deps
        assert_eq!(graph.edge_count(), 10);
    }
}
