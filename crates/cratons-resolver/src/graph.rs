//! Dependency graph representation.

use cratons_core::{Ecosystem, VersionReq};
use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::BTreeMap;

/// A node in the dependency graph.
#[derive(Debug, Clone)]
pub struct PackageNode {
    /// Package name
    pub name: String,
    /// Package ecosystem
    pub ecosystem: Ecosystem,
    /// Available versions (sorted)
    pub versions: Vec<String>,
    /// Resolved version (after MVS)
    pub resolved_version: Option<String>,
}

/// Type of dependency relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DependencyKind {
    /// Regular production dependency
    Normal,
    /// Development-only dependency
    Dev,
    /// Optional dependency (only installed when explicitly requested)
    Optional,
    /// Peer dependency (npm: must be provided by parent package)
    Peer,
    /// Peer dependency that is also optional
    PeerOptional,
}

impl Default for DependencyKind {
    fn default() -> Self {
        Self::Normal
    }
}

/// An edge in the dependency graph (dependency relationship).
#[derive(Debug, Clone)]
pub struct DependencyEdge {
    /// Version requirement
    pub version_req: VersionReq,
    /// Whether this is a direct dependency
    pub direct: bool,
    /// Features requested
    pub features: Vec<String>,
    /// Kind of dependency
    pub kind: DependencyKind,
    /// Whether this peer dependency is optional (npm peerDependenciesMeta)
    pub peer_optional: bool,
}

/// The dependency graph.
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    graph: DiGraph<PackageNode, DependencyEdge>,
    index_map: BTreeMap<(Ecosystem, String), NodeIndex>,
}

impl DependencyGraph {
    /// Create a new empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            index_map: BTreeMap::new(),
        }
    }

    /// Add a package node to the graph.
    pub fn add_package(&mut self, name: &str, ecosystem: Ecosystem) -> NodeIndex {
        let key = (ecosystem, name.to_string());

        if let Some(&idx) = self.index_map.get(&key) {
            return idx;
        }

        let node = PackageNode {
            name: name.to_string(),
            ecosystem,
            versions: Vec::new(),
            resolved_version: None,
        };

        let idx = self.graph.add_node(node);
        self.index_map.insert(key, idx);
        idx
    }

    /// Get a package node by name and ecosystem.
    #[must_use]
    pub fn get_package(&self, name: &str, ecosystem: Ecosystem) -> Option<&PackageNode> {
        let key = (ecosystem, name.to_string());
        self.index_map.get(&key).map(|&idx| &self.graph[idx])
    }

    /// Get a mutable package node.
    pub fn get_package_mut(
        &mut self,
        name: &str,
        ecosystem: Ecosystem,
    ) -> Option<&mut PackageNode> {
        let key = (ecosystem, name.to_string());
        self.index_map.get(&key).map(|&idx| &mut self.graph[idx])
    }

    /// Set available versions for a package.
    pub fn set_versions(&mut self, name: &str, ecosystem: Ecosystem, versions: Vec<String>) {
        if let Some(node) = self.get_package_mut(name, ecosystem) {
            node.versions = versions;
        }
    }

    /// Set the resolved version for a package.
    pub fn set_resolved_version(&mut self, name: &str, ecosystem: Ecosystem, version: String) {
        if let Some(node) = self.get_package_mut(name, ecosystem) {
            node.resolved_version = Some(version);
        }
    }

    /// Add a dependency edge.
    #[allow(clippy::too_many_arguments)]
    pub fn add_dependency(
        &mut self,
        from: &str,
        from_eco: Ecosystem,
        to: &str,
        to_eco: Ecosystem,
        version_req: VersionReq,
        direct: bool,
        features: Vec<String>,
        kind: DependencyKind,
    ) {
        let from_idx = self.add_package(from, from_eco);
        let to_idx = self.add_package(to, to_eco);

        let edge = DependencyEdge {
            version_req,
            direct,
            features,
            kind,
            peer_optional: kind == DependencyKind::PeerOptional,
        };

        self.graph.add_edge(from_idx, to_idx, edge);
    }

    /// Add a dependency edge with full options.
    #[allow(clippy::too_many_arguments)]
    pub fn add_dependency_with_options(
        &mut self,
        from: &str,
        from_eco: Ecosystem,
        to: &str,
        to_eco: Ecosystem,
        version_req: VersionReq,
        direct: bool,
        features: Vec<String>,
        kind: DependencyKind,
        peer_optional: bool,
    ) {
        let from_idx = self.add_package(from, from_eco);
        let to_idx = self.add_package(to, to_eco);

        let edge = DependencyEdge {
            version_req,
            direct,
            features,
            kind,
            peer_optional,
        };

        self.graph.add_edge(from_idx, to_idx, edge);
    }

    /// Get all dependencies of a package.
    pub fn dependencies(
        &self,
        name: &str,
        ecosystem: Ecosystem,
    ) -> Vec<(&PackageNode, &DependencyEdge)> {
        let key = (ecosystem, name.to_string());
        if let Some(&idx) = self.index_map.get(&key) {
            self.graph
                .edges_directed(idx, Direction::Outgoing)
                .map(|e| (&self.graph[e.target()], e.weight()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all dependents of a package (reverse dependencies).
    pub fn dependents(
        &self,
        name: &str,
        ecosystem: Ecosystem,
    ) -> Vec<(&PackageNode, &DependencyEdge)> {
        let key = (ecosystem, name.to_string());
        if let Some(&idx) = self.index_map.get(&key) {
            self.graph
                .edges_directed(idx, Direction::Incoming)
                .map(|e| (&self.graph[e.source()], e.weight()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get a topological ordering of packages.
    pub fn topological_order(&self) -> Vec<&PackageNode> {
        use petgraph::algo::toposort;

        match toposort(&self.graph, None) {
            Ok(order) => {
                // Reverse: toposort returns roots first, but we want leaves first
                // (dependencies should come before dependants for installation)
                order
                    .into_iter()
                    .rev()
                    .map(|idx| &self.graph[idx])
                    .collect()
            }
            Err(_) => {
                // Cycle detected, return in arbitrary order
                self.graph
                    .node_indices()
                    .map(|idx| &self.graph[idx])
                    .collect()
            }
        }
    }

    /// Detect cycles in the graph.
    #[must_use]
    pub fn has_cycles(&self) -> bool {
        use petgraph::algo::is_cyclic_directed;
        is_cyclic_directed(&self.graph)
    }

    /// Find all strongly connected components (cycles) in the graph using Tarjan's algorithm.
    ///
    /// Returns a list of cycles, where each cycle is a list of package names.
    /// Only returns components with more than one package (actual cycles).
    pub fn find_cycles(&self) -> Vec<Vec<String>> {
        use petgraph::algo::tarjan_scc;

        tarjan_scc(&self.graph)
            .into_iter()
            .filter(|scc| scc.len() > 1) // Only cycles, not single nodes
            .map(|scc| {
                scc.into_iter()
                    .map(|idx| {
                        let node = &self.graph[idx];
                        format!("{}:{}", node.ecosystem, node.name)
                    })
                    .collect()
            })
            .collect()
    }

    /// Get a detailed cycle description for error messages.
    ///
    /// Returns None if no cycles exist, otherwise returns a formatted
    /// description of all cycles found.
    pub fn describe_cycles(&self) -> Option<String> {
        let cycles = self.find_cycles();
        if cycles.is_empty() {
            return None;
        }

        let descriptions: Vec<String> = cycles
            .iter()
            .enumerate()
            .map(|(i, cycle)| {
                let cycle_str = cycle.join(" -> ");
                format!(
                    "  Cycle {}: {} -> {}",
                    i + 1,
                    cycle_str,
                    cycle.first().unwrap_or(&String::new())
                )
            })
            .collect();

        Some(format!(
            "Dependency cycles detected:\n{}",
            descriptions.join("\n")
        ))
    }

    /// Get the number of packages in the graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get the number of dependency edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Iterate over all packages.
    pub fn packages(&self) -> impl Iterator<Item = &PackageNode> {
        self.graph.node_indices().map(|idx| &self.graph[idx])
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_package() {
        let mut graph = DependencyGraph::new();
        let _idx = graph.add_package("lodash", Ecosystem::Npm);

        let pkg = graph.get_package("lodash", Ecosystem::Npm);
        assert!(pkg.is_some());
        assert_eq!(pkg.unwrap().name, "lodash");
    }

    #[test]
    fn test_add_dependency() {
        let mut graph = DependencyGraph::new();

        graph.add_dependency(
            "express",
            Ecosystem::Npm,
            "body-parser",
            Ecosystem::Npm,
            VersionReq::Any,
            false,
            vec![],
            DependencyKind::Normal,
        );

        let deps = graph.dependencies("express", Ecosystem::Npm);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0.name, "body-parser");
    }

    #[test]
    fn test_topological_order() {
        let mut graph = DependencyGraph::new();

        graph.add_dependency(
            "a",
            Ecosystem::Npm,
            "b",
            Ecosystem::Npm,
            VersionReq::Any,
            true,
            vec![],
            DependencyKind::Normal,
        );
        graph.add_dependency(
            "b",
            Ecosystem::Npm,
            "c",
            Ecosystem::Npm,
            VersionReq::Any,
            false,
            vec![],
            DependencyKind::Normal,
        );

        let order = graph.topological_order();
        assert_eq!(order.len(), 3);

        // c should come before b, b before a
        let names: Vec<_> = order.iter().map(|n| n.name.as_str()).collect();
        let c_pos = names.iter().position(|&n| n == "c").unwrap();
        let b_pos = names.iter().position(|&n| n == "b").unwrap();
        let a_pos = names.iter().position(|&n| n == "a").unwrap();

        assert!(c_pos < b_pos);
        assert!(b_pos < a_pos);
    }

    #[test]
    fn test_no_cycles() {
        let mut graph = DependencyGraph::new();

        // Linear dependency chain: a -> b -> c
        graph.add_dependency(
            "a",
            Ecosystem::Npm,
            "b",
            Ecosystem::Npm,
            VersionReq::Any,
            true,
            vec![],
            DependencyKind::Normal,
        );
        graph.add_dependency(
            "b",
            Ecosystem::Npm,
            "c",
            Ecosystem::Npm,
            VersionReq::Any,
            false,
            vec![],
            DependencyKind::Normal,
        );

        assert!(!graph.has_cycles());
        assert!(graph.find_cycles().is_empty());
        assert!(graph.describe_cycles().is_none());
    }

    #[test]
    fn test_simple_cycle() {
        let mut graph = DependencyGraph::new();

        // Cycle: a -> b -> c -> a
        graph.add_dependency(
            "a",
            Ecosystem::Npm,
            "b",
            Ecosystem::Npm,
            VersionReq::Any,
            true,
            vec![],
            DependencyKind::Normal,
        );
        graph.add_dependency(
            "b",
            Ecosystem::Npm,
            "c",
            Ecosystem::Npm,
            VersionReq::Any,
            false,
            vec![],
            DependencyKind::Normal,
        );
        graph.add_dependency(
            "c",
            Ecosystem::Npm,
            "a",
            Ecosystem::Npm,
            VersionReq::Any,
            false,
            vec![],
            DependencyKind::Normal,
        );

        assert!(graph.has_cycles());

        let cycles = graph.find_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 3); // a, b, c form a cycle

        let description = graph.describe_cycles();
        assert!(description.is_some());
        let desc = description.unwrap();
        assert!(desc.contains("Cycle 1:"));
    }

    #[test]
    fn test_self_cycle() {
        let mut graph = DependencyGraph::new();

        // Self-referential cycle (shouldn't happen in real packages, but test it)
        graph.add_dependency(
            "a",
            Ecosystem::Npm,
            "a",
            Ecosystem::Npm,
            VersionReq::Any,
            true,
            vec![],
            DependencyKind::Normal,
        );

        // Note: a single self-loop is still a cycle
        assert!(graph.has_cycles());
    }

    #[test]
    fn test_multiple_cycles() {
        let mut graph = DependencyGraph::new();

        // Two separate cycles:
        // Cycle 1: a -> b -> a
        graph.add_dependency(
            "a",
            Ecosystem::Npm,
            "b",
            Ecosystem::Npm,
            VersionReq::Any,
            true,
            vec![],
            DependencyKind::Normal,
        );
        graph.add_dependency(
            "b",
            Ecosystem::Npm,
            "a",
            Ecosystem::Npm,
            VersionReq::Any,
            false,
            vec![],
            DependencyKind::Normal,
        );

        // Cycle 2: x -> y -> z -> x
        graph.add_dependency(
            "x",
            Ecosystem::Npm,
            "y",
            Ecosystem::Npm,
            VersionReq::Any,
            true,
            vec![],
            DependencyKind::Normal,
        );
        graph.add_dependency(
            "y",
            Ecosystem::Npm,
            "z",
            Ecosystem::Npm,
            VersionReq::Any,
            false,
            vec![],
            DependencyKind::Normal,
        );
        graph.add_dependency(
            "z",
            Ecosystem::Npm,
            "x",
            Ecosystem::Npm,
            VersionReq::Any,
            false,
            vec![],
            DependencyKind::Normal,
        );

        assert!(graph.has_cycles());

        let cycles = graph.find_cycles();
        assert_eq!(cycles.len(), 2);

        let description = graph.describe_cycles();
        assert!(description.is_some());
        let desc = description.unwrap();
        assert!(desc.contains("Cycle 1:"));
        assert!(desc.contains("Cycle 2:"));
    }

    #[test]
    fn test_dependency_kinds() {
        let mut graph = DependencyGraph::new();

        graph.add_dependency(
            "app",
            Ecosystem::Npm,
            "lodash",
            Ecosystem::Npm,
            VersionReq::Any,
            true,
            vec![],
            DependencyKind::Normal,
        );
        graph.add_dependency(
            "app",
            Ecosystem::Npm,
            "react",
            Ecosystem::Npm,
            VersionReq::Any,
            true,
            vec![],
            DependencyKind::Peer,
        );
        graph.add_dependency(
            "app",
            Ecosystem::Npm,
            "chalk",
            Ecosystem::Npm,
            VersionReq::Any,
            false,
            vec![],
            DependencyKind::Optional,
        );

        let deps = graph.dependencies("app", Ecosystem::Npm);
        assert_eq!(deps.len(), 3);

        // Check that kind is set correctly
        let lodash = deps.iter().find(|(p, _)| p.name == "lodash").unwrap();
        assert_eq!(lodash.1.kind, DependencyKind::Normal);

        let react = deps.iter().find(|(p, _)| p.name == "react").unwrap();
        assert_eq!(react.1.kind, DependencyKind::Peer);

        let chalk = deps.iter().find(|(p, _)| p.name == "chalk").unwrap();
        assert_eq!(chalk.1.kind, DependencyKind::Optional);
    }
}
