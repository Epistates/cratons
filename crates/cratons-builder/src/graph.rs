//! Build graph for DAG-based build orchestration.
//!
//! This module provides a directed acyclic graph (DAG) for orchestrating
//! builds in monorepos where packages may depend on each other. It ensures:
//!
//! - Dependencies are built before their dependents
//! - Independent packages can be built in parallel
//! - Cycles are detected and reported as errors
//!
//! # Example
//!
//! ```ignore
//! use cratons_builder::{BuildGraph, BuildNode, BuildOrchestrator};
//!
//! let mut graph = BuildGraph::new();
//!
//! let app = graph.add_node(BuildNode::new("app", "1.0.0", config1, source1));
//! let lib = graph.add_node(BuildNode::new("lib", "1.0.0", config2, source2));
//!
//! // app depends on lib
//! graph.add_dependency(app, lib)?;
//!
//! // Get build order (lib first, then app)
//! let order = graph.topological_order()?;
//!
//! // Or use the orchestrator for parallel execution
//! let orchestrator = BuildOrchestrator::new(&store, graph);
//! let results = orchestrator.execute(4).await?; // 4 parallel workers
//! ```

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use petgraph::Direction;
use petgraph::algo::toposort;
use petgraph::graph::{DiGraph, NodeIndex};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use cratons_core::{CratonsError, Result};
use cratons_store::Store;
use cratons_store::remote::RemoteCache;

use crate::BuildResult;
use crate::config::BuildConfig;
use crate::executor::BuildExecutor;

/// A node in the build graph representing a single package to build.
#[derive(Debug, Clone)]
pub struct BuildNode {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Build configuration for this package
    pub config: BuildConfig,
    /// Source directory for the package
    pub source_dir: PathBuf,
}

impl BuildNode {
    /// Create a new build node.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        config: BuildConfig,
        source_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            config,
            source_dir: source_dir.into(),
        }
    }

    /// Get a unique identifier for this node.
    #[must_use]
    pub fn id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// A directed acyclic graph of build dependencies.
///
/// Each node represents a package that needs to be built, and edges
/// represent "depends on" relationships. The graph ensures that
/// dependencies are built before their dependents.
pub struct BuildGraph {
    graph: DiGraph<BuildNode, ()>,
    name_to_index: HashMap<String, NodeIndex>,
}

impl BuildGraph {
    /// Create a new empty build graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            name_to_index: HashMap::new(),
        }
    }

    /// Add a build node to the graph.
    ///
    /// Returns the node index for use in adding dependencies.
    pub fn add_node(&mut self, node: BuildNode) -> NodeIndex {
        let id = node.id();
        let index = self.graph.add_node(node);
        self.name_to_index.insert(id, index);
        index
    }

    /// Get a node index by package id (name@version).
    #[must_use]
    pub fn get_node(&self, id: &str) -> Option<NodeIndex> {
        self.name_to_index.get(id).copied()
    }

    /// Add a dependency edge: `dependent` depends on `dependency`.
    ///
    /// This means `dependency` must be built before `dependent`.
    ///
    /// # Errors
    ///
    /// Returns an error if adding this edge would create a cycle.
    pub fn add_dependency(&mut self, dependent: NodeIndex, dependency: NodeIndex) -> Result<()> {
        // Add edge from dependent to dependency (dependent -> dependency means
        // "dependent requires dependency", so dependency should be built first)
        self.graph.add_edge(dependent, dependency, ());

        // Check for cycles using toposort
        if toposort(&self.graph, None).is_err() {
            // Remove the edge that caused the cycle
            self.graph.remove_edge(
                self.graph
                    .find_edge(dependent, dependency)
                    .expect("edge was just added"),
            );

            let dep_node = &self.graph[dependent];
            let dependency_node = &self.graph[dependency];
            return Err(CratonsError::DependencyCycle(format!(
                "{} <-> {}",
                dep_node.id(),
                dependency_node.id()
            )));
        }

        Ok(())
    }

    /// Get the number of nodes in the graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get all nodes that the given node depends on.
    pub fn dependencies(&self, node: NodeIndex) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.neighbors_directed(node, Direction::Outgoing)
    }

    /// Get all nodes that depend on the given node.
    pub fn dependents(&self, node: NodeIndex) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.neighbors_directed(node, Direction::Incoming)
    }

    /// Get the topological order of all nodes.
    ///
    /// Returns nodes in an order where all dependencies come before
    /// their dependents.
    ///
    /// # Errors
    ///
    /// Returns an error if the graph contains a cycle (should not happen
    /// if all edges were added via `add_dependency`).
    pub fn topological_order(&self) -> Result<Vec<NodeIndex>> {
        toposort(&self.graph, None)
            .map(|mut order| {
                // toposort returns in dependency order (sources first), but
                // with our edge direction (dependent -> dependency), we need
                // to reverse to get build order
                order.reverse();
                order
            })
            .map_err(|cycle| {
                let node = &self.graph[cycle.node_id()];
                CratonsError::DependencyCycle(node.id())
            })
    }

    /// Get packages that can be built in parallel batches.
    ///
    /// Returns a vector of "levels" where all packages in a level can be
    /// built in parallel (they have no dependencies on each other).
    ///
    /// # Errors
    ///
    /// Returns an error if the graph contains a cycle.
    pub fn parallel_batches(&self) -> Result<Vec<Vec<NodeIndex>>> {
        let mut batches = Vec::new();
        let mut remaining: HashSet<NodeIndex> = self.graph.node_indices().collect();
        let mut completed: HashSet<NodeIndex> = HashSet::new();

        while !remaining.is_empty() {
            // Find all nodes whose dependencies are all completed
            let ready: Vec<NodeIndex> = remaining
                .iter()
                .filter(|&node| self.dependencies(*node).all(|dep| completed.contains(&dep)))
                .copied()
                .collect();

            if ready.is_empty() && !remaining.is_empty() {
                // This shouldn't happen if the graph is a DAG
                return Err(CratonsError::DependencyCycle(
                    "Unable to find ready nodes - possible cycle".into(),
                ));
            }

            for node in &ready {
                remaining.remove(node);
                completed.insert(*node);
            }

            batches.push(ready);
        }

        Ok(batches)
    }

    /// Get a reference to the underlying graph for inspection.
    #[must_use]
    pub fn inner(&self) -> &DiGraph<BuildNode, ()> {
        &self.graph
    }

    /// Get a node by its index.
    #[must_use]
    pub fn node(&self, index: NodeIndex) -> Option<&BuildNode> {
        self.graph.node_weight(index)
    }
}

impl Default for BuildGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Orchestrator for executing builds according to a build graph.
///
/// This handles parallel execution of independent packages while
/// respecting dependency ordering.
pub struct BuildOrchestrator<'a> {
    store: &'a Store,
    graph: BuildGraph,
    remote_cache: Option<Arc<RemoteCache>>,
    push_to_remote: bool,
}

impl<'a> BuildOrchestrator<'a> {
    /// Create a new build orchestrator.
    #[must_use]
    pub fn new(store: &'a Store, graph: BuildGraph) -> Self {
        Self {
            store,
            graph,
            remote_cache: None,
            push_to_remote: false,
        }
    }

    /// Set the remote cache for the orchestrator.
    #[must_use]
    pub fn with_remote_cache(mut self, cache: Arc<RemoteCache>) -> Self {
        self.remote_cache = Some(cache);
        self
    }

    /// Enable pushing built artifacts to the remote cache.
    #[must_use]
    pub fn with_push_to_remote(mut self, push: bool) -> Self {
        self.push_to_remote = push;
        self
    }

    /// Execute all builds in the graph with the given parallelism.
    ///
    /// # Arguments
    ///
    /// * `max_parallel` - Maximum number of concurrent builds
    ///
    /// # Returns
    ///
    /// A map from package id to build result.
    ///
    /// # Errors
    ///
    /// Returns an error if any build fails, or if there's a cycle in
    /// the build graph.
    pub async fn execute(self, max_parallel: usize) -> Result<HashMap<String, BuildResult>> {
        let batches = self.graph.parallel_batches()?;
        let mut results = HashMap::new();

        info!(
            "Building {} packages in {} batches (max {} parallel)",
            self.graph.node_count(),
            batches.len(),
            max_parallel
        );

        let semaphore = Arc::new(Semaphore::new(max_parallel));

        for (batch_idx, batch) in batches.into_iter().enumerate() {
            debug!(
                "Starting batch {} with {} packages",
                batch_idx + 1,
                batch.len()
            );

            let mut futures = FuturesUnordered::new();

            for node_idx in batch {
                let node = self
                    .graph
                    .node(node_idx)
                    .expect("node index should be valid")
                    .clone();

                let semaphore = Arc::clone(&semaphore);
                let store = self.store;
                let remote_cache = self.remote_cache.clone();
                let push_to_remote = self.push_to_remote;

                futures.push(async move {
                    let _permit = semaphore
                        .acquire()
                        .await
                        .map_err(|e| CratonsError::BuildFailed(e.to_string()))?;

                    let mut executor = BuildExecutor::new(store);
                    if let Some(cache) = remote_cache {
                        executor = executor.with_remote_cache(cache);
                    }
                    if push_to_remote {
                        executor = executor.with_push_to_remote(true);
                    }

                    let result = executor.build(&node.config, &node.source_dir).await?;
                    Ok::<_, CratonsError>((node.id(), result))
                });
            }

            // Wait for all builds in this batch to complete
            while let Some(result) = futures.next().await {
                match result {
                    Ok((id, build_result)) => {
                        info!(
                            "Built {} in {:.2}s{}",
                            id,
                            build_result.duration_secs,
                            if build_result.cached { " (cached)" } else { "" }
                        );
                        results.insert(id, build_result);
                    }
                    Err(e) => {
                        warn!("Build failed: {}", e);
                        return Err(e);
                    }
                }
            }
        }

        info!("All {} builds completed", results.len());
        Ok(results)
    }

    /// Execute builds sequentially (no parallelism).
    ///
    /// This is useful for debugging or when system resources are limited.
    pub async fn execute_sequential(self) -> Result<HashMap<String, BuildResult>> {
        self.execute(1).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BuildConfig;

    fn make_config(name: &str) -> BuildConfig {
        BuildConfig::new(
            name.to_string(),
            "1.0.0".to_string(),
            "echo hello".to_string(),
        )
    }

    #[test]
    fn test_empty_graph() {
        let graph = BuildGraph::new();
        assert_eq!(graph.node_count(), 0);
        assert!(graph.topological_order().unwrap().is_empty());
    }

    #[test]
    fn test_single_node() {
        let mut graph = BuildGraph::new();
        let node = BuildNode::new("pkg", "1.0.0", make_config("pkg"), "/src");
        graph.add_node(node);

        assert_eq!(graph.node_count(), 1);

        let order = graph.topological_order().unwrap();
        assert_eq!(order.len(), 1);
    }

    #[test]
    fn test_linear_dependencies() {
        let mut graph = BuildGraph::new();

        let a = graph.add_node(BuildNode::new("a", "1.0.0", make_config("a"), "/src/a"));
        let b = graph.add_node(BuildNode::new("b", "1.0.0", make_config("b"), "/src/b"));
        let c = graph.add_node(BuildNode::new("c", "1.0.0", make_config("c"), "/src/c"));

        // c depends on b, b depends on a
        // Build order should be: a, b, c
        graph.add_dependency(c, b).unwrap();
        graph.add_dependency(b, a).unwrap();

        let order = graph.topological_order().unwrap();
        assert_eq!(order.len(), 3);

        // a should come first (no dependencies)
        // b should come second (depends only on a)
        // c should come last (depends on b)
        let order_names: Vec<_> = order
            .iter()
            .map(|&idx| graph.node(idx).unwrap().name.as_str())
            .collect();
        assert_eq!(order_names, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_diamond_dependencies() {
        let mut graph = BuildGraph::new();

        //     a
        //    / \
        //   b   c
        //    \ /
        //     d
        let a = graph.add_node(BuildNode::new("a", "1.0.0", make_config("a"), "/src/a"));
        let b = graph.add_node(BuildNode::new("b", "1.0.0", make_config("b"), "/src/b"));
        let c = graph.add_node(BuildNode::new("c", "1.0.0", make_config("c"), "/src/c"));
        let d = graph.add_node(BuildNode::new("d", "1.0.0", make_config("d"), "/src/d"));

        graph.add_dependency(d, b).unwrap();
        graph.add_dependency(d, c).unwrap();
        graph.add_dependency(b, a).unwrap();
        graph.add_dependency(c, a).unwrap();

        let order = graph.topological_order().unwrap();
        assert_eq!(order.len(), 4);

        // a must come first, d must come last
        let order_names: Vec<_> = order
            .iter()
            .map(|&idx| graph.node(idx).unwrap().name.as_str())
            .collect();
        assert_eq!(order_names[0], "a");
        assert_eq!(order_names[3], "d");
    }

    #[test]
    fn test_cycle_detection() {
        let mut graph = BuildGraph::new();

        let a = graph.add_node(BuildNode::new("a", "1.0.0", make_config("a"), "/src/a"));
        let b = graph.add_node(BuildNode::new("b", "1.0.0", make_config("b"), "/src/b"));

        graph.add_dependency(a, b).unwrap();
        let result = graph.add_dependency(b, a);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CratonsError::DependencyCycle(_)
        ));
    }

    #[test]
    fn test_parallel_batches() {
        let mut graph = BuildGraph::new();

        //     a
        //    / \
        //   b   c
        //    \ /
        //     d
        let a = graph.add_node(BuildNode::new("a", "1.0.0", make_config("a"), "/src/a"));
        let b = graph.add_node(BuildNode::new("b", "1.0.0", make_config("b"), "/src/b"));
        let c = graph.add_node(BuildNode::new("c", "1.0.0", make_config("c"), "/src/c"));
        let d = graph.add_node(BuildNode::new("d", "1.0.0", make_config("d"), "/src/d"));

        graph.add_dependency(d, b).unwrap();
        graph.add_dependency(d, c).unwrap();
        graph.add_dependency(b, a).unwrap();
        graph.add_dependency(c, a).unwrap();

        let batches = graph.parallel_batches().unwrap();

        // Should be 3 batches:
        // 1. [a] - no dependencies
        // 2. [b, c] - both depend only on a
        // 3. [d] - depends on b and c
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), 1); // a
        assert_eq!(batches[1].len(), 2); // b, c
        assert_eq!(batches[2].len(), 1); // d
    }

    #[test]
    fn test_get_node_by_id() {
        let mut graph = BuildGraph::new();
        graph.add_node(BuildNode::new("pkg", "1.0.0", make_config("pkg"), "/src"));

        assert!(graph.get_node("pkg@1.0.0").is_some());
        assert!(graph.get_node("other@1.0.0").is_none());
    }
}
