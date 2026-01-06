//! Workspace management for Cratons.
//!
//! This crate provides functionality for managing multi-package workspaces,
//! similar to Cargo workspaces or npm/pnpm workspaces. A workspace allows
//! multiple related packages to be developed and managed together.
//!
//! # Example
//!
//! ```ignore
//! use cratons_workspace::{Workspace, WorkspaceFilter};
//! use std::path::Path;
//!
//! let workspace = Workspace::load(Path::new("."))?;
//!
//! // Filter to specific packages
//! let filter = WorkspaceFilter::names(["@myorg/core", "@myorg/cli"]);
//! let selected = workspace.filter(&filter);
//!
//! // Get execution order respecting dependencies
//! for member in workspace.topological_order(&selected)? {
//!     println!("Build: {}", member.manifest.package.name);
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use cratons_core::{CratonsError, Result};
use cratons_manifest::Manifest;
use petgraph::algo::toposort;
use petgraph::graphmap::DiGraphMap;

/// A member of a workspace.
#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    /// Path to the member directory
    pub path: PathBuf,
    /// The member's manifest
    pub manifest: Manifest,
}

/// A workspace containing multiple packages.
#[derive(Debug, Clone)]
pub struct Workspace {
    /// The root manifest
    pub root_manifest: Manifest,
    /// The root path
    pub root_path: PathBuf,
    /// Workspace members
    pub members: Vec<WorkspaceMember>,
}

impl Workspace {
    /// Load a workspace from a directory.
    pub fn load(path: &Path) -> Result<Self> {
        let (root_manifest, _) = Manifest::find_and_load(path)?;

        if !root_manifest.is_workspace_root() {
            return Err(cratons_core::CratonsError::Workspace(
                "Not a workspace root".to_string(),
            ));
        }

        let mut members = Vec::new();

        // Check each member pattern
        if let Some(ref workspace) = root_manifest.workspace {
            // Build exclude patterns for filtering
            let exclude_patterns: Vec<glob::Pattern> = workspace
                .exclude
                .iter()
                .filter_map(|pattern| {
                    let full_pattern = path.join(pattern);
                    glob::Pattern::new(&full_pattern.to_string_lossy()).ok()
                })
                .collect();

            for pattern in &workspace.members {
                // Construct glob pattern relative to root
                let full_pattern = path.join(pattern);
                let pattern_str = full_pattern.to_string_lossy();

                for entry in glob::glob(&pattern_str).map_err(|e| {
                    cratons_core::CratonsError::Workspace(format!("Invalid glob pattern: {}", e))
                })? {
                    match entry {
                        Ok(member_path) => {
                            // Check if this path matches any exclude pattern
                            let path_str = member_path.to_string_lossy();
                            let is_excluded = exclude_patterns.iter().any(|p| p.matches(&path_str));

                            if is_excluded {
                                continue;
                            }

                            if member_path.is_dir() && member_path.join("cratons.toml").exists() {
                                // Load member manifest
                                let (manifest, _) = Manifest::find_and_load(&member_path)?;
                                // Canonicalize path for consistent comparisons
                                let canonical_path =
                                    member_path.canonicalize().unwrap_or(member_path);
                                members.push(WorkspaceMember {
                                    path: canonical_path,
                                    manifest,
                                });
                            }
                        }
                        Err(e) => {
                            return Err(cratons_core::CratonsError::Workspace(format!(
                                "Glob error: {}",
                                e
                            )));
                        }
                    }
                }
            }
        }

        // Canonicalize root path for consistent comparisons
        let canonical_root = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        Ok(Self {
            root_manifest,
            root_path: canonical_root,
            members,
        })
    }

    /// Find a member by name.
    pub fn find_member(&self, name: &str) -> Option<&WorkspaceMember> {
        self.members
            .iter()
            .find(|m| m.manifest.package.name == name)
    }

    /// Filter workspace members using the given filter.
    ///
    /// Returns indices of members that match the filter.
    /// If `include_dependencies` or `include_dependents` is set on the filter,
    /// this will expand the selection to include those as well.
    #[must_use]
    pub fn filter(&self, filter: &WorkspaceFilter) -> Vec<usize> {
        // First pass: find directly matching members
        let mut matched: HashSet<usize> = self
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| filter.matches(m))
            .map(|(i, _)| i)
            .collect();

        // If include_dependencies is set, add dependencies of matched packages
        if filter.include_dependencies {
            let initially_matched: Vec<usize> = matched.iter().copied().collect();
            for idx in initially_matched {
                self.collect_dependencies(idx, &mut matched);
            }
        }

        // If include_dependents is set, add dependents of matched packages
        if filter.include_dependents {
            let initially_matched: Vec<usize> = matched.iter().copied().collect();
            for idx in initially_matched {
                self.collect_dependents(idx, &mut matched);
            }
        }

        // Apply exclusions after expansion
        let result: Vec<usize> = matched
            .into_iter()
            .filter(|&i| {
                !filter
                    .exclude
                    .contains(&self.members[i].manifest.package.name)
            })
            .collect();

        result
    }

    /// Recursively collect all workspace dependencies of a member.
    fn collect_dependencies(&self, idx: usize, collected: &mut HashSet<usize>) {
        let member = &self.members[idx];
        let name_to_idx: HashMap<&str, usize> = self
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| (m.manifest.package.name.as_str(), i))
            .collect();

        // Check all dependency types
        let deps = member.manifest.all_dependencies(true);
        for (_ecosystem, name, _dep) in deps.iter() {
            if let Some(&dep_idx) = name_to_idx.get(name) {
                if collected.insert(dep_idx) {
                    // Recursively collect transitive dependencies
                    self.collect_dependencies(dep_idx, collected);
                }
            }
        }

        // Also check workspace dependencies
        for (name, _ws_dep) in &deps.workspace {
            if let Some(&dep_idx) = name_to_idx.get(name.as_str()) {
                if collected.insert(dep_idx) {
                    self.collect_dependencies(dep_idx, collected);
                }
            }
        }
    }

    /// Recursively collect all workspace dependents (reverse dependencies) of a member.
    fn collect_dependents(&self, idx: usize, collected: &mut HashSet<usize>) {
        let target_name = &self.members[idx].manifest.package.name;

        for (i, member) in self.members.iter().enumerate() {
            if collected.contains(&i) {
                continue;
            }

            let deps = member.manifest.all_dependencies(true);

            // Check if this member depends on our target
            let depends_on_target = deps.iter().any(|(_eco, name, _)| name == target_name)
                || deps.workspace.contains_key(target_name);

            if depends_on_target {
                if collected.insert(i) {
                    // Recursively collect dependents of this dependent
                    self.collect_dependents(i, collected);
                }
            }
        }
    }

    /// Get workspace members in topological order based on inter-workspace dependencies.
    ///
    /// This ensures that dependencies are processed before their dependents.
    /// If `indices` is provided, only those members are included (but still ordered).
    pub fn topological_order(&self, indices: &[usize]) -> Result<Vec<&WorkspaceMember>> {
        // Build name -> index map for all members
        let name_to_idx: HashMap<&str, usize> = self
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| (m.manifest.package.name.as_str(), i))
            .collect();

        // Build set of included indices for filtering
        let included: HashSet<usize> = indices.iter().copied().collect();

        // Build dependency graph
        let mut graph = DiGraphMap::<usize, ()>::new();

        // Add nodes for all included members
        for &idx in indices {
            graph.add_node(idx);
        }

        // Add edges for dependencies between workspace members
        for &idx in indices {
            let member = &self.members[idx];

            // Check all dependency types (including dev dependencies)
            let deps = member.manifest.all_dependencies(true);
            for (_ecosystem, name, _dep) in deps.iter() {
                // If the dependency is a workspace member and included, add edge
                if let Some(&dep_idx) = name_to_idx.get(name) {
                    if included.contains(&dep_idx) {
                        // Edge from dependency to dependent (dep_idx must come before idx)
                        graph.add_edge(dep_idx, idx, ());
                    }
                }
            }

            // Also check workspace dependencies
            for (name, _ws_dep) in &member.manifest.all_dependencies(true).workspace {
                if let Some(&dep_idx) = name_to_idx.get(name.as_str()) {
                    if included.contains(&dep_idx) {
                        graph.add_edge(dep_idx, idx, ());
                    }
                }
            }
        }

        // Topological sort
        let sorted = toposort(&graph, None).map_err(|cycle| {
            let node = cycle.node_id();
            let name = &self.members[node].manifest.package.name;
            CratonsError::DependencyCycle(format!("Cycle detected involving package: {name}"))
        })?;

        // Map back to members
        Ok(sorted.into_iter().map(|i| &self.members[i]).collect())
    }

    /// Get all workspace members in topological order.
    pub fn all_topological(&self) -> Result<Vec<&WorkspaceMember>> {
        let all_indices: Vec<_> = (0..self.members.len()).collect();
        self.topological_order(&all_indices)
    }

    /// Get members that depend on the given member (direct dependents).
    #[must_use]
    pub fn dependents_of(&self, name: &str) -> Vec<&WorkspaceMember> {
        self.members
            .iter()
            .filter(|m| {
                let deps = m.manifest.all_dependencies(true);
                // Check regular dependencies
                deps.iter().any(|(_eco, n, _)| n == name)
                    // Check workspace dependencies
                    || deps.workspace.contains_key(name)
            })
            .collect()
    }

    /// Get members that the given member depends on (direct dependencies that are in workspace).
    #[must_use]
    pub fn workspace_dependencies_of(&self, name: &str) -> Vec<&WorkspaceMember> {
        let member = match self.find_member(name) {
            Some(m) => m,
            None => return vec![],
        };

        let workspace_names: HashSet<_> = self
            .members
            .iter()
            .map(|m| m.manifest.package.name.as_str())
            .collect();

        let deps = member.manifest.all_dependencies(true);
        let mut result = Vec::new();

        // Check regular dependencies
        for (_eco, name, _dep) in deps.iter() {
            if workspace_names.contains(name) {
                if let Some(m) = self.find_member(name) {
                    result.push(m);
                }
            }
        }

        // Check workspace dependencies
        for (name, _ws_dep) in &deps.workspace {
            if let Some(m) = self.find_member(name) {
                result.push(m);
            }
        }

        result
    }

    /// List all member names.
    #[must_use]
    pub fn member_names(&self) -> Vec<&str> {
        self.members
            .iter()
            .map(|m| m.manifest.package.name.as_str())
            .collect()
    }
}

/// Filter for selecting workspace members.
///
/// Filters can be combined and support multiple matching strategies:
/// - Exact name match
/// - Glob pattern match
/// - Path-based matching
/// - Scoped package matching (e.g., `@org/*`)
#[derive(Debug, Clone, Default)]
pub struct WorkspaceFilter {
    /// Specific package names to include
    names: Vec<String>,
    /// Glob patterns to match package names
    patterns: Vec<glob::Pattern>,
    /// Paths to include (relative to workspace root)
    paths: Vec<PathBuf>,
    /// If true, also include dependencies of matched packages
    include_dependencies: bool,
    /// If true, also include dependents of matched packages
    include_dependents: bool,
    /// Packages to explicitly exclude
    exclude: Vec<String>,
}

impl WorkspaceFilter {
    /// Create a new empty filter (matches all).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a filter matching specific package names.
    pub fn names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: names.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    /// Create a filter from a glob pattern (e.g., `@myorg/*`, `packages-*`).
    pub fn pattern(pattern: &str) -> Result<Self> {
        let pat = glob::Pattern::new(pattern).map_err(|e| {
            CratonsError::Workspace(format!("Invalid filter pattern '{pattern}': {e}"))
        })?;

        Ok(Self {
            patterns: vec![pat],
            ..Default::default()
        })
    }

    /// Create a filter matching packages at specific paths.
    pub fn paths<I, P>(paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        Self {
            paths: paths.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    /// Add more package names to match.
    #[must_use]
    pub fn with_names<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.names.extend(names.into_iter().map(Into::into));
        self
    }

    /// Add a glob pattern to match.
    pub fn with_pattern(mut self, pattern: &str) -> Result<Self> {
        let pat = glob::Pattern::new(pattern).map_err(|e| {
            CratonsError::Workspace(format!("Invalid filter pattern '{pattern}': {e}"))
        })?;
        self.patterns.push(pat);
        Ok(self)
    }

    /// Also include dependencies of matched packages.
    #[must_use]
    pub fn with_dependencies(mut self) -> Self {
        self.include_dependencies = true;
        self
    }

    /// Also include dependents of matched packages.
    #[must_use]
    pub fn with_dependents(mut self) -> Self {
        self.include_dependents = true;
        self
    }

    /// Exclude specific packages.
    #[must_use]
    pub fn excluding<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude.extend(names.into_iter().map(Into::into));
        self
    }

    /// Check if the filter is empty (matches all).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.patterns.is_empty() && self.paths.is_empty()
    }

    /// Check if a member matches this filter.
    fn matches(&self, member: &WorkspaceMember) -> bool {
        let name = &member.manifest.package.name;

        // Check exclusions first
        if self.exclude.contains(name) {
            return false;
        }

        // Empty filter matches all
        if self.is_empty() {
            return true;
        }

        // Check exact name match
        if self.names.contains(name) {
            return true;
        }

        // Check glob patterns
        for pattern in &self.patterns {
            if pattern.matches(name) {
                return true;
            }
        }

        // Check path match
        for filter_path in &self.paths {
            if member.path.ends_with(filter_path) || &member.path == filter_path {
                return true;
            }
        }

        false
    }
}

/// Workspace execution context for running commands across members.
pub struct WorkspaceExecutor<'a> {
    workspace: &'a Workspace,
    filter: WorkspaceFilter,
    parallel: bool,
    fail_fast: bool,
    topological: bool,
}

impl<'a> WorkspaceExecutor<'a> {
    /// Create a new executor for the given workspace.
    #[must_use]
    pub fn new(workspace: &'a Workspace) -> Self {
        Self {
            workspace,
            filter: WorkspaceFilter::new(),
            parallel: false,
            fail_fast: true,
            topological: false,
        }
    }

    /// Set the filter for selecting members.
    #[must_use]
    pub fn with_filter(mut self, filter: WorkspaceFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Enable parallel execution.
    #[must_use]
    pub fn parallel(mut self) -> Self {
        self.parallel = true;
        self
    }

    /// Disable fail-fast behavior (continue on error).
    #[must_use]
    pub fn continue_on_error(mut self) -> Self {
        self.fail_fast = false;
        self
    }

    /// Execute in topological order.
    #[must_use]
    pub fn topological(mut self) -> Self {
        self.topological = true;
        self
    }

    /// Get the selected members in execution order.
    pub fn selected_members(&self) -> Result<Vec<&WorkspaceMember>> {
        let indices = self.workspace.filter(&self.filter);

        if self.topological {
            self.workspace.topological_order(&indices)
        } else {
            Ok(indices
                .iter()
                .map(|&i| &self.workspace.members[i])
                .collect())
        }
    }

    /// Get the number of selected members.
    #[must_use]
    pub fn count(&self) -> usize {
        self.workspace.filter(&self.filter).len()
    }

    /// Check if parallel execution is enabled.
    #[must_use]
    pub fn is_parallel(&self) -> bool {
        self.parallel
    }

    /// Check if fail-fast is enabled.
    #[must_use]
    pub fn is_fail_fast(&self) -> bool {
        self.fail_fast
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_load_valid_workspace() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create root manifest
        fs::write(
            root.join("cratons.toml"),
            r#"
            [package]
            name = "root"
            version = "0.1.0"

            [workspace]
            members = ["crates/*"]
            "#,
        )
        .unwrap();

        // Create member 1
        let member1 = root.join("crates").join("pkg-a");
        fs::create_dir_all(&member1).unwrap();
        fs::write(
            member1.join("cratons.toml"),
            r#"
            [package]
            name = "pkg-a"
            version = "0.1.0"
            "#,
        )
        .unwrap();

        // Create member 2
        let member2 = root.join("crates").join("pkg-b");
        fs::create_dir_all(&member2).unwrap();
        fs::write(
            member2.join("cratons.toml"),
            r#"
            [package]
            name = "pkg-b"
            version = "0.1.0"
            "#,
        )
        .unwrap();

        // Load workspace
        let workspace = Workspace::load(root).unwrap();

        assert_eq!(workspace.root_manifest.package.name, "root");
        assert_eq!(workspace.members.len(), 2);

        let pkg_a = workspace.find_member("pkg-a").unwrap();
        assert_eq!(pkg_a.manifest.package.version, "0.1.0");

        let pkg_b = workspace.find_member("pkg-b").unwrap();
        assert_eq!(pkg_b.manifest.package.version, "0.1.0");
    }

    #[test]
    fn test_not_a_workspace() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create regular package manifest (no [workspace])
        fs::write(
            root.join("cratons.toml"),
            r#"
            [package]
            name = "pkg-single"
            version = "0.1.0"
            "#,
        )
        .unwrap();

        let result = Workspace::load(root);
        assert!(result.is_err());
        match result {
            Err(cratons_core::CratonsError::Workspace(msg)) => {
                assert_eq!(msg, "Not a workspace root");
            }
            _ => panic!("Expected Workspace error"),
        }
    }

    #[test]
    fn test_empty_workspace_members() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create workspace with no matching members
        fs::write(
            root.join("cratons.toml"),
            r#"
            [package]
            name = "root"
            version = "0.1.0"

            [workspace]
            members = ["crates/*"]
            "#,
        )
        .unwrap();

        fs::create_dir_all(root.join("crates")).unwrap();
        // No packages inside crates/

        let workspace = Workspace::load(root).unwrap();
        assert_eq!(workspace.members.len(), 0);
    }

    #[test]
    fn test_ignores_non_package_directories() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(
            root.join("cratons.toml"),
            r#"
            [package]
            name = "root"
            version = "0.1.0"

            [workspace]
            members = ["crates/*"]
            "#,
        )
        .unwrap();

        let member_dir = root.join("crates").join("pkg-a");
        fs::create_dir_all(&member_dir).unwrap();
        fs::write(
            member_dir.join("cratons.toml"),
            r#"
            [package]
            name = "pkg-a"
            version = "0.1.0"
            "#,
        )
        .unwrap();

        // Create a directory without cratons.toml
        let junk_dir = root.join("crates").join("junk");
        fs::create_dir_all(&junk_dir).unwrap();

        let workspace = Workspace::load(root).unwrap();
        assert_eq!(workspace.members.len(), 1);
        assert_eq!(workspace.members[0].manifest.package.name, "pkg-a");
    }
}
