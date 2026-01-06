//! Node.js environment management.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use cratons_store::Store;
use tracing::debug;

use crate::Result;
use crate::error::EnvironmentError;

/// Default Node.js version when not specified in manifest
const DEFAULT_NODE_VERSION: &str = "20";

/// File name for persisting Node version
const NODE_VERSION_FILE: &str = ".node-version";

/// A Node.js environment.
#[derive(Debug, Clone)]
pub struct NodeEnv {
    /// Root directory (.cratons/env/node/)
    root: PathBuf,
    /// Node.js version
    version: String,
    /// Path to the node binary
    node_binary: Option<PathBuf>,
    /// Path to node_modules in project
    node_modules: PathBuf,
}

impl NodeEnv {
    /// Set up a new Node.js environment with specified version.
    pub fn setup_with_version(
        env_root: &Path,
        project_dir: &Path,
        version: Option<&str>,
        store: &Store,
    ) -> Result<Self> {
        let root = env_root.join("node");
        fs::create_dir_all(&root)?;

        let version = version.unwrap_or(DEFAULT_NODE_VERSION).to_string();
        // M-21 FIX: Try to find Node in the toolchain store first, then fall back to system
        let node_binary = find_node_binary_with_store(&version, store)?;
        let node_modules = project_dir.join("node_modules");

        let env = Self {
            root: root.clone(),
            version,
            node_binary,
            node_modules,
        };

        env.create_structure()?;
        env.persist_version()?;

        debug!(
            "Created Node.js environment at {:?} (version {})",
            root, env.version
        );

        Ok(env)
    }

    /// Set up a new Node.js environment with default version.
    ///
    /// For explicit version control, use `setup_with_version` instead.
    pub fn setup(env_root: &Path, project_dir: &Path, store: &Store) -> Result<Self> {
        Self::setup_with_version(env_root, project_dir, None, store)
    }

    /// Load an existing Node.js environment.
    pub fn load(env_root: &Path) -> Result<Self> {
        let root = env_root.join("node");
        if !root.exists() {
            return Err(EnvironmentError::NotFound(root));
        }

        // Read persisted version from .node-version file
        let version_file = root.join(NODE_VERSION_FILE);
        let version = if version_file.exists() {
            fs::read_to_string(&version_file)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_NODE_VERSION.to_string())
        } else {
            DEFAULT_NODE_VERSION.to_string()
        };

        let node_binary = find_node_binary(&version).ok().flatten();

        // Try to find project dir from parent
        let project_dir = env_root
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(Path::new("."));
        let node_modules = project_dir.join("node_modules");

        Ok(Self {
            root,
            version,
            node_binary,
            node_modules,
        })
    }

    /// Persist the Node.js version to a file for later loading.
    fn persist_version(&self) -> Result<()> {
        let version_file = self.root.join(NODE_VERSION_FILE);
        let mut file = fs::File::create(&version_file)?;
        writeln!(file, "{}", self.version)?;
        Ok(())
    }

    /// Create the Node.js environment structure.
    fn create_structure(&self) -> Result<()> {
        let bin = self.root.join("bin");
        fs::create_dir_all(&bin)?;

        // Create symlinks to node, npm, npx
        if let Some(ref node_binary) = self.node_binary {
            let node_link = bin.join("node");
            let _ = fs::remove_file(&node_link);
            symlink(node_binary, &node_link)?;

            // Find npm relative to node
            if let Some(node_dir) = node_binary.parent() {
                let npm_path = node_dir.join("npm");
                if npm_path.exists() {
                    let npm_link = bin.join("npm");
                    let _ = fs::remove_file(&npm_link);
                    symlink(&npm_path, &npm_link)?;
                }

                let npx_path = node_dir.join("npx");
                if npx_path.exists() {
                    let npx_link = bin.join("npx");
                    let _ = fs::remove_file(&npx_link);
                    symlink(&npx_path, &npx_link)?;
                }
            }
        }

        Ok(())
    }

    /// Get environment variables for this Node.js environment.
    pub fn env_vars(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();

        // Set NODE_PATH for module resolution
        if self.node_modules.exists() {
            vars.insert(
                "NODE_PATH".to_string(),
                self.node_modules.to_string_lossy().to_string(),
            );
        }

        // Disable npm update notifier
        vars.insert("NO_UPDATE_NOTIFIER".to_string(), "1".to_string());

        vars
    }

    /// Get the bin directory.
    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// Get the node_modules directory.
    pub fn node_modules(&self) -> &Path {
        &self.node_modules
    }

    /// Get the Node.js version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Get the root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Find a Node.js binary for the given version, checking the store first.
///
/// This function:
/// 1. First checks the Cratons toolchain store for a pre-installed Node.js
/// 2. Falls back to finding a system Node.js installation
fn find_node_binary_with_store(version: &str, store: &Store) -> Result<Option<PathBuf>> {
    use tracing::debug;

    // M-21 FIX: First check the Cratons toolchain store for pre-installed Node.js
    if let Some(toolchain_path) = store.toolchains().get_by_name_version("node", version) {
        debug!(
            "Found Node.js {} in toolchain store: {:?}",
            version, toolchain_path
        );
        // Look for the node binary in the toolchain
        let bin_candidates = [
            toolchain_path.join("bin").join("node"),
            toolchain_path.join("node"),
            toolchain_path.join("node.exe"), // Windows
        ];

        for candidate in &bin_candidates {
            if candidate.exists() {
                debug!("Using toolchain Node.js at {:?}", candidate);
                return Ok(Some(candidate.clone()));
            }
        }
    }

    // Fall back to system Node.js discovery
    find_node_binary(version)
}

/// Find a Node.js binary for the given version (system search only).
fn find_node_binary(_version: &str) -> Result<Option<PathBuf>> {
    // Try to find node in PATH
    if let Ok(path) = which::which("node") {
        return Ok(Some(path));
    }

    // Try common installation locations
    let common_paths = [
        "/usr/local/bin/node",
        "/usr/bin/node",
        "/opt/homebrew/bin/node",
    ];

    for path in &common_paths {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(Some(p));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_find_node() {
        let result = find_node_binary("20");
        println!("Node binary: {:?}", result);
    }

    #[test]
    fn test_env_vars() {
        let dir = tempdir().unwrap();
        let env = NodeEnv {
            root: dir.path().to_path_buf(),
            version: "20".to_string(),
            node_binary: None,
            node_modules: dir.path().join("node_modules"),
        };

        let vars = env.env_vars();
        assert!(vars.contains_key("NO_UPDATE_NOTIFIER"));
    }
}
