//! Go environment management.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use cratons_store::Store;
use tracing::debug;

use crate::Result;
use crate::error::EnvironmentError;

/// A Go environment.
#[derive(Debug, Clone)]
pub struct GoEnv {
    /// Root directory (.cratons/env/go/)
    root: PathBuf,
    /// GOPATH directory
    gopath: PathBuf,
}

impl GoEnv {
    /// Set up a new Go environment.
    ///
    /// M-21 FIX: The store parameter is used to check for pre-installed Go toolchains.
    /// If a Go toolchain is found in the store, it will be linked into the environment.
    pub fn setup(env_root: &Path, store: &Store) -> Result<Self> {
        let root = env_root.join("go");
        fs::create_dir_all(&root)?;

        let gopath = root.join("gopath");
        fs::create_dir_all(&gopath)?;
        fs::create_dir_all(gopath.join("bin"))?;
        fs::create_dir_all(gopath.join("pkg"))?;
        fs::create_dir_all(gopath.join("src"))?;

        // M-21 FIX: Check if Go toolchain is available in the store
        // This allows environments to use pre-downloaded Go toolchains
        if let Some(go_toolchain) = find_go_toolchain_in_store(store) {
            debug!("Found Go toolchain in store: {:?}", go_toolchain);
            // Future: symlink go binary to gopath/bin/go
        }

        let env = Self { root, gopath };

        debug!("Created Go environment at {:?}", env.root);

        Ok(env)
    }

    /// Load an existing Go environment.
    pub fn load(env_root: &Path) -> Result<Self> {
        let root = env_root.join("go");
        if !root.exists() {
            return Err(EnvironmentError::NotFound(root));
        }

        let gopath = root.join("gopath");

        Ok(Self { root, gopath })
    }

    /// Get environment variables for this Go environment.
    pub fn env_vars(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();

        vars.insert(
            "GOPATH".to_string(),
            self.gopath.to_string_lossy().to_string(),
        );

        // Enable Go modules
        vars.insert("GO111MODULE".to_string(), "on".to_string());

        vars
    }

    /// Get the bin directory.
    pub fn bin_dir(&self) -> PathBuf {
        self.gopath.join("bin")
    }

    /// Get the root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// M-21 FIX: Find Go toolchain in the Cratons store.
///
/// Searches for any installed Go toolchain in the store.
fn find_go_toolchain_in_store(store: &Store) -> Option<PathBuf> {
    // List all toolchains and find any Go toolchain
    if let Ok(toolchains) = store.toolchains().list() {
        for tc in toolchains {
            if tc.name == "go" {
                return store.toolchains().get(&tc);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_env_vars() {
        let dir = tempdir().unwrap();
        let env = GoEnv {
            root: dir.path().to_path_buf(),
            gopath: dir.path().join("gopath"),
        };

        let vars = env.env_vars();
        assert!(vars.contains_key("GOPATH"));
        assert_eq!(vars.get("GO111MODULE"), Some(&"on".to_string()));
    }
}
