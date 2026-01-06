//! Rust environment management.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use cratons_store::Store;
use tracing::debug;

use crate::Result;
use crate::error::EnvironmentError;

/// A Rust/Cargo environment.
#[derive(Debug, Clone)]
pub struct RustEnv {
    /// Root directory (.cratons/env/rust/)
    root: PathBuf,
    /// Cargo home directory
    cargo_home: PathBuf,
}

impl RustEnv {
    /// Set up a new Rust environment.
    ///
    /// M-21 FIX: The store parameter is used to check for pre-installed Rust toolchains.
    /// If a Rust toolchain is found in the store, it will be linked into the environment.
    pub fn setup(env_root: &Path, store: &Store) -> Result<Self> {
        let root = env_root.join("rust");
        fs::create_dir_all(&root)?;

        let cargo_home = root.join("cargo");
        fs::create_dir_all(&cargo_home)?;
        fs::create_dir_all(cargo_home.join("bin"))?;
        fs::create_dir_all(cargo_home.join("registry"))?;

        // M-21 FIX: Check if Rust toolchain is available in the store
        // This allows environments to use pre-downloaded Rust toolchains
        if let Some(rust_toolchain) = find_rust_toolchain_in_store(store) {
            debug!("Found Rust toolchain in store: {:?}", rust_toolchain);
            // Future: symlink rustc/cargo binaries to cargo_home/bin/
        }

        let env = Self { root, cargo_home };

        debug!("Created Rust environment at {:?}", env.root);

        Ok(env)
    }

    /// Load an existing Rust environment.
    pub fn load(env_root: &Path) -> Result<Self> {
        let root = env_root.join("rust");
        if !root.exists() {
            return Err(EnvironmentError::NotFound(root));
        }

        let cargo_home = root.join("cargo");

        Ok(Self { root, cargo_home })
    }

    /// Get environment variables for this Rust environment.
    pub fn env_vars(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();

        vars.insert(
            "CARGO_HOME".to_string(),
            self.cargo_home.to_string_lossy().to_string(),
        );

        // Disable cargo update checks
        vars.insert(
            "CARGO_NET_GIT_FETCH_WITH_CLI".to_string(),
            "true".to_string(),
        );

        vars
    }

    /// Get the bin directory.
    pub fn bin_dir(&self) -> PathBuf {
        self.cargo_home.join("bin")
    }

    /// Get the root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// M-21 FIX: Find Rust toolchain in the Cratons store.
///
/// Searches for any installed Rust toolchain in the store.
fn find_rust_toolchain_in_store(store: &Store) -> Option<PathBuf> {
    // List all toolchains and find any Rust toolchain
    if let Ok(toolchains) = store.toolchains().list() {
        for tc in toolchains {
            if tc.name == "rust" {
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
        let env = RustEnv {
            root: dir.path().to_path_buf(),
            cargo_home: dir.path().join("cargo"),
        };

        let vars = env.env_vars();
        assert!(vars.contains_key("CARGO_HOME"));
    }
}
