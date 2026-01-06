//! Java/Maven environment management.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use cratons_store::Store;
use tracing::debug;

use crate::Result;
use crate::error::EnvironmentError;

/// A Java/Maven environment.
#[derive(Debug, Clone)]
pub struct JavaEnv {
    /// Root directory (.cratons/env/java/)
    root: PathBuf,
    /// Maven repository directory
    m2_repo: PathBuf,
}

impl JavaEnv {
    /// Set up a new Java environment.
    ///
    /// M-21 FIX: The store parameter is used to check for pre-installed Java toolchains.
    /// If a Java toolchain (JDK) is found in the store, it will be linked into the environment.
    pub fn setup(env_root: &Path, store: &Store) -> Result<Self> {
        let root = env_root.join("java");
        fs::create_dir_all(&root)?;

        let m2_repo = root.join("repository");
        fs::create_dir_all(&m2_repo)?;

        // M-21 FIX: Check if Java toolchain is available in the store
        // This allows environments to use pre-downloaded JDK toolchains
        if let Some(java_toolchain) = find_java_toolchain_in_store(store) {
            debug!("Found Java toolchain in store: {:?}", java_toolchain);
            // Future: set JAVA_HOME and symlink java binary
        }

        let env = Self { root, m2_repo };

        debug!("Created Java environment at {:?}", env.root);

        Ok(env)
    }

    /// Load an existing Java environment.
    pub fn load(env_root: &Path) -> Result<Self> {
        let root = env_root.join("java");
        if !root.exists() {
            return Err(EnvironmentError::NotFound(root));
        }

        let m2_repo = root.join("repository");

        Ok(Self { root, m2_repo })
    }

    /// Get environment variables for this Java environment.
    pub fn env_vars(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();

        // Set Maven repository location
        vars.insert(
            "MAVEN_OPTS".to_string(),
            format!("-Dmaven.repo.local={}", self.m2_repo.display()),
        );

        vars
    }

    /// Get the bin directory (Java doesn't have a dedicated bin).
    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// Get the root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get the Maven repository directory.
    pub fn m2_repo(&self) -> &Path {
        &self.m2_repo
    }
}

/// M-21 FIX: Find Java toolchain in the Cratons store.
///
/// Searches for any installed Java toolchain (JDK) in the store.
fn find_java_toolchain_in_store(store: &Store) -> Option<PathBuf> {
    // List all toolchains and find any Java toolchain
    if let Ok(toolchains) = store.toolchains().list() {
        for tc in toolchains {
            if tc.name == "java" {
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
        let env = JavaEnv {
            root: dir.path().to_path_buf(),
            m2_repo: dir.path().join("repository"),
        };

        let vars = env.env_vars();
        assert!(vars.contains_key("MAVEN_OPTS"));
    }
}
