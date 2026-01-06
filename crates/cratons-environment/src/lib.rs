//! # cratons-environment
//!
//! Hermetic environment management for all ecosystems.
//!
//! This crate provides isolated, reproducible environments for:
//! - Python (venv-compatible structure)
//! - Node.js (node_modules with bin shims)
//! - Rust (cargo home integration)
//! - Go (GOPATH/go.mod support)
//! - Java/Maven (.m2 repository)
//!
//! Key features:
//! - Zero manual setup required (no `python -m venv`, no `nvm use`)
//! - IDE-compatible structures
//! - Activation scripts for interactive use
//! - Hermetic execution via `cratons run`

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod activation;
pub mod error;
pub mod go;
pub mod java;
pub mod node;
pub mod python;
pub mod rust;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cratons_core::Ecosystem;
use cratons_lockfile::Lockfile;
use cratons_sandbox::{Sandbox, SandboxConfig, SandboxResult};
use cratons_store::Store;

pub use error::EnvironmentError;
pub use go::GoEnv;
pub use java::JavaEnv;
pub use node::NodeEnv;
pub use python::PythonEnv;
pub use rust::RustEnv;

/// Result type for environment operations.
pub type Result<T> = std::result::Result<T, EnvironmentError>;

/// The root directory name for Cratons environments.
pub const ENV_DIR: &str = ".cratons";

/// Configuration for environment toolchain versions.
///
/// This maps to the `[environment]` section in cratons.toml.
#[derive(Debug, Clone, Default)]
pub struct EnvironmentConfig {
    /// Node.js version (e.g., "20.10.0")
    pub node: Option<String>,
    /// Python version (e.g., "3.12.0")
    pub python: Option<String>,
    /// Rust toolchain version (e.g., "1.75.0")
    pub rust: Option<String>,
    /// Go version (e.g., "1.21.0")
    pub go: Option<String>,
    /// Java version (e.g., "21")
    pub java: Option<String>,
}

impl EnvironmentConfig {
    /// Create configuration from manifest environment section.
    pub fn from_manifest(env: &cratons_manifest::Environment) -> Self {
        Self {
            node: env.node.clone(),
            python: env.python.clone(),
            rust: env.rust.clone(),
            go: env.go.clone(),
            java: env.java.clone(),
        }
    }
}

/// Manages hermetic environments for all ecosystems.
pub struct EnvironmentManager {
    /// The content-addressable store.
    store: Arc<Store>,
    /// The sandbox for isolated execution.
    sandbox: Arc<dyn Sandbox>,
}

impl EnvironmentManager {
    /// Create a new environment manager.
    pub fn new(store: Arc<Store>, sandbox: Arc<dyn Sandbox>) -> Self {
        Self { store, sandbox }
    }

    /// Set up environments based on a lockfile with explicit version configuration.
    ///
    /// The `env_config` parameter allows specifying exact toolchain versions.
    /// This is typically populated from the `[environment]` section of cratons.toml.
    pub fn setup_with_config(
        &self,
        lockfile: &Lockfile,
        project_dir: &Path,
        env_config: &EnvironmentConfig,
    ) -> Result<Environment> {
        let env_root = project_dir.join(ENV_DIR).join("env");
        std::fs::create_dir_all(&env_root)?;

        let mut env = Environment::new(env_root.clone());

        // Detect which ecosystems are used
        let ecosystems: Vec<Ecosystem> = lockfile
            .packages
            .iter()
            .map(|p| p.ecosystem)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        for ecosystem in ecosystems {
            match ecosystem {
                Ecosystem::PyPi => {
                    let python_env = PythonEnv::setup_with_version(
                        &env_root,
                        env_config.python.as_deref(),
                        &self.store,
                    )?;
                    env.python = Some(python_env);
                }
                Ecosystem::Npm => {
                    let node_env = NodeEnv::setup_with_version(
                        &env_root,
                        project_dir,
                        env_config.node.as_deref(),
                        &self.store,
                    )?;
                    env.node = Some(node_env);
                }
                Ecosystem::Crates => {
                    let rust_env = RustEnv::setup(&env_root, &self.store)?;
                    env.rust = Some(rust_env);
                }
                Ecosystem::Go => {
                    let go_env = GoEnv::setup(&env_root, &self.store)?;
                    env.go = Some(go_env);
                }
                Ecosystem::Maven => {
                    let java_env = JavaEnv::setup(&env_root, &self.store)?;
                    env.java = Some(java_env);
                }
                Ecosystem::Url => {
                    // URL dependencies don't need a special environment
                }
            }
        }

        // Generate combined activation scripts
        activation::generate_scripts(&env, project_dir)?;

        Ok(env)
    }

    /// Set up environments based on a lockfile with default versions.
    ///
    /// For explicit version control, use `setup_with_config` instead.
    pub fn setup(&self, lockfile: &Lockfile, project_dir: &Path) -> Result<Environment> {
        self.setup_with_config(lockfile, project_dir, &EnvironmentConfig::default())
    }

    /// Run a command in a sandboxed environment.
    pub async fn run(
        &self,
        env: &Environment,
        project_dir: &Path,
        command: Vec<String>,
    ) -> Result<SandboxResult> {
        use cratons_sandbox::config::Mount;

        let config = SandboxConfig::new(command)
            .with_workdir(project_dir.to_path_buf())
            .with_envs(env.env_vars())
            .with_rw_mount(Mount::bind(project_dir.to_path_buf(), false))
            .with_network(cratons_sandbox::NetworkAccess::Full);

        self.sandbox
            .execute(&config)
            .await
            .map_err(|e| EnvironmentError::SandboxError(e.to_string()))
    }

    /// Load an existing environment.
    pub fn load(project_dir: &Path) -> Result<Environment> {
        let env_root = project_dir.join(ENV_DIR).join("env");
        if !env_root.exists() {
            return Err(EnvironmentError::NotFound(project_dir.to_path_buf()));
        }

        let mut env = Environment::new(env_root.clone());

        // Detect installed environments
        if env_root.join("python").exists() {
            env.python = Some(PythonEnv::load(&env_root)?);
        }
        if env_root.join("node").exists() {
            env.node = Some(NodeEnv::load(&env_root)?);
        }
        if env_root.join("rust").exists() {
            env.rust = Some(RustEnv::load(&env_root)?);
        }
        if env_root.join("go").exists() {
            env.go = Some(GoEnv::load(&env_root)?);
        }
        if env_root.join("java").exists() {
            env.java = Some(JavaEnv::load(&env_root)?);
        }

        Ok(env)
    }
}

/// An isolated environment containing runtimes and packages.
#[derive(Debug)]
pub struct Environment {
    /// Root of this environment (.cratons/env/)
    root: PathBuf,
    /// Python environment (if configured)
    pub python: Option<PythonEnv>,
    /// Node.js environment (if configured)
    pub node: Option<NodeEnv>,
    /// Rust environment (if configured)
    pub rust: Option<RustEnv>,
    /// Go environment (if configured)
    pub go: Option<GoEnv>,
    /// Java environment (if configured)
    pub java: Option<JavaEnv>,
}

impl Environment {
    /// Create a new empty environment.
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            python: None,
            node: None,
            rust: None,
            go: None,
            java: None,
        }
    }

    /// Get all environment variables for this environment.
    pub fn env_vars(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();

        // Collect PATH components
        let mut path_components = Vec::new();

        if let Some(ref python) = self.python {
            vars.extend(python.env_vars());
            path_components.push(python.bin_dir().to_string_lossy().to_string());
        }

        if let Some(ref node) = self.node {
            vars.extend(node.env_vars());
            path_components.push(node.bin_dir().to_string_lossy().to_string());
        }

        if let Some(ref rust) = self.rust {
            vars.extend(rust.env_vars());
            path_components.push(rust.bin_dir().to_string_lossy().to_string());
        }

        if let Some(ref go) = self.go {
            vars.extend(go.env_vars());
            path_components.push(go.bin_dir().to_string_lossy().to_string());
        }

        if let Some(ref java) = self.java {
            vars.extend(java.env_vars());
            path_components.push(java.bin_dir().to_string_lossy().to_string());
        }

        // Construct combined PATH using platform-specific separator
        if !path_components.is_empty() {
            let existing_path = std::env::var("PATH").unwrap_or_default();
            path_components.push(existing_path);
            // Use platform-specific PATH separator: ";" on Windows, ":" on Unix
            let separator = if cfg!(windows) { ";" } else { ":" };
            vars.insert("PATH".to_string(), path_components.join(separator));
        }

        // Mark as Cratons environment
        vars.insert("CRATONS_ENV".to_string(), "1".to_string());
        vars.insert(
            "CRATONS_ENV_ROOT".to_string(),
            self.root.to_string_lossy().to_string(),
        );

        vars
    }

    /// Get the root directory of this environment.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Check if this environment has any ecosystems configured.
    pub fn is_empty(&self) -> bool {
        self.python.is_none()
            && self.node.is_none()
            && self.rust.is_none()
            && self.go.is_none()
            && self.java.is_none()
    }

    /// Get a list of configured ecosystems.
    pub fn ecosystems(&self) -> Vec<Ecosystem> {
        let mut ecosystems = Vec::new();
        if self.python.is_some() {
            ecosystems.push(Ecosystem::PyPi);
        }
        if self.node.is_some() {
            ecosystems.push(Ecosystem::Npm);
        }
        if self.rust.is_some() {
            ecosystems.push(Ecosystem::Crates);
        }
        if self.go.is_some() {
            ecosystems.push(Ecosystem::Go);
        }
        if self.java.is_some() {
            ecosystems.push(Ecosystem::Maven);
        }
        ecosystems
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_environment_creation() {
        let dir = tempdir().unwrap();
        let env = Environment::new(dir.path().to_path_buf());

        assert!(env.is_empty());
        assert!(env.ecosystems().is_empty());
    }

    #[test]
    fn test_env_vars() {
        let dir = tempdir().unwrap();
        let env = Environment::new(dir.path().to_path_buf());

        let vars = env.env_vars();
        assert_eq!(vars.get("CRATONS_ENV"), Some(&"1".to_string()));
    }
}
