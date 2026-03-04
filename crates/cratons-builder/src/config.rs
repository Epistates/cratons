//! Build configuration.
//!
//! # Security
//!
//! This module provides validation for build configurations to prevent:
//! - Shell command injection via malformed scripts
//! - Environment variable injection
//! - Path traversal attacks in output paths
//!
//! All build configurations SHOULD be validated before execution using
//! the [`BuildConfig::validate`] method.

use cratons_core::{ContentHash, CratonsError, HashAlgorithm, Hasher, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Configuration for a build operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    /// Package name
    pub package_name: String,
    /// Package version
    pub package_version: String,
    /// Build script to execute
    pub script: String,
    /// Output paths to capture
    pub outputs: Vec<String>,
    /// Environment variables
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Toolchains required
    #[serde(default)]
    pub toolchains: Vec<ToolchainRef>,
    /// Dependencies (already resolved)
    #[serde(default)]
    pub dependencies: Vec<DependencyRef>,
    /// Memory limit in bytes
    pub memory_limit: Option<u64>,
    /// CPU limit (number of cores)
    pub cpu_limit: Option<f32>,
    /// Build timeout in seconds
    pub timeout_secs: Option<u64>,
    /// Working directory inside container
    #[serde(default = "default_workdir")]
    pub workdir: String,
}

fn default_workdir() -> String {
    "/src".to_string()
}

impl BuildConfig {
    /// Create a new build configuration.
    #[must_use]
    pub fn new(package_name: String, package_version: String, script: String) -> Self {
        Self {
            package_name,
            package_version,
            script,
            outputs: vec!["dist/".to_string()],
            env: HashMap::new(),
            toolchains: Vec::new(),
            dependencies: Vec::new(),
            memory_limit: Some(4 * 1024 * 1024 * 1024), // 4GB
            cpu_limit: None,
            timeout_secs: Some(600), // 10 minutes
            workdir: "/src".to_string(),
        }
    }

    /// Compute the input hash for cache lookup.
    #[must_use]
    pub fn input_hash(&self) -> ContentHash {
        let mut hasher = Hasher::new(HashAlgorithm::Blake3);

        // Hash package info
        hasher.update(self.package_name.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.package_version.as_bytes());
        hasher.update(b"\0");

        // Hash script
        hasher.update(self.script.as_bytes());
        hasher.update(b"\0");

        // Hash env (sorted for determinism)
        let mut env_pairs: Vec<_> = self.env.iter().collect();
        env_pairs.sort_by_key(|(k, _)| *k);
        for (k, v) in env_pairs {
            hasher.update(k.as_bytes());
            hasher.update(b"=");
            hasher.update(v.as_bytes());
            hasher.update(b"\0");
        }

        // Hash toolchains
        for tc in &self.toolchains {
            hasher.update(tc.name.as_bytes());
            hasher.update(b"@");
            hasher.update(tc.version.as_bytes());
            hasher.update(b"\0");
        }

        // Hash dependencies
        for dep in &self.dependencies {
            hasher.update(dep.name.as_bytes());
            hasher.update(b"@");
            hasher.update(dep.version.as_bytes());
            hasher.update(b"\0");
        }

        hasher.finalize()
    }

    /// Add an environment variable.
    pub fn env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.env.insert(key.into(), value.into());
    }

    /// Add a toolchain requirement.
    pub fn toolchain(&mut self, name: impl Into<String>, version: impl Into<String>) {
        self.toolchains.push(ToolchainRef {
            name: name.into(),
            version: version.into(),
            path: None,
        });
    }

    /// Add a dependency.
    pub fn dependency(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        hash: ContentHash,
    ) {
        self.dependencies.push(DependencyRef {
            name: name.into(),
            version: version.into(),
            hash,
            path: None,
        });
    }

    /// Validate the build configuration for security.
    ///
    /// This method SHOULD be called before executing any build to ensure:
    /// - Script is within size limits and doesn't contain dangerous patterns
    /// - Environment variables have safe names and values
    /// - Output paths don't contain path traversal sequences
    ///
    /// # Errors
    ///
    /// Returns an error if any validation check fails.
    pub fn validate(&self) -> Result<()> {
        self.validate_script()?;
        self.validate_env()?;
        self.validate_outputs()?;
        self.validate_workdir()?;
        Ok(())
    }

    /// Validate the build script.
    fn validate_script(&self) -> Result<()> {
        // Script length limit (1 MiB should be more than enough)
        const MAX_SCRIPT_LEN: usize = 1024 * 1024;

        if self.script.is_empty() {
            return Err(CratonsError::InvalidConfig {
                message: "Build script cannot be empty".into(),
            });
        }

        if self.script.len() > MAX_SCRIPT_LEN {
            return Err(CratonsError::InvalidConfig {
                message: format!(
                    "Build script exceeds maximum length ({} > {} bytes)",
                    self.script.len(),
                    MAX_SCRIPT_LEN
                ),
            });
        }

        // Check for null bytes which could truncate the command
        if self.script.contains('\0') {
            return Err(CratonsError::InvalidConfig {
                message: "Build script contains null bytes".into(),
            });
        }

        // SECURITY: Block patterns that could escape sandbox or access sensitive resources
        // These patterns are blocked even though we run in a sandbox as defense-in-depth
        let dangerous_patterns = [
            // Direct device access
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            // Kernel interfaces
            "/proc/kcore",
            "/sys/kernel",
            // Container escape attempts
            "nsenter",
            "unshare --user",
            "--privileged",
            // Capability manipulation
            "capsh",
            "setcap",
            "getcap",
        ];

        let script_lower = self.script.to_lowercase();
        for pattern in dangerous_patterns {
            if script_lower.contains(&pattern.to_lowercase()) {
                return Err(CratonsError::InvalidConfig {
                    message: format!("Build script contains blocked pattern: '{}'", pattern),
                });
            }
        }

        Ok(())
    }

    /// Validate environment variables.
    fn validate_env(&self) -> Result<()> {
        // POSIX environment variable name pattern: must start with letter or underscore,
        // followed by letters, digits, or underscores
        let valid_name = |name: &str| -> bool {
            if name.is_empty() {
                return false;
            }
            let mut chars = name.chars();
            let first = chars.next().unwrap();
            if !first.is_ascii_alphabetic() && first != '_' {
                return false;
            }
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        };

        for (name, value) in &self.env {
            // Validate name format
            if !valid_name(name) {
                return Err(CratonsError::InvalidConfig {
                    message: format!("Invalid environment variable name: '{}'", name),
                });
            }

            // Block shell-special variable names that could affect execution
            let blocked_names = [
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
                "LD_AUDIT",
                "LD_DEBUG",
                "BASH_ENV",
                "ENV",
                "SHELLOPTS",
                "BASHOPTS",
                "GLOBIGNORE",
                "IFS",
            ];

            if blocked_names.iter().any(|b| b.eq_ignore_ascii_case(name)) {
                return Err(CratonsError::InvalidConfig {
                    message: format!(
                        "Environment variable '{}' is blocked for security reasons",
                        name
                    ),
                });
            }

            // Value length limit (64 KiB per value)
            const MAX_VALUE_LEN: usize = 64 * 1024;
            if value.len() > MAX_VALUE_LEN {
                return Err(CratonsError::InvalidConfig {
                    message: format!(
                        "Environment variable '{}' value exceeds maximum length",
                        name
                    ),
                });
            }

            // Check for null bytes
            if value.contains('\0') {
                return Err(CratonsError::InvalidConfig {
                    message: format!("Environment variable '{}' contains null bytes", name),
                });
            }
        }

        Ok(())
    }

    /// Validate output paths.
    fn validate_outputs(&self) -> Result<()> {
        for output in &self.outputs {
            // Check for path traversal
            if output.contains("..") {
                return Err(CratonsError::InvalidConfig {
                    message: format!("Output path contains path traversal: '{}'", output),
                });
            }

            // Check for null bytes
            if output.contains('\0') {
                return Err(CratonsError::InvalidConfig {
                    message: format!("Output path contains null bytes: '{}'", output),
                });
            }

            // Block absolute paths (outputs should be relative to build dir)
            if output.starts_with('/') {
                return Err(CratonsError::InvalidConfig {
                    message: format!("Output path must be relative, not absolute: '{}'", output),
                });
            }
        }

        Ok(())
    }

    /// Validate working directory.
    fn validate_workdir(&self) -> Result<()> {
        // Workdir must be absolute path inside container
        if !self.workdir.starts_with('/') {
            return Err(CratonsError::InvalidConfig {
                message: "Working directory must be an absolute path".into(),
            });
        }

        // Check for path traversal
        if self.workdir.contains("..") {
            return Err(CratonsError::InvalidConfig {
                message: "Working directory contains path traversal".into(),
            });
        }

        // Check for null bytes
        if self.workdir.contains('\0') {
            return Err(CratonsError::InvalidConfig {
                message: "Working directory contains null bytes".into(),
            });
        }

        Ok(())
    }
}

/// Reference to a toolchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolchainRef {
    /// Toolchain name (e.g., "node", "python")
    pub name: String,
    /// Toolchain version
    pub version: String,
    /// Path to installed toolchain (filled during build setup)
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

/// Reference to a dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRef {
    /// Dependency name
    pub name: String,
    /// Dependency version
    pub version: String,
    /// Content hash
    pub hash: ContentHash,
    /// Path to installed dependency (filled during build setup)
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_config_input_hash() {
        let config1 = BuildConfig::new(
            "my-app".to_string(),
            "1.0.0".to_string(),
            "npm run build".to_string(),
        );

        let config2 = BuildConfig::new(
            "my-app".to_string(),
            "1.0.0".to_string(),
            "npm run build".to_string(),
        );

        // Same config should produce same hash
        assert_eq!(config1.input_hash(), config2.input_hash());

        // Different script should produce different hash
        let config3 = BuildConfig::new(
            "my-app".to_string(),
            "1.0.0".to_string(),
            "npm run build:prod".to_string(),
        );
        assert_ne!(config1.input_hash(), config3.input_hash());
    }
}
