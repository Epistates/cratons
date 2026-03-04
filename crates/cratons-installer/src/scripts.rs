//! Post-install script execution with optional container isolation.
//!
//! This module provides secure execution of npm lifecycle scripts (preinstall,
//! install, postinstall) with optional sandboxing for improved security.
//!
//! ## Security Approach
//!
//! Post-install scripts from npm packages can be a significant security risk as
//! they run arbitrary code. This module provides three levels of protection:
//!
//! 1. **Sandboxed** (`isolate: true`): Scripts run in platform-native sandbox
//!    - Linux: Full container isolation with namespaces and seccomp
//!    - macOS: sandbox-exec with SBPL profile (filesystem isolation)
//!    - Windows: Job Objects with restricted tokens
//!
//! 2. **Direct** (`isolate: false`): Scripts run directly (not recommended)
//!
//! ## Network Access
//!
//! By default, sandboxed scripts have no network access (hermetic execution).
//! This prevents supply chain attacks that try to phone home or download
//! additional payloads.

use cratons_core::{CratonsError, Result};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

/// Information about scripts in a package.
///
/// Provides structured access to npm lifecycle scripts for analysis,
/// pre-flight checks, and selective execution.
#[derive(Debug, Clone, Default)]
pub struct PackageScripts {
    /// Package name (from package.json)
    pub name: String,
    /// preinstall script
    pub preinstall: Option<String>,
    /// install script
    pub install: Option<String>,
    /// postinstall script
    pub postinstall: Option<String>,
    /// Whether package has binding.gyp (native module)
    pub has_native: bool,
}

impl PackageScripts {
    /// Parse scripts from a package directory.
    ///
    /// Reads package.json and extracts lifecycle scripts and native module info.
    pub fn from_package_dir(package_dir: &Path) -> Self {
        let package_json_path = package_dir.join("package.json");
        let mut scripts = Self::default();

        scripts.has_native = package_dir.join("binding.gyp").exists();

        let Ok(content) = fs::read_to_string(&package_json_path) else {
            return scripts;
        };

        let Ok(package_json): std::result::Result<serde_json::Value, _> =
            serde_json::from_str(&content)
        else {
            return scripts;
        };

        // Extract package name
        scripts.name = package_json
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Extract lifecycle scripts
        if let Some(serde_json::Value::Object(s)) = package_json.get("scripts") {
            scripts.preinstall = s
                .get("preinstall")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            scripts.install = s
                .get("install")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            scripts.postinstall = s
                .get("postinstall")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
        }

        scripts
    }

    /// Check if there are any lifecycle scripts to run.
    #[must_use]
    pub fn has_lifecycle_scripts(&self) -> bool {
        self.preinstall.is_some() || self.install.is_some() || self.postinstall.is_some()
    }

    /// Check if there's anything to execute (scripts or native build).
    #[must_use]
    pub fn has_any(&self) -> bool {
        self.has_lifecycle_scripts() || self.has_native
    }

    /// Get scripts in execution order as (name, script) pairs.
    pub fn lifecycle_scripts(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("preinstall", self.preinstall.as_deref()),
            ("install", self.install.as_deref()),
            ("postinstall", self.postinstall.as_deref()),
        ]
        .into_iter()
        .filter_map(|(name, script)| script.map(|s| (name, s)))
    }
}

/// Runs post-install scripts for packages.
pub struct PostInstallRunner {
    /// Whether to isolate scripts in containers
    isolate: bool,
}

impl PostInstallRunner {
    /// Create a new script runner.
    pub fn new(isolate: bool) -> Self {
        Self { isolate }
    }

    /// Run post-install scripts for an npm package.
    ///
    /// Executes lifecycle scripts in order: preinstall → install → postinstall
    pub async fn run_scripts(&self, package_dir: &Path, project_dir: &Path) -> Result<()> {
        let scripts = PackageScripts::from_package_dir(package_dir);

        if !scripts.has_lifecycle_scripts() {
            return Ok(());
        }

        // Run lifecycle scripts in order
        for (script_name, script) in scripts.lifecycle_scripts() {
            debug!("Running {} script for {}", script_name, scripts.name);

            if self.isolate {
                self.run_isolated(script, package_dir, project_dir).await?;
            } else {
                self.run_direct(script, package_dir)?;
            }
        }

        Ok(())
    }

    /// Run a script directly (not isolated).
    fn run_direct(&self, script: &str, working_dir: &Path) -> Result<()> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(script)
            .current_dir(working_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Script failed: {}", stderr);
            return Err(CratonsError::BuildFailed(format!(
                "Post-install script failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Run a script in an isolated sandbox.
    ///
    /// Uses platform-native sandboxing:
    /// - Linux: Full container isolation with namespaces
    /// - macOS: sandbox-exec with SBPL profile
    /// - Windows: Job Objects with restricted tokens
    async fn run_isolated(
        &self,
        script: &str,
        package_dir: &Path,
        project_dir: &Path,
    ) -> Result<()> {
        use cratons_sandbox::{
            IsolationLevel,
            config::{Mount, NetworkAccess, ResourceLimits, SandboxConfig},
            create_sandbox,
        };

        // Get the best available sandbox for this platform
        let sandbox = create_sandbox();
        let isolation = sandbox.isolation_level();

        debug!(
            isolation = ?isolation,
            package_dir = %package_dir.display(),
            "setting up sandboxed script execution"
        );

        // Fall back to direct execution if no isolation available
        if matches!(isolation, IsolationLevel::None | IsolationLevel::Process) {
            warn!(
                "No sandbox isolation available (level: {:?}), running script directly",
                isolation
            );
            return self.run_direct(script, package_dir);
        }

        // Configure the sandbox
        let config =
            SandboxConfig::new(vec!["sh".to_string(), "-c".to_string(), script.to_string()])
                .with_workdir(package_dir.to_path_buf())
                // Read-write access to package directory (scripts may write files)
                .with_rw_mount(Mount::bind(package_dir.to_path_buf(), false))
                // Read-only access to project directory (for node_modules paths)
                .with_ro_mount(Mount::bind(project_dir.to_path_buf(), true))
                // No network - hermetic execution
                .with_network(NetworkAccess::None)
                // Restrictive resource limits for post-install scripts
                .with_limits(ResourceLimits::for_post_install())
                // Inherit minimal env needed for scripts to run
                .with_env(
                    "HOME",
                    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()),
                )
                .with_env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
                .with_env("NODE_ENV", "production")
                .with_env(
                    "npm_config_cache",
                    package_dir.join(".npm-cache").to_string_lossy().to_string(),
                );

        // Add node_modules/.bin to PATH if it exists
        let bin_path = project_dir.join("node_modules").join(".bin");
        let config = if bin_path.exists() {
            config.with_env(
                "PATH",
                format!(
                    "{}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                    bin_path.display()
                ),
            )
        } else {
            config
        };

        // Execute in sandbox
        let result = sandbox
            .execute(&config)
            .await
            .map_err(|e| CratonsError::BuildFailed(format!("Sandbox execution failed: {}", e)))?;

        // Check for timeout
        if result.timed_out {
            return Err(CratonsError::BuildFailed(format!(
                "Post-install script timed out after {:?}",
                result.duration
            )));
        }

        // Check exit code
        if !result.success() {
            let stderr = result.stderr_str();
            let stdout = result.stdout_str();

            let error_output = if !stderr.is_empty() {
                stderr
            } else if !stdout.is_empty() {
                stdout
            } else {
                "(no output)".to_string()
            };

            return Err(CratonsError::BuildFailed(format!(
                "Post-install script failed (exit code {}): {}",
                result.exit_code,
                error_output.lines().take(10).collect::<Vec<_>>().join("\n")
            )));
        }

        debug!(
            duration = ?result.duration,
            "sandboxed script execution completed successfully"
        );

        Ok(())
    }

    /// Check if a package has lifecycle scripts.
    ///
    /// This is a convenience method that creates a `PackageScripts` internally.
    /// For repeated checks, prefer creating `PackageScripts` once and reusing it.
    pub fn has_scripts(package_dir: &Path) -> bool {
        PackageScripts::from_package_dir(package_dir).has_lifecycle_scripts()
    }

    /// Run binding.gyp native compilation (node-gyp).
    pub async fn run_node_gyp(&self, package_dir: &Path) -> Result<()> {
        let binding_gyp = package_dir.join("binding.gyp");
        if !binding_gyp.exists() {
            return Ok(());
        }

        info!("Running node-gyp rebuild for native module");

        let output = Command::new("node-gyp")
            .arg("rebuild")
            .current_dir(package_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match output {
            Ok(output) if output.status.success() => {
                debug!("node-gyp rebuild succeeded");
                Ok(())
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("node-gyp rebuild failed: {}", stderr);
                Err(CratonsError::BuildFailed(format!(
                    "node-gyp rebuild failed: {}",
                    stderr
                )))
            }
            Err(e) => {
                warn!("node-gyp not found or failed to execute: {}", e);
                Err(CratonsError::BuildFailed(format!(
                    "node-gyp not available: {}",
                    e
                )))
            }
        }
    }

    /// Run all scripts and native builds for a package.
    ///
    /// Combines lifecycle script execution with node-gyp for native modules.
    pub async fn run_all(&self, package_dir: &Path, project_dir: &Path) -> Result<()> {
        let scripts = PackageScripts::from_package_dir(package_dir);

        // Run lifecycle scripts first
        if scripts.has_lifecycle_scripts() {
            for (script_name, script) in scripts.lifecycle_scripts() {
                debug!("Running {} script for {}", script_name, scripts.name);

                if self.isolate {
                    self.run_isolated(script, package_dir, project_dir).await?;
                } else {
                    self.run_direct(script, package_dir)?;
                }
            }
        }

        // Run node-gyp for native modules
        if scripts.has_native {
            self.run_node_gyp(package_dir).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;

    #[test]
    fn test_has_scripts() {
        let dir = tempdir().unwrap();

        // No package.json
        assert!(!PostInstallRunner::has_scripts(dir.path()));

        // Empty package.json
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert!(!PostInstallRunner::has_scripts(dir.path()));

        // With postinstall script
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"postinstall": "echo hello"}}"#,
        )
        .unwrap();
        assert!(PostInstallRunner::has_scripts(dir.path()));
    }

    #[test]
    fn test_package_scripts_parsing() {
        let dir = tempdir().unwrap();

        fs::write(
            dir.path().join("package.json"),
            r#"{
                "name": "test",
                "scripts": {
                    "preinstall": "echo pre",
                    "postinstall": "echo post",
                    "test": "jest"
                }
            }"#,
        )
        .unwrap();

        let scripts = PackageScripts::from_package_dir(dir.path());

        assert_eq!(scripts.name, "test");
        assert_eq!(scripts.preinstall, Some("echo pre".to_string()));
        assert_eq!(scripts.install, None);
        assert_eq!(scripts.postinstall, Some("echo post".to_string()));
        assert!(!scripts.has_native);
        assert!(scripts.has_any());
        assert!(scripts.has_lifecycle_scripts());
    }

    #[test]
    fn test_native_module_detection() {
        let dir = tempdir().unwrap();

        fs::write(dir.path().join("package.json"), r#"{"name": "test"}"#).unwrap();

        let scripts = PackageScripts::from_package_dir(dir.path());
        assert!(!scripts.has_native);
        assert!(!scripts.has_any());

        // Add binding.gyp
        fs::write(dir.path().join("binding.gyp"), "{}").unwrap();

        let scripts = PackageScripts::from_package_dir(dir.path());
        assert!(scripts.has_native);
        assert!(scripts.has_any());
        assert!(!scripts.has_lifecycle_scripts());
    }

    #[test]
    fn test_lifecycle_scripts_iterator() {
        let dir = tempdir().unwrap();

        fs::write(
            dir.path().join("package.json"),
            r#"{
                "name": "test",
                "scripts": {
                    "preinstall": "echo pre",
                    "install": "echo install",
                    "postinstall": "echo post"
                }
            }"#,
        )
        .unwrap();

        let scripts = PackageScripts::from_package_dir(dir.path());
        let lifecycle: Vec<_> = scripts.lifecycle_scripts().collect();

        assert_eq!(lifecycle.len(), 3);
        assert_eq!(lifecycle[0], ("preinstall", "echo pre"));
        assert_eq!(lifecycle[1], ("install", "echo install"));
        assert_eq!(lifecycle[2], ("postinstall", "echo post"));
    }

    #[test]
    fn test_empty_scripts_filtered() {
        let dir = tempdir().unwrap();

        fs::write(
            dir.path().join("package.json"),
            r#"{
                "name": "test",
                "scripts": {
                    "preinstall": "",
                    "postinstall": "echo post"
                }
            }"#,
        )
        .unwrap();

        let scripts = PackageScripts::from_package_dir(dir.path());

        assert_eq!(scripts.preinstall, None); // Empty string filtered out
        assert_eq!(scripts.postinstall, Some("echo post".to_string()));
    }
}
