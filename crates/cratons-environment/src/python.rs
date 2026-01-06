//! Python environment management.
//!
//! Creates a venv-compatible structure for Python environments.
//! This allows IDEs and tools to recognize it as a valid virtual environment.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use cratons_store::Store;
use tracing::{debug, warn};

use crate::Result;
use crate::error::EnvironmentError;

/// Create a symlink in a cross-platform way.
#[cfg(unix)]
fn create_symlink(original: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(original, link)
}

#[cfg(windows)]
fn create_symlink(original: &Path, link: &Path) -> std::io::Result<()> {
    // On Windows, try symlink first (requires elevated privileges or dev mode)
    // Fall back to junction or copy if symlink fails
    if original.is_dir() {
        std::os::windows::fs::symlink_dir(original, link).or_else(|_| {
            junction::create(original, link)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        })
    } else {
        std::os::windows::fs::symlink_file(original, link)
            .or_else(|_| fs::copy(original, link).map(|_| ()))
    }
}

/// Default Python version when not specified in manifest
const DEFAULT_PYTHON_VERSION: &str = "3.12";

/// A Python virtual environment.
#[derive(Debug, Clone)]
pub struct PythonEnv {
    /// Root directory (.cratons/env/python/)
    root: PathBuf,
    /// Python version
    version: String,
    /// Path to the Python interpreter
    interpreter: Option<PathBuf>,
}

impl PythonEnv {
    /// Set up a new Python environment with specified version.
    pub fn setup_with_version(
        env_root: &Path,
        version: Option<&str>,
        store: &Store,
    ) -> Result<Self> {
        let root = env_root.join("python");
        fs::create_dir_all(&root)?;

        let version = version.unwrap_or(DEFAULT_PYTHON_VERSION).to_string();

        // M-21 FIX: Try to find Python in the toolchain store first, then fall back to system
        let interpreter = find_python_interpreter_with_store(&version, store)?;

        let env = Self {
            root: root.clone(),
            version: version.clone(),
            interpreter: interpreter.clone(),
        };

        // Create venv structure
        env.create_structure()?;

        // Generate pyvenv.cfg
        env.generate_pyvenv_cfg()?;

        debug!(
            "Created Python environment at {:?} (version {})",
            root, version
        );

        Ok(env)
    }

    /// Set up a new Python environment with default version.
    ///
    /// For explicit version control, use `setup_with_version` instead.
    pub fn setup(env_root: &Path, store: &Store) -> Result<Self> {
        Self::setup_with_version(env_root, None, store)
    }

    /// Load an existing Python environment.
    pub fn load(env_root: &Path) -> Result<Self> {
        let root = env_root.join("python");
        if !root.exists() {
            return Err(EnvironmentError::NotFound(root));
        }

        // Read version from pyvenv.cfg
        let pyvenv_cfg = root.join("pyvenv.cfg");
        let version = if pyvenv_cfg.exists() {
            parse_pyvenv_version(&pyvenv_cfg).unwrap_or_else(|| DEFAULT_PYTHON_VERSION.to_string())
        } else {
            DEFAULT_PYTHON_VERSION.to_string()
        };

        let interpreter = find_python_interpreter(&version).ok().flatten();

        Ok(Self {
            root,
            version,
            interpreter,
        })
    }

    /// Create the venv directory structure.
    fn create_structure(&self) -> Result<()> {
        // Platform-specific directory names
        #[cfg(windows)]
        let bin_name = "Scripts";
        #[cfg(not(windows))]
        let bin_name = "bin";

        // Create directories
        let bin = self.root.join(bin_name);
        let major_minor = self.major_minor_version();
        let lib = self.root.join("lib").join(format!("python{}", major_minor));
        let site_packages = lib.join("site-packages");

        fs::create_dir_all(&bin)?;
        fs::create_dir_all(&site_packages)?;

        // Create interpreter symlinks/copies
        if let Some(ref interpreter) = self.interpreter {
            #[cfg(windows)]
            let python_name = "python.exe";
            #[cfg(not(windows))]
            let python_name = "python";

            let python_link = bin.join(python_name);

            #[cfg(windows)]
            let python3_name = "python3.exe";
            #[cfg(not(windows))]
            let python3_name = "python3";

            let python3_link = bin.join(python3_name);
            let versioned_link = bin.join(format!(
                "python{}{}",
                major_minor,
                if cfg!(windows) { ".exe" } else { "" }
            ));

            // Remove existing links
            let _ = fs::remove_file(&python_link);
            let _ = fs::remove_file(&python3_link);
            let _ = fs::remove_file(&versioned_link);

            // Create new symlinks (cross-platform)
            // L-05: All symlinks point directly to interpreter to avoid symlink chains
            if let Err(e) = create_symlink(interpreter, &python_link) {
                warn!("Failed to create python symlink: {}. Copying instead.", e);
                fs::copy(interpreter, &python_link)?;
            }
            // Point directly to interpreter, not to another symlink
            if let Err(e) = create_symlink(interpreter, &python3_link) {
                warn!("Failed to create python3 symlink: {}. Copying instead.", e);
                fs::copy(interpreter, &python3_link)?;
            }
            if let Err(e) = create_symlink(interpreter, &versioned_link) {
                warn!(
                    "Failed to create versioned symlink: {}. Copying instead.",
                    e
                );
                fs::copy(interpreter, &versioned_link)?;
            }
        }

        Ok(())
    }

    /// Get the major.minor version string.
    fn major_minor_version(&self) -> &str {
        // Safely extract major.minor from version string
        let parts: Vec<&str> = self.version.split('.').collect();
        if parts.len() >= 2 {
            // Find the position after "X.Y"
            let major_len = parts[0].len();
            let minor_len = parts[1].len();
            if self.version.len() >= major_len + 1 + minor_len {
                return &self.version[..major_len + 1 + minor_len];
            }
        }
        // Fallback to first 4 chars (original behavior)
        if self.version.len() >= 4 {
            &self.version[..4]
        } else {
            &self.version
        }
    }

    /// Generate pyvenv.cfg file for IDE compatibility.
    fn generate_pyvenv_cfg(&self) -> Result<()> {
        let cfg_path = self.root.join("pyvenv.cfg");
        let mut file = File::create(&cfg_path)?;

        let home = self
            .interpreter
            .as_ref()
            .and_then(|p| p.parent())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/usr/bin".to_string());

        writeln!(file, "home = {}", home)?;
        writeln!(file, "include-system-site-packages = false")?;
        writeln!(file, "version = {}", self.version)?;
        if let Some(ref interpreter) = self.interpreter {
            writeln!(file, "executable = {}", interpreter.display())?;
        }

        Ok(())
    }

    /// Get environment variables for this Python environment.
    pub fn env_vars(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();

        vars.insert(
            "VIRTUAL_ENV".to_string(),
            self.root.to_string_lossy().to_string(),
        );

        // Python should not look at user site-packages
        vars.insert("PYTHONNOUSERSITE".to_string(), "1".to_string());

        // Disable pip version check
        vars.insert("PIP_DISABLE_PIP_VERSION_CHECK".to_string(), "1".to_string());

        vars
    }

    /// Get the bin directory.
    pub fn bin_dir(&self) -> PathBuf {
        #[cfg(windows)]
        return self.root.join("Scripts");
        #[cfg(not(windows))]
        return self.root.join("bin");
    }

    /// Get the site-packages directory.
    pub fn site_packages(&self) -> PathBuf {
        self.root
            .join("lib")
            .join(format!("python{}", self.major_minor_version()))
            .join("site-packages")
    }

    /// Get the Python version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Get the root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create a new PythonEnv for testing purposes.
    ///
    /// M-22 FIX: This allows activation script tests to create mock PythonEnv instances
    /// without requiring a Store or actual Python interpreter.
    #[cfg(test)]
    pub fn new_for_test(root: PathBuf, version: String) -> Self {
        Self {
            root,
            version,
            interpreter: None,
        }
    }
}

/// Find a Python interpreter for the given version, checking the store first.
///
/// This function:
/// 1. First checks the Cratons toolchain store for a pre-installed Python
/// 2. Falls back to finding a system Python interpreter matching the requested version
/// 3. Verifies the interpreter's version by executing it
fn find_python_interpreter_with_store(version: &str, store: &Store) -> Result<Option<PathBuf>> {
    // Parse requested version
    let parts: Vec<&str> = version.split('.').collect();
    let major_minor = if parts.len() >= 2 {
        format!("{}.{}", parts[0], parts[1])
    } else {
        version.to_string()
    };

    // M-21 FIX: First check the Cratons toolchain store for pre-installed Python
    if let Some(toolchain_path) = store.toolchains().get_by_name_version("python", version) {
        debug!(
            "Found Python {} in toolchain store: {:?}",
            version, toolchain_path
        );
        // Look for the python binary in the toolchain
        let bin_candidates = [
            toolchain_path
                .join("bin")
                .join(format!("python{}", major_minor)),
            toolchain_path.join("bin").join("python3"),
            toolchain_path.join("bin").join("python"),
            toolchain_path
                .join("python")
                .join("bin")
                .join(format!("python{}", major_minor)),
            toolchain_path.join("python").join("bin").join("python3"),
        ];

        for candidate in &bin_candidates {
            if candidate.exists() {
                debug!("Using toolchain Python at {:?}", candidate);
                return Ok(Some(candidate.clone()));
            }
        }
    }

    // Fall back to system Python discovery
    find_python_interpreter(version)
}

/// Find a Python interpreter for the given version (system search only).
///
/// This function attempts to find a Python interpreter matching the requested version.
/// It verifies the interpreter's version by executing it.
fn find_python_interpreter(version: &str) -> Result<Option<PathBuf>> {
    // Parse requested version
    let parts: Vec<&str> = version.split('.').collect();
    let major_minor = if parts.len() >= 2 {
        format!("{}.{}", parts[0], parts[1])
    } else {
        version.to_string()
    };

    // Try versioned interpreter first
    let versioned = format!("python{}", major_minor);
    if let Ok(path) = which::which(&versioned) {
        if verify_python_version(&path, &major_minor)? {
            return Ok(Some(path));
        }
    }

    // Try python3
    if let Ok(path) = which::which("python3") {
        if verify_python_version(&path, &major_minor)? {
            return Ok(Some(path));
        }
        // Warn if version doesn't match
        warn!(
            "python3 found but version may not match requested {}",
            major_minor
        );
        return Ok(Some(path));
    }

    // Try python (not recommended, might be Python 2)
    if let Ok(path) = which::which("python") {
        if verify_python_version(&path, &major_minor)? {
            return Ok(Some(path));
        }
    }

    // No interpreter found
    Ok(None)
}

/// Verify that a Python interpreter matches the expected version.
fn verify_python_version(path: &Path, expected_major_minor: &str) -> Result<bool> {
    use std::process::Command;

    let output = Command::new(path)
        .args(["--version"])
        .output()
        .map_err(|e| EnvironmentError::CommandFailed(format!("Failed to run Python: {}", e)))?;

    let version_output = String::from_utf8_lossy(&output.stdout);
    // Python --version outputs "Python X.Y.Z"
    let version_str = version_output
        .strip_prefix("Python ")
        .unwrap_or(&version_output)
        .trim();

    let parts: Vec<&str> = version_str.split('.').collect();
    if parts.len() >= 2 {
        let actual_major_minor = format!("{}.{}", parts[0], parts[1]);
        return Ok(actual_major_minor == expected_major_minor);
    }

    Ok(false)
}

/// Parse version from pyvenv.cfg.
fn parse_pyvenv_version(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(version) = line.strip_prefix("version = ") {
            return Some(version.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_find_python() {
        // Should find some Python on most systems
        let result = find_python_interpreter("3.12");
        // Don't assert success as Python might not be installed
        println!("Python interpreter: {:?}", result);
    }

    #[test]
    fn test_env_vars() {
        let dir = tempdir().unwrap();
        let env = PythonEnv {
            root: dir.path().to_path_buf(),
            version: "3.12.0".to_string(),
            interpreter: None,
        };

        let vars = env.env_vars();
        assert!(vars.contains_key("VIRTUAL_ENV"));
        assert!(vars.contains_key("PYTHONNOUSERSITE"));
    }

    #[test]
    fn test_paths() {
        let dir = tempdir().unwrap();
        let env = PythonEnv {
            root: dir.path().to_path_buf(),
            version: "3.12.0".to_string(),
            interpreter: None,
        };

        assert!(env.bin_dir().ends_with("bin"));
        assert!(
            env.site_packages()
                .to_string_lossy()
                .contains("site-packages")
        );
    }
}
