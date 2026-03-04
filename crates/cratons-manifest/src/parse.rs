//! Manifest parsing.

use cratons_core::{CratonsError, Ecosystem, ResolutionStrategy, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::dependency::Dependencies;
use crate::environment::Environment;
use crate::package::Package;
use crate::scripts::Scripts;
use crate::workspace::WorkspaceConfig;

/// The main manifest structure (`cratons.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Manifest {
    /// Package metadata
    #[serde(default)]
    pub package: Package,

    /// Environment/toolchain configuration
    #[serde(default)]
    pub environment: Environment,

    /// Dependencies
    #[serde(default)]
    pub dependencies: Dependencies,

    /// Development dependencies
    #[serde(default, rename = "dev-dependencies")]
    pub dev_dependencies: Dependencies,

    /// Optional dependencies (only installed when explicitly requested)
    #[serde(default, rename = "optional-dependencies")]
    pub optional_dependencies: Dependencies,

    /// Dependency overrides (patching)
    #[serde(default)]
    pub overrides: Dependencies,

    /// System dependencies (e.g., C libraries, tools)
    #[serde(default)]
    pub system: SystemDependencies,

    /// Build configuration
    #[serde(default)]
    pub build: BuildConfig,

    /// Scripts
    #[serde(default)]
    pub scripts: Scripts,

    /// Resolution strategy overrides per ecosystem
    #[serde(default)]
    pub resolution: HashMap<Ecosystem, ResolutionStrategy>,

    /// Workspace configuration (only in root)
    #[serde(default)]
    pub workspace: Option<WorkspaceConfig>,

    /// Target-specific configuration
    #[serde(default)]
    pub target: HashMap<String, TargetConfig>,

    /// Path to the manifest file (not serialized)
    #[serde(skip)]
    pub manifest_path: Option<PathBuf>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            package: Package::default(),
            environment: Environment::default(),
            dependencies: Dependencies::default(),
            dev_dependencies: Dependencies::default(),
            optional_dependencies: Dependencies::default(),
            overrides: Dependencies::default(),
            system: SystemDependencies::default(),
            build: BuildConfig::default(),
            scripts: Scripts::default(),
            resolution: HashMap::new(),
            workspace: None,
            target: HashMap::new(),
            manifest_path: None,
        }
    }
}

impl Manifest {
    /// The default manifest filename.
    pub const FILENAME: &'static str = "cratons.toml";

    /// Load a manifest from a file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|e| {
            CratonsError::Manifest(format!("Failed to read {}: {}", path.display(), e))
        })?;

        let mut manifest: Self = toml::from_str(&content).map_err(|e| {
            CratonsError::Manifest(format!("Failed to parse {}: {}", path.display(), e))
        })?;

        manifest.manifest_path = Some(path.to_path_buf());
        manifest.validate()?;

        Ok(manifest)
    }

    /// Find and load the manifest from the current or parent directories.
    pub fn find_and_load(start: impl AsRef<Path>) -> Result<(Self, PathBuf)> {
        let start = start.as_ref();
        let mut current = if start.is_file() {
            start.parent().unwrap_or(start)
        } else {
            start
        };

        loop {
            let manifest_path = current.join(Self::FILENAME);
            if manifest_path.exists() {
                let manifest = Self::load(&manifest_path)?;
                return Ok((manifest, manifest_path));
            }

            match current.parent() {
                Some(parent) => current = parent,
                None => {
                    return Err(CratonsError::Manifest(format!(
                        "Could not find {} in {} or any parent directory",
                        Self::FILENAME,
                        start.display()
                    )));
                }
            }
        }
    }

    /// Get the project root directory.
    #[must_use]
    pub fn project_root(&self) -> Option<&Path> {
        self.manifest_path.as_ref()?.parent()
    }

    /// Validate the manifest.
    pub fn validate(&self) -> Result<()> {
        // Package name is required if not a workspace root
        if self.workspace.is_none() && self.package.name.is_empty() {
            return Err(CratonsError::Manifest(
                "Package name is required".to_string(),
            ));
        }

        // Validate dependencies
        self.dependencies.validate()?;
        self.dev_dependencies.validate()?;

        Ok(())
    }

    /// Check if this is a workspace root.
    #[must_use]
    pub fn is_workspace_root(&self) -> bool {
        self.workspace.is_some()
    }

    /// Get all dependencies (including dev if requested).
    #[must_use]
    pub fn all_dependencies(&self, include_dev: bool) -> Dependencies {
        let mut deps = self.dependencies.clone();
        if include_dev {
            deps.merge(&self.dev_dependencies);
        }
        deps
    }

    /// Parse from a TOML string.
    pub fn from_str(content: &str) -> Result<Self> {
        let manifest: Self = toml::from_str(content)
            .map_err(|e| CratonsError::Manifest(format!("Failed to parse manifest: {e}")))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Serialize to TOML string.
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| CratonsError::Manifest(format!("Failed to serialize manifest: {e}")))
    }

    /// M-19 FIX: Get all optional dependencies from both sources.
    ///
    /// This unifies optional dependencies specified in two ways:
    /// 1. Dependencies in `[dependencies.X]` with `optional = true`
    /// 2. Dependencies in `[optional-dependencies.X]`
    ///
    /// # Example
    /// ```ignore
    /// # Both of these are returned by all_optional_dependencies():
    /// [dependencies.npm]
    /// express = { version = "^4.18.0", optional = true }
    ///
    /// [optional-dependencies.npm]
    /// socket-io = "^4.0.0"
    /// ```
    #[must_use]
    pub fn all_optional_dependencies(&self) -> Dependencies {
        use cratons_core::Ecosystem;
        let mut all_optionals = Dependencies::default();

        // Helper to insert dependency into the correct ecosystem map
        fn insert_dep(
            deps: &mut Dependencies,
            ecosystem: Ecosystem,
            name: &str,
            dep: crate::dependency::Dependency,
        ) {
            match ecosystem {
                Ecosystem::Npm => {
                    deps.npm.insert(name.to_string(), dep);
                }
                Ecosystem::PyPi => {
                    deps.pypi.insert(name.to_string(), dep);
                }
                Ecosystem::Crates => {
                    deps.crates.insert(name.to_string(), dep);
                }
                Ecosystem::Go => {
                    deps.go.insert(name.to_string(), dep);
                }
                Ecosystem::Maven => {
                    deps.maven.insert(name.to_string(), dep);
                }
                Ecosystem::Url => {
                    deps.url.insert(name.to_string(), dep);
                }
            }
        }

        // Collect from optional-dependencies section
        for (ecosystem, name, dep) in self.optional_dependencies.iter() {
            insert_dep(&mut all_optionals, ecosystem, name, dep.clone());
        }

        // Collect dependencies marked with optional = true
        for (ecosystem, name, dep) in self.dependencies.iter() {
            if dep.is_optional() {
                insert_dep(&mut all_optionals, ecosystem, name, dep.clone());
            }
        }

        all_optionals
    }

    /// M-19 FIX: Get all required (non-optional) dependencies.
    ///
    /// This returns dependencies that are not optional - i.e., dependencies
    /// from `[dependencies.X]` that do NOT have `optional = true`.
    #[must_use]
    pub fn required_dependencies(&self) -> Dependencies {
        use cratons_core::Ecosystem;
        let mut required = Dependencies::default();

        for (ecosystem, name, dep) in self.dependencies.iter() {
            if !dep.is_optional() {
                match ecosystem {
                    Ecosystem::Npm => {
                        required.npm.insert(name.to_string(), dep.clone());
                    }
                    Ecosystem::PyPi => {
                        required.pypi.insert(name.to_string(), dep.clone());
                    }
                    Ecosystem::Crates => {
                        required.crates.insert(name.to_string(), dep.clone());
                    }
                    Ecosystem::Go => {
                        required.go.insert(name.to_string(), dep.clone());
                    }
                    Ecosystem::Maven => {
                        required.maven.insert(name.to_string(), dep.clone());
                    }
                    Ecosystem::Url => {
                        required.url.insert(name.to_string(), dep.clone());
                    }
                }
            }
        }

        required
    }
}

/// System dependencies configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SystemDependencies {
    /// System packages (apt, brew, etc.)
    #[serde(default)]
    pub packages: Vec<String>,

    /// Required system paths/binaries
    #[serde(default)]
    pub binaries: Vec<String>,

    /// Required C libraries (pkg-config names)
    #[serde(default)]
    pub libraries: Vec<String>,
}

/// Build configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BuildConfig {
    /// Build script content or file reference
    #[serde(default)]
    pub script: BuildScript,

    /// Build outputs to capture
    #[serde(default)]
    pub outputs: Vec<String>,

    /// Build-time dependencies
    #[serde(default)]
    pub dependencies: Dependencies,

    /// Memory limit for build container (bytes)
    #[serde(default)]
    pub memory_limit: Option<u64>,

    /// CPU limit for build container (cores)
    #[serde(default)]
    pub cpu_limit: Option<f32>,

    /// Build timeout in seconds
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// Build script specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BuildScript {
    /// Inline script string
    Inline(String),
    /// Reference to a file
    File {
        /// Path to the build script
        file: String,
    },
}

impl Default for BuildScript {
    fn default() -> Self {
        // Default to empty inline script, which serializes properly
        Self::Inline(String::new())
    }
}

impl BuildScript {
    /// Check if a build script is defined.
    #[must_use]
    pub fn is_defined(&self) -> bool {
        match self {
            Self::Inline(s) => !s.is_empty(),
            Self::File { .. } => true,
        }
    }

    /// Get the script content, reading from file if necessary.
    ///
    /// Returns `None` if the script is an empty inline string.
    ///
    /// # Security
    ///
    /// This method validates that the file path does not escape the project root
    /// to prevent path traversal attacks (e.g., `../../../etc/passwd`).
    pub fn content(&self, project_root: &Path) -> Result<Option<String>> {
        match self {
            Self::Inline(s) if s.is_empty() => Ok(None),
            Self::Inline(s) => Ok(Some(s.clone())),
            Self::File { file } => {
                // SECURITY: Validate the path doesn't escape project root
                let path = project_root.join(file);

                // Canonicalize both paths to resolve any .. or symlinks
                let canonical_root = project_root.canonicalize().map_err(|e| {
                    CratonsError::Manifest(format!(
                        "Failed to canonicalize project root {}: {}",
                        project_root.display(),
                        e
                    ))
                })?;

                let canonical_path = path.canonicalize().map_err(|e| {
                    CratonsError::Manifest(format!(
                        "Failed to read build script {}: {}",
                        path.display(),
                        e
                    ))
                })?;

                // Ensure the script path is within the project root
                if !canonical_path.starts_with(&canonical_root) {
                    return Err(CratonsError::Manifest(format!(
                        "Build script path traversal attempt: {} escapes project root {}",
                        file,
                        project_root.display()
                    )));
                }

                let content = fs::read_to_string(&canonical_path).map_err(|e| {
                    CratonsError::Manifest(format!(
                        "Failed to read build script {}: {}",
                        path.display(),
                        e
                    ))
                })?;
                Ok(Some(content))
            }
        }
    }
}

/// Target-specific configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TargetConfig {
    /// Environment overrides for this target
    #[serde(default)]
    pub environment: Environment,

    /// Dependency overrides for this target
    #[serde(default)]
    pub dependencies: Dependencies,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_manifest() {
        let content = r#"
[package]
name = "my-app"
version = "1.0.0"
"#;
        let manifest = Manifest::from_str(content).unwrap();
        assert_eq!(manifest.package.name, "my-app");
        assert_eq!(manifest.package.version, "1.0.0");
    }

    #[test]
    fn test_parse_full_manifest() {
        let content = r#"
[package]
name = "my-app"
version = "1.0.0"
description = "A test application"

[environment]
node = "20.10.0"
python = "3.12.0"

[dependencies.npm]
lodash = "^4.17.21"
express = "^4.18.0"

[dependencies.pypi]
requests = ">=2.28.0"

[dev-dependencies.npm]
jest = "^29.0.0"

[build]
script = "npm run build"
outputs = ["dist/"]

[scripts]
dev = "npm run dev"
test = "npm test"
"#;
        let manifest = Manifest::from_str(content).unwrap();
        assert_eq!(manifest.package.name, "my-app");
        assert_eq!(manifest.environment.node, Some("20.10.0".to_string()));
        assert!(!manifest.dependencies.npm.is_empty());
        assert!(!manifest.dependencies.pypi.is_empty());
        assert_eq!(
            manifest.scripts.get("dev"),
            Some(&"npm run dev".to_string())
        );
    }

    #[test]
    fn test_parse_resolution_strategy() {
        let content = r#"
[package]
name = "my-app"
version = "1.0.0"

[resolution]
npm = "minimal"
pypi = "max-satisfying"
"#;
        let manifest = Manifest::from_str(content).unwrap();
        assert_eq!(
            manifest.resolution.get(&Ecosystem::Npm),
            Some(&ResolutionStrategy::Minimal)
        );
        assert_eq!(
            manifest.resolution.get(&Ecosystem::PyPi),
            Some(&ResolutionStrategy::MaxSatisfying)
        );
    }

    #[test]
    fn test_all_optional_dependencies() {
        let content = r#"
[package]
name = "my-app"
version = "1.0.0"

# Optional via flag in dependencies section
[dependencies.npm]
lodash = "^4.17.21"
express = { version = "^4.18.0", optional = true }

# Optional via optional-dependencies section
[optional-dependencies.npm]
socket-io = "^4.0.0"
"#;
        let manifest = Manifest::from_str(content).unwrap();

        // all_optional_dependencies should return both express (optional=true) and socket-io
        let optionals = manifest.all_optional_dependencies();
        assert_eq!(optionals.npm.len(), 2);
        assert!(optionals.npm.contains_key("express"));
        assert!(optionals.npm.contains_key("socket-io"));
        // lodash is not optional
        assert!(!optionals.npm.contains_key("lodash"));
    }

    #[test]
    fn test_required_dependencies() {
        let content = r#"
[package]
name = "my-app"
version = "1.0.0"

[dependencies.npm]
lodash = "^4.17.21"
express = { version = "^4.18.0", optional = true }
axios = "^1.0.0"
"#;
        let manifest = Manifest::from_str(content).unwrap();

        // required_dependencies should only return lodash and axios (not express)
        let required = manifest.required_dependencies();
        assert_eq!(required.npm.len(), 2);
        assert!(required.npm.contains_key("lodash"));
        assert!(required.npm.contains_key("axios"));
        // express is optional, should not be in required
        assert!(!required.npm.contains_key("express"));
    }
}
