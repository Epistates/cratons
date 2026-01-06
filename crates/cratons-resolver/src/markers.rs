//! Python environment marker evaluation (PEP 508).
//!
//! This module provides support for evaluating Python environment markers,
//! which are conditions in dependency specifications like:
//! - `python_version >= "3.8"`
//! - `sys_platform == "linux"`
//! - `extra == "dev"`
//!
//! Environment markers allow conditional dependencies based on the target
//! Python environment.

use cratons_core::{CratonsError, Result};
use pep508_rs::{
    MarkerEnvironment, MarkerEnvironmentBuilder, MarkerTree, Requirement, VerbatimUrl,
};
use std::str::FromStr;
use tracing::debug;

/// A parsed Python dependency with marker information.
#[derive(Debug, Clone)]
pub struct ParsedPythonDep {
    /// Package name (normalized)
    pub name: String,
    /// Version requirement string
    pub version_req: String,
    /// Requested extras
    pub extras: Vec<String>,
    /// Environment marker (if any)
    pub marker: Option<MarkerTree>,
    /// Whether this is an extra-conditional dependency
    pub is_extra_dep: bool,
    /// The extra name this dependency is conditional on (if any)
    pub extra_name: Option<String>,
}

/// Configuration for the target Python environment.
#[derive(Debug, Clone)]
pub struct PythonEnvironmentConfig {
    /// Python version (major.minor, e.g., "3.11")
    pub python_version: String,
    /// Full Python version (major.minor.patch, e.g., "3.11.4")
    pub python_full_version: String,
    /// Operating system name (e.g., "posix", "nt", "java")
    pub os_name: String,
    /// System platform (e.g., "linux", "darwin", "win32")
    pub sys_platform: String,
    /// Platform system (e.g., "Linux", "Darwin", "Windows")
    pub platform_system: String,
    /// Platform machine (e.g., "x86_64", "aarch64")
    pub platform_machine: String,
    /// Platform release version
    pub platform_release: String,
    /// Platform version string
    pub platform_version: String,
    /// Implementation name (e.g., "cpython", "pypy")
    pub implementation_name: String,
    /// Implementation version
    pub implementation_version: String,
    /// Platform Python implementation (legacy, same as implementation_name)
    pub platform_python_implementation: String,
}

impl Default for PythonEnvironmentConfig {
    fn default() -> Self {
        Self::detect_current()
    }
}

impl PythonEnvironmentConfig {
    /// Detect the current Python environment.
    ///
    /// This creates a sensible default based on the current system.
    /// For accurate detection, `detect_from_python()` should be used.
    #[must_use]
    pub fn detect_current() -> Self {
        // Default to a modern Python 3.11 on the current platform
        let (os_name, sys_platform, platform_system) = if cfg!(target_os = "linux") {
            ("posix", "linux", "Linux")
        } else if cfg!(target_os = "macos") {
            ("posix", "darwin", "Darwin")
        } else if cfg!(target_os = "windows") {
            ("nt", "win32", "Windows")
        } else {
            ("posix", "linux", "Linux") // fallback
        };

        let platform_machine = if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else if cfg!(target_arch = "x86") {
            "i686"
        } else {
            "x86_64" // fallback
        };

        Self {
            python_version: "3.11".to_string(),
            python_full_version: "3.11.0".to_string(),
            os_name: os_name.to_string(),
            sys_platform: sys_platform.to_string(),
            platform_system: platform_system.to_string(),
            platform_machine: platform_machine.to_string(),
            platform_release: "".to_string(),
            platform_version: "".to_string(),
            implementation_name: "cpython".to_string(),
            implementation_version: "3.11.0".to_string(),
            platform_python_implementation: "CPython".to_string(),
        }
    }

    /// Create a configuration for a specific Python version on the current platform.
    #[must_use]
    pub fn for_python_version(major: u8, minor: u8, patch: u8) -> Self {
        let mut config = Self::detect_current();
        config.python_version = format!("{major}.{minor}");
        config.python_full_version = format!("{major}.{minor}.{patch}");
        config.implementation_version = format!("{major}.{minor}.{patch}");
        config
    }

    /// Create configuration for Linux x86_64.
    #[must_use]
    pub fn linux_x86_64(python_version: &str) -> Self {
        let parts: Vec<&str> = python_version.split('.').collect();
        let (major, minor, patch) = match parts.as_slice() {
            [major, minor] => (*major, *minor, "0"),
            [major, minor, patch] => (*major, *minor, *patch),
            _ => ("3", "11", "0"),
        };

        Self {
            python_version: format!("{major}.{minor}"),
            python_full_version: format!("{major}.{minor}.{patch}"),
            os_name: "posix".to_string(),
            sys_platform: "linux".to_string(),
            platform_system: "Linux".to_string(),
            platform_machine: "x86_64".to_string(),
            platform_release: "".to_string(),
            platform_version: "".to_string(),
            implementation_name: "cpython".to_string(),
            implementation_version: format!("{major}.{minor}.{patch}"),
            platform_python_implementation: "CPython".to_string(),
        }
    }

    /// Create configuration for macOS arm64.
    #[must_use]
    pub fn macos_arm64(python_version: &str) -> Self {
        let mut config = Self::linux_x86_64(python_version);
        config.sys_platform = "darwin".to_string();
        config.platform_system = "Darwin".to_string();
        config.platform_machine = "arm64".to_string();
        config
    }

    /// Create configuration for Windows x86_64.
    #[must_use]
    pub fn windows_x86_64(python_version: &str) -> Self {
        let mut config = Self::linux_x86_64(python_version);
        config.os_name = "nt".to_string();
        config.sys_platform = "win32".to_string();
        config.platform_system = "Windows".to_string();
        config.platform_machine = "AMD64".to_string();
        config
    }

    /// Build a `MarkerEnvironment` from this configuration.
    pub fn to_marker_environment(&self) -> Result<MarkerEnvironment> {
        let builder = MarkerEnvironmentBuilder {
            implementation_name: &self.implementation_name,
            implementation_version: &self.implementation_version,
            os_name: &self.os_name,
            platform_machine: &self.platform_machine,
            platform_python_implementation: &self.platform_python_implementation,
            platform_release: &self.platform_release,
            platform_system: &self.platform_system,
            platform_version: &self.platform_version,
            python_full_version: &self.python_full_version,
            python_version: &self.python_version,
            sys_platform: &self.sys_platform,
        };

        MarkerEnvironment::try_from(builder).map_err(|e| {
            CratonsError::Manifest(format!("Invalid Python environment configuration: {e}"))
        })
    }
}

/// Python marker evaluator.
///
/// Evaluates PEP 508 environment markers against a target environment.
#[derive(Debug, Clone)]
pub struct MarkerEvaluator {
    env: MarkerEnvironment,
    /// Active extras for the current resolution context
    active_extras: Vec<pep508_rs::ExtraName>,
}

impl MarkerEvaluator {
    /// Create a new evaluator with the default (current) environment.
    pub fn new() -> Result<Self> {
        Self::with_config(PythonEnvironmentConfig::default())
    }

    /// Create an evaluator with a specific configuration.
    pub fn with_config(config: PythonEnvironmentConfig) -> Result<Self> {
        let env = config.to_marker_environment()?;
        Ok(Self {
            env,
            active_extras: Vec::new(),
        })
    }

    /// Create an evaluator for a specific Python version.
    pub fn for_python_version(major: u8, minor: u8, patch: u8) -> Result<Self> {
        Self::with_config(PythonEnvironmentConfig::for_python_version(
            major, minor, patch,
        ))
    }

    /// Set active extras for evaluation.
    ///
    /// Dependencies marked with `extra == "dev"` will only be included
    /// if "dev" is in the active extras.
    pub fn with_extras(mut self, extras: Vec<String>) -> Self {
        self.active_extras = extras
            .into_iter()
            .filter_map(|e| pep508_rs::ExtraName::from_str(&e).ok())
            .collect();
        self
    }

    /// Evaluate whether a marker tree applies in this environment.
    #[must_use]
    pub fn evaluate(&self, marker: &MarkerTree) -> bool {
        marker.evaluate(&self.env, &self.active_extras)
    }

    /// Parse a PEP 508 dependency string and evaluate its markers.
    ///
    /// Returns `None` if the dependency should be skipped due to markers.
    pub fn parse_and_filter(&self, spec: &str) -> Result<Option<ParsedPythonDep>> {
        let parsed = parse_pep508_requirement(spec)?;

        // If there's a marker, evaluate it
        if let Some(ref marker) = parsed.marker {
            if !self.evaluate(marker) {
                debug!(
                    "Skipping dependency {} due to marker evaluation",
                    parsed.name
                );
                return Ok(None);
            }
        }

        Ok(Some(parsed))
    }

    /// Parse multiple requirements and filter by markers.
    pub fn parse_and_filter_all(&self, specs: &[String]) -> Result<Vec<ParsedPythonDep>> {
        let mut results = Vec::new();
        for spec in specs {
            if let Some(parsed) = self.parse_and_filter(spec)? {
                results.push(parsed);
            }
        }
        Ok(results)
    }
}

impl Default for MarkerEvaluator {
    fn default() -> Self {
        Self::new().expect("Default marker evaluator should be valid")
    }
}

/// Parse a PEP 508 requirement string.
///
/// This uses the `pep508_rs` crate for proper parsing, extracting:
/// - Package name
/// - Version constraints
/// - Extras
/// - Environment markers
pub fn parse_pep508_requirement(spec: &str) -> Result<ParsedPythonDep> {
    let spec = spec.trim();

    // Parse using pep508_rs
    // Use the parse function that takes a working directory for relative paths
    let requirement: Requirement<VerbatimUrl> = Requirement::from_str(spec).map_err(|e| {
        CratonsError::Manifest(format!("Invalid PEP 508 requirement '{}': {}", spec, e))
    })?;

    // Extract name
    let name = requirement.name.to_string();

    // Extract extras
    let extras: Vec<String> = requirement.extras.iter().map(|e| e.to_string()).collect();

    // Extract version requirement
    let version_req = match &requirement.version_or_url {
        Some(pep508_rs::VersionOrUrl::VersionSpecifier(specifiers)) => {
            if specifiers.is_empty() {
                "*".to_string()
            } else {
                specifiers.to_string()
            }
        }
        Some(pep508_rs::VersionOrUrl::Url(_)) => {
            // URL-based dependency
            "*".to_string()
        }
        None => "*".to_string(),
    };

    // Check for extra-conditional markers
    let marker = if requirement.marker.is_true() {
        None
    } else {
        Some(requirement.marker.clone())
    };

    // Detect if this is an extra-conditional dependency (extra == "...")
    let (is_extra_dep, extra_name) = detect_extra_condition(&requirement.marker);

    Ok(ParsedPythonDep {
        name,
        version_req,
        extras,
        marker,
        is_extra_dep,
        extra_name,
    })
}

/// Detect if a marker tree contains an extra condition.
///
/// Returns (is_extra_dep, extra_name) where extra_name is Some if the
/// dependency is conditional on a specific extra.
fn detect_extra_condition(marker: &MarkerTree) -> (bool, Option<String>) {
    // Use the pep508_rs API to detect extra conditions
    if let Some(extra_expr) = marker.top_level_extra() {
        // Found a top-level extra condition
        // The extra_expr contains the extra name
        let extra_str = format!("{extra_expr:?}");
        // Extract the extra name from the debug representation
        // ExtraName("dev") format
        if let Some(start) = extra_str.find('"') {
            if let Some(end) = extra_str[start + 1..].find('"') {
                let name = &extra_str[start + 1..start + 1 + end];
                return (true, Some(name.to_string()));
            }
        }
        (true, None)
    } else {
        // Check if marker string contains extra references
        if let Some(marker_str) = marker.try_to_string() {
            if marker_str.contains("extra") {
                return (true, None);
            }
        }
        (false, None)
    }
}

/// Normalize a Python package name according to PEP 503.
#[must_use]
pub fn normalize_python_name(name: &str) -> String {
    name.to_lowercase().replace('_', "-").replace('.', "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_requirement() {
        let parsed = parse_pep508_requirement("requests>=2.28.0").unwrap();
        assert_eq!(parsed.name, "requests");
        assert_eq!(parsed.version_req, ">=2.28.0");
        assert!(parsed.marker.is_none());
        assert!(!parsed.is_extra_dep);
    }

    #[test]
    fn test_parse_requirement_with_marker() {
        let parsed =
            parse_pep508_requirement("typing-extensions; python_version < '3.10'").unwrap();
        assert_eq!(parsed.name, "typing-extensions");
        assert!(parsed.marker.is_some());
    }

    #[test]
    fn test_parse_requirement_with_extras() {
        let parsed = parse_pep508_requirement("requests[security,socks]>=2.28.0").unwrap();
        assert_eq!(parsed.name, "requests");
        assert_eq!(parsed.extras, vec!["security", "socks"]);
    }

    #[test]
    fn test_parse_requirement_with_extra_condition() {
        let parsed = parse_pep508_requirement("colorama>=0.4.3; extra == 'development'").unwrap();
        assert_eq!(parsed.name, "colorama");
        assert!(parsed.is_extra_dep);
        assert_eq!(parsed.extra_name, Some("development".to_string()));
    }

    #[test]
    fn test_marker_evaluation_python_version() {
        let evaluator =
            MarkerEvaluator::for_python_version(3, 9, 0).expect("Should create evaluator");

        // This should be included for Python 3.9
        let result = evaluator
            .parse_and_filter("typing-extensions; python_version < '3.10'")
            .unwrap();
        assert!(result.is_some());

        // Python 3.11 evaluator - should exclude
        let evaluator_311 =
            MarkerEvaluator::for_python_version(3, 11, 0).expect("Should create evaluator");
        let result = evaluator_311
            .parse_and_filter("typing-extensions; python_version < '3.10'")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_marker_evaluation_platform() {
        let linux_config = PythonEnvironmentConfig::linux_x86_64("3.11");
        let evaluator =
            MarkerEvaluator::with_config(linux_config).expect("Should create evaluator");

        // Linux-only dependency should be included
        let result = evaluator
            .parse_and_filter("pyinotify; sys_platform == 'linux'")
            .unwrap();
        assert!(result.is_some());

        // Windows-only dependency should be excluded
        let result = evaluator
            .parse_and_filter("pywin32; sys_platform == 'win32'")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_marker_evaluation_extras() {
        let evaluator = MarkerEvaluator::new()
            .expect("Should create evaluator")
            .with_extras(vec!["dev".to_string()]);

        // With 'dev' extra active, should be included
        let result = evaluator
            .parse_and_filter("pytest; extra == 'dev'")
            .unwrap();
        assert!(result.is_some());

        // Without 'test' extra, should be excluded
        let result = evaluator
            .parse_and_filter("coverage; extra == 'test'")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_complex_marker() {
        let evaluator =
            MarkerEvaluator::for_python_version(3, 8, 0).expect("Should create evaluator");

        // Complex marker with AND
        let result = evaluator
            .parse_and_filter(
                "importlib-metadata>=4.6; python_version < '3.10' and python_version >= '3.7'",
            )
            .unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_python_name("Requests"), "requests");
        assert_eq!(normalize_python_name("my_package"), "my-package");
        assert_eq!(normalize_python_name("My.Package"), "my-package");
    }

    #[test]
    fn test_python_environment_configs() {
        // Test Linux config
        let linux = PythonEnvironmentConfig::linux_x86_64("3.10.5");
        assert_eq!(linux.python_version, "3.10");
        assert_eq!(linux.sys_platform, "linux");

        // Test macOS config
        let macos = PythonEnvironmentConfig::macos_arm64("3.11");
        assert_eq!(macos.sys_platform, "darwin");
        assert_eq!(macos.platform_machine, "arm64");

        // Test Windows config
        let windows = PythonEnvironmentConfig::windows_x86_64("3.12.1");
        assert_eq!(windows.os_name, "nt");
        assert_eq!(windows.sys_platform, "win32");
    }
}
