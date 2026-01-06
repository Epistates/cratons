//! Package ecosystem definitions.
//!
//! Cratons supports multiple package ecosystems. Each ecosystem has its own
//! registry, version format, and dependency specification syntax.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::{CratonsError, Result};

/// Supported package ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    /// npm (Node.js packages)
    Npm,
    /// `PyPI` (Python packages)
    PyPi,
    /// `crates.io` (Rust crates)
    Crates,
    /// Go modules
    Go,
    /// Maven Central (Java/JVM packages)
    Maven,
    /// Direct URL (escape hatch)
    Url,
}

impl Ecosystem {
    /// Get the default registry URL for this ecosystem.
    ///
    /// L-01 FIX: Made const for compile-time evaluation.
    #[must_use]
    pub const fn default_registry(&self) -> &'static str {
        match self {
            Self::Npm => "https://registry.npmjs.org",
            Self::PyPi => "https://pypi.org/simple",
            Self::Crates => "https://crates.io/api/v1",
            Self::Go => "https://proxy.golang.org",
            Self::Maven => "https://repo1.maven.org/maven2",
            Self::Url => "",
        }
    }

    /// Get the manifest key for this ecosystem.
    ///
    /// L-01 FIX: Made const for compile-time evaluation.
    #[must_use]
    pub const fn manifest_key(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPi => "pypi",
            Self::Crates => "crates",
            Self::Go => "go",
            Self::Maven => "maven",
            Self::Url => "url",
        }
    }

    /// Get the file extension for lockfile entries.
    ///
    /// L-01 FIX: Made const for compile-time evaluation.
    #[must_use]
    pub const fn lockfile_extension(&self) -> &'static str {
        match self {
            Self::Npm => "tgz",
            Self::PyPi => "whl",
            Self::Crates => "crate",
            Self::Go => "zip",
            Self::Maven => "jar",
            Self::Url => "tar.gz",
        }
    }

    /// Get the default resolution strategy for this ecosystem.
    ///
    /// L-01 FIX: Made const for compile-time evaluation.
    #[must_use]
    pub const fn default_resolution_strategy(&self) -> ResolutionStrategy {
        match self {
            Self::Go | Self::Maven => ResolutionStrategy::Minimal,
            Self::Npm | Self::PyPi | Self::Crates | Self::Url => ResolutionStrategy::MaxSatisfying,
        }
    }

    /// Check if this ecosystem uses semantic versioning.
    ///
    /// L-01 FIX: Made const for compile-time evaluation.
    #[must_use]
    pub const fn uses_semver(&self) -> bool {
        matches!(self, Self::Npm | Self::Crates | Self::Go)
    }

    /// Get all supported ecosystems.
    ///
    /// L-01 FIX: Made const for compile-time evaluation.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Npm,
            Self::PyPi,
            Self::Crates,
            Self::Go,
            Self::Maven,
            Self::Url,
        ]
    }
}

/// Dependency resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionStrategy {
    /// Select the oldest/lowest version that satisfies the requirements (Go style).
    /// Best for reproducibility and avoiding accidental breaking changes.
    Minimal,
    /// Select the newest/highest version that satisfies the requirements (Npm/Cargo style).
    /// Best for getting latest features and bug fixes.
    MaxSatisfying,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.manifest_key())
    }
}

impl FromStr for Ecosystem {
    type Err = CratonsError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "npm" | "node" | "javascript" | "js" => Ok(Self::Npm),
            "pypi" | "python" | "pip" | "py" => Ok(Self::PyPi),
            "crates" | "crates.io" | "rust" | "cargo" => Ok(Self::Crates),
            "go" | "golang" | "gomod" => Ok(Self::Go),
            "maven" | "java" | "jvm" | "gradle" => Ok(Self::Maven),
            "url" | "direct" | "http" | "https" => Ok(Self::Url),
            _ => Err(CratonsError::UnknownEcosystem(s.to_string())),
        }
    }
}

/// Registry configuration for an ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// The ecosystem this registry serves
    pub ecosystem: Ecosystem,
    /// The registry URL
    pub url: String,
    /// Optional authentication token
    pub token: Option<String>,
    /// Whether to verify SSL certificates
    pub verify_ssl: bool,
}

impl RegistryConfig {
    /// Create a new registry config with default settings.
    #[must_use]
    pub fn new(ecosystem: Ecosystem) -> Self {
        Self {
            url: ecosystem.default_registry().to_string(),
            ecosystem,
            token: None,
            verify_ssl: true,
        }
    }

    /// Create a registry config with a custom URL.
    #[must_use]
    pub fn with_url(ecosystem: Ecosystem, url: impl Into<String>) -> Self {
        Self {
            ecosystem,
            url: url.into(),
            token: None,
            verify_ssl: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_parse() {
        assert_eq!(Ecosystem::from_str("npm").unwrap(), Ecosystem::Npm);
        assert_eq!(Ecosystem::from_str("python").unwrap(), Ecosystem::PyPi);
        assert_eq!(Ecosystem::from_str("rust").unwrap(), Ecosystem::Crates);
        assert_eq!(Ecosystem::from_str("golang").unwrap(), Ecosystem::Go);
        assert_eq!(Ecosystem::from_str("java").unwrap(), Ecosystem::Maven);
    }

    #[test]
    fn test_ecosystem_display() {
        assert_eq!(Ecosystem::Npm.to_string(), "npm");
        assert_eq!(Ecosystem::PyPi.to_string(), "pypi");
        assert_eq!(Ecosystem::Crates.to_string(), "crates");
    }

    #[test]
    fn test_default_registry() {
        assert_eq!(
            Ecosystem::Npm.default_registry(),
            "https://registry.npmjs.org"
        );
        assert_eq!(
            Ecosystem::Crates.default_registry(),
            "https://crates.io/api/v1"
        );
    }
}
