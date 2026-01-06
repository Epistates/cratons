//! Package metadata.

use serde::{Deserialize, Serialize};

/// Package metadata from the manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Package {
    /// Package name
    #[serde(default)]
    pub name: String,

    /// Package version
    #[serde(default)]
    pub version: String,

    /// Package description
    #[serde(default)]
    pub description: String,

    /// License identifier
    #[serde(default)]
    pub license: Option<String>,

    /// Authors
    #[serde(default)]
    pub authors: Vec<String>,

    /// Repository URL
    #[serde(default)]
    pub repository: Option<String>,

    /// Homepage URL
    #[serde(default)]
    pub homepage: Option<String>,

    /// Documentation URL
    #[serde(default)]
    pub documentation: Option<String>,

    /// Keywords
    #[serde(default)]
    pub keywords: Vec<String>,

    /// Categories
    #[serde(default)]
    pub categories: Vec<String>,

    /// Readme file path
    #[serde(default)]
    pub readme: Option<String>,

    /// Whether this package is private (not publishable)
    #[serde(default)]
    pub private: bool,
}

impl Package {
    /// Create a new package with the given name and version.
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            ..Default::default()
        }
    }

    /// Check if the package has the minimum required metadata.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.name.is_empty() && !self.version.is_empty()
    }

    /// Get the package's full identifier (name@version).
    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_new() {
        let pkg = Package::new("my-app", "1.0.0");
        assert_eq!(pkg.name, "my-app");
        assert_eq!(pkg.version, "1.0.0");
        assert!(pkg.is_valid());
    }

    #[test]
    fn test_package_full_name() {
        let pkg = Package::new("my-app", "1.0.0");
        assert_eq!(pkg.full_name(), "my-app@1.0.0");
    }
}
