//! Package identifiers and specifications.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::ecosystem::Ecosystem;
use crate::error::{CratonsError, Result};
use crate::hash::ContentHash;
use crate::version::{Version, VersionReq};

/// A unique package identifier within an ecosystem.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageId {
    /// The ecosystem this package belongs to
    pub ecosystem: Ecosystem,
    /// The package name (may include scope, e.g., "@types/node")
    pub name: String,
}

impl PackageId {
    /// Create a new package ID.
    #[must_use]
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>) -> Self {
        Self {
            ecosystem,
            name: name.into(),
        }
    }

    /// Parse a package ID from a string like "npm:lodash" or "pypi:requests".
    pub fn parse(s: &str) -> Result<Self> {
        if let Some((eco, name)) = s.split_once(':') {
            let ecosystem = eco.parse()?;
            Ok(Self::new(ecosystem, name))
        } else {
            Err(CratonsError::Manifest(format!(
                "Invalid package ID format: {s}. Expected 'ecosystem:name'"
            )))
        }
    }

    /// Check if this is a scoped npm package (e.g., "@types/node").
    #[must_use]
    pub fn is_scoped(&self) -> bool {
        self.ecosystem == Ecosystem::Npm && self.name.starts_with('@')
    }

    /// Get the scope of a scoped npm package.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        if self.is_scoped() {
            self.name.split('/').next()
        } else {
            None
        }
    }

    /// Get the unscoped name (e.g., "node" from "@types/node").
    #[must_use]
    pub fn unscoped_name(&self) -> &str {
        if self.is_scoped() {
            self.name.split('/').nth(1).unwrap_or(&self.name)
        } else {
            &self.name
        }
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ecosystem, self.name)
    }
}

/// A package specification with version constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSpec {
    /// The package identifier
    pub id: PackageId,
    /// Version requirement
    pub version_req: VersionReq,
    /// Optional features/extras to enable
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Whether this is an optional dependency
    #[serde(default)]
    pub optional: bool,
    /// Git repository URL (for git dependencies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<String>,
    /// Git branch/tag/rev
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    /// Direct URL for URL ecosystem
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Expected hash for URL dependencies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<ContentHash>,
}

impl PackageSpec {
    /// Create a new package spec with just an ID and version requirement.
    #[must_use]
    pub fn new(id: PackageId, version_req: VersionReq) -> Self {
        Self {
            id,
            version_req,
            features: Vec::new(),
            optional: false,
            git: None,
            rev: None,
            url: None,
            hash: None,
        }
    }

    /// Create a package spec from ecosystem, name, and version string.
    pub fn from_parts(
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: &str,
    ) -> Result<Self> {
        let id = PackageId::new(ecosystem, name);
        let version_req = VersionReq::parse(version, ecosystem)?;
        Ok(Self::new(id, version_req))
    }

    /// Parse a package spec from a CLI-style string like "npm:lodash@^4.17.0".
    pub fn parse(s: &str) -> Result<Self> {
        // Format: ecosystem:name@version or ecosystem:name
        let (id_part, version_part) = if let Some(at_pos) = s.rfind('@') {
            // Check if @ is part of scoped package name
            if s.starts_with('@') && !s[1..at_pos].contains('/') {
                // This is a scoped package without version
                (s, None)
            } else {
                (&s[..at_pos], Some(&s[at_pos + 1..]))
            }
        } else {
            (s, None)
        };

        let id = PackageId::parse(id_part)?;
        let version_req = if let Some(v) = version_part {
            VersionReq::parse(v, id.ecosystem)?
        } else {
            VersionReq::Any
        };

        Ok(Self::new(id, version_req))
    }

    /// Add features to this spec.
    #[must_use]
    pub fn with_features(mut self, features: Vec<String>) -> Self {
        self.features = features;
        self
    }

    /// Mark this spec as optional.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

impl fmt::Display for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.id, self.version_req)?;
        if !self.features.is_empty() {
            write!(f, "[{}]", self.features.join(","))?;
        }
        Ok(())
    }
}

/// A resolved package with exact version and source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedPackage {
    /// The package identifier
    pub id: PackageId,
    /// The exact resolved version
    pub version: Version,
    /// The source URL for downloading
    pub source: String,
    /// Content hash for integrity verification
    pub integrity: ContentHash,
    /// Whether this is a direct dependency
    pub direct: bool,
    /// Enabled features
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Dependencies of this package
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<PackageId>,
}

impl ResolvedPackage {
    /// Create a new resolved package.
    #[must_use]
    pub fn new(id: PackageId, version: Version, source: String, integrity: ContentHash) -> Self {
        Self {
            id,
            version,
            source,
            integrity,
            direct: false,
            features: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    /// Get a display name for this package.
    #[must_use]
    pub fn display_name(&self) -> String {
        format!("{}@{}", self.id.name, self.version)
    }
}

impl fmt::Display for ResolvedPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.id, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_id_parse() {
        let id = PackageId::parse("npm:lodash").unwrap();
        assert_eq!(id.ecosystem, Ecosystem::Npm);
        assert_eq!(id.name, "lodash");
    }

    #[test]
    fn test_scoped_package() {
        let id = PackageId::new(Ecosystem::Npm, "@types/node");
        assert!(id.is_scoped());
        assert_eq!(id.scope(), Some("@types"));
        assert_eq!(id.unscoped_name(), "node");
    }

    #[test]
    fn test_package_spec_parse() {
        let spec = PackageSpec::parse("npm:lodash@^4.17.0").unwrap();
        assert_eq!(spec.id.ecosystem, Ecosystem::Npm);
        assert_eq!(spec.id.name, "lodash");
    }

    #[test]
    fn test_package_spec_display() {
        let spec = PackageSpec::from_parts(Ecosystem::Crates, "serde", "1.0").unwrap();
        assert!(spec.to_string().contains("serde"));
    }
}
