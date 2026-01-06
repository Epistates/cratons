//! Dependency specifications.

use cratons_core::{ContentHash, Ecosystem, CratonsError, PackageSpec, Result, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Dependencies grouped by ecosystem.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Dependencies {
    /// npm packages
    #[serde(default)]
    pub npm: HashMap<String, Dependency>,

    /// PyPI packages
    #[serde(default)]
    pub pypi: HashMap<String, Dependency>,

    /// Rust crates
    #[serde(default)]
    pub crates: HashMap<String, Dependency>,

    /// Go modules
    #[serde(default)]
    pub go: HashMap<String, Dependency>,

    /// Maven artifacts
    #[serde(default)]
    pub maven: HashMap<String, Dependency>,

    /// Direct URL dependencies
    #[serde(default)]
    pub url: HashMap<String, Dependency>,

    /// Workspace dependencies (references to other workspace members)
    #[serde(default)]
    pub workspace: HashMap<String, WorkspaceDep>,
}

impl Dependencies {
    /// Check if there are any dependencies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.npm.is_empty()
            && self.pypi.is_empty()
            && self.crates.is_empty()
            && self.go.is_empty()
            && self.maven.is_empty()
            && self.url.is_empty()
            && self.workspace.is_empty()
    }

    /// Get total number of dependencies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.npm.len()
            + self.pypi.len()
            + self.crates.len()
            + self.go.len()
            + self.maven.len()
            + self.url.len()
            + self.workspace.len()
    }

    /// Get dependencies for a specific ecosystem.
    #[must_use]
    pub fn for_ecosystem(&self, ecosystem: Ecosystem) -> &HashMap<String, Dependency> {
        match ecosystem {
            Ecosystem::Npm => &self.npm,
            Ecosystem::PyPi => &self.pypi,
            Ecosystem::Crates => &self.crates,
            Ecosystem::Go => &self.go,
            Ecosystem::Maven => &self.maven,
            Ecosystem::Url => &self.url,
        }
    }

    /// Validate all dependencies.
    pub fn validate(&self) -> Result<()> {
        for (name, dep) in &self.npm {
            dep.validate(Ecosystem::Npm, name)?;
        }
        for (name, dep) in &self.pypi {
            dep.validate(Ecosystem::PyPi, name)?;
        }
        for (name, dep) in &self.crates {
            dep.validate(Ecosystem::Crates, name)?;
        }
        for (name, dep) in &self.go {
            dep.validate(Ecosystem::Go, name)?;
        }
        for (name, dep) in &self.maven {
            dep.validate(Ecosystem::Maven, name)?;
        }
        Ok(())
    }

    /// Merge another Dependencies into this one.
    pub fn merge(&mut self, other: &Self) {
        self.npm
            .extend(other.npm.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.pypi
            .extend(other.pypi.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.crates
            .extend(other.crates.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.go
            .extend(other.go.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.maven
            .extend(other.maven.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.url
            .extend(other.url.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.workspace
            .extend(other.workspace.iter().map(|(k, v)| (k.clone(), v.clone())));
    }

    /// Convert to a list of PackageSpecs.
    pub fn to_specs(&self) -> Result<Vec<PackageSpec>> {
        let mut specs = Vec::new();

        for (name, dep) in &self.npm {
            specs.push(dep.to_spec(Ecosystem::Npm, name)?);
        }
        for (name, dep) in &self.pypi {
            specs.push(dep.to_spec(Ecosystem::PyPi, name)?);
        }
        for (name, dep) in &self.crates {
            specs.push(dep.to_spec(Ecosystem::Crates, name)?);
        }
        for (name, dep) in &self.go {
            specs.push(dep.to_spec(Ecosystem::Go, name)?);
        }
        for (name, dep) in &self.maven {
            specs.push(dep.to_spec(Ecosystem::Maven, name)?);
        }

        Ok(specs)
    }

    /// Iterate over all dependencies with their ecosystem.
    pub fn iter(&self) -> impl Iterator<Item = (Ecosystem, &str, &Dependency)> {
        self.npm
            .iter()
            .map(|(n, d)| (Ecosystem::Npm, n.as_str(), d))
            .chain(
                self.pypi
                    .iter()
                    .map(|(n, d)| (Ecosystem::PyPi, n.as_str(), d)),
            )
            .chain(
                self.crates
                    .iter()
                    .map(|(n, d)| (Ecosystem::Crates, n.as_str(), d)),
            )
            .chain(self.go.iter().map(|(n, d)| (Ecosystem::Go, n.as_str(), d)))
            .chain(
                self.maven
                    .iter()
                    .map(|(n, d)| (Ecosystem::Maven, n.as_str(), d)),
            )
            .chain(
                self.url
                    .iter()
                    .map(|(n, d)| (Ecosystem::Url, n.as_str(), d)),
            )
    }
}

/// A single dependency specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Dependency {
    /// Simple version string (e.g., "^1.0.0")
    Version(String),
    /// Detailed dependency specification
    Detailed(DetailedDependency),
}

impl Dependency {
    /// Get the version requirement.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Version(v) => Some(v),
            Self::Detailed(d) => d.version.as_deref(),
        }
    }

    /// Check if this is an optional dependency.
    #[must_use]
    pub fn is_optional(&self) -> bool {
        match self {
            Self::Version(_) => false,
            Self::Detailed(d) => d.optional,
        }
    }

    /// Get features/extras.
    #[must_use]
    pub fn features(&self) -> &[String] {
        match self {
            Self::Version(_) => &[],
            Self::Detailed(d) => &d.features,
        }
    }

    /// Get the dependency source.
    #[must_use]
    pub fn source(&self) -> DependencySource {
        match self {
            Self::Version(_) => DependencySource::Registry,
            Self::Detailed(d) => {
                if d.git.is_some() {
                    DependencySource::Git
                } else if d.url.is_some() {
                    DependencySource::Url
                } else if d.path.is_some() {
                    DependencySource::Path
                } else if d.workspace {
                    DependencySource::Workspace
                } else {
                    DependencySource::Registry
                }
            }
        }
    }

    /// Validate the dependency.
    pub fn validate(&self, ecosystem: Ecosystem, name: &str) -> Result<()> {
        // Validate dependency name
        if name.is_empty() {
            return Err(CratonsError::Manifest(
                "Dependency name cannot be empty".to_string(),
            ));
        }

        // Ecosystem-specific name validation
        match ecosystem {
            Ecosystem::Npm => {
                // npm package names can't start with . or _
                if name.starts_with('.') || name.starts_with('_') {
                    return Err(CratonsError::Manifest(format!(
                        "Invalid npm package name '{}': cannot start with . or _",
                        name
                    )));
                }
            }
            Ecosystem::PyPi => {
                // PyPI names are normalized, check for valid characters
                if !name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
                {
                    return Err(CratonsError::Manifest(format!(
                        "Invalid PyPI package name '{}': contains invalid characters",
                        name
                    )));
                }
            }
            _ => {}
        }

        match self {
            Self::Version(v) => {
                // Try to parse the version requirement
                VersionReq::parse(v, ecosystem).map_err(|_| {
                    CratonsError::Manifest(format!(
                        "Invalid version requirement for {}: {}",
                        name, v
                    ))
                })?;
            }
            Self::Detailed(d) => {
                // Validate version if present
                if let Some(ref v) = d.version {
                    VersionReq::parse(v, ecosystem).map_err(|_| {
                        CratonsError::Manifest(format!(
                            "Invalid version requirement for {}: {}",
                            name, v
                        ))
                    })?;
                }

                // Validate source fields - only one source type should be specified
                let source_count = [
                    d.git.is_some(),
                    d.url.is_some(),
                    d.path.is_some(),
                    d.workspace,
                ]
                .iter()
                .filter(|&&x| x)
                .count();

                if source_count > 1 {
                    return Err(CratonsError::Manifest(format!(
                        "Dependency '{}' has multiple source types specified. \
                         Only one of git, url, path, or workspace can be used.",
                        name
                    )));
                }

                // Validate git source fields
                if d.git.is_some() {
                    // Validate git URL format
                    if let Some(ref git_url) = d.git {
                        if !git_url.starts_with("https://")
                            && !git_url.starts_with("git://")
                            && !git_url.starts_with("ssh://")
                            && !git_url.starts_with("git@")
                        {
                            return Err(CratonsError::Manifest(format!(
                                "Invalid git URL for '{}': {}. \
                                 Must start with https://, git://, ssh://, or git@",
                                name, git_url
                            )));
                        }
                    }

                    // Only one of branch/tag/rev should be specified
                    let ref_count = [d.branch.is_some(), d.tag.is_some(), d.rev.is_some()]
                        .iter()
                        .filter(|&&x| x)
                        .count();

                    if ref_count > 1 {
                        return Err(CratonsError::Manifest(format!(
                            "Dependency '{}' has multiple git refs specified. \
                             Only one of branch, tag, or rev can be used.",
                            name
                        )));
                    }
                } else {
                    // branch/tag/rev only valid with git
                    if d.branch.is_some() || d.tag.is_some() || d.rev.is_some() {
                        return Err(CratonsError::Manifest(format!(
                            "Dependency '{}' has branch/tag/rev without git URL",
                            name
                        )));
                    }
                }

                // Validate URL source
                if let Some(ref url) = d.url {
                    if !url.starts_with("https://") && !url.starts_with("http://") {
                        return Err(CratonsError::Manifest(format!(
                            "Invalid URL for '{}': {}. Must start with https:// or http://",
                            name, url
                        )));
                    }

                    // URL sources should have a sha256 hash for security
                    if d.sha256.is_none() {
                        // This is a warning-level issue, not an error
                        // Log it but don't fail validation
                        tracing::warn!(
                            "URL dependency '{}' has no sha256 hash specified. \
                             This is insecure and should be fixed.",
                            name
                        );
                    }
                }

                // Validate path source
                if let Some(ref path) = d.path {
                    // Check for path traversal attempts
                    if path.contains("..") {
                        return Err(CratonsError::Manifest(format!(
                            "Path dependency '{}' contains '..': {}. \
                             Path traversal is not allowed.",
                            name, path
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Convert to a PackageSpec.
    pub fn to_spec(&self, ecosystem: Ecosystem, name: &str) -> Result<PackageSpec> {
        let version_str = self.version().unwrap_or("*");
        let mut spec = PackageSpec::from_parts(ecosystem, name, version_str)?;

        if let Self::Detailed(d) = self {
            spec.features = d.features.clone();
            spec.optional = d.optional;
            spec.git = d.git.clone();
            spec.rev = d
                .rev
                .clone()
                .or_else(|| d.branch.clone())
                .or_else(|| d.tag.clone());
            spec.url = d.url.clone();
            spec.hash = d.sha256.as_ref().map(|h| ContentHash::sha256(h.clone()));
        }

        Ok(spec)
    }
}

/// Detailed dependency specification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DetailedDependency {
    /// Version requirement
    #[serde(default)]
    pub version: Option<String>,

    /// Features/extras to enable
    #[serde(default)]
    pub features: Vec<String>,

    /// Whether this is an optional dependency
    #[serde(default)]
    pub optional: bool,

    /// Git repository URL
    #[serde(default)]
    pub git: Option<String>,

    /// Git branch
    #[serde(default)]
    pub branch: Option<String>,

    /// Git tag
    #[serde(default)]
    pub tag: Option<String>,

    /// Git revision
    #[serde(default)]
    pub rev: Option<String>,

    /// Direct URL
    #[serde(default)]
    pub url: Option<String>,

    /// SHA-256 hash for URL dependencies
    #[serde(default)]
    pub sha256: Option<String>,

    /// Local path
    #[serde(default)]
    pub path: Option<String>,

    /// Workspace dependency
    #[serde(default)]
    pub workspace: bool,

    /// Default features enabled
    #[serde(default = "default_true")]
    pub default_features: bool,
}

fn default_true() -> bool {
    true
}

/// Source of a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencySource {
    /// From a registry
    Registry,
    /// From a git repository
    Git,
    /// From a direct URL
    Url,
    /// From a local path
    Path,
    /// From the workspace
    Workspace,
}

/// Workspace dependency reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkspaceDep {
    /// Simple path reference
    Path(String),
    /// Detailed workspace reference
    Detailed {
        /// Path to the workspace member
        path: String,
        /// Features to enable
        #[serde(default)]
        features: Vec<String>,
    },
}

impl WorkspaceDep {
    /// Get the path.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Path(p) => p,
            Self::Detailed { path, .. } => path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_dependency() {
        // Test via a wrapper table since TOML can't parse bare values
        #[derive(serde::Deserialize)]
        struct Wrapper {
            dep: Dependency,
        }
        let wrapper: Wrapper = toml::from_str(r#"dep = "^1.0.0""#).unwrap();
        assert_eq!(wrapper.dep.version(), Some("^1.0.0"));
        assert!(!wrapper.dep.is_optional());
    }

    #[test]
    fn test_detailed_dependency() {
        let dep: Dependency = toml::from_str(
            r#"
            version = "^1.0.0"
            features = ["derive"]
            optional = true
            "#,
        )
        .unwrap();

        assert_eq!(dep.version(), Some("^1.0.0"));
        assert!(dep.is_optional());
        assert_eq!(dep.features(), &["derive"]);
    }

    #[test]
    fn test_git_dependency() {
        let dep: Dependency = toml::from_str(
            r#"
            git = "https://github.com/example/repo"
            branch = "main"
            "#,
        )
        .unwrap();

        assert_eq!(dep.source(), DependencySource::Git);
    }

    #[test]
    fn test_dependencies_iter() {
        let deps = Dependencies {
            npm: [(
                "lodash".to_string(),
                Dependency::Version("^4.17.0".to_string()),
            )]
            .into_iter()
            .collect(),
            pypi: [(
                "requests".to_string(),
                Dependency::Version(">=2.28.0".to_string()),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let items: Vec<_> = deps.iter().collect();
        assert_eq!(items.len(), 2);
    }
}
