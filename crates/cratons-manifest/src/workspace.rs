//! Workspace configuration.

use serde::{Deserialize, Serialize};

use crate::dependency::Dependencies;
use crate::environment::Environment;

/// Workspace configuration for monorepos.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WorkspaceConfig {
    /// Glob patterns for workspace members
    #[serde(default)]
    pub members: Vec<String>,

    /// Glob patterns for excluded directories
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Shared environment (inherited by members)
    #[serde(default)]
    pub environment: Environment,

    /// Shared dependencies (can be referenced with `workspace = true`)
    #[serde(default)]
    pub dependencies: Dependencies,
}

impl WorkspaceConfig {
    /// Create a new workspace configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a member pattern.
    pub fn add_member(&mut self, pattern: impl Into<String>) {
        self.members.push(pattern.into());
    }

    /// Add an exclude pattern.
    pub fn add_exclude(&mut self, pattern: impl Into<String>) {
        self.exclude.push(pattern.into());
    }

    /// Check if there are any member patterns.
    #[must_use]
    pub fn has_members(&self) -> bool {
        !self.members.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_config() {
        let mut config = WorkspaceConfig::new();
        config.add_member("packages/*");
        config.add_member("apps/*");
        config.add_exclude("packages/deprecated");

        assert_eq!(config.members.len(), 2);
        assert_eq!(config.exclude.len(), 1);
        assert!(config.has_members());
    }

    #[test]
    fn test_workspace_parse() {
        let toml_str = r#"
members = ["packages/*", "apps/*"]
exclude = ["packages/internal"]

[environment]
node = "20.10.0"

[dependencies.npm]
typescript = "^5.0.0"
"#;
        let config: WorkspaceConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.members.len(), 2);
        assert_eq!(config.exclude.len(), 1);
        assert_eq!(config.environment.node, Some("20.10.0".to_string()));
        assert!(config.dependencies.npm.contains_key("typescript"));
    }
}
