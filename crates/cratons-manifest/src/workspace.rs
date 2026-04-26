//! Workspace configuration.

use cratons_core::{CratonsError, Result};
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

    /// Validate workspace member/exclude glob patterns.
    ///
    /// SECURITY: rejects patterns that traverse outside the workspace
    /// root (`../`) or use absolute paths (`/foo`, `\\foo`, `C:\\foo`).
    /// Without this, a malicious manifest could declare
    /// `members = ["../../../etc/*"]`, causing workspace expansion to
    /// glob arbitrary host directories. Discovery still requires a
    /// `cratons.toml` to exist at the resolved path, which is a weak
    /// invariant; we want a strong one at parse time so downstream
    /// code never has to think about it.
    pub fn validate(&self) -> Result<()> {
        for pattern in self.members.iter().chain(self.exclude.iter()) {
            validate_pattern(pattern)?;
        }
        Ok(())
    }
}

fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.is_empty() {
        return Err(CratonsError::Manifest(
            "Workspace pattern cannot be empty".to_string(),
        ));
    }
    if pattern.contains('\0') {
        return Err(CratonsError::Manifest(format!(
            "Workspace pattern contains a null byte: {pattern}"
        )));
    }
    if pattern.starts_with('/') || pattern.starts_with('\\') {
        return Err(CratonsError::Manifest(format!(
            "Workspace pattern must be relative to the workspace root, got {pattern}"
        )));
    }
    let bytes = pattern.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(CratonsError::Manifest(format!(
            "Workspace pattern must be relative to the workspace root, got {pattern}"
        )));
    }
    for segment in pattern.split(['/', '\\']) {
        if segment == ".." {
            return Err(CratonsError::Manifest(format!(
                "Workspace pattern contains '..': {pattern}. \
                 Members must live within the workspace root."
            )));
        }
    }
    Ok(())
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
    fn test_workspace_pattern_traversal_rejected() {
        // Regression for W-1: previously workspace members were globbed
        // unrestricted; `../../../etc/*` was allowed at parse and only
        // failed downstream if no cratons.toml was found there.
        let mut config = WorkspaceConfig::new();
        config.add_member("../../../etc/*");
        let err = config
            .validate()
            .expect_err("traversing workspace pattern must be rejected");
        assert!(err.to_string().contains("contains '..'"));
    }

    #[test]
    fn test_workspace_pattern_absolute_rejected() {
        let mut config = WorkspaceConfig::new();
        config.add_member("/etc/*");
        let err = config
            .validate()
            .expect_err("absolute workspace pattern must be rejected");
        assert!(err.to_string().contains("relative"));
    }

    #[test]
    fn test_workspace_pattern_windows_drive_rejected() {
        let mut config = WorkspaceConfig::new();
        config.add_member(r"C:\workspace\*");
        let err = config
            .validate()
            .expect_err("Windows-absolute workspace pattern must be rejected");
        assert!(err.to_string().contains("relative"));
    }

    #[test]
    fn test_workspace_pattern_normal_relative_ok() {
        let mut config = WorkspaceConfig::new();
        config.add_member("packages/*");
        config.add_member("apps/*");
        config.add_exclude("packages/deprecated");
        config
            .validate()
            .expect("normal relative patterns must validate");
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
