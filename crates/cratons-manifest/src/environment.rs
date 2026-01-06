//! Environment and toolchain configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Environment configuration for builds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Environment {
    /// Node.js version
    #[serde(default)]
    pub node: Option<String>,

    /// Python version
    #[serde(default)]
    pub python: Option<String>,

    /// Rust toolchain version
    #[serde(default)]
    pub rust: Option<String>,

    /// Go version
    #[serde(default)]
    pub go: Option<String>,

    /// Java version
    #[serde(default)]
    pub java: Option<String>,

    /// System packages required for build
    #[serde(default)]
    pub system: Vec<String>,

    /// Environment variables
    #[serde(default)]
    pub vars: HashMap<String, String>,
}

impl Environment {
    /// Check if any toolchains are specified.
    #[must_use]
    pub fn has_toolchains(&self) -> bool {
        self.node.is_some()
            || self.python.is_some()
            || self.rust.is_some()
            || self.go.is_some()
            || self.java.is_some()
    }

    /// Get all specified toolchains as (name, version) pairs.
    #[must_use]
    pub fn toolchains(&self) -> Vec<(&'static str, &str)> {
        let mut toolchains = Vec::new();

        if let Some(ref v) = self.node {
            toolchains.push(("node", v.as_str()));
        }
        if let Some(ref v) = self.python {
            toolchains.push(("python", v.as_str()));
        }
        if let Some(ref v) = self.rust {
            toolchains.push(("rust", v.as_str()));
        }
        if let Some(ref v) = self.go {
            toolchains.push(("go", v.as_str()));
        }
        if let Some(ref v) = self.java {
            toolchains.push(("java", v.as_str()));
        }

        toolchains
    }

    /// Merge another environment into this one (other takes precedence).
    pub fn merge(&mut self, other: &Self) {
        if other.node.is_some() {
            self.node = other.node.clone();
        }
        if other.python.is_some() {
            self.python = other.python.clone();
        }
        if other.rust.is_some() {
            self.rust = other.rust.clone();
        }
        if other.go.is_some() {
            self.go = other.go.clone();
        }
        if other.java.is_some() {
            self.java = other.java.clone();
        }

        self.system.extend(other.system.iter().cloned());
        self.vars
            .extend(other.vars.iter().map(|(k, v)| (k.clone(), v.clone())));
    }

    /// Create a HashMap of all environment variables for the build.
    #[must_use]
    pub fn build_env(&self) -> HashMap<String, String> {
        let env = self.vars.clone();

        // Add PATH entries for toolchains
        // This will be constructed based on installed toolchain locations
        // For now, just include the user's vars

        env
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_toolchains() {
        let env = Environment {
            node: Some("20.10.0".to_string()),
            python: Some("3.12.0".to_string()),
            ..Default::default()
        };

        let toolchains = env.toolchains();
        assert_eq!(toolchains.len(), 2);
        assert!(toolchains.contains(&("node", "20.10.0")));
        assert!(toolchains.contains(&("python", "3.12.0")));
    }

    #[test]
    fn test_environment_merge() {
        let mut env1 = Environment {
            node: Some("18.0.0".to_string()),
            ..Default::default()
        };

        let env2 = Environment {
            node: Some("20.10.0".to_string()),
            python: Some("3.12.0".to_string()),
            ..Default::default()
        };

        env1.merge(&env2);

        assert_eq!(env1.node, Some("20.10.0".to_string()));
        assert_eq!(env1.python, Some("3.12.0".to_string()));
    }
}
