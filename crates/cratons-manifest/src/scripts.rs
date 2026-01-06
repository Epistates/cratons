//! Script definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Scripts defined in the manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scripts {
    scripts: HashMap<String, String>,
}

impl Scripts {
    /// Create a new empty Scripts.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a script by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&String> {
        self.scripts.get(name)
    }

    /// Check if a script exists.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.scripts.contains_key(name)
    }

    /// Insert a script.
    pub fn insert(&mut self, name: String, script: String) {
        self.scripts.insert(name, script);
    }

    /// Remove a script.
    pub fn remove(&mut self, name: &str) -> Option<String> {
        self.scripts.remove(name)
    }

    /// Get all script names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.scripts.keys().map(String::as_str)
    }

    /// Iterate over all scripts.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.scripts.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Check if there are no scripts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    /// Get the number of scripts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scripts.len()
    }
}

impl FromIterator<(String, String)> for Scripts {
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        Self {
            scripts: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scripts() {
        let mut scripts = Scripts::new();
        scripts.insert("dev".to_string(), "npm run dev".to_string());
        scripts.insert("test".to_string(), "npm test".to_string());

        assert!(scripts.has("dev"));
        assert_eq!(scripts.get("dev"), Some(&"npm run dev".to_string()));
        assert_eq!(scripts.len(), 2);
    }

    #[test]
    fn test_scripts_iter() {
        let scripts: Scripts = [
            ("dev".to_string(), "npm run dev".to_string()),
            ("test".to_string(), "npm test".to_string()),
        ]
        .into_iter()
        .collect();

        let names: Vec<_> = scripts.names().collect();
        assert!(names.contains(&"dev"));
        assert!(names.contains(&"test"));
    }
}
