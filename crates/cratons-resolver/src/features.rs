//! Rust feature unification.
//!
//! This module handles Cargo-style feature resolution:
//! - Features are unified across all dependents (union of all requested features)
//! - `default-features = false` suppresses the `default` feature
//! - Features can enable optional dependencies
//! - Features can enable other features transitively
//!
//! Example:
//! ```text
//! [dependencies]
//! serde = { version = "1.0", features = ["derive"] }
//!
//! # Another package:
//! serde = { version = "1.0", default-features = false, features = ["alloc"] }
//!
//! # Unified result: serde with features ["default", "derive", "alloc"]
//! # (unless all dependents disable default)
//! ```

use cratons_core::{Ecosystem, Result};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};

/// Feature dependency request from a package.
#[derive(Debug, Clone)]
pub struct FeatureRequest {
    /// The package making the request
    pub requester: String,
    /// Requested features
    pub features: Vec<String>,
    /// Whether default features are enabled
    pub default_features: bool,
}

/// The unified feature set for a crate.
#[derive(Debug, Clone, Default)]
pub struct UnifiedFeatures {
    /// All activated features
    pub features: HashSet<String>,
    /// Whether the default feature is enabled
    pub default_enabled: bool,
    /// Optional dependencies that are activated
    pub activated_optional_deps: HashSet<String>,
}

impl UnifiedFeatures {
    /// Create a new empty unified features set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the final feature list.
    #[must_use]
    pub fn to_vec(&self) -> Vec<String> {
        let mut features: Vec<_> = self.features.iter().cloned().collect();
        features.sort();
        features
    }

    /// Check if a specific feature is enabled.
    #[must_use]
    pub fn is_enabled(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }
}

/// Feature graph for a crate.
///
/// This represents the feature structure of a single crate version.
#[derive(Debug, Clone)]
pub struct CrateFeatures {
    /// Crate name
    pub name: String,
    /// Crate version
    pub version: String,
    /// Features and what they enable (other features or optional deps)
    /// e.g., "full" => ["derive", "parsing", "printing"]
    pub features: HashMap<String, Vec<String>>,
    /// Optional dependencies (feature name equals dep name)
    pub optional_deps: HashSet<String>,
    /// Default feature contents
    pub default_features: Vec<String>,
}

impl CrateFeatures {
    /// Create from crates.io index data.
    pub fn from_index_data(
        name: String,
        version: String,
        features: HashMap<String, Vec<String>>,
        optional_deps: Vec<String>,
    ) -> Self {
        let default_features = features.get("default").cloned().unwrap_or_default();
        Self {
            name,
            version,
            features,
            optional_deps: optional_deps.into_iter().collect(),
            default_features,
        }
    }

    /// Expand a feature transitively.
    ///
    /// Given a feature name, returns all features and optional deps it enables.
    pub fn expand_feature(&self, feature: &str) -> HashSet<String> {
        let mut expanded = HashSet::new();
        let mut to_process = vec![feature.to_string()];

        while let Some(f) = to_process.pop() {
            if expanded.contains(&f) {
                continue;
            }
            expanded.insert(f.clone());

            // Check if this feature enables other features
            if let Some(enables) = self.features.get(&f) {
                for enabled in enables {
                    // Handle dep:foo syntax for optional dependencies
                    if let Some(dep_name) = enabled.strip_prefix("dep:") {
                        expanded.insert(dep_name.to_string());
                    } else if let Some((dep_name, dep_feature)) = enabled.split_once('/') {
                        // Handle foo/bar syntax for enabling features on dependencies
                        // This is tracked separately but we mark the dep as needed
                        expanded.insert(format!("{}:{}", dep_name, dep_feature));
                    } else {
                        to_process.push(enabled.clone());
                    }
                }
            }

            // Check if this is an optional dependency (implicit feature)
            if self.optional_deps.contains(&f) {
                // Optional dep enabled
                expanded.insert(format!("dep:{}", f));
            }
        }

        expanded
    }
}

/// Feature unifier for the dependency graph.
#[derive(Debug, Default)]
pub struct FeatureUnifier {
    /// Feature requests per crate: (name, ecosystem) -> Vec<FeatureRequest>
    requests: HashMap<(String, Ecosystem), Vec<FeatureRequest>>,
    /// Crate feature definitions: (name, version, ecosystem) -> CrateFeatures
    crate_features: HashMap<(String, String, Ecosystem), CrateFeatures>,
    /// Resolved unified features per crate: (name, ecosystem) -> UnifiedFeatures
    unified: HashMap<(String, Ecosystem), UnifiedFeatures>,
}

impl FeatureUnifier {
    /// Create a new feature unifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a crate's feature definitions.
    pub fn register_crate(&mut self, features: CrateFeatures, ecosystem: Ecosystem) {
        let key = (features.name.clone(), features.version.clone(), ecosystem);
        self.crate_features.insert(key, features);
    }

    /// Add a feature request from one package to another.
    pub fn add_request(
        &mut self,
        target: &str,
        ecosystem: Ecosystem,
        requester: &str,
        features: Vec<String>,
        default_features: bool,
    ) {
        let key = (target.to_string(), ecosystem);
        self.requests.entry(key).or_default().push(FeatureRequest {
            requester: requester.to_string(),
            features,
            default_features,
        });
    }

    /// Unify features for all crates.
    ///
    /// This processes all feature requests and computes the final feature set
    /// for each crate in the dependency graph.
    pub fn unify(&mut self, versions: &HashMap<(String, Ecosystem), String>) -> Result<()> {
        info!("Unifying features for {} crates", self.requests.len());

        for ((name, ecosystem), requests) in &self.requests {
            if requests.is_empty() {
                continue;
            }

            // Get the crate's feature definitions
            let version = match versions.get(&(name.clone(), *ecosystem)) {
                Some(v) => v.clone(),
                None => {
                    debug!(
                        "No version for {}:{}, skipping feature unification",
                        ecosystem, name
                    );
                    continue;
                }
            };

            let crate_key = (name.clone(), version.clone(), *ecosystem);
            let crate_features = self.crate_features.get(&crate_key);

            let mut unified = UnifiedFeatures::new();

            // Determine if default features should be enabled
            // Default is enabled unless ALL requesters disable it
            let enable_default = requests.iter().any(|r| r.default_features);
            unified.default_enabled = enable_default;

            if enable_default {
                if let Some(cf) = crate_features {
                    // Add the default feature and expand it
                    for feature in cf.expand_feature("default") {
                        unified.features.insert(feature);
                    }
                } else {
                    unified.features.insert("default".to_string());
                }
            }

            // Collect all requested features
            for request in requests {
                for feature in &request.features {
                    if let Some(cf) = crate_features {
                        // Expand the feature transitively
                        for expanded in cf.expand_feature(feature) {
                            unified.features.insert(expanded);
                        }
                    } else {
                        unified.features.insert(feature.clone());
                    }
                }
            }

            // Identify activated optional dependencies
            if let Some(cf) = crate_features {
                for dep in &cf.optional_deps {
                    if unified.features.contains(dep)
                        || unified.features.contains(&format!("dep:{}", dep))
                    {
                        unified.activated_optional_deps.insert(dep.clone());
                    }
                }
            }

            debug!(
                "Unified features for {}:{} = {:?} (default: {})",
                ecosystem, name, unified.features, unified.default_enabled
            );

            self.unified.insert((name.clone(), *ecosystem), unified);
        }

        Ok(())
    }

    /// Get the unified features for a crate.
    #[must_use]
    pub fn get_unified(&self, name: &str, ecosystem: Ecosystem) -> Option<&UnifiedFeatures> {
        self.unified.get(&(name.to_string(), ecosystem))
    }

    /// Get activated optional dependencies for a crate.
    #[must_use]
    pub fn get_activated_optional_deps(&self, name: &str, ecosystem: Ecosystem) -> Vec<String> {
        self.unified
            .get(&(name.to_string(), ecosystem))
            .map(|u| u.activated_optional_deps.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Check if a feature is enabled for a crate.
    #[must_use]
    pub fn is_feature_enabled(&self, name: &str, ecosystem: Ecosystem, feature: &str) -> bool {
        self.unified
            .get(&(name.to_string(), ecosystem))
            .map(|u| u.is_enabled(feature))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_expansion_simple() {
        let mut features = HashMap::new();
        features.insert(
            "full".to_string(),
            vec!["derive".to_string(), "parsing".to_string()],
        );
        features.insert("derive".to_string(), vec![]);
        features.insert("parsing".to_string(), vec![]);

        let cf = CrateFeatures::from_index_data(
            "syn".to_string(),
            "2.0.0".to_string(),
            features,
            vec![],
        );

        let expanded = cf.expand_feature("full");
        assert!(expanded.contains("full"));
        assert!(expanded.contains("derive"));
        assert!(expanded.contains("parsing"));
    }

    #[test]
    fn test_feature_expansion_with_optional_dep() {
        let mut features = HashMap::new();
        features.insert("default".to_string(), vec!["std".to_string()]);
        features.insert("std".to_string(), vec![]);
        features.insert("derive".to_string(), vec!["dep:serde_derive".to_string()]);

        let cf = CrateFeatures::from_index_data(
            "serde".to_string(),
            "1.0.0".to_string(),
            features,
            vec!["serde_derive".to_string()],
        );

        let expanded = cf.expand_feature("derive");
        assert!(expanded.contains("derive"));
        assert!(expanded.contains("serde_derive"));
    }

    #[test]
    fn test_unification_with_default() {
        let mut unifier = FeatureUnifier::new();

        // Package A requests serde with default features
        unifier.add_request(
            "serde",
            Ecosystem::Crates,
            "pkg_a",
            vec!["derive".to_string()],
            true,
        );

        // Package B requests serde without default features
        unifier.add_request(
            "serde",
            Ecosystem::Crates,
            "pkg_b",
            vec!["alloc".to_string()],
            false,
        );

        let mut versions = HashMap::new();
        versions.insert(
            ("serde".to_string(), Ecosystem::Crates),
            "1.0.0".to_string(),
        );

        unifier.unify(&versions).unwrap();

        let unified = unifier.get_unified("serde", Ecosystem::Crates).unwrap();

        // Default should be enabled because pkg_a requested it
        assert!(unified.default_enabled);
        assert!(unified.features.contains("derive"));
        assert!(unified.features.contains("alloc"));
    }

    #[test]
    fn test_unification_no_default() {
        let mut unifier = FeatureUnifier::new();

        // Both packages disable default features
        unifier.add_request(
            "serde",
            Ecosystem::Crates,
            "pkg_a",
            vec!["derive".to_string()],
            false,
        );
        unifier.add_request(
            "serde",
            Ecosystem::Crates,
            "pkg_b",
            vec!["alloc".to_string()],
            false,
        );

        let mut versions = HashMap::new();
        versions.insert(
            ("serde".to_string(), Ecosystem::Crates),
            "1.0.0".to_string(),
        );

        unifier.unify(&versions).unwrap();

        let unified = unifier.get_unified("serde", Ecosystem::Crates).unwrap();

        // Default should NOT be enabled
        assert!(!unified.default_enabled);
        assert!(unified.features.contains("derive"));
        assert!(unified.features.contains("alloc"));
    }

    #[test]
    fn test_crate_features_from_index() {
        let mut features = HashMap::new();
        features.insert("default".to_string(), vec!["std".to_string()]);
        features.insert("std".to_string(), vec![]);
        features.insert("alloc".to_string(), vec![]);

        let cf = CrateFeatures::from_index_data(
            "serde".to_string(),
            "1.0.193".to_string(),
            features.clone(),
            vec!["derive".to_string()],
        );

        assert_eq!(cf.name, "serde");
        assert_eq!(cf.version, "1.0.193");
        assert!(cf.optional_deps.contains("derive"));
        assert_eq!(cf.default_features, vec!["std".to_string()]);
    }
}
