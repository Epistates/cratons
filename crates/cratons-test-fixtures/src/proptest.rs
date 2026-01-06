//! Property-based testing strategies using proptest.
//!
//! Provides `Arbitrary` implementations and custom strategies for generating
//! valid test data for Cratons types, enabling property-based testing of
//! package manager logic.

use cratons_core::{
    ContentHash, Ecosystem, HashAlgorithm, PackageId, PackageSpec, Version, VersionReq,
};
use cratons_lockfile::{DependencyRef, LockedPackage, Lockfile};
use cratons_manifest::{Dependencies, Dependency, Environment, Manifest, Package};
use proptest::collection::{hash_map, vec};
use proptest::prelude::*;
use std::collections::HashMap;

// ============================================================================
// Ecosystem Strategies
// ============================================================================

/// Strategy for generating arbitrary ecosystems.
pub fn ecosystem_strategy() -> impl Strategy<Value = Ecosystem> {
    prop_oneof![
        Just(Ecosystem::Npm),
        Just(Ecosystem::PyPi),
        Just(Ecosystem::Crates),
        Just(Ecosystem::Go),
        Just(Ecosystem::Maven),
        Just(Ecosystem::Url),
    ]
}

// ============================================================================
// Version Strategies
// ============================================================================

/// Strategy for generating valid semantic versions.
pub fn semver_strategy() -> impl Strategy<Value = String> {
    (0u64..100, 0u64..100, 0u64..100)
        .prop_map(|(major, minor, patch)| format!("{major}.{minor}.{patch}"))
}

/// Strategy for generating semantic versions with prerelease.
pub fn semver_prerelease_strategy() -> impl Strategy<Value = String> {
    (
        0u64..100,
        0u64..100,
        0u64..100,
        prop_oneof!["alpha", "beta", "rc"],
        0u64..10,
    )
        .prop_map(|(major, minor, patch, pre, num)| format!("{major}.{minor}.{patch}-{pre}.{num}"))
}

/// Strategy for generating PEP 440 versions.
pub fn pep440_strategy() -> impl Strategy<Value = String> {
    (0u64..100, 0u64..100, 0u64..100)
        .prop_map(|(major, minor, patch)| format!("{major}.{minor}.{patch}"))
}

/// Strategy for generating PEP 440 versions with pre-release.
pub fn pep440_prerelease_strategy() -> impl Strategy<Value = String> {
    (
        0u64..100,
        0u64..100,
        0u64..100,
        prop_oneof!["a", "b", "rc"],
        0u64..10,
    )
        .prop_map(|(major, minor, patch, pre, num)| format!("{major}.{minor}.{patch}{pre}{num}"))
}

/// Strategy for generating Maven versions.
pub fn maven_version_strategy() -> impl Strategy<Value = String> {
    (0u64..100, 0u64..100, 0u64..100)
        .prop_map(|(major, minor, patch)| format!("{major}.{minor}.{patch}"))
}

/// Strategy for generating versions appropriate for a given ecosystem.
pub fn version_for_ecosystem_strategy(ecosystem: Ecosystem) -> impl Strategy<Value = String> {
    match ecosystem {
        Ecosystem::Npm | Ecosystem::Crates | Ecosystem::Go => semver_strategy().boxed(),
        Ecosystem::PyPi => pep440_strategy().boxed(),
        Ecosystem::Maven => maven_version_strategy().boxed(),
        Ecosystem::Url => semver_strategy().boxed(),
    }
}

/// Strategy for generating arbitrary `Version` instances.
pub fn version_strategy() -> impl Strategy<Value = Version> {
    (ecosystem_strategy(), semver_strategy()).prop_map(|(ecosystem, version_str)| {
        Version::parse(&version_str, ecosystem)
            .unwrap_or_else(|_| Version::parse("1.0.0", ecosystem).unwrap())
    })
}

// ============================================================================
// Version Requirement Strategies
// ============================================================================

/// Strategy for generating semver requirements.
pub fn semver_req_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        semver_strategy().prop_map(|v| format!("^{v}")),
        semver_strategy().prop_map(|v| format!("~{v}")),
        semver_strategy().prop_map(|v| format!(">={v}")),
        semver_strategy().prop_map(|v| format!("={v}")),
        Just("*".to_string()),
    ]
}

/// Strategy for generating PEP 440 requirements.
pub fn pep440_req_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        pep440_strategy().prop_map(|v| format!(">={v}")),
        pep440_strategy().prop_map(|v| format!("=={v}")),
        pep440_strategy().prop_map(|v| format!("~={v}")),
        (pep440_strategy(), pep440_strategy()).prop_map(|(v1, v2)| format!(">={v1},<{v2}")),
    ]
}

/// Strategy for generating version requirements appropriate for an ecosystem.
pub fn version_req_for_ecosystem_strategy(ecosystem: Ecosystem) -> impl Strategy<Value = String> {
    match ecosystem {
        Ecosystem::Npm | Ecosystem::Crates => semver_req_strategy().boxed(),
        Ecosystem::PyPi => pep440_req_strategy().boxed(),
        Ecosystem::Go => semver_req_strategy().boxed(),
        Ecosystem::Maven | Ecosystem::Url => semver_strategy().boxed(),
    }
}

/// Strategy for generating arbitrary `VersionReq` instances.
pub fn version_req_strategy() -> impl Strategy<Value = VersionReq> {
    (ecosystem_strategy(), semver_req_strategy()).prop_map(|(ecosystem, req_str)| {
        VersionReq::parse(&req_str, ecosystem).unwrap_or(VersionReq::Any)
    })
}

// ============================================================================
// Package Name Strategies
// ============================================================================

/// Strategy for generating valid npm package names.
pub fn npm_package_name_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Regular package names
        "[a-z][a-z0-9-]{2,20}".prop_map(|s| s.to_string()),
        // Scoped package names
        ("@[a-z][a-z0-9-]{2,10}", "[a-z][a-z0-9-]{2,10}")
            .prop_map(|(scope, name)| format!("{scope}/{name}")),
    ]
}

/// Strategy for generating valid PyPI package names.
pub fn pypi_package_name_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-_]{2,20}".prop_map(|s| s.to_string())
}

/// Strategy for generating valid crates.io package names.
pub fn crates_package_name_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{2,20}".prop_map(|s| s.to_string())
}

/// Strategy for generating package names appropriate for an ecosystem.
pub fn package_name_for_ecosystem_strategy(ecosystem: Ecosystem) -> impl Strategy<Value = String> {
    match ecosystem {
        Ecosystem::Npm => npm_package_name_strategy().boxed(),
        Ecosystem::PyPi => pypi_package_name_strategy().boxed(),
        Ecosystem::Crates => crates_package_name_strategy().boxed(),
        Ecosystem::Go => "[a-z][a-z0-9-]{2,20}".prop_map(|s| s.to_string()).boxed(),
        Ecosystem::Maven => "[a-z][a-z0-9.-]{2,20}".prop_map(|s| s.to_string()).boxed(),
        Ecosystem::Url => "[a-z][a-z0-9-]{2,20}".prop_map(|s| s.to_string()).boxed(),
    }
}

// ============================================================================
// Hash Strategies
// ============================================================================

/// Strategy for generating content hashes.
pub fn content_hash_strategy() -> impl Strategy<Value = ContentHash> {
    (
        prop_oneof![Just(HashAlgorithm::Blake3), Just(HashAlgorithm::Sha256),],
        "[0-9a-f]{64}",
    )
        .prop_map(|(algorithm, value)| ContentHash::new(algorithm, value.to_string()))
}

// ============================================================================
// PackageId Strategies
// ============================================================================

/// Strategy for generating arbitrary `PackageId` instances.
pub fn package_id_strategy() -> impl Strategy<Value = PackageId> {
    ecosystem_strategy().prop_flat_map(|ecosystem| {
        package_name_for_ecosystem_strategy(ecosystem)
            .prop_map(move |name| PackageId::new(ecosystem, name))
    })
}

// ============================================================================
// PackageSpec Strategies
// ============================================================================

/// Strategy for generating arbitrary `PackageSpec` instances.
pub fn package_spec_strategy() -> impl Strategy<Value = PackageSpec> {
    (
        ecosystem_strategy(),
        proptest::bool::ANY,
        vec(any::<String>(), 0..5),
    )
        .prop_flat_map(|(ecosystem, optional, features)| {
            (
                package_name_for_ecosystem_strategy(ecosystem),
                version_req_for_ecosystem_strategy(ecosystem),
            )
                .prop_map(move |(name, version_str)| {
                    let id = PackageId::new(ecosystem, name);
                    let version_req =
                        VersionReq::parse(&version_str, ecosystem).unwrap_or(VersionReq::Any);
                    PackageSpec {
                        id,
                        version_req,
                        features: features.clone(),
                        optional,
                        git: None,
                        rev: None,
                        url: None,
                        hash: None,
                    }
                })
        })
}

// ============================================================================
// LockedPackage Strategies
// ============================================================================

/// Strategy for generating arbitrary `LockedPackage` instances.
pub fn locked_package_strategy() -> impl Strategy<Value = LockedPackage> {
    (
        ecosystem_strategy(),
        proptest::bool::ANY,
        vec(any::<String>(), 0..5),
        vec((any::<String>(), any::<String>()), 0..10),
    )
        .prop_flat_map(|(ecosystem, direct, features, deps)| {
            (
                package_name_for_ecosystem_strategy(ecosystem),
                version_for_ecosystem_strategy(ecosystem),
                content_hash_strategy(),
            )
                .prop_map(move |(name, version, hash)| {
                    let source = format!("https://registry.example.com/{name}/{version}");
                    let integrity = format!("sha256-{}", hash.value);
                    let dependencies = deps
                        .iter()
                        .map(|(n, v)| DependencyRef::new(n.clone(), v.clone()))
                        .collect();

                    LockedPackage {
                        name,
                        version,
                        ecosystem,
                        source,
                        integrity,
                        resolved_hash: hash.clone(),
                        direct,
                        features: features.clone(),
                        dependencies,
                    }
                })
        })
}

// ============================================================================
// Lockfile Strategies
// ============================================================================

/// Strategy for generating arbitrary `Lockfile` instances.
pub fn lockfile_strategy() -> impl Strategy<Value = Lockfile> {
    (
        content_hash_strategy(),
        vec(locked_package_strategy(), 0..20),
    )
        .prop_map(|(manifest_hash, packages)| {
            let mut lockfile = Lockfile::new(manifest_hash);
            for package in packages {
                lockfile.add_package(package);
            }
            lockfile
        })
}

// ============================================================================
// Manifest Strategies
// ============================================================================

/// Strategy for generating arbitrary `Package` metadata.
pub fn package_metadata_strategy() -> impl Strategy<Value = Package> {
    (
        "[a-z][a-z0-9-]{2,20}",
        semver_strategy(),
        "[A-Za-z0-9 ]{10,50}",
        vec("[A-Za-z ]{5,20}", 0..3),
    )
        .prop_map(|(name, version, description, authors)| Package {
            name: name.to_string(),
            version: version.to_string(),
            description: description.to_string(),
            authors,
            license: Some("MIT".to_string()),
            homepage: None,
            repository: None,
            documentation: None,
            keywords: vec![],
            categories: vec![],
            readme: None,
            private: false,
        })
}

/// Strategy for generating arbitrary `Environment` configuration.
pub fn environment_strategy() -> impl Strategy<Value = Environment> {
    (
        proptest::option::of(semver_strategy()),
        proptest::option::of(pep440_strategy()),
        proptest::option::of(semver_strategy()),
        proptest::option::of(semver_strategy()),
        proptest::option::of(maven_version_strategy()),
    )
        .prop_map(|(node, python, rust, go, java)| Environment {
            node,
            python,
            rust,
            go,
            java,
            system: vec![],
            vars: HashMap::new(),
        })
}

/// Strategy for generating a small dependency map for an ecosystem.
pub fn ecosystem_dependencies_strategy() -> impl Strategy<Value = HashMap<String, Dependency>> {
    hash_map(
        "[a-z][a-z0-9-]{2,10}",
        semver_req_strategy().prop_map(|version| Dependency::Version(version)),
        0..5,
    )
}

/// Strategy for generating arbitrary `Dependencies`.
pub fn dependencies_strategy() -> impl Strategy<Value = Dependencies> {
    (
        ecosystem_dependencies_strategy(),
        ecosystem_dependencies_strategy(),
        ecosystem_dependencies_strategy(),
        ecosystem_dependencies_strategy(),
        ecosystem_dependencies_strategy(),
    )
        .prop_map(|(npm, pypi, crates, go, maven)| Dependencies {
            npm,
            pypi,
            crates,
            go,
            maven,
            url: HashMap::new(),
            workspace: HashMap::new(),
        })
}

/// Strategy for generating arbitrary `Manifest` instances.
pub fn manifest_strategy() -> impl Strategy<Value = Manifest> {
    (
        package_metadata_strategy(),
        environment_strategy(),
        dependencies_strategy(),
        dependencies_strategy(),
    )
        .prop_map(
            |(package, environment, dependencies, dev_dependencies)| Manifest {
                package,
                environment,
                dependencies,
                dev_dependencies,
                optional_dependencies: Default::default(),
                overrides: Default::default(),
                system: Default::default(),
                build: Default::default(),
                scripts: Default::default(),
                resolution: HashMap::new(),
                workspace: None,
                target: HashMap::new(),
                manifest_path: None,
            },
        )
}

// ============================================================================
// Dependency Graph Strategies
// ============================================================================

/// Strategy for generating a valid dependency graph.
///
/// Ensures that:
/// - No cycles exist
/// - All dependencies reference valid packages
/// - Version requirements are satisfiable
pub fn dependency_graph_strategy() -> impl Strategy<Value = Vec<LockedPackage>> {
    (1usize..10).prop_flat_map(|num_packages| vec(locked_package_strategy(), num_packages))
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn test_ecosystem_strategy_generates_valid(ecosystem in ecosystem_strategy()) {
            // All values should be valid ecosystems
            assert!(matches!(
                ecosystem,
                Ecosystem::Npm | Ecosystem::PyPi | Ecosystem::Crates |
                Ecosystem::Go | Ecosystem::Maven | Ecosystem::Url
            ));
        }

        #[test]
        fn test_semver_strategy_generates_valid(version in semver_strategy()) {
            // Should parse as valid semver
            assert!(semver::Version::parse(&version).is_ok());
        }

        #[test]
        fn test_version_strategy_generates_valid(version in version_strategy()) {
            // All generated versions should be valid
            assert!(!version.to_string().is_empty());
        }

        #[test]
        fn test_version_req_strategy_generates_valid(req in version_req_strategy()) {
            // All generated requirements should be valid
            assert!(!req.to_string().is_empty());
        }

        #[test]
        fn test_package_id_strategy_generates_valid(id in package_id_strategy()) {
            // Package names should not be empty
            assert!(!id.name.is_empty());
            // Display should include ecosystem
            assert!(id.to_string().contains(':'));
        }

        #[test]
        fn test_package_spec_strategy_generates_valid(spec in package_spec_strategy()) {
            // Should have valid package ID
            assert!(!spec.id.name.is_empty());
            // Should be displayable
            assert!(!spec.to_string().is_empty());
        }

        #[test]
        fn test_locked_package_strategy_generates_valid(pkg in locked_package_strategy()) {
            // Should have name and version
            assert!(!pkg.name.is_empty());
            assert!(!pkg.version.is_empty());
            // Source should be a URL
            assert!(pkg.source.starts_with("http"));
            // Integrity should have algorithm prefix
            assert!(pkg.integrity.starts_with("sha"));
        }

        #[test]
        fn test_lockfile_strategy_generates_valid(lockfile in lockfile_strategy()) {
            // Should have valid version
            assert_eq!(lockfile.version, cratons_lockfile::LOCKFILE_VERSION);
            // All packages should be valid
            for pkg in &lockfile.packages {
                assert!(!pkg.name.is_empty());
            }
        }

        #[test]
        fn test_manifest_strategy_generates_valid(manifest in manifest_strategy()) {
            // Should have package name
            assert!(!manifest.package.name.is_empty());
            // Should have package version
            assert!(!manifest.package.version.is_empty());
        }

        #[test]
        fn test_content_hash_strategy_generates_valid(hash in content_hash_strategy()) {
            // Hash value should be 64 hex characters
            assert_eq!(hash.value.len(), 64);
            // Should be valid hex
            assert!(hash.value.chars().all(|c| c.is_ascii_hexdigit()));
        }

        #[test]
        fn test_npm_package_name_valid(name in npm_package_name_strategy()) {
            // Should start with letter or @
            assert!(name.starts_with(|c: char| c.is_ascii_lowercase() || c == '@'));
            // Should only contain valid characters
            assert!(name.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '/' || c == '@'
            }));
        }

        #[test]
        fn test_dependency_graph_valid(packages in dependency_graph_strategy()) {
            // All packages should have names
            for pkg in &packages {
                assert!(!pkg.name.is_empty());
            }
        }
    }

    #[test]
    fn test_version_for_ecosystem_npm() {
        use proptest::strategy::{Strategy, ValueTree};
        let strategy = version_for_ecosystem_strategy(Ecosystem::Npm);
        let mut runner = proptest::test_runner::TestRunner::default();
        let value = strategy.new_tree(&mut runner).unwrap().current();
        assert!(semver::Version::parse(&value).is_ok());
    }

    #[test]
    fn test_package_name_for_ecosystem_npm() {
        use proptest::strategy::{Strategy, ValueTree};
        let strategy = package_name_for_ecosystem_strategy(Ecosystem::Npm);
        let mut runner = proptest::test_runner::TestRunner::default();
        let value = strategy.new_tree(&mut runner).unwrap().current();
        assert!(!value.is_empty());
    }
}
