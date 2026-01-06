//! # cratons-benchmarks
//!
//! Benchmark suite for the Cratons package manager.
//!
//! This crate provides comprehensive benchmarks for:
//! - Dependency resolution (MVS algorithm)
//! - Content-addressed storage operations
//! - Manifest parsing and serialization
//! - Lockfile operations
//!
//! Run with: `cargo bench`

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use cratons_core::{ContentHash, Ecosystem};
use cratons_lockfile::{DependencyRef, LockedPackage};
use cratons_manifest::{Dependencies, Dependency, Manifest, Package};
use rand::Rng;
use std::collections::HashMap;

/// Generate a small dependency tree (10 packages).
pub fn generate_small_manifest() -> Manifest {
    generate_manifest_with_deps(10)
}

/// Generate a medium dependency tree (100 packages).
pub fn generate_medium_manifest() -> Manifest {
    generate_manifest_with_deps(100)
}

/// Generate a large dependency tree (1000 packages).
pub fn generate_large_manifest() -> Manifest {
    generate_manifest_with_deps(1000)
}

/// Generate a manifest with a specified number of dependencies.
pub fn generate_manifest_with_deps(count: usize) -> Manifest {
    let mut manifest = Manifest::default();
    manifest.package = Package {
        name: "benchmark-test".to_string(),
        version: "1.0.0".to_string(),
        description: format!("Test manifest with {} dependencies", count),
        ..Default::default()
    };

    let mut deps = Dependencies::default();

    // Distribute dependencies across ecosystems
    let ecosystem_count = Ecosystem::all().len();
    let per_ecosystem = count / ecosystem_count;
    let remainder = count % ecosystem_count;

    for (idx, ecosystem) in Ecosystem::all().iter().enumerate() {
        let mut extra = 0;
        if idx < remainder {
            extra = 1;
        }
        let ecosystem_deps = per_ecosystem + extra;

        for i in 0..ecosystem_deps {
            let name = format!("package-{}-{}", ecosystem, i);
            let version = format!("^{}.0.0", (i % 10) + 1);

            let dep = Dependency::Version(version);

            match ecosystem {
                Ecosystem::Npm => {
                    deps.npm.insert(name, dep);
                }
                Ecosystem::PyPi => {
                    deps.pypi.insert(name, dep);
                }
                Ecosystem::Crates => {
                    deps.crates.insert(name, dep);
                }
                Ecosystem::Go => {
                    deps.go.insert(name, dep);
                }
                Ecosystem::Maven => {
                    deps.maven.insert(name, dep);
                }
                Ecosystem::Url => {
                    deps.url.insert(name, dep);
                }
            }
        }
    }

    manifest.dependencies = deps;
    manifest
}

/// Generate a complex manifest with various dependency types.
pub fn generate_complex_manifest() -> Manifest {
    let mut manifest = Manifest::default();
    manifest.package = Package {
        name: "complex-benchmark".to_string(),
        version: "2.5.3".to_string(),
        description: "Complex manifest with various dependency types".to_string(),
        ..Default::default()
    };

    let mut deps = Dependencies::default();

    // Add npm dependencies with different version requirements
    deps.npm.insert(
        "lodash".to_string(),
        Dependency::Version("^4.17.0".to_string()),
    );
    deps.npm.insert(
        "express".to_string(),
        Dependency::Version("~4.18.0".to_string()),
    );
    deps.npm.insert(
        "react".to_string(),
        Dependency::Version(">=18.0.0 <19.0.0".to_string()),
    );

    // Add Python dependencies
    deps.pypi.insert(
        "requests".to_string(),
        Dependency::Version(">=2.28.0".to_string()),
    );
    deps.pypi.insert(
        "numpy".to_string(),
        Dependency::Version("^1.24.0".to_string()),
    );

    // Add Rust dependencies with features
    use cratons_manifest::dependency::DetailedDependency;
    deps.crates.insert(
        "serde".to_string(),
        Dependency::Detailed(DetailedDependency {
            version: Some("^1.0".to_string()),
            features: vec!["derive".to_string()],
            optional: false,
            default_features: true,
            ..Default::default()
        }),
    );

    // Add Git source dependency
    deps.npm.insert(
        "custom-pkg".to_string(),
        Dependency::Detailed(DetailedDependency {
            git: Some("https://github.com/example/custom-pkg.git".to_string()),
            rev: Some("abc123".to_string()),
            ..Default::default()
        }),
    );

    manifest.dependencies = deps;
    manifest
}

/// Generate a lockfile with specified number of packages.
pub fn generate_lockfile(package_count: usize) -> cratons_lockfile::Lockfile {
    let manifest_hash = ContentHash::blake3(format!("manifest-{}", package_count));
    let mut lockfile = cratons_lockfile::Lockfile::new(manifest_hash);

    for i in 0..package_count {
        let ecosystem = Ecosystem::all()[i % 5];
        let name = format!("package-{}-{}", ecosystem, i);
        let version = format!("{}.{}.{}", i / 100, (i / 10) % 10, i % 10);

        lockfile.add_package(LockedPackage {
            name: name.clone(),
            version: version.clone(),
            ecosystem,
            source: format!("https://registry.example.com/{}/{}", name, version),
            integrity: format!("sha256-{:064x}", i),
            resolved_hash: ContentHash::blake3(format!("{}-{}", name, version)),
            direct: i < 20, // First 20 are direct dependencies
            features: if i % 3 == 0 {
                vec![format!("feature-{}", i % 5)]
            } else {
                vec![]
            },
            dependencies: generate_package_deps(i, package_count),
        });
    }

    lockfile
}

/// Generate dependencies for a package in lockfile.
fn generate_package_deps(pkg_idx: usize, total_pkgs: usize) -> Vec<DependencyRef> {
    let mut deps = Vec::new();
    let dep_count = (pkg_idx % 5) + 1; // 1-5 dependencies per package

    for j in 1..=dep_count {
        let dep_idx = (pkg_idx + j * 7) % total_pkgs; // Pseudo-random dependency
        if dep_idx != pkg_idx {
            let ecosystem = Ecosystem::all()[dep_idx % 5];
            let name = format!("package-{}-{}", ecosystem, dep_idx);
            let version = format!("{}.{}.{}", dep_idx / 100, (dep_idx / 10) % 10, dep_idx % 10);
            deps.push(DependencyRef::new(name, version));
        }
    }

    deps
}

/// Generate random binary content for CAS benchmarks.
pub fn generate_random_content(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.r#gen()).collect()
}

/// Generate file contents of various realistic sizes.
pub struct FileSizes;

impl FileSizes {
    /// Tiny file: 1 KB
    pub const TINY: usize = 1024;

    /// Small file: 10 KB
    pub const SMALL: usize = 10 * 1024;

    /// Medium file: 100 KB
    pub const MEDIUM: usize = 100 * 1024;

    /// Large file: 1 MB
    pub const LARGE: usize = 1024 * 1024;

    /// Extra large file: 10 MB
    pub const XLARGE: usize = 10 * 1024 * 1024;
}

/// Generate a realistic package manifest TOML string.
pub fn generate_manifest_toml(dep_count: usize) -> String {
    let mut toml = String::new();
    toml.push_str("[package]\n");
    toml.push_str("name = \"benchmark-package\"\n");
    toml.push_str("version = \"1.0.0\"\n");
    toml.push_str("description = \"A benchmark test package\"\n\n");

    toml.push_str("[dependencies]\n");
    for i in 0..dep_count {
        toml.push_str(&format!("package-{} = \"^{}.0.0\"\n", i, (i % 10) + 1));
    }

    toml
}

/// Generate a realistic lockfile TOML string.
pub fn generate_lockfile_toml(package_count: usize) -> String {
    let lockfile = generate_lockfile(package_count);
    lockfile.to_toml_string().unwrap()
}

/// Create a benchmark-friendly version map for resolver tests.
pub fn create_version_map(_package_name: &str, version_count: usize) -> Vec<String> {
    (0..version_count)
        .map(|i| format!("{}.{}.{}", i / 10, i % 10, 0))
        .collect()
}

/// Generate package metadata for resolver benchmarks.
pub fn generate_package_metadata(
    _name: String,
    _version: String,
    dep_count: usize,
) -> HashMap<String, String> {
    let mut deps = HashMap::new();
    for i in 0..dep_count {
        deps.insert(format!("dep-{}", i), format!("^{}.0.0", (i % 5) + 1));
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_small_manifest() {
        let manifest = generate_small_manifest();
        assert_eq!(manifest.dependencies.len(), 10);
    }

    #[test]
    fn test_generate_medium_manifest() {
        let manifest = generate_medium_manifest();
        assert_eq!(manifest.dependencies.len(), 100);
    }

    #[test]
    fn test_generate_large_manifest() {
        let manifest = generate_large_manifest();
        assert_eq!(manifest.dependencies.len(), 1000);
    }

    #[test]
    fn test_generate_lockfile() {
        let lockfile = generate_lockfile(50);
        assert_eq!(lockfile.package_count(), 50);
    }

    #[test]
    fn test_generate_random_content() {
        let content = generate_random_content(1024);
        assert_eq!(content.len(), 1024);
    }

    #[test]
    fn test_manifest_toml_generation() {
        let toml = generate_manifest_toml(5);
        assert!(toml.contains("[package]"));
        assert!(toml.contains("[dependencies]"));
        assert!(toml.contains("package-0"));
    }

    #[test]
    fn test_version_map() {
        let versions = create_version_map("test-pkg", 20);
        assert_eq!(versions.len(), 20);
        assert_eq!(versions[0], "0.0.0");
        assert_eq!(versions[10], "1.0.0");
    }
}
