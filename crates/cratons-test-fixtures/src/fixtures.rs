//! Common test fixtures with sample data for npm, PyPI, crates.io, and more.
//!
//! Provides pre-configured test data including:
//! - Sample package metadata for various ecosystems
//! - Sample lockfiles with different complexity levels
//! - Sample manifests for testing different scenarios
//! - Registry response payloads

use cratons_core::{ContentHash, Ecosystem};
use cratons_lockfile::{DependencyRef, LockedPackage, Lockfile};
use cratons_manifest::Manifest;

/// Sample npm package metadata for lodash.
pub const SAMPLE_NPM_METADATA: &str = r#"{
  "name": "lodash",
  "version": "4.17.21",
  "description": "Lodash modular utilities.",
  "keywords": ["modules", "stdlib", "util"],
  "homepage": "https://lodash.com/",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/lodash/lodash.git"
  },
  "license": "MIT",
  "main": "lodash.js",
  "dist": {
    "shasum": "679591c564c3bffaae8454cf0b3df370c3d6911c",
    "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
  },
  "dependencies": {}
}"#;

/// Sample PyPI package metadata for requests.
pub const SAMPLE_PYPI_METADATA: &str = r#"{
  "info": {
    "author": "Kenneth Reitz",
    "author_email": "me@kennethreitz.org",
    "description": "Python HTTP for Humans.",
    "download_url": "",
    "home_page": "https://requests.readthedocs.io",
    "keywords": "http,client,requests",
    "license": "Apache 2.0",
    "name": "requests",
    "package_url": "https://pypi.org/project/requests/",
    "project_url": "https://pypi.org/project/requests/",
    "project_urls": {
      "Documentation": "https://requests.readthedocs.io",
      "Source": "https://github.com/psf/requests"
    },
    "requires_dist": [
      "charset-normalizer (<4,>=2)",
      "idna (<4,>=2.5)",
      "urllib3 (<3,>=1.21.1)",
      "certifi (>=2017.4.17)"
    ],
    "requires_python": ">=3.7",
    "version": "2.31.0"
  },
  "urls": [
    {
      "filename": "requests-2.31.0-py3-none-any.whl",
      "url": "https://files.pythonhosted.org/packages/70/8e/0e2d847013cb52cd35b38c009bb167a1a26b2ce6cd6965bf26b47bc0bf44/requests-2.31.0-py3-none-any.whl",
      "digests": {
        "sha256": "58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"
      }
    }
  ]
}"#;

/// Sample crates.io package metadata for serde.
pub const SAMPLE_CRATES_METADATA: &str = r#"{
  "crate": {
    "id": "serde",
    "name": "serde",
    "description": "A generic serialization/deserialization framework",
    "homepage": "https://serde.rs",
    "repository": "https://github.com/serde-rs/serde",
    "documentation": "https://docs.rs/serde",
    "max_version": "1.0.195",
    "max_stable_version": "1.0.195",
    "downloads": 524819259,
    "recent_downloads": 72455134,
    "created_at": "2015-05-09T22:05:28.168882+00:00",
    "updated_at": "2024-01-18T19:29:33.715912+00:00"
  },
  "versions": [
    {
      "num": "1.0.195",
      "dl_path": "/api/v1/crates/serde/1.0.195/download",
      "readme_path": "/api/v1/crates/serde/1.0.195/readme",
      "updated_at": "2024-01-18T19:29:33.715912+00:00",
      "created_at": "2024-01-18T19:29:33.715912+00:00",
      "downloads": 5234123,
      "features": {
        "default": ["std"],
        "std": [],
        "derive": ["serde_derive"],
        "alloc": [],
        "rc": []
      },
      "yanked": false,
      "license": "MIT OR Apache-2.0",
      "crate_size": 77175,
      "published_by": null,
      "audit_actions": []
    }
  ]
}"#;

/// Module containing sample manifest fixtures.
pub mod manifests {
    use super::*;

    /// Create a minimal manifest with just a package name.
    #[must_use]
    pub fn minimal() -> Manifest {
        Manifest::from_str(
            r#"
[package]
name = "minimal-app"
version = "0.1.0"
"#,
        )
        .expect("Failed to parse minimal manifest")
    }

    /// Create a simple Node.js application manifest.
    #[must_use]
    pub fn simple_nodejs() -> Manifest {
        Manifest::from_str(
            r#"
[package]
name = "nodejs-app"
version = "1.0.0"
description = "A simple Node.js application"

[environment]
node = "20.10.0"

[dependencies.npm]
lodash = "^4.17.21"
express = "^4.18.2"

[dev-dependencies.npm]
jest = "^29.7.0"
typescript = "^5.3.3"

[scripts]
dev = "node index.js"
test = "jest"
build = "tsc"
"#,
        )
        .expect("Failed to parse simple Node.js manifest")
    }

    /// Create a Python application manifest.
    #[must_use]
    pub fn simple_python() -> Manifest {
        Manifest::from_str(
            r#"
[package]
name = "python-app"
version = "1.0.0"
description = "A simple Python application"

[environment]
python = "3.12.0"

[dependencies.pypi]
requests = ">=2.31.0"
flask = ">=3.0.0"
pydantic = ">=2.5.0"

[dev-dependencies.pypi]
pytest = ">=7.4.0"
black = ">=23.12.0"

[scripts]
dev = "python app.py"
test = "pytest"
format = "black ."
"#,
        )
        .expect("Failed to parse simple Python manifest")
    }

    /// Create a Rust application manifest.
    #[must_use]
    pub fn simple_rust() -> Manifest {
        Manifest::from_str(
            r#"
[package]
name = "rust-app"
version = "0.1.0"
description = "A simple Rust application"

[environment]
rust = "1.75.0"

[dependencies.crates]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }
anyhow = "1.0"

[dev-dependencies.crates]
proptest = "1.4"

[scripts]
dev = "cargo run"
test = "cargo test"
build = "cargo build --release"
"#,
        )
        .expect("Failed to parse simple Rust manifest")
    }

    /// Create a polyglot manifest with multiple ecosystems.
    #[must_use]
    pub fn polyglot() -> Manifest {
        Manifest::from_str(
            r#"
[package]
name = "polyglot-app"
version = "1.0.0"
description = "An application using multiple ecosystems"

[environment]
node = "20.10.0"
python = "3.12.0"
rust = "1.75.0"

[dependencies.npm]
lodash = "^4.17.21"

[dependencies.pypi]
requests = ">=2.31.0"

[dependencies.crates]
serde = "1.0"

[scripts]
build-all = "npm run build && python setup.py build && cargo build"
"#,
        )
        .expect("Failed to parse polyglot manifest")
    }

    /// Create a workspace root manifest.
    #[must_use]
    pub fn workspace_root() -> Manifest {
        Manifest::from_str(
            r#"
[workspace]
members = ["packages/*", "apps/*"]

[workspace.environment]
node = "20.10.0"
rust = "1.75.0"

[workspace.dependencies.npm]
lodash = "^4.17.21"

[workspace.dependencies.crates]
serde = "1.0"
"#,
        )
        .expect("Failed to parse workspace root manifest")
    }

    /// Create a manifest with build configuration.
    #[must_use]
    pub fn with_build() -> Manifest {
        Manifest::from_str(
            r#"
[package]
name = "build-app"
version = "1.0.0"

[environment]
node = "20.10.0"

[dependencies.npm]
typescript = "^5.3.0"

[build]
script = "npm run build"
outputs = ["dist/", "build/"]
timeout = 300

[build.dependencies.npm]
esbuild = "^0.19.0"
"#,
        )
        .expect("Failed to parse manifest with build config")
    }
}

/// Module containing sample lockfile fixtures.
pub mod lockfiles {
    use super::*;

    /// Create an empty lockfile.
    #[must_use]
    pub fn empty() -> Lockfile {
        Lockfile::new(ContentHash::blake3("empty".to_string()))
    }

    /// Create a simple lockfile with a few npm packages.
    #[must_use]
    pub fn simple_npm() -> Lockfile {
        let mut lockfile = Lockfile::new(ContentHash::blake3("simple-npm".to_string()));

        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string(),
            integrity: "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==".to_string(),
            resolved_hash: ContentHash::blake3("lodash-4.17.21".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        lockfile.add_package(LockedPackage {
            name: "express".to_string(),
            version: "4.18.2".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/express/-/express-4.18.2.tgz".to_string(),
            integrity: "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ==".to_string(),
            resolved_hash: ContentHash::blake3("express-4.18.2".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![
                DependencyRef::new("accepts", "1.3.8"),
                DependencyRef::new("body-parser", "1.20.1"),
                DependencyRef::new("cookie", "0.5.0"),
            ],
        });

        lockfile
    }

    /// Create a lockfile with PyPI packages.
    #[must_use]
    pub fn simple_pypi() -> Lockfile {
        let mut lockfile = Lockfile::new(ContentHash::blake3("simple-pypi".to_string()));

        lockfile.add_package(LockedPackage {
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            ecosystem: Ecosystem::PyPi,
            source: "https://files.pythonhosted.org/packages/70/8e/0e2d847013cb52cd35b38c009bb167a1a26b2ce6cd6965bf26b47bc0bf44/requests-2.31.0-py3-none-any.whl".to_string(),
            integrity: "sha256-58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f".to_string(),
            resolved_hash: ContentHash::blake3("requests-2.31.0".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![
                DependencyRef::new("charset-normalizer", "3.3.2"),
                DependencyRef::new("idna", "3.6"),
                DependencyRef::new("urllib3", "2.1.0"),
                DependencyRef::new("certifi", "2023.11.17"),
            ],
        });

        lockfile
    }

    /// Create a lockfile with Rust crates.
    #[must_use]
    pub fn simple_crates() -> Lockfile {
        let mut lockfile = Lockfile::new(ContentHash::blake3("simple-crates".to_string()));

        lockfile.add_package(LockedPackage {
            name: "serde".to_string(),
            version: "1.0.195".to_string(),
            ecosystem: Ecosystem::Crates,
            source: "https://crates.io/api/v1/crates/serde/1.0.195/download".to_string(),
            integrity: "sha256-bf1de9e01c5a7c9e0e5a5d4a5e8e5c1f2f3f4f5f6f7f8f9f0f1f2f3f4f5f6f7"
                .to_string(),
            resolved_hash: ContentHash::blake3("serde-1.0.195".to_string()),
            direct: true,
            features: vec!["derive".to_string(), "std".to_string()],
            dependencies: vec![DependencyRef::new("serde_derive", "1.0.195")],
        });

        lockfile
    }

    /// Create a complex lockfile with many packages and deep dependencies.
    #[must_use]
    pub fn complex() -> Lockfile {
        let mut lockfile = Lockfile::new(ContentHash::blake3("complex".to_string()));

        // Root dependencies
        lockfile.add_package(LockedPackage {
            name: "express".to_string(),
            version: "4.18.2".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/express/-/express-4.18.2.tgz".to_string(),
            integrity: "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ==".to_string(),
            resolved_hash: ContentHash::blake3("express-4.18.2".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![
                DependencyRef::new("accepts", "1.3.8"),
                DependencyRef::new("body-parser", "1.20.1"),
                DependencyRef::new("cookie", "0.5.0"),
                DependencyRef::new("debug", "2.6.9"),
            ],
        });

        // Transitive dependencies
        lockfile.add_package(LockedPackage {
            name: "accepts".to_string(),
            version: "1.3.8".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz".to_string(),
            integrity: "sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw+NACSaeXEQ+NHcVF7rONl6qcaxV3Uuemwawk+7+SJLw==".to_string(),
            resolved_hash: ContentHash::blake3("accepts-1.3.8".to_string()),
            direct: false,
            features: vec![],
            dependencies: vec![
                DependencyRef::new("mime-types", "2.1.35"),
                DependencyRef::new("negotiator", "0.6.3"),
            ],
        });

        lockfile.add_package(LockedPackage {
            name: "body-parser".to_string(),
            version: "1.20.1".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/body-parser/-/body-parser-1.20.1.tgz".to_string(),
            integrity: "sha512-jWi7abTbYwajOytWCQc37VulmWiRae5RyTpaCyDcS5/lMdtwSz5lOpDE67srw/HYe35f1z3fDQw+3txg7gNtWw==".to_string(),
            resolved_hash: ContentHash::blake3("body-parser-1.20.1".to_string()),
            direct: false,
            features: vec![],
            dependencies: vec![
                DependencyRef::new("bytes", "3.1.2"),
                DependencyRef::new("content-type", "1.0.5"),
                DependencyRef::new("debug", "2.6.9"),
            ],
        });

        lockfile
    }

    /// Create a lockfile with packages from multiple ecosystems.
    #[must_use]
    pub fn polyglot() -> Lockfile {
        let mut lockfile = Lockfile::new(ContentHash::blake3("polyglot".to_string()));

        // npm
        lockfile.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string(),
            integrity: "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==".to_string(),
            resolved_hash: ContentHash::blake3("lodash-4.17.21".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // PyPI
        lockfile.add_package(LockedPackage {
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            ecosystem: Ecosystem::PyPi,
            source: "https://files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl"
                .to_string(),
            integrity: "sha256-58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"
                .to_string(),
            resolved_hash: ContentHash::blake3("requests-2.31.0".to_string()),
            direct: true,
            features: vec![],
            dependencies: vec![],
        });

        // crates.io
        lockfile.add_package(LockedPackage {
            name: "serde".to_string(),
            version: "1.0.195".to_string(),
            ecosystem: Ecosystem::Crates,
            source: "https://crates.io/api/v1/crates/serde/1.0.195/download".to_string(),
            integrity: "sha256-bf1de9e01c5a7c9e0e5a5d4a5e8e5c1f2f3f4f5f6f7f8f9f0f1f2f3f4f5f6f7"
                .to_string(),
            resolved_hash: ContentHash::blake3("serde-1.0.195".to_string()),
            direct: true,
            features: vec!["derive".to_string()],
            dependencies: vec![],
        });

        lockfile
    }
}

/// Module containing sample package metadata.
pub mod packages {
    use super::*;
    use cratons_core::{PackageId, PackageSpec};

    /// Create a sample npm package ID.
    #[must_use]
    pub fn npm_lodash_id() -> PackageId {
        PackageId::new(Ecosystem::Npm, "lodash")
    }

    /// Create a sample npm scoped package ID.
    #[must_use]
    pub fn npm_scoped_id() -> PackageId {
        PackageId::new(Ecosystem::Npm, "@types/node")
    }

    /// Create a sample PyPI package ID.
    #[must_use]
    pub fn pypi_requests_id() -> PackageId {
        PackageId::new(Ecosystem::PyPi, "requests")
    }

    /// Create a sample crates.io package ID.
    #[must_use]
    pub fn crates_serde_id() -> PackageId {
        PackageId::new(Ecosystem::Crates, "serde")
    }

    /// Create a sample npm package spec.
    pub fn npm_lodash_spec() -> PackageSpec {
        PackageSpec::from_parts(Ecosystem::Npm, "lodash", "^4.17.0")
            .expect("Failed to create lodash spec")
    }

    /// Create a sample PyPI package spec.
    pub fn pypi_requests_spec() -> PackageSpec {
        PackageSpec::from_parts(Ecosystem::PyPi, "requests", ">=2.31.0")
            .expect("Failed to create requests spec")
    }

    /// Create a sample crates.io package spec.
    pub fn crates_serde_spec() -> PackageSpec {
        PackageSpec::from_parts(Ecosystem::Crates, "serde", "1.0")
            .expect("Failed to create serde spec")
    }
}

/// Module containing sample registry HTTP responses for WireMock.
pub mod registry_responses {
    use serde_json::{Value, json};

    /// Create an npm package metadata response.
    #[must_use]
    pub fn npm_package_metadata(name: &str, version: &str) -> Value {
        json!({
            "name": name,
            "version": version,
            "description": format!("Test package {name}"),
            "license": "MIT",
            "dist": {
                "tarball": format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
                "integrity": "sha512-test123456789",
                "shasum": "abcdef1234567890"
            },
            "dependencies": {}
        })
    }

    /// Create an npm package versions list response.
    #[must_use]
    pub fn npm_package_versions(name: &str, versions: &[&str]) -> Value {
        let versions_map: serde_json::Map<String, Value> = versions
            .iter()
            .map(|v| ((*v).to_string(), npm_package_metadata(name, v)))
            .collect();

        json!({
            "name": name,
            "versions": versions_map,
            "dist-tags": {
                "latest": versions.last().unwrap_or(&"1.0.0")
            }
        })
    }

    /// Create a PyPI package metadata response.
    #[must_use]
    pub fn pypi_package_metadata(name: &str, version: &str) -> Value {
        json!({
            "info": {
                "name": name,
                "version": version,
                "summary": format!("Test package {name}"),
                "license": "MIT",
                "requires_python": ">=3.7"
            },
            "urls": [{
                "filename": format!("{name}-{version}-py3-none-any.whl"),
                "url": format!("https://files.pythonhosted.org/packages/{name}-{version}.whl"),
                "digests": {
                    "sha256": "test123456789"
                }
            }],
            "releases": {
                version: []
            }
        })
    }

    /// Create a crates.io crate metadata response.
    #[must_use]
    pub fn crates_metadata(name: &str, version: &str) -> Value {
        json!({
            "crate": {
                "id": name,
                "name": name,
                "description": format!("Test crate {name}"),
                "max_version": version,
                "max_stable_version": version
            },
            "versions": [{
                "num": version,
                "dl_path": format!("/api/v1/crates/{name}/{version}/download"),
                "yanked": false,
                "license": "MIT OR Apache-2.0",
                "features": {
                    "default": ["std"],
                    "std": []
                }
            }]
        })
    }

    /// Create a 404 not found response.
    #[must_use]
    pub fn not_found(message: &str) -> Value {
        json!({
            "error": "Not Found",
            "message": message
        })
    }

    /// Create a rate limit error response.
    #[must_use]
    pub fn rate_limit_error() -> Value {
        json!({
            "error": "Rate Limit Exceeded",
            "message": "Too many requests. Please try again later.",
            "retry_after": 60
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_metadata_parses() {
        let npm: serde_json::Value =
            serde_json::from_str(SAMPLE_NPM_METADATA).expect("Failed to parse npm metadata");
        assert_eq!(npm["name"], "lodash");

        let pypi: serde_json::Value =
            serde_json::from_str(SAMPLE_PYPI_METADATA).expect("Failed to parse pypi metadata");
        assert_eq!(pypi["info"]["name"], "requests");

        let crates: serde_json::Value =
            serde_json::from_str(SAMPLE_CRATES_METADATA).expect("Failed to parse crates metadata");
        assert_eq!(crates["crate"]["name"], "serde");
    }

    #[test]
    fn test_manifest_fixtures() {
        let minimal = manifests::minimal();
        assert_eq!(minimal.package.name, "minimal-app");

        let nodejs = manifests::simple_nodejs();
        assert_eq!(nodejs.package.name, "nodejs-app");
        assert!(!nodejs.dependencies.npm.is_empty());

        let python = manifests::simple_python();
        assert_eq!(python.package.name, "python-app");
        assert!(!python.dependencies.pypi.is_empty());

        let rust = manifests::simple_rust();
        assert_eq!(rust.package.name, "rust-app");
        assert!(!rust.dependencies.crates.is_empty());

        let polyglot = manifests::polyglot();
        assert!(!polyglot.dependencies.npm.is_empty());
        assert!(!polyglot.dependencies.pypi.is_empty());
        assert!(!polyglot.dependencies.crates.is_empty());
    }

    #[test]
    fn test_lockfile_fixtures() {
        let empty = lockfiles::empty();
        assert_eq!(empty.packages.len(), 0);

        let npm = lockfiles::simple_npm();
        assert!(npm.packages.len() > 0);
        assert!(npm.packages.iter().all(|p| p.ecosystem == Ecosystem::Npm));

        let pypi = lockfiles::simple_pypi();
        assert!(pypi.packages.len() > 0);
        assert!(pypi.packages.iter().all(|p| p.ecosystem == Ecosystem::PyPi));

        let crates = lockfiles::simple_crates();
        assert!(crates.packages.len() > 0);
        assert!(
            crates
                .packages
                .iter()
                .all(|p| p.ecosystem == Ecosystem::Crates)
        );

        let complex = lockfiles::complex();
        assert!(complex.packages.len() > 2);
        let direct_count = complex.packages.iter().filter(|p| p.direct).count();
        let transitive_count = complex.packages.iter().filter(|p| !p.direct).count();
        assert!(direct_count > 0);
        assert!(transitive_count > 0);

        let polyglot = lockfiles::polyglot();
        assert!(
            polyglot
                .packages
                .iter()
                .any(|p| p.ecosystem == Ecosystem::Npm)
        );
        assert!(
            polyglot
                .packages
                .iter()
                .any(|p| p.ecosystem == Ecosystem::PyPi)
        );
        assert!(
            polyglot
                .packages
                .iter()
                .any(|p| p.ecosystem == Ecosystem::Crates)
        );
    }

    #[test]
    fn test_registry_responses() {
        let npm = registry_responses::npm_package_metadata("test", "1.0.0");
        assert_eq!(npm["name"], "test");
        assert_eq!(npm["version"], "1.0.0");

        let versions = registry_responses::npm_package_versions("test", &["1.0.0", "1.1.0"]);
        assert!(versions["versions"].is_object());

        let pypi = registry_responses::pypi_package_metadata("test", "1.0.0");
        assert_eq!(pypi["info"]["name"], "test");

        let crates = registry_responses::crates_metadata("test", "1.0.0");
        assert_eq!(crates["crate"]["name"], "test");
    }
}
