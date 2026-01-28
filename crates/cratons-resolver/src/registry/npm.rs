//! npm Registry Client
//!
//! Implements the npm registry API for fetching package metadata and tarballs.
//! API Documentation: https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
//!
//! # Security
//!
//! All package names and versions are validated before being used in URLs
//! to prevent SSRF attacks. See [`cratons_core::validation`] for details.

use async_trait::async_trait;
use cratons_core::{Ecosystem, CratonsError, Result, validate_package_name, validate_version, normalize_checksum_format};
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{debug, instrument, warn};

use super::{PackageMetadata, PeerDependencyMeta, RegistryClient};

/// npm registry client.
pub struct NpmClient {
    client: reqwest::Client,
    registry_url: String,
}

impl NpmClient {
    /// Create a new npm client with the official registry.
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            registry_url: "https://registry.npmjs.org".to_string(),
        }
    }

    /// Create a new npm client with a custom registry URL.
    pub fn with_registry(client: reqwest::Client, registry_url: String) -> Self {
        Self {
            client,
            registry_url: registry_url.trim_end_matches('/').to_string(),
        }
    }

    /// Build the package URL, handling scoped packages correctly.
    fn package_url(&self, name: &str) -> String {
        // Scoped packages like @org/pkg need URL encoding: %40org%2Fpkg
        let encoded = if name.starts_with('@') {
            name.replace('/', "%2F")
        } else {
            name.to_string()
        };
        format!("{}/{}", self.registry_url, encoded)
    }

    /// Build the tarball URL for a package version.
    fn tarball_url(&self, name: &str, version: &str) -> String {
        // Tarballs are at: /{name}/-/{basename}-{version}.tgz
        // For scoped packages: /@scope/name/-/name-version.tgz
        let basename = if name.contains('/') {
            name.split('/').last().unwrap_or(name)
        } else {
            name
        };
        format!(
            "{}/{}/-/{}-{}.tgz",
            self.registry_url,
            name.replace('/', "%2F"),
            basename,
            version
        )
    }
}

/// npm package document (packument) - full package metadata
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields populated by serde but not all are read
struct NpmPackument {
    name: String,
    #[serde(default)]
    versions: HashMap<String, NpmVersionMetadata>,
    #[serde(rename = "dist-tags", default)]
    dist_tags: HashMap<String, String>,
    #[serde(default)]
    time: HashMap<String, String>,
}

/// npm version-specific metadata
#[derive(Debug, Deserialize)]
struct NpmVersionMetadata {
    name: String,
    version: String,
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    dev_dependencies: HashMap<String, String>,
    #[serde(rename = "peerDependencies", default)]
    peer_dependencies: HashMap<String, String>,
    /// npm v7+ peerDependenciesMeta - marks which peer deps are optional
    #[serde(rename = "peerDependenciesMeta", default)]
    peer_dependencies_meta: HashMap<String, NpmPeerDepMeta>,
    #[serde(rename = "optionalDependencies", default)]
    optional_dependencies: HashMap<String, String>,
    /// Bundled dependencies - these are included in the tarball
    /// npm supports both spellings: bundledDependencies and bundleDependencies
    #[serde(rename = "bundledDependencies", alias = "bundleDependencies", default)]
    bundled_dependencies: Vec<String>,
    #[serde(default)]
    dist: NpmDist,
}

/// npm peerDependenciesMeta entry
#[derive(Debug, Default, Deserialize)]
struct NpmPeerDepMeta {
    /// Whether this peer dependency is optional (npm v7+)
    #[serde(default)]
    optional: bool,
}

#[derive(Debug, Default, Deserialize)]
struct NpmDist {
    #[serde(default)]
    tarball: String,
    #[serde(default)]
    shasum: String,
    #[serde(default)]
    integrity: String,
}

/// npm search response
#[derive(Debug, Deserialize)]
struct NpmSearchResponse {
    objects: Vec<NpmSearchObject>,
}

#[derive(Debug, Deserialize)]
struct NpmSearchObject {
    package: NpmSearchPackage,
}

#[derive(Debug, Deserialize)]
struct NpmSearchPackage {
    name: String,
}

#[async_trait]
impl RegistryClient for NpmClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    #[instrument(skip(self), fields(ecosystem = "npm"))]
    async fn fetch_versions(&self, name: &str) -> Result<Vec<String>> {
        // SECURITY: Validate package name before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Npm)?;

        debug!("Fetching versions for npm package: {}", name);

        let url = self.package_url(name);
        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to fetch {}: {}", name, e)))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CratonsError::PackageNotFound(name.to_string()));
        }

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "npm".to_string(),
                message: format!("HTTP {}: {}", response.status(), url),
            });
        }

        let packument: NpmPackument =
            response.json().await.map_err(|e| CratonsError::Registry {
                registry: "npm".to_string(),
                message: format!("Failed to parse response for {}: {}", name, e),
            })?;

        // Return versions sorted by semver (ascending for MVS)
        let mut versions: Vec<String> = packument.versions.keys().cloned().collect();
        versions.sort_by(|a, b| {
            let va = node_semver::Version::parse(a);
            let vb = node_semver::Version::parse(b);
            match (va, vb) {
                (Ok(va), Ok(vb)) => va.cmp(&vb),             // Ascending for MVS
                (Ok(_), Err(_)) => std::cmp::Ordering::Less, // Valid versions come before invalid
                (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                (Err(_), Err(_)) => a.cmp(b), // Both invalid - use string comparison
            }
        });

        debug!("Found {} versions for {}", versions.len(), name);
        Ok(versions)
    }

    #[instrument(skip(self), fields(ecosystem = "npm"))]
    async fn fetch_metadata(&self, name: &str, version: &str) -> Result<PackageMetadata> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Npm)?;
        validate_version(version)?;

        debug!("Fetching metadata for {}@{}", name, version);

        // Fetch specific version: /{package}/{version}
        let url = format!("{}/{}", self.package_url(name), version);
        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                CratonsError::Network(format!("Failed to fetch {}@{}: {}", name, version, e))
            })?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CratonsError::VersionNotFound {
                package: name.to_string(),
                version: version.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "npm".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let npm_meta: NpmVersionMetadata =
            response.json().await.map_err(|e| CratonsError::Registry {
                registry: "npm".to_string(),
                message: format!("Failed to parse metadata: {}", e),
            })?;

        // Use integrity if available, fall back to sha1 shasum
        // Normalize to base64 format for consistent verification
        let integrity = if !npm_meta.dist.integrity.is_empty() {
            // npm integrity is usually already sha512-base64, but normalize anyway
            match normalize_checksum_format(&npm_meta.dist.integrity) {
                Ok(normalized) => normalized,
                Err(e) => {
                    warn!("Failed to normalize npm integrity for {}@{}: {}", name, version, e);
                    npm_meta.dist.integrity.clone()
                }
            }
        } else if !npm_meta.dist.shasum.is_empty() {
            // shasum is sha1 in hex format
            match normalize_checksum_format(&format!("sha1-{}", npm_meta.dist.shasum)) {
                Ok(normalized) => normalized,
                Err(e) => {
                    warn!("Failed to normalize npm shasum for {}@{}: {}", name, version, e);
                    format!("sha1-{}", npm_meta.dist.shasum)
                }
            }
        } else {
            String::new()
        };

        // Use tarball URL from metadata, or construct it
        let dist_url = if !npm_meta.dist.tarball.is_empty() {
            npm_meta.dist.tarball.clone()
        } else {
            self.tarball_url(name, version)
        };

        Ok(PackageMetadata {
            name: npm_meta.name,
            version: npm_meta.version,
            dist_url,
            integrity,
            dependencies: npm_meta.dependencies,
            optional_dependencies: npm_meta.optional_dependencies,
            peer_dependencies: npm_meta.peer_dependencies,
            peer_dependencies_meta: npm_meta
                .peer_dependencies_meta
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        PeerDependencyMeta {
                            optional: v.optional,
                        },
                    )
                })
                .collect(),
            dev_dependencies: npm_meta.dev_dependencies,
            bundled_dependencies: npm_meta.bundled_dependencies,
            features: Vec::new(),
            feature_definitions: HashMap::new(),
        })
    }

    #[instrument(skip(self), fields(ecosystem = "npm"))]
    async fn download(&self, name: &str, version: &str) -> Result<Vec<u8>> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        // Note: fetch_metadata also validates, but we validate here for defense-in-depth
        validate_package_name(name, Ecosystem::Npm)?;
        validate_version(version)?;

        debug!("Downloading {}@{}", name, version);

        // First get metadata to find the tarball URL
        let metadata = self.fetch_metadata(name, version).await?;

        let response = self
            .client
            .get(&metadata.dist_url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to download tarball: {}", e)))?;

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "npm".to_string(),
                message: format!(
                    "Failed to download {}: HTTP {}",
                    metadata.dist_url,
                    response.status()
                ),
            });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read tarball: {}", e)))?;

        debug!("Downloaded {} bytes for {}@{}", bytes.len(), name, version);
        Ok(bytes.to_vec())
    }

    #[instrument(skip(self), fields(ecosystem = "npm"))]
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<String>> {
        debug!("Searching npm for: {}", query);

        let url = format!(
            "{}/-/v1/search?text={}&size={}",
            self.registry_url,
            urlencoding::encode(query),
            limit.min(250) // npm max is 250
        );

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Search failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "npm".to_string(),
                message: format!("Search failed: HTTP {}", response.status()),
            });
        }

        let search_response: NpmSearchResponse =
            response.json().await.map_err(|e| CratonsError::Registry {
                registry: "npm".to_string(),
                message: format!("Failed to parse search results: {}", e),
            })?;

        Ok(search_response
            .objects
            .into_iter()
            .map(|o| o.package.name)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_url() {
        let client = NpmClient::new(reqwest::Client::new());

        // Regular package
        assert_eq!(
            client.package_url("lodash"),
            "https://registry.npmjs.org/lodash"
        );

        // Scoped package
        assert_eq!(
            client.package_url("@babel/core"),
            "https://registry.npmjs.org/@babel%2Fcore"
        );
    }

    #[test]
    fn test_tarball_url() {
        let client = NpmClient::new(reqwest::Client::new());

        // Regular package
        assert_eq!(
            client.tarball_url("lodash", "4.17.21"),
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        );

        // Scoped package - basename is just the package name without scope
        assert_eq!(
            client.tarball_url("@babel/core", "7.23.0"),
            "https://registry.npmjs.org/@babel%2Fcore/-/core-7.23.0.tgz"
        );
    }

    /// M-16 FIX: Test peerDependenciesMeta parsing
    #[test]
    fn test_parse_peer_dependencies_meta() {
        // Test that NpmPeerDepMeta deserializes correctly
        let json = r#"{ "optional": true }"#;
        let meta: NpmPeerDepMeta = serde_json::from_str(json).unwrap();
        assert!(meta.optional);

        let json = r#"{ "optional": false }"#;
        let meta: NpmPeerDepMeta = serde_json::from_str(json).unwrap();
        assert!(!meta.optional);

        // Test default value (when optional field is missing)
        let json = r#"{}"#;
        let meta: NpmPeerDepMeta = serde_json::from_str(json).unwrap();
        assert!(!meta.optional);
    }

    /// M-16 FIX: Test full NpmVersionMetadata with peerDependenciesMeta
    #[test]
    fn test_parse_npm_version_metadata_with_peer_meta() {
        let json = r#"{
            "name": "my-plugin",
            "version": "1.0.0",
            "peerDependencies": {
                "react": "^17.0.0",
                "lodash": "^4.0.0"
            },
            "peerDependenciesMeta": {
                "lodash": { "optional": true }
            },
            "dist": {
                "tarball": "https://example.com/my-plugin-1.0.0.tgz",
                "integrity": "sha512-abc123"
            }
        }"#;

        let npm_meta: NpmVersionMetadata = serde_json::from_str(json).unwrap();

        // Check peer dependencies
        assert_eq!(npm_meta.peer_dependencies.len(), 2);
        assert_eq!(npm_meta.peer_dependencies.get("react").unwrap(), "^17.0.0");
        assert_eq!(npm_meta.peer_dependencies.get("lodash").unwrap(), "^4.0.0");

        // Check peerDependenciesMeta
        assert_eq!(npm_meta.peer_dependencies_meta.len(), 1);
        assert!(
            npm_meta
                .peer_dependencies_meta
                .get("lodash")
                .unwrap()
                .optional
        );
        // react is NOT optional (not in peerDependenciesMeta)
        assert!(npm_meta.peer_dependencies_meta.get("react").is_none());
    }

    /// M-16 FIX: Test bundledDependencies parsing with both spellings
    #[test]
    fn test_parse_bundled_dependencies() {
        // Test bundledDependencies (primary spelling)
        let json = r#"{
            "name": "my-package",
            "version": "1.0.0",
            "bundledDependencies": ["internal-util", "custom-lib"],
            "dist": {}
        }"#;

        let npm_meta: NpmVersionMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(npm_meta.bundled_dependencies.len(), 2);
        assert!(
            npm_meta
                .bundled_dependencies
                .contains(&"internal-util".to_string())
        );
        assert!(
            npm_meta
                .bundled_dependencies
                .contains(&"custom-lib".to_string())
        );
    }

    /// M-16 FIX: Test bundleDependencies alias (alternate npm spelling)
    #[test]
    fn test_parse_bundle_dependencies_alias() {
        // Test bundleDependencies (alternate spelling - npm supports both)
        let json = r#"{
            "name": "my-package",
            "version": "1.0.0",
            "bundleDependencies": ["some-dep"],
            "dist": {}
        }"#;

        let npm_meta: NpmVersionMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(npm_meta.bundled_dependencies.len(), 1);
        assert!(
            npm_meta
                .bundled_dependencies
                .contains(&"some-dep".to_string())
        );
    }

    /// M-16 FIX: Test empty/missing fields have correct defaults
    #[test]
    fn test_npm_metadata_defaults() {
        let json = r#"{
            "name": "minimal-package",
            "version": "1.0.0",
            "dist": {}
        }"#;

        let npm_meta: NpmVersionMetadata = serde_json::from_str(json).unwrap();

        // All optional fields should be empty/default
        assert!(npm_meta.dependencies.is_empty());
        assert!(npm_meta.peer_dependencies.is_empty());
        assert!(npm_meta.peer_dependencies_meta.is_empty());
        assert!(npm_meta.optional_dependencies.is_empty());
        assert!(npm_meta.bundled_dependencies.is_empty());
        assert!(npm_meta.dev_dependencies.is_empty());
    }
}
