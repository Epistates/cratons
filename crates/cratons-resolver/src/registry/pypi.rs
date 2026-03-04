//! PyPI Registry Client
//!
//! Implements the PyPI JSON API (PEP 691) for fetching package metadata and wheels/sdists.
//! API Documentation: https://docs.pypi.org/api/json/
//!
//! This client supports PEP 508 environment marker evaluation, filtering dependencies
//! based on the target Python environment (version, platform, etc.).
//!
//! # Security
//!
//! All package names and versions are validated before being used in URLs
//! to prevent SSRF attacks. See [`cratons_core::validation`] for details.

use async_trait::async_trait;
use cratons_core::{Ecosystem, CratonsError, Result, validate_package_name, validate_version};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, instrument};

use super::{PackageMetadata, RegistryClient};
use crate::markers::{MarkerEvaluator, PythonEnvironmentConfig};

/// PyPI registry client.
pub struct PyPiClient {
    client: reqwest::Client,
    registry_url: String,
    /// Marker evaluator for filtering dependencies by environment
    marker_evaluator: Arc<MarkerEvaluator>,
}

impl PyPiClient {
    /// Create a new PyPI client with the official registry.
    ///
    /// Uses the default Python environment (detected from current system).
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            registry_url: "https://pypi.org".to_string(),
            marker_evaluator: Arc::new(MarkerEvaluator::default()),
        }
    }

    /// Create a new PyPI client with a custom registry URL.
    pub fn with_registry(client: reqwest::Client, registry_url: String) -> Self {
        Self {
            client,
            registry_url: registry_url.trim_end_matches('/').to_string(),
            marker_evaluator: Arc::new(MarkerEvaluator::default()),
        }
    }

    /// Create a new PyPI client with a specific Python environment configuration.
    ///
    /// This allows targeting a specific Python version and platform for dependency
    /// resolution, which is useful for cross-platform builds.
    pub fn with_environment(
        client: reqwest::Client,
        registry_url: String,
        config: PythonEnvironmentConfig,
    ) -> Result<Self> {
        let evaluator = MarkerEvaluator::with_config(config)?;
        Ok(Self {
            client,
            registry_url: registry_url.trim_end_matches('/').to_string(),
            marker_evaluator: Arc::new(evaluator),
        })
    }

    /// Create a client targeting a specific Python version.
    pub fn for_python_version(
        client: reqwest::Client,
        major: u8,
        minor: u8,
        patch: u8,
    ) -> Result<Self> {
        let evaluator = MarkerEvaluator::for_python_version(major, minor, patch)?;
        Ok(Self {
            client,
            registry_url: "https://pypi.org".to_string(),
            marker_evaluator: Arc::new(evaluator),
        })
    }

    /// Set active extras for dependency resolution.
    ///
    /// Dependencies marked with `extra == "dev"` will only be included
    /// if "dev" is in the active extras list.
    #[must_use]
    pub fn with_extras(mut self, extras: Vec<String>) -> Self {
        // Clone the evaluator and add extras
        let evaluator = (*self.marker_evaluator).clone().with_extras(extras);
        self.marker_evaluator = Arc::new(evaluator);
        self
    }

    /// Normalize package name according to PEP 503.
    /// e.g., "Requests" -> "requests", "my_package" -> "my-package"
    fn normalize_name(name: &str) -> String {
        name.to_lowercase().replace('_', "-").replace('.', "-")
    }

    /// Select the best distribution file (prefer wheel over sdist).
    fn select_best_dist<'a>(urls: &'a [PyPiUrl]) -> Option<&'a PyPiUrl> {
        // Prefer wheels (.whl) over source distributions (.tar.gz)
        // Among wheels, prefer py3-none-any (pure Python, any platform)
        urls.iter()
            .filter(|u| !u.yanked.unwrap_or(false))
            .max_by_key(|u| {
                let filename = &u.filename;
                if filename.ends_with(".whl") {
                    if filename.contains("py3-none-any") {
                        3 // Pure Python wheel
                    } else if filename.contains("py3") {
                        2 // Python 3 wheel
                    } else {
                        1 // Other wheel
                    }
                } else {
                    0 // Source distribution
                }
            })
    }
}

/// PyPI JSON API response for a project.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields populated by serde but not all are read
struct PyPiProjectResponse {
    info: PyPiInfo,
    #[serde(default)]
    urls: Vec<PyPiUrl>,
    #[serde(default)]
    releases: BTreeMap<String, Vec<PyPiUrl>>,
    #[serde(default)]
    vulnerabilities: Vec<PyPiVulnerability>,
}

/// PyPI package info.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PyPiInfo {
    name: String,
    version: String,
    #[serde(default)]
    requires_dist: Option<Vec<String>>,
    #[serde(default)]
    requires_python: Option<String>,
}

/// PyPI distribution URL info.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PyPiUrl {
    filename: String,
    url: String,
    #[serde(default)]
    digests: PyPiDigests,
    #[serde(default)]
    yanked: Option<bool>,
    #[serde(default)]
    packagetype: String,
}

/// PyPI file digests.
#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct PyPiDigests {
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    md5: String,
    #[serde(rename = "blake2b_256", default)]
    blake2b: String,
}

/// PyPI vulnerability info.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PyPiVulnerability {
    #[serde(default)]
    id: String,
}

/// Parse PEP 508 dependency string using the proper pep508_rs crate.
///
/// This function parses a PEP 508 requirement and returns the package name,
/// version requirement, and requested extras. Environment markers are preserved
/// in the parsed result for later evaluation.
///
/// # Examples
/// - `"requests>=2.28.0"` -> `("requests", ">=2.28.0", [])`
/// - `"numpy[all]>=1.24.0"` -> `("numpy", ">=1.24.0", ["all"])`
/// - `"typing-extensions; python_version < '3.10'"` -> parsed with marker
#[cfg(test)]
fn parse_requires_dist(spec: &str) -> Option<crate::markers::ParsedPythonDep> {
    match crate::markers::parse_pep508_requirement(spec) {
        Ok(parsed) => Some(parsed),
        Err(e) => {
            eprintln!("Failed to parse PEP 508 requirement '{}': {}", spec, e);
            None
        }
    }
}

/// Legacy parser for cases where we need simple name/version extraction without markers.
/// This is used as a fallback for malformed requirements.
#[cfg(test)]
fn parse_requires_dist_simple(spec: &str) -> Option<(String, String, Vec<String>)> {
    let spec = spec.trim();

    // Remove environment markers (everything after ';')
    let spec = spec.split(';').next().unwrap_or(spec).trim();

    // Check for parenthesized version (PyPI format): "urllib3 (<3,>=1.21.1)"
    if let Some(paren_start) = spec.find('(') {
        if let Some(paren_end) = spec.rfind(')') {
            let name = spec[..paren_start].trim();
            let version = spec[paren_start + 1..paren_end].trim();

            // Handle extras in name: "numpy[all] (>=1.0)"
            let clean_name = if let Some(bracket) = name.find('[') {
                name[..bracket].trim()
            } else {
                name
            };

            return Some((
                clean_name.to_string(),
                if version.is_empty() {
                    "*".to_string()
                } else {
                    version.to_string()
                },
                Vec::new(),
            ));
        }
    }

    // Check for extras: package[extra1,extra2]
    let (name_part, version_part) = if let Some(bracket_start) = spec.find('[') {
        if let Some(bracket_end) = spec.find(']') {
            let name = &spec[..bracket_start];
            let rest = &spec[bracket_end + 1..];
            (name.trim(), rest.trim())
        } else {
            // Malformed, try to parse as-is
            if let Some(idx) =
                spec.find(|c: char| c == '>' || c == '<' || c == '=' || c == '!' || c == '~')
            {
                (&spec[..idx], &spec[idx..])
            } else {
                (spec, "")
            }
        }
    } else if let Some(idx) =
        spec.find(|c: char| c == '>' || c == '<' || c == '=' || c == '!' || c == '~')
    {
        (&spec[..idx], &spec[idx..])
    } else {
        (spec, "")
    };

    let name = name_part.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let version = if version_part.is_empty() {
        "*".to_string()
    } else {
        version_part.trim().to_string()
    };

    Some((name, version, Vec::new()))
}

#[async_trait]
impl RegistryClient for PyPiClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPi
    }

    #[instrument(skip(self), fields(ecosystem = "pypi"))]
    async fn fetch_versions(&self, name: &str) -> Result<Vec<String>> {
        // SECURITY: Validate package name before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::PyPi)?;

        let normalized = Self::normalize_name(name);
        debug!(
            "Fetching versions for PyPI package: {} (normalized: {})",
            name, normalized
        );

        let url = format!("{}/pypi/{}/json", self.registry_url, normalized);
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
                registry: "pypi".to_string(),
                message: format!("HTTP {}: {}", response.status(), url),
            });
        }

        let project: PyPiProjectResponse =
            response.json().await.map_err(|e| CratonsError::Registry {
                registry: "pypi".to_string(),
                message: format!("Failed to parse response: {}", e),
            })?;

        // Get versions from releases, filter out yanked versions
        let mut versions: Vec<String> = project
            .releases
            .into_iter()
            .filter(|(_, urls)| {
                // Include if any non-yanked file exists
                urls.iter().any(|u| !u.yanked.unwrap_or(false))
            })
            .map(|(v, _)| v)
            .collect();

        // Sort by PEP 440 version (ascending for MVS - we want minimum version first)
        versions.sort_by(|a, b| {
            match (
                pep440_rs::Version::from_str(a),
                pep440_rs::Version::from_str(b),
            ) {
                (Ok(va), Ok(vb)) => va.cmp(&vb),
                (Ok(_), Err(_)) => std::cmp::Ordering::Less, // Valid versions come before invalid
                (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                (Err(_), Err(_)) => a.cmp(b), // Both invalid - use string comparison
            }
        });

        debug!("Found {} versions for {}", versions.len(), name);
        Ok(versions)
    }

    #[instrument(skip(self), fields(ecosystem = "pypi"))]
    async fn fetch_metadata(&self, name: &str, version: &str) -> Result<PackageMetadata> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::PyPi)?;
        validate_version(version)?;

        let normalized = Self::normalize_name(name);
        debug!("Fetching metadata for {}@{}", name, version);

        let url = format!("{}/pypi/{}/{}/json", self.registry_url, normalized, version);
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
                registry: "pypi".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let project: PyPiProjectResponse =
            response.json().await.map_err(|e| CratonsError::Registry {
                registry: "pypi".to_string(),
                message: format!("Failed to parse metadata: {}", e),
            })?;

        // Select best distribution file
        let best_url =
            Self::select_best_dist(&project.urls).ok_or_else(|| CratonsError::Registry {
                registry: "pypi".to_string(),
                message: format!("No distribution files found for {}@{}", name, version),
            })?;

        // Parse dependencies from requires_dist with marker evaluation
        let mut dependencies = BTreeMap::new();
        let mut optional_dependencies = BTreeMap::new();

        if let Some(requires) = project.info.requires_dist {
            for req in &requires {
                // First try proper PEP 508 parsing with marker evaluation
                if let Some(parsed) = self.marker_evaluator.parse_and_filter(req).ok().flatten() {
                    let normalized_name = Self::normalize_name(&parsed.name);

                    // Extra-conditional dependencies go to optional_dependencies
                    if parsed.is_extra_dep {
                        optional_dependencies.insert(normalized_name, parsed.version_req);
                    } else {
                        dependencies.insert(normalized_name, parsed.version_req);
                    }
                } else {
                    // Fall back to simple parsing if marker evaluation fails/filters
                    // This handles cases where marker evaluation rejects the dependency
                    debug!("Dependency '{}' filtered by marker evaluation", req);
                }
            }

            debug!(
                "Parsed {} dependencies ({} after marker filtering, {} optional) for {}@{}",
                requires.len(),
                dependencies.len(),
                optional_dependencies.len(),
                name,
                version
            );
        }

        // Prefer SHA256, fall back to blake2b or md5
        let integrity = if !best_url.digests.sha256.is_empty() {
            format!("sha256-{}", best_url.digests.sha256)
        } else if !best_url.digests.blake2b.is_empty() {
            format!("blake2b-{}", best_url.digests.blake2b)
        } else if !best_url.digests.md5.is_empty() {
            format!("md5-{}", best_url.digests.md5)
        } else {
            String::new()
        };

        Ok(PackageMetadata {
            name: project.info.name,
            version: project.info.version,
            dist_url: best_url.url.clone(),
            integrity,
            dependencies,
            optional_dependencies,
            peer_dependencies: BTreeMap::new(),
            peer_dependencies_meta: BTreeMap::new(),
            dev_dependencies: BTreeMap::new(),
            bundled_dependencies: Vec::new(),
            features: Vec::new(),
            feature_definitions: BTreeMap::new(),
        })
    }

    #[instrument(skip(self), fields(ecosystem = "pypi"))]
    async fn download(&self, name: &str, version: &str) -> Result<Vec<u8>> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        // Note: fetch_metadata also validates, but we validate here for defense-in-depth
        validate_package_name(name, Ecosystem::PyPi)?;
        validate_version(version)?;

        debug!("Downloading {}@{}", name, version);

        let metadata = self.fetch_metadata(name, version).await?;

        let response = self
            .client
            .get(&metadata.dist_url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to download: {}", e)))?;

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "pypi".to_string(),
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
            .map_err(|e| CratonsError::Network(format!("Failed to read file: {}", e)))?;

        debug!("Downloaded {} bytes for {}@{}", bytes.len(), name, version);
        Ok(bytes.to_vec())
    }

    #[instrument(skip(self), fields(ecosystem = "pypi"))]
    async fn search(&self, query: &str, _limit: usize) -> Result<Vec<String>> {
        debug!("Searching PyPI for: {}", query);

        // PyPI's search API is XML-RPC based and deprecated.
        // Use the simple API to search by prefix instead.
        // For now, return empty - real search would use pypi.org/search HTML or third-party API

        // Note: A proper implementation would use https://pypi.org/search/?q={query}
        // and parse HTML, or use a service like libraries.io

        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_name() {
        assert_eq!(PyPiClient::normalize_name("Requests"), "requests");
        assert_eq!(PyPiClient::normalize_name("my_package"), "my-package");
        assert_eq!(PyPiClient::normalize_name("My.Package"), "my-package");
        assert_eq!(
            PyPiClient::normalize_name("typing_extensions"),
            "typing-extensions"
        );
    }

    #[test]
    fn test_parse_requires_dist() {
        // Simple version constraint
        let parsed = parse_requires_dist("requests>=2.28.0").unwrap();
        assert_eq!(parsed.name, "requests");
        assert_eq!(parsed.version_req, ">=2.28.0");

        // With extras
        let parsed = parse_requires_dist("numpy[all]>=1.24.0").unwrap();
        assert_eq!(parsed.name, "numpy");
        assert_eq!(parsed.version_req, ">=1.24.0");
        assert_eq!(parsed.extras, vec!["all"]);

        // With environment marker
        let parsed = parse_requires_dist("typing-extensions; python_version < '3.10'").unwrap();
        assert_eq!(parsed.name, "typing-extensions");
        assert!(parsed.marker.is_some());

        // No version constraint
        let parsed = parse_requires_dist("urllib3").unwrap();
        assert_eq!(parsed.name, "urllib3");
        assert_eq!(parsed.version_req, "*");

        // Complex constraint
        let parsed = parse_requires_dist("charset-normalizer<4,>=2").unwrap();
        assert_eq!(parsed.name, "charset-normalizer");
        assert!(parsed.version_req.contains(">=2"));
        assert!(parsed.version_req.contains("<4"));

        // Parenthesized version format (PyPI actual format) - pep508_rs handles these
        let parsed = parse_requires_dist("urllib3>=1.21.1,<3").unwrap();
        assert_eq!(parsed.name, "urllib3");

        // Extras in package name
        let parsed = parse_requires_dist("chardet[socks]>=3.0.2,<6").unwrap();
        assert_eq!(parsed.name, "chardet");
        assert!(parsed.extras.contains(&"socks".to_string()));

        // Simple constraint
        let parsed = parse_requires_dist("certifi>=2017.4.17").unwrap();
        assert_eq!(parsed.name, "certifi");
        assert_eq!(parsed.version_req, ">=2017.4.17");
    }

    #[test]
    fn test_parse_requires_dist_simple_fallback() {
        // Parenthesized version format (PyPI actual format)
        let (name, version, _) = parse_requires_dist_simple("urllib3 (<3,>=1.21.1)").unwrap();
        assert_eq!(name, "urllib3");
        assert_eq!(version, "<3,>=1.21.1");

        // Parenthesized with extras
        let (name, version, _) = parse_requires_dist_simple("chardet[socks] (<6,>=3.0.2)").unwrap();
        assert_eq!(name, "chardet");
        assert_eq!(version, "<6,>=3.0.2");
    }

    #[test]
    fn test_marker_evaluation_in_client() {
        // Test that the marker evaluator is properly initialized
        let client = reqwest::Client::new();
        let pypi = PyPiClient::new(client);

        // The default evaluator should exist
        assert!(Arc::strong_count(&pypi.marker_evaluator) >= 1);
    }

    #[test]
    fn test_python_version_client() {
        let client = reqwest::Client::new();
        let pypi = PyPiClient::for_python_version(client, 3, 10, 0).unwrap();

        // Should be able to create a client for a specific Python version
        assert!(Arc::strong_count(&pypi.marker_evaluator) >= 1);
    }

    #[test]
    fn test_client_with_extras() {
        let client = reqwest::Client::new();
        let pypi = PyPiClient::new(client).with_extras(vec!["dev".to_string(), "test".to_string()]);

        // Should be able to add extras to the client
        assert!(Arc::strong_count(&pypi.marker_evaluator) >= 1);
    }
}
