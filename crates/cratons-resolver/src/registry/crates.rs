//! crates.io Registry Client
//!
//! Implements the crates.io sparse index protocol for fetching crate metadata.
//! Index Documentation: https://doc.rust-lang.org/cargo/reference/registry-index.html
//!
//! # Security
//!
//! All crate names and versions are validated before being used in URLs
//! to prevent SSRF attacks. See [`cratons_core::validation`] for details.

use async_trait::async_trait;
use cratons_core::{Ecosystem, CratonsError, Result, validate_package_name, validate_version};
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{debug, instrument};

use super::{PackageMetadata, RegistryClient};

/// crates.io registry client using the sparse index.
pub struct CratesIoClient {
    client: reqwest::Client,
    index_url: String,
    download_url: String,
    api_url: String,
}

impl CratesIoClient {
    /// Create a new crates.io client with the official registry.
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            index_url: "https://index.crates.io".to_string(),
            download_url: "https://static.crates.io/crates".to_string(),
            api_url: "https://crates.io/api/v1".to_string(),
        }
    }

    /// Create a new client with custom URLs.
    pub fn with_urls(
        client: reqwest::Client,
        index_url: String,
        download_url: String,
        api_url: String,
    ) -> Self {
        Self {
            client,
            index_url: index_url.trim_end_matches('/').to_string(),
            download_url: download_url.trim_end_matches('/').to_string(),
            api_url: api_url.trim_end_matches('/').to_string(),
        }
    }

    /// Calculate the index path for a crate name.
    /// - 1-char names: 1/{name}
    /// - 2-char names: 2/{name}
    /// - 3-char names: 3/{first-char}/{name}
    /// - 4+ char names: {first-two}/{second-two}/{name}
    fn index_path(name: &str) -> String {
        let name_lower = name.to_lowercase();
        match name_lower.len() {
            1 => format!("1/{}", name_lower),
            2 => format!("2/{}", name_lower),
            3 => format!("3/{}/{}", &name_lower[..1], name_lower),
            _ => format!("{}/{}/{}", &name_lower[..2], &name_lower[2..4], name_lower),
        }
    }

    /// Build the download URL for a crate version.
    fn crate_download_url(&self, name: &str, version: &str) -> String {
        format!(
            "{}/{}/{}-{}.crate",
            self.download_url,
            name.to_lowercase(),
            name.to_lowercase(),
            version
        )
    }
}

/// A line from the sparse index file (one per version).
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields populated by serde but not all are read
struct IndexLine {
    name: String,
    #[serde(rename = "vers")]
    version: String,
    #[serde(default)]
    deps: Vec<IndexDep>,
    #[serde(rename = "cksum")]
    checksum: String,
    #[serde(default)]
    features: HashMap<String, Vec<String>>,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    links: Option<String>,
    #[serde(rename = "v", default)]
    format_version: Option<u32>,
    #[serde(default)]
    features2: HashMap<String, Vec<String>>,
    #[serde(default)]
    rust_version: Option<String>,
}

/// Dependency info from the index.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields populated by serde but not all are read
struct IndexDep {
    name: String,
    #[serde(rename = "req")]
    version_req: String,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    optional: bool,
    #[serde(default = "default_true")]
    default_features: bool,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    registry: Option<String>,
    #[serde(default)]
    package: Option<String>,
}

fn default_true() -> bool {
    true
}

/// API response for crate metadata (reserved for future use).
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Reserved for API fallback
struct ApiCrateResponse {
    #[serde(rename = "crate")]
    krate: ApiCrate,
    versions: Vec<ApiVersion>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ApiCrate {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ApiVersion {
    num: String,
    yanked: bool,
    checksum: String,
}

#[async_trait]
impl RegistryClient for CratesIoClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Crates
    }

    #[instrument(skip(self), fields(ecosystem = "crates"))]
    async fn fetch_versions(&self, name: &str) -> Result<Vec<String>> {
        // SECURITY: Validate crate name before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Crates)?;

        debug!("Fetching versions for crate: {}", name);

        let path = Self::index_path(name);
        let url = format!("{}/{}", self.index_url, path);

        let response = self
            .client
            .get(&url)
            .header("Accept", "text/plain")
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to fetch {}: {}", name, e)))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CratonsError::PackageNotFound(name.to_string()));
        }

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "crates.io".to_string(),
                message: format!("HTTP {}: {}", response.status(), url),
            });
        }

        let text = response
            .text()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read response: {}", e)))?;

        // Parse newline-delimited JSON
        let mut versions: Vec<String> = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<IndexLine>(line) {
                Ok(index_line) => {
                    if !index_line.yanked {
                        versions.push(index_line.version);
                    }
                }
                Err(e) => {
                    debug!("Failed to parse index line: {}", e);
                }
            }
        }

        // Sort by semver (ascending for MVS)
        versions.sort_by(|a, b| {
            match (semver::Version::parse(a), semver::Version::parse(b)) {
                (Ok(va), Ok(vb)) => va.cmp(&vb), // Ascending for MVS
                (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                (Err(_), Err(_)) => a.cmp(b),
            }
        });

        debug!("Found {} versions for {}", versions.len(), name);
        Ok(versions)
    }

    #[instrument(skip(self), fields(ecosystem = "crates"))]
    async fn fetch_metadata(&self, name: &str, version: &str) -> Result<PackageMetadata> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Crates)?;
        validate_version(version)?;

        debug!("Fetching metadata for {}@{}", name, version);

        let path = Self::index_path(name);
        let url = format!("{}/{}", self.index_url, path);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to fetch {}: {}", name, e)))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CratonsError::PackageNotFound(name.to_string()));
        }

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "crates.io".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let text = response
            .text()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read response: {}", e)))?;

        // Find the matching version line
        let mut found_version: Option<IndexLine> = None;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(index_line) = serde_json::from_str::<IndexLine>(line) {
                if index_line.version == version {
                    found_version = Some(index_line);
                    break;
                }
            }
        }

        let index_line = found_version.ok_or_else(|| CratonsError::VersionNotFound {
            package: name.to_string(),
            version: version.to_string(),
        })?;

        // Convert dependencies
        let mut dependencies = HashMap::new();
        let mut dev_dependencies = HashMap::new();
        let mut optional_dependencies = HashMap::new();

        for dep in &index_line.deps {
            // Use the actual package name if renamed
            let dep_name = dep.package.as_ref().unwrap_or(&dep.name).clone();
            let version_req = dep.version_req.clone();

            match dep.kind.as_deref() {
                Some("dev") => {
                    dev_dependencies.insert(dep_name, version_req);
                }
                Some("build") => {
                    // Build dependencies - treat as regular for now
                    dependencies.insert(dep_name, version_req);
                }
                _ => {
                    if dep.optional {
                        optional_dependencies.insert(dep_name, version_req);
                    } else {
                        dependencies.insert(dep_name, version_req);
                    }
                }
            }
        }

        // Merge features and features2
        let mut all_features: Vec<String> = index_line.features.keys().cloned().collect();
        all_features.extend(index_line.features2.keys().cloned());
        all_features.sort();
        all_features.dedup();

        // Merge feature definitions from features and features2
        let mut feature_definitions = index_line.features.clone();
        for (k, v) in index_line.features2 {
            feature_definitions.entry(k).or_insert(v);
        }

        Ok(PackageMetadata {
            name: index_line.name,
            version: index_line.version,
            dist_url: self.crate_download_url(name, version),
            integrity: format!("sha256-{}", index_line.checksum),
            dependencies,
            optional_dependencies,
            peer_dependencies: HashMap::new(),
            peer_dependencies_meta: HashMap::new(),
            dev_dependencies,
            bundled_dependencies: Vec::new(),
            features: all_features,
            feature_definitions,
        })
    }

    #[instrument(skip(self), fields(ecosystem = "crates"))]
    async fn download(&self, name: &str, version: &str) -> Result<Vec<u8>> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Crates)?;
        validate_version(version)?;

        debug!("Downloading {}@{}", name, version);

        let url = self.crate_download_url(name, version);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to download: {}", e)))?;

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "crates.io".to_string(),
                message: format!("Failed to download {}: HTTP {}", url, response.status()),
            });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read crate: {}", e)))?;

        debug!("Downloaded {} bytes for {}@{}", bytes.len(), name, version);
        Ok(bytes.to_vec())
    }

    #[instrument(skip(self), fields(ecosystem = "crates"))]
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<String>> {
        debug!("Searching crates.io for: {}", query);

        let url = format!(
            "{}/crates?q={}&per_page={}",
            self.api_url,
            urlencoding::encode(query),
            limit.min(100)
        );

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .header(
                "User-Agent",
                concat!("cratons/", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Search failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "crates.io".to_string(),
                message: format!("Search failed: HTTP {}", response.status()),
            });
        }

        #[derive(Deserialize)]
        struct SearchResponse {
            crates: Vec<SearchCrate>,
        }

        #[derive(Deserialize)]
        struct SearchCrate {
            name: String,
        }

        let search_response: SearchResponse =
            response.json().await.map_err(|e| CratonsError::Registry {
                registry: "crates.io".to_string(),
                message: format!("Failed to parse search results: {}", e),
            })?;

        Ok(search_response.crates.into_iter().map(|c| c.name).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_path() {
        // 1-char crate
        assert_eq!(CratesIoClient::index_path("a"), "1/a");

        // 2-char crate
        assert_eq!(CratesIoClient::index_path("ab"), "2/ab");

        // 3-char crate
        assert_eq!(CratesIoClient::index_path("abc"), "3/a/abc");

        // 4+ char crate
        assert_eq!(CratesIoClient::index_path("serde"), "se/rd/serde");
        assert_eq!(CratesIoClient::index_path("tokio"), "to/ki/tokio");
        assert_eq!(CratesIoClient::index_path("rand"), "ra/nd/rand");

        // Case insensitive
        assert_eq!(CratesIoClient::index_path("Serde"), "se/rd/serde");
    }

    #[test]
    fn test_crate_download_url() {
        let client = CratesIoClient::new(reqwest::Client::new());
        assert_eq!(
            client.crate_download_url("serde", "1.0.193"),
            "https://static.crates.io/crates/serde/serde-1.0.193.crate"
        );
    }
}
