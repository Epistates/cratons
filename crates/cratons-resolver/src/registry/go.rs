//! Go Module Proxy Client
//!
//! Implements the GOPROXY protocol for fetching Go module metadata and source.
//! Protocol Documentation: <https://go.dev/ref/mod#goproxy-protocol>
//!
//! # Security
//!
//! All module paths and versions are validated before being used in URLs
//! to prevent SSRF attacks. See [`cratons_core::validation`] for details.

use async_trait::async_trait;
use cratons_core::{CratonsError, Ecosystem, Result, validate_package_name, validate_version};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::OnceCell;
use tracing::{debug, instrument, warn};

use super::gosum::{self, TrustedKey};
use super::{PackageMetadata, RegistryClient};

/// Go module proxy client.
pub struct GoProxyClient {
    client: reqwest::Client,
    proxy_url: String,
    sum_db_url: String,
    /// Lazy-loaded trusted verifier for `sum.golang.org` signed notes.
    /// Bootstrapped from the compiled-in default on first use and cached
    /// on disk at `~/.cache/cratons/keys/sum.golang.org.pub`. See
    /// `gosum::DEFAULT_SUM_GOLANG_VKEY` for the rationale.
    trust_root: Arc<OnceCell<TrustedKey>>,
    /// F-1b weak-consistency baseline. Fetched from `/latest` on first
    /// use, pinned to `~/.cache/cratons/keys/sum.golang.org.checkpoint`,
    /// and validated against subsequent `/latest` responses to detect
    /// size regressions and same-size root rewrites. Full RFC 6962
    /// consistency proofs are tracked as F-1c.
    latest_checkpoint: Arc<OnceCell<gosum::tlog::Checkpoint>>,
}

impl GoProxyClient {
    /// Create a new Go proxy client with the official proxy.
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            proxy_url: "https://proxy.golang.org".to_string(),
            sum_db_url: "https://sum.golang.org".to_string(),
            trust_root: Arc::new(OnceCell::new()),
            latest_checkpoint: Arc::new(OnceCell::new()),
        }
    }

    /// Create a new client with a custom proxy URL.
    pub fn with_proxy(client: reqwest::Client, proxy_url: String) -> Self {
        Self {
            client,
            proxy_url: proxy_url.trim_end_matches('/').to_string(),
            sum_db_url: "https://sum.golang.org".to_string(),
            trust_root: Arc::new(OnceCell::new()),
            latest_checkpoint: Arc::new(OnceCell::new()),
        }
    }

    /// Return the cached trusted verifier for `sum.golang.org`, loading it
    /// from disk on first call.
    async fn trust_root(&self) -> Result<&TrustedKey> {
        self.trust_root
            .get_or_try_init(|| async { gosum::load_or_bootstrap_trust_root() })
            .await
    }

    /// F-1b: fetch and verify the current sum.golang.org transparency
    /// log checkpoint via `/latest`, enforce weak consistency against
    /// any previously-pinned baseline, and update the pinned baseline
    /// if the tree has grown. Caches the result per-client so the
    /// network fetch happens at most once per install run.
    async fn current_checkpoint(&self) -> Result<&gosum::tlog::Checkpoint> {
        self.latest_checkpoint
            .get_or_try_init(|| async {
                let url = format!("{}/latest", self.sum_db_url);
                debug!("Fetching sum.golang.org /latest: {}", url);
                let response = self.client.get(&url).send().await.map_err(|e| {
                    CratonsError::Network(format!(
                        "Failed to fetch sum.golang.org /latest: {}",
                        e
                    ))
                })?;
                if !response.status().is_success() {
                    return Err(CratonsError::Registry {
                        registry: "sum.golang.org".to_string(),
                        message: format!("HTTP {} for /latest", response.status()),
                    });
                }
                let raw = response.text().await.map_err(|e| {
                    CratonsError::Network(format!(
                        "Failed to read sum.golang.org /latest body: {}",
                        e
                    ))
                })?;
                let trust = self.trust_root().await?;
                let verified_body = gosum::verify_note(&raw, trust)?;
                let current = gosum::parse_verified_latest(&verified_body)?;

                // Weak consistency enforcement against any pinned baseline.
                match gosum::tlog::Checkpoint::load()? {
                    Some(baseline) => {
                        gosum::enforce_weak_consistency(&baseline, &current)?;
                        // Persist the new baseline only if strictly newer.
                        // Equal-size checkpoints are no-ops (already pinned).
                        if current.tree_size > baseline.tree_size {
                            current.save()?;
                        }
                    }
                    None => {
                        // First install on this machine — pin-on-first-use.
                        current.save()?;
                    }
                }
                Ok(current)
            })
            .await
    }

    /// Fetch the sum.golang.org `/lookup/{module}@{version}` response,
    /// verify its signature against the pinned trust root, and return the
    /// `h1:` hash of the module zip (base64, without the `h1:` prefix).
    ///
    /// On signature verification failure against the cached key, **does
    /// not** automatically refetch or pivot to a different key — that
    /// would be an exploitable trust-on-failure path. The operator must
    /// update the cache file if Go has rotated the verifier key.
    async fn fetch_sum_h1(&self, name: &str, version: &str) -> Result<String> {
        // F-1b: enforce weak consistency against the pinned baseline
        // before trusting any `/lookup` hash. The first call per
        // client populates the OnceCell; subsequent calls are a
        // cheap deref.
        let _checkpoint = self.current_checkpoint().await?;

        let escaped = Self::escape_module_path(name);
        let url = format!("{}/lookup/{}@{}", self.sum_db_url, escaped, version);
        debug!("Fetching sum.golang.org lookup: {}", url);

        let response = self.client.get(&url).send().await.map_err(|e| {
            CratonsError::Network(format!(
                "Failed to fetch sum.golang.org lookup for {}@{}: {}",
                name, version, e
            ))
        })?;
        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "sum.golang.org".to_string(),
                message: format!(
                    "HTTP {} for lookup {}@{}",
                    response.status(),
                    name,
                    version
                ),
            });
        }
        let raw = response.text().await.map_err(|e| {
            CratonsError::Network(format!(
                "Failed to read sum.golang.org response: {}",
                e
            ))
        })?;

        let trust = self.trust_root().await?;
        let verified_body = gosum::verify_note(&raw, trust).map_err(|e| {
            warn!(
                module = %name,
                version = %version,
                "sum.golang.org signed-note verification failed: {}",
                e
            );
            e
        })?;

        gosum::parse_verified_lookup(&verified_body, name, version)
    }

    /// Escape a module path for URL usage.
    /// Uppercase letters are escaped as !{lowercase}.
    fn escape_module_path(path: &str) -> String {
        let mut escaped = String::with_capacity(path.len() + 10);
        for c in path.chars() {
            if c.is_ascii_uppercase() {
                escaped.push('!');
                escaped.push(c.to_ascii_lowercase());
            } else {
                escaped.push(c);
            }
        }
        escaped
    }

    /// Unescape a module path from URL format.
    #[allow(dead_code)] // Reserved for future use
    fn unescape_module_path(escaped: &str) -> String {
        let mut result = String::with_capacity(escaped.len());
        let mut chars = escaped.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '!' {
                if let Some(next) = chars.next() {
                    result.push(next.to_ascii_uppercase());
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Parse go.mod file to extract dependencies (M-15: handle replace/exclude).
    fn parse_go_mod(content: &str) -> BTreeMap<String, String> {
        GoModFile::parse(content).require
    }
}

/// Parsed go.mod file data (M-15).
#[derive(Debug, Default)]
pub struct GoModFile {
    /// Module name (go.mod "module" directive)
    pub module: Option<String>,
    /// Go version requirement
    pub go_version: Option<String>,
    /// Required dependencies
    pub require: BTreeMap<String, String>,
    /// Replace directives (old -> new path, optional version)
    pub replace: BTreeMap<String, (String, Option<String>)>,
    /// Excluded module versions
    pub exclude: Vec<(String, String)>,
    /// Retracted versions (security concern)
    pub retract: Vec<String>,
}

impl GoModFile {
    /// Parse go.mod file with full directive support.
    pub fn parse(content: &str) -> Self {
        let mut result = Self::default();

        let mut in_require_block = false;
        let mut in_replace_block = false;
        let mut in_exclude_block = false;
        let mut in_retract_block = false;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            // Handle module directive
            if line.starts_with("module ") {
                result.module = line.strip_prefix("module ").map(|s| s.trim().to_string());
                continue;
            }

            // Handle go version directive
            if line.starts_with("go ") {
                result.go_version = line.strip_prefix("go ").map(|s| s.trim().to_string());
                continue;
            }

            // Handle block starts
            if line.starts_with("require (") || line == "require(" {
                in_require_block = true;
                continue;
            }
            if line.starts_with("replace (") || line == "replace(" {
                in_replace_block = true;
                continue;
            }
            if line.starts_with("exclude (") || line == "exclude(" {
                in_exclude_block = true;
                continue;
            }
            if line.starts_with("retract (") || line == "retract(" {
                in_retract_block = true;
                continue;
            }

            // Handle block end
            if line == ")" {
                in_require_block = false;
                in_replace_block = false;
                in_exclude_block = false;
                in_retract_block = false;
                continue;
            }

            // Handle inline require: require module version
            if line.starts_with("require ") && !line.contains('(') {
                let parts: Vec<&str> = line
                    .strip_prefix("require ")
                    .unwrap()
                    .split_whitespace()
                    .collect();
                if parts.len() >= 2 {
                    result
                        .require
                        .insert(parts[0].to_string(), parts[1].to_string());
                }
                continue;
            }

            // Handle inline replace: replace old => new [version]
            if line.starts_with("replace ") && !line.contains('(') {
                Self::parse_replace_line(
                    line.strip_prefix("replace ").unwrap(),
                    &mut result.replace,
                );
                continue;
            }

            // Handle inline exclude: exclude module version
            if line.starts_with("exclude ") && !line.contains('(') {
                let parts: Vec<&str> = line
                    .strip_prefix("exclude ")
                    .unwrap()
                    .split_whitespace()
                    .collect();
                if parts.len() >= 2 {
                    result
                        .exclude
                        .push((parts[0].to_string(), parts[1].to_string()));
                }
                continue;
            }

            // Handle inline retract: retract version
            if line.starts_with("retract ") && !line.contains('(') {
                if let Some(version) = line.strip_prefix("retract ") {
                    result.retract.push(version.trim().to_string());
                }
                continue;
            }

            // Handle require block entries: module version
            if in_require_block {
                // Skip indirect dependencies if marked
                let line = if line.contains("// indirect") {
                    line.split("//").next().unwrap_or(line).trim()
                } else {
                    line
                };

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    result
                        .require
                        .insert(parts[0].to_string(), parts[1].to_string());
                }
            }

            // Handle replace block entries
            if in_replace_block {
                Self::parse_replace_line(line, &mut result.replace);
            }

            // Handle exclude block entries
            if in_exclude_block {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    result
                        .exclude
                        .push((parts[0].to_string(), parts[1].to_string()));
                }
            }

            // Handle retract block entries
            if in_retract_block {
                result.retract.push(line.to_string());
            }
        }

        result
    }

    /// Parse a single replace directive line.
    fn parse_replace_line(
        line: &str,
        replace_map: &mut BTreeMap<String, (String, Option<String>)>,
    ) {
        // Format: old [version] => new [version]
        // or: old => new [version]
        if let Some((old_part, new_part)) = line.split_once("=>") {
            let old_parts: Vec<&str> = old_part.trim().split_whitespace().collect();
            let new_parts: Vec<&str> = new_part.trim().split_whitespace().collect();

            if !old_parts.is_empty() && !new_parts.is_empty() {
                let old_module = old_parts[0].to_string();
                let new_module = new_parts[0].to_string();
                let new_version = new_parts.get(1).map(|s| s.to_string());

                replace_map.insert(old_module, (new_module, new_version));
            }
        }
    }
}

/// Version info response from GOPROXY.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields populated by serde but not all are read
struct VersionInfo {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Time")]
    time: String,
    #[serde(rename = "Origin", default)]
    origin: Option<VersionOrigin>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VersionOrigin {
    #[serde(rename = "VCS", default)]
    vcs: String,
    #[serde(rename = "URL", default)]
    url: String,
    #[serde(rename = "Hash", default)]
    hash: String,
}

#[async_trait]
impl RegistryClient for GoProxyClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }

    fn registry_url(&self) -> &str {
        &self.proxy_url
    }

    #[instrument(skip(self), fields(ecosystem = "go"))]
    async fn fetch_versions(&self, name: &str) -> Result<Vec<String>> {
        // SECURITY: Validate module path before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Go)?;

        debug!("Fetching versions for Go module: {}", name);

        let escaped = Self::escape_module_path(name);
        let url = format!("{}/@v/list", escaped);
        let full_url = format!("{}/{}", self.proxy_url, url);

        let response = self
            .client
            .get(&full_url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to fetch {}: {}", name, e)))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CratonsError::PackageNotFound(name.to_string()));
        }

        // 410 Gone means module exists but no versions available yet
        if response.status() == reqwest::StatusCode::GONE {
            return Ok(Vec::new());
        }

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "goproxy".to_string(),
                message: format!("HTTP {}: {}", response.status(), full_url),
            });
        }

        let text = response
            .text()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read response: {}", e)))?;

        // Response is newline-separated list of versions
        let mut versions: Vec<String> = text
            .lines()
            .filter(|line| !line.is_empty())
            .map(String::from)
            .collect();

        // Sort by semver (ascending for MVS) - Go versions are like v1.2.3
        versions.sort_by(|a, b| {
            let va = a.strip_prefix('v').unwrap_or(a);
            let vb = b.strip_prefix('v').unwrap_or(b);
            match (semver::Version::parse(va), semver::Version::parse(vb)) {
                (Ok(va), Ok(vb)) => va.cmp(&vb), // Ascending for MVS
                (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                (Err(_), Err(_)) => a.cmp(b),
            }
        });

        debug!("Found {} versions for {}", versions.len(), name);
        Ok(versions)
    }

    #[instrument(skip(self), fields(ecosystem = "go"))]
    async fn fetch_metadata(&self, name: &str, version: &str) -> Result<PackageMetadata> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Go)?;
        validate_version(version)?;

        debug!("Fetching metadata for {}@{}", name, version);

        let escaped = Self::escape_module_path(name);

        // Fetch version info: /{module}/@v/{version}.info
        let info_url = format!("{}/{}/@v/{}.info", self.proxy_url, escaped, version);
        let response = self
            .client
            .get(&info_url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to fetch info: {}", e)))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CratonsError::VersionNotFound {
                package: name.to_string(),
                version: version.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "goproxy".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let version_info: VersionInfo =
            response.json().await.map_err(|e| CratonsError::Registry {
                registry: "goproxy".to_string(),
                message: format!("Failed to parse version info: {}", e),
            })?;

        // Fetch go.mod: /{module}/@v/{version}.mod
        let mod_url = format!("{}/{}/@v/{}.mod", self.proxy_url, escaped, version);
        let mod_response = self
            .client
            .get(&mod_url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to fetch go.mod: {}", e)))?;

        let dependencies = if mod_response.status().is_success() {
            let mod_content = mod_response
                .text()
                .await
                .map_err(|e| CratonsError::Network(format!("Failed to read go.mod: {}", e)))?;
            Self::parse_go_mod(&mod_content)
        } else {
            BTreeMap::new()
        };

        // Download URL: /{module}/@v/{version}.zip
        let zip_url = format!("{}/{}/@v/{}.zip", self.proxy_url, escaped, version);

        // F-1: Query sum.golang.org for a cross-origin, signature-verified
        // `h1:` hash. The signed-note verification is done inside
        // `fetch_sum_h1` against the pinned trust root. A failure here is
        // fatal under `IntegrityPolicy::Required`; under the default
        // (Go on the allowlist), the caller may still install with an
        // `integrity-degraded` warning.
        let integrity = match self.fetch_sum_h1(name, version).await {
            Ok(h1) => format!("h1-{}", h1),
            Err(e) => {
                warn!(
                    module = %name,
                    version = %version,
                    error = %e,
                    "sum.golang.org lookup failed; falling back to empty integrity"
                );
                // Leave integrity empty so the installer's policy gate
                // surfaces the degradation via the allowlist warning
                // path (or errors under `Required`). We do NOT fall back
                // to the proxy-reported origin.hash, which would be a
                // same-host attestation and defeats the purpose of F-1.
                String::new()
            }
        };

        Ok(PackageMetadata {
            name: name.to_string(),
            version: version_info.version,
            dist_url: zip_url,
            integrity,
            dependencies,
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
            peer_dependencies_meta: BTreeMap::new(),
            dev_dependencies: BTreeMap::new(),
            bundled_dependencies: Vec::new(),
            features: Vec::new(),
            feature_definitions: BTreeMap::new(),
        })
    }

    #[instrument(skip(self), fields(ecosystem = "go"))]
    async fn download(&self, name: &str, version: &str) -> Result<Vec<u8>> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Go)?;
        validate_version(version)?;

        debug!("Downloading {}@{}", name, version);

        let escaped = Self::escape_module_path(name);
        let url = format!("{}/{}/@v/{}.zip", self.proxy_url, escaped, version);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to download: {}", e)))?;

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "goproxy".to_string(),
                message: format!("Failed to download {}: HTTP {}", url, response.status()),
            });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read zip: {}", e)))?;

        debug!("Downloaded {} bytes for {}@{}", bytes.len(), name, version);
        Ok(bytes.to_vec())
    }

    async fn search(&self, _query: &str, _limit: usize) -> Result<Vec<String>> {
        // Go module proxy doesn't have a search API
        // Would need to use pkg.go.dev or similar
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_module_path() {
        // No uppercase
        assert_eq!(
            GoProxyClient::escape_module_path("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );

        // With uppercase
        assert_eq!(
            GoProxyClient::escape_module_path("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );

        // Mixed case
        assert_eq!(
            GoProxyClient::escape_module_path("github.com/Azure/go-autorest"),
            "github.com/!azure/go-autorest"
        );
    }

    #[test]
    fn test_unescape_module_path() {
        assert_eq!(
            GoProxyClient::unescape_module_path("github.com/!burnt!sushi/toml"),
            "github.com/BurntSushi/toml"
        );
    }

    #[test]
    fn test_parse_go_mod() {
        let content = r#"
module github.com/gin-gonic/gin

go 1.20

require (
    github.com/bytedance/sonic v1.9.1
    github.com/gin-contrib/sse v0.1.0
    github.com/go-playground/validator/v10 v10.14.0
    golang.org/x/net v0.10.0 // indirect
)

require github.com/json-iterator/go v1.1.12
"#;

        let deps = GoProxyClient::parse_go_mod(content);

        assert_eq!(
            deps.get("github.com/bytedance/sonic"),
            Some(&"v1.9.1".to_string())
        );
        assert_eq!(
            deps.get("github.com/gin-contrib/sse"),
            Some(&"v0.1.0".to_string())
        );
        assert_eq!(
            deps.get("github.com/json-iterator/go"),
            Some(&"v1.1.12".to_string())
        );
        assert_eq!(deps.get("golang.org/x/net"), Some(&"v0.10.0".to_string()));
    }

    #[test]
    fn test_parse_go_mod_full() {
        let content = r#"
module github.com/example/mymodule

go 1.21

require (
    github.com/pkg/errors v0.9.1
    golang.org/x/sync v0.3.0
)

replace (
    github.com/pkg/errors => github.com/pkg/errors v0.9.2
    golang.org/x/sync => ./local/sync
)

exclude (
    github.com/vuln/package v1.0.0
    github.com/vuln/package v1.0.1
)

retract (
    v1.0.0
    [v1.1.0, v1.2.0]
)
"#;

        let mod_file = GoModFile::parse(content);

        // Check module name
        assert_eq!(
            mod_file.module,
            Some("github.com/example/mymodule".to_string())
        );
        assert_eq!(mod_file.go_version, Some("1.21".to_string()));

        // Check require
        assert_eq!(
            mod_file.require.get("github.com/pkg/errors"),
            Some(&"v0.9.1".to_string())
        );
        assert_eq!(
            mod_file.require.get("golang.org/x/sync"),
            Some(&"v0.3.0".to_string())
        );

        // Check replace
        assert_eq!(
            mod_file.replace.get("github.com/pkg/errors"),
            Some(&(
                "github.com/pkg/errors".to_string(),
                Some("v0.9.2".to_string())
            ))
        );
        assert_eq!(
            mod_file.replace.get("golang.org/x/sync"),
            Some(&("./local/sync".to_string(), None))
        );

        // Check exclude
        assert!(
            mod_file
                .exclude
                .contains(&("github.com/vuln/package".to_string(), "v1.0.0".to_string()))
        );
        assert!(
            mod_file
                .exclude
                .contains(&("github.com/vuln/package".to_string(), "v1.0.1".to_string()))
        );

        // Check retract
        assert!(mod_file.retract.contains(&"v1.0.0".to_string()));
    }
}
