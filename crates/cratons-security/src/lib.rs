//! Security auditing and SBOM generation.
//!
//! This crate provides security vulnerability scanning using [OSV.dev](https://osv.dev)
//! and SBOM (Software Bill of Materials) generation in CycloneDX format.
//!
//! # Example
//!
//! ```ignore
//! use cratons_security::Auditor;
//! use cratons_lockfile::Lockfile;
//!
//! let auditor = Auditor::new();
//! let lockfile = Lockfile::load("cratons.lock")?;
//! let result = auditor.audit(&lockfile).await?;
//!
//! for vuln in &result.vulnerabilities {
//!     println!("{}: {} ({})", vuln.id, vuln.title, vuln.severity);
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod policy;

use cratons_core::{Ecosystem, CratonsError, Result};
use cratons_lockfile::Lockfile;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// OSV.dev API base URL.
const OSV_API_URL: &str = "https://api.osv.dev/v1";

/// Maximum packages per batch query (OSV limit).
const OSV_BATCH_SIZE: usize = 1000;

/// Default cache TTL (6 hours).
const DEFAULT_CACHE_TTL_SECS: u64 = 6 * 60 * 60;

/// Severity of a vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Self::Low
    }
}

impl Severity {
    /// Parse severity from OSV severity string.
    fn from_osv(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "HIGH" => Self::High,
            "MODERATE" | "MEDIUM" => Self::Medium,
            "LOW" => Self::Low,
            _ => Self::Low,
        }
    }

    /// Parse severity from CVSS score.
    fn from_cvss_score(score: f64) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    /// Parse severity from CVSS 3.x vector string.
    ///
    /// CVSS 3.x vectors look like: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    /// This calculates an approximate base score using the impact and exploitability metrics.
    pub fn from_cvss_vector(vector: &str) -> Option<Self> {
        // Must start with CVSS:3
        if !vector.starts_with("CVSS:3") {
            return None;
        }

        // Parse vector components
        let mut av_score = 0.0; // Attack Vector
        let mut ac_score = 0.0; // Attack Complexity
        let mut pr_score = 0.0; // Privileges Required
        let mut ui_score = 0.0; // User Interaction
        let mut scope_changed = false;
        let mut c_score = 0.0; // Confidentiality Impact
        let mut i_score = 0.0; // Integrity Impact
        let mut a_score = 0.0; // Availability Impact

        for part in vector.split('/') {
            let (metric, value) = match part.split_once(':') {
                Some((m, v)) => (m, v),
                None => continue,
            };

            match metric {
                "AV" => {
                    av_score = match value {
                        "N" => 0.85, // Network
                        "A" => 0.62, // Adjacent
                        "L" => 0.55, // Local
                        "P" => 0.2,  // Physical
                        _ => 0.0,
                    };
                }
                "AC" => {
                    ac_score = match value {
                        "L" => 0.77, // Low
                        "H" => 0.44, // High
                        _ => 0.0,
                    };
                }
                "PR" => {
                    pr_score = match (value, scope_changed) {
                        ("N", _) => 0.85,     // None
                        ("L", false) => 0.62, // Low, unchanged scope
                        ("L", true) => 0.68,  // Low, changed scope
                        ("H", false) => 0.27, // High, unchanged scope
                        ("H", true) => 0.50,  // High, changed scope
                        _ => 0.0,
                    };
                }
                "UI" => {
                    ui_score = match value {
                        "N" => 0.85, // None
                        "R" => 0.62, // Required
                        _ => 0.0,
                    };
                }
                "S" => {
                    scope_changed = value == "C";
                    // Recalculate PR if scope changes
                }
                "C" => {
                    c_score = match value {
                        "H" => 0.56, // High
                        "L" => 0.22, // Low
                        "N" => 0.0,  // None
                        _ => 0.0,
                    };
                }
                "I" => {
                    i_score = match value {
                        "H" => 0.56, // High
                        "L" => 0.22, // Low
                        "N" => 0.0,  // None
                        _ => 0.0,
                    };
                }
                "A" => {
                    a_score = match value {
                        "H" => 0.56, // High
                        "L" => 0.22, // Low
                        "N" => 0.0,  // None
                        _ => 0.0,
                    };
                }
                _ => {}
            }
        }

        // Calculate Impact Sub Score (ISS)
        let iss: f64 = 1.0 - ((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score));

        // Calculate Impact
        let impact: f64 = if scope_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powf(15.0)
        } else {
            6.42 * iss
        };

        // Calculate Exploitability
        let exploitability: f64 = 8.22 * av_score * ac_score * pr_score * ui_score;

        // Calculate Base Score
        let base_score: f64 = if impact <= 0.0 {
            0.0
        } else if scope_changed {
            ((1.08 * (impact + exploitability)).min(10.0) * 10.0).ceil() / 10.0
        } else {
            ((impact + exploitability).min(10.0) * 10.0).ceil() / 10.0
        };

        Some(Self::from_cvss_score(base_score))
    }
}

/// A security vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Vulnerability ID (e.g., CVE-2023-12345, GHSA-xxxx-xxxx-xxxx, RUSTSEC-2024-0001)
    pub id: String,
    /// Package name
    pub package: String,
    /// Ecosystem
    pub ecosystem: Ecosystem,
    /// Affected version range
    pub affected_versions: String,
    /// Fixed version (if available)
    pub fixed_version: Option<String>,
    /// Summary/Title
    pub title: String,
    /// Description
    pub description: String,
    /// Severity
    pub severity: Severity,
    /// CVE ID (if available)
    pub cve: Option<String>,
    /// URL for more information
    pub url: Option<String>,
}

/// Result of a security audit.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuditResult {
    /// Number of packages audited
    pub packages_audited: usize,
    /// Found vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,
    /// Packages that failed to check (network errors, etc.)
    pub failed_packages: Vec<String>,
}

/// Configuration for security auditing.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Minimum severity threshold to fail the audit (None = don't fail)
    pub fail_threshold: Option<Severity>,
    /// Ignore specific vulnerability IDs
    pub ignore_vulns: Vec<String>,
    /// Only check direct dependencies (not transitive)
    pub direct_only: bool,
    /// Timeout for OSV API requests
    pub timeout: Duration,
    /// Output format for reports
    pub output_format: OutputFormat,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            fail_threshold: None,
            ignore_vulns: Vec::new(),
            direct_only: false,
            timeout: Duration::from_secs(30),
            output_format: OutputFormat::Text,
        }
    }
}

impl AuditConfig {
    /// Create a new audit config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the fail threshold.
    #[must_use]
    pub fn with_fail_threshold(mut self, threshold: Severity) -> Self {
        self.fail_threshold = Some(threshold);
        self
    }

    /// Add a vulnerability ID to ignore.
    #[must_use]
    pub fn ignore(mut self, vuln_id: impl Into<String>) -> Self {
        self.ignore_vulns.push(vuln_id.into());
        self
    }

    /// Only audit direct dependencies.
    #[must_use]
    pub fn direct_only(mut self) -> Self {
        self.direct_only = true;
        self
    }

    /// Set the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the output format.
    #[must_use]
    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }
}

/// Output format for audit reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable text output
    #[default]
    Text,
    /// JSON output
    Json,
    /// SARIF output (for CI integration)
    Sarif,
}

impl AuditResult {
    /// Check if there are any vulnerabilities above a certain severity.
    pub fn vulnerabilities_above(&self, severity: Severity) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity >= severity)
            .collect()
    }

    /// Get count of vulnerabilities by severity.
    pub fn count_by_severity(&self) -> HashMap<Severity, usize> {
        let mut counts = HashMap::new();
        for vuln in &self.vulnerabilities {
            *counts.entry(vuln.severity).or_insert(0) += 1;
        }
        counts
    }

    /// Check if the audit passed (no vulnerabilities above threshold).
    pub fn passed(&self, threshold: Severity) -> bool {
        self.vulnerabilities_above(threshold).is_empty()
    }
}

// ============================================================================
// OSV Cache (M-13)
// ============================================================================

/// Cached OSV vulnerability entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedVulns {
    /// Vulnerabilities for this package version.
    vulns: Vec<String>, // Vulnerability IDs
    /// When this cache entry was created.
    #[serde(with = "humantime_serde")]
    cached_at: SystemTime,
}

/// OSV response cache to avoid repeated network calls.
#[derive(Debug)]
pub struct OsvCache {
    cache_dir: PathBuf,
    ttl: Duration,
}

impl OsvCache {
    /// Create a new OSV cache with default location.
    pub fn new() -> Result<Self> {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("cratons")
            .join("osv");

        std::fs::create_dir_all(&cache_dir)?;

        Ok(Self {
            cache_dir,
            ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        })
    }

    /// Create a cache with custom directory.
    pub fn with_dir(cache_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            cache_dir,
            ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        })
    }

    /// Set the cache TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Get cache key for a package.
    fn cache_key(ecosystem: &str, name: &str, version: &str) -> String {
        // Sanitize name for filesystem
        let safe_name = name.replace('/', "_").replace('\\', "_");
        format!("{}_{}_{}_.json", ecosystem, safe_name, version)
    }

    /// Get cached vulnerabilities if fresh.
    pub fn get(&self, ecosystem: &str, name: &str, version: &str) -> Option<Vec<String>> {
        let key = Self::cache_key(ecosystem, name, version);
        let path = self.cache_dir.join(&key);

        if !path.exists() {
            return None;
        }

        // Read and parse cache file
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to read cache file {}: {}", path.display(), e);
                return None;
            }
        };

        let cached: CachedVulns = match serde_json::from_str(&content) {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to parse cache file {}: {}", path.display(), e);
                // Remove invalid cache file
                let _ = std::fs::remove_file(&path);
                return None;
            }
        };

        // Check if cache is still fresh
        let age = cached.cached_at.elapsed().unwrap_or(Duration::MAX);
        if age > self.ttl {
            debug!("Cache expired for {}:{}", ecosystem, name);
            let _ = std::fs::remove_file(&path);
            return None;
        }

        debug!(
            "Cache hit for {}:{}@{} ({} vulns)",
            ecosystem,
            name,
            version,
            cached.vulns.len()
        );
        Some(cached.vulns)
    }

    /// Store vulnerabilities in cache.
    pub fn set(&self, ecosystem: &str, name: &str, version: &str, vuln_ids: Vec<String>) {
        let key = Self::cache_key(ecosystem, name, version);
        let path = self.cache_dir.join(&key);

        let cached = CachedVulns {
            vulns: vuln_ids,
            cached_at: SystemTime::now(),
        };

        if let Ok(content) = serde_json::to_string(&cached) {
            if let Err(e) = std::fs::write(&path, content) {
                debug!("Failed to write cache file {}: {}", path.display(), e);
            }
        }
    }

    /// Clear all cached entries.
    pub fn clear(&self) -> Result<usize> {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                if entry
                    .path()
                    .extension()
                    .map(|e| e == "json")
                    .unwrap_or(false)
                {
                    if std::fs::remove_file(entry.path()).is_ok() {
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }
}

impl Default for OsvCache {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            cache_dir: PathBuf::from(".cache/cratons/osv"),
            ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        })
    }
}

// ============================================================================
// OSV API request/response types
// ============================================================================

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    vulns: Option<Vec<OsvVulnerability>>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResponse>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    affected: Option<Vec<OsvAffected>>,
    references: Option<Vec<OsvReference>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    #[allow(dead_code)] // Captured for future CVSS vector parsing
    severity_type: Option<String>,
    score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[allow(dead_code)] // Available for detailed vulnerability reporting
    package: Option<OsvAffectedPackage>,
    ranges: Option<Vec<OsvRange>>,
    versions: Option<Vec<String>>,
    ecosystem_specific: Option<OsvEcosystemSpecific>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Complete OSV schema - fields available for future enhancements
struct OsvAffectedPackage {
    name: Option<String>,
    ecosystem: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    #[allow(dead_code)] // Range type (SEMVER, GIT, ECOSYSTEM) for advanced filtering
    range_type: Option<String>,
    events: Option<Vec<OsvEvent>>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvEcosystemSpecific {
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    ref_type: Option<String>,
    url: Option<String>,
}

/// Security auditor using OSV.dev vulnerability database.
pub struct Auditor {
    /// HTTP client for API requests
    client: Client,
    /// OSV API base URL (can be overridden for testing)
    api_url: String,
    /// Request timeout
    timeout: Duration,
}

impl Auditor {
    /// Create a new auditor with default configuration.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("cratons-security/0.1.0")
                .build()
                .expect("Failed to create HTTP client"),
            api_url: OSV_API_URL.to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Create an auditor with a custom API URL (for testing).
    #[cfg(test)]
    pub fn with_api_url(api_url: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("cratons-security/0.1.0")
                .build()
                .expect("Failed to create HTTP client"),
            api_url: api_url.to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Map Cratons ecosystem to OSV ecosystem string.
    fn ecosystem_to_osv(ecosystem: Ecosystem) -> &'static str {
        match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "PyPI",
            Ecosystem::Crates => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Maven => "Maven",
            Ecosystem::Url => "npm", // URL dependencies don't have a specific ecosystem in OSV
        }
    }

    /// Perform a security audit on a lockfile.
    ///
    /// This method queries the OSV.dev API to check for known vulnerabilities
    /// in all packages listed in the lockfile.
    pub async fn audit(&self, lockfile: &Lockfile) -> Result<AuditResult> {
        let mut result = AuditResult {
            packages_audited: lockfile.package_count(),
            vulnerabilities: Vec::new(),
            failed_packages: Vec::new(),
        };

        if lockfile.packages.is_empty() {
            return Ok(result);
        }

        info!(
            "Auditing {} packages for vulnerabilities",
            lockfile.packages.len()
        );

        // Build batch queries
        let queries: Vec<OsvQuery> = lockfile
            .packages
            .iter()
            .map(|pkg| OsvQuery {
                package: OsvPackage {
                    name: pkg.name.clone(),
                    ecosystem: Self::ecosystem_to_osv(pkg.ecosystem).to_string(),
                },
                version: pkg.version.clone(),
            })
            .collect();

        // Process in batches
        for chunk in queries.chunks(OSV_BATCH_SIZE) {
            match self.query_batch(chunk).await {
                Ok(vulns) => {
                    for (i, vuln_list) in vulns.into_iter().enumerate() {
                        if let Some(query) = chunk.get(i) {
                            let ecosystem = Self::parse_ecosystem(&query.package.ecosystem);
                            for vuln in vuln_list {
                                result.vulnerabilities.push(self.convert_vulnerability(
                                    vuln,
                                    &query.package.name,
                                    ecosystem,
                                ));
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Batch query failed: {}. Falling back to individual queries.",
                        e
                    );
                    // Fall back to individual queries
                    for query in chunk {
                        match self.query_single(query).await {
                            Ok(vulns) => {
                                for vuln in vulns {
                                    let ecosystem = Self::parse_ecosystem(&query.package.ecosystem);
                                    result.vulnerabilities.push(self.convert_vulnerability(
                                        vuln,
                                        &query.package.name,
                                        ecosystem,
                                    ));
                                }
                            }
                            Err(e) => {
                                debug!("Failed to query {}: {}", query.package.name, e);
                                result.failed_packages.push(query.package.name.clone());
                            }
                        }
                    }
                }
            }
        }

        info!(
            "Audit complete: {} vulnerabilities found in {} packages",
            result.vulnerabilities.len(),
            result.packages_audited
        );

        Ok(result)
    }

    /// Query OSV API for a batch of packages.
    async fn query_batch(&self, queries: &[OsvQuery]) -> Result<Vec<Vec<OsvVulnerability>>> {
        let url = format!("{}/querybatch", self.api_url);

        let batch = OsvBatchQuery {
            queries: queries
                .iter()
                .map(|q| OsvQuery {
                    package: OsvPackage {
                        name: q.package.name.clone(),
                        ecosystem: q.package.ecosystem.clone(),
                    },
                    version: q.version.clone(),
                })
                .collect(),
        };

        debug!("Querying OSV batch API with {} packages", queries.len());

        let response = self
            .client
            .post(&url)
            .json(&batch)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("OSV API request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "OSV API returned error: {}",
                response.status()
            )));
        }

        let batch_response: OsvBatchResponse = response
            .json()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to parse OSV response: {e}")))?;

        Ok(batch_response
            .results
            .into_iter()
            .map(|r| r.vulns.unwrap_or_default())
            .collect())
    }

    /// Query OSV API for a single package.
    async fn query_single(&self, query: &OsvQuery) -> Result<Vec<OsvVulnerability>> {
        let url = format!("{}/query", self.api_url);

        debug!("Querying OSV for {}@{}", query.package.name, query.version);

        let response = self
            .client
            .post(&url)
            .json(query)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("OSV API request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(CratonsError::Network(format!(
                "OSV API returned error: {}",
                response.status()
            )));
        }

        let query_response: OsvQueryResponse = response
            .json()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to parse OSV response: {e}")))?;

        Ok(query_response.vulns.unwrap_or_default())
    }

    /// Convert an OSV vulnerability to our Vulnerability type.
    fn convert_vulnerability(
        &self,
        osv: OsvVulnerability,
        package_name: &str,
        ecosystem: Ecosystem,
    ) -> Vulnerability {
        // Extract severity
        let severity = self.extract_severity(&osv);

        // Extract fixed version
        let fixed_version = self.extract_fixed_version(&osv);

        // Extract affected versions description
        let affected_versions = self.extract_affected_versions(&osv);

        // Extract CVE ID from references
        let cve = self.extract_cve(&osv);

        // Extract URL
        let url = self.extract_url(&osv);

        Vulnerability {
            id: osv.id,
            package: package_name.to_string(),
            ecosystem,
            affected_versions,
            fixed_version,
            title: osv
                .summary
                .unwrap_or_else(|| "Unknown vulnerability".to_string()),
            description: osv.details.unwrap_or_default(),
            severity,
            cve,
            url,
        }
    }

    /// Extract severity from OSV vulnerability.
    fn extract_severity(&self, osv: &OsvVulnerability) -> Severity {
        // Try CVSS score/vector first (M-14: proper CVSS vector parsing)
        if let Some(severities) = &osv.severity {
            for sev in severities {
                if let Some(score_str) = &sev.score {
                    // Try parsing as direct numeric score first
                    if let Ok(score) = score_str.parse::<f64>() {
                        return Severity::from_cvss_score(score);
                    }

                    // Try parsing as CVSS 3.x vector (e.g., "CVSS:3.1/AV:N/AC:L/...")
                    if score_str.starts_with("CVSS:3") {
                        if let Some(severity) = Severity::from_cvss_vector(score_str) {
                            return severity;
                        }
                    }

                    // CVSS 2.0 vectors start differently - extract AV for rough estimate
                    if score_str.contains("AV:N") && score_str.contains("AC:L") {
                        // Network-accessible, low complexity = High severity estimate
                        if score_str.contains("Au:N") || score_str.contains("PR:N") {
                            return Severity::Critical;
                        }
                        return Severity::High;
                    }
                }
            }
        }

        // Try ecosystem-specific severity
        if let Some(affected) = &osv.affected {
            for aff in affected {
                if let Some(eco_spec) = &aff.ecosystem_specific {
                    if let Some(sev_str) = &eco_spec.severity {
                        return Severity::from_osv(sev_str);
                    }
                }
            }
        }

        // Default to Medium for unknown severity
        Severity::Medium
    }

    /// Extract fixed version from OSV vulnerability.
    fn extract_fixed_version(&self, osv: &OsvVulnerability) -> Option<String> {
        if let Some(affected) = &osv.affected {
            for aff in affected {
                if let Some(ranges) = &aff.ranges {
                    for range in ranges {
                        if let Some(events) = &range.events {
                            for event in events {
                                if let Some(fixed) = &event.fixed {
                                    return Some(fixed.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract affected versions description from OSV vulnerability.
    fn extract_affected_versions(&self, osv: &OsvVulnerability) -> String {
        let mut versions = Vec::new();

        if let Some(affected) = &osv.affected {
            for aff in affected {
                // Direct version list
                if let Some(vers) = &aff.versions {
                    if !vers.is_empty() {
                        versions.extend(vers.iter().take(5).cloned());
                        if vers.len() > 5 {
                            versions.push(format!("... ({} more)", vers.len() - 5));
                        }
                    }
                }

                // Range-based versions
                if let Some(ranges) = &aff.ranges {
                    for range in ranges {
                        if let Some(events) = &range.events {
                            let mut introduced = None;
                            let mut fixed = None;
                            for event in events {
                                if event.introduced.is_some() {
                                    introduced = event.introduced.clone();
                                }
                                if event.fixed.is_some() {
                                    fixed = event.fixed.clone();
                                }
                            }
                            match (introduced, fixed) {
                                (Some(i), Some(f)) => versions.push(format!(">={i}, <{f}")),
                                (Some(i), None) => versions.push(format!(">={i}")),
                                (None, Some(f)) => versions.push(format!("<{f}")),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        if versions.is_empty() {
            "Unknown versions".to_string()
        } else {
            versions.join(", ")
        }
    }

    /// Extract CVE ID from OSV vulnerability references.
    fn extract_cve(&self, osv: &OsvVulnerability) -> Option<String> {
        // First check if the ID itself is a CVE
        if osv.id.starts_with("CVE-") {
            return Some(osv.id.clone());
        }

        // Check references for CVE
        if let Some(refs) = &osv.references {
            for r in refs {
                if let Some(url) = &r.url {
                    // Extract CVE from URLs like https://nvd.nist.gov/vuln/detail/CVE-2023-12345
                    if let Some(cve) = url.split('/').find(|s| s.starts_with("CVE-")) {
                        return Some(cve.to_string());
                    }
                }
            }
        }

        None
    }

    /// Extract primary URL from OSV vulnerability.
    fn extract_url(&self, osv: &OsvVulnerability) -> Option<String> {
        // OSV URL
        let osv_url = format!("https://osv.dev/vulnerability/{}", osv.id);

        // Check for advisory URL
        if let Some(refs) = &osv.references {
            for r in refs {
                if r.ref_type.as_deref() == Some("ADVISORY") {
                    if let Some(url) = &r.url {
                        return Some(url.clone());
                    }
                }
            }
        }

        Some(osv_url)
    }

    /// Parse ecosystem string back to Ecosystem enum.
    fn parse_ecosystem(s: &str) -> Ecosystem {
        match s {
            "npm" => Ecosystem::Npm,
            "PyPI" => Ecosystem::PyPi,
            "crates.io" => Ecosystem::Crates,
            "Go" => Ecosystem::Go,
            "Maven" => Ecosystem::Maven,
            _ => Ecosystem::Npm, // Default fallback
        }
    }

    /// Generate an SBOM (Software Bill of Materials) from a lockfile.
    ///
    /// Generates a CycloneDX 1.4 format SBOM.
    pub fn generate_sbom(&self, lockfile: &Lockfile) -> Result<String> {
        let sbom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "tools": [{
                    "vendor": "Cratons",
                    "name": "cratons-security",
                    "version": env!("CARGO_PKG_VERSION")
                }]
            },
            "components": lockfile.packages.iter().map(|pkg| {
                serde_json::json!({
                    "type": "library",
                    "name": pkg.name,
                    "version": pkg.version,
                    "purl": format!("pkg:{}/{}@{}",
                        Self::ecosystem_to_purl(pkg.ecosystem),
                        pkg.name,
                        pkg.version
                    ),
                    "properties": [{
                        "name": "cratons:ecosystem",
                        "value": format!("{:?}", pkg.ecosystem).to_lowercase()
                    }, {
                        "name": "cratons:direct",
                        "value": pkg.direct.to_string()
                    }]
                })
            }).collect::<Vec<_>>()
        });

        Ok(serde_json::to_string_pretty(&sbom)?)
    }

    /// Convert ecosystem to PURL type.
    fn ecosystem_to_purl(ecosystem: Ecosystem) -> &'static str {
        match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "pypi",
            Ecosystem::Crates => "cargo",
            Ecosystem::Go => "golang",
            Ecosystem::Maven => "maven",
            Ecosystem::Url => "generic", // URL dependencies use generic PURL type
        }
    }
}

impl Default for Auditor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratons_core::ContentHash;
    use cratons_lockfile::LockedPackage;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_test_lockfile() -> Lockfile {
        let mut lockfile = Lockfile::new(ContentHash::blake3("test".to_string()));
        lockfile.packages.push(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.20".to_string(),
            ecosystem: Ecosystem::Npm,
            source: "registry".to_string(),
            integrity: "sha256-123".to_string(),
            resolved_hash: ContentHash::blake3("lodash".to_string()),
            direct: true,
            features: Vec::new(),
            dependencies: Vec::new(),
        });
        lockfile
    }

    #[tokio::test]
    async fn test_audit_with_mock_server() {
        let mock_server = MockServer::start().await;

        // Mock the batch query endpoint
        Mock::given(method("POST"))
            .and(path("/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{
                    "vulns": [{
                        "id": "GHSA-test-1234",
                        "summary": "Test vulnerability",
                        "details": "This is a test vulnerability",
                        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                        "affected": [{
                            "package": {"name": "lodash", "ecosystem": "npm"},
                            "ranges": [{
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "4.17.21"}
                                ]
                            }]
                        }],
                        "references": [{
                            "type": "ADVISORY",
                            "url": "https://github.com/advisories/GHSA-test-1234"
                        }]
                    }]
                }]
            })))
            .mount(&mock_server)
            .await;

        let auditor = Auditor::with_api_url(&mock_server.uri());
        let lockfile = create_test_lockfile();

        let result = auditor.audit(&lockfile).await.unwrap();

        assert_eq!(result.packages_audited, 1);
        assert_eq!(result.vulnerabilities.len(), 1);
        assert_eq!(result.vulnerabilities[0].id, "GHSA-test-1234");
        assert_eq!(result.vulnerabilities[0].package, "lodash");
        assert_eq!(result.vulnerabilities[0].severity, Severity::High);
        assert_eq!(
            result.vulnerabilities[0].fixed_version,
            Some("4.17.21".to_string())
        );
    }

    #[tokio::test]
    async fn test_audit_no_vulnerabilities() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{
                    "vulns": []
                }]
            })))
            .mount(&mock_server)
            .await;

        let auditor = Auditor::with_api_url(&mock_server.uri());
        let lockfile = create_test_lockfile();

        let result = auditor.audit(&lockfile).await.unwrap();

        assert_eq!(result.packages_audited, 1);
        assert!(result.vulnerabilities.is_empty());
        assert!(result.passed(Severity::Low));
    }

    #[tokio::test]
    async fn test_audit_empty_lockfile() {
        let auditor = Auditor::new();
        let lockfile = Lockfile::new(ContentHash::blake3("empty".to_string()));

        let result = auditor.audit(&lockfile).await.unwrap();

        assert_eq!(result.packages_audited, 0);
        assert!(result.vulnerabilities.is_empty());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(Severity::from_cvss_score(9.5), Severity::Critical);
        assert_eq!(Severity::from_cvss_score(8.0), Severity::High);
        assert_eq!(Severity::from_cvss_score(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss_score(2.0), Severity::Low);
    }

    #[test]
    fn test_severity_from_osv() {
        assert_eq!(Severity::from_osv("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::from_osv("HIGH"), Severity::High);
        assert_eq!(Severity::from_osv("MODERATE"), Severity::Medium);
        assert_eq!(Severity::from_osv("MEDIUM"), Severity::Medium);
        assert_eq!(Severity::from_osv("LOW"), Severity::Low);
        assert_eq!(Severity::from_osv("unknown"), Severity::Low);
    }

    #[test]
    fn test_ecosystem_mapping() {
        assert_eq!(Auditor::ecosystem_to_osv(Ecosystem::Npm), "npm");
        assert_eq!(Auditor::ecosystem_to_osv(Ecosystem::PyPi), "PyPI");
        assert_eq!(Auditor::ecosystem_to_osv(Ecosystem::Crates), "crates.io");
        assert_eq!(Auditor::ecosystem_to_osv(Ecosystem::Go), "Go");
        assert_eq!(Auditor::ecosystem_to_osv(Ecosystem::Maven), "Maven");
    }

    #[test]
    fn test_generate_sbom() {
        let auditor = Auditor::new();
        let lockfile = create_test_lockfile();

        let sbom_json = auditor.generate_sbom(&lockfile).unwrap();
        let sbom: serde_json::Value = serde_json::from_str(&sbom_json).unwrap();

        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.4");
        assert_eq!(sbom["components"][0]["name"], "lodash");
        assert_eq!(sbom["components"][0]["version"], "4.17.20");
        assert!(
            sbom["components"][0]["purl"]
                .as_str()
                .unwrap()
                .contains("npm/lodash@4.17.20")
        );
    }

    #[test]
    fn test_count_by_severity() {
        let result = AuditResult {
            packages_audited: 3,
            vulnerabilities: vec![
                Vulnerability {
                    id: "CVE-1".to_string(),
                    package: "a".to_string(),
                    ecosystem: Ecosystem::Npm,
                    affected_versions: "*".to_string(),
                    fixed_version: None,
                    title: "Test".to_string(),
                    description: "".to_string(),
                    severity: Severity::Critical,
                    cve: None,
                    url: None,
                },
                Vulnerability {
                    id: "CVE-2".to_string(),
                    package: "b".to_string(),
                    ecosystem: Ecosystem::Npm,
                    affected_versions: "*".to_string(),
                    fixed_version: None,
                    title: "Test".to_string(),
                    description: "".to_string(),
                    severity: Severity::High,
                    cve: None,
                    url: None,
                },
                Vulnerability {
                    id: "CVE-3".to_string(),
                    package: "c".to_string(),
                    ecosystem: Ecosystem::Npm,
                    affected_versions: "*".to_string(),
                    fixed_version: None,
                    title: "Test".to_string(),
                    description: "".to_string(),
                    severity: Severity::High,
                    cve: None,
                    url: None,
                },
            ],
            failed_packages: Vec::new(),
        };

        let counts = result.count_by_severity();
        assert_eq!(counts.get(&Severity::Critical), Some(&1));
        assert_eq!(counts.get(&Severity::High), Some(&2));
        assert_eq!(counts.get(&Severity::Medium), None);
    }

    #[test]
    fn test_vulnerabilities_above() {
        let result = AuditResult {
            packages_audited: 2,
            vulnerabilities: vec![
                Vulnerability {
                    id: "CVE-1".to_string(),
                    package: "a".to_string(),
                    ecosystem: Ecosystem::Npm,
                    affected_versions: "*".to_string(),
                    fixed_version: None,
                    title: "Test".to_string(),
                    description: "".to_string(),
                    severity: Severity::Low,
                    cve: None,
                    url: None,
                },
                Vulnerability {
                    id: "CVE-2".to_string(),
                    package: "b".to_string(),
                    ecosystem: Ecosystem::Npm,
                    affected_versions: "*".to_string(),
                    fixed_version: None,
                    title: "Test".to_string(),
                    description: "".to_string(),
                    severity: Severity::High,
                    cve: None,
                    url: None,
                },
            ],
            failed_packages: Vec::new(),
        };

        assert_eq!(result.vulnerabilities_above(Severity::High).len(), 1);
        assert_eq!(result.vulnerabilities_above(Severity::Medium).len(), 1);
        assert_eq!(result.vulnerabilities_above(Severity::Low).len(), 2);
        assert!(result.passed(Severity::Critical));
        assert!(!result.passed(Severity::High));
    }
}
