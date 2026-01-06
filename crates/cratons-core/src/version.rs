//! Version types and requirements.
//!
//! Cratons supports multiple versioning schemes across ecosystems:
//! - Semantic versioning (npm, Cargo, Go)
//! - PEP 440 (Python)
//! - Maven versioning (Java)

use pep440_rs::{Version as Pep440Version, VersionSpecifiers};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use crate::ecosystem::Ecosystem;
use crate::error::{CratonsError, Result};

/// A parsed version number.
///
/// This enum represents versions across multiple ecosystems while maintaining
/// efficient string representation for display purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Version {
    /// Semantic version (major.minor.patch)
    /// We store both the parsed version and its string representation
    /// to avoid allocations on as_str() calls.
    Semver(#[serde(with = "semver_with_string")] SemverWithString),
    /// PEP 440 version (Python)
    Pep440(String),
    /// Maven version
    Maven(String),
    /// Raw version string (fallback)
    Raw(String),
}

/// A semver::Version paired with its string representation to avoid allocations.
#[derive(Debug, Clone)]
pub struct SemverWithString {
    version: semver::Version,
    string: String,
}

impl SemverWithString {
    /// Create a new SemverWithString from a parsed version.
    #[must_use]
    pub fn new(version: semver::Version) -> Self {
        let string = version.to_string();
        Self { version, string }
    }

    /// Get the underlying semver::Version.
    #[must_use]
    pub const fn version(&self) -> &semver::Version {
        &self.version
    }

    /// Get the string representation without allocation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.string
    }
}

impl PartialEq for SemverWithString {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl Eq for SemverWithString {}

impl std::hash::Hash for SemverWithString {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.version.hash(state);
    }
}

impl PartialOrd for SemverWithString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemverWithString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.version.cmp(&other.version)
    }
}

/// Custom serde module for SemverWithString that serializes as just the version string.
mod semver_with_string {
    use super::SemverWithString;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &SemverWithString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.string.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SemverWithString, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let version = semver::Version::parse(&s).map_err(serde::de::Error::custom)?;
        Ok(SemverWithString::new(version))
    }
}

impl Version {
    /// Parse a version string for a specific ecosystem.
    ///
    /// # Errors
    ///
    /// Returns an error if the version string cannot be parsed for the given ecosystem.
    pub fn parse(s: &str, ecosystem: Ecosystem) -> Result<Self> {
        match ecosystem {
            Ecosystem::Npm | Ecosystem::Crates => {
                // Try semver first
                if let Ok(v) = semver::Version::parse(s) {
                    return Ok(Self::Semver(SemverWithString::new(v)));
                }
                // npm allows versions without patch (1.0 -> 1.0.0)
                if ecosystem == Ecosystem::Npm {
                    if let Ok(v) = semver::Version::parse(&format!("{s}.0")) {
                        return Ok(Self::Semver(SemverWithString::new(v)));
                    }
                    if let Ok(v) = semver::Version::parse(&format!("{s}.0.0")) {
                        return Ok(Self::Semver(SemverWithString::new(v)));
                    }
                }
                Ok(Self::Raw(s.to_string()))
            }
            Ecosystem::Go => {
                // Go versions are prefixed with 'v'
                let version_str = s.strip_prefix('v').unwrap_or(s);
                if let Ok(v) = semver::Version::parse(version_str) {
                    return Ok(Self::Semver(SemverWithString::new(v)));
                }
                Ok(Self::Raw(s.to_string()))
            }
            Ecosystem::PyPi => Ok(Self::Pep440(s.to_string())),
            Ecosystem::Maven => Ok(Self::Maven(s.to_string())),
            Ecosystem::Url => Ok(Self::Raw(s.to_string())),
        }
    }

    /// Get the version as a string without allocation.
    ///
    /// This method returns a borrowed string slice, avoiding memory allocation
    /// for repeated calls.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Semver(v) => v.as_str(),
            Self::Pep440(s) | Self::Maven(s) | Self::Raw(s) => s,
        }
    }

    /// Check if this is a prerelease version.
    #[must_use]
    pub fn is_prerelease(&self) -> bool {
        match self {
            Self::Semver(v) => !v.version().pre.is_empty(),
            Self::Pep440(s) => {
                s.contains('a') || s.contains('b') || s.contains("rc") || s.contains("dev")
            }
            Self::Maven(s) => {
                let lower = s.to_lowercase();
                lower.contains("snapshot")
                    || lower.contains("alpha")
                    || lower.contains("beta")
                    || lower.contains("rc")
            }
            Self::Raw(_) => false,
        }
    }

    /// Get the underlying semver::Version if this is a Semver variant.
    #[must_use]
    pub fn as_semver(&self) -> Option<&semver::Version> {
        match self {
            Self::Semver(v) => Some(v.version()),
            _ => None,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Semver(v) => write!(f, "{}", v.as_str()),
            Self::Pep440(s) | Self::Maven(s) | Self::Raw(s) => write!(f, "{s}"),
        }
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Semver(a), Self::Semver(b)) => a.version() == b.version(),
            (Self::Pep440(a), Self::Pep440(b)) => a == b,
            (Self::Maven(a), Self::Maven(b)) => a == b,
            (Self::Raw(a), Self::Raw(b)) => a == b,
            _ => false, // Different types are not equal
        }
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare by variant, using explicit ordering for cross-type comparison
        // This avoids allocation from format!("{:?}", discriminant)
        fn variant_order(v: &Version) -> u8 {
            match v {
                Version::Semver(_) => 0,
                Version::Pep440(_) => 1,
                Version::Maven(_) => 2,
                Version::Raw(_) => 3,
            }
        }

        let self_order = variant_order(self);
        let other_order = variant_order(other);

        if self_order != other_order {
            return self_order.cmp(&other_order);
        }

        // Same type - compare values
        match (self, other) {
            (Self::Semver(a), Self::Semver(b)) => a.version().cmp(b.version()),
            (Self::Pep440(a), Self::Pep440(b)) => {
                // Use pep440_rs for proper version comparison
                match (Pep440Version::from_str(a), Pep440Version::from_str(b)) {
                    (Ok(va), Ok(vb)) => va.cmp(&vb),
                    (Ok(_), Err(_)) => Ordering::Less, // Valid versions come before invalid
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => a.cmp(b), // Both invalid - use string comparison
                }
            }
            (Self::Maven(a), Self::Maven(b)) => compare_maven_versions(a, b),
            (Self::Raw(a), Self::Raw(b)) => a.cmp(b),
            // This should never happen due to variant_order check above
            _ => Ordering::Equal,
        }
    }
}

/// Compare Maven versions properly.
/// Maven versions follow: major.minor.incremental-qualifier
/// where qualifier ordering is: alpha < beta < milestone < rc < snapshot < "" < sp
fn compare_maven_versions(a: &str, b: &str) -> Ordering {
    // Strip qualifiers for base comparison
    let (a_base, a_qual) = split_maven_version(a);
    let (b_base, b_qual) = split_maven_version(b);

    // Compare base versions numerically
    let a_parts: Vec<u64> = a_base.split('.').filter_map(|s| s.parse().ok()).collect();
    let b_parts: Vec<u64> = b_base.split('.').filter_map(|s| s.parse().ok()).collect();

    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        let cmp = ap.cmp(bp);
        if cmp != Ordering::Equal {
            return cmp;
        }
    }

    // If base parts are equal but different lengths, longer is greater
    match a_parts.len().cmp(&b_parts.len()) {
        Ordering::Equal => {}
        other => return other,
    }

    // Compare qualifiers
    maven_qualifier_order(a_qual).cmp(&maven_qualifier_order(b_qual))
}

fn split_maven_version(v: &str) -> (&str, &str) {
    if let Some(idx) = v.find('-') {
        (&v[..idx], &v[idx + 1..])
    } else {
        (v, "")
    }
}

fn maven_qualifier_order(qual: &str) -> i32 {
    let qual_lower = qual.to_lowercase();
    if qual_lower.is_empty() {
        return 50; // Release versions
    }
    if qual_lower.starts_with("alpha") || qual_lower == "a" {
        return 10;
    }
    if qual_lower.starts_with("beta") || qual_lower == "b" {
        return 20;
    }
    if qual_lower.starts_with("milestone") || qual_lower == "m" {
        return 25;
    }
    if qual_lower.starts_with("rc") || qual_lower.starts_with("cr") {
        return 30;
    }
    if qual_lower.contains("snapshot") {
        return 40;
    }
    if qual_lower.starts_with("sp") {
        return 60; // Service packs come after release
    }
    45 // Unknown qualifiers between snapshot and release
}

impl std::hash::Hash for Version {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_string().hash(state);
    }
}

/// A version requirement/constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VersionReq {
    /// Semver requirement (e.g., "^1.0.0", ">=1.2.3")
    Semver(semver::VersionReq),
    /// npm-style requirement (may differ slightly from Cargo semver)
    Npm(String),
    /// PEP 440 requirement (e.g., ">=1.0,<2.0")
    Pep440(String),
    /// Exact version pin
    Exact(String),
    /// Any version
    Any,
}

impl VersionReq {
    /// Parse a version requirement for a specific ecosystem.
    pub fn parse(s: &str, ecosystem: Ecosystem) -> Result<Self> {
        let s = s.trim();

        if s == "*" || s.is_empty() {
            return Ok(Self::Any);
        }

        match ecosystem {
            Ecosystem::Crates => semver::VersionReq::parse(s).map(Self::Semver).map_err(|e| {
                CratonsError::InvalidVersionSimple(format!("Invalid version requirement: {e}"))
            }),
            Ecosystem::Npm => {
                // npm has slightly different semver semantics
                // For now, store as string and use node-semver for matching
                Ok(Self::Npm(s.to_string()))
            }
            Ecosystem::Go => {
                // Go uses semver but with 'v' prefix
                let version_str = s.strip_prefix('v').unwrap_or(s);
                semver::VersionReq::parse(version_str)
                    .map(Self::Semver)
                    .map_err(|e| {
                        CratonsError::InvalidVersionSimple(format!(
                            "Invalid version requirement: {e}"
                        ))
                    })
            }
            Ecosystem::PyPi => Ok(Self::Pep440(s.to_string())),
            Ecosystem::Maven | Ecosystem::Url => Ok(Self::Exact(s.to_string())),
        }
    }

    /// Check if a version matches this requirement.
    #[must_use]
    pub fn matches(&self, version: &Version) -> bool {
        match (self, version) {
            (Self::Any, _) => true,
            (Self::Semver(req), Version::Semver(ver)) => req.matches(ver.version()),
            (Self::Npm(req), Version::Semver(ver)) => {
                // Use node-semver for npm compatibility
                let Ok(range) = node_semver::Range::parse(req) else {
                    return false;
                };
                let Ok(node_ver) = node_semver::Version::parse(ver.as_str()) else {
                    return false;
                };
                range.satisfies(&node_ver)
            }
            (Self::Exact(req), ver) => req == &ver.to_string(),
            (Self::Pep440(req), Version::Pep440(ver)) => {
                // Use pep440_rs for proper PEP 440 specifier matching
                let Ok(parsed_ver) = Pep440Version::from_str(ver) else {
                    return false;
                };

                // Handle common cases
                let req_trimmed = req.trim();

                // No constraint or wildcard
                if req_trimmed.is_empty() || req_trimmed == "*" {
                    return true;
                }

                // Try to parse as version specifiers (e.g., ">=1.0,<2.0")
                if let Ok(specifiers) = VersionSpecifiers::from_str(req_trimmed) {
                    return specifiers.contains(&parsed_ver);
                }

                // If it looks like a bare version, treat as exact match
                if !req_trimmed
                    .starts_with(|c: char| c == '>' || c == '<' || c == '=' || c == '!' || c == '~')
                {
                    // Bare version string - treat as ==
                    if let Ok(req_ver) = Pep440Version::from_str(req_trimmed) {
                        return parsed_ver == req_ver;
                    }
                }

                // Fallback: if we can't parse the specifier, don't match
                false
            }
            _ => false,
        }
    }
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Semver(v) => write!(f, "{v}"),
            Self::Npm(s) | Self::Pep440(s) | Self::Exact(s) => write!(f, "{s}"),
            Self::Any => write!(f, "*"),
        }
    }
}

impl FromStr for VersionReq {
    type Err = CratonsError;

    fn from_str(s: &str) -> Result<Self> {
        // Default to Crates/semver style
        Self::parse(s, Ecosystem::Crates)
    }
}

impl Default for VersionReq {
    fn default() -> Self {
        Self::Any
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_version() {
        let v = Version::parse("1.2.3", Ecosystem::Crates).unwrap();
        assert!(matches!(v, Version::Semver(_)));
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_go_version() {
        let v = Version::parse("v1.2.3", Ecosystem::Go).unwrap();
        assert!(matches!(v, Version::Semver(_)));
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_version_req_matches() {
        let req = VersionReq::parse("^1.0.0", Ecosystem::Crates).unwrap();
        let v1 = Version::parse("1.2.3", Ecosystem::Crates).unwrap();
        let v2 = Version::parse("2.0.0", Ecosystem::Crates).unwrap();

        assert!(req.matches(&v1));
        assert!(!req.matches(&v2));
    }

    #[test]
    fn test_any_version_req() {
        let req = VersionReq::parse("*", Ecosystem::Crates).unwrap();
        let v = Version::parse("99.99.99", Ecosystem::Crates).unwrap();
        assert!(req.matches(&v));
    }
}
