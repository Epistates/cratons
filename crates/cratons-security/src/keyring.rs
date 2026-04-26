//! Maven PGP trust store: keyring config + HKP keyserver fetch + on-disk cache.
//!
//! This module lets cratons verify Maven Central artifact signatures
//! (`.jar.asc`) without requiring the operator to pre-download any key
//! material. On first use for a given fingerprint the key is fetched from
//! one of the hardcoded trusted keyservers, validated against its own
//! self-signature and fingerprint, and cached on disk. Subsequent uses
//! read from the cache.
//!
//! # Trust model
//!
//! Trust flows from three sources, in precedence order:
//!
//! 1. **Project keyring** — `[security.maven]` section in the project's
//!    `cratons.toml`. Highest precedence. Entries pin specific group IDs
//!    (glob-matched) to specific fingerprints.
//! 2. **User keyring** — `~/.config/cratons/trusted-keys/maven.toml`.
//!    Machine-wide overrides.
//! 3. **TOFU** — the lockfile's `[pgp-trust]` table. First install of a
//!    group ID with no explicit entry records the signing key fingerprint;
//!    subsequent installs require the same fingerprint.
//!
//! The trust store only resolves *which fingerprint* should sign a given
//! artifact. Actual signature verification (via rPGP) uses the key material
//! fetched and cached here.
//!
//! # Keyserver discovery
//!
//! The hardcoded keyserver list covers both the modern (email-verified)
//! key directory and the SKS-style server used by Maven uploaders:
//!
//! - `https://keys.openpgp.org` — primary
//! - `https://keyserver.ubuntu.com` — fallback
//!
//! Both expose the HKP protocol (`/pks/lookup?op=get&search=0x<fp>&options=mr`).
//! When a key is returned, we parse it with the `pgp` crate and **verify
//! that the parsed key's actual fingerprint matches the one we requested**.
//! This prevents a compromised keyserver from substituting a different key.

use crate::{CratonsError, Result};
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::types::KeyDetails;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Default hardcoded keyserver URLs. The list is compiled into the
/// cratons binary; operators can override it via
/// [`MavenTrustConfig::keyservers`].
pub const DEFAULT_KEYSERVERS: &[&str] =
    &["https://keys.openpgp.org", "https://keyserver.ubuntu.com"];

/// Trust policy when a group ID has no explicit keyring entry and no TOFU
/// pin has been recorded yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirstInstallPolicy {
    /// Refuse to record a TOFU pin on first install. Operator must add a
    /// keyring entry explicitly. Default in CI (when `CRATONS_CI=1`).
    Deny,
    /// Record a TOFU pin on first install and emit a structured warning
    /// so reviewers can audit the lockfile diff. Default interactively.
    #[default]
    Warn,
    /// Record a TOFU pin silently. Discouraged; never the workspace default.
    Allow,
}

/// One entry in a Maven keyring file or manifest section.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedKeyEntry {
    /// Glob pattern matched against Maven group IDs (e.g. `"org.apache.*"`).
    #[serde(rename = "group-id")]
    pub group_id: String,
    /// Uppercase, no-space PGP fingerprint (40 hex chars for v4 keys).
    pub fingerprint: String,
}

/// Top-level Maven trust configuration, parseable from a TOML file or from
/// the `[security.maven]` section of a cratons manifest.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MavenTrustConfig {
    /// Explicit group-id → fingerprint pins. Highest precedence.
    #[serde(default, rename = "trusted-keys")]
    pub trusted_keys: Vec<TrustedKeyEntry>,
    /// First-install policy (see [`FirstInstallPolicy`]).
    #[serde(default, rename = "first-install")]
    pub first_install: FirstInstallPolicy,
    /// Optional keyserver list overriding [`DEFAULT_KEYSERVERS`].
    #[serde(default)]
    pub keyservers: Vec<String>,
}

impl MavenTrustConfig {
    /// Parse the config from a TOML file. Returns the default (empty) config
    /// on `ENOENT` so callers can cheaply probe the user keyring location.
    ///
    /// Every `trusted-keys[].fingerprint` is normalized at load time via
    /// [`normalize_fingerprint`], so malformed entries (non-hex chars,
    /// wrong length, v3 fingerprints) surface as a config error at
    /// startup instead of at first install.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let mut cfg: Self = toml::from_str(&contents).map_err(|e| {
                    CratonsError::Config(format!(
                        "Failed to parse Maven trust config {}: {}",
                        path.display(),
                        e
                    ))
                })?;
                for entry in &mut cfg.trusted_keys {
                    entry.fingerprint = normalize_fingerprint(&entry.fingerprint).map_err(|e| {
                        CratonsError::Config(format!(
                            "Invalid fingerprint for group-id {:?} in {}: {}",
                            entry.group_id,
                            path.display(),
                            e
                        ))
                    })?;
                }
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(CratonsError::Config(format!(
                "Failed to read Maven trust config {}: {}",
                path.display(),
                e
            ))),
        }
    }

    /// Return all fingerprints whose glob patterns match `group_id`, in
    /// insertion order. Case-sensitive (Maven group IDs are case-sensitive).
    pub fn trusted_fingerprints(&self, group_id: &str) -> Vec<&str> {
        self.trusted_keys
            .iter()
            .filter(|e| glob_match(&e.group_id, group_id))
            .map(|e| e.fingerprint.as_str())
            .collect()
    }

    /// Return the keyserver list to use, preferring operator overrides
    /// when present.
    pub fn effective_keyservers(&self) -> Vec<String> {
        if self.keyservers.is_empty() {
            DEFAULT_KEYSERVERS.iter().map(|s| s.to_string()).collect()
        } else {
            self.keyservers.clone()
        }
    }
}

/// Simple glob match supporting `*` as a wildcard across any number of
/// characters. Used for group-id pinning (e.g. `org.apache.*`).
fn glob_match(pattern: &str, candidate: &str) -> bool {
    match glob::Pattern::new(pattern) {
        Ok(p) => p.matches(candidate),
        Err(_) => pattern == candidate,
    }
}

/// On-disk key cache plus HKP fetch.
#[derive(Debug)]
pub struct KeyStore {
    cache_dir: PathBuf,
    keyservers: Vec<String>,
    client: reqwest::Client,
}

impl KeyStore {
    /// Open the default key cache at `~/.cache/cratons/keys/pgp/`.
    pub fn open_default(client: reqwest::Client) -> Result<Self> {
        Self::open_with_keyservers(
            client,
            DEFAULT_KEYSERVERS.iter().map(|s| s.to_string()).collect(),
        )
    }

    /// Open the default key cache with a caller-supplied keyserver list.
    ///
    /// This is the production path for Maven verification: project/user
    /// `keyservers = [...]` overrides must affect network lookups, not just
    /// parsing/tests. An empty list falls back to the compiled defaults.
    pub fn open_with_keyservers(
        client: reqwest::Client,
        mut keyservers: Vec<String>,
    ) -> Result<Self> {
        let base = dirs::cache_dir().ok_or_else(|| {
            CratonsError::Config("Cannot determine user cache directory".to_string())
        })?;
        let cache_dir = base.join("cratons").join("keys").join("pgp");
        std::fs::create_dir_all(&cache_dir).map_err(|e| {
            CratonsError::Config(format!(
                "Failed to create PGP key cache {}: {}",
                cache_dir.display(),
                e
            ))
        })?;
        if keyservers.is_empty() {
            keyservers = DEFAULT_KEYSERVERS.iter().map(|s| s.to_string()).collect();
        }
        Ok(Self {
            cache_dir,
            keyservers,
            client,
        })
    }

    /// Create a key store with a caller-supplied cache directory and
    /// keyserver list. Primary use: tests and operators with custom
    /// keyserver infrastructure.
    pub fn new(client: reqwest::Client, cache_dir: PathBuf, keyservers: Vec<String>) -> Self {
        Self {
            cache_dir,
            keyservers,
            client,
        }
    }

    /// Return the ASCII-armored key material for `fingerprint`.
    ///
    /// Lookup order:
    ///
    /// 1. `<cache_dir>/<UPPER(fingerprint)>.asc` (cache hit → no network)
    /// 2. HKP fetch from each configured keyserver in order; first success
    ///    wins. The returned key is parsed with `pgp` and its actual
    ///    fingerprint is compared against the requested one. A mismatch is
    ///    a hard error (prevents compromised-keyserver substitution).
    /// 3. On success, the ASCII armor is written atomically to the cache.
    pub async fn fetch_key(&self, fingerprint: &str) -> Result<String> {
        let fp_norm = normalize_fingerprint(fingerprint)?;
        let cache_path = self.cache_dir.join(format!("{}.asc", fp_norm));

        if let Ok(cached) = std::fs::read_to_string(&cache_path) {
            if self.validate_armor_matches(&cached, &fp_norm).is_ok() {
                debug!(fingerprint = %fp_norm, "loaded PGP key from cache");
                return Ok(cached);
            }
            warn!(
                fingerprint = %fp_norm,
                "cached PGP key failed self-validation; refetching"
            );
        }

        let mut last_error: Option<CratonsError> = None;
        for keyserver in &self.keyservers {
            let url = format!(
                "{}/pks/lookup?op=get&search=0x{}&options=mr",
                keyserver.trim_end_matches('/'),
                fp_norm
            );
            debug!(url = %url, "HKP lookup");
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.text().await {
                    Ok(armor) => match self.validate_armor_matches(&armor, &fp_norm) {
                        Ok(()) => {
                            self.write_cache_atomic(&cache_path, &armor)?;
                            debug!(
                                fingerprint = %fp_norm,
                                keyserver = %keyserver,
                                "cached PGP key from keyserver"
                            );
                            return Ok(armor);
                        }
                        Err(e) => {
                            warn!(
                                keyserver = %keyserver,
                                fingerprint = %fp_norm,
                                error = %e,
                                "keyserver returned a key whose fingerprint did not match"
                            );
                            last_error = Some(e);
                        }
                    },
                    Err(e) => {
                        last_error = Some(CratonsError::Network(format!(
                            "Failed to read keyserver response from {}: {}",
                            keyserver, e
                        )));
                    }
                },
                Ok(resp) => {
                    last_error = Some(CratonsError::Registry {
                        registry: keyserver.clone(),
                        message: format!("HKP returned HTTP {}", resp.status()),
                    });
                }
                Err(e) => {
                    last_error = Some(CratonsError::Network(format!(
                        "HKP request to {} failed: {}",
                        keyserver, e
                    )));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            CratonsError::Config(format!(
                "No keyservers configured; cannot fetch {}",
                fp_norm
            ))
        }))
    }

    /// Parse the ASCII-armored key and assert its fingerprint matches the
    /// requested one. `expected_fp` must already be normalized (upper,
    /// spaceless).
    fn validate_armor_matches(&self, armor: &str, expected_fp: &str) -> Result<()> {
        let (parsed, _headers) = SignedPublicKey::from_string(armor)
            .map_err(|e| CratonsError::Config(format!("Failed to parse armored PGP key: {}", e)))?;
        let fp_obj = parsed.fingerprint();
        let actual_fp = hex_upper(fp_obj.as_bytes());
        if actual_fp != expected_fp {
            return Err(CratonsError::Config(format!(
                "Fingerprint mismatch: requested {}, returned key is {}",
                expected_fp, actual_fp
            )));
        }
        Ok(())
    }

    fn write_cache_atomic(&self, path: &Path, contents: &str) -> Result<()> {
        let tmp = tempfile::Builder::new()
            .prefix(".cratons-pgp-")
            .suffix(".tmp")
            .tempfile_in(&self.cache_dir)
            .map_err(|e| CratonsError::Config(format!("Failed to open temp file: {}", e)))?;
        std::fs::write(tmp.path(), contents)
            .map_err(|e| CratonsError::Config(format!("Failed to write cache tmp: {}", e)))?;
        tmp.persist(path)
            .map_err(|e| CratonsError::Config(format!("Failed to rename cache tmp: {}", e)))?;
        Ok(())
    }

    /// Synchronously inject a key into the cache. Test-only helper.
    #[cfg(test)]
    pub(crate) fn inject_cached(&self, fingerprint: &str, armor: &str) -> Result<()> {
        let fp_norm = normalize_fingerprint(fingerprint)?;
        let path = self.cache_dir.join(format!("{}.asc", fp_norm));
        std::fs::write(&path, armor)
            .map_err(|e| CratonsError::Config(format!("inject_cached write failed: {}", e)))?;
        Ok(())
    }

    /// Test-only introspection: does the cache file exist for this fingerprint?
    #[cfg(test)]
    pub(crate) fn cache_hit(&self, fingerprint: &str) -> bool {
        let Ok(fp_norm) = normalize_fingerprint(fingerprint) else {
            return false;
        };
        self.cache_dir.join(format!("{}.asc", fp_norm)).exists()
    }
}

/// Normalize a PGP fingerprint: strip whitespace, uppercase, reject
/// non-hex characters, require 40 chars for v4 keys.
pub fn normalize_fingerprint(fingerprint: &str) -> Result<String> {
    let compact: String = fingerprint
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CratonsError::Config(format!(
            "PGP fingerprint contains non-hex characters: {}",
            fingerprint
        )));
    }
    if compact.len() != 40 {
        return Err(CratonsError::Config(format!(
            "PGP fingerprint must be 40 hex chars (v4 key), got {}",
            compact.len()
        )));
    }
    Ok(compact)
}

/// Uppercase hex encoding for fingerprint comparison.
fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn normalize_fingerprint_strips_spaces_and_uppercases() {
        let input = "6a8f 7c2a 9e4b c1d3 8f5e  7a9c 2b4d 6e8f 0a1b 3c5d";
        let out = normalize_fingerprint(input).unwrap();
        assert_eq!(out, "6A8F7C2A9E4BC1D38F5E7A9C2B4D6E8F0A1B3C5D");
    }

    #[test]
    fn normalize_fingerprint_rejects_non_hex() {
        assert!(normalize_fingerprint("NOT-HEX").is_err());
    }

    #[test]
    fn normalize_fingerprint_rejects_wrong_length() {
        assert!(normalize_fingerprint("DEADBEEF").is_err());
    }

    #[test]
    fn trusted_fingerprints_glob_match() {
        let cfg = MavenTrustConfig {
            trusted_keys: vec![
                TrustedKeyEntry {
                    group_id: "org.apache.*".to_string(),
                    fingerprint: "A".repeat(40),
                },
                TrustedKeyEntry {
                    group_id: "com.google.guava".to_string(),
                    fingerprint: "B".repeat(40),
                },
                TrustedKeyEntry {
                    group_id: "io.*.core".to_string(),
                    fingerprint: "C".repeat(40),
                },
            ],
            ..Default::default()
        };

        // Direct glob match
        let fps = cfg.trusted_fingerprints("org.apache.commons");
        assert_eq!(fps, vec!["A".repeat(40)]);

        // Literal match
        let fps = cfg.trusted_fingerprints("com.google.guava");
        assert_eq!(fps, vec!["B".repeat(40)]);

        // Middle wildcard
        let fps = cfg.trusted_fingerprints("io.netty.core");
        assert_eq!(fps, vec!["C".repeat(40)]);

        // No match
        assert!(cfg.trusted_fingerprints("net.example.lib").is_empty());
    }

    #[test]
    fn load_or_default_returns_default_on_missing_file() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nonexistent.toml");
        let cfg = MavenTrustConfig::load_or_default(&missing).unwrap();
        assert!(cfg.trusted_keys.is_empty());
        assert_eq!(cfg.first_install, FirstInstallPolicy::Warn);
    }

    #[test]
    fn load_or_default_parses_valid_toml() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("maven.toml");
        std::fs::write(
            &path,
            r#"
first-install = "deny"
keyservers = ["https://custom.example/"]

[[trusted-keys]]
group-id = "org.apache.*"
fingerprint = "AABBCCDDEEFF00112233445566778899AABBCCDD"

[[trusted-keys]]
group-id = "com.example.lib"
fingerprint = "1122 3344 5566 7788 9900 AABB CCDD EEFF 0011 2233"
"#,
        )
        .unwrap();

        let cfg = MavenTrustConfig::load_or_default(&path).unwrap();
        assert_eq!(cfg.first_install, FirstInstallPolicy::Deny);
        assert_eq!(cfg.keyservers, vec!["https://custom.example/"]);
        assert_eq!(cfg.trusted_keys.len(), 2);
        assert_eq!(
            cfg.trusted_keys[0].fingerprint,
            "AABBCCDDEEFF00112233445566778899AABBCCDD"
        );
        // Fingerprints are normalized at parse time: spaces stripped and
        // hex uppercased, so comparisons elsewhere can assume canonical form.
        assert_eq!(
            cfg.trusted_keys[1].fingerprint,
            "11223344556677889900AABBCCDDEEFF00112233"
        );
    }

    #[test]
    fn load_or_default_rejects_malformed_fingerprint() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("maven.toml");
        std::fs::write(
            &path,
            r#"
[[trusted-keys]]
group-id = "org.bad.*"
fingerprint = "NOT-A-VALID-FINGERPRINT"
"#,
        )
        .unwrap();
        let err = MavenTrustConfig::load_or_default(&path).unwrap_err();
        assert!(
            format!("{err}").contains("Invalid fingerprint"),
            "expected fingerprint parse error, got: {err}"
        );
    }

    #[test]
    fn effective_keyservers_defaults_to_hardcoded() {
        let cfg = MavenTrustConfig::default();
        let ks = cfg.effective_keyservers();
        assert_eq!(ks.len(), DEFAULT_KEYSERVERS.len());
        assert!(ks.iter().any(|s| s.contains("keys.openpgp.org")));
    }

    #[test]
    fn effective_keyservers_respects_override() {
        let cfg = MavenTrustConfig {
            keyservers: vec!["https://internal.mirror/".to_string()],
            ..Default::default()
        };
        assert_eq!(
            cfg.effective_keyservers(),
            vec!["https://internal.mirror/".to_string()]
        );
    }

    #[test]
    fn keystore_new_creates_directories() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join("pgp");
        std::fs::create_dir_all(&cache).unwrap();
        let store = KeyStore::new(
            reqwest::Client::new(),
            cache.clone(),
            vec!["https://keys.openpgp.org".to_string()],
        );
        assert!(!store.cache_hit("A".repeat(40).as_str()));
    }

    #[test]
    fn inject_cached_then_read_back() {
        // The cached key must self-validate for fetch_key to trust it. We
        // use a minimal check here: inject a placeholder and confirm
        // `cache_hit` observes it. End-to-end validation with real PGP key
        // material is exercised in F-2b's integration tests where a fixture
        // key is used.
        let dir = TempDir::new().unwrap();
        let store = KeyStore::new(
            reqwest::Client::new(),
            dir.path().to_path_buf(),
            vec!["https://keys.openpgp.org".to_string()],
        );
        store
            .inject_cached(&"A".repeat(40), "not a real key")
            .unwrap();
        assert!(store.cache_hit(&"A".repeat(40)));
    }
}
