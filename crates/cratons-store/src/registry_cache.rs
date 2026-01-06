//! Registry metadata cache for offline mode support.
//!
//! This module provides a disk-based cache for registry metadata (version lists
//! and package metadata) to enable offline resolution when network is unavailable.
//!
//! ## Cache Structure
//!
//! ```text
//! cache/registry/
//! ├── npm/
//! │   ├── lodash/
//! │   │   ├── versions.json        # List of available versions
//! │   │   └── 4.17.21/
//! │   │       └── metadata.json    # Full package metadata
//! │   └── ...
//! ├── pypi/
//! └── ...
//! ```

use fs2::FileExt;
use cratons_core::{Ecosystem, CratonsError, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{debug, trace, warn};

/// Default cache TTL: 24 hours.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Registry metadata cache.
pub struct RegistryCache {
    root: PathBuf,
    ttl: Duration,
}

/// Cached versions list for a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVersions {
    /// Package name
    pub name: String,
    /// Ecosystem
    pub ecosystem: String,
    /// List of available versions (sorted)
    pub versions: Vec<String>,
    /// When this cache entry was created
    pub cached_at: u64, // Unix timestamp
}

/// Cached peer dependency metadata (npm peerDependenciesMeta).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPeerDepMeta {
    /// Whether this peer dependency is optional.
    #[serde(default)]
    pub optional: bool,
}

/// Cached package metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMetadata {
    /// Package name
    pub name: String,
    /// Version
    pub version: String,
    /// Ecosystem
    pub ecosystem: String,
    /// Download URL
    pub dist_url: String,
    /// Integrity hash (algorithm:base64 format)
    pub integrity: String,
    /// Dependencies (name -> version requirement)
    pub dependencies: std::collections::HashMap<String, String>,
    /// Optional dependencies
    pub optional_dependencies: std::collections::HashMap<String, String>,
    /// Peer dependencies (npm-specific)
    pub peer_dependencies: std::collections::HashMap<String, String>,
    /// Peer dependency metadata (npm peerDependenciesMeta)
    #[serde(default)]
    pub peer_dependencies_meta: std::collections::HashMap<String, CachedPeerDepMeta>,
    /// Dev dependencies
    pub dev_dependencies: std::collections::HashMap<String, String>,
    /// Bundled dependencies (npm bundledDependencies/bundleDependencies)
    #[serde(default)]
    pub bundled_dependencies: Vec<String>,
    /// Features/extras enabled
    pub features: Vec<String>,
    /// When this cache entry was created
    pub cached_at: u64, // Unix timestamp
}

impl RegistryCache {
    /// Create a new registry cache at the specified directory.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            ttl: DEFAULT_CACHE_TTL,
        })
    }

    /// Create a cache with a custom TTL.
    pub fn with_ttl(root: impl Into<PathBuf>, ttl: Duration) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root, ttl })
    }

    /// Get the root directory of the cache.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get or fetch versions for a package.
    ///
    /// Returns cached versions if fresh, otherwise returns None.
    pub fn get_versions(&self, ecosystem: Ecosystem, name: &str) -> Option<Vec<String>> {
        let path = self.versions_path(ecosystem, name);
        self.read_cached::<CachedVersions>(&path)
            .map(|cached| cached.versions)
    }

    /// Store versions for a package.
    pub fn put_versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        versions: Vec<String>,
    ) -> Result<()> {
        let path = self.versions_path(ecosystem, name);

        let cached = CachedVersions {
            name: name.to_string(),
            ecosystem: ecosystem.to_string(),
            versions,
            cached_at: now_timestamp(),
        };

        self.write_cached(&path, &cached)
    }

    /// Get cached metadata for a package version.
    pub fn get_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Option<CachedMetadata> {
        let path = self.metadata_path(ecosystem, name, version);
        self.read_cached::<CachedMetadata>(&path)
    }

    /// Store metadata for a package version.
    pub fn put_metadata(&self, metadata: CachedMetadata) -> Result<()> {
        let ecosystem = metadata
            .ecosystem
            .parse::<Ecosystem>()
            .map_err(|e| CratonsError::Config(format!("Invalid ecosystem: {}", e)))?;
        let path = self.metadata_path(ecosystem, &metadata.name, &metadata.version);
        self.write_cached(&path, &metadata)
    }

    /// Check if versions cache is fresh (not expired).
    pub fn is_versions_fresh(&self, ecosystem: Ecosystem, name: &str) -> bool {
        let path = self.versions_path(ecosystem, name);
        self.is_cache_fresh(&path)
    }

    /// Check if metadata cache is fresh.
    pub fn is_metadata_fresh(&self, ecosystem: Ecosystem, name: &str, version: &str) -> bool {
        let path = self.metadata_path(ecosystem, name, version);
        self.is_cache_fresh(&path)
    }

    /// Invalidate versions cache for a package.
    pub fn invalidate_versions(&self, ecosystem: Ecosystem, name: &str) -> Result<()> {
        let path = self.versions_path(ecosystem, name);
        if path.exists() {
            fs::remove_file(&path)?;
            debug!("Invalidated versions cache for {}:{}", ecosystem, name);
        }
        Ok(())
    }

    /// Invalidate metadata cache for a package version.
    pub fn invalidate_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<()> {
        let path = self.metadata_path(ecosystem, name, version);
        if path.exists() {
            fs::remove_file(&path)?;
            debug!(
                "Invalidated metadata cache for {}:{}@{}",
                ecosystem, name, version
            );
        }
        Ok(())
    }

    /// Clear all cache entries for an ecosystem.
    pub fn clear_ecosystem(&self, ecosystem: Ecosystem) -> Result<()> {
        let path = self.root.join(ecosystem.to_string());
        if path.exists() {
            fs::remove_dir_all(&path)?;
            debug!("Cleared cache for ecosystem {}", ecosystem);
        }
        Ok(())
    }

    /// Clear entire cache.
    pub fn clear_all(&self) -> Result<()> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            }
        }
        debug!("Cleared entire registry cache");
        Ok(())
    }

    /// Get cache statistics.
    pub fn stats(&self) -> Result<CacheStats> {
        let mut stats = CacheStats::default();

        for ecosystem in Ecosystem::all() {
            let eco_path = self.root.join(ecosystem.to_string());
            if !eco_path.exists() {
                continue;
            }

            let (packages, versions, metadata_entries, size) = Self::count_directory(&eco_path)?;
            stats.total_packages += packages;
            stats.total_versions += versions;
            stats.total_metadata += metadata_entries;
            stats.total_size += size;
            stats.per_ecosystem.insert(
                *ecosystem,
                EcosystemStats {
                    packages,
                    versions,
                    metadata_entries,
                    size,
                },
            );
        }

        Ok(stats)
    }

    // === Private helpers ===

    fn versions_path(&self, ecosystem: Ecosystem, name: &str) -> PathBuf {
        // Sanitize package name for filesystem safety
        let safe_name = sanitize_package_name(name);
        self.root
            .join(ecosystem.to_string())
            .join(&safe_name)
            .join("versions.json")
    }

    fn metadata_path(&self, ecosystem: Ecosystem, name: &str, version: &str) -> PathBuf {
        let safe_name = sanitize_package_name(name);
        let safe_version = sanitize_version(version);
        self.root
            .join(ecosystem.to_string())
            .join(&safe_name)
            .join(&safe_version)
            .join("metadata.json")
    }

    fn read_cached<T: DeserializeOwned>(&self, path: &Path) -> Option<T> {
        if !path.exists() {
            trace!("Cache miss: {}", path.display());
            return None;
        }

        // Check freshness
        if !self.is_cache_fresh(path) {
            trace!("Cache expired: {}", path.display());
            return None;
        }

        // Read with shared lock
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to open cache file {}: {}", path.display(), e);
                return None;
            }
        };

        if let Err(e) = file.lock_shared() {
            warn!("Failed to acquire shared lock on {}: {}", path.display(), e);
            return None;
        }

        let mut content = String::new();
        let mut reader = std::io::BufReader::new(&file);
        if let Err(e) = reader.read_to_string(&mut content) {
            warn!("Failed to read cache file {}: {}", path.display(), e);
            return None;
        }

        // Unlock happens automatically when file is dropped

        match serde_json::from_str(&content) {
            Ok(data) => {
                trace!("Cache hit: {}", path.display());
                Some(data)
            }
            Err(e) => {
                warn!("Failed to parse cache file {}: {}", path.display(), e);
                None
            }
        }
    }

    fn write_cached<T: Serialize>(&self, path: &Path, data: &T) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(data)
            .map_err(|e| CratonsError::Config(format!("Failed to serialize cache data: {}", e)))?;

        // Write atomically via temp file with exclusive lock
        let temp_path = path.with_extension("json.tmp");

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;

        file.lock_exclusive()?;

        let mut writer = std::io::BufWriter::new(&file);
        writer.write_all(content.as_bytes())?;
        writer.flush()?;

        // Rename to final path (atomic on POSIX)
        fs::rename(&temp_path, path)?;

        trace!("Cached data at {}", path.display());
        Ok(())
    }

    fn is_cache_fresh(&self, path: &Path) -> bool {
        if !path.exists() {
            return false;
        }

        match path.metadata() {
            Ok(meta) => match meta.modified() {
                Ok(modified) => match SystemTime::now().duration_since(modified) {
                    Ok(age) => age < self.ttl,
                    Err(_) => true, // Future modification time? Treat as fresh.
                },
                Err(_) => true, // Can't get mtime, treat as fresh.
            },
            Err(_) => false,
        }
    }

    fn count_directory(path: &Path) -> Result<(usize, usize, usize, u64)> {
        let mut packages = 0usize;
        let mut versions = 0usize;
        let mut metadata = 0usize;
        let mut size = 0u64;

        for entry in walkdir::WalkDir::new(path) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let filename = entry.file_name().to_string_lossy();
                if filename == "versions.json" {
                    packages += 1;
                    versions += 1; // Each versions.json represents at least one version entry
                } else if filename == "metadata.json" {
                    metadata += 1;
                }
                size += entry.metadata()?.len();
            }
        }

        Ok((packages, versions, metadata, size))
    }
}

/// Sanitize package name for filesystem safety.
///
/// Handles scoped packages like @scope/name by replacing @ and / with safe chars.
fn sanitize_package_name(name: &str) -> String {
    name.replace('@', "_at_")
        .replace('/', "_")
        .replace('\\', "_")
        .replace(':', "_")
}

/// Sanitize version string for filesystem safety.
fn sanitize_version(version: &str) -> String {
    version
        .replace('/', "_")
        .replace('\\', "_")
        .replace(':', "_")
}

/// Get current Unix timestamp.
fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cache statistics.
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Total number of packages cached
    pub total_packages: usize,
    /// Total number of version lists cached
    pub total_versions: usize,
    /// Total number of metadata entries
    pub total_metadata: usize,
    /// Total size in bytes
    pub total_size: u64,
    /// Per-ecosystem breakdown
    pub per_ecosystem: std::collections::HashMap<Ecosystem, EcosystemStats>,
}

/// Per-ecosystem cache statistics.
#[derive(Debug, Default)]
pub struct EcosystemStats {
    /// Number of packages
    pub packages: usize,
    /// Number of version lists
    pub versions: usize,
    /// Number of metadata entries
    pub metadata_entries: usize,
    /// Size in bytes
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cache_versions() {
        let dir = tempdir().unwrap();
        let cache = RegistryCache::new(dir.path()).unwrap();

        let versions = vec![
            "1.0.0".to_string(),
            "1.1.0".to_string(),
            "2.0.0".to_string(),
        ];
        cache
            .put_versions(Ecosystem::Npm, "lodash", versions.clone())
            .unwrap();

        let retrieved = cache.get_versions(Ecosystem::Npm, "lodash").unwrap();
        assert_eq!(retrieved, versions);
    }

    #[test]
    fn test_cache_metadata() {
        let dir = tempdir().unwrap();
        let cache = RegistryCache::new(dir.path()).unwrap();

        let metadata = CachedMetadata {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: "npm".to_string(),
            dist_url: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string(),
            integrity: "sha512-test".to_string(),
            dependencies: std::collections::HashMap::new(),
            optional_dependencies: std::collections::HashMap::new(),
            peer_dependencies: std::collections::HashMap::new(),
            peer_dependencies_meta: std::collections::HashMap::new(),
            dev_dependencies: std::collections::HashMap::new(),
            bundled_dependencies: vec![],
            features: vec![],
            cached_at: now_timestamp(),
        };

        cache.put_metadata(metadata.clone()).unwrap();

        let retrieved = cache
            .get_metadata(Ecosystem::Npm, "lodash", "4.17.21")
            .unwrap();
        assert_eq!(retrieved.name, "lodash");
        assert_eq!(retrieved.version, "4.17.21");
    }

    #[test]
    fn test_scoped_package_names() {
        let dir = tempdir().unwrap();
        let cache = RegistryCache::new(dir.path()).unwrap();

        // Test scoped npm package
        let versions = vec!["1.0.0".to_string()];
        cache
            .put_versions(Ecosystem::Npm, "@types/node", versions.clone())
            .unwrap();

        let retrieved = cache.get_versions(Ecosystem::Npm, "@types/node").unwrap();
        assert_eq!(retrieved, versions);
    }

    #[test]
    fn test_cache_invalidation() {
        let dir = tempdir().unwrap();
        let cache = RegistryCache::new(dir.path()).unwrap();

        let versions = vec!["1.0.0".to_string()];
        cache
            .put_versions(Ecosystem::Npm, "test-pkg", versions)
            .unwrap();

        assert!(cache.get_versions(Ecosystem::Npm, "test-pkg").is_some());

        cache
            .invalidate_versions(Ecosystem::Npm, "test-pkg")
            .unwrap();

        assert!(cache.get_versions(Ecosystem::Npm, "test-pkg").is_none());
    }

    #[test]
    fn test_cache_ttl() {
        use std::time::Duration;

        let dir = tempdir().unwrap();
        // Create cache with very short TTL
        let cache = RegistryCache::with_ttl(dir.path(), Duration::from_millis(1)).unwrap();

        let versions = vec!["1.0.0".to_string()];
        cache
            .put_versions(Ecosystem::Npm, "test-pkg", versions)
            .unwrap();

        // Wait for TTL to expire
        std::thread::sleep(Duration::from_millis(10));

        // Should return None because cache is expired
        assert!(cache.get_versions(Ecosystem::Npm, "test-pkg").is_none());
    }

    #[test]
    fn test_sanitize_package_name() {
        assert_eq!(sanitize_package_name("lodash"), "lodash");
        assert_eq!(sanitize_package_name("@types/node"), "_at_types_node");
        assert_eq!(sanitize_package_name("@scope/package"), "_at_scope_package");
    }
}
