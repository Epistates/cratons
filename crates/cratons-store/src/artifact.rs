//! Artifact storage for built packages.

use cratons_core::{ContentHash, HashAlgorithm, Hasher, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Metadata about a built artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactManifest {
    /// Hash of all build inputs (deps + source + toolchain + build script)
    pub input_hash: ContentHash,
    /// The package this artifact is for
    pub package: String,
    /// Version of the package
    pub version: String,
    /// When the artifact was built
    pub built_at: chrono::DateTime<chrono::Utc>,
    /// Build duration in seconds
    pub build_duration_secs: f64,
    /// Environment variables used in build
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<(String, String)>,
    /// Toolchain versions used
    #[serde(default)]
    pub toolchains: std::collections::HashMap<String, String>,
}

impl ArtifactManifest {
    /// Create a new artifact manifest.
    #[must_use]
    pub fn new(input_hash: ContentHash, package: String, version: String) -> Self {
        Self {
            input_hash,
            package,
            version,
            built_at: chrono::Utc::now(),
            build_duration_secs: 0.0,
            env: Vec::new(),
            toolchains: std::collections::HashMap::new(),
        }
    }
}

/// A stored artifact.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// The artifact manifest
    pub manifest: ArtifactManifest,
    /// Path to the artifact directory
    pub path: PathBuf,
}

impl Artifact {
    /// Get the path to a file within the artifact.
    #[must_use]
    pub fn file(&self, relative: &str) -> PathBuf {
        self.path.join(relative)
    }

    /// Check if a file exists in the artifact.
    #[must_use]
    pub fn has_file(&self, relative: &str) -> bool {
        self.file(relative).exists()
    }
}

/// Store for built artifacts.
#[derive(Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    /// Create a new artifact store.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Get the root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Store an artifact from a build output directory.
    pub fn store(&self, manifest: &ArtifactManifest, output_dir: &Path) -> Result<ContentHash> {
        // Compute hash of the output directory
        let output_hash = Hasher::hash_directory(HashAlgorithm::Blake3, output_dir)?;

        // Create artifact directory
        let artifact_dir = self.root.join(format!(
            "{}-{}",
            manifest.input_hash.short(),
            output_hash.short()
        ));

        if artifact_dir.exists() {
            debug!("Artifact already exists: {}", artifact_dir.display());
            return Ok(manifest.input_hash.clone());
        }

        fs::create_dir_all(&artifact_dir)?;

        // Copy output files to artifact directory
        copy_dir_contents(output_dir, &artifact_dir)?;

        // Write manifest
        let manifest_path = artifact_dir.join("cratons-manifest.json");
        let manifest_json = serde_json::to_string_pretty(manifest)?;
        fs::write(manifest_path, manifest_json)?;

        info!(
            "Stored artifact for {}@{} at {}",
            manifest.package,
            manifest.version,
            artifact_dir.display()
        );

        Ok(manifest.input_hash.clone())
    }

    /// Get an artifact by input hash.
    pub fn get(&self, input_hash: &ContentHash) -> Option<PathBuf> {
        // Look for directories starting with the input hash prefix
        let prefix = input_hash.short();

        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(prefix) && entry.path().is_dir() {
                    return Some(entry.path());
                }
            }
        }

        None
    }

    /// Load an artifact with its manifest.
    pub fn load(&self, input_hash: &ContentHash) -> Result<Option<Artifact>> {
        if let Some(path) = self.get(input_hash) {
            let manifest_path = path.join("cratons-manifest.json");
            if manifest_path.exists() {
                let manifest_json = fs::read_to_string(manifest_path)?;
                let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)?;
                return Ok(Some(Artifact { manifest, path }));
            }
        }
        Ok(None)
    }

    /// Check if an artifact exists for the given input hash.
    pub fn contains(&self, input_hash: &ContentHash) -> bool {
        self.get(input_hash).is_some()
    }

    /// List all artifacts.
    pub fn list(&self) -> Result<Vec<Artifact>> {
        let mut artifacts = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().is_dir() {
                    let manifest_path = entry.path().join("cratons-manifest.json");
                    if manifest_path.exists() {
                        if let Ok(manifest_json) = fs::read_to_string(&manifest_path) {
                            if let Ok(manifest) = serde_json::from_str(&manifest_json) {
                                artifacts.push(Artifact {
                                    manifest,
                                    path: entry.path(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(artifacts)
    }

    /// Remove an artifact.
    pub fn remove(&self, input_hash: &ContentHash) -> Result<bool> {
        if let Some(path) = self.get(input_hash) {
            fs::remove_dir_all(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get total size of all artifacts.
    pub fn size(&self) -> Result<u64> {
        let mut total = 0u64;
        for entry in walkdir::WalkDir::new(&self.root) {
            let entry = entry?;
            if entry.file_type().is_file() {
                total += entry.metadata()?.len();
            }
        }
        Ok(total)
    }
}

/// Copy directory contents recursively.
fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(src) {
        let entry = entry?;
        let relative = entry
            .path()
            .strip_prefix(src)
            .map_err(|e| cratons_core::CratonsError::Io(std::io::Error::other(e.to_string())))?;
        let target = dst.join(relative);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_artifact_store() {
        let store_dir = tempdir().unwrap();
        let output_dir = tempdir().unwrap();

        // Create some output files
        fs::write(output_dir.path().join("binary"), b"test binary").unwrap();
        fs::create_dir(output_dir.path().join("lib")).unwrap();
        fs::write(output_dir.path().join("lib/lib.so"), b"test lib").unwrap();

        let store = ArtifactStore::new(store_dir.path());
        let input_hash = ContentHash::blake3("test_input_hash".to_string());
        let manifest = ArtifactManifest::new(
            input_hash.clone(),
            "test-package".to_string(),
            "1.0.0".to_string(),
        );

        let stored_hash = store.store(&manifest, output_dir.path()).unwrap();
        assert_eq!(stored_hash, input_hash);

        // Should be able to retrieve
        assert!(store.contains(&input_hash));

        let artifact = store.load(&input_hash).unwrap().unwrap();
        assert_eq!(artifact.manifest.package, "test-package");
        assert!(artifact.has_file("binary"));
        assert!(artifact.has_file("lib/lib.so"));
    }
}
