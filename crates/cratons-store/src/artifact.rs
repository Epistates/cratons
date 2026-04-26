//! Artifact storage for built packages.

use cratons_core::{ContentHash, HashAlgorithm, Hasher, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Canonical manifest filename stored alongside an artifact directory.
pub const ARTIFACT_MANIFEST_NAME: &str = "cratons-manifest.json";

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
    /// Hash of the captured build outputs before the manifest was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<ContentHash>,
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
            output_hash: None,
            env: Vec::new(),
            toolchains: std::collections::HashMap::new(),
        }
    }
}

/// Hash stored artifact contents while excluding the store-managed root manifest.
///
/// This is used when verifying or re-hashing artifact directories after they
/// have already been written to disk with `cratons-manifest.json` at the root.
pub fn hash_artifact_contents(path: &Path) -> Result<ContentHash> {
    hash_artifact_contents_with(path, HashAlgorithm::Blake3)
}

/// Hash stored artifact contents with an explicit algorithm.
pub fn hash_artifact_contents_with(path: &Path, algorithm: HashAlgorithm) -> Result<ContentHash> {
    use walkdir::WalkDir;

    let root_manifest = path.join(ARTIFACT_MANIFEST_NAME);
    let mut entries: Vec<_> = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file() && entry.path() != root_manifest.as_path())
        .collect();
    entries.sort_by(|a, b| a.path().cmp(b.path()));

    let mut hasher = Hasher::new(algorithm);
    for entry in entries {
        let relative = entry
            .path()
            .strip_prefix(path)
            .map_err(|e| cratons_core::CratonsError::Io(std::io::Error::other(e.to_string())))?;
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update(b"\0");

        let file_hash = Hasher::hash_file(algorithm, entry.path())?;
        hasher.update(file_hash.value.as_bytes());
        hasher.update(b"\0");
    }

    Ok(hasher.finalize())
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
        let output_hash = hash_artifact_contents_with(
            output_dir,
            manifest
                .output_hash
                .as_ref()
                .map(|hash| hash.algorithm)
                .unwrap_or(HashAlgorithm::Blake3),
        )?;
        if let Some(expected_output_hash) = &manifest.output_hash {
            if expected_output_hash != &output_hash {
                return Err(cratons_core::CratonsError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "artifact output hash mismatch: manifest={}, actual={}",
                        expected_output_hash, output_hash
                    ),
                )));
            }
        }

        let mut stored_manifest = manifest.clone();
        stored_manifest.output_hash = Some(output_hash.clone());

        // Create artifact directory. The full input and output hashes are
        // embedded in the path so the directory name is not a 12-character
        // security boundary. Legacy short-prefix directories are still read
        // by manifest scanning in `load`.
        let artifact_dir = self.root.join(format!(
            "{}-{}-{}-{}",
            manifest.input_hash.algorithm,
            manifest.input_hash.value,
            output_hash.algorithm,
            output_hash.value
        ));

        if artifact_dir.exists() {
            match Self::verify_artifact_dir(&artifact_dir, &manifest.input_hash)? {
                Some(_) => {
                    debug!("Artifact already exists: {}", artifact_dir.display());
                    return Ok(manifest.input_hash.clone());
                }
                None => {
                    return Err(cratons_core::CratonsError::Io(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "artifact directory exists but does not match expected input hash: {}",
                            artifact_dir.display()
                        ),
                    )));
                }
            }
        }

        fs::create_dir_all(&artifact_dir)?;

        // Copy output files to artifact directory
        copy_dir_contents(output_dir, &artifact_dir)?;

        // Write manifest
        let manifest_path = artifact_dir.join(ARTIFACT_MANIFEST_NAME);
        let manifest_json = serde_json::to_string_pretty(&stored_manifest)?;
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
        match self.load(input_hash) {
            Ok(Some(artifact)) => Some(artifact.path),
            Ok(None) => None,
            Err(e) => {
                warn!(
                    input_hash = %input_hash,
                    error = %e,
                    "failed to verify local artifact cache entry"
                );
                None
            }
        }
    }

    /// Load an artifact with its manifest.
    pub fn load(&self, input_hash: &ContentHash) -> Result<Option<Artifact>> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Ok(None);
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            match Self::verify_artifact_dir(&path, input_hash) {
                Ok(Some(manifest)) => return Ok(Some(Artifact { manifest, path })),
                Ok(None) => continue,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        input_hash = %input_hash,
                        error = %e,
                        "ignoring invalid local artifact cache entry"
                    );
                }
            }
        }

        Ok(None)
    }

    /// Verify that an artifact directory matches the requested full input hash.
    pub fn verify_artifact_dir(
        path: &Path,
        expected_input_hash: &ContentHash,
    ) -> Result<Option<ArtifactManifest>> {
        let manifest_path = path.join(ARTIFACT_MANIFEST_NAME);
        if !manifest_path.exists() {
            return Ok(None);
        }

        let manifest_json = fs::read_to_string(&manifest_path)?;
        let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)?;

        if !manifest
            .input_hash
            .constant_time_verify(expected_input_hash)
        {
            return Ok(None);
        }

        let Some(expected_output_hash) = &manifest.output_hash else {
            return Err(cratons_core::CratonsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact manifest missing output_hash",
            )));
        };

        let actual_output_hash = hash_artifact_contents_with(path, expected_output_hash.algorithm)?;
        if !actual_output_hash.constant_time_verify(expected_output_hash) {
            return Err(cratons_core::CratonsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "artifact output hash mismatch: manifest={}, actual={}",
                    expected_output_hash, actual_output_hash
                ),
            )));
        }

        Ok(Some(manifest))
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
                    let manifest_path = entry.path().join(ARTIFACT_MANIFEST_NAME);
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
    fn test_hash_artifact_contents_ignores_root_manifest() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("artifact.bin"), b"payload").unwrap();
        fs::create_dir_all(temp.path().join("nested")).unwrap();
        fs::write(
            temp.path().join("nested").join(ARTIFACT_MANIFEST_NAME),
            b"nested payload",
        )
        .unwrap();
        fs::write(
            temp.path().join(ARTIFACT_MANIFEST_NAME),
            b"{\"package\":\"x\"}",
        )
        .unwrap();

        let compare = tempdir().unwrap();
        fs::write(compare.path().join("artifact.bin"), b"payload").unwrap();
        fs::create_dir_all(compare.path().join("nested")).unwrap();
        fs::write(
            compare.path().join("nested").join(ARTIFACT_MANIFEST_NAME),
            b"nested payload",
        )
        .unwrap();

        let actual = hash_artifact_contents(temp.path()).unwrap();
        let expected = Hasher::hash_directory(HashAlgorithm::Blake3, compare.path()).unwrap();
        assert_eq!(actual, expected);
    }

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
        assert!(artifact.manifest.output_hash.is_some());
        assert!(artifact.has_file("binary"));
        assert!(artifact.has_file("lib/lib.so"));
    }

    #[test]
    fn test_artifact_get_ignores_short_prefix_collision() {
        let store_dir = tempdir().unwrap();
        let store = ArtifactStore::new(store_dir.path());
        let expected_hash = ContentHash::blake3("aaaaaaaaaaaa11111111111111111111".to_string());
        let wrong_hash = ContentHash::blake3("aaaaaaaaaaaa22222222222222222222".to_string());

        let collision_dir = store_dir.path().join("aaaaaaaaaaaa-collision");
        fs::create_dir_all(&collision_dir).unwrap();
        fs::write(collision_dir.join("artifact.bin"), b"payload").unwrap();
        let output_hash = hash_artifact_contents(&collision_dir).unwrap();
        let mut manifest =
            ArtifactManifest::new(wrong_hash, "wrong-package".to_string(), "1.0.0".to_string());
        manifest.output_hash = Some(output_hash);
        fs::write(
            collision_dir.join(ARTIFACT_MANIFEST_NAME),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        assert!(store.get(&expected_hash).is_none());
    }

    #[test]
    fn test_artifact_get_rejects_tampered_payload() {
        let store_dir = tempdir().unwrap();
        let output_dir = tempdir().unwrap();
        fs::write(output_dir.path().join("binary"), b"test binary").unwrap();

        let store = ArtifactStore::new(store_dir.path());
        let input_hash = ContentHash::blake3("test_input_hash".to_string());
        let manifest = ArtifactManifest::new(
            input_hash.clone(),
            "test-package".to_string(),
            "1.0.0".to_string(),
        );

        store.store(&manifest, output_dir.path()).unwrap();
        let path = store.get(&input_hash).unwrap();
        fs::write(path.join("binary"), b"tampered").unwrap();

        assert!(store.get(&input_hash).is_none());
    }
}
