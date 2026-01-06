//! Content-addressable file storage.

use fs2::FileExt;
use cratons_core::{ContentHash, HashAlgorithm, Hasher, CratonsError, Result};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, trace, warn};

/// Content-addressable store for individual files.
///
/// Files are stored by their Blake3 hash in a directory structure like:
/// ```text
/// files/
/// ├── 00/
/// │   └── 00a1b2c3d4e5f6...
/// ├── 01/
/// └── ...
/// ```
pub struct ContentAddressableStore {
    root: PathBuf,
    /// Cache of known hashes to avoid filesystem checks
    known_hashes: RwLock<HashSet<String>>,
}

impl ContentAddressableStore {
    /// Create a new CAS at the specified directory.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            known_hashes: RwLock::new(HashSet::new()),
        }
    }

    /// Get the root directory of the store.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Store content and return its hash.
    pub fn store(&self, content: &[u8]) -> Result<ContentHash> {
        let hash = Hasher::hash_bytes(HashAlgorithm::Blake3, content);
        let path = self.hash_path(&hash);

        // Check if already stored
        if path.exists() {
            trace!("CAS hit: {}", hash.short());
            self.known_hashes.write().insert(hash.value.clone());
            return Ok(hash);
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write atomically via temp file with exclusive lock
        let temp_path = path.with_extension("tmp");

        {
            let file = fs::File::create(&temp_path)?;

            // Acquire exclusive lock
            if let Err(e) = file.lock_exclusive() {
                // If locking fails, someone else might be writing.
                // In a robust implementation, we might wait or check if target exists.
                // For now, we propagate the error as it shouldn't happen often.
                // We clean up the temp file if we can't lock it.
                let _ = fs::remove_file(&temp_path);
                return Err(e.into());
            }

            // Write content
            fs::write(&temp_path, content)?;

            // Rename to final path
            // Note: rename is atomic on POSIX, but replacing an existing file
            // (if a race happened) is also fine as content is content-addressed.
            fs::rename(&temp_path, &path)?;

            // Unlock is automatic when file is dropped
        }

        debug!("Stored {} bytes at {}", content.len(), hash.short());
        self.known_hashes.write().insert(hash.value.clone());

        Ok(hash)
    }

    /// Store a file by path.
    pub fn store_file(&self, source: &Path) -> Result<ContentHash> {
        let content = fs::read(source)?;
        self.store(&content)
    }

    /// Get the path to a stored file by hash.
    pub fn get(&self, hash: &ContentHash) -> Option<PathBuf> {
        // Check memory cache first
        {
            let known = self.known_hashes.read();
            if known.contains(&hash.value) {
                return Some(self.hash_path(hash));
            }
        }

        // Check filesystem
        let path = self.hash_path(hash);
        if path.exists() {
            self.known_hashes.write().insert(hash.value.clone());
            Some(path)
        } else {
            None
        }
    }

    /// Check if a hash exists in the store.
    pub fn contains(&self, hash: &ContentHash) -> bool {
        self.get(hash).is_some()
    }

    /// Read the content of a stored file.
    pub fn read(&self, hash: &ContentHash) -> Result<Option<Vec<u8>>> {
        self.read_with_verify(hash, false)
    }

    /// Read the content of a stored file with optional integrity verification (L-12).
    ///
    /// When `verify` is true, the content is re-hashed and compared to the expected hash.
    /// This protects against bit rot, disk corruption, or tampering.
    pub fn read_with_verify(&self, hash: &ContentHash, verify: bool) -> Result<Option<Vec<u8>>> {
        if let Some(path) = self.get(hash) {
            let content = fs::read(&path)?;

            if verify {
                let actual_hash = Hasher::hash_bytes(hash.algorithm, &content);
                if actual_hash.value != hash.value {
                    warn!(
                        "CAS integrity check failed for {}: expected {}, got {}",
                        path.display(),
                        hash.short(),
                        actual_hash.short()
                    );
                    return Err(CratonsError::ChecksumMismatch {
                        package: path.display().to_string(),
                        expected: hash.value.clone(),
                        actual: actual_hash.value,
                    });
                }
                trace!("CAS integrity verified: {}", hash.short());
            }

            Ok(Some(content))
        } else {
            Ok(None)
        }
    }

    /// Get the path for a given hash.
    fn hash_path(&self, hash: &ContentHash) -> PathBuf {
        let prefix = hash.prefix();
        self.root.join(prefix).join(&hash.value)
    }

    /// Iterate over all stored hashes.
    pub fn iter(&self) -> impl Iterator<Item = Result<ContentHash>> + '_ {
        walkdir::WalkDir::new(&self.root)
            .min_depth(2)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| {
                let hash = e.file_name().to_string_lossy().to_string();
                Ok(ContentHash::blake3(hash))
            })
    }

    /// Get total size of the store in bytes.
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

    /// Get the number of files in the store.
    pub fn count(&self) -> Result<usize> {
        let count = walkdir::WalkDir::new(&self.root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count();
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_store_and_retrieve() {
        let dir = tempdir().unwrap();
        let cas = ContentAddressableStore::new(dir.path());

        let content = b"hello world";
        let hash = cas.store(content).unwrap();

        assert!(cas.contains(&hash));

        let retrieved = cas.read(&hash).unwrap().unwrap();
        assert_eq!(retrieved, content);
    }

    #[test]
    fn test_duplicate_store() {
        let dir = tempdir().unwrap();
        let cas = ContentAddressableStore::new(dir.path());

        let content = b"duplicate test";
        let hash1 = cas.store(content).unwrap();
        let hash2 = cas.store(content).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(cas.count().unwrap(), 1);
    }

    #[test]
    fn test_hash_path_structure() {
        let dir = tempdir().unwrap();
        let cas = ContentAddressableStore::new(dir.path());

        let hash = cas.store(b"test").unwrap();
        let path = cas.get(&hash).unwrap();

        // Should be in a subdirectory based on hash prefix
        assert!(path.parent().unwrap().file_name().is_some());
    }
}
