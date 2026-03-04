//! Content-addressable file storage.

use fs2::FileExt;
use cratons_core::{ContentHash, HashAlgorithm, Hasher, CratonsError, Result};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, trace, warn};
use uuid::Uuid;

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
    ///
    /// This method is designed to be safe against TOCTOU (Time-Of-Check-Time-Of-Use)
    /// race conditions. It uses:
    /// - Unique temp file names (PID + UUID) to prevent collisions
    /// - Atomic file creation with O_EXCL to detect races
    /// - Atomic rename for final placement
    pub fn store(&self, content: &[u8]) -> Result<ContentHash> {
        let hash = Hasher::hash_bytes(HashAlgorithm::Blake3, content);
        let path = self.hash_path(&hash);

        // Fast path: check memory cache first (no filesystem access)
        {
            let known = self.known_hashes.read();
            if known.contains(&hash.value) {
                trace!("CAS memory cache hit: {}", hash.short());
                return Ok(hash);
            }
        }

        // Check if already stored on filesystem
        if path.exists() {
            trace!("CAS filesystem hit: {}", hash.short());
            self.known_hashes.write().insert(hash.value.clone());
            return Ok(hash);
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // SECURITY: Use unique temp file name to prevent TOCTOU attacks
        // The combination of PID + UUID ensures uniqueness across processes and threads
        let temp_path = path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));

        // SECURITY: Use create_new (O_EXCL) for atomic file creation
        // This fails if the file already exists, preventing race conditions
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true) // O_EXCL: atomic create, fails if exists
                .open(&temp_path)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        // Another process created this exact temp file (extremely unlikely with UUID)
                        CratonsError::Io(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            format!("Temp file collision: {}", temp_path.display()),
                        ))
                    } else {
                        CratonsError::Io(e)
                    }
                })?;

            // Acquire exclusive lock for additional safety
            file.lock_exclusive().inspect_err(|_| {
                // Clean up on lock failure
                let _ = fs::remove_file(&temp_path);
            })?;

            // Write content
            file.write_all(content)?;
            file.sync_all()?; // Ensure data is flushed to disk before rename

            // Lock released when file is dropped
            drop(file);

            // Atomic rename to final path
            // On POSIX, rename is atomic. If another process raced us and already
            // created the final file, that's fine - content is content-addressed,
            // so the content is identical.
            match fs::rename(&temp_path, &path) {
                Ok(()) => Ok(()),
                Err(e) => {
                    // Clean up temp file on rename failure
                    let _ = fs::remove_file(&temp_path);
                    // If final file now exists (another process won the race), that's OK
                    if path.exists() {
                        trace!("CAS race: another process stored {} first", hash.short());
                        Ok(())
                    } else {
                        Err(CratonsError::Io(e))
                    }
                }
            }
        })();

        // Clean up temp file if anything went wrong
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }

        result?;

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
