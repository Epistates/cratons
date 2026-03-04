//! Garbage collection for the store.
//!
//! # Security
//!
//! The garbage collector uses file locking to prevent race conditions where
//! artifacts could be deleted while in use. This is achieved through:
//! - Exclusive lock acquisition before any deletion
//! - Lock file per-artifact to coordinate concurrent access
//! - Graceful handling of lock failures (skip instead of corrupt)

use cratons_core::Result;
use fs2::FileExt;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

use crate::Store;

/// Lock file name used within artifact directories
const LOCK_FILE_NAME: &str = ".cratons-gc-lock";

/// Statistics from a garbage collection run.
#[derive(Debug, Clone, Default)]
pub struct GcStats {
    /// Number of files checked
    pub files_checked: usize,
    /// Number of files removed
    pub files_removed: usize,
    /// Number of artifacts checked
    pub artifacts_checked: usize,
    /// Number of artifacts removed
    pub artifacts_removed: usize,
    /// Bytes freed
    pub bytes_freed: u64,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Garbage collector for the store.
pub struct GarbageCollector<'a> {
    store: &'a Store,
}

impl<'a> GarbageCollector<'a> {
    /// Create a new garbage collector.
    #[must_use]
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    /// Run garbage collection.
    ///
    /// Removes artifacts older than `keep_days` that are not referenced
    /// by any current project.
    pub fn run(&self, keep_days: u32) -> Result<GcStats> {
        let mut stats = GcStats::default();
        let cutoff = SystemTime::now() - Duration::from_secs(u64::from(keep_days) * 24 * 60 * 60);

        info!("Starting garbage collection (keep_days: {})", keep_days);

        // Collect referenced hashes from artifacts
        let mut referenced_hashes = HashSet::new();

        // Phase 1: Remove old artifacts
        let artifacts_dir = self.store.root().join("store/v1/artifacts");
        if artifacts_dir.exists() {
            for entry in fs::read_dir(&artifacts_dir)? {
                let entry = entry?;
                stats.artifacts_checked += 1;

                if entry.path().is_dir() {
                    match self.check_artifact_age(&entry.path(), cutoff) {
                        Ok(should_remove) => {
                            if should_remove {
                                // SECURITY: Acquire exclusive lock before deletion to prevent
                                // race conditions where another process might be using this artifact
                                match self.try_lock_for_deletion(&entry.path()) {
                                    Ok(Some(_lock_guard)) => {
                                        // Re-check age after acquiring lock (double-check pattern)
                                        // This prevents TOCTOU where artifact was accessed between
                                        // our initial check and acquiring the lock
                                        match self.check_artifact_age(&entry.path(), cutoff) {
                                            Ok(true) => {
                                                let size = dir_size(&entry.path());
                                                if let Err(e) = fs::remove_dir_all(entry.path()) {
                                                    stats.errors.push(format!(
                                                        "Failed to remove artifact {}: {}",
                                                        entry.path().display(),
                                                        e
                                                    ));
                                                } else {
                                                    stats.artifacts_removed += 1;
                                                    stats.bytes_freed += size;
                                                    debug!("Removed artifact: {}", entry.path().display());
                                                }
                                            }
                                            Ok(false) => {
                                                // Artifact was accessed since our initial check, skip
                                                debug!(
                                                    "Artifact {} was accessed during GC, skipping",
                                                    entry.path().display()
                                                );
                                            }
                                            Err(e) => {
                                                stats.errors.push(format!(
                                                    "Failed to re-check artifact {}: {}",
                                                    entry.path().display(),
                                                    e
                                                ));
                                            }
                                        }
                                        // Lock is released when _lock_guard is dropped
                                    }
                                    Ok(None) => {
                                        // Could not acquire lock - artifact is in use
                                        debug!(
                                            "Artifact {} is locked, skipping GC",
                                            entry.path().display()
                                        );
                                    }
                                    Err(e) => {
                                        stats.errors.push(format!(
                                            "Failed to lock artifact {}: {}",
                                            entry.path().display(),
                                            e
                                        ));
                                    }
                                }
                            } else {
                                // Collect referenced file hashes from this artifact
                                self.collect_referenced_hashes(
                                    &entry.path(),
                                    &mut referenced_hashes,
                                )?;
                            }
                        }
                        Err(e) => {
                            stats.errors.push(format!(
                                "Failed to check artifact {}: {}",
                                entry.path().display(),
                                e
                            ));
                        }
                    }
                }
            }
        }

        // Phase 2: Remove unreferenced files from CAS
        let files_dir = self.store.root().join("store/v1/files");
        if files_dir.exists() {
            for prefix_entry in fs::read_dir(&files_dir)? {
                let prefix_entry = prefix_entry?;
                if prefix_entry.path().is_dir() {
                    for file_entry in fs::read_dir(prefix_entry.path())? {
                        let file_entry = file_entry?;
                        stats.files_checked += 1;

                        if file_entry.path().is_file() {
                            let hash = file_entry.file_name().to_string_lossy().to_string();

                            if !referenced_hashes.contains(&hash) {
                                // Check age before removing
                                if let Ok(metadata) = file_entry.metadata() {
                                    if let Ok(modified) = metadata.modified() {
                                        if modified < cutoff {
                                            let size = metadata.len();
                                            if let Err(e) = fs::remove_file(file_entry.path()) {
                                                stats.errors.push(format!(
                                                    "Failed to remove file {}: {}",
                                                    file_entry.path().display(),
                                                    e
                                                ));
                                            } else {
                                                stats.files_removed += 1;
                                                stats.bytes_freed += size;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 3: Clean up empty directories in CAS
        self.remove_empty_dirs(&files_dir)?;

        info!(
            "GC complete: {} artifacts removed, {} files removed, {} bytes freed",
            stats.artifacts_removed, stats.files_removed, stats.bytes_freed
        );

        if !stats.errors.is_empty() {
            warn!("GC completed with {} errors", stats.errors.len());
        }

        Ok(stats)
    }

    /// Check if an artifact is older than the cutoff.
    fn check_artifact_age(&self, path: &PathBuf, cutoff: SystemTime) -> Result<bool> {
        // Check the manifest for build time
        let manifest_path = path.join("cratons-manifest.json");
        if manifest_path.exists() {
            let content = fs::read_to_string(&manifest_path)?;
            if let Ok(manifest) =
                serde_json::from_str::<crate::artifact::ArtifactManifest>(&content)
            {
                let build_time = manifest.built_at.timestamp() as u64;
                let cutoff_time = cutoff
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                return Ok(build_time < cutoff_time);
            }
        }

        // Fallback to directory modification time
        let metadata = fs::metadata(path)?;
        let modified = metadata.modified()?;
        Ok(modified < cutoff)
    }

    /// Collect hashes of files referenced by an artifact.
    ///
    /// This scans the artifact's manifest and files to identify all content-addressed
    /// storage (CAS) files that are referenced, preventing them from being garbage collected.
    fn collect_referenced_hashes(
        &self,
        path: &PathBuf,
        hashes: &mut HashSet<String>,
    ) -> Result<()> {
        use cratons_core::{HashAlgorithm, Hasher};

        // Check for cratons-manifest.json which may contain explicit file hashes
        let manifest_path = path.join("cratons-manifest.json");
        if manifest_path.exists() {
            if let Ok(content) = fs::read_to_string(&manifest_path) {
                // Parse manifest to extract referenced hashes
                if let Ok(manifest) =
                    serde_json::from_str::<crate::artifact::ArtifactManifest>(&content)
                {
                    // The manifest contains the input_hash which references CAS entries
                    hashes.insert(manifest.input_hash.to_string());
                    debug!(
                        "Collected hash from manifest: {}",
                        manifest.input_hash.short()
                    );
                }
            }
        }

        // Scan files and compute their Blake3 hashes to track CAS references
        for entry in walkdir::WalkDir::new(path)
            .follow_links(false) // Don't follow symlinks to avoid loops
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                // Compute the Blake3 hash of this file
                if let Ok(data) = fs::read(entry.path()) {
                    let hash = Hasher::hash_bytes(HashAlgorithm::Blake3, &data);
                    hashes.insert(hash.to_string());
                }
            }
        }

        debug!(
            "Collected {} hashes from artifact at {}",
            hashes.len(),
            path.display()
        );
        Ok(())
    }

    /// Try to acquire an exclusive lock for deletion.
    ///
    /// Returns `Ok(Some(file))` if the lock was acquired (caller must keep file alive).
    /// Returns `Ok(None)` if the artifact is in use (lock could not be acquired).
    /// Returns `Err` on I/O errors.
    ///
    /// # Security
    ///
    /// This prevents race conditions where an artifact could be deleted while
    /// another process is reading or using it. The lock file is created inside
    /// the artifact directory and must be held for the duration of any deletion.
    fn try_lock_for_deletion(&self, artifact_path: &Path) -> Result<Option<File>> {
        let lock_path = artifact_path.join(LOCK_FILE_NAME);

        // Create or open the lock file
        let lock_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;

        // Try to acquire exclusive lock (non-blocking)
        match lock_file.try_lock_exclusive() {
            Ok(()) => {
                debug!("Acquired GC lock for {}", artifact_path.display());
                Ok(Some(lock_file))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Lock is held by another process
                debug!(
                    "Could not acquire GC lock for {} (in use)",
                    artifact_path.display()
                );
                Ok(None)
            }
            Err(e) => {
                // Other I/O error
                Err(cratons_core::CratonsError::Io(e))
            }
        }
    }

    /// Remove empty directories.
    fn remove_empty_dirs(&self, dir: &PathBuf) -> Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if entry.path().is_dir() {
                    self.remove_empty_dirs(&entry.path())?;
                }
            }

            // Try to remove if empty
            if fs::read_dir(dir)?.next().is_none() {
                let _ = fs::remove_dir(dir);
            }
        }
        Ok(())
    }
}

/// Calculate the size of a directory.
fn dir_size(path: &PathBuf) -> u64 {
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gc_stats_default() {
        let stats = GcStats::default();
        assert_eq!(stats.files_removed, 0);
        assert_eq!(stats.artifacts_removed, 0);
        assert_eq!(stats.bytes_freed, 0);
    }
}
