//! Package extraction for various archive formats.
//!
//! This module provides secure archive extraction with protections against:
//! - Path traversal attacks (zip-slip, tar-slip)
//! - Decompression bombs (zip bombs, tar bombs)
//! - Symlink attacks
//! - Dangerous file permissions (SUID/SGID)

use cratons_core::{CratonsError, Ecosystem, Result};
use cratons_store::Store;
use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Component, Path, PathBuf};
use tar::Archive;
use tracing::{debug, warn};

/// Maximum allowed size for a single extracted file (1 GB)
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Maximum total extraction size (10 GB)
const MAX_TOTAL_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// Maximum compression ratio before we suspect a bomb (100:1)
const MAX_COMPRESSION_RATIO: u64 = 100;

/// Maximum number of files to extract
const MAX_FILE_COUNT: usize = 100_000;

/// Extracts packages from various archive formats.
pub struct PackageExtractor {
    /// Temporary directory for extraction staging
    #[allow(dead_code)] // Reserved for future custom temp directory support
    temp_base: Option<PathBuf>,
    /// Maximum file size limit
    max_file_size: u64,
    /// Maximum total extraction size
    max_total_size: u64,
    /// Maximum file count
    max_file_count: usize,
}

impl PackageExtractor {
    /// Create a new extractor with default security limits.
    pub fn new() -> Self {
        Self {
            temp_base: None,
            max_file_size: MAX_FILE_SIZE,
            max_total_size: MAX_TOTAL_SIZE,
            max_file_count: MAX_FILE_COUNT,
        }
    }

    /// Create an extractor with a custom temp directory.
    pub fn with_temp_dir(temp_base: PathBuf) -> Self {
        Self {
            temp_base: Some(temp_base),
            max_file_size: MAX_FILE_SIZE,
            max_total_size: MAX_TOTAL_SIZE,
            max_file_count: MAX_FILE_COUNT,
        }
    }

    /// Configure custom size limits (for testing or special cases).
    #[must_use]
    pub fn with_limits(
        mut self,
        max_file_size: u64,
        max_total_size: u64,
        max_file_count: usize,
    ) -> Self {
        self.max_file_size = max_file_size;
        self.max_total_size = max_total_size;
        self.max_file_count = max_file_count;
        self
    }

    /// Validate that a path is safe for extraction.
    ///
    /// This prevents path traversal attacks by ensuring:
    /// - No absolute paths
    /// - No parent directory references (..)
    /// - No Windows-style absolute paths
    /// - Path stays within the destination directory
    fn validate_path(path: &Path, dest: &Path) -> Result<PathBuf> {
        // Check for problematic components
        for component in path.components() {
            match component {
                Component::ParentDir => {
                    return Err(CratonsError::Config(format!(
                        "Path traversal attempt detected: path contains '..': {}",
                        path.display()
                    )));
                }
                Component::Prefix(_) => {
                    return Err(CratonsError::Config(format!(
                        "Absolute Windows path not allowed: {}",
                        path.display()
                    )));
                }
                Component::RootDir => {
                    return Err(CratonsError::Config(format!(
                        "Absolute path not allowed: {}",
                        path.display()
                    )));
                }
                _ => {}
            }
        }

        // Construct the final path and verify it's within dest
        let final_path = dest.join(path);
        let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());

        // For paths that don't exist yet, we check the parent
        let check_path = if final_path.exists() {
            final_path
                .canonicalize()
                .unwrap_or_else(|_| final_path.clone())
        } else if let Some(parent) = final_path.parent() {
            if parent.exists() {
                let canonical_parent = parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf());
                canonical_parent.join(final_path.file_name().unwrap_or_default())
            } else {
                final_path.clone()
            }
        } else {
            final_path.clone()
        };

        // Verify the path is within the destination
        if !check_path.starts_with(&canonical_dest) && !final_path.starts_with(dest) {
            return Err(CratonsError::Config(format!(
                "Path escapes destination directory: {} (dest: {})",
                path.display(),
                dest.display()
            )));
        }

        Ok(final_path)
    }

    /// Validate that a symlink target is safe.
    ///
    /// Symlinks must point to locations within the extraction directory.
    fn validate_symlink_target(target: &Path, link_location: &Path, dest: &Path) -> Result<()> {
        // Absolute symlink targets are never allowed
        if target.is_absolute() {
            return Err(CratonsError::Config(format!(
                "Absolute symlink target not allowed: {} -> {}",
                link_location.display(),
                target.display()
            )));
        }

        // Resolve the symlink relative to its location
        let parent = link_location.parent().unwrap_or(dest);
        let resolved = parent.join(target);

        // Normalize the resolved path, counting parent directory references
        // that would escape the destination
        let mut depth: i32 = 0;

        // First, count how deep we are in the destination
        if let Ok(rel_parent) = parent.strip_prefix(dest) {
            depth = rel_parent.components().count() as i32;
        }

        // Now walk through the target components and track if we escape
        for component in target.components() {
            match component {
                Component::ParentDir => {
                    depth -= 1;
                    if depth < 0 {
                        return Err(CratonsError::Config(format!(
                            "Symlink escapes destination: {} -> {}",
                            link_location.display(),
                            target.display()
                        )));
                    }
                }
                Component::Normal(_) => {
                    depth += 1;
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(CratonsError::Config(format!(
                        "Symlink target has absolute component: {} -> {}",
                        link_location.display(),
                        target.display()
                    )));
                }
                Component::CurDir => {}
            }
        }

        // Also verify the resolved path is within dest (double-check)
        // Use a simple string prefix check since paths may not exist yet
        let resolved_str = resolved.to_string_lossy();
        let dest_str = dest.to_string_lossy();
        if !resolved_str.starts_with(&*dest_str) {
            return Err(CratonsError::Config(format!(
                "Symlink target escapes destination: {} -> {} (resolved: {})",
                link_location.display(),
                target.display(),
                resolved.display()
            )));
        }

        Ok(())
    }

    /// Strip dangerous permissions from a mode (SUID, SGID, sticky).
    #[cfg(unix)]
    fn sanitize_mode(mode: u32) -> u32 {
        // Clear SUID (4000), SGID (2000), and sticky (1000) bits
        // Keep only standard permission bits (0777)
        mode & 0o777
    }

    /// Extract a package archive to a destination directory.
    ///
    /// Returns the path to the extracted content.
    pub fn extract(
        &self,
        archive_path: &Path,
        ecosystem: Ecosystem,
        store: &Store,
    ) -> Result<PathBuf> {
        // Hash the archive to create a unique extraction directory
        let archive_hash =
            cratons_core::Hasher::hash_file(cratons_core::HashAlgorithm::Blake3, archive_path)?;

        // Extract to store's package cache
        let extract_dir = store.cache_dir().join("packages").join(&archive_hash.value);

        // If already extracted, return existing path
        if extract_dir.exists() {
            debug!("Package already extracted: {}", extract_dir.display());
            return Ok(extract_dir);
        }

        // Create extraction directory
        fs::create_dir_all(&extract_dir)?;

        // Extract based on ecosystem/format
        let result = match ecosystem {
            Ecosystem::Npm => self.extract_npm_tarball(archive_path, &extract_dir),
            Ecosystem::PyPi => self.extract_pypi_package(archive_path, &extract_dir),
            Ecosystem::Crates => self.extract_crate(archive_path, &extract_dir),
            Ecosystem::Go => self.extract_go_module(archive_path, &extract_dir),
            Ecosystem::Maven => self.extract_maven_jar(archive_path, &extract_dir),
            Ecosystem::Url => self.extract_url_package(archive_path, &extract_dir),
        };

        // Clean up on failure
        if result.is_err() {
            let _ = fs::remove_dir_all(&extract_dir);
        }

        result?;
        debug!("Extracted package to: {}", extract_dir.display());
        Ok(extract_dir)
    }

    /// Extract npm tarball (.tgz).
    ///
    /// npm tarballs contain a `package/` directory with the actual content.
    fn extract_npm_tarball(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        let file = File::open(archive_path)?;
        let compressed_size = file.metadata()?.len();
        let gz = GzDecoder::new(BufReader::new(file));
        let mut archive = Archive::new(gz);

        let mut total_size: u64 = 0;
        let mut file_count: usize = 0;

        // npm tarballs have a `package/` prefix we need to strip
        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?;

            // Strip the `package/` prefix
            let stripped = path.strip_prefix("package").unwrap_or(&path);

            if stripped.as_os_str().is_empty() {
                continue;
            }

            // Validate the path is safe (no path traversal)
            let dest_path = Self::validate_path(stripped, dest)?;

            // Check file count limit
            file_count += 1;
            if file_count > self.max_file_count {
                return Err(CratonsError::Config(format!(
                    "Archive contains too many files (>{} files), possible archive bomb",
                    self.max_file_count
                )));
            }

            let entry_type = entry.header().entry_type();
            let entry_size = entry.header().size()?;

            // Check individual file size
            if entry_size > self.max_file_size {
                return Err(CratonsError::Config(format!(
                    "File too large: {} ({} bytes > {} max)",
                    path.display(),
                    entry_size,
                    self.max_file_size
                )));
            }

            // Check total size with compression ratio
            total_size += entry_size;
            if total_size > self.max_total_size {
                return Err(CratonsError::Config(format!(
                    "Total extraction size exceeds limit ({} bytes > {} max), possible archive bomb",
                    total_size, self.max_total_size
                )));
            }

            // Check compression ratio (detect bombs)
            if compressed_size > 0 && total_size / compressed_size.max(1) > MAX_COMPRESSION_RATIO {
                return Err(CratonsError::Config(format!(
                    "Suspicious compression ratio ({}:1), possible archive bomb",
                    total_size / compressed_size.max(1)
                )));
            }

            // Create parent directories
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Get mode and link name before consuming entry
            #[cfg(unix)]
            let mode = entry.header().mode().ok();
            let link_name = entry.link_name().ok().flatten().map(|c| c.into_owned());

            // Handle different entry types securely
            if entry_type.is_file() {
                // Extract to file with size-limited copy
                let mut outfile = File::create(&dest_path)?;
                let mut limited_reader = entry.take(self.max_file_size);
                io::copy(&mut limited_reader, &mut outfile)?;

                // Sanitize permissions on Unix
                #[cfg(unix)]
                if let Some(mode) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    let safe_mode = Self::sanitize_mode(mode);
                    fs::set_permissions(&dest_path, fs::Permissions::from_mode(safe_mode))?;
                }
            } else if entry_type.is_dir() {
                fs::create_dir_all(&dest_path)?;
            } else if entry_type.is_symlink() {
                // Validate symlink target
                if let Some(ref target) = link_name {
                    Self::validate_symlink_target(target, &dest_path, dest)?;

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        symlink(target, &dest_path)?;
                    }
                }
            } else if entry_type.is_hard_link() {
                // Hard links must also be validated
                if let Some(ref target) = link_name {
                    let target_path = dest.join(target);
                    if !target_path.starts_with(dest) {
                        return Err(CratonsError::Config(format!(
                            "Hard link target escapes destination: {} -> {}",
                            path.display(),
                            target.display()
                        )));
                    }
                }
            }
            // Skip other types (block devices, char devices, etc.)
        }

        debug!(
            "Extracted npm tarball to {} ({} files, {} bytes)",
            dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract PyPI package (.whl or .tar.gz).
    fn extract_pypi_package(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        let path_str = archive_path.to_string_lossy();

        if path_str.ends_with(".whl") {
            // Wheels are ZIP files
            self.extract_zip(archive_path, dest)
        } else if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
            // Source distributions are tarballs
            self.extract_tarball(archive_path, dest)
        } else {
            Err(CratonsError::Config(format!(
                "Unknown PyPI package format: {}",
                path_str
            )))
        }
    }

    /// Extract Rust crate (.crate is a .tar.gz).
    fn extract_crate(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        // .crate files are gzipped tarballs with a top-level directory
        // named `{name}-{version}/`
        let file = File::open(archive_path)?;
        let compressed_size = file.metadata()?.len();
        let gz = GzDecoder::new(BufReader::new(file));
        let mut archive = Archive::new(gz);

        let mut total_size: u64 = 0;
        let mut file_count: usize = 0;

        // Extract, stripping the top-level directory
        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?;

            // Strip first component (crate-version/)
            let components: Vec<_> = path.components().collect();
            if components.len() <= 1 {
                continue;
            }

            let stripped: PathBuf = components[1..].iter().collect();
            if stripped.as_os_str().is_empty() {
                continue;
            }

            // Validate the path is safe
            let dest_path = Self::validate_path(&stripped, dest)?;

            // Check limits
            file_count += 1;
            if file_count > self.max_file_count {
                return Err(CratonsError::Config(format!(
                    "Archive contains too many files (>{} files)",
                    self.max_file_count
                )));
            }

            let entry_size = entry.header().size()?;
            if entry_size > self.max_file_size {
                return Err(CratonsError::Config(format!(
                    "File too large: {} ({} bytes)",
                    path.display(),
                    entry_size
                )));
            }

            total_size += entry_size;
            if total_size > self.max_total_size {
                return Err(CratonsError::Config(format!(
                    "Total extraction size exceeds limit ({} bytes)",
                    total_size
                )));
            }

            if compressed_size > 0 && total_size / compressed_size.max(1) > MAX_COMPRESSION_RATIO {
                return Err(CratonsError::Config(
                    "Suspicious compression ratio, possible archive bomb".to_string(),
                ));
            }

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let entry_type = entry.header().entry_type();
            #[cfg(unix)]
            let mode = entry.header().mode().ok();
            let link_name = entry.link_name().ok().flatten().map(|c| c.into_owned());

            if entry_type.is_file() {
                let mut outfile = File::create(&dest_path)?;
                let mut limited_reader = entry.take(self.max_file_size);
                io::copy(&mut limited_reader, &mut outfile)?;

                #[cfg(unix)]
                if let Some(mode) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(
                        &dest_path,
                        fs::Permissions::from_mode(Self::sanitize_mode(mode)),
                    )?;
                }
            } else if entry_type.is_dir() {
                fs::create_dir_all(&dest_path)?;
            } else if entry_type.is_symlink() {
                if let Some(target) = link_name {
                    Self::validate_symlink_target(&target, &dest_path, dest)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        symlink(&target, &dest_path)?;
                    }
                }
            }
        }

        debug!(
            "Extracted crate to {} ({} files, {} bytes)",
            dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract Go module (.zip).
    fn extract_go_module(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        // Go modules are ZIP files with module@version/ prefix
        self.extract_zip_strip_prefix(archive_path, dest, 1)
    }

    /// Extract Maven JAR.
    ///
    /// JARs are ZIP files, but we typically don't need to extract them -
    /// they're used as-is. We copy and verify the file.
    fn extract_maven_jar(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        let filename = archive_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        // Validate the JAR is a valid ZIP file first
        let file = File::open(archive_path)?;
        let mut archive = zip::ZipArchive::new(BufReader::new(file)).map_err(|e| {
            CratonsError::Config(format!(
                "Invalid JAR file '{}': {}. JAR files must be valid ZIP archives.",
                filename, e
            ))
        })?;

        // Basic validation: check file count limits
        if archive.len() > self.max_file_count {
            return Err(CratonsError::Config(format!(
                "JAR contains too many entries ({} > {} max)",
                archive.len(),
                self.max_file_count
            )));
        }

        // Check for dangerous entries (path traversal, etc.)
        for i in 0..archive.len() {
            let file = archive
                .by_index(i)
                .map_err(|e| CratonsError::Config(format!("Invalid JAR entry: {}", e)))?;

            // Verify no path traversal in entry names
            if file.name().contains("..") {
                return Err(CratonsError::Config(format!(
                    "JAR contains path traversal in entry: {}",
                    file.name()
                )));
            }
        }

        // Compute hash for integrity verification
        let jar_hash =
            cratons_core::Hasher::hash_file(cratons_core::HashAlgorithm::Blake3, archive_path)?;
        debug!("Maven JAR hash: {}", jar_hash);

        // Copy the validated JAR file
        let dest_path = dest.join(&*filename);
        fs::copy(archive_path, &dest_path)?;

        // Write hash file for later verification
        let hash_path = dest.join(format!("{}.blake3", filename));
        fs::write(&hash_path, jar_hash.value.as_bytes())?;

        debug!(
            "Copied and verified Maven JAR to {} (hash: {})",
            dest.display(),
            jar_hash.short()
        );
        Ok(())
    }

    /// Extract a gzipped tarball with security checks.
    fn extract_tarball(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        let file = File::open(archive_path)?;
        let compressed_size = file.metadata()?.len();
        let gz = GzDecoder::new(BufReader::new(file));
        let mut archive = Archive::new(gz);

        let mut total_size: u64 = 0;
        let mut file_count: usize = 0;

        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?;

            // Validate the path is safe
            let dest_path = Self::validate_path(&path, dest)?;

            file_count += 1;
            if file_count > self.max_file_count {
                return Err(CratonsError::Config(format!(
                    "Archive contains too many files (>{} files)",
                    self.max_file_count
                )));
            }

            let entry_size = entry.header().size()?;
            if entry_size > self.max_file_size {
                return Err(CratonsError::Config(format!(
                    "File too large: {} ({} bytes)",
                    path.display(),
                    entry_size
                )));
            }

            total_size += entry_size;
            if total_size > self.max_total_size {
                return Err(CratonsError::Config(format!(
                    "Total extraction size exceeds limit ({} bytes)",
                    total_size
                )));
            }

            if compressed_size > 0 && total_size / compressed_size.max(1) > MAX_COMPRESSION_RATIO {
                return Err(CratonsError::Config(
                    "Suspicious compression ratio, possible archive bomb".to_string(),
                ));
            }

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let entry_type = entry.header().entry_type();
            #[cfg(unix)]
            let mode = entry.header().mode().ok();
            let link_name = entry.link_name().ok().flatten().map(|c| c.into_owned());

            if entry_type.is_file() {
                let mut outfile = File::create(&dest_path)?;
                let mut limited_reader = entry.take(self.max_file_size);
                io::copy(&mut limited_reader, &mut outfile)?;

                #[cfg(unix)]
                if let Some(mode) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(
                        &dest_path,
                        fs::Permissions::from_mode(Self::sanitize_mode(mode)),
                    )?;
                }
            } else if entry_type.is_dir() {
                fs::create_dir_all(&dest_path)?;
            } else if entry_type.is_symlink() {
                if let Some(target) = link_name {
                    Self::validate_symlink_target(&target, &dest_path, dest)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        symlink(&target, &dest_path)?;
                    }
                }
            }
        }

        debug!(
            "Extracted tarball to {} ({} files, {} bytes)",
            dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract a ZIP file with security checks.
    fn extract_zip(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        let file = File::open(archive_path)?;
        let compressed_size = file.metadata()?.len();
        let mut archive = zip::ZipArchive::new(BufReader::new(file))
            .map_err(|e| CratonsError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;

        let mut total_size: u64 = 0;
        let file_count = archive.len();

        if file_count > self.max_file_count {
            return Err(CratonsError::Config(format!(
                "Archive contains too many files ({} > {} max)",
                file_count, self.max_file_count
            )));
        }

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| CratonsError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;

            // enclosed_name() already handles path traversal for ZIP
            let outpath = match file.enclosed_name() {
                Some(path) => {
                    // Additional validation
                    Self::validate_path(&path, dest)?
                }
                None => {
                    warn!("Skipping potentially unsafe ZIP entry: {}", file.name());
                    continue;
                }
            };

            let entry_size = file.size();
            if entry_size > self.max_file_size {
                return Err(CratonsError::Config(format!(
                    "File too large: {} ({} bytes)",
                    file.name(),
                    entry_size
                )));
            }

            total_size += entry_size;
            if total_size > self.max_total_size {
                return Err(CratonsError::Config(format!(
                    "Total extraction size exceeds limit ({} bytes)",
                    total_size
                )));
            }

            if compressed_size > 0 && total_size / compressed_size.max(1) > MAX_COMPRESSION_RATIO {
                return Err(CratonsError::Config(
                    "Suspicious compression ratio, possible archive bomb".to_string(),
                ));
            }

            if file.name().ends_with('/') {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&outpath)?;
                // Use size-limited copy
                let mut limited_reader = (&mut file).take(self.max_file_size);
                io::copy(&mut limited_reader, &mut outfile)?;
            }

            // Set permissions on Unix (sanitized)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    let safe_mode = Self::sanitize_mode(mode);
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(safe_mode))?;
                }
            }
        }

        debug!(
            "Extracted ZIP to {} ({} files, {} bytes)",
            dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract a ZIP file, stripping N path prefix components.
    fn extract_zip_strip_prefix(
        &self,
        archive_path: &Path,
        dest: &Path,
        strip: usize,
    ) -> Result<()> {
        let file = File::open(archive_path)?;
        let compressed_size = file.metadata()?.len();
        let mut archive = zip::ZipArchive::new(BufReader::new(file))
            .map_err(|e| CratonsError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;

        let mut total_size: u64 = 0;
        let file_count = archive.len();

        if file_count > self.max_file_count {
            return Err(CratonsError::Config(format!(
                "Archive contains too many files ({} > {} max)",
                file_count, self.max_file_count
            )));
        }

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| CratonsError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;

            let path = match file.enclosed_name() {
                Some(path) => path.to_path_buf(),
                None => {
                    warn!("Skipping potentially unsafe ZIP entry: {}", file.name());
                    continue;
                }
            };

            // Strip prefix components
            let components: Vec<_> = path.components().collect();
            if components.len() <= strip {
                continue;
            }

            let stripped: PathBuf = components[strip..].iter().collect();
            if stripped.as_os_str().is_empty() {
                continue;
            }

            // Validate the stripped path
            let outpath = Self::validate_path(&stripped, dest)?;

            let entry_size = file.size();
            if entry_size > self.max_file_size {
                return Err(CratonsError::Config(format!(
                    "File too large: {} ({} bytes)",
                    file.name(),
                    entry_size
                )));
            }

            total_size += entry_size;
            if total_size > self.max_total_size {
                return Err(CratonsError::Config(format!(
                    "Total extraction size exceeds limit ({} bytes)",
                    total_size
                )));
            }

            if compressed_size > 0 && total_size / compressed_size.max(1) > MAX_COMPRESSION_RATIO {
                return Err(CratonsError::Config(
                    "Suspicious compression ratio, possible archive bomb".to_string(),
                ));
            }

            if file.name().ends_with('/') {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&outpath)?;
                let mut limited_reader = (&mut file).take(self.max_file_size);
                io::copy(&mut limited_reader, &mut outfile)?;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(
                        &outpath,
                        fs::Permissions::from_mode(Self::sanitize_mode(mode)),
                    )?;
                }
            }
        }

        debug!(
            "Extracted ZIP (stripped {}) to {} ({} files, {} bytes)",
            strip,
            dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract a plain tar archive with security checks.
    fn extract_plain_tar(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        let file = File::open(archive_path)?;
        let file_size = file.metadata()?.len();
        let mut archive = Archive::new(BufReader::new(file));

        let mut total_size: u64 = 0;
        let mut file_count: usize = 0;

        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?;

            let dest_path = Self::validate_path(&path, dest)?;

            file_count += 1;
            if file_count > self.max_file_count {
                return Err(CratonsError::Config(format!(
                    "Archive contains too many files (>{} files)",
                    self.max_file_count
                )));
            }

            let entry_size = entry.header().size()?;
            if entry_size > self.max_file_size {
                return Err(CratonsError::Config(format!(
                    "File too large: {} ({} bytes)",
                    path.display(),
                    entry_size
                )));
            }

            total_size += entry_size;
            if total_size > self.max_total_size {
                return Err(CratonsError::Config(format!(
                    "Total extraction size exceeds limit ({} bytes)",
                    total_size
                )));
            }

            // Plain tar has 1:1 ratio, but check anyway for consistency
            if file_size > 0 && total_size / file_size.max(1) > MAX_COMPRESSION_RATIO {
                return Err(CratonsError::Config(
                    "Suspicious size ratio, possible malformed archive".to_string(),
                ));
            }

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let entry_type = entry.header().entry_type();
            #[cfg(unix)]
            let mode = entry.header().mode().ok();
            let link_name = entry.link_name().ok().flatten().map(|c| c.into_owned());

            if entry_type.is_file() {
                let mut outfile = File::create(&dest_path)?;
                let mut limited_reader = entry.take(self.max_file_size);
                io::copy(&mut limited_reader, &mut outfile)?;

                #[cfg(unix)]
                if let Some(mode) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(
                        &dest_path,
                        fs::Permissions::from_mode(Self::sanitize_mode(mode)),
                    )?;
                }
            } else if entry_type.is_dir() {
                fs::create_dir_all(&dest_path)?;
            } else if entry_type.is_symlink() {
                if let Some(target) = link_name {
                    Self::validate_symlink_target(&target, &dest_path, dest)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        symlink(&target, &dest_path)?;
                    }
                }
            }
        }

        debug!(
            "Extracted tar to {} ({} files, {} bytes)",
            dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract a URL-sourced package.
    ///
    /// Attempts to auto-detect the format based on file extension.
    fn extract_url_package(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        let path_str = archive_path.to_string_lossy().to_lowercase();

        if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
            self.extract_tarball(archive_path, dest)
        } else if path_str.ends_with(".zip") {
            self.extract_zip(archive_path, dest)
        } else if path_str.ends_with(".tar") {
            self.extract_plain_tar(archive_path, dest)
        } else if path_str.ends_with(".tar.xz") || path_str.ends_with(".txz") {
            // XZ compressed tarball - use same security checks
            self.extract_xz_tarball(archive_path, dest)
        } else {
            // Unknown format - just copy the file (validated destination)
            let filename = archive_path
                .file_name()
                .ok_or_else(|| CratonsError::Config("Invalid archive path".to_string()))?;
            let dest_path = Self::validate_path(Path::new(filename), dest)?;
            fs::copy(archive_path, &dest_path)?;
            debug!("Copied URL package to {}", dest.display());
            Ok(())
        }
    }

    /// Extract an XZ-compressed tarball with security checks.
    fn extract_xz_tarball(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        use xz2::read::XzDecoder;

        let file = File::open(archive_path)?;
        let compressed_size = file.metadata()?.len();
        let xz = XzDecoder::new(BufReader::new(file));
        let mut archive = Archive::new(xz);

        let mut total_size: u64 = 0;
        let mut file_count: usize = 0;

        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?;

            let dest_path = Self::validate_path(&path, dest)?;

            file_count += 1;
            if file_count > self.max_file_count {
                return Err(CratonsError::Config(format!(
                    "Archive contains too many files (>{} files)",
                    self.max_file_count
                )));
            }

            let entry_size = entry.header().size()?;
            if entry_size > self.max_file_size {
                return Err(CratonsError::Config(format!(
                    "File too large: {} ({} bytes)",
                    path.display(),
                    entry_size
                )));
            }

            total_size += entry_size;
            if total_size > self.max_total_size {
                return Err(CratonsError::Config(format!(
                    "Total extraction size exceeds limit ({} bytes)",
                    total_size
                )));
            }

            if compressed_size > 0 && total_size / compressed_size.max(1) > MAX_COMPRESSION_RATIO {
                return Err(CratonsError::Config(
                    "Suspicious compression ratio, possible archive bomb".to_string(),
                ));
            }

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let entry_type = entry.header().entry_type();
            #[cfg(unix)]
            let mode = entry.header().mode().ok();
            let link_name = entry.link_name().ok().flatten().map(|c| c.into_owned());

            if entry_type.is_file() {
                let mut outfile = File::create(&dest_path)?;
                let mut limited_reader = entry.take(self.max_file_size);
                io::copy(&mut limited_reader, &mut outfile)?;

                #[cfg(unix)]
                if let Some(mode) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(
                        &dest_path,
                        fs::Permissions::from_mode(Self::sanitize_mode(mode)),
                    )?;
                }
            } else if entry_type.is_dir() {
                fs::create_dir_all(&dest_path)?;
            } else if entry_type.is_symlink() {
                if let Some(target) = link_name {
                    Self::validate_symlink_target(&target, &dest_path, dest)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        symlink(&target, &dest_path)?;
                    }
                }
            }
        }

        debug!(
            "Extracted xz tarball to {} ({} files, {} bytes)",
            dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }
}

impl Default for PackageExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_extractor_creation() {
        let extractor = PackageExtractor::new();
        assert!(extractor.temp_base.is_none());
        assert_eq!(extractor.max_file_size, MAX_FILE_SIZE);
        assert_eq!(extractor.max_total_size, MAX_TOTAL_SIZE);
        assert_eq!(extractor.max_file_count, MAX_FILE_COUNT);

        let extractor = PackageExtractor::with_temp_dir(PathBuf::from("/tmp"));
        assert!(extractor.temp_base.is_some());
    }

    #[test]
    fn test_extractor_with_limits() {
        let extractor = PackageExtractor::new().with_limits(1024, 4096, 10);
        assert_eq!(extractor.max_file_size, 1024);
        assert_eq!(extractor.max_total_size, 4096);
        assert_eq!(extractor.max_file_count, 10);
    }

    #[test]
    fn test_validate_path_normal() {
        let dest = TempDir::new().unwrap();
        let dest_path = dest.path();

        // Normal path should work
        let result = PackageExtractor::validate_path(Path::new("foo/bar/baz.txt"), dest_path);
        assert!(result.is_ok());
        assert!(result.unwrap().starts_with(dest_path));
    }

    #[test]
    fn test_validate_path_traversal_blocked() {
        let dest = TempDir::new().unwrap();
        let dest_path = dest.path();

        // Path traversal should be blocked
        let result = PackageExtractor::validate_path(Path::new("../../../etc/passwd"), dest_path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("path contains '..'")
        );

        let result =
            PackageExtractor::validate_path(Path::new("foo/../../../etc/passwd"), dest_path);
        assert!(result.is_err());

        let result = PackageExtractor::validate_path(Path::new("foo/bar/../../.."), dest_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_absolute_blocked() {
        let dest = TempDir::new().unwrap();
        let dest_path = dest.path();

        // Absolute paths should be blocked
        let result = PackageExtractor::validate_path(Path::new("/etc/passwd"), dest_path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Absolute path not allowed")
        );
    }

    #[test]
    fn test_validate_symlink_target_normal() {
        let dest = TempDir::new().unwrap();
        let dest_path = dest.path();
        let link_location = dest_path.join("link");

        // Normal relative symlink should work
        let result = PackageExtractor::validate_symlink_target(
            Path::new("target.txt"),
            &link_location,
            dest_path,
        );
        assert!(result.is_ok());

        // Symlink to sibling should work
        let link_in_subdir = dest_path.join("subdir/link");
        let result = PackageExtractor::validate_symlink_target(
            Path::new("../other.txt"),
            &link_in_subdir,
            dest_path,
        );
        // This should work as it stays within dest
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_symlink_target_escape_blocked() {
        let dest = TempDir::new().unwrap();
        let dest_path = dest.path();
        let link_location = dest_path.join("link");

        // Symlink escaping destination should be blocked
        let result = PackageExtractor::validate_symlink_target(
            Path::new("../../../etc/passwd"),
            &link_location,
            dest_path,
        );
        assert!(result.is_err());

        // Absolute symlink should be blocked
        let result = PackageExtractor::validate_symlink_target(
            Path::new("/etc/passwd"),
            &link_location,
            dest_path,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Absolute symlink target")
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_sanitize_mode() {
        // Normal permissions should pass through
        assert_eq!(PackageExtractor::sanitize_mode(0o644), 0o644);
        assert_eq!(PackageExtractor::sanitize_mode(0o755), 0o755);

        // SUID should be stripped
        assert_eq!(PackageExtractor::sanitize_mode(0o4755), 0o755);

        // SGID should be stripped
        assert_eq!(PackageExtractor::sanitize_mode(0o2755), 0o755);

        // Sticky bit should be stripped
        assert_eq!(PackageExtractor::sanitize_mode(0o1755), 0o755);

        // All special bits should be stripped
        assert_eq!(PackageExtractor::sanitize_mode(0o7777), 0o777);
    }

    #[test]
    fn test_path_with_dots_in_name() {
        let dest = TempDir::new().unwrap();
        let dest_path = dest.path();

        // Dots in filename (not as directory traversal) should work
        let result = PackageExtractor::validate_path(Path::new("foo/.hidden"), dest_path);
        assert!(result.is_ok());

        let result = PackageExtractor::validate_path(Path::new("foo/file.tar.gz"), dest_path);
        assert!(result.is_ok());

        // Current directory should be fine
        let result = PackageExtractor::validate_path(Path::new("./foo/bar"), dest_path);
        assert!(result.is_ok());
    }
}
