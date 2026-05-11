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

/// Per-extraction context holding the canonicalized destination directory.
///
/// Canonicalization is a syscall. Precomputing it once at the start of an
/// extraction (rather than per-entry) avoids both the perf hit and a class of
/// TOCTOU hazards where intermediate symlinks created by earlier entries could
/// be resolved differently by a later entry's `canonicalize` call.
///
/// All entry-level path validation must go through `validate_path_ctx` /
/// `validate_symlink_target_ctx` / `validate_hard_link_target_ctx` so that
/// every containment check uses the same canonical root.
#[allow(dead_code)] // wired into callers in Phase 2
struct ExtractContext {
    /// The canonicalized destination directory. Falls back to the uncanonicalized
    /// path only if the destination does not yet exist on disk (it must though,
    /// since `PackageExtractor::extract` creates it before building the context).
    canonical_dest: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlArchiveFormat {
    GzipTar,
    Zip,
    Tar,
    XzTar,
    Unknown,
}

impl ExtractContext {
    /// Build a new context by canonicalizing `dest`. `dest` must already exist.
    #[allow(dead_code)] // wired into callers in Phase 2
    fn new(dest: &Path) -> Result<Self> {
        let canonical_dest = dest.canonicalize().map_err(|e| {
            CratonsError::Config(format!(
                "Failed to canonicalize extraction destination {}: {}",
                dest.display(),
                e
            ))
        })?;
        Ok(Self { canonical_dest })
    }
}

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
    ///
    /// Retained for the existing unit test suite only. Production extraction
    /// code goes through [`Self::validate_path_ctx`] with a pre-built
    /// [`ExtractContext`], which is both faster and strictly more secure.
    #[allow(dead_code)]
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

    /// Validate a path for extraction using a pre-canonicalized destination.
    ///
    /// This is the canonical entry point for Phase 2+ callers. It reuses
    /// `ctx.canonical_dest` instead of canonicalizing per entry, removing a
    /// class of TOCTOU hazards where an earlier-extracted symlink could shift
    /// the meaning of a later entry's `canonicalize` call, and avoids the
    /// unsafe `starts_with(dest)` fallback on non-canonical `dest` values.
    #[allow(dead_code)] // wired into callers in Phase 2
    fn validate_path_ctx(ctx: &ExtractContext, path: &Path) -> Result<PathBuf> {
        // Reject problematic components up front.
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

        let final_path = ctx.canonical_dest.join(path);

        // Determine the path we canonicalize: if `final_path` exists, canonicalize
        // it directly. Otherwise walk up until we find an existing ancestor,
        // canonicalize that, and append the missing tail. This preserves the
        // property that containment is always checked against a canonical root,
        // even for not-yet-created paths.
        let check_path = if final_path.exists() {
            final_path.canonicalize().map_err(|e| {
                CratonsError::Config(format!(
                    "Failed to canonicalize extraction path {}: {}",
                    final_path.display(),
                    e
                ))
            })?
        } else {
            let mut ancestor = final_path.as_path();
            let mut trailing: Vec<&std::ffi::OsStr> = Vec::new();
            loop {
                if ancestor.exists() {
                    break;
                }
                match ancestor.file_name() {
                    Some(name) => trailing.push(name),
                    None => break,
                }
                match ancestor.parent() {
                    Some(parent) => ancestor = parent,
                    None => break,
                }
            }
            let anchor = if ancestor.as_os_str().is_empty() {
                ctx.canonical_dest.clone()
            } else {
                ancestor.canonicalize().map_err(|e| {
                    CratonsError::Config(format!(
                        "Failed to canonicalize ancestor {}: {}",
                        ancestor.display(),
                        e
                    ))
                })?
            };
            let mut result = anchor;
            for name in trailing.iter().rev() {
                result.push(name);
            }
            result
        };

        if !check_path.starts_with(&ctx.canonical_dest) {
            return Err(CratonsError::Config(format!(
                "Path escapes destination directory: {} (dest: {})",
                path.display(),
                ctx.canonical_dest.display()
            )));
        }

        Ok(final_path)
    }

    /// Validate a symlink target using a pre-canonicalized destination.
    ///
    /// Re-uses the existing component-walk logic from `validate_symlink_target`
    /// but keys the containment check off `ctx.canonical_dest` so that every
    /// resolution happens against the same canonical root.
    #[allow(dead_code)] // wired into callers in Phase 2
    fn validate_symlink_target_ctx(
        ctx: &ExtractContext,
        target: &Path,
        link_location: &Path,
    ) -> Result<()> {
        Self::validate_symlink_target(target, link_location, &ctx.canonical_dest)
    }

    /// Validate a hard-link target inside `ctx.canonical_dest`.
    ///
    /// Unlike symlinks, hard links materialize an additional directory entry
    /// for an existing inode. They cannot escape containment at read time (the
    /// inode is already inside the tree) but a malicious tarball can still try
    /// to:
    ///
    /// 1. Name a target outside `canonical_dest` (e.g. `../../etc/shadow`).
    /// 2. Name a target that is itself a symlink pointing outside.
    /// 3. Reference an entry that has not been extracted yet.
    ///
    /// We defend against all three: reject `..`/absolute components, require
    /// the resolved target to live under `canonical_dest`, and require it to
    /// already exist on disk (POSIX ustar guarantees source-before-link order
    /// for well-formed archives; any archive that violates this ordering is
    /// either broken or malicious).
    ///
    /// Returns the absolute, canonical-rooted path that should be passed to
    /// `std::fs::hard_link` as the existing source.
    #[allow(dead_code)] // wired into callers in Phase 2
    fn validate_hard_link_target_ctx(
        ctx: &ExtractContext,
        link_location: &Path,
        target: &Path,
    ) -> Result<PathBuf> {
        if target.is_absolute() {
            return Err(CratonsError::Config(format!(
                "Absolute hard link target not allowed: {} -> {}",
                link_location.display(),
                target.display()
            )));
        }
        for component in target.components() {
            match component {
                Component::ParentDir => {
                    return Err(CratonsError::Config(format!(
                        "Hard link target contains '..': {} -> {}",
                        link_location.display(),
                        target.display()
                    )));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(CratonsError::Config(format!(
                        "Hard link target has absolute component: {} -> {}",
                        link_location.display(),
                        target.display()
                    )));
                }
                _ => {}
            }
        }

        let resolved = ctx.canonical_dest.join(target);
        if !resolved.exists() {
            return Err(CratonsError::Config(format!(
                "Hard link target does not exist inside extraction directory: {} -> {}",
                link_location.display(),
                target.display()
            )));
        }

        let canonical_resolved = resolved.canonicalize().map_err(|e| {
            CratonsError::Config(format!(
                "Failed to canonicalize hard link target {}: {}",
                resolved.display(),
                e
            ))
        })?;
        if !canonical_resolved.starts_with(&ctx.canonical_dest) {
            return Err(CratonsError::Config(format!(
                "Hard link target escapes destination: {} -> {} (resolved: {})",
                link_location.display(),
                target.display(),
                canonical_resolved.display()
            )));
        }

        Ok(canonical_resolved)
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

        // Build the per-extraction context once. All path validation below
        // goes through `ctx.canonical_dest`, preventing intermediate symlinks
        // or non-canonical roots from bypassing containment checks.
        let ctx = ExtractContext::new(&extract_dir)?;

        // Extract based on ecosystem/format
        let result = match ecosystem {
            Ecosystem::Npm => self.extract_npm_tarball(archive_path, &ctx),
            Ecosystem::PyPi => self.extract_pypi_package(archive_path, &ctx),
            Ecosystem::Crates => self.extract_crate(archive_path, &ctx),
            Ecosystem::Go => self.extract_go_module(archive_path, &ctx),
            Ecosystem::Maven => self.extract_maven_jar(archive_path, &ctx),
            Ecosystem::Url => self.extract_url_package(archive_path, &ctx),
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
    fn extract_npm_tarball(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
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

            // Validate the path is safe (no path traversal), rooted at the
            // pre-canonicalized destination.
            let dest_path = Self::validate_path_ctx(ctx, stripped)?;

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
                // Validate symlink target against the canonical dest.
                if let Some(ref target) = link_name {
                    Self::validate_symlink_target_ctx(ctx, target, &dest_path)?;

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
                // Hard links: validate the target stays inside canonical_dest
                // AND actually create the hardlink. The previous implementation
                // silently dropped the entry, leaving packages half-extracted
                // and giving a false sense of containment.
                if let Some(ref target) = link_name {
                    let resolved = Self::validate_hard_link_target_ctx(ctx, &dest_path, target)?;
                    #[cfg(any(unix, windows))]
                    {
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        fs::hard_link(&resolved, &dest_path)?;
                    }
                }
            }
            // Skip other types (block devices, char devices, etc.)
        }

        debug!(
            "Extracted npm tarball to {} ({} files, {} bytes)",
            ctx.canonical_dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract PyPI package (.whl or .tar.gz).
    fn extract_pypi_package(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
        let path_str = archive_path.to_string_lossy();

        if path_str.ends_with(".whl") {
            // Wheels are ZIP files
            self.extract_zip(archive_path, ctx)
        } else if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
            // Source distributions are tarballs
            self.extract_tarball(archive_path, ctx)
        } else {
            Err(CratonsError::Config(format!(
                "Unknown PyPI package format: {}",
                path_str
            )))
        }
    }

    /// Extract Rust crate (.crate is a .tar.gz).
    fn extract_crate(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
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
            let dest_path = Self::validate_path_ctx(ctx, &stripped)?;

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
                    Self::validate_symlink_target_ctx(ctx, &target, &dest_path)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        symlink(&target, &dest_path)?;
                    }
                }
            } else if entry_type.is_hard_link() {
                // Hard links: validated against canonical_dest and materialized.
                if let Some(ref target) = link_name {
                    let resolved = Self::validate_hard_link_target_ctx(ctx, &dest_path, target)?;
                    #[cfg(any(unix, windows))]
                    {
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        fs::hard_link(&resolved, &dest_path)?;
                    }
                }
            }
        }

        debug!(
            "Extracted crate to {} ({} files, {} bytes)",
            ctx.canonical_dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract Go module (.zip).
    fn extract_go_module(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
        // Go modules are ZIP files with module@version/ prefix
        self.extract_zip_strip_prefix(archive_path, ctx, 1)
    }

    /// Extract Maven JAR.
    ///
    /// JARs are ZIP files, but we typically don't need to extract them -
    /// they're used as-is. We copy and verify the file.
    fn extract_maven_jar(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
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
        let dest_path = ctx.canonical_dest.join(&*filename);
        fs::copy(archive_path, &dest_path)?;

        // Write hash file for later verification
        let hash_path = ctx.canonical_dest.join(format!("{}.blake3", filename));
        fs::write(&hash_path, jar_hash.value.as_bytes())?;

        debug!(
            "Copied and verified Maven JAR to {} (hash: {})",
            ctx.canonical_dest.display(),
            jar_hash.short()
        );
        Ok(())
    }

    /// Extract a gzipped tarball with security checks.
    fn extract_tarball(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
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
            let dest_path = Self::validate_path_ctx(ctx, &path)?;

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
                    Self::validate_symlink_target_ctx(ctx, &target, &dest_path)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        symlink(&target, &dest_path)?;
                    }
                }
            } else if entry_type.is_hard_link() {
                // Hard links: validated against canonical_dest and materialized.
                if let Some(ref target) = link_name {
                    let resolved = Self::validate_hard_link_target_ctx(ctx, &dest_path, target)?;
                    #[cfg(any(unix, windows))]
                    {
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        fs::hard_link(&resolved, &dest_path)?;
                    }
                }
            }
        }

        debug!(
            "Extracted tarball to {} ({} files, {} bytes)",
            ctx.canonical_dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract a ZIP file with security checks.
    fn extract_zip(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
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
                    // Additional validation against canonical_dest.
                    Self::validate_path_ctx(ctx, &path)?
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
            ctx.canonical_dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract a ZIP file, stripping N path prefix components.
    fn extract_zip_strip_prefix(
        &self,
        archive_path: &Path,
        ctx: &ExtractContext,
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
            let outpath = Self::validate_path_ctx(ctx, &stripped)?;

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
            ctx.canonical_dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract a plain tar archive with security checks.
    fn extract_plain_tar(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
        let file = File::open(archive_path)?;
        let file_size = file.metadata()?.len();
        let mut archive = Archive::new(BufReader::new(file));

        let mut total_size: u64 = 0;
        let mut file_count: usize = 0;

        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?;

            let dest_path = Self::validate_path_ctx(ctx, &path)?;

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
                    Self::validate_symlink_target_ctx(ctx, &target, &dest_path)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        symlink(&target, &dest_path)?;
                    }
                }
            } else if entry_type.is_hard_link() {
                // Hard links: validated against canonical_dest and materialized.
                if let Some(ref target) = link_name {
                    let resolved = Self::validate_hard_link_target_ctx(ctx, &dest_path, target)?;
                    #[cfg(any(unix, windows))]
                    {
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        fs::hard_link(&resolved, &dest_path)?;
                    }
                }
            }
        }

        debug!(
            "Extracted tar to {} ({} files, {} bytes)",
            ctx.canonical_dest.display(),
            file_count,
            total_size
        );
        Ok(())
    }

    /// Extract a URL-sourced package.
    ///
    /// Attempts to auto-detect the format by extension first, then magic
    /// bytes. URL packages are stored in CAS under extensionless hash names,
    /// so extension-only detection would copy most archives without extracting.
    fn extract_url_package(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
        match Self::detect_url_archive_format(archive_path)? {
            UrlArchiveFormat::GzipTar => self.extract_tarball(archive_path, ctx),
            UrlArchiveFormat::Zip => self.extract_zip(archive_path, ctx),
            UrlArchiveFormat::Tar => self.extract_plain_tar(archive_path, ctx),
            UrlArchiveFormat::XzTar => self.extract_xz_tarball(archive_path, ctx),
            UrlArchiveFormat::Unknown => {
                let filename = archive_path
                    .file_name()
                    .ok_or_else(|| CratonsError::Config("Invalid archive path".to_string()))?;
                let dest_path = Self::validate_path_ctx(ctx, Path::new(filename))?;
                fs::copy(archive_path, &dest_path)?;
                debug!("Copied URL package to {}", ctx.canonical_dest.display());
                Ok(())
            }
        }
    }

    fn detect_url_archive_format(archive_path: &Path) -> Result<UrlArchiveFormat> {
        let path_str = archive_path.to_string_lossy().to_lowercase();

        if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
            return Ok(UrlArchiveFormat::GzipTar);
        } else if path_str.ends_with(".zip") {
            return Ok(UrlArchiveFormat::Zip);
        } else if path_str.ends_with(".tar") {
            return Ok(UrlArchiveFormat::Tar);
        } else if path_str.ends_with(".tar.xz") || path_str.ends_with(".txz") {
            return Ok(UrlArchiveFormat::XzTar);
        }

        let mut file = File::open(archive_path)?;
        let mut header = [0_u8; 265];
        let bytes_read = file.read(&mut header)?;

        if bytes_read >= 6 && header[..6] == [0xfd, b'7', b'z', b'X', b'Z', 0x00] {
            Ok(UrlArchiveFormat::XzTar)
        } else if bytes_read >= 4
            && (&header[..4] == b"PK\x03\x04"
                || &header[..4] == b"PK\x05\x06"
                || &header[..4] == b"PK\x07\x08")
        {
            Ok(UrlArchiveFormat::Zip)
        } else if bytes_read >= 2 && header[..2] == [0x1f, 0x8b] {
            Ok(UrlArchiveFormat::GzipTar)
        } else if bytes_read >= 262 && &header[257..262] == b"ustar" {
            Ok(UrlArchiveFormat::Tar)
        } else {
            Ok(UrlArchiveFormat::Unknown)
        }
    }

    /// Extract an XZ-compressed tarball with security checks.
    fn extract_xz_tarball(&self, archive_path: &Path, ctx: &ExtractContext) -> Result<()> {
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

            let dest_path = Self::validate_path_ctx(ctx, &path)?;

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
                    Self::validate_symlink_target_ctx(ctx, &target, &dest_path)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        symlink(&target, &dest_path)?;
                    }
                }
            } else if entry_type.is_hard_link() {
                if let Some(ref target) = link_name {
                    let resolved = Self::validate_hard_link_target_ctx(ctx, &dest_path, target)?;
                    #[cfg(any(unix, windows))]
                    {
                        if dest_path.exists() {
                            fs::remove_file(&dest_path)?;
                        }
                        fs::hard_link(&resolved, &dest_path)?;
                    }
                }
            }
        }

        debug!(
            "Extracted xz tarball to {} ({} files, {} bytes)",
            ctx.canonical_dest.display(),
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

    #[test]
    fn extract_context_resolves_canonical_dest() {
        // ExtractContext must canonicalize the destination once, so that any
        // symlinks in the path (e.g. /var -> /private/var on macOS) are
        // resolved for all subsequent containment checks.
        let dest = TempDir::new().unwrap();
        let ctx = ExtractContext::new(dest.path()).expect("canonicalize");
        let expected = dest.path().canonicalize().unwrap();
        assert_eq!(ctx.canonical_dest, expected);
    }

    #[test]
    fn extract_context_new_rejects_missing_dest() {
        // A non-existent destination cannot be canonicalized; we refuse to
        // start extraction against an unknown root.
        let missing = std::path::PathBuf::from("/definitely/does/not/exist/cratons-test");
        assert!(ExtractContext::new(&missing).is_err());
    }

    #[test]
    fn validate_path_ctx_rejects_parent_dir() {
        let dest = TempDir::new().unwrap();
        let ctx = ExtractContext::new(dest.path()).unwrap();
        assert!(PackageExtractor::validate_path_ctx(&ctx, Path::new("../escape")).is_err());
    }

    #[test]
    fn validate_path_ctx_accepts_deeply_nested_new_path() {
        // Deeply nested not-yet-existing paths are allowed as long as their
        // ancestor resolves within canonical_dest. This closes L-1: the
        // previous implementation fell through to a non-canonical prefix
        // check for paths whose parent did not yet exist.
        let dest = TempDir::new().unwrap();
        let ctx = ExtractContext::new(dest.path()).unwrap();
        let result =
            PackageExtractor::validate_path_ctx(&ctx, Path::new("a/b/c/d/e/f/new-file.txt"));
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn validate_path_ctx_rejects_escape_via_symlinked_ancestor() {
        // Plant a symlink inside dest that points outside. A later entry that
        // tries to write through it must be rejected by the canonical
        // containment check.
        use std::os::unix::fs::symlink;
        let outside = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let link_path = dest.path().join("escape");
        symlink(outside.path(), &link_path).unwrap();

        let ctx = ExtractContext::new(dest.path()).unwrap();
        let result = PackageExtractor::validate_path_ctx(&ctx, Path::new("escape/new-file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn extract_url_package_detects_extensionless_targz_by_magic_bytes() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let archive_dir = TempDir::new().unwrap();
        let archive_path = archive_dir.path().join("b3ab7e-cas-object");
        let archive_file = File::create(&archive_path).unwrap();
        let encoder = GzEncoder::new(archive_file, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let contents = b"hello from url package";
        let mut header = tar::Header::new_gnu();
        header.set_path("nested/file.txt").unwrap();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append(&header, &contents[..]).unwrap();
        archive.into_inner().unwrap().finish().unwrap();

        let dest = TempDir::new().unwrap();
        let ctx = ExtractContext::new(dest.path()).unwrap();
        PackageExtractor::new()
            .extract_url_package(&archive_path, &ctx)
            .unwrap();

        let extracted = std::fs::read_to_string(dest.path().join("nested/file.txt")).unwrap();
        assert_eq!(extracted, "hello from url package");
    }
}
