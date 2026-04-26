//! Safe archive extraction utilities.
//!
//! This module provides secure extraction of tar and zip archives with protection
//! against path traversal attacks (e.g., files with paths like `../../../etc/passwd`).
//!
//! # Security
//!
//! All extraction functions validate that extracted file paths:
//! - Are relative (not absolute)
//! - Do not contain `..` components that would escape the destination
//! - Are within the canonical destination directory
//!
//! This prevents "zip slip" and similar attacks where malicious archives could
//! overwrite arbitrary files on the filesystem.

use cratons_core::{CratonsError, Result};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use tracing::debug;

/// Hard upper bound on the total extracted bytes from a single archive.
///
/// This caps zip-bomb / tar-bomb DoS: a small compressed input that
/// decompresses to terabytes will hit this limit and abort extraction
/// rather than fill the host disk. 16 GiB is generous enough for legitimate
/// large packages (e.g. fat node_modules trees, multi-arch toolchains)
/// while still bounding pathological inputs orders of magnitude below
/// modern disk sizes.
pub const MAX_EXTRACTED_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Bounded copy from a reader into a writer that aborts when the running
/// total across all archive entries exceeds [`MAX_EXTRACTED_BYTES`].
fn copy_with_extracted_budget<R: Read, W: io::Write>(
    src: &mut R,
    dst: &mut W,
    extracted_total: &mut u64,
    archive_kind: &'static str,
) -> Result<u64> {
    // Heap-allocated to keep the stack frame small; the same pattern is
    // used in cratons-core hash::hash_file for the same reason.
    let mut buf = vec![0u8; 64 * 1024];
    let mut entry_total = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return Ok(entry_total);
        }
        let next_total = extracted_total.saturating_add(n as u64);
        if next_total > MAX_EXTRACTED_BYTES {
            return Err(CratonsError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} archive exceeded extraction budget ({} bytes); refusing to continue",
                    archive_kind, MAX_EXTRACTED_BYTES
                ),
            )));
        }
        dst.write_all(&buf[..n])?;
        *extracted_total = next_total;
        entry_total = entry_total.saturating_add(n as u64);
    }
}

/// Validates that a path is safe to extract to within a destination directory.
///
/// Returns the sanitized path relative to the destination, or an error if the
/// path would escape the destination directory.
///
/// # Security
///
/// This function protects against:
/// - Absolute paths (e.g., `/etc/passwd`)
/// - Path traversal (e.g., `../../../etc/passwd`)
/// - Symlink-based escapes (by checking the canonical path)
fn validate_extract_path(dest: &Path, entry_path: &Path) -> Result<PathBuf> {
    // Build a sanitized path by processing each component
    let mut sanitized = PathBuf::new();

    for component in entry_path.components() {
        match component {
            Component::Normal(name) => {
                sanitized.push(name);
            }
            Component::CurDir => {
                // Current directory (.) is allowed but ignored
            }
            Component::ParentDir => {
                // Parent directory (..) is dangerous - reject the entire path
                return Err(CratonsError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Path traversal attempt detected: archive contains '..': {}",
                        entry_path.display()
                    ),
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                // Absolute paths are rejected
                return Err(CratonsError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Absolute path in archive rejected: {}",
                        entry_path.display()
                    ),
                )));
            }
        }
    }

    // Final check: ensure the resolved path is within the destination
    let full_path = dest.join(&sanitized);

    // Canonicalize the destination (it must exist)
    let canonical_dest = dest.canonicalize().map_err(|e| {
        CratonsError::Io(io::Error::new(
            e.kind(),
            format!(
                "Failed to canonicalize destination {}: {}",
                dest.display(),
                e
            ),
        ))
    })?;

    // For the full path, we need to check its parent (the file may not exist yet)
    // and verify it would be within the destination
    let mut check_path = full_path.clone();
    while !check_path.exists() {
        if let Some(parent) = check_path.parent() {
            check_path = parent.to_path_buf();
        } else {
            break;
        }
    }

    if check_path.exists() {
        let canonical_check = check_path.canonicalize().map_err(|e| {
            CratonsError::Io(io::Error::new(
                e.kind(),
                format!(
                    "Failed to canonicalize path {}: {}",
                    check_path.display(),
                    e
                ),
            ))
        })?;

        if !canonical_check.starts_with(&canonical_dest) {
            return Err(CratonsError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Path escapes destination directory: {} is not within {}",
                    entry_path.display(),
                    dest.display()
                ),
            )));
        }
    }

    Ok(sanitized)
}

/// Validate that a symlink target stays within the extraction directory.
fn validate_symlink_target(target: &Path, link_path: &Path) -> Result<()> {
    if target.as_os_str().is_empty() {
        return Err(CratonsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Empty symlink target rejected: {}", link_path.display()),
        )));
    }

    if target.is_absolute() {
        return Err(CratonsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Absolute symlink target rejected: {} -> {}",
                link_path.display(),
                target.display()
            ),
        )));
    }

    let mut depth = link_path
        .parent()
        .map(|parent| {
            parent
                .components()
                .filter(|component| matches!(component, Component::Normal(_)))
                .count() as i32
        })
        .unwrap_or(0);

    for component in target.components() {
        match component {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return Err(CratonsError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Symlink target escapes destination: {} -> {}",
                            link_path.display(),
                            target.display()
                        ),
                    )));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(CratonsError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Absolute symlink component rejected: {} -> {}",
                        link_path.display(),
                        target.display()
                    ),
                )));
            }
            Component::Normal(_) => {
                depth += 1;
            }
            Component::CurDir => {}
        }
    }

    Ok(())
}

/// Validate that a tar hard-link target resolves to an existing file inside `dest`.
fn validate_hard_link_target(dest: &Path, target: &Path, link_path: &Path) -> Result<PathBuf> {
    if target.as_os_str().is_empty() {
        return Err(CratonsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Empty hard link target rejected: {}", link_path.display()),
        )));
    }

    if target.is_absolute() {
        return Err(CratonsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Absolute hard link target rejected: {} -> {}",
                link_path.display(),
                target.display()
            ),
        )));
    }

    for component in target.components() {
        match component {
            Component::ParentDir => {
                return Err(CratonsError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Hard link target escapes destination: {} -> {}",
                        link_path.display(),
                        target.display()
                    ),
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(CratonsError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Absolute hard link component rejected: {} -> {}",
                        link_path.display(),
                        target.display()
                    ),
                )));
            }
            Component::Normal(_) | Component::CurDir => {}
        }
    }

    let canonical_dest = dest.canonicalize().map_err(|e| {
        CratonsError::Io(io::Error::new(
            e.kind(),
            format!(
                "Failed to canonicalize destination {}: {}",
                dest.display(),
                e
            ),
        ))
    })?;
    let resolved = canonical_dest.join(target);

    if !resolved.exists() {
        return Err(CratonsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Hard link target does not exist inside destination: {} -> {}",
                link_path.display(),
                target.display()
            ),
        )));
    }

    let canonical_target = resolved.canonicalize().map_err(|e| {
        CratonsError::Io(io::Error::new(
            e.kind(),
            format!(
                "Failed to canonicalize hard link target {}: {}",
                resolved.display(),
                e
            ),
        ))
    })?;

    if !canonical_target.starts_with(&canonical_dest) {
        return Err(CratonsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Hard link target escapes destination: {} -> {}",
                link_path.display(),
                target.display()
            ),
        )));
    }

    Ok(canonical_target)
}

fn remove_existing_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Safely extract a tar archive to a destination directory.
///
/// This function validates each entry path before extraction to prevent
/// path traversal attacks.
///
/// # Security
///
/// - Rejects paths containing `..`
/// - Rejects absolute paths
/// - Validates that all extracted files remain within the destination
/// - Preserves file permissions but not ownership (unprivileged extraction)
pub fn safe_unpack_tar<R: Read>(archive: &mut tar::Archive<R>, dest: &Path) -> Result<()> {
    safe_unpack_tar_with_strip(archive, dest, 0)
}

/// Safely extract a tar archive with path component stripping (L-10).
///
/// The `strip_components` parameter removes the first N path components from each
/// entry. This is equivalent to `tar --strip-components=N`.
///
/// Common use: `strip_components=1` removes the top-level directory that most
/// tarballs have (e.g., `package-1.0.0/src/main.rs` becomes `src/main.rs`).
pub fn safe_unpack_tar_with_strip<R: Read>(
    archive: &mut tar::Archive<R>,
    dest: &Path,
    strip_components: usize,
) -> Result<()> {
    // Ensure destination exists and is a directory
    fs::create_dir_all(dest)?;

    // Track cumulative extracted bytes to enforce MAX_EXTRACTED_BYTES.
    let mut extracted_total: u64 = 0;

    // Get entries and process them one by one with validation
    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_path = entry.path()?;

        // Strip leading path components if requested
        let stripped_path = if strip_components > 0 {
            let components: Vec<_> = entry_path.components().collect();
            if components.len() <= strip_components {
                // This entry is within the stripped prefix, skip it
                debug!(
                    "Skipping entry within strip prefix: {}",
                    entry_path.display()
                );
                continue;
            }
            PathBuf::from_iter(components.into_iter().skip(strip_components))
        } else {
            entry_path.to_path_buf()
        };

        // SECURITY: Fail-closed on path validation. A malformed entry —
        // whether a real attack or a corrupt archive — aborts the whole
        // extraction rather than producing a partial result with silently
        // dropped entries. Warn-and-continue lets a single planted entry
        // sit alongside a benign tarball and still ship the rest.
        let sanitized_path = validate_extract_path(dest, &stripped_path).map_err(|e| {
            CratonsError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Refusing to extract tar entry '{}': {e}",
                    entry_path.display()
                ),
            ))
        })?;

        let full_path = dest.join(&sanitized_path);

        // Handle different entry types
        let entry_type = entry.header().entry_type();
        match entry_type {
            tar::EntryType::Directory => {
                fs::create_dir_all(&full_path)?;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                // Create parent directories
                if let Some(parent) = full_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                // Extract file with cumulative-byte budget enforcement.
                let mut file = File::create(&full_path)?;
                copy_with_extracted_budget(&mut entry, &mut file, &mut extracted_total, "tar")?;

                // Preserve permissions on Unix, but strip SUID/SGID/sticky
                // bits. A malicious archive must never be able to install a
                // setuid binary via cratons, regardless of the process uid.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(mode) = entry.header().mode() {
                        let permissions = fs::Permissions::from_mode(mode & 0o777);
                        fs::set_permissions(&full_path, permissions)?;
                    }
                }
            }
            tar::EntryType::Symlink => {
                let target = match entry.link_name() {
                    Ok(Some(target)) => target.into_owned(),
                    Ok(None) => {
                        return Err(CratonsError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Refusing to extract tar symlink '{}': missing target",
                                entry_path.display()
                            ),
                        )));
                    }
                    Err(err) => {
                        return Err(CratonsError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Refusing to extract tar symlink '{}': {err}",
                                entry_path.display()
                            ),
                        )));
                    }
                };

                validate_symlink_target(&target, &sanitized_path).map_err(|e| {
                    CratonsError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Refusing to extract tar symlink '{}' -> '{}': {e}",
                            entry_path.display(),
                            target.display()
                        ),
                    ))
                })?;

                if let Some(parent) = full_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;

                    remove_existing_path(&full_path)?;
                    symlink(&target, &full_path)?;
                }

                #[cfg(windows)]
                {
                    debug!("Skipping symlink on Windows: {}", entry_path.display());
                }
            }
            tar::EntryType::Link => {
                let target = match entry.link_name() {
                    Ok(Some(target)) => target.into_owned(),
                    Ok(None) => {
                        return Err(CratonsError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Refusing to extract hard link '{}': missing target",
                                entry_path.display()
                            ),
                        )));
                    }
                    Err(err) => {
                        return Err(CratonsError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Refusing to extract hard link '{}': {err}",
                                entry_path.display()
                            ),
                        )));
                    }
                };

                let source = validate_hard_link_target(dest, &target, &sanitized_path).map_err(
                    |e| {
                        CratonsError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Refusing to extract hard link '{}' -> '{}': {e}",
                                entry_path.display(),
                                target.display()
                            ),
                        ))
                    },
                )?;

                if let Some(parent) = full_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                remove_existing_path(&full_path)?;
                fs::hard_link(&source, &full_path)?;
            }
            _ => {
                debug!(
                    "Skipping unsupported entry type {:?}: {}",
                    entry_type,
                    entry_path.display()
                );
            }
        }
    }

    Ok(())
}

/// Safely extract a ZIP archive to a destination directory.
///
/// This function validates each entry path before extraction to prevent
/// path traversal attacks.
pub fn safe_extract_zip(
    archive: &mut zip::ZipArchive<impl Read + io::Seek>,
    dest: &Path,
) -> Result<()> {
    safe_extract_zip_with_strip(archive, dest, 0)
}

/// Safely extract a ZIP archive with path component stripping (L-10).
pub fn safe_extract_zip_with_strip(
    archive: &mut zip::ZipArchive<impl Read + io::Seek>,
    dest: &Path,
    strip_components: usize,
) -> Result<()> {
    // Ensure destination exists
    fs::create_dir_all(dest)?;

    // Track cumulative extracted bytes to enforce MAX_EXTRACTED_BYTES.
    // Caps zip-bomb DoS: a small malicious zip can decompress to TBs.
    let mut extracted_total: u64 = 0;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| {
            CratonsError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        })?;

        // Fail-closed: an entry whose name escapes the zip's logical layout
        // (absolute path, embedded NUL, or path-traversal sequences) is treated
        // as a hostile archive rather than a benign quirk. See the tar branch
        // above for the same rationale.
        let entry_path = match file.enclosed_name() {
            Some(p) => p.to_path_buf(),
            None => {
                return Err(CratonsError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Refusing to extract zip entry with unsafe name: '{}'",
                        file.name()
                    ),
                )));
            }
        };

        // Strip leading path components if requested
        let stripped_path = if strip_components > 0 {
            let components: Vec<_> = entry_path.components().collect();
            if components.len() <= strip_components {
                // This entry is within the stripped prefix, skip it
                continue;
            }
            PathBuf::from_iter(components.into_iter().skip(strip_components))
        } else {
            entry_path.clone()
        };

        let sanitized_path = validate_extract_path(dest, &stripped_path).map_err(|e| {
            CratonsError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Refusing to extract zip entry '{}': {e}",
                    entry_path.display()
                ),
            ))
        })?;

        let full_path = dest.join(&sanitized_path);

        if file.is_dir() {
            fs::create_dir_all(&full_path)?;
        } else {
            // Create parent directories
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Extract file with cumulative-byte budget enforcement.
            let mut outfile = File::create(&full_path)?;
            copy_with_extracted_budget(&mut file, &mut outfile, &mut extracted_total, "zip")?;

            // Preserve permissions on Unix, but strip SUID/SGID/sticky
            // bits so a malicious zip cannot install a setuid binary.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    let permissions = fs::Permissions::from_mode(mode & 0o777);
                    fs::set_permissions(&full_path, permissions)?;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io;

    use tempfile::tempdir;

    #[test]
    fn test_validate_normal_path() {
        let temp = tempdir().unwrap();
        let dest = temp.path();

        let result = validate_extract_path(dest, Path::new("foo/bar/baz.txt"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("foo/bar/baz.txt"));
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        let temp = tempdir().unwrap();
        let dest = temp.path();

        let result = validate_extract_path(dest, Path::new("foo/../../../etc/passwd"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Path traversal"));
    }

    #[test]
    fn test_validate_absolute_path_rejected() {
        let temp = tempdir().unwrap();
        let dest = temp.path();

        let result = validate_extract_path(dest, Path::new("/etc/passwd"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Absolute path"));
    }

    #[test]
    fn test_validate_current_dir_normalized() {
        let temp = tempdir().unwrap();
        let dest = temp.path();

        let result = validate_extract_path(dest, Path::new("./foo/./bar.txt"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("foo/bar.txt"));
    }

    #[test]
    fn test_safe_unpack_tar() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();

        // Create a simple tar archive in memory
        let mut builder = tar::Builder::new(Vec::new());

        // Add a regular file
        let data = b"hello world";
        let mut header = tar::Header::new_gnu();
        header.set_path("test/hello.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();

        // Extract it safely
        let mut archive = tar::Archive::new(&tar_data[..]);
        safe_unpack_tar(&mut archive, &dest).unwrap();

        // Verify extraction
        let extracted = dest.join("test/hello.txt");
        assert!(extracted.exists());
        assert_eq!(fs::read_to_string(extracted).unwrap(), "hello world");
    }

    #[cfg(unix)]
    #[test]
    fn test_safe_unpack_tar_strips_setuid_bits() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let data = b"suid payload";
        let mut header = tar::Header::new_gnu();
        header.set_path("pkg/setuid.bin").unwrap();
        header.set_size(data.len() as u64);
        // SUID + SGID + sticky + world-exec
        header.set_mode(0o7755);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = tar::Archive::new(&tar_data[..]);
        safe_unpack_tar(&mut archive, &dest).unwrap();

        let extracted = dest.join("pkg/setuid.bin");
        let mode = fs::metadata(&extracted).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            mode & 0o7000,
            0,
            "SUID/SGID/sticky bits must be stripped, got {:o}",
            mode
        );
        assert_eq!(mode & 0o777, 0o755, "standard permissions must survive");
    }

    #[test]
    fn test_safe_unpack_tar_enforces_extraction_budget() {
        // Regression for E-4: a malicious tar with a single oversized
        // entry must not be allowed to fill the host disk. Use a tiny
        // local cap by re-using the public budget against a generous
        // payload — the payload is larger than the local check window
        // but still small enough for tests. We check the helper
        // directly so the test stays cheap.
        let mut sink = Vec::new();
        let mut src = std::io::repeat(b'x').take(1024 * 1024); // 1 MiB stream
        let mut total: u64 = MAX_EXTRACTED_BYTES - 512;
        let err = copy_with_extracted_budget(&mut src, &mut sink, &mut total, "tar")
            .expect_err("budget overrun must error");
        assert!(
            err.to_string().contains("extraction budget"),
            "expected extraction-budget error, got {err}"
        );
    }

    #[test]
    fn test_safe_unpack_tar_rejects_absolute_symlink_targets() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_path("pkg/link").unwrap();
        header.set_link_name("/etc/passwd").unwrap();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        builder.append(&header, io::empty()).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = tar::Archive::new(&tar_data[..]);
        let err = safe_unpack_tar(&mut archive, &dest)
            .expect_err("absolute symlink target must abort extraction");
        assert!(
            err.to_string().contains("Refusing to extract"),
            "expected fail-closed error, got {err}"
        );
        assert!(dest.join("pkg/link").symlink_metadata().is_err());
    }

    #[test]
    fn test_safe_unpack_tar_rejects_absolute_hard_link_targets() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let data = b"hello world";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_path("pkg/hello.txt").unwrap();
        file_header.set_size(data.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        builder.append(&file_header, &data[..]).unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_path("pkg/escape.txt").unwrap();
        link_header.set_link_name("/etc/passwd").unwrap();
        link_header.set_size(0);
        link_header.set_mode(0o644);
        link_header.set_cksum();
        builder.append(&link_header, io::empty()).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = tar::Archive::new(&tar_data[..]);
        let err = safe_unpack_tar(&mut archive, &dest)
            .expect_err("absolute hard link target must abort extraction");
        assert!(
            err.to_string().contains("Refusing to extract"),
            "expected fail-closed error, got {err}"
        );
        assert!(!dest.join("pkg/escape.txt").exists());
    }

    #[test]
    fn test_safe_unpack_tar_creates_internal_hard_links() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("extract");
        fs::create_dir_all(&dest).unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let data = b"payload";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_path("pkg/target.txt").unwrap();
        file_header.set_size(data.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        builder.append(&file_header, &data[..]).unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_path("pkg/link.txt").unwrap();
        link_header.set_link_name("pkg/target.txt").unwrap();
        link_header.set_size(0);
        link_header.set_mode(0o644);
        link_header.set_cksum();
        builder.append(&link_header, io::empty()).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = tar::Archive::new(&tar_data[..]);
        safe_unpack_tar(&mut archive, &dest).unwrap();

        let target = dest.join("pkg/target.txt");
        let link = dest.join("pkg/link.txt");
        assert_eq!(fs::read(&target).unwrap(), b"payload");
        assert_eq!(fs::read(&link).unwrap(), b"payload");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let target_meta = fs::metadata(target).unwrap();
            let link_meta = fs::metadata(link).unwrap();
            assert_eq!(target_meta.ino(), link_meta.ino());
        }
    }
}
