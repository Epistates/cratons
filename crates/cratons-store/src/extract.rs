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
use tracing::{debug, warn};

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

        // Validate the path
        let sanitized_path = match validate_extract_path(dest, &stripped_path) {
            Ok(p) => p,
            Err(e) => {
                warn!("Skipping potentially malicious archive entry: {}", e);
                continue;
            }
        };

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

                // Extract file
                let mut file = File::create(&full_path)?;
                io::copy(&mut entry, &mut file)?;

                // Preserve permissions on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(mode) = entry.header().mode() {
                        let permissions = fs::Permissions::from_mode(mode);
                        fs::set_permissions(&full_path, permissions)?;
                    }
                }
            }
            tar::EntryType::Symlink | tar::EntryType::Link => {
                // Validate symlink targets too
                if let Ok(link_target) = entry.link_name() {
                    if let Some(target) = link_target {
                        // Check if symlink target would escape destination
                        let resolved = sanitized_path
                            .parent()
                            .unwrap_or(Path::new(""))
                            .join(&target);

                        if resolved
                            .components()
                            .any(|c| matches!(c, Component::ParentDir))
                        {
                            let depth: i32 = resolved
                                .components()
                                .map(|c| match c {
                                    Component::ParentDir => -1,
                                    Component::Normal(_) => 1,
                                    _ => 0,
                                })
                                .scan(0i32, |acc, x| {
                                    *acc += x;
                                    Some(*acc)
                                })
                                .min()
                                .unwrap_or(0);

                            if depth < 0 {
                                warn!(
                                    "Skipping symlink that escapes destination: {} -> {}",
                                    entry_path.display(),
                                    target.display()
                                );
                                continue;
                            }
                        }

                        // Create parent directory
                        if let Some(parent) = full_path.parent() {
                            fs::create_dir_all(parent)?;
                        }

                        // Create symlink (Unix) or copy (Windows)
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::symlink;
                            if full_path.exists() || full_path.symlink_metadata().is_ok() {
                                fs::remove_file(&full_path)?;
                            }
                            symlink(target, &full_path)?;
                        }

                        #[cfg(windows)]
                        {
                            // On Windows, we'll skip symlinks or try to copy instead
                            debug!("Skipping symlink on Windows: {}", entry_path.display());
                        }
                    }
                }
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

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| {
            CratonsError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        })?;

        let entry_path = match file.enclosed_name() {
            Some(p) => p.to_path_buf(),
            None => {
                warn!("Skipping zip entry with invalid name");
                continue;
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

        // Validate the path
        let sanitized_path = match validate_extract_path(dest, &stripped_path) {
            Ok(p) => p,
            Err(e) => {
                warn!("Skipping potentially malicious zip entry: {}", e);
                continue;
            }
        };

        let full_path = dest.join(&sanitized_path);

        if file.is_dir() {
            fs::create_dir_all(&full_path)?;
        } else {
            // Create parent directories
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Extract file
            let mut outfile = File::create(&full_path)?;
            io::copy(&mut file, &mut outfile)?;

            // Preserve permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    let permissions = fs::Permissions::from_mode(mode);
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
}
