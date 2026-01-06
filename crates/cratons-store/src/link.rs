//! Linking strategies for sharing files.

use cratons_core::Result;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, trace};

/// Strategy for linking files from the store into projects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkStrategy {
    /// Use hard links (default on POSIX, fastest)
    #[default]
    HardLink,
    /// Use symbolic links (works across filesystems)
    Symlink,
    /// Use reflinks (copy-on-write, APFS/Btrfs/XFS)
    Reflink,
    /// Full copy (fallback, slowest)
    Copy,
}

impl LinkStrategy {
    /// Detect the best strategy for the given source and target paths.
    #[must_use]
    pub fn detect(source: &Path, target: &Path) -> Self {
        // Check if on same filesystem (for hard links)
        if same_filesystem(source, target) {
            // Try to detect reflink support
            if Self::supports_reflink(source) {
                return Self::Reflink;
            }
            return Self::HardLink;
        }

        // Different filesystems - use symlinks if possible
        Self::Symlink
    }

    /// Check if the filesystem supports reflinks.
    #[cfg(target_os = "macos")]
    fn supports_reflink(path: &Path) -> bool {
        // APFS supports reflinks on macOS
        use std::process::Command;

        if let Ok(output) = Command::new("diskutil")
            .args(["info", "-plist"])
            .arg(path)
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.contains("APFS");
        }
        false
    }

    #[cfg(target_os = "linux")]
    fn supports_reflink(path: &Path) -> bool {
        // Check for Btrfs or XFS with reflink support
        use std::process::Command;

        if let Ok(output) = Command::new("stat")
            .args(["-f", "-c", "%T"])
            .arg(path)
            .output()
        {
            let fs_type = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_lowercase();
            return matches!(fs_type.as_str(), "btrfs" | "xfs");
        }
        false
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn supports_reflink(_path: &Path) -> bool {
        false
    }

    /// Link a single file from source to target.
    ///
    /// # TOCTOU Protection
    ///
    /// Instead of check-then-remove-then-create (which has a race window),
    /// we use atomic operations where possible:
    /// - For symlinks/hard links: create to temp path then rename (atomic)
    /// - For copies: write to temp then rename (atomic)
    ///
    /// The rename operation is atomic on POSIX systems, preventing attackers
    /// from inserting malicious content between remove and create.
    pub fn link_file(&self, source: &Path, target: &Path) -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Ensure parent directory exists
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        // Generate a unique temporary path in the same directory as target
        // (same directory ensures atomic rename works on same filesystem)
        let temp_name = format!(
            ".cratons-tmp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let temp_path = target
            .parent()
            .map(|p| p.join(&temp_name))
            .unwrap_or_else(|| PathBuf::from(&temp_name));

        // Create link/copy at temp path first
        let result = match self {
            Self::HardLink => {
                trace!(
                    "Hard linking {} -> {} (via temp)",
                    source.display(),
                    target.display()
                );
                match fs::hard_link(source, &temp_path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
                        debug!("Hard link failed (cross-device), falling back to copy");
                        fs::copy(source, &temp_path)?;
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            Self::Symlink => {
                trace!(
                    "Symlinking {} -> {} (via temp)",
                    source.display(),
                    target.display()
                );
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(source, &temp_path)?;
                    Ok(())
                }
                #[cfg(windows)]
                {
                    std::os::windows::fs::symlink_file(source, &temp_path)?;
                    Ok(())
                }
            }
            Self::Reflink => {
                trace!(
                    "Reflinking {} -> {} (via temp)",
                    source.display(),
                    target.display()
                );
                reflink_file(source, &temp_path)?;
                Ok(())
            }
            Self::Copy => {
                trace!(
                    "Copying {} -> {} (via temp)",
                    source.display(),
                    target.display()
                );
                fs::copy(source, &temp_path)?;
                Ok(())
            }
        };

        // Handle errors from link/copy creation
        if let Err(e) = result {
            let _ = fs::remove_file(&temp_path);
            return Err(e.into());
        }

        // Atomic rename: replace target with temp (this is atomic on POSIX)
        // This eliminates the TOCTOU window between remove and create
        if let Err(e) = fs::rename(&temp_path, target) {
            // Clean up temp file on failure
            let _ = fs::remove_file(&temp_path);
            return Err(e.into());
        }

        Ok(())
    }

    /// Link a directory tree from source to target.
    pub fn link_directory(&self, source: &Path, target: &Path) -> Result<()> {
        for entry in walkdir::WalkDir::new(source) {
            let entry = entry?;
            let relative = entry.path().strip_prefix(source).map_err(|e| {
                cratons_core::CratonsError::Io(std::io::Error::other(e.to_string()))
            })?;
            let target_path = target.join(relative);

            if entry.file_type().is_dir() {
                fs::create_dir_all(&target_path)?;
            } else if entry.file_type().is_file() {
                self.link_file(entry.path(), &target_path)?;
            } else if entry.file_type().is_symlink() {
                // Preserve symlinks using atomic rename to prevent TOCTOU
                use std::time::{SystemTime, UNIX_EPOCH};

                let link_target = fs::read_link(entry.path())?;

                // Create a unique temp path in the same directory
                let temp_name = format!(
                    ".cratons-tmp-symlink-{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                );
                let temp_path = target_path
                    .parent()
                    .map(|p| p.join(&temp_name))
                    .unwrap_or_else(|| PathBuf::from(&temp_name));

                // Create symlink at temp path
                #[cfg(unix)]
                std::os::unix::fs::symlink(&link_target, &temp_path)?;
                #[cfg(windows)]
                std::os::windows::fs::symlink_file(&link_target, &temp_path)?;

                // Atomic rename to target (replaces existing)
                if let Err(e) = fs::rename(&temp_path, &target_path) {
                    let _ = fs::remove_file(&temp_path);
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }
}

/// Check if two paths are on the same filesystem.
fn same_filesystem(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let a_meta = match a.metadata().or_else(|_| {
            a.parent()
                .map(Path::metadata)
                .unwrap_or(Err(std::io::Error::other("")))
        }) {
            Ok(m) => m,
            Err(_) => return false,
        };
        let b_meta = match b.metadata().or_else(|_| {
            b.parent()
                .map(Path::metadata)
                .unwrap_or(Err(std::io::Error::other("")))
        }) {
            Ok(m) => m,
            Err(_) => return false,
        };

        a_meta.dev() == b_meta.dev()
    }

    #[cfg(not(unix))]
    {
        // On Windows, assume same filesystem for simplicity
        // A more robust implementation would check volume serial numbers
        let _ = (a, b);
        true
    }
}

/// Create a reflink copy (copy-on-write).
///
/// # Safety vs Performance
///
/// Since we forbid `unsafe` code in this codebase to maintain high security standards,
/// we use the `cp --reflink=auto` command on Linux instead of using `libc::ioctl`
/// or other FFI bindings which would require `unsafe` blocks.
///
/// While spawning a process has a slight overhead compared to a syscall, it provides:
/// 1. Complete memory safety (no raw pointer manipulation)
/// 2. Robustness (deferring to the highly-optimized system `cp` binary)
/// 3. Future-proofing (if the OS changes reflink implementation details)
#[cfg(target_os = "linux")]
fn reflink_file(source: &Path, target: &Path) -> Result<()> {
    use std::process::Command;

    // Try cp --reflink=auto which does CoW if available, regular copy otherwise
    let status = Command::new("cp")
        .arg("--reflink=auto")
        .arg(source)
        .arg(target)
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        _ => {
            debug!("Reflink via cp failed, falling back to regular copy");
            fs::copy(source, target)?;
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
fn reflink_file(source: &Path, target: &Path) -> Result<()> {
    use std::process::Command;

    // Try cp -c which uses clonefile on APFS
    let status = Command::new("cp")
        .arg("-c")
        .arg(source)
        .arg(target)
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        _ => {
            debug!("Reflink via cp failed, falling back to regular copy");
            fs::copy(source, target)?;
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn reflink_file(source: &Path, target: &Path) -> Result<()> {
    // No reflink support, use regular copy
    fs::copy(source, target)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_hard_link() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");

        fs::write(&source, b"test content").unwrap();

        LinkStrategy::HardLink.link_file(&source, &target).unwrap();

        assert!(target.exists());
        assert_eq!(fs::read(&target).unwrap(), b"test content");
    }

    #[test]
    fn test_symlink() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");

        fs::write(&source, b"test content").unwrap();

        LinkStrategy::Symlink.link_file(&source, &target).unwrap();

        assert!(target.is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"test content");
    }

    #[test]
    fn test_copy() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");

        fs::write(&source, b"test content").unwrap();

        LinkStrategy::Copy.link_file(&source, &target).unwrap();

        assert!(target.exists());
        assert_eq!(fs::read(&target).unwrap(), b"test content");
    }
}
