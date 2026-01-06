//! Rootfs preparation for build containers.

use cratons_core::Result;
use cratons_store::Store;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

use crate::config::BuildConfig;

/// Builder for container root filesystems.
pub struct RootfsBuilder<'a> {
    store: &'a Store,
    store_mount_point: &'a Path,
}

impl<'a> RootfsBuilder<'a> {
    /// Create a new rootfs builder.
    #[must_use]
    pub fn new(store: &'a Store, store_mount_point: &'a Path) -> Self {
        Self {
            store,
            store_mount_point,
        }
    }

    /// Build the rootfs for a build container.
    pub async fn build(
        &self,
        config: &BuildConfig,
        source_dir: &Path,
        work_dir: &Path,
    ) -> Result<PathBuf> {
        let rootfs = work_dir.join("rootfs");
        fs::create_dir_all(&rootfs)?;

        // Create essential directories
        self.create_base_structure(&rootfs)?;

        // Copy source code (read-only in container)
        self.copy_source(source_dir, &rootfs.join("src"))?;

        // Link toolchains
        for tc in &config.toolchains {
            self.link_toolchain(&tc.name, &tc.version, &rootfs)?;
        }

        // Link dependencies
        let deps_dir = rootfs.join("deps");
        fs::create_dir_all(&deps_dir)?;
        for dep in &config.dependencies {
            self.link_dependency(&dep.name, &dep.hash, &deps_dir)?;
        }

        // Create output directory (writable)
        fs::create_dir_all(rootfs.join("out"))?;

        // Create tmp directory
        fs::create_dir_all(rootfs.join("tmp"))?;

        debug!("Rootfs prepared at {}", rootfs.display());
        Ok(rootfs)
    }

    /// Create the base directory structure.
    fn create_base_structure(&self, rootfs: &Path) -> Result<()> {
        let dirs = [
            "bin",
            "dev",
            "etc",
            "lib",
            "lib64",
            "proc",
            "run",
            "sys",
            "tmp",
            "usr/bin",
            "usr/lib",
            "usr/local/bin",
            "var/tmp",
        ];

        for dir in dirs {
            fs::create_dir_all(rootfs.join(dir))?;
        }

        // Create minimal /etc files
        fs::write(
            rootfs.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n",
        )?;
        fs::write(rootfs.join("etc/group"), "root:x:0:\nnogroup:x:65534:\n")?;
        fs::write(rootfs.join("etc/hosts"), "127.0.0.1 localhost\n")?;

        Ok(())
    }

    /// Copy source code into rootfs.
    fn copy_source(&self, source: &Path, target: &Path) -> Result<()> {
        if !source.exists() {
            return Ok(());
        }

        fs::create_dir_all(target)?;

        for entry in walkdir::WalkDir::new(source)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !is_ignored(e.path()))
        {
            let entry = entry?;
            let relative = entry.path().strip_prefix(source).map_err(|e| {
                cratons_core::CratonsError::Io(std::io::Error::other(e.to_string()))
            })?;
            let dest = target.join(relative);

            if entry.file_type().is_dir() {
                fs::create_dir_all(&dest)?;
            } else if entry.file_type().is_file() {
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(entry.path(), &dest)?;
            }
        }

        Ok(())
    }

    /// Link a toolchain from the store.
    fn link_toolchain(&self, name: &str, version: &str, rootfs: &Path) -> Result<()> {
        if let Some(tc_path) = self.store.toolchains().get_by_name_version(name, version) {
            let relative_path = tc_path.strip_prefix(self.store.root()).map_err(|e| {
                cratons_core::CratonsError::Io(std::io::Error::other(format!(
                    "Toolchain path outside store: {}",
                    e
                )))
            })?;
            let container_path = self.store_mount_point.join(relative_path);

            let target = rootfs.join("toolchain").join(name);
            fs::create_dir_all(target.parent().unwrap())?;

            #[cfg(unix)]
            std::os::unix::fs::symlink(&container_path, &target)?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(&container_path, &target)?;

            debug!(
                "Linked toolchain {} -> {} (host: {})",
                name,
                container_path.display(),
                tc_path.display()
            );
        }
        Ok(())
    }

    /// Link a dependency from the store.
    fn link_dependency(
        &self,
        name: &str,
        hash: &cratons_core::ContentHash,
        deps_dir: &Path,
    ) -> Result<()> {
        if let Some(dep_path) = self.store.get_artifact(hash) {
            let relative_path = dep_path.strip_prefix(self.store.root()).map_err(|e| {
                cratons_core::CratonsError::Io(std::io::Error::other(format!(
                    "Dependency path outside store: {}",
                    e
                )))
            })?;
            let container_path = self.store_mount_point.join(relative_path);

            let target = deps_dir.join(name);

            #[cfg(unix)]
            std::os::unix::fs::symlink(&container_path, &target)?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(&container_path, &target)?;

            debug!(
                "Linked dependency {} -> {} (host: {})",
                name,
                container_path.display(),
                dep_path.display()
            );
        }
        Ok(())
    }
}

/// Check if a path should be ignored when copying source.
fn is_ignored(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();

    matches!(
        name.as_ref(),
        ".git"
            | ".hg"
            | ".svn"
            | "node_modules"
            | "__pycache__"
            | ".pytest_cache"
            | "target"
            | "dist"
            | "build"
            | ".cratons"
            | "cratons.lock"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ignored() {
        assert!(is_ignored(Path::new(".git")));
        assert!(is_ignored(Path::new("node_modules")));
        assert!(is_ignored(Path::new("target")));
        assert!(!is_ignored(Path::new("src")));
        assert!(!is_ignored(Path::new("main.rs")));
    }
}
