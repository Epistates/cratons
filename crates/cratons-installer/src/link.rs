//! Package linking from CAS to project directories.

use cratons_core::{Ecosystem, CratonsError, Result};
use cratons_store::Store;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;
use walkdir::WalkDir;

use crate::LinkStrategy;

/// Links packages from content-addressable storage to project directories.
pub struct PackageLinker<'a> {
    #[allow(dead_code)] // Reserved for CAS-based linking
    store: &'a Store,
    strategy: LinkStrategy,
}

impl<'a> PackageLinker<'a> {
    /// Create a new linker.
    pub fn new(store: &'a Store, strategy: LinkStrategy) -> Self {
        Self { store, strategy }
    }

    /// Link a package to the project's install directory.
    pub fn link_package(
        &self,
        source: &Path,
        install_dir: &Path,
        ecosystem: Ecosystem,
        package_name: &str,
    ) -> Result<PathBuf> {
        match ecosystem {
            Ecosystem::Npm => self.link_npm_package(source, install_dir, package_name),
            Ecosystem::PyPi => self.link_pypi_package(source, install_dir, package_name),
            Ecosystem::Crates => self.link_crate(source, install_dir, package_name),
            Ecosystem::Go => self.link_go_module(source, install_dir, package_name),
            Ecosystem::Maven => self.link_maven_artifact(source, install_dir, package_name),
            Ecosystem::Url => self.link_url_package(source, install_dir, package_name),
        }
    }

    /// Link a URL-sourced package.
    fn link_url_package(
        &self,
        source: &Path,
        install_dir: &Path,
        package_name: &str,
    ) -> Result<PathBuf> {
        let dest = install_dir.join(package_name);
        self.create_link(source, &dest)?;
        debug!("Linked URL package {} to {}", package_name, dest.display());
        Ok(dest)
    }

    /// Link an npm package to node_modules.
    ///
    /// Structure:
    /// ```text
    /// node_modules/
    /// ├── lodash/           -> symlink to CAS or copy
    /// │   ├── package.json
    /// │   └── index.js
    /// └── @scope/
    ///     └── package/      -> symlink or copy
    /// ```
    fn link_npm_package(
        &self,
        source: &Path,
        install_dir: &Path,
        package_name: &str,
    ) -> Result<PathBuf> {
        let dest = if package_name.starts_with('@') {
            // Scoped package: @scope/name -> node_modules/@scope/name
            let parts: Vec<&str> = package_name.splitn(2, '/').collect();
            if parts.len() == 2 {
                let scope_dir = install_dir.join(parts[0]);
                fs::create_dir_all(&scope_dir)?;
                scope_dir.join(parts[1])
            } else {
                install_dir.join(package_name)
            }
        } else {
            install_dir.join(package_name)
        };

        self.create_link(source, &dest)?;
        debug!("Linked npm package {} to {}", package_name, dest.display());
        Ok(dest)
    }

    /// Link a PyPI package to site-packages.
    ///
    /// For Python, we typically link the package directory and any .dist-info.
    fn link_pypi_package(
        &self,
        source: &Path,
        install_dir: &Path,
        package_name: &str,
    ) -> Result<PathBuf> {
        // Python package names are normalized (- to _, lowercase)
        let normalized = package_name.replace('-', "_").to_lowercase();

        // Find the actual package directory in the source
        // Wheels extract to: package_name/ and package_name-version.dist-info/
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Link package directories and dist-info
            if name_str.starts_with(&normalized) || name_str.contains(".dist-info") {
                let dest = install_dir.join(&name);
                self.create_link(&entry.path(), &dest)?;
            }
        }

        let dest = install_dir.join(&normalized);
        debug!(
            "Linked PyPI package {} to {}",
            package_name,
            install_dir.display()
        );
        Ok(dest)
    }

    /// Link a Rust crate to Cargo registry.
    ///
    /// Crates are stored in ~/.cargo/registry/cache/ as .crate files
    /// and extracted to ~/.cargo/registry/src/
    fn link_crate(&self, source: &Path, install_dir: &Path, package_name: &str) -> Result<PathBuf> {
        // For crates, we link to the src directory
        let dest = install_dir.join(package_name);

        self.create_link(source, &dest)?;
        debug!("Linked crate {} to {}", package_name, dest.display());
        Ok(dest)
    }

    /// Link a Go module to GOPATH/pkg/mod.
    ///
    /// Go modules use a specific directory structure:
    /// $GOPATH/pkg/mod/github.com/user/repo@v1.0.0/
    fn link_go_module(
        &self,
        source: &Path,
        install_dir: &Path,
        package_name: &str,
    ) -> Result<PathBuf> {
        // Go module paths can have @ for version
        let dest = install_dir.join(package_name);

        // Create parent directories for nested module paths
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        self.create_link(source, &dest)?;
        debug!("Linked Go module {} to {}", package_name, dest.display());
        Ok(dest)
    }

    /// Link a Maven artifact to .m2/repository.
    ///
    /// Maven structure:
    /// ~/.m2/repository/org/apache/commons/commons-lang3/3.12.0/
    ///   commons-lang3-3.12.0.jar
    ///   commons-lang3-3.12.0.pom
    fn link_maven_artifact(
        &self,
        source: &Path,
        install_dir: &Path,
        package_name: &str,
    ) -> Result<PathBuf> {
        // Parse Maven coordinates: groupId:artifactId
        let parts: Vec<&str> = package_name.split(':').collect();
        let (group_id, artifact_id) = if parts.len() >= 2 {
            (parts[0], parts[1])
        } else {
            ("", package_name)
        };

        // Convert groupId to path: org.apache.commons -> org/apache/commons
        let group_path = group_id.replace('.', "/");
        let artifact_dir = install_dir.join(&group_path).join(artifact_id);

        fs::create_dir_all(&artifact_dir)?;

        // Link all files from source to artifact directory
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let dest = artifact_dir.join(entry.file_name());
            self.create_link(&entry.path(), &dest)?;
        }

        debug!(
            "Linked Maven artifact {} to {}",
            package_name,
            artifact_dir.display()
        );
        Ok(artifact_dir)
    }

    /// Create a link using the configured strategy.
    fn create_link(&self, source: &Path, dest: &Path) -> Result<()> {
        // Remove existing destination if present
        if dest.exists() || dest.is_symlink() {
            if dest.is_dir() && !dest.is_symlink() {
                fs::remove_dir_all(dest)?;
            } else {
                fs::remove_file(dest)?;
            }
        }

        // Create parent directories
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        match self.strategy {
            LinkStrategy::Symlink => {
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(source, dest)?;
                }
                #[cfg(windows)]
                {
                    if source.is_dir() {
                        // Try symlink first (requires Developer Mode or Admin)
                        if std::os::windows::fs::symlink_dir(source, dest).is_err() {
                            // Fallback to Junction (no admin needed for dirs)
                            // This provides a much faster and more correct behavior than copying
                            // 'junction' crate handles the reparse point magic
                            debug!("Symlink failed, attempting junction for {}", dest.display());
                            if let Err(e) = junction::create(source, dest) {
                                debug!("Junction failed ({}), falling back to copy", e);
                                self.copy_directory(source, dest)?;
                            }
                        }
                    } else {
                        if std::os::windows::fs::symlink_file(source, dest).is_err() {
                            // Fallback to hard link
                            if fs::hard_link(source, dest).is_err() {
                                // Fallback to copy
                                debug!(
                                    "Symlink/Hardlink failed, falling back to copy for {}",
                                    dest.display()
                                );
                                fs::copy(source, dest)?;
                            }
                        }
                    }
                }
            }
            LinkStrategy::HardLink => {
                if source.is_dir() {
                    // Hard links don't work for directories, recurse
                    self.hardlink_directory(source, dest)?;
                } else {
                    fs::hard_link(source, dest)?;
                }
            }
            LinkStrategy::Copy => {
                if source.is_dir() {
                    self.copy_directory(source, dest)?;
                } else {
                    fs::copy(source, dest)?;
                }
            }
        }

        Ok(())
    }

    /// Recursively hard-link a directory.
    fn hardlink_directory(&self, source: &Path, dest: &Path) -> Result<()> {
        fs::create_dir_all(dest)?;

        for entry in WalkDir::new(source).min_depth(1) {
            let entry = entry?;
            let relative = entry.path().strip_prefix(source).map_err(|e| {
                CratonsError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    e.to_string(),
                ))
            })?;
            let dest_path = dest.join(relative);

            if entry.file_type().is_dir() {
                fs::create_dir_all(&dest_path)?;
            } else if entry.file_type().is_file() {
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                // Try hard link, fall back to copy on cross-device
                if fs::hard_link(entry.path(), &dest_path).is_err() {
                    fs::copy(entry.path(), &dest_path)?;
                }
            }
        }

        Ok(())
    }

    /// Recursively copy a directory.
    fn copy_directory(&self, source: &Path, dest: &Path) -> Result<()> {
        fs::create_dir_all(dest)?;

        for entry in WalkDir::new(source).min_depth(1) {
            let entry = entry?;
            let relative = entry.path().strip_prefix(source).map_err(|e| {
                CratonsError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    e.to_string(),
                ))
            })?;
            let dest_path = dest.join(relative);

            if entry.file_type().is_dir() {
                fs::create_dir_all(&dest_path)?;
            } else if entry.file_type().is_file() {
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(entry.path(), &dest_path)?;
            }
        }

        Ok(())
    }
}

/// Create the appropriate node_modules structure for npm packages.
pub fn create_node_modules_structure(
    packages: &[(String, PathBuf)],
    node_modules: &Path,
    strategy: LinkStrategy,
) -> Result<()> {
    fs::create_dir_all(node_modules)?;

    for (name, source) in packages {
        let dest = if name.starts_with('@') {
            // Scoped package
            let parts: Vec<&str> = name.splitn(2, '/').collect();
            if parts.len() == 2 {
                let scope_dir = node_modules.join(parts[0]);
                fs::create_dir_all(&scope_dir)?;
                scope_dir.join(parts[1])
            } else {
                node_modules.join(name)
            }
        } else {
            node_modules.join(name)
        };

        // Create link based on strategy
        match strategy {
            LinkStrategy::Symlink => {
                #[cfg(unix)]
                std::os::unix::fs::symlink(source, &dest)?;
                #[cfg(windows)]
                {
                    if std::os::windows::fs::symlink_dir(source, &dest).is_err() {
                        // Fallback to copy for node_modules on Windows
                        copy_dir_all(source, &dest)?;
                    }
                }
            }
            LinkStrategy::HardLink | LinkStrategy::Copy => {
                // Copy for hard link (directories) and copy strategy
                copy_dir_all(source, &dest)?;
            }
        }
    }

    Ok(())
}

/// Helper to copy a directory recursively.
fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());

        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_copy_directory() {
        let src = tempdir().unwrap();
        let dst = tempdir().unwrap();

        // Create source structure
        fs::write(src.path().join("file.txt"), "content").unwrap();
        fs::create_dir(src.path().join("subdir")).unwrap();
        fs::write(src.path().join("subdir/nested.txt"), "nested").unwrap();

        // Copy
        copy_dir_all(src.path(), dst.path()).unwrap();

        // Verify
        assert!(dst.path().join("file.txt").exists());
        assert!(dst.path().join("subdir/nested.txt").exists());
    }
}
