//! Package linking from CAS to project directories.

use cratons_core::{CratonsError, Ecosystem, Result};
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

    /// Get the configured link strategy.
    pub fn strategy(&self) -> LinkStrategy {
        self.strategy
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
        let dest = npm_package_dest(install_dir, package_name)?;
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
        create_link_with_strategy(source, dest, self.strategy)
    }
}

/// Compute the destination path for an npm package in node_modules.
///
/// Handles scoped packages (@scope/name) by creating the scope directory.
fn npm_package_dest(node_modules: &Path, package_name: &str) -> Result<PathBuf> {
    if package_name.starts_with('@') {
        // Scoped package: @scope/name -> node_modules/@scope/name
        let parts: Vec<&str> = package_name.splitn(2, '/').collect();
        if parts.len() == 2 {
            let scope_dir = node_modules.join(parts[0]);
            fs::create_dir_all(&scope_dir)?;
            Ok(scope_dir.join(parts[1]))
        } else {
            Ok(node_modules.join(package_name))
        }
    } else {
        Ok(node_modules.join(package_name))
    }
}

/// Create a link from source to dest using the specified strategy.
///
/// This is the canonical implementation of linking with fallback behavior.
fn create_link_with_strategy(source: &Path, dest: &Path, strategy: LinkStrategy) -> Result<()> {
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

    match strategy {
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
                        debug!("Symlink failed, attempting junction for {}", dest.display());
                        if let Err(e) = junction::create(source, dest) {
                            debug!("Junction failed ({}), falling back to copy", e);
                            copy_directory(source, dest)?;
                        }
                    }
                } else if std::os::windows::fs::symlink_file(source, dest).is_err() {
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
        LinkStrategy::HardLink => {
            if source.is_dir() {
                // Hard links don't work for directories, recurse
                hardlink_directory(source, dest)?;
            } else {
                fs::hard_link(source, dest)?;
            }
        }
        LinkStrategy::Copy => {
            if source.is_dir() {
                copy_directory(source, dest)?;
            } else {
                fs::copy(source, dest)?;
            }
        }
    }

    Ok(())
}

/// Recursively hard-link a directory.
fn hardlink_directory(source: &Path, dest: &Path) -> Result<()> {
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
///
/// Uses WalkDir for robust traversal including symlink handling.
fn copy_directory(source: &Path, dest: &Path) -> Result<()> {
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

/// Create the appropriate node_modules structure for npm packages.
///
/// This is an alternative bulk installation API for scenarios like:
/// - pnpm-style symlink farms with content-addressable deduplication
/// - Batch linking of pre-resolved package sets
/// - Custom installation strategies
///
/// For standard per-package linking, use `PackageLinker::link_package()` instead.
pub fn create_node_modules_structure(
    packages: &[(String, PathBuf)],
    node_modules: &Path,
    strategy: LinkStrategy,
) -> Result<()> {
    fs::create_dir_all(node_modules)?;

    for (name, source) in packages {
        let dest = npm_package_dest(node_modules, name)?;
        create_link_with_strategy(source, &dest, strategy)?;
        debug!("Linked {} to {}", name, dest.display());
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
        let dst_dir = tempdir().unwrap();
        let dst = dst_dir.path().join("copied");

        // Create source structure
        fs::write(src.path().join("file.txt"), "content").unwrap();
        fs::create_dir(src.path().join("subdir")).unwrap();
        fs::write(src.path().join("subdir/nested.txt"), "nested").unwrap();

        // Copy
        copy_directory(src.path(), &dst).unwrap();

        // Verify
        assert!(dst.join("file.txt").exists());
        assert!(dst.join("subdir/nested.txt").exists());
        assert_eq!(fs::read_to_string(dst.join("file.txt")).unwrap(), "content");
    }

    #[test]
    fn test_npm_package_dest_regular() {
        let node_modules = PathBuf::from("/project/node_modules");
        let dest = npm_package_dest(&node_modules, "lodash").unwrap();
        assert_eq!(dest, PathBuf::from("/project/node_modules/lodash"));
    }

    #[test]
    fn test_npm_package_dest_scoped() {
        let temp = tempdir().unwrap();
        let node_modules = temp.path().join("node_modules");
        fs::create_dir_all(&node_modules).unwrap();

        let dest = npm_package_dest(&node_modules, "@types/node").unwrap();
        assert_eq!(dest, node_modules.join("@types").join("node"));
        assert!(node_modules.join("@types").exists());
    }

    #[test]
    fn test_create_node_modules_structure() {
        let temp = tempdir().unwrap();
        let node_modules = temp.path().join("node_modules");

        // Create source packages
        let pkg1_src = temp.path().join("pkg1");
        let pkg2_src = temp.path().join("pkg2");
        fs::create_dir_all(&pkg1_src).unwrap();
        fs::create_dir_all(&pkg2_src).unwrap();
        fs::write(pkg1_src.join("index.js"), "module.exports = 1").unwrap();
        fs::write(pkg2_src.join("index.js"), "module.exports = 2").unwrap();

        let packages = vec![
            ("lodash".to_string(), pkg1_src),
            ("express".to_string(), pkg2_src),
        ];

        create_node_modules_structure(&packages, &node_modules, LinkStrategy::Copy).unwrap();

        assert!(node_modules.join("lodash/index.js").exists());
        assert!(node_modules.join("express/index.js").exists());
    }

    #[test]
    fn test_create_node_modules_structure_scoped() {
        let temp = tempdir().unwrap();
        let node_modules = temp.path().join("node_modules");

        // Create source package
        let pkg_src = temp.path().join("types-node");
        fs::create_dir_all(&pkg_src).unwrap();
        fs::write(pkg_src.join("index.d.ts"), "declare module 'node'").unwrap();

        let packages = vec![("@types/node".to_string(), pkg_src)];

        create_node_modules_structure(&packages, &node_modules, LinkStrategy::Copy).unwrap();

        assert!(node_modules.join("@types/node/index.d.ts").exists());
    }
}
