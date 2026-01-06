//! Toolchain storage and management.

use cratons_core::{ContentHash, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

/// A pinned toolchain (Node, Python, Rust, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Toolchain {
    /// Toolchain name (e.g., "node", "python", "rust")
    pub name: String,
    /// Version string
    pub version: String,
    /// Content hash of the toolchain archive
    pub hash: ContentHash,
    /// Download URL
    pub url: String,
    /// Platform this toolchain is for
    pub platform: String,
    /// Architecture
    pub arch: String,
}

impl Toolchain {
    /// Get the directory name for this toolchain.
    #[must_use]
    pub fn dir_name(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            self.name, self.version, self.platform, self.arch
        )
    }

    /// Get the current platform string.
    #[must_use]
    pub fn current_platform() -> &'static str {
        #[cfg(target_os = "macos")]
        return "darwin";
        #[cfg(target_os = "linux")]
        return "linux";
        #[cfg(target_os = "windows")]
        return "win32";
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return "unknown";
    }

    /// Get the current architecture string.
    #[must_use]
    pub fn current_arch() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        return "x64";
        #[cfg(target_arch = "aarch64")]
        return "arm64";
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return "unknown";
    }
}

/// Store for toolchains.
pub struct ToolchainStore {
    root: PathBuf,
}

impl ToolchainStore {
    /// Create a new toolchain store.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Get the root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get the path to an installed toolchain.
    pub fn get(&self, toolchain: &Toolchain) -> Option<PathBuf> {
        let path = self.root.join(toolchain.dir_name());
        if path.exists() { Some(path) } else { None }
    }

    /// Get a toolchain by name and version.
    pub fn get_by_name_version(&self, name: &str, version: &str) -> Option<PathBuf> {
        let pattern = format!("{name}-{version}-");
        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.filter_map(|e| e.ok()) {
                let file_name = entry.file_name().to_string_lossy().to_string();
                if file_name.starts_with(&pattern) && entry.path().is_dir() {
                    return Some(entry.path());
                }
            }
        }
        None
    }

    /// Install a toolchain from an extracted directory.
    pub fn install(&self, toolchain: &Toolchain, source_dir: &Path) -> Result<PathBuf> {
        let target_dir = self.root.join(toolchain.dir_name());

        if target_dir.exists() {
            info!("Toolchain {} already installed", toolchain.dir_name());
            return Ok(target_dir);
        }

        fs::create_dir_all(&target_dir)?;

        // Copy contents
        for entry in walkdir::WalkDir::new(source_dir) {
            let entry = entry?;
            let relative = entry.path().strip_prefix(source_dir).map_err(|e| {
                cratons_core::CratonsError::Io(std::io::Error::other(e.to_string()))
            })?;
            let target_path = target_dir.join(relative);

            if entry.file_type().is_dir() {
                fs::create_dir_all(&target_path)?;
            } else if entry.file_type().is_file() {
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(entry.path(), &target_path)?;

                // Preserve executable permissions on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let metadata = entry.metadata()?;
                    let mode = metadata.permissions().mode();
                    if mode & 0o111 != 0 {
                        fs::set_permissions(&target_path, std::fs::Permissions::from_mode(mode))?;
                    }
                }
            }
        }

        // Write metadata
        let meta_path = target_dir.join("cratons-toolchain.json");
        let meta_json = serde_json::to_string_pretty(toolchain)?;
        fs::write(meta_path, meta_json)?;

        info!("Installed toolchain: {}", toolchain.dir_name());
        Ok(target_dir)
    }

    /// List all installed toolchains.
    pub fn list(&self) -> Result<Vec<Toolchain>> {
        let mut toolchains = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().is_dir() {
                    let meta_path = entry.path().join("cratons-toolchain.json");
                    if meta_path.exists() {
                        if let Ok(content) = fs::read_to_string(&meta_path) {
                            if let Ok(tc) = serde_json::from_str(&content) {
                                toolchains.push(tc);
                            }
                        }
                    }
                }
            }
        }

        Ok(toolchains)
    }

    /// List toolchains grouped by name.
    pub fn list_grouped(&self) -> Result<HashMap<String, Vec<Toolchain>>> {
        let toolchains = self.list()?;
        let mut grouped: HashMap<String, Vec<Toolchain>> = HashMap::new();

        for tc in toolchains {
            grouped.entry(tc.name.clone()).or_default().push(tc);
        }

        Ok(grouped)
    }

    /// Remove a toolchain.
    pub fn remove(&self, toolchain: &Toolchain) -> Result<bool> {
        let path = self.root.join(toolchain.dir_name());
        if path.exists() {
            fs::remove_dir_all(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get the path to the binary directory for a toolchain.
    pub fn bin_dir(&self, toolchain: &Toolchain) -> Option<PathBuf> {
        let tc_dir = self.get(toolchain)?;

        // Common binary locations
        let candidates = [
            tc_dir.join("bin"),
            tc_dir.join("usr/bin"),
            tc_dir.join("usr/local/bin"),
        ];

        for candidate in candidates {
            if candidate.exists() {
                return Some(candidate);
            }
        }

        // For node, it might be directly in the toolchain directory
        if toolchain.name == "node" {
            return Some(tc_dir);
        }

        Some(tc_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_toolchain_dir_name() {
        let tc = Toolchain {
            name: "node".to_string(),
            version: "20.10.0".to_string(),
            hash: ContentHash::blake3("test".to_string()),
            url: "https://example.com".to_string(),
            platform: "darwin".to_string(),
            arch: "arm64".to_string(),
        };

        assert_eq!(tc.dir_name(), "node-20.10.0-darwin-arm64");
    }

    #[test]
    fn test_toolchain_install() {
        let store_dir = tempdir().unwrap();
        let source_dir = tempdir().unwrap();

        // Create a fake toolchain
        fs::create_dir(source_dir.path().join("bin")).unwrap();
        fs::write(source_dir.path().join("bin/node"), b"fake node").unwrap();

        let store = ToolchainStore::new(store_dir.path());
        let tc = Toolchain {
            name: "node".to_string(),
            version: "20.10.0".to_string(),
            hash: ContentHash::blake3("test".to_string()),
            url: "https://example.com".to_string(),
            platform: "darwin".to_string(),
            arch: "arm64".to_string(),
        };

        let installed_path = store.install(&tc, source_dir.path()).unwrap();
        assert!(installed_path.join("bin/node").exists());

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "node");
    }
}
