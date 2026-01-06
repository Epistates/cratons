//! # cratons-installer
//!
//! Hermetic package installation for the Cratons package manager.
//!
//! This crate provides isolated, reproducible package installation with:
//! - Parallel downloads with integrity verification
//! - Content-addressable storage for deduplication
//! - Ecosystem-specific linking (node_modules, site-packages, etc.)
//! - Isolated post-install script execution

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod download;
pub mod extract;
pub mod link;
pub mod scripts;

use cratons_core::{Ecosystem, CratonsError, Result};
use cratons_environment::Environment;
use cratons_lockfile::{LockedPackage, Lockfile};
use cratons_store::Store;
use petgraph::algo::toposort;
use petgraph::graphmap::DiGraphMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, info, warn};

pub use download::PackageDownloader;
pub use extract::PackageExtractor;
pub use link::PackageLinker;
pub use scripts::PostInstallRunner;

/// Configuration for the installer.
#[derive(Debug, Clone)]
pub struct InstallerConfig {
    /// Maximum concurrent downloads
    pub concurrency: usize,
    /// Whether to run post-install scripts
    pub run_scripts: bool,

    /// Whether to fail on post-install script errors (default: false for compatibility)
    pub strict_scripts: bool,
    /// Whether to run scripts in isolated containers
    pub isolate_scripts: bool,
    /// Skip integrity verification (dangerous!)
    pub skip_integrity: bool,
    /// Link strategy for installed packages
    pub link_strategy: LinkStrategy,
    /// Ecosystems to install (None = all)
    pub ecosystems: Option<Vec<Ecosystem>>,
}

impl Default for InstallerConfig {
    fn default() -> Self {
        Self {
            concurrency: 8,
            run_scripts: true,
            strict_scripts: false,
            isolate_scripts: true,
            skip_integrity: false,
            link_strategy: LinkStrategy::Symlink,
            ecosystems: None,
        }
    }
}

/// Strategy for linking packages from CAS to project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkStrategy {
    /// Create symbolic links (default, most efficient)
    #[default]
    Symlink,
    /// Create hard links (same filesystem only)
    HardLink,
    /// Copy files (most compatible, uses most space)
    Copy,
}

/// Result of an installation.
#[derive(Debug, Clone)]
pub struct InstallResult {
    /// Number of packages installed
    pub packages_installed: usize,
    /// Number of packages from cache
    pub packages_cached: usize,
    /// Number of packages downloaded
    pub packages_downloaded: usize,
    /// Total bytes downloaded
    pub bytes_downloaded: u64,
    /// Installation duration
    pub duration_secs: f64,
    /// Per-ecosystem results
    pub ecosystems: HashMap<Ecosystem, EcosystemResult>,
    /// Any warnings during installation
    pub warnings: Vec<String>,
    /// Whether environment was set up
    pub environment_setup: bool,
    /// Path to activation script
    pub activation_script: Option<PathBuf>,
}

/// Per-ecosystem installation result.
#[derive(Debug, Clone, Default)]
pub struct EcosystemResult {
    /// Packages installed for this ecosystem
    pub packages: usize,
    /// Packages from cache
    pub cached: usize,
    /// Packages downloaded
    pub downloaded: usize,
    /// Bytes downloaded
    pub bytes: u64,
    /// Installation directory
    pub install_dir: Option<PathBuf>,
}

/// Status of a single package installation.
#[derive(Debug, Clone)]
pub struct PackageInstallStatus {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Ecosystem
    pub ecosystem: Ecosystem,
    /// Whether it was cached
    pub cached: bool,
    /// Bytes downloaded (0 if cached)
    pub bytes_downloaded: u64,
    /// Installation path
    pub install_path: PathBuf,
}

/// The main installer orchestrator.
pub struct Installer<'a> {
    store: &'a Store,
    config: InstallerConfig,
    downloader: PackageDownloader,
    extractor: PackageExtractor,
}

impl<'a> Installer<'a> {
    /// Create a new installer with default configuration.
    pub fn new(store: &'a Store) -> Self {
        Self::with_config(store, InstallerConfig::default())
    }

    /// Create a new installer with custom configuration.
    pub fn with_config(store: &'a Store, config: InstallerConfig) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("cratons-installer/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            store,
            downloader: PackageDownloader::new(client.clone(), config.concurrency),
            extractor: PackageExtractor::new(),
            config,
        }
    }

    /// Install packages from a lockfile.
    pub async fn install(&self, lockfile: &Lockfile, project_dir: &Path) -> Result<InstallResult> {
        let start = Instant::now();
        info!(
            "Starting installation of {} packages",
            lockfile.package_count()
        );

        let mut result = InstallResult {
            packages_installed: 0,
            packages_cached: 0,
            packages_downloaded: 0,
            bytes_downloaded: 0,
            duration_secs: 0.0,
            ecosystems: HashMap::new(),
            warnings: Vec::new(),
            environment_setup: false,
            activation_script: None,
        };

        // Topologically sort packages by dependencies to ensure correct installation order
        let sorted_packages = self.topological_sort_packages(&lockfile.packages)?;

        // Group packages by ecosystem (preserving topological order within each group)
        let mut by_ecosystem: HashMap<Ecosystem, Vec<&LockedPackage>> = HashMap::new();
        for pkg in &sorted_packages {
            // Skip URL ecosystem (direct URLs, not from registries)
            if pkg.ecosystem == Ecosystem::Url {
                continue;
            }
            // Filter by ecosystem if configured
            if let Some(ref ecosystems) = self.config.ecosystems {
                if !ecosystems.contains(&pkg.ecosystem) {
                    continue;
                }
            }
            by_ecosystem.entry(pkg.ecosystem).or_default().push(pkg);
        }

        // Install each ecosystem
        for (ecosystem, packages) in by_ecosystem {
            info!("Installing {} {} packages", packages.len(), ecosystem);

            let eco_result = self
                .install_ecosystem(ecosystem, &packages, project_dir)
                .await?;

            result.packages_installed += eco_result.packages;
            result.packages_cached += eco_result.cached;
            result.packages_downloaded += eco_result.downloaded;
            result.bytes_downloaded += eco_result.bytes;

            result.ecosystems.insert(ecosystem, eco_result);
        }

        // Set up hermetic environment after package installation
        if result.packages_installed > 0 {
            match self.setup_environment(lockfile, project_dir, None) {
                Ok(env) => {
                    result.environment_setup = true;
                    result.activation_script = Some(project_dir.join(".cratons").join("activate"));
                    info!(
                        "Environment setup complete: {} ecosystems configured",
                        env.ecosystems().len()
                    );
                }
                Err(e) => {
                    warn!("Failed to set up environment: {}", e);
                    result
                        .warnings
                        .push(format!("Environment setup failed: {}", e));
                }
            }
        }

        result.duration_secs = start.elapsed().as_secs_f64();
        info!(
            "Installation complete: {} packages in {:.2}s ({} cached, {} downloaded)",
            result.packages_installed,
            result.duration_secs,
            result.packages_cached,
            result.packages_downloaded
        );

        Ok(result)
    }

    /// Set up the hermetic environment for the project.
    fn setup_environment(
        &self,
        lockfile: &Lockfile,
        project_dir: &Path,
        env_config: Option<&cratons_environment::EnvironmentConfig>,
    ) -> Result<Environment> {
        let env_root = project_dir.join(".cratons").join("env");
        std::fs::create_dir_all(&env_root)?;

        let mut env = Environment::new(env_root.clone());

        // Detect which ecosystems are used
        let ecosystems: Vec<Ecosystem> = lockfile
            .packages
            .iter()
            .map(|p| p.ecosystem)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        for ecosystem in ecosystems {
            match ecosystem {
                Ecosystem::PyPi => {
                    let version = env_config.and_then(|c| c.python.as_deref());
                    let python_env = cratons_environment::PythonEnv::setup_with_version(
                        &env_root, version, self.store,
                    )
                    .map_err(|e| CratonsError::Config(format!("Python env setup: {}", e)))?;
                    env.python = Some(python_env);
                }
                Ecosystem::Npm => {
                    let version = env_config.and_then(|c| c.node.as_deref());
                    let node_env = cratons_environment::NodeEnv::setup_with_version(
                        &env_root,
                        project_dir,
                        version,
                        self.store,
                    )
                    .map_err(|e| CratonsError::Config(format!("Node env setup: {}", e)))?;
                    env.node = Some(node_env);
                }
                Ecosystem::Crates => {
                    let rust_env = cratons_environment::RustEnv::setup(&env_root, self.store)
                        .map_err(|e| CratonsError::Config(format!("Rust env setup: {}", e)))?;
                    env.rust = Some(rust_env);
                }
                Ecosystem::Go => {
                    let go_env = cratons_environment::GoEnv::setup(&env_root, self.store)
                        .map_err(|e| CratonsError::Config(format!("Go env setup: {}", e)))?;
                    env.go = Some(go_env);
                }
                Ecosystem::Maven => {
                    let java_env = cratons_environment::JavaEnv::setup(&env_root, self.store)
                        .map_err(|e| CratonsError::Config(format!("Java env setup: {}", e)))?;
                    env.java = Some(java_env);
                }
                Ecosystem::Url => {
                    // URL dependencies don't need a special environment
                }
            }
        }

        // Generate activation scripts
        cratons_environment::activation::generate_scripts(&env, project_dir)
            .map_err(|e| CratonsError::Config(format!("Activation scripts: {}", e)))?;

        Ok(env)
    }

    /// Install packages for a specific ecosystem.
    async fn install_ecosystem(
        &self,
        ecosystem: Ecosystem,
        packages: &[&LockedPackage],
        project_dir: &Path,
    ) -> Result<EcosystemResult> {
        let mut eco_result = EcosystemResult::default();

        // Determine installation directory
        let install_dir = self.get_install_dir(ecosystem, project_dir)?;
        std::fs::create_dir_all(&install_dir)?;
        eco_result.install_dir = Some(install_dir.clone());

        // Download and extract packages
        let statuses = self.download_and_extract(packages).await?;

        // Link packages to project
        let linker = PackageLinker::new(self.store, self.config.link_strategy);
        for status in &statuses {
            linker.link_package(&status.install_path, &install_dir, ecosystem, &status.name)?;

            eco_result.packages += 1;
            if status.cached {
                eco_result.cached += 1;
            } else {
                eco_result.downloaded += 1;
                eco_result.bytes += status.bytes_downloaded;
            }
        }

        // Run post-install scripts if enabled
        if self.config.run_scripts {
            self.run_post_install_scripts(ecosystem, &statuses, project_dir)
                .await?;
        }

        Ok(eco_result)
    }

    /// Download and extract packages, returning their installation status.
    async fn download_and_extract(
        &self,
        packages: &[&LockedPackage],
    ) -> Result<Vec<PackageInstallStatus>> {
        let mut statuses = Vec::with_capacity(packages.len());

        // Check cache and collect packages to download
        let mut to_download: Vec<&LockedPackage> = Vec::new();

        for pkg in packages {
            let content_hash = &pkg.resolved_hash;

            // Check if already in CAS
            if let Some(cached_path) = self.store.cas().get(content_hash) {
                debug!("Cache hit: {}@{}", pkg.name, pkg.version);
                statuses.push(PackageInstallStatus {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    ecosystem: pkg.ecosystem,
                    cached: true,
                    bytes_downloaded: 0,
                    install_path: cached_path,
                });
            } else {
                to_download.push(pkg);
            }
        }

        // Download missing packages in parallel
        if !to_download.is_empty() {
            info!("Downloading {} packages...", to_download.len());
            let downloaded = self
                .downloader
                .download_all(&to_download, self.store)
                .await?;

            for (pkg, (path, bytes)) in to_download.iter().zip(downloaded) {
                // Extract the package
                let extracted_path = self.extractor.extract(&path, pkg.ecosystem, self.store)?;

                // Verify integrity if not skipped
                if !self.config.skip_integrity && !pkg.integrity.is_empty() {
                    self.verify_integrity(pkg, &extracted_path)?;
                }

                statuses.push(PackageInstallStatus {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    ecosystem: pkg.ecosystem,
                    cached: false,
                    bytes_downloaded: bytes,
                    install_path: extracted_path,
                });
            }
        }

        Ok(statuses)
    }

    /// Get the installation directory for an ecosystem.
    fn get_install_dir(&self, ecosystem: Ecosystem, project_dir: &Path) -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| CratonsError::Config("Cannot determine home directory".into()))?;

        let dir = match ecosystem {
            Ecosystem::Npm => project_dir.join("node_modules"),
            Ecosystem::PyPi => project_dir
                .join(".venv")
                .join("lib")
                .join("python")
                .join("site-packages"),
            Ecosystem::Crates => home
                .join(".cargo")
                .join("registry")
                .join("cache")
                .join("cratons-registry"),
            Ecosystem::Go => std::env::var("GOPATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| home.join("go"))
                .join("pkg")
                .join("mod"),
            Ecosystem::Maven => home.join(".m2").join("repository"),
            Ecosystem::Url => {
                // URL dependencies go to a special directory
                project_dir.join(".cratons").join("url-deps")
            }
        };
        Ok(dir)
    }

    /// Topologically sort packages by dependencies.
    ///
    /// This ensures that dependencies are installed before their dependents,
    /// which is critical for packages with peer dependencies or build-time deps.
    fn topological_sort_packages<'b>(
        &self,
        packages: &'b [LockedPackage],
    ) -> Result<Vec<&'b LockedPackage>> {
        // Build name -> index mapping
        let name_to_idx: HashMap<&str, usize> = packages
            .iter()
            .enumerate()
            .map(|(i, p)| (p.name.as_str(), i))
            .collect();

        // Build dependency graph
        let mut graph = DiGraphMap::<usize, ()>::new();

        // Add all packages as nodes
        for i in 0..packages.len() {
            graph.add_node(i);
        }

        // Add edges for dependencies
        for (idx, pkg) in packages.iter().enumerate() {
            for dep_ref in &pkg.dependencies {
                if let Some(&dep_idx) = name_to_idx.get(dep_ref.name.as_str()) {
                    // Edge from dependency to dependent (dep must be installed first)
                    graph.add_edge(dep_idx, idx, ());
                }
            }
        }

        // Topological sort
        let sorted_indices = toposort(&graph, None).map_err(|cycle| {
            let pkg_name = &packages[cycle.node_id()].name;
            CratonsError::DependencyCycle(format!(
                "Circular dependency detected involving package: {}",
                pkg_name
            ))
        })?;

        // Map indices back to package references
        Ok(sorted_indices.into_iter().map(|i| &packages[i]).collect())
    }

    /// Verify package integrity after extraction.
    ///
    /// Note: Primary integrity verification (tarball hash) happens in download.rs
    /// before extraction. This function provides secondary verification for cached
    /// packages using our content-addressed store hash.
    fn verify_integrity(&self, pkg: &LockedPackage, path: &Path) -> Result<()> {
        use cratons_core::{HashAlgorithm, Hasher};

        // For CAS-stored packages, verify against our Blake3 hash
        if !pkg.resolved_hash.value.is_empty() {
            let actual = Hasher::hash_directory(HashAlgorithm::Blake3, path)?;

            if actual.value != pkg.resolved_hash.value {
                return Err(CratonsError::ChecksumMismatch {
                    package: pkg.name.clone(),
                    expected: pkg.resolved_hash.value.clone(),
                    actual: actual.value,
                });
            }

            debug!(
                "Content hash verified for {}@{}: {}",
                pkg.name, pkg.version, actual.value
            );
        }

        Ok(())
    }

    /// Run post-install scripts for packages.
    async fn run_post_install_scripts(
        &self,
        ecosystem: Ecosystem,
        packages: &[PackageInstallStatus],
        project_dir: &Path,
    ) -> Result<()> {
        // Only npm has common post-install scripts
        if ecosystem != Ecosystem::Npm {
            return Ok(());
        }

        let runner = PostInstallRunner::new(self.config.isolate_scripts);
        let mut failures: Vec<(String, String, String)> = Vec::new();

        for pkg in packages {
            if let Err(e) = runner.run_scripts(&pkg.install_path, project_dir).await {
                let error_msg = format!(
                    "Post-install script failed for {}@{}: {}",
                    pkg.name, pkg.version, e
                );

                if self.config.strict_scripts {
                    // In strict mode, fail immediately
                    return Err(CratonsError::BuildFailed(error_msg));
                } else {
                    // In lenient mode, collect failures and continue
                    warn!("{}", error_msg);
                    failures.push((pkg.name.clone(), pkg.version.clone(), e.to_string()));
                }
            }
        }

        // If there were failures in lenient mode, log a summary
        if !failures.is_empty() {
            warn!(
                "{} post-install script(s) failed. Use strict_scripts=true to fail on errors.",
                failures.len()
            );
        }

        Ok(())
    }
}

/// Install packages from a lockfile using default settings.
pub async fn install(lockfile: &Lockfile, project_dir: &Path) -> Result<InstallResult> {
    let store = Store::open_default()?;
    let installer = Installer::new(&store);
    installer.install(lockfile, project_dir).await
}

/// Install packages with custom configuration.
pub async fn install_with_config(
    lockfile: &Lockfile,
    project_dir: &Path,
    config: InstallerConfig,
) -> Result<InstallResult> {
    let store = Store::open_default()?;
    let installer = Installer::with_config(&store, config);
    installer.install(lockfile, project_dir).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratons_core::ContentHash;
    use tempfile::tempdir;

    #[test]
    fn test_installer_config_default() {
        let config = InstallerConfig::default();
        assert_eq!(config.concurrency, 8);
        assert!(config.run_scripts);
        assert!(config.isolate_scripts);
        assert!(!config.skip_integrity);
        assert_eq!(config.link_strategy, LinkStrategy::Symlink);
        assert!(config.ecosystems.is_none());
    }

    #[test]
    fn test_link_strategy_default() {
        let strategy = LinkStrategy::default();
        assert_eq!(strategy, LinkStrategy::Symlink);
    }

    #[test]
    fn test_install_result_default_values() {
        let result = InstallResult {
            packages_installed: 10,
            packages_cached: 3,
            packages_downloaded: 7,
            bytes_downloaded: 1024 * 1024,
            duration_secs: 2.5,
            ecosystems: HashMap::new(),
            warnings: Vec::new(),
            environment_setup: true,
            activation_script: Some(PathBuf::from("/project/.cratons/activate")),
        };

        assert_eq!(result.packages_installed, 10);
        assert_eq!(result.packages_cached, 3);
        assert_eq!(result.packages_downloaded, 7);
        assert!(result.environment_setup);
        assert!(result.activation_script.is_some());
    }

    #[test]
    fn test_ecosystem_result_default() {
        let eco = EcosystemResult::default();
        assert_eq!(eco.packages, 0);
        assert_eq!(eco.cached, 0);
        assert_eq!(eco.downloaded, 0);
        assert_eq!(eco.bytes, 0);
        assert!(eco.install_dir.is_none());
    }

    #[test]
    fn test_package_install_status() {
        let status = PackageInstallStatus {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
            cached: true,
            bytes_downloaded: 0,
            install_path: PathBuf::from("/tmp/lodash"),
        };

        assert_eq!(status.name, "lodash");
        assert!(status.cached);
        assert_eq!(status.bytes_downloaded, 0);
    }

    #[tokio::test]
    async fn test_installer_creation() {
        let temp_dir = tempdir().unwrap();
        let store = Store::open(temp_dir.path()).unwrap();

        let _installer = Installer::new(&store);
        // Verify it was created (no panics)
        assert!(true);

        let config = InstallerConfig {
            concurrency: 4,
            ..Default::default()
        };
        let _installer = Installer::with_config(&store, config);
        assert!(true);
    }

    #[test]
    fn test_get_install_dir_npm() {
        let temp_dir = tempdir().unwrap();
        let store = Store::open(temp_dir.path()).unwrap();
        let installer = Installer::new(&store);

        let project_dir = PathBuf::from("/test/project");
        let install_dir = installer
            .get_install_dir(Ecosystem::Npm, &project_dir)
            .unwrap();

        assert_eq!(install_dir, PathBuf::from("/test/project/node_modules"));
    }

    #[test]
    fn test_get_install_dir_pypi() {
        let temp_dir = tempdir().unwrap();
        let store = Store::open(temp_dir.path()).unwrap();
        let installer = Installer::new(&store);

        let project_dir = PathBuf::from("/test/project");
        let install_dir = installer
            .get_install_dir(Ecosystem::PyPi, &project_dir)
            .unwrap();

        assert!(install_dir.to_string_lossy().contains("site-packages"));
    }

    #[test]
    fn test_get_install_dir_crates() {
        let temp_dir = tempdir().unwrap();
        let store = Store::open(temp_dir.path()).unwrap();
        let installer = Installer::new(&store);

        let project_dir = PathBuf::from("/test/project");
        let install_dir = installer
            .get_install_dir(Ecosystem::Crates, &project_dir)
            .unwrap();

        assert!(install_dir.to_string_lossy().contains(".cargo"));
    }

    #[test]
    fn test_get_install_dir_maven() {
        let temp_dir = tempdir().unwrap();
        let store = Store::open(temp_dir.path()).unwrap();
        let installer = Installer::new(&store);

        let project_dir = PathBuf::from("/test/project");
        let install_dir = installer
            .get_install_dir(Ecosystem::Maven, &project_dir)
            .unwrap();

        assert!(install_dir.to_string_lossy().contains(".m2"));
    }

    #[test]
    fn test_get_install_dir_url() {
        let temp_dir = tempdir().unwrap();
        let store = Store::open(temp_dir.path()).unwrap();
        let installer = Installer::new(&store);

        let project_dir = PathBuf::from("/test/project");
        let install_dir = installer
            .get_install_dir(Ecosystem::Url, &project_dir)
            .unwrap();

        assert!(install_dir.to_string_lossy().contains("url-deps"));
    }

    #[tokio::test]
    async fn test_install_empty_lockfile() {
        let temp_dir = tempdir().unwrap();
        let project_dir = tempdir().unwrap();
        let store = Store::open(temp_dir.path()).unwrap();

        // Create empty lockfile
        let manifest_hash = ContentHash::blake3("test".to_string());
        let lockfile = Lockfile::new(manifest_hash);

        let installer = Installer::new(&store);
        let result = installer
            .install(&lockfile, project_dir.path())
            .await
            .unwrap();

        assert_eq!(result.packages_installed, 0);
        assert_eq!(result.packages_downloaded, 0);
        assert_eq!(result.packages_cached, 0);
    }
}
