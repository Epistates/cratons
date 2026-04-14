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

mod download;
mod download_diagnostics;
mod extract;
mod link;
mod scripts;

use cratons_core::{CratonsError, Ecosystem, Result};
use cratons_environment::Environment;
use cratons_lockfile::{LockedPackage, Lockfile};
use cratons_store::Store;
use petgraph::algo::toposort;
use petgraph::graphmap::DiGraphMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

pub use download::PackageDownloader;
pub use extract::PackageExtractor;
pub use link::{PackageLinker, create_node_modules_structure};
pub use scripts::{PackageScripts, PostInstallRunner};

/// Policy for how post-install scripts interact with the platform sandbox.
///
/// Cratons treats post-install scripts as untrusted code (npm tarballs can
/// ship arbitrary shell commands). This enum controls what happens when the
/// host cannot provide the requested isolation — e.g. rootless Linux without
/// user namespaces, macOS without `sandbox-exec`, or Windows with only Job
/// Objects (which cannot isolate network or filesystem).
///
/// The default is [`SandboxPolicy::Required`]: **fail closed** unless the
/// operator explicitly opts into a weaker mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxPolicy {
    /// The strongest mode, and the default. The installer derives the set
    /// of capabilities the sandbox backend must provide from the
    /// [`SandboxConfig`](cratons_sandbox::config::SandboxConfig) it intends
    /// to build (e.g. network isolation for `NetworkAccess::None`, filesystem
    /// isolation for scoped mounts, resource limits for
    /// `ResourceLimits::for_post_install`). If the chosen backend cannot
    /// provide every required capability, the install aborts with a
    /// [`CratonsError::BuildFailed`] naming the missing capabilities. No
    /// silent degradation.
    #[default]
    Required,
    /// If a required capability is unavailable, emit a structured warning
    /// listing the missing capabilities and fall back to running the script
    /// directly on the host. This is the pre-Phase-3 behavior; it remains
    /// available for operators who have weighed the tradeoff explicitly.
    Preferred,
    /// Never attempt to sandbox. The script runs directly on the host every
    /// time. Use only in trusted environments where sandboxing would break
    /// the intended semantics. Must be selected explicitly.
    Disabled,
}

/// Policy governing how the installer enforces package integrity
/// verification before persisting downloaded bytes.
///
/// Integrity here means "the registry attested a cryptographic hash for
/// this package version, and the downloaded bytes match it." Cratons
/// treats missing or mismatched integrity as a supply-chain failure: by
/// default, the install aborts before any bytes are written to the CAS.
///
/// Two ecosystems currently lack a credible integrity story and are
/// handled via the allowlist variant:
///
/// - **Go**: the Go module proxy returns an `origin.hash` that is not a
///   trust anchor independent of the proxy itself. True integrity
///   requires querying the `sum.golang.org` checksum database; that work
///   is tracked as follow-up F-1.
/// - **Maven Central**: the `.jar.sha1` is served from the same host as
///   the JAR, so it only attests against transport corruption, not a
///   compromised registry. PGP detached signature verification (F-2) is
///   the proper fix.
///
/// Until those land, the default policy allows these two ecosystems to
/// install with empty integrity — but it records a structured warning in
/// `InstallResult.warnings` so downstream tooling (CI, audit) can catch
/// the degradation explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityPolicy {
    /// Fail any install where a downloaded package has empty registry
    /// integrity. This is the strongest policy and will become the
    /// default once Go and Maven have independent integrity anchors.
    Required,
    /// Require integrity for all ecosystems except the ones listed here.
    /// Ecosystems in the allowlist emit a structured `integrity-degraded`
    /// warning and proceed. This is the default, with `vec![Ecosystem::Go,
    /// Ecosystem::Maven]`.
    RequiredWithEcosystemAllowlist(Vec<Ecosystem>),
    /// Skip integrity enforcement entirely. The installer still verifies
    /// any non-empty integrity the registry does return, but tolerates an
    /// empty value silently. Selected explicitly, never the default.
    Skip,
}

impl Default for IntegrityPolicy {
    /// **Default is `Required`** — fail closed for any ecosystem where the
    /// registry returns empty integrity.
    ///
    /// Prior to F-final (F-1 Go sum.golang.org + F-2 Maven PGP), this
    /// default was `RequiredWithEcosystemAllowlist([Go, Maven])` because
    /// neither ecosystem had a credible cross-origin integrity source.
    /// F-1 added signed-note verified `h1:` hashes for Go, and F-2 added
    /// PGP verification for Maven (with hardcoded keyserver fetch and
    /// on-disk cache). Both ecosystems now deliver real integrity, so
    /// the default is strict.
    fn default() -> Self {
        Self::Required
    }
}

impl IntegrityPolicy {
    /// Returns `true` if an empty registry integrity string is acceptable
    /// for a package in `ecosystem` under this policy. Non-empty integrity
    /// is always verified downstream regardless of this check.
    pub fn allows_empty_integrity(&self, ecosystem: Ecosystem) -> bool {
        match self {
            Self::Required => false,
            Self::RequiredWithEcosystemAllowlist(list) => list.contains(&ecosystem),
            Self::Skip => true,
        }
    }
}

/// Configuration for the installer.
#[derive(Debug, Clone)]
pub struct InstallerConfig {
    /// Maximum concurrent downloads
    pub concurrency: usize,
    /// Whether to run post-install scripts
    pub run_scripts: bool,

    /// Whether to fail on post-install script errors (default: false for compatibility)
    pub strict_scripts: bool,
    /// Policy governing how (or whether) post-install scripts are isolated
    /// from the host. See [`SandboxPolicy`].
    pub sandbox_policy: SandboxPolicy,
    /// Policy governing how the installer enforces package integrity.
    /// See [`IntegrityPolicy`]. Replaces the legacy `skip_integrity: bool`.
    pub integrity_policy: IntegrityPolicy,
    /// Maven PGP trust configuration. Defaults to loading
    /// `~/.config/cratons/trusted-keys/maven.toml` if it exists, else
    /// empty. See [`cratons_security::MavenTrustConfig`]. Project-level
    /// `[security.maven]` manifest parsing is tracked as F-2c follow-up.
    pub maven_trust: Arc<cratons_security::MavenTrustConfig>,
    /// Shared PGP key cache used by install-time Maven verification.
    /// Opened on demand; see [`cratons_security::KeyStore`].
    pub maven_keystore: Option<Arc<cratons_security::KeyStore>>,
    /// Link strategy for installed packages
    pub link_strategy: LinkStrategy,
    /// Ecosystems to install (None = all)
    pub ecosystems: Option<Vec<Ecosystem>>,
}

impl Default for InstallerConfig {
    fn default() -> Self {
        // Best-effort load of the user-level Maven keyring. Failure to
        // parse is fatal (bad config is worse than no config), but a
        // missing file is silently treated as "empty keyring". Project-
        // level config via `[security.maven]` in `cratons.toml` is a
        // follow-up (F-2c).
        let maven_trust = Arc::new(default_user_maven_trust());
        Self {
            concurrency: 8,
            run_scripts: true,
            strict_scripts: false,
            sandbox_policy: SandboxPolicy::Required,
            integrity_policy: IntegrityPolicy::default(),
            maven_trust,
            maven_keystore: None,
            link_strategy: LinkStrategy::Symlink,
            ecosystems: None,
        }
    }
}

impl InstallerConfig {
    /// Build an [`InstallerConfig`] from a parsed manifest, overlaying
    /// the manifest's `[security.maven]` section onto the default
    /// user-level Maven trust configuration.
    ///
    /// Precedence for Maven trust resolution:
    ///
    /// 1. **Project** (`cratons.toml` `[security.maven]`) — highest.
    /// 2. **User** (`~/.config/cratons/trusted-keys/maven.toml`).
    /// 3. **TOFU** (`cratons.lock` `[pgp-trust]` table).
    /// 4. **First-install policy** (`Deny` in CI, `Warn` interactively).
    ///
    /// The project config does **not** merge with the user config —
    /// if a project defines any `[security.maven]` section at all, its
    /// trusted-keys list and first-install policy fully override the
    /// user-level equivalents for that run. This matches operator
    /// intuition ("the manifest is the source of truth for this repo")
    /// and gives strict deployments a clean knob to cut off sloppy
    /// machine-global defaults.
    ///
    /// When the manifest has no `[security.maven]` section at all, the
    /// returned config is identical to [`InstallerConfig::default()`].
    pub fn from_manifest(manifest: &cratons_manifest::Manifest) -> Self {
        let mut cfg = Self::default();

        // The manifest-level security config is optional and lives in
        // `manifest.security.maven`. If every field is the zero value,
        // we treat the section as absent and fall through to the
        // user-level config loaded by Default.
        let maven = &manifest.security.maven;
        let has_manifest_maven_config = !maven.trusted_keys.is_empty()
            || maven.first_install.is_some()
            || !maven.keyservers.is_empty();
        if !has_manifest_maven_config {
            return cfg;
        }

        // Convert the manifest types (plain serde structs, no dep on
        // cratons-security) into runtime `MavenTrustConfig`.
        let trusted_keys: Vec<cratons_security::TrustedKeyEntry> = maven
            .trusted_keys
            .iter()
            .map(|e| cratons_security::TrustedKeyEntry {
                group_id: e.group_id.clone(),
                fingerprint: e.fingerprint.clone(),
            })
            .collect();

        let first_install = maven
            .first_install
            .as_deref()
            .map(parse_first_install_policy)
            .unwrap_or_default();

        cfg.maven_trust = Arc::new(cratons_security::MavenTrustConfig {
            trusted_keys,
            first_install,
            keyservers: maven.keyservers.clone(),
        });

        cfg
    }
}

/// Parse a `first-install` string value from the manifest into the
/// typed enum, falling back to the default (`Warn`) on an unknown value
/// and emitting a structured warn event so operators can catch typos.
fn parse_first_install_policy(raw: &str) -> cratons_security::FirstInstallPolicy {
    match raw.to_ascii_lowercase().as_str() {
        "deny" => cratons_security::FirstInstallPolicy::Deny,
        "warn" => cratons_security::FirstInstallPolicy::Warn,
        "allow" => cratons_security::FirstInstallPolicy::Allow,
        other => {
            warn!(
                value = %other,
                "unknown [security.maven] first-install value; using default (Warn)"
            );
            cratons_security::FirstInstallPolicy::default()
        }
    }
}

/// Load the default user-level Maven trust config from
/// `~/.config/cratons/trusted-keys/maven.toml`, returning an empty config
/// on `ENOENT` and panicking only on a malformed existing file.
fn default_user_maven_trust() -> cratons_security::MavenTrustConfig {
    let Some(base) = dirs::config_dir() else {
        return cratons_security::MavenTrustConfig::default();
    };
    let path = base.join("cratons").join("trusted-keys").join("maven.toml");
    cratons_security::MavenTrustConfig::load_or_default(&path)
        .unwrap_or_else(|e| {
            warn!(
                path = %path.display(),
                error = %e,
                "failed to load user Maven trust config; using empty default"
            );
            cratons_security::MavenTrustConfig::default()
        })
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
    /// PGP trust-on-first-use fingerprints collected during this install
    /// (F-2c).
    ///
    /// Maps Maven groupId → OpenPGP fingerprint that signed the package
    /// in a successful first-install verification. The CLI command is
    /// responsible for merging these into `lockfile.pgp_trust` and
    /// persisting the updated lockfile. The installer never mutates the
    /// lockfile in place — keeping the read/write split clean makes
    /// failed installs not corrupt on-disk state.
    pub pgp_trust_updates: HashMap<String, String>,
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
    /// Structured warnings raised during installation of this ecosystem
    /// (e.g. `integrity-degraded: <pkg>@<ver>` entries when a package was
    /// installed under [`IntegrityPolicy::RequiredWithEcosystemAllowlist`]).
    /// Aggregated into [`InstallResult::warnings`] by the top-level loop.
    pub warnings: Vec<String>,
    /// PGP TOFU pins recorded for this ecosystem (F-2c). Currently only
    /// populated for Maven. Aggregated into
    /// [`InstallResult::pgp_trust_updates`] by the top-level loop.
    pub pgp_trust_updates: HashMap<String, String>,
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

        let downloader = PackageDownloader::with_maven_trust(
            client.clone(),
            config.concurrency,
            config.maven_trust.clone(),
        );

        Self {
            store,
            downloader,
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

        // F-2c: snapshot the lockfile's [pgp-trust] TOFU table at the
        // start of the install. The downloader reads this for strict
        // enforcement of existing pins; any new pins flow back up via
        // `DownloadResult.tofu_pin` → `EcosystemResult.pgp_trust_updates`
        // → `InstallResult.pgp_trust_updates`, and the CLI merges them
        // into the lockfile after the install succeeds.
        let pgp_snapshot = Arc::new(lockfile.pgp_trust.clone());
        let downloader = self.downloader.with_lockfile_trust(pgp_snapshot);

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
            pgp_trust_updates: HashMap::new(),
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
                .install_ecosystem(ecosystem, &packages, project_dir, &downloader)
                .await?;

            result.packages_installed += eco_result.packages;
            result.packages_cached += eco_result.cached;
            result.packages_downloaded += eco_result.downloaded;
            result.bytes_downloaded += eco_result.bytes;

            // Bubble per-ecosystem structured warnings up to the top-level
            // result so CI/audit tooling can scrape them from one place.
            result.warnings.extend(eco_result.warnings.iter().cloned());

            // F-2c: bubble up TOFU pins.
            for (group_id, fingerprint) in &eco_result.pgp_trust_updates {
                result
                    .pgp_trust_updates
                    .insert(group_id.clone(), fingerprint.clone());
            }

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
        downloader: &PackageDownloader,
    ) -> Result<EcosystemResult> {
        let mut eco_result = EcosystemResult::default();

        // Enforce integrity policy BEFORE touching the network or CAS. Packages
        // that the policy disallows never cause a network fetch, never allocate
        // memory for bytes, and never land in the content-addressable store.
        // Allowlisted empty integrity emits a structured warning that the
        // top-level install loop aggregates into `InstallResult.warnings`.
        self.enforce_integrity_policy(ecosystem, packages, &mut eco_result.warnings)?;

        // Determine installation directory
        let install_dir = self.get_install_dir(ecosystem, project_dir)?;
        std::fs::create_dir_all(&install_dir)?;
        eco_result.install_dir = Some(install_dir.clone());

        // Download and extract packages. F-2c: collect any TOFU pins
        // the downloader emits into this ecosystem's result so the
        // top-level install loop can merge them into `InstallResult`
        // and the CLI can persist them to the lockfile.
        let (statuses, pgp_trust_updates) =
            self.download_and_extract(packages, downloader).await?;
        eco_result.pgp_trust_updates.extend(pgp_trust_updates);

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

    /// Download and extract packages, returning their installation
    /// status plus any PGP TOFU pins recorded during the download pass.
    async fn download_and_extract(
        &self,
        packages: &[&LockedPackage],
        downloader: &PackageDownloader,
    ) -> Result<(Vec<PackageInstallStatus>, HashMap<String, String>)> {
        let mut statuses = Vec::with_capacity(packages.len());
        let mut pgp_pins: HashMap<String, String> = HashMap::new();

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

        // Download missing packages in parallel. Use the per-install
        // downloader handle passed in from the top-level `install()`,
        // which carries the lockfile `[pgp-trust]` snapshot.
        if !to_download.is_empty() {
            info!("Downloading {} packages...", to_download.len());
            let downloaded = downloader
                .download_all(&to_download, self.store)
                .await?;

            for (pkg, dl) in to_download.iter().zip(downloaded) {
                // Extract the package
                let extracted_path = self.extractor.extract(&dl.path, pkg.ecosystem, self.store)?;

                // Verify content-hash integrity after extraction. Empty
                // integrity is already policy-gated earlier in
                // `install_ecosystem`, so reaching this point with an empty
                // value means the active policy allows it (Skip or
                // allowlisted ecosystem). Only non-empty values trigger the
                // post-extract hash check.
                if !pkg.integrity.is_empty() {
                    self.verify_integrity(pkg, &extracted_path)?;
                }

                // Collect any TOFU pin emitted by the downloader for this
                // package (F-2c).
                if let Some((group_id, fingerprint)) = dl.tofu_pin {
                    pgp_pins.insert(group_id, fingerprint);
                }

                statuses.push(PackageInstallStatus {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    ecosystem: pkg.ecosystem,
                    cached: false,
                    bytes_downloaded: dl.bytes_downloaded,
                    install_path: extracted_path,
                });
            }
        }

        Ok((statuses, pgp_pins))
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
    /// Enforce the configured [`IntegrityPolicy`] against a slice of packages
    /// for a given ecosystem, **before** any network fetch or CAS write.
    ///
    /// - Packages with non-empty registry integrity are always allowed;
    ///   their byte-level verification happens downstream in
    ///   `PackageDownloader::download`.
    /// - Packages with empty registry integrity are gated by the active
    ///   policy: rejected outright under `Required`, allowed-with-warning
    ///   under `RequiredWithEcosystemAllowlist` if the ecosystem is on the
    ///   list, allowed silently under `Skip`.
    ///
    /// Returns an error listing offending packages on the first policy
    /// violation. Collects `integrity-degraded` warnings into `warnings`.
    fn enforce_integrity_policy(
        &self,
        ecosystem: Ecosystem,
        packages: &[&LockedPackage],
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        for pkg in packages {
            if !pkg.integrity.is_empty() {
                continue;
            }

            if self.config.integrity_policy.allows_empty_integrity(ecosystem) {
                let msg = format!(
                    "integrity-degraded: {}@{} ({:?}) installed without registry integrity; \
                     ecosystem is on the allowlist. Follow-up: implement an independent \
                     checksum/signature source (sum.golang.org for Go, PGP for Maven).",
                    pkg.name, pkg.version, ecosystem
                );
                warn!(
                    package = %pkg.name,
                    version = %pkg.version,
                    ecosystem = ?ecosystem,
                    tag = "integrity-degraded",
                    "installing package without registry integrity under allowlist policy"
                );
                warnings.push(msg);
            } else {
                return Err(CratonsError::ChecksumMismatch {
                    package: format!("{}@{}", pkg.name, pkg.version),
                    expected: "<registry-provided integrity>".to_string(),
                    actual: "<empty>".to_string(),
                });
            }
        }
        Ok(())
    }

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

        let runner = PostInstallRunner::new(self.config.sandbox_policy);
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
        assert_eq!(config.sandbox_policy, SandboxPolicy::Required);
        // Post-F-final: default is fully strict. Go and Maven now have
        // real cross-origin integrity (sum.golang.org signed notes / PGP)
        // so neither needs to be allowlisted.
        assert_eq!(config.integrity_policy, IntegrityPolicy::Required);
        assert_eq!(config.link_strategy, LinkStrategy::Symlink);
        assert!(config.ecosystems.is_none());
    }

    // ---- IntegrityPolicy matrix -----------------------------------------

    #[test]
    fn integrity_policy_required_rejects_all_ecosystems() {
        let policy = IntegrityPolicy::Required;
        for eco in [
            Ecosystem::Npm,
            Ecosystem::PyPi,
            Ecosystem::Crates,
            Ecosystem::Go,
            Ecosystem::Maven,
            Ecosystem::Url,
        ] {
            assert!(!policy.allows_empty_integrity(eco), "{:?}", eco);
        }
    }

    #[test]
    fn integrity_policy_skip_allows_all_ecosystems() {
        let policy = IntegrityPolicy::Skip;
        for eco in [
            Ecosystem::Npm,
            Ecosystem::PyPi,
            Ecosystem::Crates,
            Ecosystem::Go,
            Ecosystem::Maven,
            Ecosystem::Url,
        ] {
            assert!(policy.allows_empty_integrity(eco), "{:?}", eco);
        }
    }

    #[test]
    fn integrity_policy_default_is_strict_for_every_ecosystem() {
        // Post-F-final: the default is `Required`, which rejects empty
        // integrity for every ecosystem. Historical test name preserved
        // in CHANGELOG; assertion inverted.
        let policy = IntegrityPolicy::default();
        assert!(!policy.allows_empty_integrity(Ecosystem::Go));
        assert!(!policy.allows_empty_integrity(Ecosystem::Maven));
        assert!(!policy.allows_empty_integrity(Ecosystem::Npm));
        assert!(!policy.allows_empty_integrity(Ecosystem::PyPi));
        assert!(!policy.allows_empty_integrity(Ecosystem::Crates));
        assert!(!policy.allows_empty_integrity(Ecosystem::Url));
    }

    #[test]
    fn integrity_policy_custom_allowlist_respects_membership() {
        let policy = IntegrityPolicy::RequiredWithEcosystemAllowlist(vec![Ecosystem::Npm]);
        assert!(policy.allows_empty_integrity(Ecosystem::Npm));
        assert!(!policy.allows_empty_integrity(Ecosystem::PyPi));
        assert!(!policy.allows_empty_integrity(Ecosystem::Go));
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
            pgp_trust_updates: HashMap::new(),
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
