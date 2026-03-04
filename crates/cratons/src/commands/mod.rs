//! CLI command implementations.

pub mod workspace;

use workspace::WorkspaceOpts;
use indicatif::{ProgressBar, ProgressStyle};
use cratons_core::Ecosystem;
use cratons_installer::{InstallerConfig, LinkStrategy};
use cratons_lockfile::{LOCKFILE_NAME, Lockfile};
use cratons_manifest::Manifest;
use cratons_store::Store;
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};

/// Initialize a new project.
pub fn init(path: &str) -> Result<()> {
    let project_dir = if path == "." {
        std::env::current_dir().into_diagnostic()?
    } else {
        let p = Path::new(path);
        if !p.exists() {
            std::fs::create_dir_all(p).into_diagnostic()?;
        }
        p.to_path_buf()
    };

    let manifest_path = project_dir.join("cratons.toml");
    if manifest_path.exists() {
        println!("{} cratons.toml already exists", "!".yellow());
        return Ok(());
    }

    // Get project name from directory
    let name = project_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "my-project".to_string());

    let manifest_content = format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
description = ""

[environment]
# node = "20.10.0"
# python = "3.12.0"
# rust = "1.75.0"

[dependencies]
# [dependencies.npm]
# lodash = "^4.17.21"

# [dependencies.pypi]
# requests = ">=2.28.0"

[scripts]
# dev = "npm run dev"
# test = "npm test"
# build = "npm run build"
"#
    );

    std::fs::write(&manifest_path, manifest_content).into_diagnostic()?;

    println!("{} Created cratons.toml", "✓".green());
    println!();
    println!("Next steps:");
    println!("  1. Edit {} to add dependencies", "cratons.toml".cyan());
    println!("  2. Run {} to install", "cratons install".cyan());

    Ok(())
}

/// Add dependencies.
pub fn add(deps: &[String], dev: bool, _build: bool) -> Result<()> {
    let (mut manifest, manifest_path) =
        Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    let mut added = Vec::new();

    for dep in deps {
        // Parse dep format: ecosystem:name@version (e.g., "npm:lodash@^4.17.0")
        let spec = cratons_core::PackageSpec::parse(dep)
            .map_err(|e| miette::miette!("Invalid dependency: {}", e))?;

        let ecosystem = spec.id.ecosystem;
        let name = spec.id.name.clone();
        let version = spec.version_req.to_string();

        // Create the dependency entry
        let dependency = cratons_manifest::Dependency::Version(version.clone());

        // Choose target: dev-dependencies or regular dependencies
        let target_deps = if dev {
            &mut manifest.dev_dependencies
        } else {
            &mut manifest.dependencies
        };

        // Add to the correct ecosystem
        match ecosystem {
            cratons_core::Ecosystem::Npm => {
                target_deps.npm.insert(name.clone(), dependency);
            }
            cratons_core::Ecosystem::PyPi => {
                target_deps.pypi.insert(name.clone(), dependency);
            }
            cratons_core::Ecosystem::Crates => {
                target_deps.crates.insert(name.clone(), dependency);
            }
            cratons_core::Ecosystem::Go => {
                target_deps.go.insert(name.clone(), dependency);
            }
            cratons_core::Ecosystem::Maven => {
                target_deps.maven.insert(name.clone(), dependency);
            }
            cratons_core::Ecosystem::Url => {
                target_deps.url.insert(name.clone(), dependency);
            }
        }

        println!(
            "{} {}:{}@{}{}",
            "+".green(),
            format!("{:?}", ecosystem).to_lowercase().dimmed(),
            name.cyan(),
            version,
            if dev {
                " (dev)".dimmed().to_string()
            } else {
                String::new()
            }
        );

        added.push(name);
    }

    // Serialize and save the manifest
    let toml_content = manifest
        .to_toml_string()
        .map_err(|e| miette::miette!("Failed to serialize manifest: {}", e))?;

    std::fs::write(&manifest_path, toml_content)
        .into_diagnostic()
        .wrap_err("Failed to write manifest")?;

    println!();
    println!(
        "{} Added {} dependenc{} to {}",
        "✓".green(),
        added.len(),
        if added.len() == 1 { "y" } else { "ies" },
        manifest_path.display()
    );
    println!(
        "  {} Run {} to install",
        "→".dimmed(),
        "cratons install".cyan()
    );

    Ok(())
}

/// Remove dependencies.
pub fn remove(deps: &[String]) -> Result<()> {
    let (mut manifest, manifest_path) =
        Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    let mut removed = Vec::new();
    let mut not_found = Vec::new();

    for dep in deps {
        // Try to parse as a full spec (ecosystem:name) or just a name
        let (ecosystem, name) = if let Ok(spec) = cratons_core::PackageSpec::parse(dep) {
            (Some(spec.id.ecosystem), spec.id.name)
        } else {
            // Just a plain name - search all ecosystems
            (None, dep.clone())
        };

        let mut found = false;

        // Helper macro to try removing from an ecosystem
        macro_rules! try_remove {
            ($eco:expr, $map:expr, $dev_map:expr) => {
                if ecosystem.is_none() || ecosystem == Some($eco) {
                    if $map.remove(&name).is_some() {
                        found = true;
                        println!(
                            "{} {}:{} (dependencies)",
                            "-".red(),
                            format!("{:?}", $eco).to_lowercase().dimmed(),
                            name.cyan()
                        );
                    }
                    if $dev_map.remove(&name).is_some() {
                        found = true;
                        println!(
                            "{} {}:{} (dev-dependencies)",
                            "-".red(),
                            format!("{:?}", $eco).to_lowercase().dimmed(),
                            name.cyan()
                        );
                    }
                }
            };
        }

        try_remove!(
            cratons_core::Ecosystem::Npm,
            manifest.dependencies.npm,
            manifest.dev_dependencies.npm
        );
        try_remove!(
            cratons_core::Ecosystem::PyPi,
            manifest.dependencies.pypi,
            manifest.dev_dependencies.pypi
        );
        try_remove!(
            cratons_core::Ecosystem::Crates,
            manifest.dependencies.crates,
            manifest.dev_dependencies.crates
        );
        try_remove!(
            cratons_core::Ecosystem::Go,
            manifest.dependencies.go,
            manifest.dev_dependencies.go
        );
        try_remove!(
            cratons_core::Ecosystem::Maven,
            manifest.dependencies.maven,
            manifest.dev_dependencies.maven
        );
        try_remove!(
            cratons_core::Ecosystem::Url,
            manifest.dependencies.url,
            manifest.dev_dependencies.url
        );

        if found {
            removed.push(name);
        } else {
            not_found.push(dep.clone());
        }
    }

    if !not_found.is_empty() {
        for name in &not_found {
            println!("{} {} not found in manifest", "!".yellow(), name.cyan());
        }
    }

    if removed.is_empty() {
        println!();
        println!("{} No dependencies removed", "!".yellow());
        return Ok(());
    }

    // Serialize and save the manifest
    let toml_content = manifest
        .to_toml_string()
        .map_err(|e| miette::miette!("Failed to serialize manifest: {}", e))?;

    std::fs::write(&manifest_path, toml_content)
        .into_diagnostic()
        .wrap_err("Failed to write manifest")?;

    println!();
    println!(
        "{} Removed {} dependenc{} from {}",
        "✓".green(),
        removed.len(),
        if removed.len() == 1 { "y" } else { "ies" },
        manifest_path.display()
    );

    // Delete the lockfile since it's now stale
    let lockfile_path = manifest_path
        .parent()
        .map(|p| p.join(LOCKFILE_NAME))
        .filter(|p| p.exists());

    if let Some(_lockfile) = lockfile_path {
        println!(
            "  {} Lockfile invalidated - run {} to regenerate",
            "→".dimmed(),
            "cratons install".cyan()
        );
    }

    Ok(())
}

/// Install dependencies.
pub fn install(force: bool, frozen: bool, offline: bool) -> Result<()> {
    // Use tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new().into_diagnostic()?;
    rt.block_on(install_async(force, frozen, offline))
}

/// Async implementation of install.
async fn install_async(force: bool, frozen: bool, offline: bool) -> Result<()> {
    let (manifest, manifest_path) =
        Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    let project_dir = manifest_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    println!(
        "{} Installing dependencies for {}",
        "→".blue(),
        manifest.package.name.cyan()
    );

    if offline {
        println!("{} Offline mode enabled", "!".yellow());
    }

    // Open the store
    let store =
        Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

    // Check for existing lockfile
    let lockfile_path = project_dir.join(LOCKFILE_NAME);
    let lockfile = if lockfile_path.exists() {
        let lockfile = Lockfile::load(&lockfile_path)
            .map_err(|e| miette::miette!("Failed to load lockfile: {}", e))?;

        // Check if lockfile is fresh
        let manifest_hash = cratons_resolver::compute_manifest_hash(&manifest);

        if lockfile.is_fresh(&manifest_hash) && !force {
            println!("{} Lockfile is up to date", "✓".green());
            lockfile
        } else if frozen {
            return Err(miette::miette!(
                "Lockfile is out of date but --frozen was specified. \
                 Run `cratons install` without --frozen to update."
            ));
        } else {
            println!(
                "{} Lockfile is stale, resolving dependencies...",
                "!".yellow()
            );
            resolve_and_generate_lockfile(&manifest, &manifest_path, &lockfile_path, offline)
                .await?
        }
    } else if frozen {
        return Err(miette::miette!(
            "No lockfile found but --frozen was specified. \
             Run `cratons install` without --frozen to generate one."
        ));
    } else {
        println!(
            "{} No lockfile found, resolving dependencies...",
            "→".blue()
        );
        resolve_and_generate_lockfile(&manifest, &manifest_path, &lockfile_path, offline).await?
    };

    let package_count = lockfile.package_count();
    if package_count == 0 {
        println!("{} No packages to install", "✓".green());
        return Ok(());
    }

    // Create progress bar
    let pb = ProgressBar::new(package_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message("Installing packages...");

    // Configure installer
    let config = InstallerConfig {
        concurrency: 8,
        run_scripts: true,
        strict_scripts: false,  // Don't fail on script errors by default
        isolate_scripts: false, // Default to non-isolated for now
        skip_integrity: false,
        link_strategy: LinkStrategy::Symlink,
        ecosystems: None, // Install all ecosystems
    };

    // Run installation
    let installer = cratons_installer::Installer::with_config(&store, config);
    let result = installer
        .install(&lockfile, &project_dir)
        .await
        .map_err(|e| miette::miette!("Installation failed: {}", e))?;

    pb.finish_and_clear();

    // Print summary
    println!();
    println!(
        "{} Installed {} packages in {:.2}s",
        "✓".green(),
        result.packages_installed,
        result.duration_secs
    );

    if result.packages_cached > 0 {
        println!("  {} {} from cache", "→".dimmed(), result.packages_cached);
    }

    if result.packages_downloaded > 0 {
        let bytes_str = format_bytes(result.bytes_downloaded);
        println!(
            "  {} {} downloaded ({})",
            "→".dimmed(),
            result.packages_downloaded,
            bytes_str
        );
    }

    // Print per-ecosystem breakdown
    if result.ecosystems.len() > 1 {
        println!();
        for (ecosystem, eco_result) in &result.ecosystems {
            if let Some(ref dir) = eco_result.install_dir {
                println!(
                    "  {} {}: {} packages → {}",
                    "→".dimmed(),
                    ecosystem,
                    eco_result.packages,
                    dir.display()
                );
            }
        }
    }

    // Print environment setup info
    if result.environment_setup {
        println!();
        println!("{} Hermetic environment configured", "✓".green());
        if let Some(ref script) = result.activation_script {
            println!(
                "  {} Activate with: {}",
                "→".dimmed(),
                format!("source {}", script.display()).cyan()
            );
        }
    }

    // Print warnings
    for warning in &result.warnings {
        println!("{} {}", "!".yellow(), warning);
    }

    Ok(())
}

/// Resolve dependencies and generate a lockfile.
async fn resolve_and_generate_lockfile(
    manifest: &Manifest,
    manifest_path: &Path,
    lockfile_path: &Path,
    offline: bool,
) -> Result<Lockfile> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    spinner.set_message("Resolving dependencies...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    // Create resolver with offline flag
    let resolver = cratons_resolver::Resolver::with_defaults(offline)
        .map_err(|e| miette::miette!("Failed to initialize resolver: {}", e))?;

    // Perform resolution
    let (_resolution, lockfile) = resolver
        .resolve_and_lock(manifest, manifest_path)
        .await
        .map_err(|e| miette::miette!("Resolution failed: {}", e))?;

    spinner.finish_with_message(format!(
        "{} Resolved {} packages",
        "✓".green(),
        lockfile.package_count()
    ));

    // Save lockfile
    lockfile
        .save(lockfile_path)
        .map_err(|e| miette::miette!("Failed to save lockfile: {}", e))?;

    println!("{} Saved {}", "✓".green(), lockfile_path.display());

    Ok(lockfile)
}

/// Format bytes into a human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Update dependencies.
pub fn update(packages: &[String], offline: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().into_diagnostic()?;
    rt.block_on(update_async(packages, offline))
}

/// Async implementation of update.
async fn update_async(packages: &[String], offline: bool) -> Result<()> {
    let (manifest, manifest_path) =
        Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    let project_dir = manifest_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    if packages.is_empty() {
        println!("{} Updating all dependencies", "→".blue());
    } else {
        println!(
            "{} Updating {} packages: {}",
            "→".blue(),
            packages.len(),
            packages.join(", ").cyan()
        );
    }

    if offline {
        println!("{} Offline mode enabled", "!".yellow());
    }

    // Load existing lockfile to compare versions
    let lockfile_path = project_dir.join(LOCKFILE_NAME);
    let old_lockfile = if lockfile_path.exists() {
        Some(
            Lockfile::load(&lockfile_path)
                .map_err(|e| miette::miette!("Failed to load lockfile: {}", e))?,
        )
    } else {
        None
    };

    // Check if manifest has any dependencies
    if manifest.dependencies.is_empty() && manifest.dev_dependencies.is_empty() {
        println!("{} No dependencies to update", "✓".green());
        return Ok(());
    }

    // Re-resolve all dependencies (this will get the latest compatible versions)
    println!("{} Resolving dependencies...", "→".blue());

    // Create resolver
    let resolver = cratons_resolver::Resolver::with_defaults(offline)
        .map_err(|e| miette::miette!("Failed to initialize resolver: {}", e))?;

    // Resolve dependencies
    let resolved = resolver
        .resolve(&manifest)
        .await
        .map_err(|e| miette::miette!("Resolution failed: {}", e))?;

    // Compare with old lockfile and show changes
    let mut updated_count = 0;
    let mut new_count = 0;

    if let Some(ref old_lock) = old_lockfile {
        for pkg in &resolved.packages {
            let old_version = old_lock
                .packages
                .iter()
                .find(|p| p.name == pkg.name && p.ecosystem == pkg.ecosystem)
                .map(|p| p.version.as_str());

            let new_version = &pkg.version;

            match old_version {
                Some(old) if old != new_version => {
                    if packages.is_empty() || packages.iter().any(|p| p == &pkg.name) {
                        println!(
                            "  {} {}:{} {} → {}",
                            "↑".green(),
                            format!("{:?}", pkg.ecosystem).to_lowercase().dimmed(),
                            pkg.name.cyan(),
                            old.dimmed(),
                            new_version.green()
                        );
                        updated_count += 1;
                    }
                }
                None => {
                    println!(
                        "  {} {}:{} {}",
                        "+".green(),
                        format!("{:?}", pkg.ecosystem).to_lowercase().dimmed(),
                        pkg.name.cyan(),
                        new_version.green()
                    );
                    new_count += 1;
                }
                _ => {}
            }
        }
    } else {
        new_count = resolved.package_count();
    }

    // Generate new lockfile
    let manifest_hash = cratons_resolver::compute_manifest_hash(&manifest);
    let new_lockfile = resolved.to_lockfile(manifest_hash);

    // Save lockfile
    new_lockfile
        .save(&lockfile_path)
        .map_err(|e| miette::miette!("Failed to save lockfile: {}", e))?;

    println!();
    if updated_count > 0 || new_count > 0 {
        println!(
            "{} Updated {} package{}, {} new",
            "✓".green(),
            updated_count,
            if updated_count == 1 { "" } else { "s" },
            new_count
        );
        println!(
            "  {} Run {} to install updated packages",
            "→".dimmed(),
            "cratons install".cyan()
        );
    } else {
        println!("{} All dependencies are up to date", "✓".green());
    }

    Ok(())
}

/// Execute a tool transiently.
pub fn exec(package: &str, args: &[String], offline: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().into_diagnostic()?;
    rt.block_on(exec_async(package, args, offline))
}

async fn exec_async(package: &str, args: &[String], offline: bool) -> Result<()> {
    use cratons_core::PackageSpec;

    // Parse package spec
    let spec = PackageSpec::parse(package)
        .map_err(|e| miette::miette!("Invalid package spec '{}': {}", package, e))?;

    println!(
        "{} Executing {}:{} transiently...",
        "→".blue(),
        spec.id.ecosystem,
        spec.id.name
    );

    if offline {
        println!("{} Offline mode enabled", "!".yellow());
    }

    // Create a temporary directory for the environment
    let temp_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("Failed to create temporary directory: {}", e))?;
    let project_dir = temp_dir.path();

    // Create a minimal manifest
    let mut manifest = Manifest::default();
    manifest.package.name = "cratons-exec-transient".to_string();
    manifest.package.version = "0.0.0".to_string();

    // Add the requested package as a dependency
    let dep = cratons_manifest::Dependency::Version(spec.version_req.to_string());
    match spec.id.ecosystem {
        Ecosystem::Npm => {
            manifest.dependencies.npm.insert(spec.id.name.clone(), dep);
        }
        Ecosystem::PyPi => {
            manifest.dependencies.pypi.insert(spec.id.name.clone(), dep);
        }
        Ecosystem::Crates => {
            manifest
                .dependencies
                .crates
                .insert(spec.id.name.clone(), dep);
        }
        Ecosystem::Go => {
            manifest.dependencies.go.insert(spec.id.name.clone(), dep);
        }
        Ecosystem::Maven => {
            manifest
                .dependencies
                .maven
                .insert(spec.id.name.clone(), dep);
        }
        Ecosystem::Url => {
            manifest.dependencies.url.insert(spec.id.name.clone(), dep);
        }
    }

    // Resolve dependencies
    let resolver = cratons_resolver::Resolver::with_defaults(offline)
        .map_err(|e| miette::miette!("Failed to initialize resolver: {}", e))?;

    let resolution = resolver
        .resolve(&manifest)
        .await
        .map_err(|e| miette::miette!("Resolution failed: {}", e))?;

    let lockfile = resolution.to_lockfile(cratons_resolver::compute_manifest_hash(&manifest));

    // Install dependencies
    let store =
        Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

    let config = InstallerConfig {
        concurrency: 4,
        run_scripts: true,
        strict_scripts: false,
        isolate_scripts: false,
        skip_integrity: false,
        link_strategy: LinkStrategy::Symlink,
        ecosystems: None,
    };

    let installer = cratons_installer::Installer::with_config(&store, config);
    installer
        .install(&lockfile, project_dir)
        .await
        .map_err(|e| miette::miette!("Installation failed: {}", e))?;

    // Determine command to run
    // For now, assume the package name is the binary name, or use ecosystem defaults
    // TODO: Look at metadata 'bin' field or equivalent
    let (cmd, cmd_args) = match spec.id.ecosystem {
        Ecosystem::Npm => {
            // node_modules/.bin/<name>
            let bin_path = project_dir
                .join("node_modules")
                .join(".bin")
                .join(&spec.id.name);
            (bin_path.to_string_lossy().to_string(), args.to_vec())
        }
        Ecosystem::PyPi => {
            // .venv/bin/<name> (conceptually) - depends on cratons-installer impl for pypi
            // For now, assume it's in a bin dir
            (spec.id.name.clone(), args.to_vec())
        }
        _ => (spec.id.name.clone(), args.to_vec()),
    };

    println!("{} Running {}...", "→".blue(), cmd);

    // Run the command
    let status = std::process::Command::new(&cmd)
        .args(&cmd_args)
        .current_dir(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .env(
            "PATH",
            format!(
                "{}:{}",
                project_dir.join("node_modules/.bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .status()
        .into_diagnostic()?;

    if !status.success() {
        return Err(miette::miette!(
            "Command failed with exit code {}",
            status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

/// Build the project.
pub fn build(release: bool, no_cache: bool, workspace_opts: WorkspaceOpts) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().into_diagnostic()?;
    rt.block_on(build_async(release, no_cache, workspace_opts))
}

/// Async implementation of build.
async fn build_async(release: bool, no_cache: bool, workspace_opts: WorkspaceOpts) -> Result<()> {
    // Try to load workspace
    if let Ok(workspace) = cratons_workspace::Workspace::load(Path::new(".")) {
        let filter = workspace_opts.to_filter()?;

        // Execute build for selected members
        let executor = cratons_workspace::WorkspaceExecutor::new(&workspace)
            .with_filter(filter)
            .topological(); // Always build topological

        let selected = executor
            .selected_members()
            .map_err(|e| miette::miette!("Failed to select workspace members: {}", e))?;

        if selected.is_empty() {
            // Check if we are in a subdirectory that is a workspace member but not the root
            // Note: Workspace::load(".") only works if . is the root.
            // If we are here, we are at the workspace root.
            // If selected is empty, it means the filter matched nothing.
            
            // However, if no filter was provided (default), we might want to build ALL members?
            // Current WorkspaceOpts logic: empty filter = match all?
            // Let's check WorkspaceOpts::to_filter implementation.
            // It defaults to empty filter which matches all.
            // So if selected is empty, the workspace is empty.
            
            println!("{} No packages to build", "!".yellow());
            return Ok(());
        }

        println!(
            "{} Building {} packages in workspace",
            "→".blue(),
            selected.len()
        );

        // Open store once
        let store =
            Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

        for member in selected {
            build_package(&member.manifest, &member.path, release, no_cache, &store).await?;
        }

        return Ok(());
    }

    // Fallback to single package build
    let (manifest, manifest_path) =
        Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    let project_dir = manifest_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let store =
        Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

    build_package(&manifest, &project_dir, release, no_cache, &store).await
}

async fn build_package(
    manifest: &Manifest,
    project_dir: &Path,
    release: bool,
    no_cache: bool,
    store: &Store,
) -> Result<()> {
    let mode = if release { "release" } else { "debug" };
    println!(
        "{} Building {} in {} mode",
        "→".blue(),
        manifest.package.name.cyan(),
        mode
    );

    if no_cache {
        println!("{} Cache disabled", "!".yellow());
    }

    // Check for build script in manifest
    let build_script = match &manifest.build.script {
        cratons_manifest::parse::BuildScript::Inline(s) if s.is_empty() => {
            // No build script defined - check for a "build" script in scripts section
            match manifest.scripts.get("build") {
                Some(s) => s.clone(),
                None => {
                    return Err(miette::miette!(
                        "No build script defined for {}. Add a [build] section or a 'build' script to your cratons.toml",
                        manifest.package.name
                    ));
                }
            }
        }
        cratons_manifest::parse::BuildScript::Inline(s) => s.clone(),
        cratons_manifest::parse::BuildScript::File { file } => {
            let script_path = project_dir.join(file);
            std::fs::read_to_string(&script_path)
                .map_err(|e| miette::miette!("Failed to read build script {}: {}", file, e))?
        }
    };

    // Create build configuration
    let mut config = cratons_builder::BuildConfig::new(
        manifest.package.name.clone(),
        manifest.package.version.clone(),
        build_script,
    );

    // Set build outputs if specified
    if !manifest.build.outputs.is_empty() {
        config.outputs = manifest.build.outputs.clone();
    }

    // Set resource limits from manifest
    if let Some(memory) = manifest.build.memory_limit {
        config.memory_limit = Some(memory);
    }
    if let Some(cpu) = manifest.build.cpu_limit {
        config.cpu_limit = Some(cpu);
    }
    if let Some(timeout) = manifest.build.timeout {
        config.timeout_secs = Some(timeout);
    }

    // Add environment variables
    if release {
        config.env("NODE_ENV".to_string(), "production".to_string());
        config.env("CRATONS_BUILD_MODE".to_string(), "release".to_string());
    } else {
        config.env("NODE_ENV".to_string(), "development".to_string());
        config.env("CRATONS_BUILD_MODE".to_string(), "debug".to_string());
    }

    // Add toolchains from environment config
    if let Some(ref node) = manifest.environment.node {
        config.toolchain("node", node);
    }
    if let Some(ref python) = manifest.environment.python {
        config.toolchain("python", python);
    }
    if let Some(ref rust) = manifest.environment.rust {
        config.toolchain("rust", rust);
    }

    // Execute build
    println!("{} Executing build script...", "→".blue());

    // Emit BuildStarted event
    cratons_core::BuildEvent::BuildStarted {
        total_packages: 1, // Currently building 1 package
    }
    .emit();

    let start = std::time::Instant::now();
    let result = match cratons_builder::build(store, &config, project_dir).await {
        Ok(res) => res,
        Err(e) => {
            cratons_core::BuildEvent::BuildFinished {
                success: false,
                duration_ms: start.elapsed().as_millis() as u64,
            }
            .emit();
            return Err(miette::miette!("Build failed: {}", e));
        }
    };

    let duration = start.elapsed();

    // Emit BuildFinished event
    cratons_core::BuildEvent::BuildFinished {
        success: true,
        duration_ms: duration.as_millis() as u64,
    }
    .emit();

    println!();
    if result.cached {
        println!(
            "{} Build cached (input hash: {})",
            "✓".green(),
            result.input_hash.short().dimmed()
        );
    } else {
        println!(
            "{} Build complete in {:.2}s",
            "✓".green(),
            duration.as_secs_f64()
        );
    }
    println!(
        "  {} Output: {}",
        "→".dimmed(),
        result.output_path.display()
    );

    Ok(())
}

/// Run a script in the hermetic environment.
pub fn run(script: &str, args: &[String], workspace_opts: WorkspaceOpts) -> Result<()> {
    // Try to load workspace
    if let Ok(workspace) = cratons_workspace::Workspace::load(Path::new(".")) {
        let filter = workspace_opts.to_filter()?;
        let executor = cratons_workspace::WorkspaceExecutor::new(&workspace)
            .with_filter(filter)
            .topological();

        let selected = executor
            .selected_members()
            .map_err(|e| miette::miette!("Failed to select workspace members: {}", e))?;

        if selected.is_empty() {
            println!("{} No packages selected", "!".yellow());
            return Ok(());
        }

        println!(
            "{} Running script '{}' in {} packages",
            "→".blue(),
            script.cyan(),
            selected.len()
        );

        for member in selected {
            // Check if member has the script
            if member.manifest.scripts.has(script) {
                println!(
                    "{} In package {}:",
                    "→".blue(),
                    member.manifest.package.name.cyan()
                );
                if let Err(e) = run_package_script(script, args, &member.manifest, &member.path) {
                    println!("{} Script failed: {}", "!".red(), e);
                    if executor.is_fail_fast() {
                        return Err(e);
                    }
                }
                println!();
            } else {
                // If specific filter was used, we might want to warn.
                // But for "all", skipping is expected.
                // For now, silent skip to reduce noise, unless debugging.
            }
        }
        return Ok(());
    }

    let (manifest, manifest_path) =
        Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    let project_dir = manifest_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    run_package_script(script, args, &manifest, &project_dir)
}

fn run_package_script(
    script: &str,
    args: &[String],
    manifest: &Manifest,
    project_dir: &Path,
) -> Result<()> {
    let script_cmd = manifest
        .scripts
        .get(script)
        .ok_or_else(|| miette::miette!("Script '{}' not found", script))?;

    println!("{} Running '{}'", "→".blue(), script.cyan());
    println!("{} {}", "$".dimmed(), script_cmd);

    // Load environment variables from hermetic environment
    let env_vars = load_environment_vars(project_dir)?;

    // Execute the script with hermetic environment
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c").arg(script_cmd).args(args);
    // Important: run in the package directory
    cmd.current_dir(project_dir);

    // Inject hermetic environment variables
    for (key, value) in &env_vars {
        cmd.env(key, value);
    }

    // Prepend hermetic bin directories to PATH
    if let Some(path_additions) = env_vars.get("PATH") {
        if let Ok(current_path) = std::env::var("PATH") {
            cmd.env("PATH", format!("{}:{}", path_additions, current_path));
        }
    }

    let status = cmd.status().into_diagnostic()?;

    if !status.success() {
        return Err(miette::miette!(
            "Script '{}' failed with exit code {}",
            script,
            status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

/// Load environment variables from the hermetic environment.
fn load_environment_vars(project_dir: &Path) -> Result<std::collections::HashMap<String, String>> {
    let env_root = project_dir.join(".cratons").join("env");
    let mut vars = std::collections::HashMap::new();

    // Try to load the environment
    if env_root.exists() {
        // Use EnvironmentManager to load the environment
        let env = cratons_environment::EnvironmentManager::load(project_dir)
            .map_err(|e| miette::miette!("Failed to load environment: {}", e))?;
        vars = env.env_vars();
    }

    Ok(vars)
}

/// Start an interactive shell with the hermetic environment activated.
pub fn shell() -> Result<()> {
    let (manifest, manifest_path) =
        Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    let project_dir = manifest_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let activate_script = project_dir.join(".cratons").join("activate");

    if !activate_script.exists() {
        return Err(miette::miette!(
            "No hermetic environment found. Run `cratons install` first."
        ));
    }

    println!(
        "{} Starting shell for {}",
        "→".blue(),
        manifest.package.name.cyan()
    );
    println!(
        "  {} Environment: {}",
        "→".dimmed(),
        project_dir.join(".cratons").join("env").display()
    );
    println!("  {} Type 'exit' to leave", "→".dimmed());
    println!();

    // Get the user's default shell
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
    let shell_name = Path::new(&shell)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "bash".to_string());

    // Load environment variables
    let env_vars = load_environment_vars(&project_dir)?;

    // Prepare environment with hermetic settings
    let mut cmd = std::process::Command::new(&shell);
    cmd.current_dir(&project_dir);

    // Set environment variables
    for (key, value) in &env_vars {
        cmd.env(key, value);
    }

    // Set markers that we're in a cratons environment
    cmd.env("CRATONS_ENV", "1");
    cmd.env(
        "CRATONS_ENV_ROOT",
        project_dir.join(".cratons").join("env"),
    );

    // Update PATH to include hermetic bin directories
    if let Ok(current_path) = std::env::var("PATH") {
        let mut paths = Vec::new();

        // Add hermetic bin directories first
        let env_root = project_dir.join(".cratons").join("env");
        if env_root.join("python").join("bin").exists() {
            paths.push(
                env_root
                    .join("python")
                    .join("bin")
                    .to_string_lossy()
                    .to_string(),
            );
        }
        if env_root.join("node").join("bin").exists() {
            paths.push(
                env_root
                    .join("node")
                    .join("bin")
                    .to_string_lossy()
                    .to_string(),
            );
        }
        if env_root.join("rust").join("cargo").join("bin").exists() {
            paths.push(
                env_root
                    .join("rust")
                    .join("cargo")
                    .join("bin")
                    .to_string_lossy()
                    .to_string(),
            );
        }
        if env_root.join("go").join("gopath").join("bin").exists() {
            paths.push(
                env_root
                    .join("go")
                    .join("gopath")
                    .join("bin")
                    .to_string_lossy()
                    .to_string(),
            );
        }

        if !paths.is_empty() {
            paths.push(current_path);
            cmd.env("PATH", paths.join(":"));
        }
    }

    // Set a custom prompt to indicate we're in a cratons environment
    match shell_name.as_str() {
        "bash" => {
            cmd.env(
                "PS1",
                format!("(mei:{}) \\u@\\h:\\w\\$ ", manifest.package.name),
            );
        }
        "zsh" => {
            cmd.env(
                "PS1",
                format!("(mei:{}) %n@%m:%~%# ", manifest.package.name),
            );
        }
        "fish" => {
            // Fish handles prompts differently, we'll rely on CRATONS_ENV variable
        }
        _ => {}
    }

    // Start the shell
    let status = cmd.status().into_diagnostic()?;

    if !status.success() {
        // Shell exited with non-zero - this is fine, user might have used `exit 1`
    }

    println!();
    println!("{} Left cratons environment", "→".blue());

    Ok(())
}

/// Show dependency tree.
pub fn tree(all: bool, depth: Option<usize>) -> Result<()> {
    use cratons_lockfile::{LOCKFILE_NAME, Lockfile};
    use std::collections::{HashMap, HashSet};

    let (manifest, _) = Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    // Print root package
    println!(
        "{}@{}",
        manifest.package.name.cyan().bold(),
        manifest.package.version
    );

    // Load lockfile for full dependency graph
    let lockfile_path = Path::new(LOCKFILE_NAME);
    let lockfile = if lockfile_path.exists() {
        Some(
            Lockfile::load(lockfile_path)
                .map_err(|e| miette::miette!("Failed to load lockfile: {}", e))?,
        )
    } else {
        None
    };

    // Build a lookup map for packages in the lockfile
    let package_map: HashMap<(String, Ecosystem), _> = lockfile
        .as_ref()
        .map(|lf| {
            lf.packages
                .iter()
                .map(|p| ((p.name.clone(), p.ecosystem), p))
                .collect()
        })
        .unwrap_or_default();

    // Collect direct dependencies
    let direct_deps: Vec<_> = manifest.dependencies.iter().collect();
    let dep_count = direct_deps.len();

    // Track visited to avoid cycles
    let mut visited = HashSet::new();

    // Maximum depth (default to reasonable limit if showing all)
    let max_depth = depth.unwrap_or(if all { 10 } else { 1 });

    // Recursive tree printing function
    fn print_tree(
        name: &str,
        ecosystem: Ecosystem,
        version: &str,
        package_map: &HashMap<(String, Ecosystem), &cratons_lockfile::LockedPackage>,
        visited: &mut HashSet<(String, Ecosystem)>,
        prefix: &str,
        is_last: bool,
        current_depth: usize,
        max_depth: usize,
        all: bool,
    ) {
        // Print this node
        let connector = if is_last { "└── " } else { "├── " };
        let eco_label = format!("{}:", ecosystem);
        println!(
            "{}{}{}{} @ {}",
            prefix,
            connector,
            eco_label.dimmed(),
            name.cyan(),
            version
        );

        // Check depth limit
        if current_depth >= max_depth {
            return;
        }

        // Check for cycles
        let key = (name.to_string(), ecosystem);
        if visited.contains(&key) {
            let next_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
            println!("{}└── {}", next_prefix, "(circular)".yellow());
            return;
        }
        visited.insert(key.clone());

        // Get transitive dependencies if showing all
        if all {
            if let Some(pkg) = package_map.get(&(name.to_string(), ecosystem)) {
                let deps = &pkg.dependencies;
                let dep_count = deps.len();

                for (i, dep) in deps.iter().enumerate() {
                    let is_last_dep = i == dep_count - 1;
                    let next_prefix =
                        format!("{}{}", prefix, if is_last { "    " } else { "│   " });

                    // Look up the transitive dep in the package map
                    let dep_version = package_map
                        .get(&(dep.name.clone(), ecosystem))
                        .map(|p| p.version.as_str())
                        .unwrap_or(&dep.version);

                    print_tree(
                        &dep.name,
                        ecosystem,
                        dep_version,
                        package_map,
                        visited,
                        &next_prefix,
                        is_last_dep,
                        current_depth + 1,
                        max_depth,
                        all,
                    );
                }
            }
        }

        visited.remove(&key);
    }

    // Print dependency tree
    for (i, (eco, name, dep)) in direct_deps.iter().enumerate() {
        let is_last = i == dep_count - 1;
        let version = lockfile
            .as_ref()
            .and_then(|lf| lf.find_package(name, *eco))
            .map(|p| p.version.as_str())
            .unwrap_or_else(|| dep.version().unwrap_or("*"));

        print_tree(
            name,
            *eco,
            version,
            &package_map,
            &mut visited,
            "",
            is_last,
            0,
            max_depth,
            all,
        );
    }

    // Summary
    let transitive_count = lockfile
        .as_ref()
        .map(|lf| lf.packages.iter().filter(|p| !p.direct).count())
        .unwrap_or(0);

    println!();
    if all && transitive_count > 0 {
        println!(
            "{} {} direct, {} transitive dependencies",
            "→".blue(),
            dep_count,
            transitive_count
        );
    } else {
        println!("{} {} direct dependencies", "→".blue(), dep_count);
        if transitive_count > 0 && !all {
            println!(
                "  {} Use {} to see all transitive dependencies",
                "hint:".dimmed(),
                "--all".cyan()
            );
        }
    }

    Ok(())
}

/// Explain why a package is installed.
pub fn why(package: &str) -> Result<()> {
    use cratons_lockfile::{LOCKFILE_NAME, Lockfile};
    use std::collections::{HashMap, HashSet, VecDeque};

    let (manifest, _) = Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    // Load lockfile for dependency graph
    let lockfile_path = Path::new(LOCKFILE_NAME);
    let lockfile = Lockfile::load(lockfile_path)
        .map_err(|e| miette::miette!("Failed to load lockfile: {}", e))?;

    // Parse target package (format: name or ecosystem:name)
    let (target_ecosystem, target_name) = if let Some(pos) = package.find(':') {
        let eco_str = &package[..pos];
        let name = &package[pos + 1..];
        let ecosystem = match eco_str.to_lowercase().as_str() {
            "npm" => Some(Ecosystem::Npm),
            "pypi" | "pip" => Some(Ecosystem::PyPi),
            "cargo" | "crates" => Some(Ecosystem::Crates),
            "go" => Some(Ecosystem::Go),
            "maven" => Some(Ecosystem::Maven),
            _ => None,
        };
        (ecosystem, name.to_string())
    } else {
        (None, package.to_string())
    };

    // Find matching packages in lockfile
    let target_packages: Vec<_> = lockfile
        .packages
        .iter()
        .filter(|p| {
            let name_matches = p.name.to_lowercase() == target_name.to_lowercase();
            let eco_matches = target_ecosystem.map_or(true, |eco| p.ecosystem == eco);
            name_matches && eco_matches
        })
        .collect();

    if target_packages.is_empty() {
        println!(
            "{} Package {} not found in dependency graph",
            "!".yellow(),
            package.cyan()
        );
        return Ok(());
    }

    // Build reverse dependency graph (child -> parents)
    let mut reverse_deps: HashMap<(String, Ecosystem), Vec<(String, Ecosystem)>> = HashMap::new();

    for pkg in &lockfile.packages {
        for dep in &pkg.dependencies {
            reverse_deps
                .entry((dep.name.clone(), pkg.ecosystem))
                .or_default()
                .push((pkg.name.clone(), pkg.ecosystem));
        }
    }

    // Map direct dependencies from manifest
    let direct_deps: HashSet<(String, Ecosystem)> = manifest
        .dependencies
        .iter()
        .map(|(eco, name, _)| (name.to_string(), eco))
        .collect();

    println!(
        "\n{} Why is {} installed?\n",
        "?".blue().bold(),
        package.cyan().bold()
    );

    for target_pkg in &target_packages {
        let target_key = (target_pkg.name.clone(), target_pkg.ecosystem);

        // Check if it's a direct dependency
        if target_pkg.direct || direct_deps.contains(&target_key) {
            println!(
                "  {} {}:{} @ {}",
                "→".green(),
                target_pkg.ecosystem.to_string().dimmed(),
                target_pkg.name.cyan(),
                target_pkg.version
            );
            println!(
                "    └── {} {}",
                manifest.package.name.bold(),
                "(direct dependency)".green()
            );
            continue;
        }

        // BFS to find all paths from root to target
        let mut paths: Vec<Vec<(String, Ecosystem)>> = Vec::new();
        let mut queue: VecDeque<Vec<(String, Ecosystem)>> = VecDeque::new();
        queue.push_back(vec![target_key.clone()]);

        let max_paths = 5; // Limit paths to avoid explosion
        let max_depth = 20;

        while let Some(path) = queue.pop_front() {
            if paths.len() >= max_paths {
                break;
            }

            if path.len() > max_depth {
                continue;
            }

            let current = path.last().unwrap();

            // Check if we reached a direct dependency
            if direct_deps.contains(current) {
                paths.push(path.clone());
                continue;
            }

            // Get parents
            if let Some(parents) = reverse_deps.get(current) {
                for parent in parents {
                    // Avoid cycles
                    if !path.contains(parent) {
                        let mut new_path = path.clone();
                        new_path.push(parent.clone());
                        queue.push_back(new_path);
                    }
                }
            }
        }

        // Print the target package
        println!(
            "  {} {}:{} @ {}",
            "→".green(),
            target_pkg.ecosystem.to_string().dimmed(),
            target_pkg.name.cyan(),
            target_pkg.version
        );

        if paths.is_empty() {
            println!(
                "    └── {}",
                "(orphaned - no dependency path found)".yellow()
            );
        } else {
            for (i, path) in paths.iter().enumerate() {
                let is_last_path = i == paths.len() - 1;
                let prefix = if is_last_path { "└" } else { "├" };

                // Build the path string: root -> a -> b -> target
                let mut path_parts: Vec<String> = vec![manifest.package.name.bold().to_string()];

                // Reverse path (it's from target to root)
                for (name, eco) in path.iter().rev().skip(1) {
                    path_parts.push(format!("{}:{}", eco.to_string().dimmed(), name.cyan()));
                }

                println!("    {}── {}", prefix, path_parts.join(" → "));
            }

            if paths.len() == max_paths {
                println!(
                    "    ... {} more paths (truncated)",
                    "(and possibly".dimmed()
                );
            }
        }
    }

    // Summary
    let total_deps = lockfile.packages.len();
    let direct_count = lockfile.packages.iter().filter(|p| p.direct).count();
    println!();
    println!(
        "{} {} of {} total packages ({} direct)",
        "→".blue(),
        target_packages.len(),
        total_deps,
        direct_count
    );

    Ok(())
}

/// Show outdated dependencies.
pub fn outdated(offline: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().into_diagnostic()?;
    rt.block_on(outdated_async(offline))
}

async fn outdated_async(offline: bool) -> Result<()> {
    use cratons_resolver::registry::Registry;
    use semver::Version;

    let (manifest, _) = Manifest::find_and_load(".").map_err(|e| miette::miette!("{}", e))?;

    // Load lockfile for current versions
    let lockfile_path = Path::new(LOCKFILE_NAME);
    let lockfile = if lockfile_path.exists() {
        Some(
            Lockfile::load(lockfile_path)
                .map_err(|e| miette::miette!("Failed to load lockfile: {}", e))?,
        )
    } else {
        None
    };

    // Collect dependencies to check
    let mut deps_to_check: Vec<(cratons_core::Ecosystem, String, String, Option<String>)> =
        Vec::new();

    for (eco, name, dep) in manifest.dependencies.iter() {
        let wanted = dep.version().unwrap_or("*").to_string();
        let current = lockfile
            .as_ref()
            .and_then(|lf| lf.find_package(&name, eco))
            .map(|p| p.version.clone());
        deps_to_check.push((eco, name.to_string(), wanted, current));
    }

    if deps_to_check.is_empty() {
        println!("{} No dependencies to check", "!".yellow());
        return Ok(());
    }

    println!(
        "{} Checking {} dependencies for updates...",
        "→".blue(),
        deps_to_check.len()
    );

    if offline {
        println!(
            "{} Offline mode enabled (will fail if not cached)",
            "!".yellow()
        );
    }

    println!();

    // Create registry
    let registry = Registry::with_defaults(offline)
        .map_err(|e| miette::miette!("Failed to create registry client: {}", e))?;

    // Table header
    println!(
        "{:<30} {:<12} {:<12} {:<12} {:<10}",
        "Package".bold(),
        "Current".bold(),
        "Wanted".bold(),
        "Latest".bold(),
        "Status".bold()
    );
    println!("{}", "─".repeat(78));

    let mut outdated_count = 0;
    let mut major_updates = 0;
    let mut minor_updates = 0;
    let mut patch_updates = 0;

    for (ecosystem, name, wanted, current) in deps_to_check {
        // Fetch available versions from registry
        let latest = match registry.fetch_versions(ecosystem, &name).await {
            Ok(versions) => {
                // Filter to stable versions and get the latest
                let stable_versions: Vec<&String> = versions
                    .iter()
                    .filter(|v| {
                        // Filter out pre-release versions
                        !v.contains('-')
                            && !v.contains("alpha")
                            && !v.contains("beta")
                            && !v.contains("rc")
                    })
                    .collect();

                if stable_versions.is_empty() {
                    versions.first().cloned()
                } else {
                    // Sort by semver if possible
                    let mut sorted: Vec<_> = stable_versions
                        .into_iter()
                        .filter_map(|v| Version::parse(v).ok().map(|sv| (v, sv)))
                        .collect();
                    sorted.sort_by(|a, b| b.1.cmp(&a.1));
                    sorted.first().map(|(v, _)| (*v).clone())
                }
            }
            Err(e) => {
                println!(
                    "{:<30} {:<12} {:<12} {:<12} {}",
                    format!("{}:{}", ecosystem, name).cyan(),
                    current.as_deref().unwrap_or("-"),
                    &wanted,
                    "?",
                    format!("Error: {}", e).red()
                );
                continue;
            }
        };

        let latest_str = latest.as_deref().unwrap_or("unknown");
        let current_str = current.as_deref().unwrap_or("-");

        // Determine if outdated and update type
        let (status, is_outdated) = if let (Some(curr), Some(lat)) = (&current, &latest) {
            if let (Ok(curr_ver), Ok(lat_ver)) = (Version::parse(curr), Version::parse(lat)) {
                if lat_ver > curr_ver {
                    let update_type = if lat_ver.major > curr_ver.major {
                        major_updates += 1;
                        "major".red().to_string()
                    } else if lat_ver.minor > curr_ver.minor {
                        minor_updates += 1;
                        "minor".yellow().to_string()
                    } else {
                        patch_updates += 1;
                        "patch".green().to_string()
                    };
                    (update_type, true)
                } else {
                    ("✓".green().to_string(), false)
                }
            } else {
                // Can't parse versions, do string comparison
                if curr != lat {
                    ("update".yellow().to_string(), true)
                } else {
                    ("✓".green().to_string(), false)
                }
            }
        } else if current.is_none() {
            ("not installed".dimmed().to_string(), false)
        } else {
            ("✓".green().to_string(), false)
        };

        if is_outdated {
            outdated_count += 1;
        }

        // Print row
        let pkg_display = format!("{}:{}", ecosystem, name);
        println!(
            "{:<30} {:<12} {:<12} {:<12} {}",
            if is_outdated {
                pkg_display.yellow().to_string()
            } else {
                pkg_display
            },
            current_str,
            &wanted,
            latest_str,
            status
        );
    }

    println!("{}", "─".repeat(78));
    println!();

    if outdated_count == 0 {
        println!("{} All dependencies are up to date!", "✓".green());
    } else {
        println!(
            "{} {} outdated {} found",
            "!".yellow(),
            outdated_count,
            if outdated_count == 1 {
                "dependency"
            } else {
                "dependencies"
            }
        );

        if major_updates > 0 || minor_updates > 0 || patch_updates > 0 {
            println!();
            println!(
                "  {} {} major, {} minor, {} patch updates available",
                "→".dimmed(),
                major_updates.to_string().red(),
                minor_updates.to_string().yellow(),
                patch_updates.to_string().green()
            );
        }

        println!();
        println!("Run {} to update dependencies", "cratons update".cyan());
    }

    Ok(())
}

/// Run security audit.
pub fn audit(fail_on: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().into_diagnostic()?;
    rt.block_on(audit_async(fail_on))
}

async fn audit_async(fail_on: &str) -> Result<()> {
    use cratons_security::{Auditor, Severity, policy::PolicyEngine};

    // Load lockfile (required for audit)
    let lockfile_path = Path::new(LOCKFILE_NAME);
    if !lockfile_path.exists() {
        return Err(miette::miette!(
            "No lockfile found. Run `cratons install` first."
        ));
    }

    let lockfile = Lockfile::load(lockfile_path)
        .map_err(|e| miette::miette!("Failed to load lockfile: {}", e))?;

    if lockfile.packages.is_empty() {
        println!("{} No packages to audit", "!".yellow());
        return Ok(());
    }

    // Check for policy file
    let policy_path = Path::new("policy.cedar");
    let policy = if policy_path.exists() {
        println!(
            "{} Loading security policy from {}",
            "→".blue(),
            policy_path.display()
        );
        Some(
            PolicyEngine::load(policy_path)
                .map_err(|e| miette::miette!("Failed to load policy: {}", e))?,
        )
    } else {
        None
    };

    println!(
        "{} Auditing {} packages...",
        "→".blue(),
        lockfile.package_count()
    );

    let auditor = Auditor::new();
    let result = auditor
        .audit(&lockfile)
        .await
        .map_err(|e| miette::miette!("Audit failed: {}", e))?;

    println!();

    // Check policy violations first if policy exists
    if let Some(ref p) = policy {
        // Run checks
        let violations = p
            .check(&lockfile, &result)
            .map_err(|e| miette::miette!("Policy check failed: {}", e))?;

        if !violations.is_empty() {
            println!("{} Policy violations found:", "!".red());
            for v in &violations {
                println!("  {} {}", "×".red(), v);
            }
            println!();
            return Err(miette::miette!(
                "Security policy check failed with {} violations",
                violations.len()
            ));
        } else {
            println!("{} Security policy check passed", "✓".green());
        }
    }

    if result.vulnerabilities.is_empty() {
        println!("{} No vulnerabilities found", "✓".green());
        println!("  Audited {} packages", result.packages_audited);
        return Ok(());
    }

    // Display vulnerabilities
    println!(
        "{} Found {} vulnerabilities",
        "!".red(),
        result.vulnerabilities.len()
    );
    println!();

    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    for vuln in &result.vulnerabilities {
        let (severity_str, _severity_color) = match vuln.severity {
            Severity::Critical => {
                critical_count += 1;
                ("CRITICAL".to_string(), "red")
            }
            Severity::High => {
                high_count += 1;
                ("HIGH".to_string(), "red")
            }
            Severity::Medium => {
                medium_count += 1;
                ("MEDIUM".to_string(), "yellow")
            }
            Severity::Low => {
                low_count += 1;
                ("LOW".to_string(), "blue")
            }
        };

        println!("  {} {}", severity_str.bold(), vuln.id);
        println!(
            "    {} {} ({})",
            "Package:".dimmed(),
            vuln.package,
            vuln.affected_versions
        );
        println!("    {} {}", "Title:".dimmed(), vuln.title);
        if let Some(ref fixed) = vuln.fixed_version {
            println!("    {} {}", "Fixed in:".dimmed(), fixed.green());
        }
        println!();
    }

    // Summary
    println!("  {} vulnerabilities found:", "Summary:".bold());
    if critical_count > 0 {
        println!("    {} critical", critical_count.to_string().red());
    }
    if high_count > 0 {
        println!("    {} high", high_count.to_string().red());
    }
    if medium_count > 0 {
        println!("    {} medium", medium_count.to_string().yellow());
    }
    if low_count > 0 {
        println!("    {} low", low_count.to_string().blue());
    }

    // Check if we should fail based on severity
    let fail_severity = match fail_on.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "none" => return Ok(()),
        _ => Severity::High, // default
    };

    let failing_vulns = result.vulnerabilities_above(fail_severity);
    if !failing_vulns.is_empty() {
        return Err(miette::miette!(
            "Found {} vulnerabilities at {} severity or above",
            failing_vulns.len(),
            fail_on
        ));
    }

    Ok(())
}

/// Run garbage collection.
pub fn gc(keep_days: u32) -> Result<()> {
    let store =
        Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

    println!(
        "{} Running garbage collection (keep {} days)...",
        "→".blue(),
        keep_days
    );

    let stats = store
        .gc(keep_days)
        .map_err(|e| miette::miette!("GC failed: {}", e))?;

    println!();
    println!(
        "{} Removed {} artifacts, {} files ({} bytes freed)",
        "✓".green(),
        stats.artifacts_removed,
        stats.files_removed,
        stats.bytes_freed
    );

    Ok(())
}

/// Show store info.
pub fn store_info() -> Result<()> {
    let store =
        Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

    println!("{} {}", "Location:".bold(), store.root().display());

    let cas_size = store
        .cas()
        .size()
        .map_err(|e| miette::miette!("Failed to get CAS size: {}", e))?;
    let cas_count = store
        .cas()
        .count()
        .map_err(|e| miette::miette!("Failed to get CAS count: {}", e))?;

    println!("{} {} files ({} bytes)", "CAS:".bold(), cas_count, cas_size);

    let artifacts = store
        .artifacts()
        .list()
        .map_err(|e| miette::miette!("Failed to list artifacts: {}", e))?;
    let artifacts_size = store
        .artifacts()
        .size()
        .map_err(|e| miette::miette!("Failed to get artifacts size: {}", e))?;

    println!(
        "{} {} artifacts ({} bytes)",
        "Artifacts:".bold(),
        artifacts.len(),
        artifacts_size
    );

    let toolchains = store
        .toolchains()
        .list()
        .map_err(|e| miette::miette!("Failed to list toolchains: {}", e))?;

    println!("{} {} installed", "Toolchains:".bold(), toolchains.len());

    Ok(())
}

/// List store artifacts.
pub fn store_list() -> Result<()> {
    let store =
        Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

    let artifacts = store
        .artifacts()
        .list()
        .map_err(|e| miette::miette!("Failed to list artifacts: {}", e))?;

    if artifacts.is_empty() {
        println!("No artifacts in store");
        return Ok(());
    }

    println!(
        "{:<40} {:<20} {:<20}",
        "Hash".bold(),
        "Package".bold(),
        "Built".bold()
    );
    println!("{}", "─".repeat(80));

    for artifact in artifacts {
        println!(
            "{:<40} {:<20} {:<20}",
            artifact.manifest.input_hash.short(),
            format!(
                "{}@{}",
                artifact.manifest.package, artifact.manifest.version
            ),
            artifact.manifest.built_at.format("%Y-%m-%d %H:%M")
        );
    }

    Ok(())
}

/// Remove artifact from store.
pub fn store_remove(hash: &str) -> Result<()> {
    let store =
        Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

    let content_hash = cratons_core::ContentHash::parse(hash)
        .map_err(|e| miette::miette!("Invalid hash: {}", e))?;

    let removed = store
        .artifacts()
        .remove(&content_hash)
        .map_err(|e| miette::miette!("Failed to remove artifact: {}", e))?;

    if removed {
        println!("{} Removed artifact {}", "✓".green(), hash);
    } else {
        println!("{} Artifact not found: {}", "!".yellow(), hash);
    }

    Ok(())
}

/// Generate shell completions.
pub fn completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    let mut cmd = super::Cli::command();
    clap_complete::generate(shell, &mut cmd, "cratons", &mut std::io::stdout());
}

// ============================================================================
// Remote Cache Commands
// ============================================================================

/// Show remote cache configuration.
pub fn cache_info() -> Result<()> {
    use crate::config;

    println!("{}", "Remote Build Cache".bold());
    println!();

    let cfg = config::get();

    // Check for configuration from config file or environment
    if let Some(ref remote) = cfg.cache.remote {
        println!("{} {}", "Backend:".bold(), remote.backend_type);
        if let Some(ref url) = remote.url {
            println!("{} {}", "URL:".bold(), url);
        }
        if let Some(ref path) = remote.path {
            println!("{} {}", "Path:".bold(), path);
        }
        if let Some(ref region) = remote.region {
            println!("{} {}", "Region:".bold(), region);
        }
        if remote.token.is_some() {
            println!("{} (set)", "Token:".bold());
        } else {
            println!("{} (not set)", "Token:".bold().dimmed());
        }
        if let Some(ref read_only) = remote.read_only {
            if *read_only {
                println!("{} read-only", "Mode:".bold());
            }
        }
    } else {
        println!("{} Remote cache not configured", "!".yellow());
        println!();
        println!("Configure with a config file:");
        println!(
            "  {} (project)",
            "cratons.toml [config.cache.remote]".cyan()
        );
        println!("  {} (user)", "~/.config/cratons/config.toml".cyan());
        println!();
        println!("Or environment variables:");
        println!("  {} - Cache backend URL", "CRATONS_CACHE_URL".cyan());
        println!("  {} - Authentication token", "CRATONS_CACHE_TOKEN".cyan());
        println!();
        println!("Or use:");
        println!(
            "  {} --backend s3 --url s3://bucket/prefix",
            "cratons cache config".cyan()
        );
        println!(
            "  {} --backend filesystem --url /path/to/cache",
            "cratons cache config".cyan()
        );
    }

    Ok(())
}

/// Push artifacts to remote cache.
pub fn cache_push(all: bool, hash: Option<&str>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().into_diagnostic()?;
    rt.block_on(cache_push_async(all, hash))
}

async fn cache_push_async(all: bool, hash: Option<&str>) -> Result<()> {
    use crate::config;
    use cratons_store::RemoteCache;

    let store =
        Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

    // Get remote cache configuration from config system
    let cfg = config::get();
    let remote_config = cfg.to_store_remote_config()
        .ok_or_else(|| miette::miette!(
            "Remote cache not configured. Set CRATONS_CACHE_URL or configure in ~/.config/cratons/config.toml"
        ))?;

    println!("{} Connecting to remote cache...", "→".blue());

    let remote_cache = RemoteCache::new(vec![remote_config], store.artifacts().clone())
        .map_err(|e| miette::miette!("Failed to connect to remote cache: {}", e))?;

    if let Some(hash_str) = hash {
        // Push specific artifact
        let content_hash = cratons_core::ContentHash::parse(hash_str)
            .map_err(|e| miette::miette!("Invalid hash: {}", e))?;

        println!(
            "{} Pushing artifact {}...",
            "→".blue(),
            content_hash.short()
        );

        let count = remote_cache
            .push(&content_hash)
            .await
            .map_err(|e| miette::miette!("Failed to push artifact: {}", e))?;

        if count > 0 {
            println!(
                "{} Pushed {} to {} backend(s)",
                "✓".green(),
                content_hash.short(),
                count
            );
        } else {
            println!(
                "{} Artifact not found or no writable backends available",
                "!".yellow()
            );
        }
    } else if all {
        // Push all artifacts
        let artifacts = store
            .artifacts()
            .list()
            .map_err(|e| miette::miette!("Failed to list artifacts: {}", e))?;

        if artifacts.is_empty() {
            println!("{} No local artifacts to push", "!".yellow());
            return Ok(());
        }

        println!(
            "{} Pushing {} artifacts to remote cache...",
            "→".blue(),
            artifacts.len()
        );

        let (pushed, failed) = remote_cache
            .push_all()
            .await
            .map_err(|e| miette::miette!("Failed to push artifacts: {}", e))?;

        println!();
        if failed == 0 {
            println!("{} Pushed {} artifacts", "✓".green(), pushed);
        } else {
            println!(
                "{} Pushed {} artifacts, {} failed",
                "!".yellow(),
                pushed,
                failed
            );
        }
    } else {
        // No args - show help
        println!(
            "{} No artifacts specified. Use --all to push all artifacts or --hash <HASH>",
            "!".yellow()
        );
    }

    Ok(())
}

/// Fetch artifact from remote cache.
pub fn cache_fetch(hash: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().into_diagnostic()?;
    rt.block_on(cache_fetch_async(hash))
}

async fn cache_fetch_async(hash: &str) -> Result<()> {
    use crate::config;
    use cratons_store::RemoteCache;

    let store =
        Store::open_default().map_err(|e| miette::miette!("Failed to open store: {}", e))?;

    // Get remote cache configuration from config system
    let cfg = config::get();
    let remote_config = cfg.to_store_remote_config()
        .ok_or_else(|| miette::miette!(
            "Remote cache not configured. Set CRATONS_CACHE_URL or configure in ~/.config/cratons/config.toml"
        ))?;

    let content_hash = cratons_core::ContentHash::parse(hash)
        .map_err(|e| miette::miette!("Invalid hash: {}", e))?;

    println!(
        "{} Fetching artifact {} from remote cache...",
        "→".blue(),
        content_hash.short()
    );

    let remote_cache = RemoteCache::new(vec![remote_config], store.artifacts().clone())
        .map_err(|e| miette::miette!("Failed to connect to remote cache: {}", e))?;

    match remote_cache.fetch(&content_hash).await {
        Ok(Some(path)) => {
            println!("{} Fetched artifact to {}", "✓".green(), path.display());
        }
        Ok(None) => {
            println!(
                "{} Artifact {} not found in remote cache",
                "!".yellow(),
                content_hash.short()
            );
        }
        Err(e) => {
            return Err(miette::miette!("Failed to fetch artifact: {}", e));
        }
    }

    Ok(())
}

/// Configure remote cache.
pub fn cache_config(backend: Option<&str>, url: Option<&str>, show: bool) -> Result<()> {
    if show {
        // Show current configuration
        return cache_info();
    }

    match (backend, url) {
        (Some(backend_type), Some(backend_url)) => {
            println!("{} Configuring remote cache...", "→".blue());
            println!();
            println!("  {} {}", "Backend:".bold(), backend_type);
            println!("  {} {}", "URL:".bold(), backend_url);
            println!();

            // Validate backend type
            match backend_type {
                "s3" | "filesystem" | "http" => {}
                _ => {
                    return Err(miette::miette!(
                        "Unknown backend type: {}. Use: s3, filesystem, or http",
                        backend_type
                    ));
                }
            }

            // Generate config
            let config_snippet = match backend_type {
                "s3" => {
                    format!(
                        r#"# Add to cratons.toml [config] section or ~/.config/cratons/config.toml
[cache.remote]
type = "s3"
url = "{}"
# region = "us-east-1"
# path_style = false"#,
                        backend_url
                    )
                }
                "filesystem" => {
                    format!(
                        r#"# Add to cratons.toml [config] section or ~/.config/cratons/config.toml
[cache.remote]
type = "filesystem"
path = "{}""#,
                        backend_url
                    )
                }
                "http" => {
                    format!(
                        r#"# Add to cratons.toml [config] section or ~/.config/cratons/config.toml
[cache.remote]
type = "http"
url = "{}""#,
                        backend_url
                    )
                }
                _ => unreachable!(),
            };

            println!("{}", "Configuration snippet:".bold());
            println!();
            println!("{}", config_snippet.dimmed());
            println!();
            println!("{} Or set environment variables:", "Tip:".cyan());
            println!("  export CRATONS_CACHE_URL={}", backend_url);

            Ok(())
        }
        (None, None) => {
            // No arguments - show help
            println!("{}", "Remote Cache Configuration".bold());
            println!();
            println!("Usage:");
            println!(
                "  {} --backend <TYPE> --url <URL>",
                "cratons cache config".cyan()
            );
            println!();
            println!("Backend types:");
            println!("  {} - AWS S3, MinIO, Cloudflare R2, etc.", "s3".cyan());
            println!("  {} - Local or network filesystem", "filesystem".cyan());
            println!("  {} - Read-only HTTP cache", "http".cyan());
            println!();
            println!("Examples:");
            println!("  cratons cache config --backend s3 --url s3://my-bucket/cratons-cache");
            println!("  cratons cache config --backend filesystem --url /shared/cratons-cache");
            println!("  cratons cache config --backend http --url https://cache.example.com");

            Ok(())
        }
        _ => Err(miette::miette!("Both --backend and --url are required")),
    }
}
