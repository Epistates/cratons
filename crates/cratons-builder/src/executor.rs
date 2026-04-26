//! Build executor using cratons-sandbox for isolated execution.

use cratons_core::{CratonsError, Result};
use cratons_sandbox::{
    IsolationLevel, Mount, NetworkAccess, ResourceLimits, SandboxConfig, create_sandbox,
};
use cratons_store::{
    LinkStrategy, Store,
    artifact::{ARTIFACT_MANIFEST_NAME, ArtifactManifest, hash_artifact_contents},
    remote::RemoteCache,
};
use glob::{MatchOptions, glob_with};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;
use tracing::{debug, info, warn};

use crate::BuildResult;
use crate::config::BuildConfig;
use crate::rootfs::RootfsBuilder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SandboxLayout {
    Container,
    Host,
}

#[derive(Debug)]
struct PreparedBuild {
    sandbox_config: SandboxConfig,
    host_workdir: PathBuf,
    output_dir: PathBuf,
}

/// Executor for running builds in isolated containers.
pub struct BuildExecutor<'a> {
    store: &'a Store,
    remote_cache: Option<Arc<RemoteCache>>,
    push_to_remote: bool,
}

impl<'a> BuildExecutor<'a> {
    /// Create a new build executor.
    #[must_use]
    pub fn new(store: &'a Store) -> Self {
        Self {
            store,
            remote_cache: None,
            push_to_remote: false,
        }
    }

    /// Set the remote cache for the executor.
    #[must_use]
    pub fn with_remote_cache(mut self, cache: Arc<RemoteCache>) -> Self {
        self.remote_cache = Some(cache);
        self
    }

    /// Enable pushing built artifacts to the remote cache.
    #[must_use]
    pub fn with_push_to_remote(mut self, push: bool) -> Self {
        self.push_to_remote = push;
        self
    }

    /// Execute a build.
    ///
    /// # Security
    ///
    /// This method validates the build configuration before execution to prevent:
    /// - Command injection via malformed scripts
    /// - Environment variable injection
    /// - Path traversal attacks
    pub async fn build(&self, config: &BuildConfig, source_dir: &Path) -> Result<BuildResult> {
        // SECURITY: Validate configuration before execution
        config.validate()?;

        let start = Instant::now();
        let input_hash = config.input_hash();

        // Check local artifact cache first
        if let Some(cached_path) = self.store.get_artifact(&input_hash) {
            info!("Local cache hit: {}", input_hash.short());
            let output_hash = self
                .store
                .artifacts()
                .load(&input_hash)
                .ok()
                .flatten()
                .map(|artifact| {
                    artifact.manifest.output_hash.clone().unwrap_or_else(|| {
                        hash_artifact_contents(&artifact.path)
                            .unwrap_or_else(|_| input_hash.clone())
                    })
                })
                .unwrap_or_else(|| input_hash.clone());
            return Ok(BuildResult {
                input_hash: input_hash.clone(),
                output_hash,
                output_path: cached_path,
                duration_secs: start.elapsed().as_secs_f64(),
                cached: true,
            });
        }

        // Check remote cache if configured
        if let Some(ref remote_cache) = self.remote_cache {
            match remote_cache.fetch(&input_hash).await {
                Ok(Some(remote_path)) => {
                    info!("Remote cache hit: {}", input_hash.short());
                    let output_hash = read_cached_output_hash(&remote_path)
                        .or_else(|_| hash_artifact_contents(&remote_path))
                        .unwrap_or_else(|_| input_hash.clone());
                    return Ok(BuildResult {
                        input_hash: input_hash.clone(),
                        output_hash,
                        output_path: remote_path,
                        duration_secs: start.elapsed().as_secs_f64(),
                        cached: true,
                    });
                }
                Ok(None) => {
                    debug!("Remote cache miss: {}", input_hash.short());
                }
                Err(e) => {
                    warn!("Remote cache check failed: {}. Proceeding with build.", e);
                }
            }
        }

        info!(
            "Building {}@{}",
            config.package_name, config.package_version
        );
        debug!("Input hash: {}", input_hash);

        let build_dir = TempDir::new()?;
        let sandbox = create_sandbox();
        let layout = match sandbox.isolation_level() {
            IsolationLevel::Container => SandboxLayout::Container,
            _ => SandboxLayout::Host,
        };
        let prepared = self
            .prepare_build(config, source_dir, build_dir.path(), layout)
            .await?;
        let result = sandbox
            .execute(&prepared.sandbox_config)
            .await
            .map_err(|e| CratonsError::BuildFailed(format!("Sandbox execution failed: {}", e)))?;

        if !result.success() {
            // Include stdout/stderr in error message for debugging
            return Err(CratonsError::BuildFailed(format!(
                "Build process exited with code {}
Stdout: {}
Stderr: {}",
                result.exit_code,
                result.stdout_str(),
                result.stderr_str()
            )));
        }

        capture_outputs(config, &prepared.host_workdir, &prepared.output_dir)?;

        // Hash and store outputs
        let output_hash = hash_artifact_contents(&prepared.output_dir)?;

        let manifest = ArtifactManifest {
            input_hash: input_hash.clone(),
            package: config.package_name.clone(),
            version: config.package_version.clone(),
            built_at: chrono::Utc::now(),
            build_duration_secs: start.elapsed().as_secs_f64(),
            output_hash: Some(output_hash.clone()),
            env: config
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            toolchains: config
                .toolchains
                .iter()
                .map(|t| (t.name.clone(), t.version.clone()))
                .collect(),
        };

        let stored_hash = self.store.store_artifact(&manifest, &prepared.output_dir)?;
        let output_path = self.store.get_artifact(&stored_hash).ok_or_else(|| {
            CratonsError::BuildFailed("Failed to retrieve stored artifact".into())
        })?;

        // Push to remote cache if configured
        if self.push_to_remote {
            if let Some(ref remote_cache) = self.remote_cache {
                match remote_cache.push(&input_hash).await {
                    Ok(count) => {
                        if count > 0 {
                            info!(
                                "Pushed artifact {} to {} remote cache(s)",
                                input_hash.short(),
                                count
                            );
                        }
                    }
                    Err(e) => {
                        warn!("Failed to push artifact to remote cache: {}", e);
                    }
                }
            }
        }

        let duration = start.elapsed().as_secs_f64();
        info!("Build completed in {:.2}s", duration);

        Ok(BuildResult {
            input_hash,
            output_hash,
            output_path,
            duration_secs: duration,
            cached: false,
        })
    }

    async fn prepare_build(
        &self,
        config: &BuildConfig,
        source_dir: &Path,
        work_dir: &Path,
        layout: SandboxLayout,
    ) -> Result<PreparedBuild> {
        let output_dir = work_dir.join("output");
        fs::create_dir_all(&output_dir)?;

        let store_reference_root = match layout {
            SandboxLayout::Container => PathBuf::from("/cratons_store"),
            SandboxLayout::Host => self.store.root().to_path_buf(),
        };
        let rootfs_builder = RootfsBuilder::new(self.store, &store_reference_root);
        let staged_root = rootfs_builder.build(config, source_dir, work_dir).await?;
        let host_workdir = resolve_host_workdir(&staged_root, &config.workdir)?;

        if layout == SandboxLayout::Host {
            let staged_out = staged_root.join("out");
            remove_existing_path(&staged_out)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&output_dir, &staged_out)?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(&output_dir, &staged_out)?;
        }

        let env = build_runtime_env(config, layout, &staged_root, &output_dir);
        let limits = build_resource_limits(config);

        let sandbox_config = match layout {
            SandboxLayout::Container => SandboxConfig::new(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                config.script.clone(),
            ])
            .with_workdir(PathBuf::from(&config.workdir))
            .with_envs(env)
            .with_rootfs(staged_root.clone())
            .with_network(NetworkAccess::None)
            .with_ro_mount(Mount::readonly(
                self.store.root().to_path_buf(),
                PathBuf::from("/cratons_store"),
            ))
            .with_rw_mount(Mount::readwrite(output_dir.clone(), PathBuf::from("/out")))
            .with_limits(limits),
            SandboxLayout::Host => {
                let sb_config = SandboxConfig::new(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    config.script.clone(),
                ])
                .with_workdir(host_workdir.clone())
                .with_envs(env)
                .with_network(NetworkAccess::None)
                .with_rw_mount(Mount::readwrite(staged_root.clone(), staged_root.clone()))
                .with_rw_mount(Mount::readwrite(output_dir.clone(), output_dir.clone()))
                .with_ro_mount(Mount::readonly(
                    self.store.root().to_path_buf(),
                    self.store.root().to_path_buf(),
                ))
                .with_limits(limits);

                sb_config
            }
        };

        Ok(PreparedBuild {
            sandbox_config,
            host_workdir,
            output_dir,
        })
    }
}

fn build_resource_limits(config: &BuildConfig) -> ResourceLimits {
    let mut limits = ResourceLimits::for_build();
    limits.memory = config.memory_limit;
    if let Some(cpu) = config.cpu_limit {
        limits.cpu_shares = Some((cpu * 1024.0) as u64);
    }
    if let Some(timeout_secs) = config.timeout_secs {
        limits.timeout = Some(std::time::Duration::from_secs(timeout_secs));
    }
    limits
}

fn resolve_host_workdir(staged_root: &Path, configured_workdir: &str) -> Result<PathBuf> {
    let relative = relative_path_from_absolute(configured_workdir)?;
    Ok(if relative.as_os_str().is_empty() {
        staged_root.to_path_buf()
    } else {
        staged_root.join(relative)
    })
}

fn relative_path_from_absolute(path: &str) -> Result<PathBuf> {
    let absolute = Path::new(path);
    let mut relative = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(CratonsError::InvalidConfig {
                    message: format!("Unsupported working directory component in '{}'", path),
                });
            }
        }
    }
    Ok(relative)
}

fn build_runtime_env(
    config: &BuildConfig,
    layout: SandboxLayout,
    staged_root: &Path,
    output_dir: &Path,
) -> HashMap<String, String> {
    let mut env = config.env.clone();

    let visible_src_dir = match layout {
        SandboxLayout::Container => PathBuf::from(&config.workdir),
        SandboxLayout::Host => resolve_host_workdir(staged_root, &config.workdir)
            .unwrap_or_else(|_| staged_root.to_path_buf()),
    };
    let visible_toolchain_dir = match layout {
        SandboxLayout::Container => PathBuf::from("/toolchain"),
        SandboxLayout::Host => staged_root.join("toolchain"),
    };
    let visible_deps_dir = match layout {
        SandboxLayout::Container => PathBuf::from("/deps"),
        SandboxLayout::Host => staged_root.join("deps"),
    };
    let visible_out_dir = match layout {
        SandboxLayout::Container => PathBuf::from("/out"),
        SandboxLayout::Host => output_dir.to_path_buf(),
    };

    env.insert(
        "CRATONS_SRC_DIR".to_string(),
        visible_src_dir.to_string_lossy().to_string(),
    );
    env.insert(
        "CRATONS_TOOLCHAIN_DIR".to_string(),
        visible_toolchain_dir.to_string_lossy().to_string(),
    );
    env.insert(
        "CRATONS_DEPS_DIR".to_string(),
        visible_deps_dir.to_string_lossy().to_string(),
    );
    env.insert(
        "CRATONS_OUT_DIR".to_string(),
        visible_out_dir.to_string_lossy().to_string(),
    );

    let mut path_entries = Vec::new();
    for toolchain in &config.toolchains {
        let host_toolchain_root = staged_root.join("toolchain").join(&toolchain.name);
        let visible_toolchain_root = visible_toolchain_dir.join(&toolchain.name);
        let mut found_candidate = false;
        for candidate in ["bin", "usr/bin", "usr/local/bin"] {
            if host_toolchain_root.join(candidate).exists() {
                let entry = visible_toolchain_root
                    .join(candidate)
                    .to_string_lossy()
                    .to_string();
                if !path_entries.contains(&entry) {
                    path_entries.push(entry);
                }
                found_candidate = true;
            }
        }

        if !found_candidate && host_toolchain_root.exists() {
            let entry = visible_toolchain_root.to_string_lossy().to_string();
            if !path_entries.contains(&entry) {
                path_entries.push(entry);
            }
        }
    }

    let base_path = env
        .get("PATH")
        .cloned()
        .unwrap_or_else(|| cratons_sandbox::runner::DEFAULT_PATH.to_string());
    if !path_entries.is_empty() {
        path_entries.push(base_path);
        env.insert("PATH".to_string(), path_entries.join(":"));
    } else {
        env.entry("PATH".to_string()).or_insert(base_path);
    }

    env
}

fn capture_outputs(config: &BuildConfig, workdir: &Path, output_dir: &Path) -> Result<()> {
    let options = MatchOptions {
        case_sensitive: true,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };

    let canonical_workdir = workdir.canonicalize().map_err(|e| {
        CratonsError::BuildFailed(format!(
            "Failed to canonicalize workdir '{}': {}",
            workdir.display(),
            e
        ))
    })?;

    for pattern in &config.outputs {
        if Path::new(pattern).is_absolute()
            || pattern
                .split(['/', '\\'])
                .any(|component| component == "..")
        {
            return Err(CratonsError::BuildFailed(format!(
                "Output pattern '{}' must be relative and must not contain '..'",
                pattern
            )));
        }
        let absolute_pattern = workdir.join(pattern);
        let pattern_string = absolute_pattern.to_string_lossy().to_string();
        for matched in glob_with(&pattern_string, options).map_err(|e| {
            CratonsError::BuildFailed(format!("Invalid output glob '{}': {}", pattern, e))
        })? {
            let matched = matched.map_err(|e| {
                CratonsError::BuildFailed(format!(
                    "Failed to read output path for pattern '{}': {}",
                    pattern, e
                ))
            })?;
            if !matched.exists() {
                continue;
            }
            let canonical_match = matched.canonicalize().map_err(|e| {
                CratonsError::BuildFailed(format!(
                    "Failed to canonicalize output path '{}': {}",
                    matched.display(),
                    e
                ))
            })?;
            if !canonical_match.starts_with(&canonical_workdir) {
                return Err(CratonsError::BuildFailed(format!(
                    "Output path '{}' escaped the build workspace after resolving symlinks",
                    matched.display()
                )));
            }
            copy_output_path(workdir, &canonical_workdir, &matched, output_dir)?;
        }
    }

    Ok(())
}

fn copy_output_path(
    workdir: &Path,
    canonical_workdir: &Path,
    source: &Path,
    output_dir: &Path,
) -> Result<()> {
    let relative = source.strip_prefix(workdir).map_err(|e| {
        CratonsError::BuildFailed(format!(
            "Output path '{}' escaped the build workspace: {}",
            source.display(),
            e
        ))
    })?;
    let destination = output_dir.join(relative);

    if source.is_dir() {
        if fs::symlink_metadata(&destination)
            .map(|metadata| !metadata.is_dir() || metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            remove_existing_path(&destination)?;
        }
        fs::create_dir_all(&destination)?;
        for entry in walkdir::WalkDir::new(source).follow_links(false) {
            let entry = entry?;
            let entry_relative = entry.path().strip_prefix(source).map_err(|e| {
                CratonsError::BuildFailed(format!(
                    "Failed to compute output relative path for '{}': {}",
                    entry.path().display(),
                    e
                ))
            })?;
            let target = destination.join(entry_relative);
            if entry.file_type().is_dir() {
                if fs::symlink_metadata(&target)
                    .map(|metadata| !metadata.is_dir() || metadata.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    remove_existing_path(&target)?;
                }
                fs::create_dir_all(&target)?;
            } else if entry.file_type().is_file() {
                remove_existing_path(&target)?;
                LinkStrategy::Copy.link_file(entry.path(), &target)?;
            } else if entry.file_type().is_symlink() {
                // SECURITY: A build script can plant symlinks pointing outside
                // the workspace (e.g. /etc/passwd or ../../host-secret). Resolve
                // the target through the entry's real location and reject any
                // link whose resolved target escapes the build workspace before
                // reproducing it in the artifact.
                let resolved = fs::canonicalize(entry.path()).map_err(|e| {
                    CratonsError::BuildFailed(format!(
                        "Failed to resolve output symlink '{}': {}",
                        entry.path().display(),
                        e
                    ))
                })?;
                if !resolved.starts_with(canonical_workdir) {
                    return Err(CratonsError::BuildFailed(format!(
                        "Output symlink '{}' resolves outside the build workspace",
                        entry.path().display()
                    )));
                }
                #[cfg(unix)]
                {
                    let link_target = fs::read_link(entry.path())?;
                    if link_target.is_absolute() {
                        return Err(CratonsError::BuildFailed(format!(
                            "Output symlink '{}' has absolute target '{}'; only relative \
                             intra-workspace links are allowed",
                            entry.path().display(),
                            link_target.display()
                        )));
                    }
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    remove_existing_path(&target)?;
                    std::os::unix::fs::symlink(link_target, &target)?;
                }
                #[cfg(windows)]
                {
                    remove_existing_path(&target)?;
                    if resolved.is_dir() {
                        LinkStrategy::Copy.link_directory(&resolved, &target)?;
                    } else {
                        LinkStrategy::Copy.link_file(&resolved, &target)?;
                    }
                }
            }
        }
    } else {
        remove_existing_path(&destination)?;
        LinkStrategy::Copy.link_file(source, &destination)?;
    }

    Ok(())
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
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn read_cached_output_hash(artifact_path: &Path) -> Result<cratons_core::ContentHash> {
    let manifest_path = artifact_path.join(ARTIFACT_MANIFEST_NAME);
    let manifest_json = fs::read_to_string(&manifest_path)?;
    let manifest: ArtifactManifest = serde_json::from_str(&manifest_json)?;
    manifest.output_hash.ok_or_else(|| {
        CratonsError::BuildFailed(format!(
            "Artifact manifest at {} does not contain an output hash",
            manifest_path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratons_core::{HashAlgorithm, Hasher};

    #[test]
    fn hash_artifact_contents_ignores_manifest() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("artifact.bin"), b"payload").unwrap();
        fs::write(
            temp.path().join(ARTIFACT_MANIFEST_NAME),
            b"{\"package\":\"x\"}",
        )
        .unwrap();

        let expected = Hasher::hash_directory(HashAlgorithm::Blake3, temp.path()).unwrap();
        let actual = hash_artifact_contents(temp.path()).unwrap();

        assert_ne!(expected, actual);

        let compare = tempfile::tempdir().unwrap();
        fs::write(compare.path().join("artifact.bin"), b"payload").unwrap();
        let compare_hash = Hasher::hash_directory(HashAlgorithm::Blake3, compare.path()).unwrap();
        assert_eq!(actual, compare_hash);
    }

    #[test]
    fn capture_outputs_preserves_relative_layout() {
        let workdir = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(workdir.path().join("dist/assets")).unwrap();
        fs::write(
            workdir.path().join("dist/assets/app.js"),
            b"console.log('ok');",
        )
        .unwrap();

        let mut config =
            BuildConfig::new("pkg".to_string(), "1.0.0".to_string(), "true".to_string());
        config.outputs = vec!["dist/**/*".to_string()];

        capture_outputs(&config, workdir.path(), output_dir.path()).unwrap();

        assert!(output_dir.path().join("dist/assets/app.js").exists());
    }

    #[test]
    fn capture_outputs_rejects_absolute_pattern() {
        let workdir = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let mut config =
            BuildConfig::new("pkg".to_string(), "1.0.0".to_string(), "true".to_string());
        config.outputs = vec!["/etc/passwd".to_string()];

        let result = capture_outputs(&config, workdir.path(), output_dir.path());
        assert!(matches!(result, Err(CratonsError::BuildFailed(_))));
    }

    #[test]
    fn capture_outputs_rejects_parent_dir_in_pattern() {
        let workdir = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let mut config =
            BuildConfig::new("pkg".to_string(), "1.0.0".to_string(), "true".to_string());
        config.outputs = vec!["../etc/passwd".to_string()];

        let result = capture_outputs(&config, workdir.path(), output_dir.path());
        assert!(matches!(result, Err(CratonsError::BuildFailed(_))));
    }

    #[cfg(unix)]
    #[test]
    fn capture_outputs_rejects_symlink_escape() {
        let workdir = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let escape_target = tempfile::tempdir().unwrap();
        fs::write(escape_target.path().join("secret.txt"), b"secret").unwrap();

        fs::create_dir_all(workdir.path().join("dist")).unwrap();
        std::os::unix::fs::symlink(
            escape_target.path(),
            workdir.path().join("dist").join("leak"),
        )
        .unwrap();

        let mut config =
            BuildConfig::new("pkg".to_string(), "1.0.0".to_string(), "true".to_string());
        config.outputs = vec!["dist/**/*".to_string()];

        let result = capture_outputs(&config, workdir.path(), output_dir.path());
        assert!(matches!(result, Err(CratonsError::BuildFailed(_))));
        assert!(!output_dir.path().join("dist/leak/secret.txt").exists());
    }
}
