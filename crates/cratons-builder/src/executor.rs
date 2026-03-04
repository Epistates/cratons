//! Build executor using cratons-sandbox for isolated execution.

use cratons_core::{CratonsError, HashAlgorithm, Hasher, Result};
use cratons_sandbox::{Mount, NetworkAccess, ResourceLimits, SandboxConfig, create_sandbox};
use cratons_store::{Store, artifact::ArtifactManifest, remote::RemoteCache};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;
use tracing::{debug, info, warn};

use crate::BuildResult;
use crate::config::BuildConfig;
use crate::rootfs::RootfsBuilder;

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
            // Load output_hash from the artifact manifest
            let output_hash = self
                .store
                .artifacts()
                .load(&input_hash)
                .ok()
                .flatten()
                .map(|artifact| {
                    // Compute hash from stored artifact directory for integrity
                    Hasher::hash_directory(HashAlgorithm::Blake3, &artifact.path)
                        .unwrap_or_else(|_| input_hash.clone())
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
                    // Compute output hash from fetched artifact
                    let output_hash = Hasher::hash_directory(HashAlgorithm::Blake3, &remote_path)
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

        // Create temporary build directory
        let build_dir = TempDir::new()?;
        let output_dir = build_dir.path().join("output");
        std::fs::create_dir_all(&output_dir)?;

        let container_store_root = PathBuf::from("/cratons_store");

        // Build rootfs
        let rootfs_builder = RootfsBuilder::new(self.store, &container_store_root);
        let rootfs_path = rootfs_builder
            .build(config, source_dir, build_dir.path())
            .await?;

        // Prepare Sandbox Configuration
        let sb_config = SandboxConfig::new(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            config.script.clone(),
        ])
        .with_workdir(PathBuf::from(&config.workdir))
        .with_envs(config.env.clone())
        .with_rootfs(rootfs_path.to_path_buf())
        .with_network(NetworkAccess::None) // SOTA: No network in builds
        .with_ro_mount(Mount::readonly(
            self.store.root().to_path_buf(),
            container_store_root,
        ))
        .with_rw_mount(Mount::readwrite(output_dir.clone(), PathBuf::from("/out")))
        .with_limits({
            let mut limits = ResourceLimits::for_build();
            limits.memory = config.memory_limit;
            if let Some(cpu) = config.cpu_limit {
                // Convert cpu float to shares (approx)
                limits.cpu_shares = Some((cpu * 1024.0) as u64);
            }
            // Set timeout from config
            if let Some(timeout_secs) = config.timeout_secs {
                limits.timeout = Some(std::time::Duration::from_secs(timeout_secs));
            }
            limits
        });

        // Execute Build in Sandbox
        let sandbox = create_sandbox();
        let result = sandbox
            .execute(&sb_config)
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

        // Hash and store outputs
        let output_hash = Hasher::hash_directory(HashAlgorithm::Blake3, &output_dir)?;

        let manifest = ArtifactManifest {
            input_hash: input_hash.clone(),
            package: config.package_name.clone(),
            version: config.package_version.clone(),
            built_at: chrono::Utc::now(),
            build_duration_secs: start.elapsed().as_secs_f64(),
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

        let stored_hash = self.store.store_artifact(&manifest, &output_dir)?;
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
}
