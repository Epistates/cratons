//! # cratons-store
//!
//! Content-addressable storage for the Cratons package manager.
//!
//! This crate implements a global store where all package artifacts are stored
//! by their content hash. It uses hard links (or reflinks/symlinks as fallback)
//! to efficiently share files across projects.
//!
//! ## Architecture
//!
//! ```text
//! ~/.cratons/
//! ├── store/v1/
//! │   ├── files/           # Individual files by hash
//! │   │   ├── 00/
//! │   │   │   └── 00a1b2c3...
//! │   │   └── ...
//! │   └── artifacts/       # Built package artifacts
//! │       └── sha256-xxx/
//! │           ├── manifest.json
//! │           └── ...
//! ├── cache/               # Download cache
//! └── toolchains/          # Pinned toolchains
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod artifact;
pub mod cas;
pub mod config;
pub mod download;
pub mod extract;
pub mod gc;
pub mod link;
pub mod registry_cache;
pub mod remote;
pub mod toolchain;
pub mod verify;

pub use artifact::{Artifact, ArtifactManifest, ArtifactStore};
pub use cas::ContentAddressableStore;
pub use config::StoreConfig;
pub use download::{ToolchainDownloader, ToolchainEcosystem, ToolchainRequest};
pub use gc::GarbageCollector;
pub use link::LinkStrategy;
pub use registry_cache::{
    CacheStats, CachedMetadata, CachedPeerDepMeta, CachedVersions, RegistryCache,
};
pub use remote::{RemoteCache, RemoteCacheBackend, RemoteCacheConfig};
pub use toolchain::{Toolchain, ToolchainStore};

use cratons_core::{ContentHash, Result};
use std::path::{Path, PathBuf};

/// The main store handle for Cratons.
pub struct Store {
    /// Root directory for the store
    root: PathBuf,
    /// Content-addressable file store
    cas: ContentAddressableStore,
    /// Artifact store
    artifacts: artifact::ArtifactStore,
    /// Toolchain store
    toolchains: ToolchainStore,
    /// Registry metadata cache
    registry_cache: RegistryCache,
    /// Store configuration
    config: StoreConfig,
}

impl Store {
    /// Open or create a store at the default location (~/.cratons).
    pub fn open_default() -> Result<Self> {
        let root = Self::default_root()?;
        Self::open(root)
    }

    /// Open or create a store at the specified location.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let config = StoreConfig::load_or_default(&root)?;

        // Ensure directory structure exists
        std::fs::create_dir_all(root.join("store/v1/files"))?;
        std::fs::create_dir_all(root.join("store/v1/artifacts"))?;
        std::fs::create_dir_all(root.join("cache/registry"))?;
        std::fs::create_dir_all(root.join("cache/sources"))?;
        std::fs::create_dir_all(root.join("toolchains"))?;

        let cas = ContentAddressableStore::new(root.join("store/v1/files"));
        let artifacts = artifact::ArtifactStore::new(root.join("store/v1/artifacts"));
        let toolchains = ToolchainStore::new(root.join("toolchains"));
        let registry_cache = RegistryCache::new(root.join("cache/registry"))?;

        Ok(Self {
            root,
            cas,
            artifacts,
            toolchains,
            registry_cache,
            config,
        })
    }

    /// Get the default store root directory.
    pub fn default_root() -> Result<PathBuf> {
        dirs::home_dir().map(|h| h.join(".cratons")).ok_or_else(|| {
            cratons_core::CratonsError::Config("Could not determine home directory".into())
        })
    }

    /// Get the store root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get the CAS (content-addressable store).
    #[must_use]
    pub fn cas(&self) -> &ContentAddressableStore {
        &self.cas
    }

    /// Get the artifact store.
    #[must_use]
    pub fn artifacts(&self) -> &artifact::ArtifactStore {
        &self.artifacts
    }

    /// Get the toolchain store.
    #[must_use]
    pub fn toolchains(&self) -> &ToolchainStore {
        &self.toolchains
    }

    /// Get the cache directory for downloaded sources.
    #[must_use]
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache/sources")
    }

    /// Get the registry cache directory.
    #[must_use]
    pub fn registry_cache_dir(&self) -> PathBuf {
        self.root.join("cache/registry")
    }

    /// Get the registry metadata cache.
    #[must_use]
    pub fn registry_cache(&self) -> &RegistryCache {
        &self.registry_cache
    }

    /// Store a file by content hash.
    pub fn store_file(&self, content: &[u8]) -> Result<ContentHash> {
        self.cas.store(content)
    }

    /// Retrieve a file by content hash.
    pub fn get_file(&self, hash: &ContentHash) -> Option<PathBuf> {
        self.cas.get(hash)
    }

    /// Store an artifact (built package output).
    pub fn store_artifact(
        &self,
        manifest: &ArtifactManifest,
        output_dir: &Path,
    ) -> Result<ContentHash> {
        self.artifacts.store(manifest, output_dir)
    }

    /// Get an artifact by input hash.
    pub fn get_artifact(&self, input_hash: &ContentHash) -> Option<PathBuf> {
        self.artifacts.get(input_hash)
    }

    /// Run garbage collection.
    pub fn gc(&self, keep_days: u32) -> Result<gc::GcStats> {
        let collector = GarbageCollector::new(self);
        collector.run(keep_days)
    }

    /// Get the store configuration.
    #[must_use]
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }
}
