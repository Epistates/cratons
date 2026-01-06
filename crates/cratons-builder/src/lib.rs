//! # cratons-builder
//!
//! Isolated build execution via youki for the Cratons package manager.
//!
//! This crate provides hermetic build isolation using OCI containers,
//! ensuring reproducible builds with no network access and controlled inputs.

#![warn(missing_docs)]

pub mod config;
pub mod executor;
pub mod graph;
pub mod rootfs;
pub mod spec;

pub use config::BuildConfig;
pub use executor::BuildExecutor;
pub use graph::{BuildGraph, BuildNode, BuildOrchestrator};
pub use spec::OciSpecBuilder;

use cratons_core::{ContentHash, Result};
use cratons_store::Store;
use std::path::Path;

/// Build a project using isolated containers.
pub async fn build(store: &Store, config: &BuildConfig, source_dir: &Path) -> Result<BuildResult> {
    let executor = BuildExecutor::new(store);
    executor.build(config, source_dir).await
}

/// Result of a build operation.
#[derive(Debug, Clone)]
pub struct BuildResult {
    /// Hash of the build inputs
    pub input_hash: ContentHash,
    /// Hash of the build outputs
    pub output_hash: ContentHash,
    /// Path to the output artifacts
    pub output_path: std::path::PathBuf,
    /// Build duration in seconds
    pub duration_secs: f64,
    /// Whether the build was cached
    pub cached: bool,
}

impl BuildResult {
    /// Check if this build succeeded.
    #[must_use]
    pub fn success(&self) -> bool {
        self.output_path.exists()
    }
}
