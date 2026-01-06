//! # cratons-manifest
//!
//! Manifest parsing and validation for the Cratons package manager.
//!
//! The manifest file (`cratons.toml`) defines:
//! - Package metadata
//! - Environment/toolchain requirements
//! - Dependencies across multiple ecosystems
//! - Build configuration
//! - Scripts

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dependency;
pub mod environment;
pub mod package;
pub mod parse;
pub mod scripts;
pub mod workspace;

pub use dependency::{Dependencies, Dependency, DependencySource};
pub use environment::Environment;
pub use package::Package;
pub use parse::Manifest;
pub use scripts::Scripts;
pub use workspace::WorkspaceConfig;

use cratons_core::Result;
use std::path::Path;

/// Load a manifest from a file path.
pub fn load(path: impl AsRef<Path>) -> Result<Manifest> {
    Manifest::load(path)
}

/// Find and load the manifest from the current or parent directories.
pub fn find_and_load(start: impl AsRef<Path>) -> Result<(Manifest, std::path::PathBuf)> {
    Manifest::find_and_load(start)
}
