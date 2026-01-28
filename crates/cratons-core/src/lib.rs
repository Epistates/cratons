//! # cratons-core
//!
//! Core types, traits, and utilities for the Cratons package manager.
//!
//! This crate provides the foundational abstractions used throughout Cratons:
//! - Content hashing (Blake3 and SHA-256)
//! - Ecosystem definitions (npm, `PyPI`, `crates.io`, etc.)
//! - Version types and requirements
//! - Package identifiers and specifications
//! - Input validation for security
//! - Error types

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ecosystem;
pub mod error;
pub mod events;
pub mod hash;
pub mod hash_normalization;
pub mod package;
pub mod validation;
pub mod version;

pub use ecosystem::{Ecosystem, ResolutionStrategy};
pub use error::{IoError, CratonsError, Result};
pub use events::BuildEvent;
pub use hash::{ContentHash, HashAlgorithm, Hasher};
pub use hash_normalization::normalize_checksum_format;
pub use package::{PackageId, PackageSpec};
pub use validation::{validate_package_name, validate_path_component, validate_version};
pub use version::{Version, VersionReq};
