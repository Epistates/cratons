//! # cratons-test-fixtures
//!
//! Comprehensive test fixtures, builders, mocks, and property-based testing
//! utilities for the Cratons package manager.
//!
//! This crate provides:
//! - Builder patterns for creating test data structures
//! - Pre-configured fixtures for common test scenarios
//! - Mock implementations of registries and caches
//! - Property-based testing strategies (proptest)
//! - WireMock helpers for HTTP testing
//!
//! ## Usage
//!
//! ```rust
//! use cratons_test_fixtures::builders::ManifestBuilder;
//! use cratons_core::Ecosystem;
//!
//! let manifest = ManifestBuilder::new("my-app")
//!     .version("1.0.0")
//!     .npm_dependency("lodash", "^4.17.0")
//!     .build();
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builders;
pub mod fixtures;
pub mod mocks;
pub mod proptest;

// Re-export commonly used items
pub use builders::{
    DependencyGraphBuilder, LockfileBuilder, ManifestBuilder, PackageBuilder, PackageSpecBuilder,
};
pub use fixtures::{
    SAMPLE_CRATES_METADATA, SAMPLE_NPM_METADATA, SAMPLE_PYPI_METADATA, lockfiles, manifests,
    packages, registry_responses,
};
pub use mocks::{MockRegistry, MockRemoteCache, WireMockExt};

// Re-export test dependencies for convenience
pub use fake;
pub use proptest as prop;
pub use tempfile;
pub use wiremock;
