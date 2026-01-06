//! Build Event Protocol (BEP) for observability.

use serde::Serialize;

/// Structured events emitted during the build lifecycle.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BuildEvent {
    /// The build process has started.
    BuildStarted {
        /// Total number of packages to build.
        total_packages: usize,
    },
    /// Started resolving a package's dependencies.
    PackageResolveStarted {
        /// The ecosystem of the package (e.g., "npm", "pypi").
        ecosystem: String,
        /// The name of the package.
        package: String,
    },
    /// Finished resolving a package.
    PackageResolveFinished {
        /// The ecosystem of the package.
        ecosystem: String,
        /// The name of the package.
        package: String,
        /// The resolved version.
        version: String,
        /// Whether the resolution was served from cache.
        cached: bool,
    },
    /// Started a specific build task (e.g., "compile", "link").
    BuildTaskStarted {
        /// The package being built.
        package: String,
        /// The name of the task.
        task: String,
    },
    /// Finished a build task.
    BuildTaskFinished {
        /// The package being built.
        package: String,
        /// The name of the task.
        task: String,
        /// Duration of the task in milliseconds.
        duration_ms: u64,
        /// Whether the task succeeded.
        success: bool,
    },
    /// A cache hit occurred.
    CacheHit {
        /// The hash of the artifact.
        hash: String,
        /// The size of the artifact in bytes.
        size: u64,
    },
    /// A cache miss occurred.
    CacheMiss {
        /// The hash that was requested.
        hash: String,
    },
    /// The entire build process finished.
    BuildFinished {
        /// Whether the build succeeded.
        success: bool,
        /// Total duration in milliseconds.
        duration_ms: u64,
    },
}

impl BuildEvent {
    /// Emit the event as a structured log.
    pub fn emit(&self) {
        // Emit as a structured log event with target "build_event"
        // This allows filtering logs to just events: RUST_LOG=build_event=info
        match serde_json::to_string(self) {
            Ok(json) => {
                tracing::info!(target: "build_event", event_json = %json, "event");
            }
            Err(e) => {
                tracing::error!("Failed to serialize build event: {}", e);
            }
        }
    }
}
