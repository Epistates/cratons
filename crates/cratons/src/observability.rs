//! Observability configuration and initialization for Cratons.
//!
//! This module provides a unified interface for configuring logging, tracing,
//! and other observability features. It follows the patterns established by
//! youki and other production Rust projects.
//!
//! # Features
//!
//! - Configurable log levels (trace, debug, info, warn, error)
//! - Multiple output formats (text for human, JSON for machine processing)
//! - Optional file logging
//! - Environment variable overrides via RUST_LOG
//!
//! # Example
//!
//! ```ignore
//! use cratons::observability::{ObservabilityConfig, init};
//!
//! let config = ObservabilityConfig {
//!     log_level: Some("debug".to_string()),
//!     log_format: Some("json".to_string()),
//!     ..Default::default()
//! };
//! init(config)?;
//! ```

use miette::{Result, miette};
use std::borrow::Cow;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

// OTel imports
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::Resource;

/// Default log level for debug builds.
#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: &str = "debug";

/// Default log level for release builds.
#[cfg(not(debug_assertions))]
const DEFAULT_LOG_LEVEL: &str = "info";

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable text format (default).
    #[default]
    Text,
    /// JSON format for structured logging.
    Json,
}

impl FromStr for LogFormat {
    type Err = miette::Report;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "text" | "plain" | "human" => Ok(Self::Text),
            "json" | "structured" => Ok(Self::Json),
            other => Err(miette!(
                "invalid log format '{}': expected 'text' or 'json'",
                other
            )),
        }
    }
}

/// Configuration for observability features.
#[derive(Debug, Default)]
pub struct ObservabilityConfig {
    /// Whether the debug flag was passed (legacy, prefer log_level).
    pub debug_flag: bool,
    /// Whether the verbose flag was passed (shorthand for debug).
    pub verbose_flag: bool,
    /// Whether the quiet flag was passed (shorthand for error only).
    pub quiet_flag: bool,
    /// Explicit log level (overrides flags).
    pub log_level: Option<String>,
    /// Path to a log file (in addition to stderr).
    pub log_file: Option<PathBuf>,
    /// Log format: "text" or "json".
    pub log_format: Option<String>,
}

impl ObservabilityConfig {
    /// Create a new config from CLI flags.
    pub fn from_flags(verbose: bool, quiet: bool) -> Self {
        Self {
            verbose_flag: verbose,
            quiet_flag: quiet,
            ..Default::default()
        }
    }

    /// Set the log level.
    #[allow(dead_code)]
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = Some(level.into());
        self
    }

    /// Set the log format.
    #[allow(dead_code)]
    pub fn with_log_format(mut self, format: impl Into<String>) -> Self {
        self.log_format = Some(format.into());
        self
    }

    /// Set the log file path.
    #[allow(dead_code)]
    pub fn with_log_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_file = Some(path.into());
        self
    }
}

/// Detect the effective log level from configuration.
fn detect_log_level(config: &ObservabilityConfig) -> Result<Level> {
    let log_level: Cow<str> = match &config.log_level {
        Some(level) => level.as_str().into(),
        None if config.quiet_flag => "error".into(),
        None if config.verbose_flag || config.debug_flag => "debug".into(),
        None => DEFAULT_LOG_LEVEL.into(),
    };

    Level::from_str(log_level.as_ref()).map_err(|_| {
        miette!(
            "invalid log level '{}': expected trace, debug, info, warn, or error",
            log_level
        )
    })
}

/// Detect the log format from configuration.
fn detect_log_format(format: Option<&str>) -> Result<LogFormat> {
    match format {
        Some(f) => LogFormat::from_str(f),
        None => Ok(LogFormat::default()),
    }
}

/// Initialize the observability stack.
pub fn init(config: ObservabilityConfig) -> Result<()> {
    let level = detect_log_level(&config)?;
    let format = detect_log_format(config.log_format.as_deref())?;

    // Create the base filter
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));

    let registry = tracing_subscriber::registry().with(filter);

    // Configure OpenTelemetry if enabled
    let otel_layer = if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .build()
            .map_err(|e| miette!("failed to build otel exporter: {}", e))?;

        let resource = Resource::builder()
            .with_service_name("cratons")
            .with_attribute(opentelemetry::KeyValue::new(
                "service.version",
                env!("CARGO_PKG_VERSION"),
            ))
            .build();

        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();

        global::set_tracer_provider(provider.clone());

        Some(tracing_opentelemetry::layer().with_tracer(provider.tracer("cratons")))
    } else {
        None
    };

    let registry = registry.with(otel_layer);

    match (config.log_file.as_ref(), format) {
        // Text to stderr (most common case)
        (None, LogFormat::Text) => {
            registry
                .with(
                    fmt::layer()
                        .with_target(false)
                        .without_time()
                        .with_writer(std::io::stderr),
                )
                .try_init()
                .map_err(|e| miette!("failed to initialize logger: {}", e))?;
        }

        // JSON to stderr
        (None, LogFormat::Json) => {
            registry
                .with(
                    fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_span_list(false)
                        .with_writer(std::io::stderr),
                )
                .try_init()
                .map_err(|e| miette!("failed to initialize logger: {}", e))?;
        }

        // Text to file
        (Some(path), LogFormat::Text) => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| miette!("failed to open log file '{}': {}", path.display(), e))?;

            registry
                .with(fmt::layer().with_writer(file))
                .try_init()
                .map_err(|e| miette!("failed to initialize logger: {}", e))?;
        }

        // JSON to file
        (Some(path), LogFormat::Json) => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| miette!("failed to open log file '{}': {}", path.display(), e))?;

            registry
                .with(
                    fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_span_list(false)
                        .with_writer(file),
                )
                .try_init()
                .map_err(|e| miette!("failed to initialize logger: {}", e))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_from_str() {
        assert_eq!(LogFormat::from_str("text").unwrap(), LogFormat::Text);
        assert_eq!(LogFormat::from_str("json").unwrap(), LogFormat::Json);
        assert_eq!(LogFormat::from_str("TEXT").unwrap(), LogFormat::Text);
        assert_eq!(LogFormat::from_str("JSON").unwrap(), LogFormat::Json);
        assert!(LogFormat::from_str("invalid").is_err());
    }

    #[test]
    fn test_config_builder() {
        let config = ObservabilityConfig::from_flags(true, false)
            .with_log_level("debug")
            .with_log_format("json");

        assert!(config.verbose_flag);
        assert!(!config.quiet_flag);
        assert_eq!(config.log_level, Some("debug".to_string()));
        assert_eq!(config.log_format, Some("json".to_string()));
    }

    #[test]
    fn test_detect_log_level() {
        let config = ObservabilityConfig {
            log_level: Some("warn".to_string()),
            ..Default::default()
        };
        assert_eq!(detect_log_level(&config).unwrap(), Level::WARN);

        let config = ObservabilityConfig {
            quiet_flag: true,
            ..Default::default()
        };
        assert_eq!(detect_log_level(&config).unwrap(), Level::ERROR);

        let config = ObservabilityConfig {
            verbose_flag: true,
            ..Default::default()
        };
        assert_eq!(detect_log_level(&config).unwrap(), Level::DEBUG);
    }
}
