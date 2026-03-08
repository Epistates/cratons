//! CLI configuration file support.
//!
//! Loads configuration from (in order of precedence, highest last):
//! 1. Defaults
//! 2. System config: `/etc/cratons/config.toml` (Unix only)
//! 3. User config: `~/.config/cratons/config.toml`
//! 4. Project config: `./cratons.toml` `[config]` section
//! 5. Environment variables (CRATONS_*)
//! 6. Corporate policy: `/etc/cratons/policy.toml` (wins all, keys are locked)
//!
//! Any key present in the corporate policy file is "locked" and cannot be
//! overridden by any other source. The corp config path can be overridden
//! via `CRATONS_CORP_CONFIG` env var (useful for CI/testing).
//!
//! # Example Configuration
//!
//! ```toml
//! # ~/.config/cratons/config.toml
//!
//! [cache]
//! dir = "~/.cache/cratons"
//!
//! [cache.remote]
//! type = "s3"
//! url = "s3://my-bucket/cratons-cache"
//! region = "us-east-1"
//!
//! [install]
//! concurrency = 8
//! run_scripts = true
//! strict_scripts = false
//!
//! [build]
//! memory_limit = 4294967296  # 4GB
//! timeout = 600
//! push_to_remote = false
//!
//! [security]
//! fail_on = "high"
//! strict_verification = false
//!
//! [telemetry]
//! enabled = false
//! endpoint = "http://localhost:4317"
//! ```

use cratons_resolver::registry::RegistryPolicyConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

/// Source of a configuration value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// Built-in defaults
    Default,
    /// System-wide config (`/etc/cratons/config.toml`)
    System,
    /// User config (`~/.config/cratons/config.toml`)
    User,
    /// Project config (`./cratons.toml` `[config]` section)
    Project,
    /// Environment variable override
    Env,
    /// Corporate policy (locked, cannot be overridden)
    Corp,
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::System => write!(f, "system"),
            Self::User => write!(f, "user"),
            Self::Project => write!(f, "project"),
            Self::Env => write!(f, "env"),
            Self::Corp => write!(f, "corp"),
        }
    }
}

/// CLI configuration loaded from config files and environment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Cache configuration
    pub cache: CacheConfig,
    /// Installation configuration
    pub install: InstallConfig,
    /// Build configuration
    pub build: BuildConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Telemetry configuration
    pub telemetry: TelemetryConfig,
    /// Registry overrides
    pub registries: HashMap<String, RegistryConfig>,
    /// Registry access policy
    pub registry_policy: RegistryPolicyConfig,
}

/// Cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Local cache directory
    pub dir: Option<PathBuf>,
    /// Remote cache configuration
    pub remote: Option<RemoteCacheConfig>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            dir: None,
            remote: None,
        }
    }
}

/// Remote cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteCacheConfig {
    /// Backend type: s3, http, filesystem
    #[serde(rename = "type")]
    pub backend_type: String,
    /// URL or path for the backend
    pub url: Option<String>,
    /// Path (for filesystem backend)
    pub path: Option<String>,
    /// AWS region (for S3)
    pub region: Option<String>,
    /// Authentication token
    pub token: Option<String>,
    /// Read-only mode
    pub read_only: Option<bool>,
}

/// Installation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InstallConfig {
    /// Number of parallel downloads
    pub concurrency: usize,
    /// Run post-install scripts
    pub run_scripts: bool,
    /// Fail if scripts fail
    pub strict_scripts: bool,
    /// Skip integrity checks
    pub skip_integrity: bool,
}

impl Default for InstallConfig {
    fn default() -> Self {
        Self {
            concurrency: 8,
            run_scripts: true,
            strict_scripts: false,
            skip_integrity: false,
        }
    }
}

/// Build configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BuildConfig {
    /// Default memory limit for builds (bytes)
    pub memory_limit: Option<u64>,
    /// Default CPU limit
    pub cpu_limit: Option<f64>,
    /// Default timeout (seconds)
    pub timeout: Option<u64>,
    /// Push artifacts to remote cache
    pub push_to_remote: bool,
    /// Maximum parallel builds
    pub max_parallel: usize,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            memory_limit: None,
            cpu_limit: None,
            timeout: Some(600),
            push_to_remote: false,
            max_parallel: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
        }
    }
}

/// Security configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Minimum severity to fail audit
    pub fail_on: String,
    /// Enable strict verification for toolchain downloads
    pub strict_verification: bool,
    /// Vulnerability IDs to ignore
    pub ignore_vulns: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            fail_on: "high".to_string(),
            strict_verification: false,
            ignore_vulns: Vec::new(),
        }
    }
}

/// Telemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Enable OpenTelemetry tracing
    pub enabled: bool,
    /// OTLP endpoint
    pub endpoint: Option<String>,
    /// Service name for traces
    pub service_name: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            service_name: "cratons".to_string(),
        }
    }
}

/// Registry override configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Override URL for the registry
    pub url: Option<String>,
    /// Authentication token
    pub token: Option<String>,
}

/// Configuration with provenance tracking and corporate locking.
pub struct ConfigWithProvenance {
    /// The resolved configuration
    pub config: Config,
    /// Keys that are locked by corporate policy
    pub locked_keys: HashSet<String>,
    /// Source of each key's value
    pub sources: HashMap<String, ConfigSource>,
}

impl Config {
    /// Load configuration from all sources.
    ///
    /// Sources are applied in order (last wins):
    /// 1. Defaults
    /// 2. System config (/etc/cratons/config.toml)
    /// 3. User config (~/.config/cratons/config.toml)
    /// 4. Project config (./cratons.toml `[config]` section)
    /// 5. Environment variable overrides
    /// 6. Corporate policy (wins all, locks keys)
    pub fn load() -> Self {
        Self::load_with_provenance().config
    }

    /// Load configuration with full provenance tracking.
    pub fn load_with_provenance() -> ConfigWithProvenance {
        let mut config = Self::default();
        let mut sources: HashMap<String, ConfigSource> = HashMap::new();

        // Track default keys
        let default_val = toml::to_string(&config)
            .ok()
            .and_then(|s| s.parse::<toml::Value>().ok())
            .unwrap_or(toml::Value::Table(toml::map::Map::new()));
        let default_keys = extract_present_keys(&default_val, "");
        for key in &default_keys {
            sources.insert(key.clone(), ConfigSource::Default);
        }

        // Load from system config (lowest file precedence)
        #[cfg(unix)]
        if let Some(system_config) = Self::load_file("/etc/cratons/config.toml") {
            if let Ok(raw) = std::fs::read_to_string("/etc/cratons/config.toml") {
                if let Ok(val) = raw.parse::<toml::Value>() {
                    for key in extract_present_keys(&val, "") {
                        sources.insert(key, ConfigSource::System);
                    }
                }
            }
            config = config.merge(system_config);
        }

        // Load from user config
        if let Some(user_config_path) = Self::user_config_path() {
            if let Some(user_config) = Self::load_file(&user_config_path) {
                if let Ok(raw) = std::fs::read_to_string(&user_config_path) {
                    if let Ok(val) = raw.parse::<toml::Value>() {
                        for key in extract_present_keys(&val, "") {
                            sources.insert(key, ConfigSource::User);
                        }
                    }
                }
                config = config.merge(user_config);
            }
        }

        // Load from project config ([config] section of cratons.toml)
        if let Some(project_config) = Self::load_project_config() {
            if let Ok(raw) = std::fs::read_to_string("cratons.toml") {
                if let Ok(manifest) = raw.parse::<toml::Value>() {
                    if let Some(config_section) = manifest.get("config") {
                        for key in extract_present_keys(config_section, "") {
                            sources.insert(key, ConfigSource::Project);
                        }
                    }
                }
            }
            config = config.merge(project_config);
        }

        // Apply environment variable overrides
        let env_keys = config.apply_env_overrides();
        for key in env_keys {
            sources.insert(key, ConfigSource::Env);
        }

        // Load corporate policy (wins all)
        let mut locked_keys = HashSet::new();
        if let Some(corp_path) = Self::corp_config_path() {
            if let Some(corp_config) = Self::load_file(&corp_path) {
                if let Ok(raw) = std::fs::read_to_string(&corp_path) {
                    if let Ok(val) = raw.parse::<toml::Value>() {
                        let corp_keys = extract_present_keys(&val, "");
                        for key in &corp_keys {
                            sources.insert(key.clone(), ConfigSource::Corp);
                        }
                        locked_keys = corp_keys;
                    }
                }
                config = config.merge(corp_config);
            }
        }

        ConfigWithProvenance {
            config,
            locked_keys,
            sources,
        }
    }

    /// Get the corporate policy config file path.
    pub fn corp_config_path() -> Option<PathBuf> {
        // Check env var override first (for CI/testing)
        if let Ok(path) = std::env::var("CRATONS_CORP_CONFIG") {
            let p = PathBuf::from(&path);
            if p.exists() {
                return Some(p);
            }
            return None;
        }

        // Platform-specific default
        #[cfg(unix)]
        {
            let path = PathBuf::from("/etc/cratons/policy.toml");
            if path.exists() {
                return Some(path);
            }
        }
        #[cfg(windows)]
        {
            let path = PathBuf::from(r"C:\ProgramData\cratons\policy.toml");
            if path.exists() {
                return Some(path);
            }
        }

        None
    }

    /// Get the user config file path.
    fn user_config_path() -> Option<PathBuf> {
        // Check CRATONS_CONFIG_PATH first
        if let Ok(path) = std::env::var("CRATONS_CONFIG_PATH") {
            return Some(PathBuf::from(path));
        }

        // Use XDG_CONFIG_HOME or default
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::home_dir()
                    .map(|h| h.join(".config"))
                    .unwrap_or_else(|| PathBuf::from(".config"))
            });

        Some(config_dir.join("cratons").join("config.toml"))
    }

    /// Load configuration from a TOML file.
    fn load_file<P: AsRef<Path>>(path: P) -> Option<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return None;
        }

        match std::fs::read_to_string(path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => Some(config),
                Err(e) => {
                    tracing::warn!("Failed to parse config file {}: {}", path.display(), e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Failed to read config file {}: {}", path.display(), e);
                None
            }
        }
    }

    /// Load `[config]` section from project cratons.toml.
    fn load_project_config() -> Option<Self> {
        let manifest_path = PathBuf::from("cratons.toml");
        if !manifest_path.exists() {
            return None;
        }

        let content = std::fs::read_to_string(&manifest_path).ok()?;
        let manifest: toml::Value = toml::from_str(&content).ok()?;

        // Extract [config] section if present
        let config_section = manifest.get("config")?;
        let config_str = toml::to_string(config_section).ok()?;
        toml::from_str(&config_str).ok()
    }

    /// Merge another config into this one (other takes precedence).
    fn merge(mut self, other: Self) -> Self {
        // Cache
        if other.cache.dir.is_some() {
            self.cache.dir = other.cache.dir;
        }
        if other.cache.remote.is_some() {
            self.cache.remote = other.cache.remote;
        }

        // Install
        self.install.concurrency = other.install.concurrency;
        self.install.run_scripts = other.install.run_scripts;
        self.install.strict_scripts = other.install.strict_scripts;
        self.install.skip_integrity = other.install.skip_integrity;

        // Build
        if other.build.memory_limit.is_some() {
            self.build.memory_limit = other.build.memory_limit;
        }
        if other.build.cpu_limit.is_some() {
            self.build.cpu_limit = other.build.cpu_limit;
        }
        if other.build.timeout.is_some() {
            self.build.timeout = other.build.timeout;
        }
        self.build.push_to_remote = other.build.push_to_remote;
        self.build.max_parallel = other.build.max_parallel;

        // Security
        self.security.fail_on = other.security.fail_on;
        self.security.strict_verification = other.security.strict_verification;
        if !other.security.ignore_vulns.is_empty() {
            self.security.ignore_vulns = other.security.ignore_vulns;
        }

        // Telemetry
        self.telemetry.enabled = other.telemetry.enabled;
        if other.telemetry.endpoint.is_some() {
            self.telemetry.endpoint = other.telemetry.endpoint;
        }
        self.telemetry.service_name = other.telemetry.service_name;

        // Registries
        self.registries.extend(other.registries);

        // Registry policy
        if other.registry_policy.default.is_some() {
            self.registry_policy.default = other.registry_policy.default;
        }
        if !other.registry_policy.allow.is_empty() {
            self.registry_policy.allow = other.registry_policy.allow;
        }
        if !other.registry_policy.block.is_empty() {
            self.registry_policy.block = other.registry_policy.block;
        }
        if !other.registry_policy.access.is_empty() {
            self.registry_policy
                .access
                .extend(other.registry_policy.access);
        }

        self
    }

    /// Apply environment variable overrides. Returns the keys that were set.
    fn apply_env_overrides(&mut self) -> Vec<String> {
        let mut set_keys = Vec::new();

        // Cache
        if let Ok(dir) = std::env::var("CRATONS_CACHE_DIR") {
            self.cache.dir = Some(PathBuf::from(dir));
            set_keys.push("cache.dir".to_string());
        }

        // Remote cache from env
        if let Ok(url) = std::env::var("CRATONS_CACHE_URL") {
            let backend_type = if url.starts_with("s3://") {
                "s3"
            } else if url.starts_with("http://") || url.starts_with("https://") {
                "http"
            } else {
                "filesystem"
            };

            let token = std::env::var("CRATONS_CACHE_TOKEN").ok();

            let region = std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .ok();

            self.cache.remote = Some(RemoteCacheConfig {
                backend_type: backend_type.to_string(),
                url: Some(url),
                path: None,
                region,
                token,
                read_only: None,
            });
            set_keys.push("cache.remote".to_string());
        }

        // Install
        if let Ok(val) = std::env::var("CRATONS_CONCURRENCY") {
            if let Ok(n) = val.parse() {
                self.install.concurrency = n;
                set_keys.push("install.concurrency".to_string());
            }
        }
        if let Ok(val) = std::env::var("CRATONS_STRICT_SCRIPTS") {
            self.install.strict_scripts = val == "1" || val.eq_ignore_ascii_case("true");
            set_keys.push("install.strict_scripts".to_string());
        }

        // Build
        if let Ok(val) = std::env::var("CRATONS_BUILD_TIMEOUT") {
            if let Ok(n) = val.parse() {
                self.build.timeout = Some(n);
                set_keys.push("build.timeout".to_string());
            }
        }
        if let Ok(val) = std::env::var("CRATONS_PUSH_TO_REMOTE") {
            self.build.push_to_remote = val == "1" || val.eq_ignore_ascii_case("true");
            set_keys.push("build.push_to_remote".to_string());
        }
        if let Ok(val) = std::env::var("CRATONS_MAX_PARALLEL") {
            if let Ok(n) = val.parse() {
                self.build.max_parallel = n;
                set_keys.push("build.max_parallel".to_string());
            }
        }

        // Security
        if let Ok(val) = std::env::var("CRATONS_FAIL_ON") {
            self.security.fail_on = val;
            set_keys.push("security.fail_on".to_string());
        }
        if let Ok(val) = std::env::var("CRATONS_STRICT_VERIFICATION") {
            self.security.strict_verification = val == "1" || val.eq_ignore_ascii_case("true");
            set_keys.push("security.strict_verification".to_string());
        }

        // Telemetry
        if let Ok(val) = std::env::var("CRATONS_TELEMETRY_ENABLED") {
            self.telemetry.enabled = val == "1" || val.eq_ignore_ascii_case("true");
            set_keys.push("telemetry.enabled".to_string());
        }
        if let Ok(val) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
            self.telemetry.endpoint = Some(val);
            set_keys.push("telemetry.endpoint".to_string());
        }
        if let Ok(val) = std::env::var("OTEL_SERVICE_NAME") {
            self.telemetry.service_name = val;
            set_keys.push("telemetry.service_name".to_string());
        }

        set_keys
    }

    /// Get the remote cache URL if configured.
    pub fn remote_cache_url(&self) -> Option<&str> {
        self.cache.remote.as_ref().and_then(|r| r.url.as_deref())
    }

    /// Get the remote cache token if configured.
    pub fn remote_cache_token(&self) -> Option<&str> {
        self.cache.remote.as_ref().and_then(|r| r.token.as_deref())
    }

    /// Convert remote cache config to cratons_store::RemoteCacheConfig.
    pub fn to_store_remote_config(&self) -> Option<cratons_store::RemoteCacheConfig> {
        let remote = self.cache.remote.as_ref()?;

        match remote.backend_type.as_str() {
            "s3" => {
                let url = remote.url.as_deref()?;
                let without_scheme = url.strip_prefix("s3://")?;
                let (bucket, prefix) = match without_scheme.split_once('/') {
                    Some((b, p)) => (b.to_string(), p.to_string()),
                    None => (without_scheme.to_string(), String::new()),
                };
                let region = remote
                    .region
                    .clone()
                    .unwrap_or_else(|| "us-east-1".to_string());
                Some(cratons_store::RemoteCacheConfig::s3_from_env(
                    bucket, prefix, region,
                ))
            }
            "http" | "https" => {
                let url = remote.url.clone()?;
                Some(cratons_store::RemoteCacheConfig::http(
                    url,
                    remote.token.clone(),
                ))
            }
            "filesystem" => {
                let path = remote.path.as_deref().or(remote.url.as_deref())?;
                let read_only = remote.read_only.unwrap_or(false);
                Some(cratons_store::RemoteCacheConfig::filesystem(
                    path, read_only,
                ))
            }
            _ => None,
        }
    }
}

/// Extract all explicitly-set keys from a TOML value, using dot-separated paths.
pub fn extract_present_keys(value: &toml::Value, prefix: &str) -> HashSet<String> {
    let mut keys = HashSet::new();

    match value {
        toml::Value::Table(table) => {
            for (k, v) in table {
                let full_key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };

                match v {
                    toml::Value::Table(_) => {
                        // Recurse into nested tables
                        keys.extend(extract_present_keys(v, &full_key));
                    }
                    _ => {
                        keys.insert(full_key);
                    }
                }
            }
        }
        _ => {
            if !prefix.is_empty() {
                keys.insert(prefix.to_string());
            }
        }
    }

    keys
}

/// Singleton for lazily loaded config.
static CONFIG: std::sync::OnceLock<Config> = std::sync::OnceLock::new();

/// Get the global configuration.
pub fn get() -> &'static Config {
    CONFIG.get_or_init(Config::load)
}

/// Reset the global configuration (for testing).
#[cfg(test)]
pub fn reset() {
    // OnceLock doesn't support reset, so tests should use Config::load() directly
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.install.concurrency, 8);
        assert!(config.install.run_scripts);
        assert!(!config.install.strict_scripts);
        assert_eq!(config.security.fail_on, "high");
    }

    #[test]
    fn test_merge_configs() {
        let base = Config::default();
        let override_config = Config {
            install: InstallConfig {
                concurrency: 16,
                ..Default::default()
            },
            ..Default::default()
        };

        let merged = base.merge(override_config);
        assert_eq!(merged.install.concurrency, 16);
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
            [install]
            concurrency = 4
            strict_scripts = true

            [security]
            fail_on = "critical"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.install.concurrency, 4);
        assert!(config.install.strict_scripts);
        assert_eq!(config.security.fail_on, "critical");
    }

    #[test]
    fn test_extract_present_keys() {
        let toml_str = r#"
            [security]
            fail_on = "medium"
            strict_verification = true

            [install]
            run_scripts = false
        "#;
        let val: toml::Value = toml_str.parse().unwrap();
        let keys = extract_present_keys(&val, "");

        assert!(keys.contains("security.fail_on"));
        assert!(keys.contains("security.strict_verification"));
        assert!(keys.contains("install.run_scripts"));
        assert!(!keys.contains("install.concurrency"));
    }

    #[test]
    fn test_corp_config_merge_wins() {
        // Simulate: user sets fail_on=low, corp sets fail_on=critical
        let user = Config {
            security: SecurityConfig {
                fail_on: "low".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let corp = Config {
            security: SecurityConfig {
                fail_on: "critical".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        // Corp merges last, so it wins
        let merged = user.merge(corp);
        assert_eq!(merged.security.fail_on, "critical");
    }

    #[test]
    fn test_registry_policy_config_parse() {
        let toml_str = r#"
            [registry_policy]
            default = "blocked"
            allow = ["npm.corp.com", "*.internal.com"]
            block = ["evil.com"]
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.registry_policy.default, Some("blocked".to_string()));
        assert_eq!(config.registry_policy.allow.len(), 2);
        assert_eq!(config.registry_policy.block.len(), 1);
    }

    #[test]
    fn test_registry_policy_merge() {
        let base = Config::default();
        let corp = Config {
            registry_policy: RegistryPolicyConfig {
                default: Some("blocked".to_string()),
                allow: vec!["npm.corp.com".to_string()],
                block: vec!["evil.com".to_string()],
                access: Default::default(),
            },
            ..Default::default()
        };

        let merged = base.merge(corp);
        assert_eq!(merged.registry_policy.default, Some("blocked".to_string()));
        assert_eq!(merged.registry_policy.allow, vec!["npm.corp.com"]);
        assert_eq!(merged.registry_policy.block, vec!["evil.com"]);
    }

    #[test]
    fn test_corp_config_load_and_merge() {
        use std::io::Write;

        // Create a temp corp config file
        let dir = tempfile::tempdir().unwrap();
        let corp_path = dir.path().join("policy.toml");
        let mut f = std::fs::File::create(&corp_path).unwrap();
        writeln!(
            f,
            r#"
[security]
fail_on = "critical"
strict_verification = true
"#
        )
        .unwrap();

        // Test loading the corp config file directly
        let corp_config = Config::load_file(&corp_path).unwrap();
        assert_eq!(corp_config.security.fail_on, "critical");
        assert!(corp_config.security.strict_verification);

        // Test that corp config wins when merged last
        let user_config = Config {
            security: SecurityConfig {
                fail_on: "low".to_string(),
                strict_verification: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = user_config.merge(corp_config);
        assert_eq!(merged.security.fail_on, "critical");
        assert!(merged.security.strict_verification);
    }

    #[test]
    fn test_corp_locked_keys_detection() {
        use std::io::Write;

        // Create a temp corp config file
        let dir = tempfile::tempdir().unwrap();
        let corp_path = dir.path().join("policy.toml");
        let mut f = std::fs::File::create(&corp_path).unwrap();
        writeln!(
            f,
            r#"
[security]
fail_on = "critical"
strict_verification = true

[install]
run_scripts = false
"#
        )
        .unwrap();

        // Parse and extract keys
        let raw = std::fs::read_to_string(&corp_path).unwrap();
        let val: toml::Value = raw.parse().unwrap();
        let locked = extract_present_keys(&val, "");

        assert!(locked.contains("security.fail_on"));
        assert!(locked.contains("security.strict_verification"));
        assert!(locked.contains("install.run_scripts"));
        assert!(!locked.contains("install.concurrency")); // not in corp file
        assert!(!locked.contains("telemetry.enabled")); // not in corp file
    }
}
