//! Store configuration.

use cratons_core::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::link::LinkStrategy;

/// Configuration for the Cratons store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StoreConfig {
    /// Preferred linking strategy
    pub link_strategy: LinkStrategyConfig,
    /// Maximum cache age in days (for garbage collection)
    pub max_cache_age_days: u32,
    /// Maximum store size in bytes (0 = unlimited)
    pub max_store_size_bytes: u64,
    /// Enable store compression
    pub compress_artifacts: bool,
    /// Remote cache URL (optional)
    pub remote_cache_url: Option<String>,
    /// Remote cache authentication token
    pub remote_cache_token: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            link_strategy: LinkStrategyConfig::Auto,
            max_cache_age_days: 30,
            max_store_size_bytes: 0,
            compress_artifacts: true,
            remote_cache_url: None,
            remote_cache_token: None,
        }
    }
}

impl StoreConfig {
    /// Load configuration from the store root, or return defaults.
    pub fn load_or_default(store_root: &Path) -> Result<Self> {
        let config_path = store_root.join("config.toml");

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: Self = toml::from_str(&content)
                .map_err(|e| cratons_core::CratonsError::Config(e.to_string()))?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    /// Save configuration to the store root.
    pub fn save(&self, store_root: &Path) -> Result<()> {
        let config_path = store_root.join("config.toml");
        let content = toml::to_string_pretty(self)
            .map_err(|e| cratons_core::CratonsError::Config(e.to_string()))?;
        fs::write(config_path, content)?;
        Ok(())
    }

    /// Get the link strategy to use.
    #[must_use]
    pub fn link_strategy(&self, source: &Path, target: &Path) -> LinkStrategy {
        match self.link_strategy {
            LinkStrategyConfig::Auto => LinkStrategy::detect(source, target),
            LinkStrategyConfig::HardLink => LinkStrategy::HardLink,
            LinkStrategyConfig::Symlink => LinkStrategy::Symlink,
            LinkStrategyConfig::Reflink => LinkStrategy::Reflink,
            LinkStrategyConfig::Copy => LinkStrategy::Copy,
        }
    }
}

/// Link strategy configuration option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkStrategyConfig {
    /// Automatically detect the best strategy
    #[default]
    Auto,
    /// Always use hard links
    HardLink,
    /// Always use symbolic links
    Symlink,
    /// Always use reflinks (copy-on-write)
    Reflink,
    /// Always copy files
    Copy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = StoreConfig::default();
        assert_eq!(config.max_cache_age_days, 30);
        assert!(config.compress_artifacts);
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();

        let config = StoreConfig {
            max_cache_age_days: 60,
            ..Default::default()
        };

        config.save(dir.path()).unwrap();
        let loaded = StoreConfig::load_or_default(dir.path()).unwrap();

        assert_eq!(loaded.max_cache_age_days, 60);
    }
}
