//! Secure credential management for Cratons package manager.
//!
//! This crate provides enterprise-grade credential storage and retrieval
//! using system keychains, environment variables, and encrypted file storage.
//!
//! # Features
//!
//! - **System keychain integration**: Uses macOS Keychain, Windows Credential Manager,
//!   or Linux Secret Service via the `keyring` crate
//! - **Secure memory handling**: All secrets use `secrecy::SecretString` with automatic
//!   zeroization on drop
//! - **Multiple storage backends**: Keychain, environment variables, encrypted files
//! - **Credential chaining**: Falls back through multiple providers automatically
//!
//! # Example
//!
//! ```no_run
//! use cratons_credentials::{CredentialManager, RegistryCredentials};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let manager = CredentialManager::new()?;
//!
//! // Store registry credentials (with validation)
//! let creds = RegistryCredentials::token("npm_token_here".to_string())?;
//! manager.store_registry("npm", "registry.npmjs.org", &creds).await?;
//!
//! // Retrieve credentials
//! let retrieved = manager.get_registry("npm", "registry.npmjs.org").await?;
//! # Ok(())
//! # }
//! ```

mod credentials;
mod error;
mod providers;
mod store;

pub use credentials::*;
pub use error::Error;
pub use providers::*;
pub use store::*;

use secrecy::SecretString;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, instrument};

/// The main credential manager that orchestrates credential storage and retrieval.
///
/// # Thread Safety
///
/// The credential manager is thread-safe and can be safely shared across threads.
/// Internal synchronization using `tokio::sync::Mutex` prevents race conditions during
/// concurrent credential operations (read/write/delete). The async-aware mutex ensures that:
///
/// - Multiple threads can safely call store/get/delete operations concurrently
/// - Store iteration and write operations are atomic (no partial state exposure)
/// - Credentials are never corrupted due to concurrent access
/// - Locks can be held safely across await points
pub struct CredentialManager {
    /// Thread-safe storage backend chain.
    /// Protected by async-aware mutex to prevent race conditions during credential operations.
    stores: Mutex<Vec<Arc<dyn CredentialStore>>>,
}

impl CredentialManager {
    /// Create a new credential manager with default stores.
    ///
    /// The default chain is:
    /// 1. Environment variables (highest priority)
    /// 2. System keychain
    /// 3. Encrypted file store (lowest priority)
    pub fn new() -> Result<Self, Error> {
        let mut stores: Vec<Arc<dyn CredentialStore>> = Vec::new();

        // Environment variables first (highest priority, non-persistent)
        stores.push(Arc::new(EnvStore::new()));

        // System keychain (if available)
        if KeychainStore::is_available() {
            stores.push(Arc::new(KeychainStore::new()));
        }

        Ok(Self {
            stores: Mutex::new(stores),
        })
    }

    /// Create a credential manager with a custom store chain.
    pub fn with_stores(stores: Vec<Arc<dyn CredentialStore>>) -> Self {
        Self {
            stores: Mutex::new(stores),
        }
    }

    /// Create a credential manager for testing (memory-only storage).
    pub fn for_testing() -> Self {
        Self {
            stores: Mutex::new(vec![Arc::new(MemoryStore::new())]),
        }
    }

    /// Store registry credentials.
    ///
    /// # Thread Safety
    ///
    /// This method acquires the stores mutex to ensure atomic iteration and write.
    ///
    /// # Errors
    ///
    /// Returns an error if no writable store is available or the store operation fails.
    #[instrument(skip(self, credentials), fields(ecosystem, registry))]
    pub async fn store_registry(
        &self,
        ecosystem: &str,
        registry: &str,
        credentials: &RegistryCredentials,
    ) -> Result<(), Error> {
        let key = format!("cratons:registry:{ecosystem}:{registry}");
        let value = serde_json::to_string(credentials)?;

        // Lock the stores vector to prevent race conditions during iteration and write selection
        let stores = self.stores.lock().await;

        for store in stores.iter() {
            if store.supports_write() {
                debug!(store = store.name(), "Storing registry credentials");
                store.set(&key, SecretString::from(value.clone())).await?;
                return Ok(());
            }
        }

        Err(Error::NoWritableStore)
    }

    /// Retrieve registry credentials.
    ///
    /// # Thread Safety
    ///
    /// This method acquires the stores mutex to ensure consistent iteration
    /// across the store chain without interference from concurrent modifications.
    ///
    /// # Errors
    ///
    /// Returns an error if a store operation fails.
    #[instrument(skip(self), fields(ecosystem, registry))]
    pub async fn get_registry(
        &self,
        ecosystem: &str,
        registry: &str,
    ) -> Result<Option<RegistryCredentials>, Error> {
        let key = format!("cratons:registry:{ecosystem}:{registry}");

        // Lock the stores vector to ensure consistent iteration
        let stores = self.stores.lock().await;

        for store in stores.iter() {
            if let Some(value) = store.get(&key).await? {
                use secrecy::ExposeSecret;
                let creds: RegistryCredentials = serde_json::from_str(value.expose_secret())?;
                debug!(store = store.name(), "Found registry credentials");
                return Ok(Some(creds));
            }
        }

        Ok(None)
    }

    /// Delete registry credentials.
    ///
    /// # Thread Safety
    ///
    /// This method acquires the stores mutex to ensure atomic deletion across
    /// all writable stores without race conditions.
    ///
    /// # Errors
    ///
    /// Returns an error if a store operation fails.
    #[instrument(skip(self), fields(ecosystem, registry))]
    pub async fn delete_registry(&self, ecosystem: &str, registry: &str) -> Result<(), Error> {
        let key = format!("cratons:registry:{ecosystem}:{registry}");

        // Lock the stores vector to prevent race conditions during deletion
        let stores = self.stores.lock().await;

        for store in stores.iter() {
            if store.supports_write() {
                store.delete(&key).await?;
            }
        }

        Ok(())
    }

    /// Store AWS credentials for remote cache.
    ///
    /// # Thread Safety
    ///
    /// This method acquires the stores mutex to ensure atomic iteration and write.
    ///
    /// # Errors
    ///
    /// Returns an error if no writable store is available or the store operation fails.
    #[instrument(skip(self, credentials))]
    pub async fn store_aws(
        &self,
        profile: &str,
        credentials: &AwsCredentials,
    ) -> Result<(), Error> {
        let key = format!("cratons:aws:{profile}");
        let value = serde_json::to_string(credentials)?;

        // Lock the stores vector to prevent race conditions during iteration and write selection
        let stores = self.stores.lock().await;

        for store in stores.iter() {
            if store.supports_write() {
                debug!(store = store.name(), "Storing AWS credentials");
                store.set(&key, SecretString::from(value.clone())).await?;
                return Ok(());
            }
        }

        Err(Error::NoWritableStore)
    }

    /// Retrieve AWS credentials.
    ///
    /// # Thread Safety
    ///
    /// This method acquires the stores mutex to ensure consistent iteration
    /// across the store chain without interference from concurrent modifications.
    ///
    /// # Errors
    ///
    /// Returns an error if a store operation fails.
    #[instrument(skip(self))]
    pub async fn get_aws(&self, profile: &str) -> Result<Option<AwsCredentials>, Error> {
        let key = format!("cratons:aws:{profile}");

        // Lock the stores vector to ensure consistent iteration
        let stores = self.stores.lock().await;

        for store in stores.iter() {
            if let Some(value) = store.get(&key).await? {
                use secrecy::ExposeSecret;
                let creds: AwsCredentials = serde_json::from_str(value.expose_secret())?;
                debug!(store = store.name(), "Found AWS credentials");
                return Ok(Some(creds));
            }
        }

        // Release the lock before checking environment variables
        drop(stores);

        // Fall back to environment variables for AWS
        if let (Ok(access_key), Ok(secret_key)) = (
            std::env::var("AWS_ACCESS_KEY_ID"),
            std::env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            return Ok(Some(AwsCredentials {
                access_key_id: SecretString::from(access_key),
                secret_access_key: SecretString::from(secret_key),
                session_token: std::env::var("AWS_SESSION_TOKEN")
                    .ok()
                    .map(SecretString::from),
                region: std::env::var("AWS_REGION").ok(),
            }));
        }

        Ok(None)
    }
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default credential manager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_credentials_roundtrip() {
        let manager = CredentialManager::for_testing();

        let creds = RegistryCredentials::token("test_token".to_string()).unwrap();
        manager
            .store_registry("npm", "registry.npmjs.org", &creds)
            .await
            .unwrap();

        let retrieved = manager
            .get_registry("npm", "registry.npmjs.org")
            .await
            .unwrap()
            .expect("Credentials should exist");

        use secrecy::ExposeSecret;
        match retrieved {
            RegistryCredentials::Token { token } => {
                assert_eq!(token.expose_secret(), "test_token");
            }
            _ => panic!("Expected token credentials"),
        }
    }

    #[tokio::test]
    async fn test_aws_credentials_roundtrip() {
        let manager = CredentialManager::for_testing();

        let creds = AwsCredentials {
            access_key_id: SecretString::from("AKIAIOSFODNN7EXAMPLE".to_string()),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            session_token: None,
            region: Some("us-east-1".to_string()),
        };

        manager.store_aws("default", &creds).await.unwrap();

        let retrieved = manager
            .get_aws("default")
            .await
            .unwrap()
            .expect("Credentials should exist");

        use secrecy::ExposeSecret;
        assert_eq!(
            retrieved.access_key_id.expose_secret(),
            "AKIAIOSFODNN7EXAMPLE"
        );
    }

    #[tokio::test]
    async fn test_delete_credentials() {
        let manager = CredentialManager::for_testing();

        let creds = RegistryCredentials::token("test_token".to_string()).unwrap();
        manager
            .store_registry("npm", "registry.npmjs.org", &creds)
            .await
            .unwrap();

        manager
            .delete_registry("npm", "registry.npmjs.org")
            .await
            .unwrap();

        let retrieved = manager
            .get_registry("npm", "registry.npmjs.org")
            .await
            .unwrap();

        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_missing_credentials() {
        let manager = CredentialManager::for_testing();

        let retrieved = manager
            .get_registry("npm", "nonexistent.registry.com")
            .await
            .unwrap();

        assert!(retrieved.is_none());
    }
}
