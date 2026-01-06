//! Credential storage backends.
//!
//! # Security
//!
//! This module implements secure credential storage with:
//! - **Memory protection**: Sensitive data is zeroized when dropped
//! - **Encryption**: AES-256-GCM for at-rest encryption
//! - **File permissions**: Restrictive permissions (0600) on credential files

use crate::Error;
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, warn};
use zeroize::Zeroize;

/// Trait for credential storage backends.
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Get a credential by key.
    async fn get(&self, key: &str) -> Result<Option<SecretString>, Error>;

    /// Set a credential.
    async fn set(&self, key: &str, value: SecretString) -> Result<(), Error>;

    /// Delete a credential.
    async fn delete(&self, key: &str) -> Result<(), Error>;

    /// Check if this store supports writing.
    fn supports_write(&self) -> bool {
        true
    }

    /// Get the name of this store for logging.
    fn name(&self) -> &'static str;
}

/// System keychain storage (macOS Keychain, Windows Credential Manager, Linux Secret Service).
///
/// # Security Considerations
///
/// The underlying `keyring` crate uses OS-provided credential storage:
/// - **macOS**: Keychain Services (credentials protected by login password)
/// - **Windows**: Credential Manager (credentials encrypted per-user)
/// - **Linux**: Secret Service API (typically via GNOME Keyring or KWallet)
///
/// Access control is managed by the OS; we cannot programmatically configure
/// which applications can access stored credentials. Users should review their
/// OS keychain settings if stricter access control is required.
pub struct KeychainStore {
    service: String,
}

impl KeychainStore {
    /// Create a new keychain store.
    pub fn new() -> Self {
        Self {
            service: "cratons-package-manager".to_string(),
        }
    }

    /// Create a keychain store with a custom service name.
    pub fn with_service(service: String) -> Self {
        Self { service }
    }

    /// Check if keychain access is available on this system.
    pub fn is_available() -> bool {
        // Try to create a test entry to check if keychain is accessible
        let entry = keyring::Entry::new("cratons-availability-check", "test");
        match entry {
            Ok(_) => true,
            Err(e) => {
                debug!("Keychain not available: {}", e);
                false
            }
        }
    }
}

impl Default for KeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialStore for KeychainStore {
    async fn get(&self, key: &str) -> Result<Option<SecretString>, Error> {
        let entry = keyring::Entry::new(&self.service, key)?;

        match entry.get_password() {
            Ok(password) => Ok(Some(SecretString::from(password))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::Keychain(e)),
        }
    }

    async fn set(&self, key: &str, value: SecretString) -> Result<(), Error> {
        use secrecy::ExposeSecret;
        let entry = keyring::Entry::new(&self.service, key)?;
        entry.set_password(value.expose_secret())?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), Error> {
        let entry = keyring::Entry::new(&self.service, key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // Already deleted
            Err(e) => Err(Error::Keychain(e)),
        }
    }

    fn name(&self) -> &'static str {
        "keychain"
    }
}

/// Environment variable storage (read-only).
pub struct EnvStore {
    /// Mapping of credential keys to environment variable names.
    mappings: HashMap<String, String>,
}

impl EnvStore {
    /// Create a new environment store with default mappings.
    pub fn new() -> Self {
        let mut mappings = HashMap::new();

        // Registry tokens
        mappings.insert(
            "cratons:registry:npm:registry.npmjs.org".to_string(),
            "NPM_TOKEN".to_string(),
        );
        mappings.insert(
            "cratons:registry:pypi:pypi.org".to_string(),
            "PYPI_TOKEN".to_string(),
        );
        mappings.insert(
            "cratons:registry:crates:crates.io".to_string(),
            "CARGO_REGISTRY_TOKEN".to_string(),
        );

        Self { mappings }
    }

    /// Add a custom mapping.
    pub fn with_mapping(mut self, key: &str, env_var: &str) -> Self {
        self.mappings.insert(key.to_string(), env_var.to_string());
        self
    }
}

impl Default for EnvStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialStore for EnvStore {
    async fn get(&self, key: &str) -> Result<Option<SecretString>, Error> {
        // SECURITY: Only look up credentials from explicitly mapped environment variables.
        // We intentionally do NOT auto-generate env var names from keys because:
        // 1. Auto-generated names can leak information about what credentials are being requested
        // 2. Environment variables are inherited by child processes
        // 3. Explicit mappings provide better security auditing
        if let Some(env_var) = self.mappings.get(key) {
            if let Ok(value) = std::env::var(env_var) {
                debug!(env_var, "Found credential in environment");
                return Ok(Some(SecretString::from(value)));
            }
        }

        Ok(None)
    }

    async fn set(&self, _key: &str, _value: SecretString) -> Result<(), Error> {
        warn!("Cannot write to environment store");
        Err(Error::NoWritableStore)
    }

    async fn delete(&self, _key: &str) -> Result<(), Error> {
        warn!("Cannot delete from environment store");
        Err(Error::NoWritableStore)
    }

    fn supports_write(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "environment"
    }
}

/// In-memory store for testing.
pub struct MemoryStore {
    data: RwLock<HashMap<String, SecretString>>,
}

impl MemoryStore {
    /// Create a new memory store.
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialStore for MemoryStore {
    async fn get(&self, key: &str) -> Result<Option<SecretString>, Error> {
        let data = self.data.read().unwrap();
        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: &str, value: SecretString) -> Result<(), Error> {
        let mut data = self.data.write().unwrap();
        data.insert(key.to_string(), value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), Error> {
        let mut data = self.data.write().unwrap();
        data.remove(key);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "memory"
    }
}

/// Encrypted file-based storage for CI environments.
///
/// # Security
///
/// This store uses **AES-256-GCM** for authenticated encryption, which provides
/// both confidentiality and integrity verification. The GCM (Galois/Counter Mode)
/// authentication tag ensures that any tampering with the ciphertext will be
/// detected during decryption - no separate HMAC is needed.
///
/// Key derivation uses **Argon2id** with OWASP-recommended parameters to resist
/// GPU-based attacks on passwords.
///
/// Memory protection:
/// - Password is stored in `SecretString` and zeroized when dropped
/// - Derived encryption keys are explicitly zeroized after use
/// - File permissions are set to 0600 (owner read/write only)
///
/// ## File format
///
/// - 22 bytes: Base64-encoded salt (for Argon2 key derivation)
/// - Rest: Base64-encoded encrypted data (12-byte nonce + ciphertext + 16-byte auth tag)
pub struct FileStore {
    path: std::path::PathBuf,
    /// Password stored as SecretString for automatic zeroization on drop
    password: SecretString,
}

impl FileStore {
    /// Salt length in base64 encoding (16 bytes = 22 base64 chars).
    const SALT_LEN: usize = 22;

    /// Create a new file store with password-based encryption.
    pub fn new(path: std::path::PathBuf, password: &str) -> Result<Self, Error> {
        Ok(Self {
            path,
            password: SecretString::from(password.to_string()),
        })
    }

    /// Derive encryption key from password and salt.
    ///
    /// Uses OWASP-recommended Argon2id parameters for credential protection:
    /// - 19 MiB memory (protects against GPU attacks)
    /// - 2 iterations
    /// - 1 thread (parallelism)
    ///
    /// # Security
    ///
    /// The caller MUST zeroize the returned key after use to prevent
    /// it from lingering in memory.
    fn derive_key(&self, salt: &str) -> Result<[u8; 32], Error> {
        use argon2::password_hash::SaltString;
        use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};

        let salt = SaltString::from_b64(salt)
            .map_err(|e| Error::Encryption(format!("Invalid salt: {e}")))?;

        // SECURITY: Use OWASP-recommended Argon2id parameters
        // See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
        let params = Params::new(
            19 * 1024, // 19 MiB memory
            2,         // 2 iterations
            1,         // 1 thread
            Some(32),  // 32-byte output
        )
        .map_err(|e| Error::Encryption(format!("Invalid Argon2 params: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let password_hash = argon2
            .hash_password(self.password.expose_secret().as_bytes(), &salt)
            .map_err(|e| Error::Encryption(e.to_string()))?;

        let hash_bytes = password_hash
            .hash
            .ok_or_else(|| Error::Encryption("Failed to get hash output".to_string()))?;

        let mut key = [0u8; 32];
        let hash_slice = hash_bytes.as_bytes();
        let copy_len = hash_slice.len().min(32);
        key[..copy_len].copy_from_slice(&hash_slice[..copy_len]);

        Ok(key)
    }

    /// Generate a new random salt.
    fn generate_salt() -> String {
        use argon2::password_hash::SaltString;
        use rand::rngs::OsRng;
        SaltString::generate(&mut OsRng).to_string()
    }

    fn encrypt(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        use aes_gcm::{
            Aes256Gcm, Nonce,
            aead::{Aead, KeyInit},
        };
        use rand::RngCore;
        use rand::rngs::OsRng;

        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|e| Error::Encryption(e.to_string()))?;

        // SECURITY: Use OsRng directly for cryptographic nonces to avoid
        // any potential issues with thread-local PRNG state
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| Error::Encryption(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        use aes_gcm::{
            Aes256Gcm, Nonce,
            aead::{Aead, KeyInit},
        };

        if data.len() < 12 {
            return Err(Error::Decryption("Data too short".to_string()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|e| Error::Decryption(e.to_string()))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::Decryption(e.to_string()))
    }

    fn load_store(&self) -> Result<HashMap<String, String>, Error> {
        use base64::Engine;

        if !self.path.exists() {
            return Ok(HashMap::new());
        }

        let contents = std::fs::read_to_string(&self.path)?;
        let contents = contents.trim();

        // File format: salt (22 chars) + base64 encrypted data
        if contents.len() < Self::SALT_LEN {
            return Err(Error::Decryption("File too short".to_string()));
        }

        let (salt, encoded) = contents.split_at(Self::SALT_LEN);
        let mut key = self.derive_key(salt)?;

        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| Error::Decryption(e.to_string()))?;

        let result = self.decrypt(&encrypted, &key);

        // SECURITY: Zeroize key immediately after use
        key.zeroize();

        let decrypted = result?;
        let json = String::from_utf8(decrypted).map_err(|e| Error::Decryption(e.to_string()))?;

        serde_json::from_str(&json).map_err(Error::from)
    }

    fn save_store(&self, data: &HashMap<String, String>) -> Result<(), Error> {
        use base64::Engine;

        // Check if file exists and has a salt we should reuse
        let salt = if self.path.exists() {
            let contents = std::fs::read_to_string(&self.path)?;
            let contents = contents.trim();
            if contents.len() >= Self::SALT_LEN {
                contents[..Self::SALT_LEN].to_string()
            } else {
                Self::generate_salt()
            }
        } else {
            Self::generate_salt()
        };

        let mut key = self.derive_key(&salt)?;
        let json = serde_json::to_string(data)?;
        let encrypt_result = self.encrypt(json.as_bytes(), &key);

        // SECURITY: Zeroize key immediately after use
        key.zeroize();

        let encrypted = encrypt_result?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write salt + encrypted data
        std::fs::write(&self.path, format!("{salt}{encoded}"))?;

        // SECURITY: Set restrictive file permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.path, permissions)?;
        }

        Ok(())
    }
}

#[async_trait]
impl CredentialStore for FileStore {
    async fn get(&self, key: &str) -> Result<Option<SecretString>, Error> {
        let store = self.load_store()?;
        Ok(store.get(key).map(|v| SecretString::from(v.clone())))
    }

    async fn set(&self, key: &str, value: SecretString) -> Result<(), Error> {
        use secrecy::ExposeSecret;
        let mut store = self.load_store()?;
        store.insert(key.to_string(), value.expose_secret().to_string());
        self.save_store(&store)
    }

    async fn delete(&self, key: &str) -> Result<(), Error> {
        let mut store = self.load_store()?;
        store.remove(key);
        self.save_store(&store)
    }

    fn name(&self) -> &'static str {
        "file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_store() {
        let store = MemoryStore::new();
        let key = "test_key";
        let value = SecretString::from("test_value".to_string());

        // Set and get
        store.set(key, value).await.unwrap();
        let retrieved = store.get(key).await.unwrap();
        assert!(retrieved.is_some());

        use secrecy::ExposeSecret;
        assert_eq!(retrieved.unwrap().expose_secret(), "test_value");

        // Delete
        store.delete(key).await.unwrap();
        let deleted = store.get(key).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_env_store() {
        let store = EnvStore::new();

        // Test with unset variable
        let result = store.get("nonexistent").await.unwrap();
        assert!(result.is_none());

        // Test write rejection
        let result = store
            .set("key", SecretString::from("value".to_string()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_file_store() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store_path = temp_dir.path().join("credentials.enc");

        let store = FileStore::new(store_path.clone(), "test_password").unwrap();
        let key = "test_key";
        let value = SecretString::from("test_value".to_string());

        // Set and get
        store.set(key, value).await.unwrap();
        let retrieved = store.get(key).await.unwrap();
        assert!(retrieved.is_some());

        use secrecy::ExposeSecret;
        assert_eq!(retrieved.unwrap().expose_secret(), "test_value");

        // Create new store instance with same password - should read existing data
        let store2 = FileStore::new(store_path, "test_password").unwrap();
        let retrieved2 = store2.get(key).await.unwrap();
        assert!(retrieved2.is_some());
        assert_eq!(retrieved2.unwrap().expose_secret(), "test_value");
    }

    #[tokio::test]
    async fn test_file_store_wrong_password() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store_path = temp_dir.path().join("credentials.enc");

        let store = FileStore::new(store_path.clone(), "correct_password").unwrap();
        store
            .set("key", SecretString::from("value".to_string()))
            .await
            .unwrap();

        // Try to read with wrong password
        let store2 = FileStore::new(store_path, "wrong_password").unwrap();
        let result = store2.get("key").await;
        assert!(result.is_err());
    }
}
