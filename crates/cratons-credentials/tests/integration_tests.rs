//! Integration tests for the credential management system.
//!
//! These tests verify the complete credential lifecycle using the public API.

use cratons_credentials::{
    AwsCredentials, ChainedProvider, CredentialManager, CredentialProvider, CredentialStore,
    EnvStore, EnvironmentProvider, Error, FileStore, GitCredentials, MemoryStore,
    RegistryCredentials, StaticProvider,
};
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

// ============================================================================
// CredentialManager Tests
// ============================================================================

#[tokio::test]
async fn test_credential_manager_registry_roundtrip() {
    let manager = CredentialManager::for_testing();

    // Store token credentials
    let creds = RegistryCredentials::token("my_npm_token".to_string()).unwrap();
    manager
        .store_registry("npm", "registry.npmjs.org", &creds)
        .await
        .expect("Failed to store credentials");

    // Retrieve credentials
    let retrieved = manager
        .get_registry("npm", "registry.npmjs.org")
        .await
        .expect("Failed to get credentials")
        .expect("Credentials should exist");

    match retrieved {
        RegistryCredentials::Token { token } => {
            assert_eq!(token.expose_secret(), "my_npm_token");
        }
        _ => panic!("Expected token credentials"),
    }
}

#[tokio::test]
async fn test_credential_manager_basic_auth() {
    let manager = CredentialManager::for_testing();

    let creds =
        RegistryCredentials::basic("username".to_string(), "password123".to_string()).unwrap();
    manager
        .store_registry("pypi", "pypi.org", &creds)
        .await
        .expect("Failed to store credentials");

    let retrieved = manager
        .get_registry("pypi", "pypi.org")
        .await
        .expect("Failed to get credentials")
        .expect("Credentials should exist");

    match retrieved {
        RegistryCredentials::Basic { username, password } => {
            assert_eq!(username, "username");
            assert_eq!(password.expose_secret(), "password123");
        }
        _ => panic!("Expected basic credentials"),
    }
}

#[tokio::test]
async fn test_credential_manager_aws_credentials() {
    let manager = CredentialManager::for_testing();

    let creds = AwsCredentials::new(
        "AKIAIOSFODNN7EXAMPLE".to_string(),
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        None,
        Some("us-east-1".to_string()),
    )
    .unwrap();

    manager
        .store_aws("default", &creds)
        .await
        .expect("Failed to store AWS credentials");

    let retrieved = manager
        .get_aws("default")
        .await
        .expect("Failed to get AWS credentials")
        .expect("AWS credentials should exist");

    assert_eq!(
        retrieved.access_key_id.expose_secret(),
        "AKIAIOSFODNN7EXAMPLE"
    );
    assert_eq!(retrieved.region, Some("us-east-1".to_string()));
}

#[tokio::test]
async fn test_credential_manager_delete_registry() {
    let manager = CredentialManager::for_testing();

    let creds = RegistryCredentials::token("delete_me".to_string()).unwrap();
    manager
        .store_registry("crates", "crates.io", &creds)
        .await
        .expect("Failed to store");

    // Verify it exists
    assert!(
        manager
            .get_registry("crates", "crates.io")
            .await
            .unwrap()
            .is_some()
    );

    // Delete it
    manager
        .delete_registry("crates", "crates.io")
        .await
        .expect("Failed to delete");

    // Verify it's gone
    assert!(
        manager
            .get_registry("crates", "crates.io")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_credential_manager_nonexistent() {
    let manager = CredentialManager::for_testing();

    let result = manager
        .get_registry("npm", "nonexistent.registry.com")
        .await
        .expect("Should not error");

    assert!(result.is_none());
}

// ============================================================================
// MemoryStore Tests
// ============================================================================

#[tokio::test]
async fn test_memory_store_basic_operations() {
    let store = MemoryStore::new();

    // Set a credential
    let secret = SecretString::from("test-password".to_string());
    store
        .set("test-key", secret)
        .await
        .expect("Failed to set credential");

    // Get the credential
    let retrieved = store
        .get("test-key")
        .await
        .expect("Failed to get credential")
        .expect("Credential should exist");

    assert_eq!(retrieved.expose_secret(), "test-password");

    // Delete the credential
    store
        .delete("test-key")
        .await
        .expect("Failed to delete credential");

    // Verify it's gone
    assert!(store.get("test-key").await.unwrap().is_none());
}

#[tokio::test]
async fn test_memory_store_multiple_keys() {
    let store = MemoryStore::new();

    // Store multiple credentials
    for i in 0..5 {
        let key = format!("key-{i}");
        let secret = SecretString::from(format!("secret-{i}"));
        store.set(&key, secret).await.expect("Failed to store");
    }

    // Retrieve each
    for i in 0..5 {
        let key = format!("key-{i}");
        let retrieved = store
            .get(&key)
            .await
            .expect("Failed to get")
            .expect("Should exist");
        assert_eq!(retrieved.expose_secret(), &format!("secret-{i}"));
    }
}

#[tokio::test]
async fn test_memory_store_overwrite() {
    let store = MemoryStore::new();

    store
        .set("key", SecretString::from("first".to_string()))
        .await
        .unwrap();
    store
        .set("key", SecretString::from("second".to_string()))
        .await
        .unwrap();

    let retrieved = store.get("key").await.unwrap().unwrap();
    assert_eq!(retrieved.expose_secret(), "second");
}

// ============================================================================
// EnvStore Tests
// ============================================================================

#[tokio::test]
async fn test_env_store_read_only() {
    let store = EnvStore::new();

    // Should fail to write
    let result = store
        .set("key", SecretString::from("value".to_string()))
        .await;
    assert!(result.is_err());

    // Should fail to delete
    let result = store.delete("key").await;
    assert!(result.is_err());

    // Verify it's marked as read-only
    assert!(!store.supports_write());
}

// ============================================================================
// FileStore Tests
// ============================================================================

#[tokio::test]
async fn test_file_store_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("credentials.enc");

    // Create store and add credentials
    let store =
        FileStore::new(file_path.clone(), "master-password-123").expect("Failed to create store");

    store
        .set("service1:user1", SecretString::from("secret1".to_string()))
        .await
        .expect("Failed to store");
    store
        .set("service2:user2", SecretString::from("secret2".to_string()))
        .await
        .expect("Failed to store");

    // Verify file exists
    assert!(file_path.exists());

    // Load store again with same password and verify
    let store2 = FileStore::new(file_path, "master-password-123").expect("Failed to load store");

    let secret1 = store2
        .get("service1:user1")
        .await
        .expect("Failed to get")
        .expect("Should exist");
    assert_eq!(secret1.expose_secret(), "secret1");

    let secret2 = store2
        .get("service2:user2")
        .await
        .expect("Failed to get")
        .expect("Should exist");
    assert_eq!(secret2.expose_secret(), "secret2");
}

#[tokio::test]
async fn test_file_store_wrong_password() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("credentials.enc");

    // Create with one password
    let store =
        FileStore::new(file_path.clone(), "correct-password").expect("Failed to create store");
    store
        .set("key", SecretString::from("secret".to_string()))
        .await
        .expect("Failed to store");

    // Try to read with wrong password
    let store2 = FileStore::new(file_path, "wrong-password").expect("Creation should succeed");
    let result = store2.get("key").await;

    // Should fail to decrypt
    assert!(result.is_err());
}

#[tokio::test]
async fn test_file_store_delete() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("credentials.enc");

    let store = FileStore::new(file_path, "password").expect("Failed to create store");

    store
        .set("key", SecretString::from("value".to_string()))
        .await
        .unwrap();
    assert!(store.get("key").await.unwrap().is_some());

    store.delete("key").await.unwrap();
    assert!(store.get("key").await.unwrap().is_none());
}

// ============================================================================
// RegistryCredentials Tests
// ============================================================================

#[test]
fn test_registry_credentials_token_auth_header() {
    let creds = RegistryCredentials::token("my_token_123".to_string()).unwrap();
    let header = creds.authorization_header().expect("Should have header");
    assert_eq!(header, "Bearer my_token_123");
}

#[test]
fn test_registry_credentials_basic_auth_header() {
    let creds = RegistryCredentials::basic("user".to_string(), "pass".to_string()).unwrap();
    let header = creds.authorization_header().expect("Should have header");
    assert!(header.starts_with("Basic "));

    // Verify it's valid base64
    use base64::Engine;
    let encoded_part = header.strip_prefix("Basic ").unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded_part)
        .expect("Should be valid base64");
    let decoded_str = String::from_utf8(decoded).expect("Should be valid UTF-8");
    assert_eq!(decoded_str, "user:pass");
}

#[test]
fn test_registry_credentials_api_key() {
    let creds =
        RegistryCredentials::api_key("api-key-value".to_string(), Some("key-id".to_string()))
            .unwrap();
    let header = creds.authorization_header().expect("Should have header");
    assert_eq!(header, "api-key-value");
}

#[test]
fn test_registry_credentials_serialization() {
    let creds = RegistryCredentials::token("test_token".to_string()).unwrap();
    let json = serde_json::to_string(&creds).expect("Serialization failed");
    assert!(json.contains("token"));

    let deserialized: RegistryCredentials =
        serde_json::from_str(&json).expect("Deserialization failed");

    match deserialized {
        RegistryCredentials::Token { token } => {
            assert_eq!(token.expose_secret(), "test_token");
        }
        _ => panic!("Expected token credentials"),
    }
}

// ============================================================================
// AwsCredentials Tests
// ============================================================================

#[test]
fn test_aws_credentials_permanent() {
    let creds = AwsCredentials::new(
        "AKIAIOSFODNN7EXAMPLE".to_string(),
        "secret-key".to_string(),
        None,
        Some("us-west-2".to_string()),
    )
    .unwrap();

    assert_eq!(creds.access_key_id.expose_secret(), "AKIAIOSFODNN7EXAMPLE");
    assert_eq!(creds.secret_access_key.expose_secret(), "secret-key");
    assert!(creds.session_token.is_none());
    assert!(!creds.is_temporary());
    assert_eq!(creds.region, Some("us-west-2".to_string()));
}

#[test]
fn test_aws_credentials_temporary() {
    let creds = AwsCredentials::new(
        "ASIATEMPEXAMPLE1234".to_string(), // Valid length (20 chars)
        "temp-secret".to_string(),
        Some("session-token".to_string()),
        None,
    )
    .unwrap();

    assert!(creds.is_temporary());
    assert!(creds.session_token.is_some());
    assert_eq!(
        creds.session_token.as_ref().unwrap().expose_secret(),
        "session-token"
    );
}

#[test]
fn test_aws_credentials_serialization() {
    let creds = AwsCredentials::new(
        "AKIATESTEXAMPLE12345".to_string(), // Valid length (20 chars)
        "secret".to_string(),
        None,
        Some("us-east-1".to_string()),
    )
    .unwrap();

    let json = serde_json::to_string(&creds).expect("Serialization failed");
    let deserialized: AwsCredentials = serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(
        deserialized.access_key_id.expose_secret(),
        "AKIATESTEXAMPLE12345"
    );
    assert_eq!(deserialized.region, Some("us-east-1".to_string()));
}

// ============================================================================
// GitCredentials Tests
// ============================================================================

#[test]
fn test_git_credentials_https() {
    let creds = GitCredentials::https("git-user".to_string(), "git-password".to_string()).unwrap();

    match creds {
        GitCredentials::Https { username, password } => {
            assert_eq!(username, "git-user");
            assert_eq!(password.expose_secret(), "git-password");
        }
        _ => panic!("Expected HTTPS credentials"),
    }
}

#[test]
fn test_git_credentials_github_token() {
    let creds = GitCredentials::github_token("ghp_xxxxxxxxxxxx".to_string()).unwrap();

    match creds {
        GitCredentials::Https { username, password } => {
            assert_eq!(username, "x-access-token");
            assert_eq!(password.expose_secret(), "ghp_xxxxxxxxxxxx");
        }
        _ => panic!("Expected HTTPS credentials"),
    }
}

#[test]
fn test_git_credentials_ssh_key() {
    let creds = GitCredentials::ssh_key(
        "/home/user/.ssh/id_rsa".to_string(),
        Some("passphrase".to_string()),
    )
    .unwrap();

    match creds {
        GitCredentials::SshKey {
            private_key_path,
            passphrase,
        } => {
            assert_eq!(private_key_path, "/home/user/.ssh/id_rsa");
            assert_eq!(passphrase.as_ref().unwrap().expose_secret(), "passphrase");
        }
        _ => panic!("Expected SSH key credentials"),
    }
}

// ============================================================================
// Provider Tests
// ============================================================================

#[tokio::test]
async fn test_static_provider() {
    let provider = StaticProvider::new()
        .with_registry(RegistryCredentials::token("static-token".to_string()).unwrap())
        .with_aws(
            AwsCredentials::new(
                "AKIATESTEXAMPLE12345".to_string(), // Valid length (20 chars)
                "secret".to_string(),
                None,
                None,
            )
            .unwrap(),
        )
        .with_git(GitCredentials::github_token("ghp_test".to_string()).unwrap());

    // Get registry credentials (any ecosystem/registry returns the static one)
    let registry = provider
        .get_registry_credentials("npm", "any")
        .await
        .expect("Failed to get registry credentials")
        .expect("Should have credentials");

    match registry {
        RegistryCredentials::Token { token } => {
            assert_eq!(token.expose_secret(), "static-token");
        }
        _ => panic!("Expected token"),
    }

    // Get AWS credentials
    let aws = provider
        .get_aws_credentials("any")
        .await
        .expect("Failed to get AWS credentials")
        .expect("Should have credentials");

    assert_eq!(aws.access_key_id.expose_secret(), "AKIATESTEXAMPLE12345");

    // Get Git credentials
    let git = provider
        .get_git_credentials("any")
        .await
        .expect("Failed to get Git credentials")
        .expect("Should have credentials");

    match git {
        GitCredentials::Https { username, .. } => {
            assert_eq!(username, "x-access-token");
        }
        _ => panic!("Expected HTTPS"),
    }
}

#[tokio::test]
async fn test_static_provider_empty() {
    let provider = StaticProvider::new();

    assert!(
        provider
            .get_registry_credentials("npm", "any")
            .await
            .unwrap()
            .is_none()
    );
    assert!(provider.get_aws_credentials("any").await.unwrap().is_none());
    assert!(provider.get_git_credentials("any").await.unwrap().is_none());
}

#[tokio::test]
async fn test_environment_provider_no_vars() {
    let provider = EnvironmentProvider::new();

    // Without env vars set, should return None for unknown ecosystem
    let result = provider
        .get_registry_credentials("unknown-ecosystem", "registry.example.com")
        .await
        .expect("Should not error");

    assert!(result.is_none());
}

#[tokio::test]
async fn test_chained_provider_fallback() {
    use std::sync::Arc;

    // First provider is empty
    let empty = Arc::new(StaticProvider::new());

    // Second provider has credentials
    let with_creds = Arc::new(
        StaticProvider::new()
            .with_registry(RegistryCredentials::token("fallback-token".to_string()).unwrap()),
    );

    let chain = ChainedProvider::new(vec![empty, with_creds]);

    let creds = chain
        .get_registry_credentials("npm", "any")
        .await
        .expect("Failed to get credentials")
        .expect("Should have fallback credentials");

    match creds {
        RegistryCredentials::Token { token } => {
            assert_eq!(token.expose_secret(), "fallback-token");
        }
        _ => panic!("Expected token"),
    }
}

#[tokio::test]
async fn test_chained_provider_first_wins() {
    use std::sync::Arc;

    let first = Arc::new(
        StaticProvider::new()
            .with_registry(RegistryCredentials::token("first-token".to_string()).unwrap()),
    );

    let second = Arc::new(
        StaticProvider::new()
            .with_registry(RegistryCredentials::token("second-token".to_string()).unwrap()),
    );

    let chain = ChainedProvider::new(vec![first, second]);

    let creds = chain
        .get_registry_credentials("npm", "any")
        .await
        .expect("Failed to get credentials")
        .expect("Should have credentials");

    match creds {
        RegistryCredentials::Token { token } => {
            assert_eq!(token.expose_secret(), "first-token");
        }
        _ => panic!("Expected token"),
    }
}

// ============================================================================
// Error Tests
// ============================================================================

#[test]
fn test_error_display() {
    let err = Error::NoWritableStore;
    let msg = format!("{err}");
    assert!(msg.contains("No writable credential store"));

    let err = Error::NotFound("test-key".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("test-key"));
}
