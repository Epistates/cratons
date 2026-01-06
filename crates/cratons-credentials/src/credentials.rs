//! Credential types for various services.
//!
//! # Security Considerations
//!
//! - Credential types implement a custom `Debug` that redacts sensitive values
//! - `Clone` is implemented but should be used sparingly to minimize copies of secrets
//! - All constructors validate inputs (non-empty tokens, valid AWS key format, etc.)

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Error returned when credential validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Description of what validation failed.
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "credential validation failed: {}", self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Helper to serialize SecretString (WARNING: exposes secret in serialized form)
fn serialize_secret<S: Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}

/// Helper to deserialize SecretString
fn deserialize_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretString, D::Error> {
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::from(s))
}

/// Helper to serialize Option<SecretString>
fn serialize_secret_opt<S: Serializer>(
    secret: &Option<SecretString>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match secret {
        Some(s) => serializer.serialize_some(s.expose_secret()),
        None => serializer.serialize_none(),
    }
}

/// Helper to deserialize Option<SecretString>
fn deserialize_secret_opt<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SecretString>, D::Error> {
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.map(SecretString::from))
}

/// Credentials for package registries (npm, PyPI, crates.io, etc.).
///
/// # Security
///
/// The `Debug` implementation redacts sensitive values. Clone should be used
/// sparingly to minimize copies of secrets in memory.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RegistryCredentials {
    /// Bearer token authentication.
    Token {
        /// The authentication token.
        #[serde(
            serialize_with = "serialize_secret",
            deserialize_with = "deserialize_secret"
        )]
        token: SecretString,
    },
    /// Basic authentication (username/password).
    Basic {
        /// Username.
        username: String,
        /// Password.
        #[serde(
            serialize_with = "serialize_secret",
            deserialize_with = "deserialize_secret"
        )]
        password: SecretString,
    },
    /// API key authentication.
    ApiKey {
        /// The API key.
        #[serde(
            serialize_with = "serialize_secret",
            deserialize_with = "deserialize_secret"
        )]
        key: SecretString,
        /// Optional key ID or name.
        #[serde(default)]
        key_id: Option<String>,
    },
}

impl fmt::Debug for RegistryCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token { .. } => f
                .debug_struct("Token")
                .field("token", &"[REDACTED]")
                .finish(),
            Self::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::ApiKey { key_id, .. } => f
                .debug_struct("ApiKey")
                .field("key", &"[REDACTED]")
                .field("key_id", key_id)
                .finish(),
        }
    }
}

impl RegistryCredentials {
    /// Create token-based credentials.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if the token is empty.
    pub fn token(token: String) -> Result<Self, ValidationError> {
        if token.is_empty() {
            return Err(ValidationError {
                message: "token cannot be empty".to_string(),
            });
        }
        Ok(Self::Token {
            token: SecretString::from(token),
        })
    }

    /// Create basic auth credentials.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if username or password is empty.
    pub fn basic(username: String, password: String) -> Result<Self, ValidationError> {
        if username.is_empty() {
            return Err(ValidationError {
                message: "username cannot be empty".to_string(),
            });
        }
        if password.is_empty() {
            return Err(ValidationError {
                message: "password cannot be empty".to_string(),
            });
        }
        Ok(Self::Basic {
            username,
            password: SecretString::from(password),
        })
    }

    /// Create API key credentials.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if the key is empty.
    pub fn api_key(key: String, key_id: Option<String>) -> Result<Self, ValidationError> {
        if key.is_empty() {
            return Err(ValidationError {
                message: "API key cannot be empty".to_string(),
            });
        }
        Ok(Self::ApiKey {
            key: SecretString::from(key),
            key_id,
        })
    }

    /// Get the authorization header value for HTTP requests.
    pub fn authorization_header(&self) -> Option<String> {
        use base64::Engine;
        use secrecy::ExposeSecret;

        match self {
            Self::Token { token } => Some(format!("Bearer {}", token.expose_secret())),
            Self::Basic { username, password } => {
                let credentials = format!("{}:{}", username, password.expose_secret());
                let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
                Some(format!("Basic {}", encoded))
            }
            Self::ApiKey { key, .. } => Some(key.expose_secret().to_string()),
        }
    }
}

/// AWS credentials for S3 remote cache access.
///
/// # Security
///
/// The `Debug` implementation redacts sensitive values.
#[derive(Clone, Serialize, Deserialize)]
pub struct AwsCredentials {
    /// AWS Access Key ID.
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub access_key_id: SecretString,
    /// AWS Secret Access Key.
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub secret_access_key: SecretString,
    /// Optional session token for temporary credentials.
    #[serde(
        default,
        serialize_with = "serialize_secret_opt",
        deserialize_with = "deserialize_secret_opt"
    )]
    pub session_token: Option<SecretString>,
    /// AWS region (optional, can use default).
    #[serde(default)]
    pub region: Option<String>,
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("region", &self.region)
            .finish()
    }
}

impl AwsCredentials {
    /// Minimum valid AWS access key ID length.
    const MIN_ACCESS_KEY_LEN: usize = 16;
    /// Maximum valid AWS access key ID length.
    const MAX_ACCESS_KEY_LEN: usize = 128;

    /// Create new AWS credentials with validation.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if:
    /// - Access key ID is empty or has invalid length
    /// - Secret access key is empty
    /// - Access key ID doesn't match AWS format (starts with AKIA, ASIA, etc.)
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        region: Option<String>,
    ) -> Result<Self, ValidationError> {
        // Validate access key ID format
        if access_key_id.is_empty() {
            return Err(ValidationError {
                message: "access_key_id cannot be empty".to_string(),
            });
        }
        if access_key_id.len() < Self::MIN_ACCESS_KEY_LEN
            || access_key_id.len() > Self::MAX_ACCESS_KEY_LEN
        {
            return Err(ValidationError {
                message: format!(
                    "access_key_id must be between {} and {} characters",
                    Self::MIN_ACCESS_KEY_LEN,
                    Self::MAX_ACCESS_KEY_LEN
                ),
            });
        }

        // AWS access key IDs start with specific prefixes
        let valid_prefixes = ["AKIA", "ASIA", "AIDA", "AROA", "ANPA", "ANVA", "AGPA"];
        let has_valid_prefix = valid_prefixes
            .iter()
            .any(|prefix| access_key_id.starts_with(prefix));
        if !has_valid_prefix {
            return Err(ValidationError {
                message: format!(
                    "access_key_id should start with one of: {}",
                    valid_prefixes.join(", ")
                ),
            });
        }

        if secret_access_key.is_empty() {
            return Err(ValidationError {
                message: "secret_access_key cannot be empty".to_string(),
            });
        }

        // If session token is provided, it shouldn't be empty
        if let Some(ref token) = session_token {
            if token.is_empty() {
                return Err(ValidationError {
                    message: "session_token cannot be empty if provided".to_string(),
                });
            }
        }

        Ok(Self {
            access_key_id: SecretString::from(access_key_id),
            secret_access_key: SecretString::from(secret_access_key),
            session_token: session_token.map(SecretString::from),
            region,
        })
    }

    /// Create AWS credentials without validation (for testing or known-good values).
    ///
    /// # Safety
    ///
    /// This bypasses validation. Only use with credentials you've already validated.
    #[must_use]
    pub fn new_unchecked(
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        region: Option<String>,
    ) -> Self {
        Self {
            access_key_id: SecretString::from(access_key_id),
            secret_access_key: SecretString::from(secret_access_key),
            session_token: session_token.map(SecretString::from),
            region,
        }
    }

    /// Check if these are temporary credentials (have a session token).
    #[must_use]
    pub fn is_temporary(&self) -> bool {
        self.session_token.is_some()
    }
}

/// Git credentials for git-based dependencies.
///
/// # Security
///
/// The `Debug` implementation redacts sensitive values.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GitCredentials {
    /// SSH key authentication.
    SshKey {
        /// Path to the private key file.
        private_key_path: String,
        /// Optional passphrase for the key.
        #[serde(
            default,
            serialize_with = "serialize_secret_opt",
            deserialize_with = "deserialize_secret_opt"
        )]
        passphrase: Option<SecretString>,
    },
    /// HTTPS basic authentication.
    Https {
        /// Username (often "git" for token auth).
        username: String,
        /// Password or personal access token.
        #[serde(
            serialize_with = "serialize_secret",
            deserialize_with = "deserialize_secret"
        )]
        password: SecretString,
    },
    /// GitHub App authentication.
    GitHubApp {
        /// App ID.
        app_id: String,
        /// Installation ID.
        installation_id: String,
        /// Private key (PEM format).
        #[serde(
            serialize_with = "serialize_secret",
            deserialize_with = "deserialize_secret"
        )]
        private_key: SecretString,
    },
}

impl fmt::Debug for GitCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SshKey {
                private_key_path, ..
            } => f
                .debug_struct("SshKey")
                .field("private_key_path", private_key_path)
                .field("passphrase", &"[REDACTED]")
                .finish(),
            Self::Https { username, .. } => f
                .debug_struct("Https")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::GitHubApp {
                app_id,
                installation_id,
                ..
            } => f
                .debug_struct("GitHubApp")
                .field("app_id", app_id)
                .field("installation_id", installation_id)
                .field("private_key", &"[REDACTED]")
                .finish(),
        }
    }
}

impl GitCredentials {
    /// Create SSH key credentials.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if the private key path is empty.
    pub fn ssh_key(
        private_key_path: String,
        passphrase: Option<String>,
    ) -> Result<Self, ValidationError> {
        if private_key_path.is_empty() {
            return Err(ValidationError {
                message: "private_key_path cannot be empty".to_string(),
            });
        }
        // Passphrase can be empty (not all keys have passphrases)
        Ok(Self::SshKey {
            private_key_path,
            passphrase: passphrase.map(SecretString::from),
        })
    }

    /// Create HTTPS credentials.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if username or password is empty.
    pub fn https(username: String, password: String) -> Result<Self, ValidationError> {
        if username.is_empty() {
            return Err(ValidationError {
                message: "username cannot be empty".to_string(),
            });
        }
        if password.is_empty() {
            return Err(ValidationError {
                message: "password cannot be empty".to_string(),
            });
        }
        Ok(Self::Https {
            username,
            password: SecretString::from(password),
        })
    }

    /// Create GitHub token credentials (uses HTTPS with token as password).
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if the token is empty.
    pub fn github_token(token: String) -> Result<Self, ValidationError> {
        if token.is_empty() {
            return Err(ValidationError {
                message: "GitHub token cannot be empty".to_string(),
            });
        }
        Ok(Self::Https {
            username: "x-access-token".to_string(),
            password: SecretString::from(token),
        })
    }

    /// Create GitHub App credentials.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if any required field is empty or if the private key
    /// doesn't look like a PEM-formatted key.
    pub fn github_app(
        app_id: String,
        installation_id: String,
        private_key: String,
    ) -> Result<Self, ValidationError> {
        if app_id.is_empty() {
            return Err(ValidationError {
                message: "app_id cannot be empty".to_string(),
            });
        }
        if installation_id.is_empty() {
            return Err(ValidationError {
                message: "installation_id cannot be empty".to_string(),
            });
        }
        if private_key.is_empty() {
            return Err(ValidationError {
                message: "private_key cannot be empty".to_string(),
            });
        }
        // Basic PEM format validation
        if !private_key.contains("-----BEGIN") {
            return Err(ValidationError {
                message: "private_key doesn't appear to be in PEM format".to_string(),
            });
        }
        Ok(Self::GitHubApp {
            app_id,
            installation_id,
            private_key: SecretString::from(private_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_token_credentials() {
        let creds = RegistryCredentials::token("my_token".to_string()).unwrap();
        let header = creds.authorization_header().unwrap();
        assert_eq!(header, "Bearer my_token");
    }

    #[test]
    fn test_token_credentials_empty_fails() {
        let result = RegistryCredentials::token("".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("empty"));
    }

    #[test]
    fn test_basic_credentials() {
        let creds = RegistryCredentials::basic("user".to_string(), "pass".to_string()).unwrap();
        let header = creds.authorization_header().unwrap();
        assert!(header.starts_with("Basic "));
    }

    #[test]
    fn test_basic_credentials_empty_fails() {
        assert!(RegistryCredentials::basic("".to_string(), "pass".to_string()).is_err());
        assert!(RegistryCredentials::basic("user".to_string(), "".to_string()).is_err());
    }

    #[test]
    fn test_aws_credentials() {
        let creds = AwsCredentials::new(
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "secret".to_string(),
            None,
            Some("us-east-1".to_string()),
        )
        .unwrap();
        assert!(!creds.is_temporary());
        assert_eq!(creds.access_key_id.expose_secret(), "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_aws_credentials_invalid_prefix() {
        let result = AwsCredentials::new(
            "INVALID_KEY_12345678".to_string(),
            "secret".to_string(),
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("should start with"));
    }

    #[test]
    fn test_aws_temporary_credentials() {
        let creds = AwsCredentials::new(
            "ASIAIOSFODNN7EXAMPLE".to_string(), // ASIA prefix for temp creds
            "secret".to_string(),
            Some("session_token".to_string()),
            None,
        )
        .unwrap();
        assert!(creds.is_temporary());
    }

    #[test]
    fn test_git_credentials() {
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
    fn test_git_credentials_empty_fails() {
        assert!(GitCredentials::github_token("".to_string()).is_err());
        assert!(GitCredentials::https("".to_string(), "pass".to_string()).is_err());
        assert!(GitCredentials::ssh_key("".to_string(), None).is_err());
    }

    #[test]
    fn test_credential_serialization() {
        let creds = RegistryCredentials::token("test".to_string()).unwrap();
        let json = serde_json::to_string(&creds).unwrap();
        assert!(json.contains("token"));

        let deserialized: RegistryCredentials = serde_json::from_str(&json).unwrap();
        match deserialized {
            RegistryCredentials::Token { token } => {
                assert_eq!(token.expose_secret(), "test");
            }
            _ => panic!("Expected token credentials"),
        }
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let token_creds = RegistryCredentials::token("secret_token".to_string()).unwrap();
        let debug_str = format!("{:?}", token_creds);
        assert!(!debug_str.contains("secret_token"));
        assert!(debug_str.contains("[REDACTED]"));

        let aws_creds = AwsCredentials::new_unchecked(
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "super_secret".to_string(),
            None,
            None,
        );
        let debug_str = format!("{:?}", aws_creds);
        assert!(!debug_str.contains("super_secret"));
        assert!(debug_str.contains("[REDACTED]"));
    }
}
