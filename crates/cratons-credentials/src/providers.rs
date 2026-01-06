//! Credential providers for different authentication scenarios.

use crate::Error;
use crate::credentials::{AwsCredentials, GitCredentials, RegistryCredentials};
use crate::store::{CredentialStore, KeychainStore};
use async_trait::async_trait;
use secrecy::SecretString;
use std::sync::Arc;
use tracing::debug;

/// A provider that supplies credentials on demand.
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Get registry credentials for the given ecosystem and registry.
    async fn get_registry_credentials(
        &self,
        ecosystem: &str,
        registry: &str,
    ) -> Result<Option<RegistryCredentials>, Error>;

    /// Get AWS credentials for the given profile.
    async fn get_aws_credentials(&self, profile: &str) -> Result<Option<AwsCredentials>, Error>;

    /// Get Git credentials for the given repository URL.
    async fn get_git_credentials(&self, repo_url: &str) -> Result<Option<GitCredentials>, Error>;

    /// Get the provider name for logging.
    fn name(&self) -> &'static str;
}

/// Static credential provider for testing.
pub struct StaticProvider {
    registry_credentials: Option<RegistryCredentials>,
    aws_credentials: Option<AwsCredentials>,
    git_credentials: Option<GitCredentials>,
}

impl StaticProvider {
    /// Create an empty static provider.
    pub fn new() -> Self {
        Self {
            registry_credentials: None,
            aws_credentials: None,
            git_credentials: None,
        }
    }

    /// Set registry credentials.
    pub fn with_registry(mut self, credentials: RegistryCredentials) -> Self {
        self.registry_credentials = Some(credentials);
        self
    }

    /// Set AWS credentials.
    pub fn with_aws(mut self, credentials: AwsCredentials) -> Self {
        self.aws_credentials = Some(credentials);
        self
    }

    /// Set Git credentials.
    pub fn with_git(mut self, credentials: GitCredentials) -> Self {
        self.git_credentials = Some(credentials);
        self
    }
}

impl Default for StaticProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialProvider for StaticProvider {
    async fn get_registry_credentials(
        &self,
        _ecosystem: &str,
        _registry: &str,
    ) -> Result<Option<RegistryCredentials>, Error> {
        Ok(self.registry_credentials.clone())
    }

    async fn get_aws_credentials(&self, _profile: &str) -> Result<Option<AwsCredentials>, Error> {
        Ok(self.aws_credentials.clone())
    }

    async fn get_git_credentials(&self, _repo_url: &str) -> Result<Option<GitCredentials>, Error> {
        Ok(self.git_credentials.clone())
    }

    fn name(&self) -> &'static str {
        "static"
    }
}

/// Environment variable credential provider.
pub struct EnvironmentProvider;

impl EnvironmentProvider {
    /// Create a new environment provider.
    pub fn new() -> Self {
        Self
    }
}

impl Default for EnvironmentProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialProvider for EnvironmentProvider {
    async fn get_registry_credentials(
        &self,
        ecosystem: &str,
        _registry: &str,
    ) -> Result<Option<RegistryCredentials>, Error> {
        let env_var = match ecosystem.to_lowercase().as_str() {
            "npm" => "NPM_TOKEN",
            "pypi" => "PYPI_TOKEN",
            "crates" => "CARGO_REGISTRY_TOKEN",
            "go" => "GOPROXY_TOKEN",
            "maven" => "MAVEN_TOKEN",
            _ => return Ok(None),
        };

        if let Ok(token) = std::env::var(env_var) {
            if let Ok(creds) = RegistryCredentials::token(token) {
                debug!(ecosystem, env_var, "Found registry token in environment");
                return Ok(Some(creds));
            }
        }

        Ok(None)
    }

    async fn get_aws_credentials(&self, _profile: &str) -> Result<Option<AwsCredentials>, Error> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").ok();
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok();

        match (access_key, secret_key) {
            (Some(access), Some(secret)) => {
                debug!("Found AWS credentials in environment");
                Ok(Some(AwsCredentials {
                    access_key_id: SecretString::from(access),
                    secret_access_key: SecretString::from(secret),
                    session_token: std::env::var("AWS_SESSION_TOKEN")
                        .ok()
                        .map(SecretString::from),
                    region: std::env::var("AWS_REGION").ok(),
                }))
            }
            _ => Ok(None),
        }
    }

    async fn get_git_credentials(&self, _repo_url: &str) -> Result<Option<GitCredentials>, Error> {
        // Check for GitHub token
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            if let Ok(creds) = GitCredentials::github_token(token) {
                debug!("Found GitHub token in environment");
                return Ok(Some(creds));
            }
        }

        // Check for generic Git credentials
        if let (Ok(username), Ok(password)) =
            (std::env::var("GIT_USERNAME"), std::env::var("GIT_PASSWORD"))
        {
            if let Ok(creds) = GitCredentials::https(username, password) {
                debug!("Found Git credentials in environment");
                return Ok(Some(creds));
            }
        }

        Ok(None)
    }

    fn name(&self) -> &'static str {
        "environment"
    }
}

/// Keychain-based credential provider.
pub struct KeychainProvider {
    store: KeychainStore,
}

impl KeychainProvider {
    /// Create a new keychain provider.
    pub fn new() -> Self {
        Self {
            store: KeychainStore::new(),
        }
    }

    /// Check if keychain is available.
    pub fn is_available() -> bool {
        KeychainStore::is_available()
    }
}

impl Default for KeychainProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialProvider for KeychainProvider {
    async fn get_registry_credentials(
        &self,
        ecosystem: &str,
        registry: &str,
    ) -> Result<Option<RegistryCredentials>, Error> {
        let key = format!("cratons:registry:{}:{}", ecosystem, registry);

        if let Some(value) = self.store.get(&key).await? {
            use secrecy::ExposeSecret;
            let creds: RegistryCredentials = serde_json::from_str(value.expose_secret())?;
            debug!(
                ecosystem,
                registry, "Found registry credentials in keychain"
            );
            return Ok(Some(creds));
        }

        Ok(None)
    }

    async fn get_aws_credentials(&self, profile: &str) -> Result<Option<AwsCredentials>, Error> {
        let key = format!("cratons:aws:{}", profile);

        if let Some(value) = self.store.get(&key).await? {
            use secrecy::ExposeSecret;
            let creds: AwsCredentials = serde_json::from_str(value.expose_secret())?;
            debug!(profile, "Found AWS credentials in keychain");
            return Ok(Some(creds));
        }

        Ok(None)
    }

    async fn get_git_credentials(&self, repo_url: &str) -> Result<Option<GitCredentials>, Error> {
        let key = format!("cratons:git:{}", repo_url);

        if let Some(value) = self.store.get(&key).await? {
            use secrecy::ExposeSecret;
            let creds: GitCredentials = serde_json::from_str(value.expose_secret())?;
            debug!(repo_url, "Found Git credentials in keychain");
            return Ok(Some(creds));
        }

        Ok(None)
    }

    fn name(&self) -> &'static str {
        "keychain"
    }
}

/// Chained credential provider that tries multiple providers in order.
pub struct ChainedProvider {
    providers: Vec<Arc<dyn CredentialProvider>>,
}

impl ChainedProvider {
    /// Create a new chained provider.
    pub fn new(providers: Vec<Arc<dyn CredentialProvider>>) -> Self {
        Self { providers }
    }

    /// Create a default chain (environment -> keychain).
    pub fn default_chain() -> Self {
        let mut providers: Vec<Arc<dyn CredentialProvider>> = Vec::new();

        // Environment variables first (highest priority)
        providers.push(Arc::new(EnvironmentProvider::new()));

        // Keychain if available
        if KeychainProvider::is_available() {
            providers.push(Arc::new(KeychainProvider::new()));
        }

        Self { providers }
    }
}

#[async_trait]
impl CredentialProvider for ChainedProvider {
    async fn get_registry_credentials(
        &self,
        ecosystem: &str,
        registry: &str,
    ) -> Result<Option<RegistryCredentials>, Error> {
        for provider in &self.providers {
            if let Some(creds) = provider
                .get_registry_credentials(ecosystem, registry)
                .await?
            {
                debug!(
                    provider = provider.name(),
                    ecosystem, registry, "Found registry credentials"
                );
                return Ok(Some(creds));
            }
        }
        Ok(None)
    }

    async fn get_aws_credentials(&self, profile: &str) -> Result<Option<AwsCredentials>, Error> {
        for provider in &self.providers {
            if let Some(creds) = provider.get_aws_credentials(profile).await? {
                debug!(provider = provider.name(), profile, "Found AWS credentials");
                return Ok(Some(creds));
            }
        }
        Ok(None)
    }

    async fn get_git_credentials(&self, repo_url: &str) -> Result<Option<GitCredentials>, Error> {
        for provider in &self.providers {
            if let Some(creds) = provider.get_git_credentials(repo_url).await? {
                debug!(
                    provider = provider.name(),
                    repo_url, "Found Git credentials"
                );
                return Ok(Some(creds));
            }
        }
        Ok(None)
    }

    fn name(&self) -> &'static str {
        "chained"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_provider() {
        let provider = StaticProvider::new()
            .with_registry(RegistryCredentials::token("test_token".to_string()).unwrap());

        let creds = provider
            .get_registry_credentials("npm", "registry.npmjs.org")
            .await
            .unwrap();

        assert!(creds.is_some());
    }

    #[tokio::test]
    async fn test_environment_provider() {
        let provider = EnvironmentProvider::new();

        // Should return None for unset variables
        let creds = provider
            .get_registry_credentials("npm", "registry.npmjs.org")
            .await
            .unwrap();

        // This will be None unless NPM_TOKEN is set in the environment
        // In CI, this might be set, so we just verify no error
        let _ = creds;
    }

    #[tokio::test]
    async fn test_chained_provider() {
        let static_provider = Arc::new(
            StaticProvider::new()
                .with_registry(RegistryCredentials::token("test_token".to_string()).unwrap()),
        );

        let chain = ChainedProvider::new(vec![static_provider]);

        let creds = chain
            .get_registry_credentials("npm", "registry.npmjs.org")
            .await
            .unwrap();

        assert!(creds.is_some());
    }

    #[tokio::test]
    async fn test_chained_provider_fallback() {
        // First provider returns None
        let empty_provider = Arc::new(StaticProvider::new());

        // Second provider has credentials
        let full_provider = Arc::new(
            StaticProvider::new()
                .with_registry(RegistryCredentials::token("fallback_token".to_string()).unwrap()),
        );

        let chain = ChainedProvider::new(vec![empty_provider, full_provider]);

        let creds = chain
            .get_registry_credentials("npm", "registry.npmjs.org")
            .await
            .unwrap();

        assert!(creds.is_some());
        use secrecy::ExposeSecret;
        match creds.unwrap() {
            RegistryCredentials::Token { token } => {
                assert_eq!(token.expose_secret(), "fallback_token");
            }
            _ => panic!("Expected token credentials"),
        }
    }
}
