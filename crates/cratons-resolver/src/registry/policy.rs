//! Registry access control policy.
//!
//! Domain-level allow/block lists with wildcard support for controlling
//! which package registries can be accessed. This is a network-level gate
//! that runs before any HTTP request, complementary to Cedar package-level policies.
//!
//! Semantics:
//! - Block list always wins (checked first)
//! - If default is `Blocked`, only explicitly allowed domains are reachable
//! - No policy configured = all allowed (backward compatible)

use serde::{Deserialize, Serialize};

/// Access level for a registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryAccess {
    /// Full read and write access
    ReadWrite,
    /// Read-only access (downloads allowed, publishing denied)
    ReadOnly,
    /// All access denied
    Blocked,
}

impl Default for RegistryAccess {
    fn default() -> Self {
        Self::ReadWrite
    }
}

/// Type of operation being performed against a registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryOperation {
    /// Reading metadata / fetching version lists
    Read,
    /// Downloading package artifacts
    Download,
    /// Publishing / pushing packages
    Write,
}

/// A domain pattern for matching registry hostnames.
#[derive(Debug, Clone)]
struct DomainPattern {
    /// The lowercased domain suffix (without leading `*.`)
    suffix: String,
    /// Whether this is a wildcard pattern (e.g., `*.corp.com`)
    is_wildcard: bool,
}

impl DomainPattern {
    /// Parse a pattern string like `"*.foo.com"` or `"foo.com"`.
    fn new(pattern: &str) -> Self {
        let pattern = pattern.trim().to_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            Self {
                suffix: suffix.to_string(),
                is_wildcard: true,
            }
        } else {
            Self {
                suffix: pattern,
                is_wildcard: false,
            }
        }
    }

    /// Check if a domain matches this pattern.
    ///
    /// - Exact match: `"foo.com"` matches `"foo.com"`
    /// - Wildcard match: `"*.foo.com"` matches `"bar.foo.com"` but NOT `"foo.com"` itself
    fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        if self.is_wildcard {
            // Wildcard: domain must be a proper subdomain
            domain.ends_with(&format!(".{}", self.suffix)) && domain != self.suffix
        } else {
            domain == self.suffix
        }
    }
}

/// Configuration for registry access policy (deserialized from TOML).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistryPolicyConfig {
    /// Default access level when no rule matches
    pub default: Option<String>,
    /// Allowed domain patterns
    pub allow: Vec<String>,
    /// Blocked domain patterns
    pub block: Vec<String>,
    /// Per-domain access level overrides (domain -> "read-only" | "read-write" | "blocked")
    pub access: std::collections::HashMap<String, String>,
}

/// Evaluated registry access policy.
#[derive(Debug)]
pub struct RegistryPolicy {
    default: RegistryAccess,
    allowed: Vec<DomainPattern>,
    blocked: Vec<DomainPattern>,
    access_overrides: Vec<(DomainPattern, RegistryAccess)>,
}

impl RegistryPolicy {
    /// Construct from config.
    pub fn from_config(config: &RegistryPolicyConfig) -> Self {
        let default = match config.default.as_deref() {
            Some("blocked") => RegistryAccess::Blocked,
            Some("read-only") => RegistryAccess::ReadOnly,
            _ => RegistryAccess::ReadWrite,
        };

        let allowed = config.allow.iter().map(|p| DomainPattern::new(p)).collect();
        let blocked = config.block.iter().map(|p| DomainPattern::new(p)).collect();

        let access_overrides = config
            .access
            .iter()
            .map(|(domain, level)| {
                let access = match level.as_str() {
                    "read-only" => RegistryAccess::ReadOnly,
                    "blocked" => RegistryAccess::Blocked,
                    _ => RegistryAccess::ReadWrite,
                };
                (DomainPattern::new(domain), access)
            })
            .collect();

        Self {
            default,
            allowed,
            blocked,
            access_overrides,
        }
    }

    /// Check if the given domain and operation are allowed.
    ///
    /// Returns `Ok(())` if allowed, or `Err(reason)` if denied.
    pub fn check(&self, domain: &str, operation: RegistryOperation) -> Result<(), String> {
        // 1. Block list always wins
        if self.blocked.iter().any(|p| p.matches(domain)) {
            return Err(format!("domain '{}' is blocked by registry policy", domain));
        }

        // 2. Check per-domain access overrides
        for (pattern, access) in &self.access_overrides {
            if pattern.matches(domain) {
                return Self::check_access(domain, access, operation);
            }
        }

        // 3. Check allow list (if default is blocked, must be explicitly allowed)
        let is_allowed = self.allowed.iter().any(|p| p.matches(domain));

        let effective_access = if is_allowed {
            &RegistryAccess::ReadWrite
        } else {
            &self.default
        };

        Self::check_access(domain, effective_access, operation)
    }

    fn check_access(
        domain: &str,
        access: &RegistryAccess,
        operation: RegistryOperation,
    ) -> Result<(), String> {
        match (access, operation) {
            (RegistryAccess::Blocked, _) => {
                Err(format!("domain '{}' is blocked by registry policy", domain))
            }
            (RegistryAccess::ReadOnly, RegistryOperation::Write) => Err(format!(
                "domain '{}' is read-only; write operations are not allowed",
                domain
            )),
            _ => Ok(()),
        }
    }

    /// Returns true if this policy has any rules configured.
    pub fn has_rules(&self) -> bool {
        !self.allowed.is_empty()
            || !self.blocked.is_empty()
            || !self.access_overrides.is_empty()
            || self.default != RegistryAccess::ReadWrite
    }
}

/// Extract the domain from a URL string.
pub fn extract_domain(url: &str) -> Option<String> {
    // Handle URLs with or without scheme
    let url = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };

    url::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_pattern_exact() {
        let p = DomainPattern::new("registry.npmjs.org");
        assert!(p.matches("registry.npmjs.org"));
        assert!(p.matches("Registry.Npmjs.Org"));
        assert!(!p.matches("evil.registry.npmjs.org"));
        assert!(!p.matches("npmjs.org"));
    }

    #[test]
    fn test_domain_pattern_wildcard() {
        let p = DomainPattern::new("*.corp.com");
        assert!(p.matches("npm.corp.com"));
        assert!(p.matches("pypi.corp.com"));
        assert!(p.matches("deep.sub.corp.com"));
        assert!(!p.matches("corp.com")); // wildcard requires subdomain
        assert!(!p.matches("notcorp.com"));
    }

    #[test]
    fn test_policy_default_allow() {
        let config = RegistryPolicyConfig::default();
        let policy = RegistryPolicy::from_config(&config);

        assert!(
            policy
                .check("registry.npmjs.org", RegistryOperation::Read)
                .is_ok()
        );
        assert!(
            policy
                .check("pypi.org", RegistryOperation::Download)
                .is_ok()
        );
    }

    #[test]
    fn test_policy_block_list_wins() {
        let config = RegistryPolicyConfig {
            default: None,
            allow: vec!["registry.npmjs.org".to_string()],
            block: vec!["registry.npmjs.org".to_string()],
            access: Default::default(),
        };
        let policy = RegistryPolicy::from_config(&config);

        // Block wins even though it's also in allow
        assert!(
            policy
                .check("registry.npmjs.org", RegistryOperation::Read)
                .is_err()
        );
    }

    #[test]
    fn test_policy_default_blocked() {
        let config = RegistryPolicyConfig {
            default: Some("blocked".to_string()),
            allow: vec![
                "npm.internal.corp.com".to_string(),
                "*.corp.com".to_string(),
            ],
            block: vec![],
            access: Default::default(),
        };
        let policy = RegistryPolicy::from_config(&config);

        // Allowed domains work
        assert!(
            policy
                .check("npm.internal.corp.com", RegistryOperation::Read)
                .is_ok()
        );
        assert!(
            policy
                .check("pypi.corp.com", RegistryOperation::Read)
                .is_ok()
        );

        // Non-allowed domains are blocked
        assert!(
            policy
                .check("registry.npmjs.org", RegistryOperation::Read)
                .is_err()
        );
        assert!(
            policy
                .check("pypi.org", RegistryOperation::Download)
                .is_err()
        );
    }

    #[test]
    fn test_policy_read_only() {
        let mut access = std::collections::HashMap::new();
        access.insert("mirror.corp.com".to_string(), "read-only".to_string());

        let config = RegistryPolicyConfig {
            default: None,
            allow: vec![],
            block: vec![],
            access,
        };
        let policy = RegistryPolicy::from_config(&config);

        assert!(
            policy
                .check("mirror.corp.com", RegistryOperation::Read)
                .is_ok()
        );
        assert!(
            policy
                .check("mirror.corp.com", RegistryOperation::Download)
                .is_ok()
        );
        assert!(
            policy
                .check("mirror.corp.com", RegistryOperation::Write)
                .is_err()
        );
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://registry.npmjs.org"),
            Some("registry.npmjs.org".to_string())
        );
        assert_eq!(
            extract_domain("https://npm.corp.com/path"),
            Some("npm.corp.com".to_string())
        );
        assert_eq!(
            extract_domain("http://localhost:4873"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_has_rules() {
        let empty = RegistryPolicy::from_config(&RegistryPolicyConfig::default());
        assert!(!empty.has_rules());

        let with_block = RegistryPolicy::from_config(&RegistryPolicyConfig {
            block: vec!["evil.com".to_string()],
            ..Default::default()
        });
        assert!(with_block.has_rules());
    }
}
