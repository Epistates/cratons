//! Security policy enforcement using Cedar.

use crate::{AuditResult, Severity};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema,
};
use cratons_core::{Ecosystem, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;

/// A security policy violation.
#[derive(Debug, Clone)]
pub struct PolicyViolation {
    /// The package that violated the policy
    pub package: String,
    /// The version of the package
    pub version: String,
    /// The specific reasons (if provided by policy annotations/messages)
    pub reasons: Vec<String>,
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Package '{}@{}' denied by policy",
            self.package, self.version
        )?;
        if !self.reasons.is_empty() {
            write!(f, ": {}", self.reasons.join(", "))?;
        }
        Ok(())
    }
}

/// The Security Policy Engine.
#[derive(Debug)]
pub struct PolicyEngine {
    #[allow(dead_code)]
    policy_set: PolicySet,
    #[allow(dead_code)]
    schema: Schema,
}

impl PolicyEngine {
    /// Load policy from a `.cedar` file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Create engine from Cedar policy string.
    pub fn from_str(policy_src: &str) -> Result<Self> {
        let policy_set = PolicySet::from_str(policy_src).map_err(|e| {
            cratons_core::CratonsError::Config(format!("Failed to parse Cedar policy: {}", e))
        })?;

        // We use a predefined schema for Cratons packages
        // Note: Cedar schema must define actions separately from entities
        let schema_src = r#"
namespace Cratons {
    entity User;
    entity Package {
        name: String,
        ecosystem: String,
        registry: String,
        version: String,
        max_severity: Long,
        vulnerabilities: Set<String>
    };
    action install appliesTo {
        principal: User,
        resource: Package
    };
    action audit appliesTo {
        principal: User,
        resource: Package
    };
}
"#;

        let schema = Schema::from_str(schema_src).map_err(|e| {
            cratons_core::CratonsError::Config(format!("Failed to parse Cedar schema: {}", e))
        })?;

        Ok(Self { policy_set, schema })
    }

    /// M-12 FIX: Check package metadata against security policy BEFORE installation.
    ///
    /// This method allows checking security policy during resolution/download phase,
    /// before any packages are installed. This prevents downloading or installing
    /// packages that would violate security policy.
    ///
    /// # Arguments
    /// * `package_name` - The package name
    /// * `version` - The package version
    /// * `ecosystem` - The package ecosystem
    /// * `vulnerabilities` - Known vulnerabilities for this package (from OSV/advisory lookup)
    /// * `max_severity` - Maximum severity of known vulnerabilities (0=none, 1=low, 2=medium, 3=high, 4=critical)
    ///
    /// # Returns
    /// * `Ok(None)` - Package is allowed by policy
    /// * `Ok(Some(violation))` - Package is denied by policy
    pub fn check_pre_install(
        &self,
        package_name: &str,
        version: &str,
        ecosystem: Ecosystem,
        vulnerabilities: &[String],
        max_severity: i64,
    ) -> Result<Option<PolicyViolation>> {
        let authorizer = Authorizer::new();

        // Cedar Entity ID: Package::"ecosystem:name"
        let resource_uid = EntityUid::from_type_name_and_id(
            "Cratons::Package".parse().unwrap(),
            EntityId::from_str(&format!("{}:{}", ecosystem, package_name))
                .unwrap_or_else(|_| EntityId::from_str("generic_package").unwrap()),
        );

        // Attributes
        let mut attrs = HashMap::new();

        fn mk_str(s: &str) -> RestrictedExpression {
            let escaped = s.replace('"', "\"");
            RestrictedExpression::from_str(&format!("\"{}\"", escaped)).unwrap()
        }

        fn mk_long(i: i64) -> RestrictedExpression {
            RestrictedExpression::from_str(&i.to_string()).unwrap()
        }

        attrs.insert("name".to_string(), mk_str(package_name));
        attrs.insert("ecosystem".to_string(), mk_str(&ecosystem.to_string()));
        attrs.insert("registry".to_string(), mk_str(ecosystem.default_registry()));
        attrs.insert("version".to_string(), mk_str(version));
        attrs.insert("max_severity".to_string(), mk_long(max_severity));

        // Set of vulnerabilities
        let vuln_list: Vec<String> = vulnerabilities
            .iter()
            .map(|v| format!("\"{}\"", v.replace('"', "\"")))
            .collect();
        let vuln_set_str = format!("[{}]", vuln_list.join(", "));
        let vuln_expr = RestrictedExpression::from_str(&vuln_set_str).unwrap();
        attrs.insert("vulnerabilities".to_string(), vuln_expr);

        // Create Entity
        let entity = Entity::new(resource_uid.clone(), attrs, HashSet::new()).map_err(|e| {
            cratons_core::CratonsError::Config(format!("Failed to create entity: {}", e))
        })?;

        let entities = Entities::from_entities(vec![entity], Some(&self.schema)).map_err(|e| {
            cratons_core::CratonsError::Config(format!("Failed to create entities: {}", e))
        })?;

        // Make Request
        let principal = EntityUid::from_type_name_and_id(
            "Cratons::User".parse().unwrap(),
            "pre_install_check".parse().unwrap(),
        );
        let action = EntityUid::from_type_name_and_id(
            "Cratons::Action".parse().unwrap(),
            "install".parse().unwrap(),
        );

        let request = Request::new(
            principal,
            action,
            resource_uid,
            Context::empty(),
            Some(&self.schema),
        )
        .map_err(|e| {
            cratons_core::CratonsError::Config(format!("Failed to create request: {}", e))
        })?;

        // Authorize
        let response = authorizer.is_authorized(&request, &self.policy_set, &entities);

        if response.decision() == Decision::Deny {
            let reasons: Vec<String> = response
                .diagnostics()
                .reason()
                .map(|r| format!("Policy ID: {}", r))
                .collect();

            Ok(Some(PolicyViolation {
                package: package_name.to_string(),
                version: version.to_string(),
                reasons,
            }))
        } else {
            Ok(None)
        }
    }

    /// Check the audit result and lockfile against the policy (post-install check).
    pub fn check(
        &self,
        lockfile: &cratons_lockfile::Lockfile,
        audit: &AuditResult,
    ) -> Result<Vec<PolicyViolation>> {
        let mut violations = Vec::new();
        let authorizer = Authorizer::new();

        // 1. Map vulnerabilities for quick lookup
        // Package Key -> Max Severity (numeric)
        let mut package_vulns: HashMap<(String, Ecosystem), i64> = HashMap::new();
        let mut vuln_ids: HashMap<(String, Ecosystem), HashSet<String>> = HashMap::new();

        for vuln in &audit.vulnerabilities {
            let key = (vuln.package.clone(), vuln.ecosystem);

            let severity_score = match vuln.severity {
                Severity::Critical => 4,
                Severity::High => 3,
                Severity::Medium => 2,
                Severity::Low => 1,
            };

            let current = package_vulns.entry(key.clone()).or_insert(0);
            if severity_score > *current {
                *current = severity_score;
            }

            vuln_ids.entry(key).or_default().insert(vuln.id.clone());
        }

        // 2. Iterate over all packages in lockfile
        for pkg in &lockfile.packages {
            // Construct Entity for the package
            let key = (pkg.name.clone(), pkg.ecosystem);
            let max_severity = *package_vulns.get(&key).unwrap_or(&0);
            let vulns = vuln_ids.get(&key).cloned().unwrap_or_default();

            // Cedar Entity ID: Package::"ecosystem:name" (sanitized)
            let resource_uid = EntityUid::from_type_name_and_id(
                "Cratons::Package".parse().unwrap(),
                EntityId::from_str(&format!("{}:{}", pkg.ecosystem, pkg.name))
                    .unwrap_or_else(|_| EntityId::from_str("generic_package").unwrap()),
            );

            // Attributes
            let mut attrs = HashMap::new();

            // Helper to create expressions safely
            fn mk_str(s: &str) -> RestrictedExpression {
                // Escape string for Cedar syntax
                let escaped = s.replace('"', "\"");
                RestrictedExpression::from_str(&format!("\"{}\"", escaped)).unwrap()
            }

            fn mk_long(i: i64) -> RestrictedExpression {
                RestrictedExpression::from_str(&i.to_string()).unwrap()
            }

            attrs.insert("name".to_string(), mk_str(&pkg.name));
            attrs.insert("ecosystem".to_string(), mk_str(&pkg.ecosystem.to_string()));
            attrs.insert("registry".to_string(), mk_str(&pkg.source));
            attrs.insert("version".to_string(), mk_str(&pkg.version));
            attrs.insert("max_severity".to_string(), mk_long(max_severity));

            // Set of vulnerabilities
            let vuln_list: Vec<String> = vulns
                .into_iter()
                .map(|v| format!("\"{}\"", v.replace('"', "\"")))
                .collect();
            let vuln_set_str = format!("[{}]", vuln_list.join(", "));
            let vuln_expr = RestrictedExpression::from_str(&vuln_set_str).unwrap();

            attrs.insert("vulnerabilities".to_string(), vuln_expr);

            // Create Entity
            let entity = Entity::new(resource_uid.clone(), attrs, HashSet::new()).map_err(|e| {
                cratons_core::CratonsError::Config(format!("Failed to create entity: {}", e))
            })?;

            let entities =
                Entities::from_entities(vec![entity], Some(&self.schema)).map_err(|e| {
                    cratons_core::CratonsError::Config(format!(
                        "Failed to create entities: {}",
                        e
                    ))
                })?;

            // 3. Make Request
            // Principal: User::"audit_cli"
            // Action: Action::"audit"
            // Resource: Package::<id>
            let principal = EntityUid::from_type_name_and_id(
                "Cratons::User".parse().unwrap(),
                "audit_cli".parse().unwrap(),
            );
            let action = EntityUid::from_type_name_and_id(
                "Cratons::Action".parse().unwrap(),
                "audit".parse().unwrap(),
            );

            let request = Request::new(
                principal,
                action,
                resource_uid,
                Context::empty(),
                Some(&self.schema),
            )
            .map_err(|e| {
                cratons_core::CratonsError::Config(format!("Failed to create request: {}", e))
            })?;

            // 4. Authorize
            let response = authorizer.is_authorized(&request, &self.policy_set, &entities);

            if response.decision() == Decision::Deny {
                // Collect reasons
                let reasons: Vec<String> = response
                    .diagnostics()
                    .reason()
                    .map(|r| format!("Policy ID: {}", r))
                    .collect();

                violations.push(PolicyViolation {
                    package: pkg.name.clone(),
                    version: pkg.version.clone(),
                    reasons,
                });
            }
        }

        Ok(violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_violation_display() {
        let violation = PolicyViolation {
            package: "lodash".to_string(),
            version: "4.17.0".to_string(),
            reasons: vec![],
        };
        assert_eq!(
            violation.to_string(),
            "Package 'lodash@4.17.0' denied by policy"
        );

        let violation_with_reasons = PolicyViolation {
            package: "lodash".to_string(),
            version: "4.17.0".to_string(),
            reasons: vec!["has_critical_vuln".to_string()],
        };
        assert_eq!(
            violation_with_reasons.to_string(),
            "Package 'lodash@4.17.0' denied by policy: has_critical_vuln"
        );
    }

    #[test]
    fn test_policy_violation_multiple_reasons() {
        let violation = PolicyViolation {
            package: "axios".to_string(),
            version: "0.21.0".to_string(),
            reasons: vec![
                "critical_vulnerability".to_string(),
                "deprecated_package".to_string(),
            ],
        };
        assert_eq!(
            violation.to_string(),
            "Package 'axios@0.21.0' denied by policy: critical_vulnerability, deprecated_package"
        );
    }

    #[test]
    fn test_policy_engine_invalid_policy() {
        let invalid_policy = "this is not valid cedar syntax";
        let result = PolicyEngine::from_str(invalid_policy);
        assert!(result.is_err(), "Should fail on invalid policy");
        assert!(
            result.unwrap_err().to_string().contains("Cedar policy"),
            "Error should mention Cedar policy"
        );
    }

    #[test]
    fn test_policy_load_nonexistent_file() {
        let result = PolicyEngine::load("/nonexistent/path/to/policy.cedar");
        assert!(result.is_err(), "Should fail when file doesn't exist");
    }

    // NOTE: Integration tests for PolicyEngine.check() require proper Cedar schema configuration.
    // The Cedar policy engine requires specific entity types and action definitions.
    // Full integration tests should use the actual cratons Cedar schema.

    #[test]
    fn test_pre_install_check_allow() {
        // A permissive policy that allows everything
        let policy = r#"
permit(
    principal,
    action,
    resource
);
"#;
        let engine = PolicyEngine::from_str(policy).unwrap();

        // Should allow a package with no vulnerabilities
        let result = engine.check_pre_install(
            "lodash",
            "4.17.21",
            cratons_core::Ecosystem::Npm,
            &[],
            0, // No severity
        );

        assert!(result.is_ok());
        assert!(
            result.unwrap().is_none(),
            "Should allow package with no vulnerabilities"
        );
    }

    #[test]
    fn test_pre_install_check_deny_critical() {
        // A policy that denies packages with critical vulnerabilities (max_severity >= 4)
        let policy = r#"
forbid(
    principal,
    action,
    resource
) when {
    resource.max_severity >= 4
};
"#;
        let engine = PolicyEngine::from_str(policy).unwrap();

        // Should deny a package with critical vulnerability
        let result = engine.check_pre_install(
            "lodash",
            "4.17.0",
            cratons_core::Ecosystem::Npm,
            &["CVE-2021-23337".to_string()],
            4, // Critical severity
        );

        assert!(result.is_ok());
        let violation = result.unwrap();
        assert!(
            violation.is_some(),
            "Should deny package with critical vulnerability"
        );
        let v = violation.unwrap();
        assert_eq!(v.package, "lodash");
        assert_eq!(v.version, "4.17.0");
    }
}
