//! Input validation for package names, versions, and paths.
//!
//! This module provides strict validation for user-supplied inputs to prevent
//! security vulnerabilities including:
//!
//! - **SSRF (Server-Side Request Forgery)**: Package names containing URL characters
//!   could be used to construct malicious URLs
//! - **Path Traversal**: Package names or paths containing `..` or absolute paths
//!   could access files outside the intended directory
//! - **Command Injection**: Package names containing shell metacharacters could
//!   be used in command injection attacks
//!
//! # Security Model
//!
//! All validation functions are designed to be conservative:
//! - They reject anything that looks suspicious
//! - They use allowlists rather than blocklists
//! - They are case-insensitive where appropriate
//!
//! # Usage
//!
//! ```ignore
//! use cratons_core::validation::{validate_package_name, validate_path_component};
//!
//! // Validate before using in URLs
//! validate_package_name("lodash", Ecosystem::Npm)?;
//!
//! // Validate before using in file paths
//! validate_path_component("my-package")?;
//! ```

use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

use crate::{CratonsError, Ecosystem, Result};

/// Maximum length for package names (prevents DoS via huge names).
pub const MAX_PACKAGE_NAME_LENGTH: usize = 214; // npm limit

/// Maximum length for version strings.
pub const MAX_VERSION_LENGTH: usize = 256;

/// Maximum depth for nested scopes/namespaces.
pub const MAX_SCOPE_DEPTH: usize = 5;

// Pre-compiled regex patterns for efficient validation
static NPM_PACKAGE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // npm package names: optional scope + name
    // Scope: @[a-z0-9-._]+
    // Name: [a-z0-9-._]+
    // Allows: lodash, @types/node, @scope/pkg-name
    Regex::new(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$").unwrap()
});

static PYPI_PACKAGE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // PyPI package names: alphanumeric with hyphens, underscores, dots
    // PEP 503 normalized: lowercase, hyphens replace underscores/dots
    Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$").unwrap()
});

static CRATES_PACKAGE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // crates.io: alphanumeric with hyphens and underscores
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9_-]*$").unwrap()
});

static GO_MODULE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Go modules: domain/path format
    // Examples: github.com/gin-gonic/gin, golang.org/x/sync
    Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*(\.[a-zA-Z0-9][a-zA-Z0-9._-]*)+(/[a-zA-Z0-9][a-zA-Z0-9._-]*)*$").unwrap()
});

static MAVEN_COORDINATE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Maven coordinates: groupId:artifactId
    // Examples: org.apache.commons:commons-lang3
    Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*(\.[a-zA-Z0-9][a-zA-Z0-9._-]*)*(:[a-zA-Z0-9][a-zA-Z0-9._-]*)?$").unwrap()
});

static PATH_COMPONENT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Safe path component: alphanumeric with limited punctuation
    // Explicitly disallows: / \ : * ? " < > | ..
    Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._@-]*$").unwrap()
});

static VERSION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Permissive version pattern: semver-like with pre-release and build metadata
    Regex::new(r"^[0-9a-zA-Z][0-9a-zA-Z._+-]*$").unwrap()
});

/// Characters that are dangerous in URLs and could enable SSRF.
const DANGEROUS_URL_CHARS: &[char] = &[
    '/', '\\', '?', '#', '@', ':', '%', '[', ']', '{', '}', '|', '^', '`', '<', '>', ' ', '\t',
    '\n', '\r', '\0',
];

/// Characters that are dangerous in shell commands.
const DANGEROUS_SHELL_CHARS: &[char] = &[
    ';', '&', '|', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '!', '*', '?', '~', '\n',
    '\r', '\0',
];

/// Validate a package name for the given ecosystem.
///
/// # Security
///
/// This function prevents SSRF attacks by ensuring package names cannot
/// be used to construct URLs pointing to internal services.
///
/// # Arguments
///
/// * `name` - The package name to validate
/// * `ecosystem` - The ecosystem the package belongs to
///
/// # Returns
///
/// `Ok(())` if the name is valid, `Err` with details otherwise.
///
/// # Examples
///
/// ```ignore
/// use cratons_core::{Ecosystem, validation::validate_package_name};
///
/// // Valid names
/// validate_package_name("lodash", Ecosystem::Npm).unwrap();
/// validate_package_name("@types/node", Ecosystem::Npm).unwrap();
/// validate_package_name("requests", Ecosystem::PyPi).unwrap();
///
/// // Invalid names (SSRF attempts)
/// validate_package_name("localhost/evil", Ecosystem::Npm).is_err();
/// validate_package_name("169.254.169.254", Ecosystem::Npm).is_err();
/// ```
pub fn validate_package_name(name: &str, ecosystem: Ecosystem) -> Result<()> {
    // Check length limits
    if name.is_empty() {
        return Err(CratonsError::InvalidPackage {
            message: "package name cannot be empty".to_string(),
        });
    }
    if name.len() > MAX_PACKAGE_NAME_LENGTH {
        return Err(CratonsError::InvalidPackage {
            message: format!(
                "package name exceeds maximum length of {} characters",
                MAX_PACKAGE_NAME_LENGTH
            ),
        });
    }

    // Check for dangerous URL characters that could enable SSRF
    for c in DANGEROUS_URL_CHARS {
        // Allow @ for npm scopes, / for npm scoped packages, Go modules, and Maven
        if *c == '@' && matches!(ecosystem, Ecosystem::Npm) {
            continue;
        }
        if *c == '/' && matches!(ecosystem, Ecosystem::Npm | Ecosystem::Go | Ecosystem::Maven) {
            continue;
        }
        if *c == ':' && matches!(ecosystem, Ecosystem::Maven) {
            continue;
        }
        if name.contains(*c) {
            return Err(CratonsError::InvalidPackage {
                message: format!(
                    "package name contains disallowed character '{}'",
                    c.escape_default()
                ),
            });
        }
    }

    // Check for path traversal
    if name.contains("..") {
        return Err(CratonsError::InvalidPackage {
            message: "package name cannot contain '..' (path traversal)".to_string(),
        });
    }

    // Check for absolute paths
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(CratonsError::InvalidPackage {
            message: "package name cannot be an absolute path".to_string(),
        });
    }

    // Check for localhost/internal IP addresses (SSRF prevention)
    let lower = name.to_lowercase();
    if lower.contains("localhost")
        || lower.contains("127.0.0.")
        || lower.contains("169.254.")  // AWS metadata
        || lower.contains("10.0.")
        || lower.contains("172.16.")
        || lower.contains("192.168.")
        || lower.contains("::1")
        || lower.contains("0.0.0.0")
    {
        return Err(CratonsError::InvalidPackage {
            message: "package name appears to reference internal network".to_string(),
        });
    }

    // Ecosystem-specific validation
    let valid = match ecosystem {
        Ecosystem::Npm => NPM_PACKAGE_PATTERN.is_match(name),
        Ecosystem::PyPi => PYPI_PACKAGE_PATTERN.is_match(name),
        Ecosystem::Crates => CRATES_PACKAGE_PATTERN.is_match(name),
        Ecosystem::Go => GO_MODULE_PATTERN.is_match(name),
        Ecosystem::Maven => MAVEN_COORDINATE_PATTERN.is_match(name),
        // URL ecosystem uses URL validation, not package name patterns
        // The name is the URL itself, which has already passed SSRF checks above
        Ecosystem::Url => true,
    };

    if !valid {
        return Err(CratonsError::InvalidPackage {
            message: format!(
                "package name '{}' does not match {} naming rules",
                name, ecosystem
            ),
        });
    }

    Ok(())
}

/// Validate a version string.
///
/// # Security
///
/// Version strings are used in URLs and file paths, so they must be validated
/// to prevent injection attacks.
pub fn validate_version(version: &str) -> Result<()> {
    if version.is_empty() {
        return Err(CratonsError::InvalidVersion {
            version: version.to_string(),
            message: "version cannot be empty".to_string(),
        });
    }
    if version.len() > MAX_VERSION_LENGTH {
        return Err(CratonsError::InvalidVersion {
            version: version.to_string(),
            message: format!("version exceeds maximum length of {MAX_VERSION_LENGTH}"),
        });
    }

    // Check for dangerous characters
    for c in DANGEROUS_URL_CHARS {
        if version.contains(*c) {
            return Err(CratonsError::InvalidVersion {
                version: version.to_string(),
                message: format!(
                    "version contains disallowed character '{}'",
                    c.escape_default()
                ),
            });
        }
    }

    // Check for path traversal
    if version.contains("..") {
        return Err(CratonsError::InvalidVersion {
            version: version.to_string(),
            message: "version cannot contain '..' (path traversal)".to_string(),
        });
    }

    if !VERSION_PATTERN.is_match(version) {
        return Err(CratonsError::InvalidVersion {
            version: version.to_string(),
            message: "version does not match expected format".to_string(),
        });
    }

    Ok(())
}

/// Validate a path component for safe filesystem operations.
///
/// # Security
///
/// This function ensures a path component cannot be used for path traversal
/// or to access files outside the intended directory.
pub fn validate_path_component(component: &str) -> Result<()> {
    if component.is_empty() {
        return Err(CratonsError::InvalidPath {
            path: component.to_string(),
            message: "path component cannot be empty".to_string(),
        });
    }

    // Reject current and parent directory references
    if component == "." || component == ".." {
        return Err(CratonsError::InvalidPath {
            path: component.to_string(),
            message: "path component cannot be '.' or '..'".to_string(),
        });
    }

    // Check for path separators
    if component.contains('/') || component.contains('\\') {
        return Err(CratonsError::InvalidPath {
            path: component.to_string(),
            message: "path component cannot contain path separators".to_string(),
        });
    }

    // Check for null bytes
    if component.contains('\0') {
        return Err(CratonsError::InvalidPath {
            path: component.to_string(),
            message: "path component cannot contain null bytes".to_string(),
        });
    }

    // Use allowlist pattern
    if !PATH_COMPONENT_PATTERN.is_match(component) {
        return Err(CratonsError::InvalidPath {
            path: component.to_string(),
            message: "path component contains disallowed characters".to_string(),
        });
    }

    Ok(())
}

/// Validate and sanitize a file path for safe filesystem operations.
///
/// # Security
///
/// This function canonicalizes paths and ensures they don't escape
/// the given base directory.
///
/// # Arguments
///
/// * `path` - The path to validate
/// * `base` - The base directory that the path must stay within
///
/// # Returns
///
/// The canonicalized path if valid, or an error if the path escapes
/// the base directory.
pub fn validate_path_within_base(path: &Path, base: &Path) -> Result<std::path::PathBuf> {
    // Canonicalize both paths to resolve symlinks and relative components
    let canonical_base = base.canonicalize().map_err(|e| CratonsError::InvalidPath {
        path: base.display().to_string(),
        message: format!("failed to canonicalize base path: {e}"),
    })?;

    // For the target path, we need to handle the case where it doesn't exist yet
    // We canonicalize the parent and then append the filename
    let canonical_path = if path.exists() {
        path.canonicalize().map_err(|e| CratonsError::InvalidPath {
            path: path.display().to_string(),
            message: format!("failed to canonicalize path: {e}"),
        })?
    } else {
        // Path doesn't exist - canonicalize parent and append filename
        let parent = path.parent().ok_or_else(|| CratonsError::InvalidPath {
            path: path.display().to_string(),
            message: "path has no parent".to_string(),
        })?;

        let filename = path.file_name().ok_or_else(|| CratonsError::InvalidPath {
            path: path.display().to_string(),
            message: "path has no filename".to_string(),
        })?;

        // Validate filename
        if let Some(name) = filename.to_str() {
            if name.contains("..") || name.contains('\0') {
                return Err(CratonsError::InvalidPath {
                    path: path.display().to_string(),
                    message: "filename contains disallowed characters".to_string(),
                });
            }
        }

        let canonical_parent = parent
            .canonicalize()
            .map_err(|e| CratonsError::InvalidPath {
                path: parent.display().to_string(),
                message: format!("failed to canonicalize parent: {e}"),
            })?;

        canonical_parent.join(filename)
    };

    // Check that the path is within the base
    if !canonical_path.starts_with(&canonical_base) {
        return Err(CratonsError::InvalidPath {
            path: path.display().to_string(),
            message: format!(
                "path escapes base directory: {} is not within {}",
                canonical_path.display(),
                canonical_base.display()
            ),
        });
    }

    Ok(canonical_path)
}

/// Validate a command for safe execution.
///
/// # Security
///
/// This function checks for shell metacharacters that could enable
/// command injection attacks.
pub fn validate_command_arg(arg: &str) -> Result<()> {
    if arg.is_empty() {
        return Err(CratonsError::InvalidConfig {
            message: "command argument cannot be empty".to_string(),
        });
    }

    // Check for shell metacharacters
    for c in DANGEROUS_SHELL_CHARS {
        if arg.contains(*c) {
            return Err(CratonsError::InvalidConfig {
                message: format!(
                    "command argument contains shell metacharacter '{}'",
                    c.escape_default()
                ),
            });
        }
    }

    Ok(())
}

/// URL-encode a string for safe use in URLs.
///
/// # Security
///
/// This function encodes all characters except alphanumerics and `-._~`
/// to prevent URL injection attacks.
#[must_use]
pub fn url_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~' {
            encoded.push(c);
        } else {
            for byte in c.to_string().as_bytes() {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_npm_names() {
        assert!(validate_package_name("lodash", Ecosystem::Npm).is_ok());
        assert!(validate_package_name("@types/node", Ecosystem::Npm).is_ok());
        assert!(validate_package_name("@scope/package", Ecosystem::Npm).is_ok());
        assert!(validate_package_name("my-package", Ecosystem::Npm).is_ok());
        assert!(validate_package_name("my_package", Ecosystem::Npm).is_ok());
        assert!(validate_package_name("my.package", Ecosystem::Npm).is_ok());
    }

    #[test]
    fn test_invalid_npm_names() {
        // Empty
        assert!(validate_package_name("", Ecosystem::Npm).is_err());
        // Path traversal
        assert!(validate_package_name("../evil", Ecosystem::Npm).is_err());
        assert!(validate_package_name("foo/../bar", Ecosystem::Npm).is_err());
        // URL characters
        assert!(validate_package_name("foo?bar", Ecosystem::Npm).is_err());
        assert!(validate_package_name("foo#bar", Ecosystem::Npm).is_err());
        // Internal network (SSRF)
        assert!(validate_package_name("localhost", Ecosystem::Npm).is_err());
        assert!(validate_package_name("127.0.0.1", Ecosystem::Npm).is_err());
        assert!(validate_package_name("169.254.169.254", Ecosystem::Npm).is_err());
    }

    #[test]
    fn test_valid_pypi_names() {
        assert!(validate_package_name("requests", Ecosystem::PyPi).is_ok());
        assert!(validate_package_name("Flask", Ecosystem::PyPi).is_ok());
        assert!(validate_package_name("my-package", Ecosystem::PyPi).is_ok());
        assert!(validate_package_name("my_package", Ecosystem::PyPi).is_ok());
    }

    #[test]
    fn test_valid_go_modules() {
        assert!(validate_package_name("github.com/gin-gonic/gin", Ecosystem::Go).is_ok());
        assert!(validate_package_name("golang.org/x/sync", Ecosystem::Go).is_ok());
    }

    #[test]
    fn test_valid_maven_coordinates() {
        assert!(
            validate_package_name("org.apache.commons:commons-lang3", Ecosystem::Maven).is_ok()
        );
        assert!(validate_package_name("com.google.guava", Ecosystem::Maven).is_ok());
    }

    #[test]
    fn test_version_validation() {
        assert!(validate_version("1.0.0").is_ok());
        assert!(validate_version("1.0.0-beta.1").is_ok());
        assert!(validate_version("1.0.0+build.123").is_ok());

        assert!(validate_version("").is_err());
        assert!(validate_version("../evil").is_err());
        assert!(validate_version("1.0.0?evil").is_err());
    }

    #[test]
    fn test_path_component_validation() {
        assert!(validate_path_component("package").is_ok());
        assert!(validate_path_component("my-package").is_ok());
        assert!(validate_path_component("v1.0.0").is_ok());

        assert!(validate_path_component("").is_err());
        assert!(validate_path_component(".").is_err());
        assert!(validate_path_component("..").is_err());
        assert!(validate_path_component("foo/bar").is_err());
        assert!(validate_path_component("foo\\bar").is_err());
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("@scope/pkg"), "%40scope%2Fpkg");
    }
}
