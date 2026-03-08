//! Maven Central Repository Client
//!
//! Implements the Maven repository protocol for fetching artifact metadata.
//! Repository Layout: <https://maven.apache.org/repositories/metadata.html>
//!
//! # Security
//!
//! All artifact coordinates and versions are validated before being used in URLs
//! to prevent SSRF attacks. See [`cratons_core::validation`] for details.
//!
//! ## XXE Prevention
//!
//! The XML parsing in this module uses a simple string-based parser that does not
//! process DOCTYPE declarations, external entities, or other XML features that
//! could enable XXE (XML External Entity) attacks. This is intentional - we only
//! extract the specific elements we need without using a full XML parser.

use async_trait::async_trait;
use cratons_core::{CratonsError, Ecosystem, Result, validate_package_name, validate_version};
use serde::Deserialize;
use std::collections::BTreeMap;
use tracing::{debug, instrument};

use super::{PackageMetadata, RegistryClient};

/// Maven repository client.
pub struct MavenClient {
    client: reqwest::Client,
    repo_url: String,
    search_url: String,
}

impl MavenClient {
    /// Create a new Maven client with Maven Central.
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            repo_url: "https://repo1.maven.org/maven2".to_string(),
            search_url: "https://search.maven.org/solrsearch/select".to_string(),
        }
    }

    /// Create a new client with a custom repository URL.
    pub fn with_repo(client: reqwest::Client, repo_url: String) -> Self {
        Self {
            client,
            repo_url: repo_url.trim_end_matches('/').to_string(),
            search_url: "https://search.maven.org/solrsearch/select".to_string(),
        }
    }

    /// Parse Maven coordinates from the name.
    /// Expected format: "groupId:artifactId" or "groupId:artifactId:classifier"
    fn parse_coordinates(name: &str) -> Result<(String, String, Option<String>)> {
        let parts: Vec<&str> = name.split(':').collect();
        match parts.len() {
            2 => Ok((parts[0].to_string(), parts[1].to_string(), None)),
            3 => Ok((
                parts[0].to_string(),
                parts[1].to_string(),
                Some(parts[2].to_string()),
            )),
            _ => Err(CratonsError::Manifest(format!(
                "Invalid Maven coordinates '{}'. Expected 'groupId:artifactId' or 'groupId:artifactId:classifier'",
                name
            ))),
        }
    }

    /// Convert groupId to path format (dots -> slashes).
    fn group_to_path(group_id: &str) -> String {
        group_id.replace('.', "/")
    }

    /// Build the base path for an artifact.
    fn artifact_path(group_id: &str, artifact_id: &str) -> String {
        format!("{}/{}", Self::group_to_path(group_id), artifact_id)
    }

    /// Build the URL for maven-metadata.xml.
    fn metadata_url(&self, group_id: &str, artifact_id: &str) -> String {
        format!(
            "{}/{}/maven-metadata.xml",
            self.repo_url,
            Self::artifact_path(group_id, artifact_id)
        )
    }

    /// Build the URL for a POM file.
    fn pom_url(&self, group_id: &str, artifact_id: &str, version: &str) -> String {
        format!(
            "{}/{}/{}/{}-{}.pom",
            self.repo_url,
            Self::artifact_path(group_id, artifact_id),
            version,
            artifact_id,
            version
        )
    }

    /// Build the URL for a JAR file.
    fn jar_url(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        classifier: Option<&str>,
    ) -> String {
        let classifier_suffix = classifier.map(|c| format!("-{}", c)).unwrap_or_default();
        format!(
            "{}/{}/{}/{}-{}{}.jar",
            self.repo_url,
            Self::artifact_path(group_id, artifact_id),
            version,
            artifact_id,
            version,
            classifier_suffix
        )
    }

    /// Parse maven-metadata.xml to extract versions.
    fn parse_metadata_xml(xml: &str) -> Result<Vec<String>> {
        // Simple XML parsing for versions
        // Full XML: <metadata><versioning><versions><version>1.0</version>...</versions></versioning></metadata>

        let mut versions = Vec::new();
        let mut in_versions = false;

        for line in xml.lines() {
            let line = line.trim();

            if line.contains("<versions>") {
                in_versions = true;
            } else if line.contains("</versions>") {
                in_versions = false;
            } else if in_versions && line.starts_with("<version>") {
                // Extract version from <version>x.y.z</version>
                if let Some(start) = line.find("<version>") {
                    if let Some(end) = line.find("</version>") {
                        let version = &line[start + 9..end];
                        versions.push(version.to_string());
                    }
                }
            }
        }

        Ok(versions)
    }

    /// Parse POM XML to extract dependencies.
    fn parse_pom_dependencies(xml: &str) -> BTreeMap<String, String> {
        let mut deps = BTreeMap::new();

        // Simple state machine for parsing dependencies
        // Full structure: <dependencies><dependency><groupId>...</groupId><artifactId>...</artifactId><version>...</version></dependency></dependencies>

        let mut in_dependencies = false;
        let mut in_dependency = false;
        let mut in_dependency_management = false;
        let mut current_group = String::new();
        let mut current_artifact = String::new();
        let mut current_version = String::new();
        let mut current_scope = String::new();

        for line in xml.lines() {
            let line = line.trim();

            // Skip dependencyManagement section
            if line.contains("<dependencyManagement>") {
                in_dependency_management = true;
            } else if line.contains("</dependencyManagement>") {
                in_dependency_management = false;
            }

            if in_dependency_management {
                continue;
            }

            if line.contains("<dependencies>") {
                in_dependencies = true;
            } else if line.contains("</dependencies>") {
                in_dependencies = false;
            } else if in_dependencies && line.contains("<dependency>") {
                in_dependency = true;
                current_group.clear();
                current_artifact.clear();
                current_version.clear();
                current_scope.clear();
            } else if in_dependency && line.contains("</dependency>") {
                in_dependency = false;

                // Only include compile/runtime scope (skip test, provided)
                if current_scope.is_empty()
                    || current_scope == "compile"
                    || current_scope == "runtime"
                {
                    if !current_group.is_empty() && !current_artifact.is_empty() {
                        let key = format!("{}:{}", current_group, current_artifact);
                        let version = if current_version.is_empty() {
                            "*".to_string()
                        } else {
                            current_version.clone()
                        };
                        deps.insert(key, version);
                    }
                }
            } else if in_dependency {
                // Extract tag values
                if let Some(value) = Self::extract_xml_value(line, "groupId") {
                    current_group = value;
                } else if let Some(value) = Self::extract_xml_value(line, "artifactId") {
                    current_artifact = value;
                } else if let Some(value) = Self::extract_xml_value(line, "version") {
                    // Handle property references like ${project.version}
                    if !value.starts_with("${") {
                        current_version = value;
                    }
                } else if let Some(value) = Self::extract_xml_value(line, "scope") {
                    current_scope = value;
                }
            }
        }

        deps
    }

    /// Extract value from an XML tag on a single line.
    fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);

        if let Some(start) = line.find(&open) {
            if let Some(end) = line.find(&close) {
                let value = &line[start + open.len()..end];
                return Some(value.to_string());
            }
        }
        None
    }
}

#[async_trait]
impl RegistryClient for MavenClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    fn registry_url(&self) -> &str {
        &self.repo_url
    }

    #[instrument(skip(self), fields(ecosystem = "maven"))]
    async fn fetch_versions(&self, name: &str) -> Result<Vec<String>> {
        // SECURITY: Validate artifact coordinates before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Maven)?;

        let (group_id, artifact_id, _) = Self::parse_coordinates(name)?;
        debug!(
            "Fetching versions for Maven artifact: {}:{}",
            group_id, artifact_id
        );

        let url = self.metadata_url(&group_id, &artifact_id);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to fetch {}: {}", name, e)))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CratonsError::PackageNotFound(name.to_string()));
        }

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "maven".to_string(),
                message: format!("HTTP {}: {}", response.status(), url),
            });
        }

        let xml = response
            .text()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read response: {}", e)))?;

        let mut versions = Self::parse_metadata_xml(&xml)?;

        // Sort by version (ascending for MVS)
        // Maven versions are typically like 1.2.3 or 1.2.3-SNAPSHOT
        versions.sort_by(|a, b| {
            // Simple comparison - prefer non-SNAPSHOT versions (they come first)
            let a_snapshot = a.contains("SNAPSHOT");
            let b_snapshot = b.contains("SNAPSHOT");

            match (a_snapshot, b_snapshot) {
                (true, false) => std::cmp::Ordering::Greater, // b (non-snapshot) first
                (false, true) => std::cmp::Ordering::Less,    // a (non-snapshot) first
                _ => {
                    // Both same type, compare version numbers (ascending for MVS)
                    let va = a.replace("-SNAPSHOT", "").replace('-', ".");
                    let vb = b.replace("-SNAPSHOT", "").replace('-', ".");
                    va.cmp(&vb)
                }
            }
        });

        debug!("Found {} versions for {}", versions.len(), name);
        Ok(versions)
    }

    #[instrument(skip(self), fields(ecosystem = "maven"))]
    async fn fetch_metadata(&self, name: &str, version: &str) -> Result<PackageMetadata> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Maven)?;
        validate_version(version)?;

        let (group_id, artifact_id, classifier) = Self::parse_coordinates(name)?;
        debug!(
            "Fetching metadata for {}:{}@{}",
            group_id, artifact_id, version
        );

        // Fetch POM for dependency information
        let pom_url = self.pom_url(&group_id, &artifact_id, version);
        let pom_response = self
            .client
            .get(&pom_url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to fetch POM: {}", e)))?;

        if pom_response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CratonsError::VersionNotFound {
                package: name.to_string(),
                version: version.to_string(),
            });
        }

        let dependencies = if pom_response.status().is_success() {
            let pom_xml = pom_response
                .text()
                .await
                .map_err(|e| CratonsError::Network(format!("Failed to read POM: {}", e)))?;
            Self::parse_pom_dependencies(&pom_xml)
        } else {
            BTreeMap::new()
        };

        // Get JAR URL and check for SHA1 checksum
        let jar_url = self.jar_url(&group_id, &artifact_id, version, classifier.as_deref());
        let sha1_url = format!("{}.sha1", jar_url);

        // Try to fetch SHA1 checksum
        let integrity = if let Ok(response) = self.client.get(&sha1_url).send().await {
            if response.status().is_success() {
                if let Ok(sha1) = response.text().await {
                    format!("sha1-{}", sha1.trim())
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        Ok(PackageMetadata {
            name: format!("{}:{}", group_id, artifact_id),
            version: version.to_string(),
            dist_url: jar_url,
            integrity,
            dependencies,
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
            peer_dependencies_meta: BTreeMap::new(),
            dev_dependencies: BTreeMap::new(),
            bundled_dependencies: Vec::new(),
            features: Vec::new(),
            feature_definitions: BTreeMap::new(),
        })
    }

    #[instrument(skip(self), fields(ecosystem = "maven"))]
    async fn download(&self, name: &str, version: &str) -> Result<Vec<u8>> {
        // SECURITY: Validate inputs before using in URL to prevent SSRF
        validate_package_name(name, Ecosystem::Maven)?;
        validate_version(version)?;

        let (group_id, artifact_id, classifier) = Self::parse_coordinates(name)?;
        debug!("Downloading {}:{}@{}", group_id, artifact_id, version);

        let url = self.jar_url(&group_id, &artifact_id, version, classifier.as_deref());

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to download: {}", e)))?;

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "maven".to_string(),
                message: format!("Failed to download {}: HTTP {}", url, response.status()),
            });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| CratonsError::Network(format!("Failed to read JAR: {}", e)))?;

        debug!("Downloaded {} bytes for {}@{}", bytes.len(), name, version);
        Ok(bytes.to_vec())
    }

    #[instrument(skip(self), fields(ecosystem = "maven"))]
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<String>> {
        debug!("Searching Maven Central for: {}", query);

        let url = format!(
            "{}?q={}&rows={}&wt=json",
            self.search_url,
            urlencoding::encode(query),
            limit.min(200)
        );

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| CratonsError::Network(format!("Search failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(CratonsError::Registry {
                registry: "maven".to_string(),
                message: format!("Search failed: HTTP {}", response.status()),
            });
        }

        #[derive(Deserialize)]
        struct SearchResponse {
            response: SearchResponseInner,
        }

        #[derive(Deserialize)]
        struct SearchResponseInner {
            docs: Vec<SearchDoc>,
        }

        #[derive(Deserialize)]
        struct SearchDoc {
            g: String, // groupId
            a: String, // artifactId
        }

        let search_response: SearchResponse =
            response.json().await.map_err(|e| CratonsError::Registry {
                registry: "maven".to_string(),
                message: format!("Failed to parse search results: {}", e),
            })?;

        Ok(search_response
            .response
            .docs
            .into_iter()
            .map(|d| format!("{}:{}", d.g, d.a))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_coordinates() {
        let (g, a, c) = MavenClient::parse_coordinates("org.apache.commons:commons-lang3").unwrap();
        assert_eq!(g, "org.apache.commons");
        assert_eq!(a, "commons-lang3");
        assert!(c.is_none());

        let (g, a, c) =
            MavenClient::parse_coordinates("io.netty:netty-transport:linux-x86_64").unwrap();
        assert_eq!(g, "io.netty");
        assert_eq!(a, "netty-transport");
        assert_eq!(c, Some("linux-x86_64".to_string()));

        assert!(MavenClient::parse_coordinates("invalid").is_err());
    }

    #[test]
    fn test_group_to_path() {
        assert_eq!(
            MavenClient::group_to_path("org.apache.commons"),
            "org/apache/commons"
        );
        assert_eq!(MavenClient::group_to_path("io.netty"), "io/netty");
    }

    #[test]
    fn test_parse_metadata_xml() {
        let xml = r#"
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <versioning>
    <latest>3.14.0</latest>
    <release>3.14.0</release>
    <versions>
      <version>3.12.0</version>
      <version>3.13.0</version>
      <version>3.14.0</version>
    </versions>
  </versioning>
</metadata>
"#;

        let versions = MavenClient::parse_metadata_xml(xml).unwrap();
        assert_eq!(versions, vec!["3.12.0", "3.13.0", "3.14.0"]);
    }

    #[test]
    fn test_parse_pom_dependencies() {
        let pom = r#"
<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.0</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.9</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.1.3-jre</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>
"#;

        let deps = MavenClient::parse_pom_dependencies(pom);

        // Test scope should be excluded
        assert!(!deps.contains_key("org.junit.jupiter:junit-jupiter"));

        // Compile scope should be included
        assert_eq!(deps.get("org.slf4j:slf4j-api"), Some(&"2.0.9".to_string()));
        assert_eq!(
            deps.get("com.google.guava:guava"),
            Some(&"32.1.3-jre".to_string())
        );
    }
}
