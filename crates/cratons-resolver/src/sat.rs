//! SAT solver using `PubGrub` for complex dependency resolution (NPM, `PyPI`).
//!
//! This implementation provides a SOTA hybrid resolver capable of handling
//! both Semantic Versioning (NPM/Cargo) and PEP 440 (Python) within the same
//! resolution graph, leveraging `pubgrub`'s generic solver.

use crate::registry::Registry;
use cratons_core::{CratonsError, Ecosystem, ResolutionStrategy, Result};
use pubgrub::{
    Dependencies, DependencyConstraints, DependencyProvider, PackageResolutionStatistics, Ranges,
    resolve,
};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::str::FromStr;
use std::sync::Arc;
use tokio::runtime::Handle;

/// Error type for the SAT dependency provider.
#[derive(Debug, thiserror::Error)]
pub enum SatResolverError {
    /// Registry or I/O error during resolution.
    #[error("{0}")]
    Registry(#[from] CratonsError),
    /// Generic resolution error.
    #[error("{0}")]
    Other(String),
}

// --- Version Types ---

/// A unified version type that handles both `SemVer` and PEP 440.
///
/// This "super-version" allows the solver to reason about versions from
/// distinct ecosystems simultaneously without type erasure losing comparison logic.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SatVersion {
    /// Semantic Version (NPM, Cargo, etc.)
    SemVer(semver::Version),
    /// PEP 440 Version (Python)
    Pep440(pep440_rs::Version),
    /// Root/Virtual version
    Virtual(u64),
}

impl Display for SatVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SemVer(v) => write!(f, "{v}"),
            Self::Pep440(v) => write!(f, "{v}"),
            Self::Virtual(v) => write!(f, "virtual-{v}"),
        }
    }
}

impl Ord for SatVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::SemVer(a), Self::SemVer(b)) => a.cmp(b),
            (Self::Pep440(a), Self::Pep440(b)) => a.cmp(b),
            (Self::Virtual(a), Self::Virtual(b)) => a.cmp(b),

            // Virtual is lowest, SemVer < Pep440
            (Self::Virtual(_), _) | (Self::SemVer(_), Self::Pep440(_)) => Ordering::Less,
            (_, Self::Virtual(_)) | (Self::Pep440(_), Self::SemVer(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for SatVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// --- Package Types ---

/// A package in the `PubGrub` solver.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SatPackage {
    name: String,
    ecosystem: Ecosystem,
}

impl Display for SatPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ecosystem, self.name)
    }
}

impl PartialOrd for SatPackage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SatPackage {
    fn cmp(&self, other: &Self) -> Ordering {
        // Ecosystem first, then name
        match self.ecosystem.to_string().cmp(&other.ecosystem.to_string()) {
            Ordering::Equal => self.name.cmp(&other.name),
            ord => ord,
        }
    }
}

// --- Resolver ---

/// The SAT resolver.
pub struct SatResolver {
    registry: Arc<Registry>,
}

impl SatResolver {
    /// Create a new SAT resolver instance.
    pub const fn new(registry: Arc<Registry>) -> Self {
        Self { registry }
    }

    /// Resolve dependencies using `PubGrub` for multiple ecosystems simultaneously.
    ///
    /// # Errors
    ///
    /// Returns an error if resolution fails or if there is a system error.
    pub async fn resolve_multi(
        &self,
        root_deps: Vec<(String, String, Ecosystem)>,
        strategies: BTreeMap<Ecosystem, ResolutionStrategy>,
    ) -> Result<BTreeMap<(String, Ecosystem), String>> {
        // Use Npm as the "host" ecosystem for root, but it doesn't matter
        // as long as the name is unique.
        let root_package = SatPackage {
            name: "__root__".to_string(),
            ecosystem: Ecosystem::Npm,
        };

        let root_version = SatVersion::Virtual(1);
        let registry = self.registry.clone();
        let handle = Handle::current();

        // Run solver in blocking task to allow inner block_on calls
        let solution = tokio::task::spawn_blocking(move || {
            let provider = SatDependencyProvider {
                registry,
                root_deps,
                root_package: root_package.clone(),
                handle,
                strategies,
            };

            resolve(&provider, root_package, root_version)
                .map_err(|e| CratonsError::Config(format!("PubGrub resolution failed: {e}")))
        })
        .await
        .map_err(|e| CratonsError::Config(format!("Join error in SAT resolver: {e}")))??;

        // Extract results
        let mut result = BTreeMap::new();
        for (pkg, ver) in solution {
            if pkg.name == "__root__" {
                continue;
            }
            result.insert((pkg.name, pkg.ecosystem), ver.to_string());
        }

        Ok(result)
    }
}

// --- Dependency Provider ---

struct SatDependencyProvider {
    registry: Arc<Registry>,
    root_deps: Vec<(String, String, Ecosystem)>,
    root_package: SatPackage,
    handle: Handle,
    strategies: BTreeMap<Ecosystem, ResolutionStrategy>,
}

impl DependencyProvider for SatDependencyProvider {
    type P = SatPackage;
    type V = SatVersion;
    type VS = Ranges<SatVersion>;
    type M = String;
    type Priority = u32;
    type Err = SatResolverError;

    fn prioritize(
        &self,
        package: &SatPackage,
        _range: &Ranges<SatVersion>,
        _stats: &PackageResolutionStatistics,
    ) -> u32 {
        // Root package gets highest priority
        if package == &self.root_package {
            u32::MAX
        } else {
            0
        }
    }

    fn choose_version(
        &self,
        package: &SatPackage,
        range: &Ranges<SatVersion>,
    ) -> std::result::Result<Option<SatVersion>, Self::Err> {
        // Virtual root package logic
        if package == &self.root_package {
            let v = SatVersion::Virtual(1);
            if range.contains(&v) {
                return Ok(Some(v));
            }
            return Ok(None);
        }

        // Fetch versions from registry
        let versions_raw = self.handle.block_on(
            self.registry
                .fetch_versions(package.ecosystem, &package.name),
        )?;

        // Parse versions based on ecosystem
        let mut parsed_versions: Vec<SatVersion> = versions_raw
            .iter()
            .filter_map(|v_str| match package.ecosystem {
                Ecosystem::Npm | Ecosystem::Crates | Ecosystem::Go | Ecosystem::Maven => {
                    semver::Version::parse(v_str).ok().map(SatVersion::SemVer)
                }
                Ecosystem::PyPi => v_str.parse().ok().map(SatVersion::Pep440),
                _ => None,
            })
            .collect();

        // Sort versions
        parsed_versions.sort();

        // Apply ecosystem-specific strategy
        let strategy = self
            .strategies
            .get(&package.ecosystem)
            .copied()
            .unwrap_or(ResolutionStrategy::MaxSatisfying);

        match strategy {
            ResolutionStrategy::MaxSatisfying => {
                let best_version = parsed_versions
                    .into_iter()
                    .rev()
                    .find(|v| range.contains(v));
                Ok(best_version)
            }
            ResolutionStrategy::Minimal => {
                let best_version = parsed_versions.into_iter().find(|v| range.contains(v));
                Ok(best_version)
            }
        }
    }

    fn get_dependencies(
        &self,
        package: &SatPackage,
        version: &SatVersion,
    ) -> std::result::Result<Dependencies<SatPackage, Ranges<SatVersion>, String>, Self::Err> {
        let mut deps = DependencyConstraints::<SatPackage, Ranges<SatVersion>>::default();

        // Root dependencies
        if package == &self.root_package {
            for (name, req, ecosystem) in &self.root_deps {
                let dep_pkg = SatPackage {
                    name: name.clone(),
                    ecosystem: *ecosystem,
                };
                let range = parse_range(*ecosystem, req);
                deps.insert(dep_pkg, range);
            }
            return Ok(Dependencies::Available(deps));
        }

        // Fetch metadata
        let version_str = version.to_string();

        let metadata = self.handle.block_on(self.registry.fetch_metadata(
            package.ecosystem,
            &package.name,
            &version_str,
        ))?;

        // M-16: Create set of bundled dependencies to skip from resolution
        let bundled_set: std::collections::HashSet<&String> =
            metadata.bundled_dependencies.iter().collect();

        // Regular dependencies (excluding bundled)
        for (name, req) in &metadata.dependencies {
            // Skip bundled dependencies - they're included in the package tarball
            if bundled_set.contains(name) {
                continue;
            }
            let dep_pkg = SatPackage {
                name: name.clone(),
                ecosystem: package.ecosystem,
            };
            let range = parse_range(package.ecosystem, req);
            deps.insert(dep_pkg, range);
        }

        // M-16: Add required peer dependencies as hard constraints (npm v7+ semantics)
        // Optional peer deps are NOT added as constraints - they don't fail if missing
        for (name, req) in &metadata.peer_dependencies {
            // Check if this peer dep is optional via peerDependenciesMeta
            let is_optional = metadata
                .peer_dependencies_meta
                .get(name)
                .map(|m| m.optional)
                .unwrap_or(false);

            if !is_optional {
                // Required peer dep - add as hard constraint
                let dep_pkg = SatPackage {
                    name: name.clone(),
                    ecosystem: package.ecosystem,
                };
                let range = parse_range(package.ecosystem, req);
                deps.insert(dep_pkg, range);
            }
            // Optional peer deps are NOT added as constraints
        }

        Ok(Dependencies::Available(deps))
    }
}

// --- Range Parsing ---

/// Parse a version requirement string into a `PubGrub` Range.
fn parse_range(ecosystem: Ecosystem, req: &str) -> Ranges<SatVersion> {
    if req == "*" || req.is_empty() {
        return Ranges::full();
    }

    match ecosystem {
        Ecosystem::Npm | Ecosystem::Crates => semver::VersionReq::parse(req).map_or_else(
            |_| Ranges::full(),
            |semver_req| semver_to_range(&semver_req),
        ),
        Ecosystem::PyPi => req
            .parse::<pep440_rs::VersionSpecifiers>()
            .map_or_else(|_| Ranges::full(), |pep_req| pep440_to_range(&pep_req)),
        _ => Ranges::full(),
    }
}

fn semver_to_range(req: &semver::VersionReq) -> Ranges<SatVersion> {
    let mut final_range = Ranges::full();

    for comparator in &req.comparators {
        let v = SatVersion::SemVer(semver::Version {
            major: comparator.major,
            minor: comparator.minor.unwrap_or(0),
            patch: comparator.patch.unwrap_or(0),
            pre: comparator.pre.clone(),
            build: semver::BuildMetadata::EMPTY,
        });

        let comp_range = match comparator.op {
            semver::Op::Exact => Ranges::singleton(v),
            semver::Op::Greater => Ranges::strictly_higher_than(v),
            semver::Op::GreaterEq => Ranges::higher_than(v),
            semver::Op::Less => Ranges::strictly_lower_than(v),
            semver::Op::LessEq => Ranges::lower_than(v),
            semver::Op::Tilde => {
                // ~1.2.3 := >=1.2.3 <1.3.0
                let upper = if comparator.minor.is_none() {
                    // ~1 := >=1.0.0 <2.0.0
                    SatVersion::SemVer(semver::Version::new(comparator.major + 1, 0, 0))
                } else if comparator.patch.is_none() {
                    // ~1.2 := >=1.2.0 <1.3.0
                    SatVersion::SemVer(semver::Version::new(
                        comparator.major,
                        comparator.minor.unwrap() + 1,
                        0,
                    ))
                } else {
                    // ~1.2.3 := >=1.2.3 <1.3.0
                    SatVersion::SemVer(semver::Version::new(
                        comparator.major,
                        comparator.minor.unwrap() + 1,
                        0,
                    ))
                };

                // >= v AND < upper
                Ranges::higher_than(v).intersection(&Ranges::strictly_lower_than(upper))
            }
            semver::Op::Caret => {
                // ^1.2.3 := >=1.2.3 <2.0.0
                let major = comparator.major;
                let minor = comparator.minor.unwrap_or(0);
                let patch = comparator.patch.unwrap_or(0);

                let upper = if major == 0 {
                    if minor == 0 {
                        // ^0.0.x := >=0.0.x <0.0.(x+1)
                        SatVersion::SemVer(semver::Version::new(0, 0, patch + 1))
                    } else {
                        // ^0.x.y := >=0.x.y <0.(x+1).0
                        SatVersion::SemVer(semver::Version::new(0, minor + 1, 0))
                    }
                } else {
                    // ^x.y.z := >=x.y.z <(x+1).0.0
                    SatVersion::SemVer(semver::Version::new(major + 1, 0, 0))
                };

                // >= v AND < upper
                Ranges::higher_than(v).intersection(&Ranges::strictly_lower_than(upper))
            }
            semver::Op::Wildcard | _ => Ranges::full(),
        };

        final_range = final_range.intersection(&comp_range);
    }

    final_range
}

fn pep440_to_range(req: &pep440_rs::VersionSpecifiers) -> Ranges<SatVersion> {
    let mut final_range = Ranges::full();

    for spec in req.iter() {
        let v = SatVersion::Pep440(spec.version().clone());

        let spec_range = match spec.operator() {
            pep440_rs::Operator::Equal => Ranges::singleton(v),
            pep440_rs::Operator::NotEqual => Ranges::singleton(v).complement(),
            pep440_rs::Operator::GreaterThan => Ranges::strictly_higher_than(v),
            pep440_rs::Operator::GreaterThanEqual => Ranges::higher_than(v),
            pep440_rs::Operator::LessThan => Ranges::strictly_lower_than(v),
            pep440_rs::Operator::LessThanEqual => Ranges::lower_than(v),
            pep440_rs::Operator::TildeEqual => {
                // PEP 440 compatible release: ~=X.Y.Z means >=X.Y.Z, ==X.Y.*
                // Example: ~=1.4.5 means >=1.4.5, <1.5.0
                let release = spec.version().release();
                if release.len() >= 2 {
                    let major = release[0];
                    let minor = release[1];
                    let upper = pep440_rs::Version::from_str(&format!("{}.{}", major, minor + 1))
                        .unwrap_or_else(|_| spec.version().clone());
                    let upper_v = SatVersion::Pep440(upper);
                    // >= v AND < upper
                    Ranges::higher_than(v).intersection(&Ranges::strictly_lower_than(upper_v))
                } else {
                    // Fallback for versions with only major: >= v
                    Ranges::higher_than(v)
                }
            }
            _ => Ranges::full(),
        };

        final_range = final_range.intersection(&spec_range);
    }

    final_range
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_range_conversion() {
        let req = semver::VersionReq::parse("^1.2.3").unwrap();
        let range = semver_to_range(&req);
        let v_in = SatVersion::SemVer(semver::Version::parse("1.2.3").unwrap());
        let v_out = SatVersion::SemVer(semver::Version::parse("2.0.0").unwrap());

        assert!(range.contains(&v_in));
        assert!(!range.contains(&v_out));
    }

    #[test]
    fn test_semver_pre_release() {
        let req = semver::VersionReq::parse("=1.0.0-alpha").unwrap();
        let range = semver_to_range(&req);
        let v = SatVersion::SemVer(semver::Version::parse("1.0.0-alpha").unwrap());
        assert!(range.contains(&v));
    }

    /// M-17: Test npm-style version ranges (tilde, caret, exact, wildcard)
    #[test]
    fn test_parse_range_npm_operators() {
        // Test caret (^) - allows minor/patch updates
        let range = parse_range(Ecosystem::Npm, "^1.0.0");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 0, 0))));
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 5, 3))));
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 99, 99))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(2, 0, 0))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(0, 9, 0))));

        // Test tilde (~) - allows patch updates only
        let range = parse_range(Ecosystem::Npm, "~1.2.0");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 2, 0))));
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 2, 5))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(1, 3, 0))));

        // Test exact (=)
        let range = parse_range(Ecosystem::Npm, "=1.0.0");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 0, 0))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(1, 0, 1))));

        // Test greater-than (>)
        let range = parse_range(Ecosystem::Npm, ">1.0.0");
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(1, 0, 0))));
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 0, 1))));
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(2, 0, 0))));

        // Test wildcard (*)
        let range = parse_range(Ecosystem::Npm, "*");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(0, 0, 1))));
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(99, 99, 99))));
    }

    /// M-17: Test PEP 440 version specifiers (Python)
    #[test]
    fn test_parse_range_pypi_operators() {
        // Test greater-than-equal (>=) - straightforward comparison
        let range = parse_range(Ecosystem::PyPi, ">=1.0");
        let v1 = pep440_rs::Version::from_str("1.0").unwrap();
        let v2 = pep440_rs::Version::from_str("2.0").unwrap();
        let v0 = pep440_rs::Version::from_str("0.9").unwrap();
        assert!(range.contains(&SatVersion::Pep440(v1)));
        assert!(range.contains(&SatVersion::Pep440(v2)));
        assert!(!range.contains(&SatVersion::Pep440(v0)));

        // Test less-than (<)
        let range = parse_range(Ecosystem::PyPi, "<2.0");
        let v1 = pep440_rs::Version::from_str("1.0").unwrap();
        let v19 = pep440_rs::Version::from_str("1.9").unwrap();
        let v2 = pep440_rs::Version::from_str("2.0").unwrap();
        assert!(range.contains(&SatVersion::Pep440(v1)));
        assert!(range.contains(&SatVersion::Pep440(v19)));
        assert!(!range.contains(&SatVersion::Pep440(v2)));

        // Test compatible release (~=) - PEP 440 specific
        // ~=1.4.0 means >=1.4.0, <1.5.0
        let range = parse_range(Ecosystem::PyPi, "~=1.4.0");
        let v140 = pep440_rs::Version::from_str("1.4.0").unwrap();
        let v145 = pep440_rs::Version::from_str("1.4.5").unwrap();
        let v150 = pep440_rs::Version::from_str("1.5.0").unwrap();
        assert!(range.contains(&SatVersion::Pep440(v140)));
        assert!(range.contains(&SatVersion::Pep440(v145)));
        assert!(!range.contains(&SatVersion::Pep440(v150)));
    }

    /// M-17: Test compound version ranges (AND semantics)
    #[test]
    fn test_parse_range_compound() {
        // Test compound requirement: >=1.0.0, <2.0.0
        let range = parse_range(Ecosystem::Npm, ">=1.0.0, <2.0.0");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 0, 0))));
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 5, 0))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(0, 9, 0))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(2, 0, 0))));
    }

    /// M-17: Test SatVersion ordering (critical for PubGrub)
    #[test]
    fn test_sat_version_ordering() {
        let v1 = SatVersion::SemVer(semver::Version::new(1, 0, 0));
        let v2 = SatVersion::SemVer(semver::Version::new(2, 0, 0));
        let virtual_0 = SatVersion::Virtual(0);
        let pep_1 = SatVersion::Pep440("1.0.0".parse().unwrap());

        // Virtual is lowest
        assert!(virtual_0 < v1);
        assert!(virtual_0 < pep_1);

        // SemVer ordering
        assert!(v1 < v2);

        // Cross-ecosystem: SemVer < Pep440
        assert!(v1 < pep_1);
    }

    /// M-17: Test SatPackage Display and ordering
    #[test]
    fn test_sat_package_display() {
        let pkg = SatPackage {
            name: "lodash".to_string(),
            ecosystem: Ecosystem::Npm,
        };
        assert_eq!(pkg.to_string(), "npm:lodash");

        let pkg2 = SatPackage {
            name: "requests".to_string(),
            ecosystem: Ecosystem::PyPi,
        };
        assert_eq!(pkg2.to_string(), "pypi:requests");
    }

    /// M-17: Test zero-major caret ranges (special npm semantics)
    #[test]
    fn test_caret_zero_major() {
        // ^0.2.3 should be >=0.2.3 <0.3.0 (minor is not updated for 0.x)
        let range = parse_range(Ecosystem::Npm, "^0.2.3");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(0, 2, 3))));
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(0, 2, 9))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(0, 3, 0))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(0, 2, 2))));

        // ^0.0.3 should be >=0.0.3 <0.0.4 (only patch allowed for 0.0.x)
        let range = parse_range(Ecosystem::Npm, "^0.0.3");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(0, 0, 3))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(0, 0, 4))));
        assert!(!range.contains(&SatVersion::SemVer(semver::Version::new(0, 0, 2))));
    }

    /// M-17: Test invalid/empty version requirements
    #[test]
    fn test_parse_range_edge_cases() {
        // Empty string should match any
        let range = parse_range(Ecosystem::Npm, "");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 0, 0))));

        // Wildcard should match any
        let range = parse_range(Ecosystem::Npm, "*");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(0, 0, 1))));
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(99, 0, 0))));

        // Invalid version requirement falls back to any
        let range = parse_range(Ecosystem::Npm, "not-a-version");
        assert!(range.contains(&SatVersion::SemVer(semver::Version::new(1, 0, 0))));
    }
}
