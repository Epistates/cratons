//! Minimal Version Selection algorithm.

use cratons_core::{
    CratonsError, Ecosystem, ResolutionStrategy, Result, Version, VersionReq,
    hash_normalization::normalize_checksum_format,
};
use cratons_lockfile::{LOCKFILE_NAME, Lockfile};
use cratons_manifest::{Dependency, Manifest};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::compute_manifest_hash;

use crate::graph::{DependencyGraph, DependencyKind};
use crate::registry::{PackageMetadata, Registry, RegistryClient};
use crate::sat::SatResolver;
use crate::{Resolution, ResolvedPackage};

/// The dependency resolver using Minimal Version Selection.
pub struct Resolver {
    registry: Arc<Registry>,
}

impl Resolver {
    /// Create a new resolver with default registry clients.
    pub fn new(offline: bool) -> Self {
        Self {
            registry: Arc::new(Registry::new(offline)),
        }
    }

    /// Create a resolver with all default registry clients initialized.
    pub fn with_defaults(offline: bool) -> Result<Self> {
        Ok(Self {
            registry: Arc::new(Registry::with_defaults(offline)?),
        })
    }

    /// Add a custom registry client for an ecosystem.
    pub fn add_registry(&mut self, client: Arc<dyn RegistryClient>) {
        if let Some(registry) = Arc::get_mut(&mut self.registry) {
            registry.add_client(client);
        } else {
            // Should clone if multiple references exist, but for now panic or log
            warn!("Cannot add registry client: registry is shared");
        }
    }

    /// Get access to the underlying registry.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    fn add_url_dependencies(
        &self,
        manifest: &Manifest,
        graph: &mut DependencyGraph,
        metadata_cache: &mut BTreeMap<(String, Ecosystem, String), PackageMetadata>,
        requested_optional: &mut HashSet<(Ecosystem, String)>,
    ) -> Result<()> {
        for (name, dep) in &manifest.dependencies.url {
            self.add_url_dependency(
                name,
                dep,
                DependencyKind::Normal,
                graph,
                metadata_cache,
                requested_optional,
            )?;
        }

        for (name, dep) in &manifest.optional_dependencies.url {
            self.add_url_dependency(
                name,
                dep,
                DependencyKind::Optional,
                graph,
                metadata_cache,
                requested_optional,
            )?;
        }

        Ok(())
    }

    fn add_url_dependency(
        &self,
        name: &str,
        dep: &Dependency,
        kind: DependencyKind,
        graph: &mut DependencyGraph,
        metadata_cache: &mut BTreeMap<(String, Ecosystem, String), PackageMetadata>,
        requested_optional: &mut HashSet<(Ecosystem, String)>,
    ) -> Result<()> {
        let Dependency::Detailed(detail) = dep else {
            return Err(CratonsError::Manifest(format!(
                "URL dependency '{name}' must use detailed syntax with url and sha256"
            )));
        };

        let url = detail.url.clone().ok_or_else(|| {
            CratonsError::Manifest(format!("URL dependency '{name}' is missing url"))
        })?;
        let sha256 = detail.sha256.as_ref().ok_or_else(|| {
            CratonsError::Manifest(format!("URL dependency '{name}' is missing sha256"))
        })?;
        let integrity = normalize_checksum_format(&format!("sha256-{sha256}"))?;
        let version = detail
            .version
            .clone()
            .unwrap_or_else(|| "0.0.0".to_string());
        Version::parse(&version, Ecosystem::Url)?;

        if kind == DependencyKind::Optional {
            requested_optional.insert((Ecosystem::Url, name.to_string()));
        }

        graph.add_package(name, Ecosystem::Url);
        graph.set_versions(name, Ecosystem::Url, vec![version.clone()]);
        graph.set_resolved_version(name, Ecosystem::Url, version.clone());
        graph.add_dependency(
            "__root__",
            Ecosystem::Npm,
            name,
            Ecosystem::Url,
            detail
                .version
                .as_deref()
                .map(|v| VersionReq::parse(v, Ecosystem::Url))
                .transpose()?
                .unwrap_or(VersionReq::Any),
            true,
            detail.features.clone(),
            kind,
        );

        metadata_cache.insert(
            (name.to_string(), Ecosystem::Url, version.clone()),
            PackageMetadata::new(name.to_string(), version, url, integrity),
        );

        Ok(())
    }

    async fn hydrate_sat_solution(
        &self,
        solution: BTreeMap<(String, Ecosystem), String>,
        root_deps: &[(String, String, Ecosystem)],
        graph: &mut DependencyGraph,
        metadata_cache: &mut BTreeMap<(String, Ecosystem, String), PackageMetadata>,
    ) -> Result<()> {
        for ((name, ecosystem), version) in &solution {
            graph.add_package(name, *ecosystem);
            graph.set_versions(name, *ecosystem, vec![version.clone()]);
            graph.set_resolved_version(name, *ecosystem, version.clone());
            self.fetch_metadata_cached(name, *ecosystem, version, metadata_cache)
                .await?;
        }

        for (name, req, ecosystem) in root_deps {
            graph.add_dependency(
                "__root__",
                Ecosystem::Npm,
                name,
                *ecosystem,
                VersionReq::parse(req, *ecosystem)?,
                true,
                vec![],
                DependencyKind::Normal,
            );
        }

        for ((name, ecosystem), version) in &solution {
            let metadata = self
                .fetch_metadata_cached(name, *ecosystem, version, metadata_cache)
                .await?;
            self.add_metadata_edges(name, *ecosystem, &metadata, &solution, graph)?;
        }

        Ok(())
    }

    fn add_metadata_edges(
        &self,
        name: &str,
        ecosystem: Ecosystem,
        metadata: &PackageMetadata,
        solution: &BTreeMap<(String, Ecosystem), String>,
        graph: &mut DependencyGraph,
    ) -> Result<()> {
        let bundled_set: HashSet<&String> = metadata.bundled_dependencies.iter().collect();
        for (dep_name, req) in &metadata.dependencies {
            if bundled_set.contains(dep_name) {
                continue;
            }
            if solution.contains_key(&(dep_name.clone(), ecosystem)) {
                graph.add_dependency(
                    name,
                    ecosystem,
                    dep_name,
                    ecosystem,
                    VersionReq::parse(req, ecosystem)?,
                    false,
                    vec![],
                    DependencyKind::Normal,
                );
            }
        }

        for (dep_name, req) in &metadata.peer_dependencies {
            let is_optional = metadata
                .peer_dependencies_meta
                .get(dep_name)
                .map(|m| m.optional)
                .unwrap_or(false);
            if is_optional || !solution.contains_key(&(dep_name.clone(), ecosystem)) {
                continue;
            }
            graph.add_dependency(
                name,
                ecosystem,
                dep_name,
                ecosystem,
                VersionReq::parse(req, ecosystem)?,
                false,
                vec![],
                DependencyKind::Peer,
            );
        }

        Ok(())
    }

    async fn fetch_metadata_cached(
        &self,
        name: &str,
        ecosystem: Ecosystem,
        version: &str,
        metadata_cache: &mut BTreeMap<(String, Ecosystem, String), PackageMetadata>,
    ) -> Result<PackageMetadata> {
        let metadata_key = (name.to_string(), ecosystem, version.to_string());
        if let Some(cached) = metadata_cache.get(&metadata_key) {
            return Ok(cached.clone());
        }

        let metadata = self
            .registry
            .fetch_metadata(ecosystem, name, version)
            .await
            .map_err(|e| CratonsError::Registry {
                registry: ecosystem.to_string(),
                message: format!("Failed to fetch metadata for {ecosystem}:{name}@{version}: {e}"),
            })?;
        metadata_cache.insert(metadata_key, metadata.clone());
        Ok(metadata)
    }

    fn select_version(
        &self,
        versions: &[String],
        ecosystem: Ecosystem,
        name: &str,
        version_req: &VersionReq,
        manifest: &Manifest,
    ) -> Result<String> {
        let strategy = manifest
            .resolution
            .get(&ecosystem)
            .cloned()
            .unwrap_or_else(|| ecosystem.default_resolution_strategy());

        let override_req = manifest
            .overrides
            .for_ecosystem(ecosystem)
            .get(name)
            .and_then(|d| d.version())
            .map(|v| VersionReq::parse(v, ecosystem))
            .transpose()?;

        let predicate = |v: &&String| {
            let ver = match Version::parse(v, ecosystem) {
                Ok(ver) => ver,
                Err(_) => return false,
            };

            override_req.as_ref().unwrap_or(version_req).matches(&ver)
        };

        let selected = match strategy {
            ResolutionStrategy::Minimal => versions.iter().find(predicate),
            ResolutionStrategy::MaxSatisfying => versions.iter().rfind(predicate),
        };

        selected.cloned().ok_or_else(|| {
            let available_versions = versions
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let more = if versions.len() > 5 {
                format!(" (and {} more)", versions.len() - 5)
            } else {
                String::new()
            };
            CratonsError::NoSatisfyingVersion {
                package: name.to_string(),
                constraint: format!("{version_req} (available: {available_versions}{more})"),
            }
        })
    }

    async fn ensure_final_metadata(
        &self,
        graph: &mut DependencyGraph,
        metadata_cache: &mut BTreeMap<(String, Ecosystem, String), PackageMetadata>,
        manifest: &Manifest,
        requested_optional: &HashSet<(Ecosystem, String)>,
    ) -> Result<()> {
        const MAX_METADATA_FIXPOINT: usize = 128;

        for _ in 0..MAX_METADATA_FIXPOINT {
            let nodes = graph
                .packages()
                .filter_map(|node| {
                    if node.name == "__root__" {
                        None
                    } else {
                        node.resolved_version
                            .as_ref()
                            .map(|version| (node.name.clone(), node.ecosystem, version.clone()))
                    }
                })
                .collect::<Vec<_>>();

            let mut changed = false;
            for (name, ecosystem, version) in nodes {
                let metadata = self
                    .fetch_metadata_cached(&name, ecosystem, &version, metadata_cache)
                    .await?;
                let bundled_set: HashSet<&String> = metadata.bundled_dependencies.iter().collect();

                for (dep_name, dep_req_str, dep_kind) in metadata
                    .dependencies
                    .iter()
                    .filter(|(dep_name, _)| !bundled_set.contains(dep_name))
                    .map(|(dep_name, req)| (dep_name, req, DependencyKind::Normal))
                    .chain(
                        metadata
                            .optional_dependencies
                            .iter()
                            .filter(|(dep_name, _)| {
                                requested_optional.contains(&(ecosystem, (*dep_name).clone()))
                            })
                            .map(|(dep_name, req)| (dep_name, req, DependencyKind::Optional)),
                    )
                    .chain(
                        metadata
                            .peer_dependencies
                            .iter()
                            .filter_map(|(dep_name, req)| {
                                let is_optional = metadata
                                    .peer_dependencies_meta
                                    .get(dep_name)
                                    .map(|m| m.optional)
                                    .unwrap_or(false);
                                (!is_optional).then_some((dep_name, req, DependencyKind::Peer))
                            }),
                    )
                {
                    let dep_req = VersionReq::parse(dep_req_str, ecosystem)?;

                    if graph.get_package(dep_name, ecosystem).is_none() {
                        let versions = self
                            .registry
                            .fetch_versions(ecosystem, dep_name)
                            .await
                            .map_err(|e| CratonsError::Registry {
                                registry: ecosystem.to_string(),
                                message: format!("Failed to fetch versions for {dep_name}: {e}"),
                            })?;
                        let selected = self
                            .select_version(&versions, ecosystem, dep_name, &dep_req, manifest)?;
                        graph.add_package(dep_name, ecosystem);
                        graph.set_versions(dep_name, ecosystem, versions);
                        graph.set_resolved_version(dep_name, ecosystem, selected);
                        changed = true;
                    }

                    if !graph.has_dependency_edge(
                        &name, ecosystem, dep_name, ecosystem, &dep_req, dep_kind,
                    ) {
                        graph.add_dependency(
                            &name,
                            ecosystem,
                            dep_name,
                            ecosystem,
                            dep_req,
                            false,
                            vec![],
                            dep_kind,
                        );
                        changed = true;
                    }
                }
            }

            if changed {
                self.apply_mvs(graph, manifest)?;
            } else {
                return Ok(());
            }
        }

        Err(CratonsError::Config(
            "Resolution metadata fixpoint exceeded maximum iterations".to_string(),
        ))
    }

    /// Resolve dependencies from a manifest.
    #[tracing::instrument(level = "debug", skip(self, manifest))]
    pub async fn resolve(&self, manifest: &Manifest) -> Result<Resolution> {
        info!("Starting dependency resolution");
        let mut resolution = Resolution::new();
        let mut graph = DependencyGraph::new();
        let mut metadata_cache: BTreeMap<(String, Ecosystem, String), PackageMetadata> =
            BTreeMap::new();
        let mut requested_optional: HashSet<(Ecosystem, String)> = HashSet::new();

        // Add a root node used for direct dependency edges.
        graph.add_package("__root__", Ecosystem::Npm);

        self.add_url_dependencies(
            manifest,
            &mut graph,
            &mut metadata_cache,
            &mut requested_optional,
        )?;

        // 1. Hybrid Strategy: Unified SAT Solving for NPM/PyPI
        let sat_ecosystems = [Ecosystem::Npm, Ecosystem::PyPi];
        let mut sat_roots = Vec::new();
        let mut strategies = BTreeMap::new();

        for ecosystem in sat_ecosystems {
            let deps = manifest.dependencies.for_ecosystem(ecosystem);
            if !deps.is_empty() {
                let strategy = manifest
                    .resolution
                    .get(&ecosystem)
                    .copied()
                    .unwrap_or(ResolutionStrategy::MaxSatisfying);
                strategies.insert(ecosystem, strategy);

                info!("Using SAT solver for {}", ecosystem);
                for (name, dep) in deps {
                    sat_roots.push((
                        name.clone(),
                        dep.version().unwrap_or("*").to_string(),
                        ecosystem,
                    ));
                }
            }
        }

        if !sat_roots.is_empty() {
            let sat_resolver = SatResolver::new(self.registry.clone());
            let sat_roots_for_edges = sat_roots.clone();

            match sat_resolver.resolve_multi(sat_roots, strategies).await {
                Ok(solution) => {
                    self.hydrate_sat_solution(
                        solution,
                        &sat_roots_for_edges,
                        &mut graph,
                        &mut metadata_cache,
                    )
                    .await?;
                }
                Err(e) => {
                    return Err(CratonsError::Config(format!(
                        "SAT resolution failed: {}",
                        e
                    )));
                }
            }
        }

        // 2. MVS Strategy for others (Cargo, Go, Maven)
        // ... (rest of MVS logic adapted to skip already resolved ecosystems) ...

        // Track what we've already processed to avoid cycles
        let mut processed: HashSet<(String, Ecosystem)> = HashSet::new();

        // Track peer dependency requirements for validation
        let mut peer_requirements: BTreeMap<(Ecosystem, String), Vec<(String, VersionReq)>> =
            BTreeMap::new();

        // Work queue: (name, ecosystem, version_req, is_direct, from_package, kind)
        let mut queue: VecDeque<(
            String,
            Ecosystem,
            VersionReq,
            bool,
            Option<String>,
            DependencyKind,
        )> = VecDeque::new();

        // Collect direct dependencies
        for ecosystem in Ecosystem::all() {
            // Skip if already resolved by SAT or handled as direct URL metadata.
            if *ecosystem == Ecosystem::Npm
                || *ecosystem == Ecosystem::PyPi
                || *ecosystem == Ecosystem::Url
            {
                continue;
            }

            let deps = manifest.dependencies.for_ecosystem(*ecosystem);
            if deps.is_empty() {
                continue;
            }

            debug!("Found {} direct {} dependencies", deps.len(), ecosystem);

            for (name, dep) in deps {
                let version_req = dep
                    .version()
                    .map(|v| VersionReq::parse(v, *ecosystem))
                    .transpose()?
                    .unwrap_or(VersionReq::Any);

                queue.push_back((
                    name.clone(),
                    *ecosystem,
                    version_req,
                    true,
                    None,
                    DependencyKind::Normal,
                ));
            }
        }

        // Collect optional dependencies that are explicitly requested
        for ecosystem in Ecosystem::all() {
            if *ecosystem == Ecosystem::Url {
                continue;
            }
            let opt_deps = manifest.optional_dependencies.for_ecosystem(*ecosystem);
            for (name, dep) in opt_deps {
                let version_req = dep
                    .version()
                    .map(|v| VersionReq::parse(v, *ecosystem))
                    .transpose()?
                    .unwrap_or(VersionReq::Any);

                requested_optional.insert((*ecosystem, name.clone()));
                queue.push_back((
                    name.clone(),
                    *ecosystem,
                    version_req,
                    true,
                    None,
                    DependencyKind::Optional,
                ));
            }
        }

        // Process queue until fixed point
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 10000; // Safety limit

        while let Some((name, ecosystem, version_req, is_direct, from_pkg, dep_kind)) =
            queue.pop_front()
        {
            iterations += 1;
            if iterations > MAX_ITERATIONS {
                return Err(CratonsError::Config(
                    "Resolution exceeded maximum iterations - possible cycle".to_string(),
                ));
            }

            // Skip if already processed
            let key = (name.clone(), ecosystem);
            if processed.contains(&key) {
                // Still add the dependency edge if we have a from_pkg
                if let Some(ref from) = from_pkg {
                    graph.add_dependency(
                        from,
                        ecosystem, // Assume same ecosystem for simplicity
                        &name,
                        ecosystem,
                        version_req,
                        false,
                        vec![],
                        dep_kind,
                    );
                }
                continue;
            }

            debug!(
                "Processing {}:{} (from: {:?}, kind: {:?})",
                ecosystem, name, from_pkg, dep_kind
            );

            // Emit event
            cratons_core::BuildEvent::PackageResolveStarted {
                ecosystem: ecosystem.to_string(),
                package: name.clone(),
            }
            .emit();

            // Fetch available versions
            let versions = match self.registry.fetch_versions(ecosystem, &name).await {
                Ok(v) => v,
                Err(e) => {
                    // For optional/peer dependencies, don't fail the entire resolution
                    match dep_kind {
                        DependencyKind::Optional | DependencyKind::PeerOptional => {
                            warn!(
                                "Optional dependency {}:{} not found: {}",
                                ecosystem, name, e
                            );
                            continue;
                        }
                        DependencyKind::Peer => {
                            // Peer dependencies that aren't satisfied are a warning, not error
                            // The package may work without them or they may be provided elsewhere
                            warn!("Peer dependency {}:{} not found: {}", ecosystem, name, e);
                            // Track as unmet peer dep for later warning
                            peer_requirements
                                .entry((ecosystem, name.clone()))
                                .or_default()
                                .push((from_pkg.clone().unwrap_or_default(), version_req.clone()));
                            continue;
                        }
                        _ => {
                            return Err(CratonsError::Registry {
                                registry: ecosystem.to_string(),
                                message: format!("Failed to fetch versions for {}: {}", name, e),
                            });
                        }
                    }
                }
            };

            if versions.is_empty() {
                warn!("No versions found for {}:{}", ecosystem, name);
                continue;
            }

            // Add package to graph with versions
            graph.add_package(&name, ecosystem);
            graph.set_versions(&name, ecosystem, versions.clone());

            // Add dependency edge
            if let Some(ref from) = from_pkg {
                graph.add_dependency(
                    from,
                    ecosystem,
                    &name,
                    ecosystem,
                    version_req.clone(),
                    false,
                    vec![],
                    dep_kind,
                );
            } else {
                // Direct dependency from root
                graph.add_dependency(
                    "__root__",
                    Ecosystem::Npm,
                    &name,
                    ecosystem,
                    version_req.clone(),
                    is_direct,
                    vec![],
                    dep_kind,
                );
            }

            // Select version based on ecosystem strategy
            let strategy = manifest
                .resolution
                .get(&ecosystem)
                .cloned()
                .unwrap_or_else(|| ecosystem.default_resolution_strategy());

            // Check for override
            let override_req = manifest
                .overrides
                .for_ecosystem(ecosystem)
                .get(&name)
                .and_then(|d| d.version())
                .map(|v| VersionReq::parse(v, ecosystem))
                .transpose()?;

            if let Some(ref o) = override_req {
                debug!("Overriding {} with {}", name, o);
            }

            let predicate = |v: &&String| {
                let ver = match Version::parse(v, ecosystem) {
                    Ok(ver) => ver,
                    Err(_) => return false,
                };

                if let Some(ref o) = override_req {
                    // If overridden, must match override
                    o.matches(&ver)
                } else {
                    // Otherwise match the requested version
                    version_req.matches(&ver)
                }
            };

            let selected_version = match strategy {
                ResolutionStrategy::Minimal => versions.iter().find(predicate),
                ResolutionStrategy::MaxSatisfying => versions.iter().rfind(predicate),
            }
            .cloned();

            let Some(version) = selected_version else {
                // This is a hard error - no version satisfies the constraints
                // We must not silently fall back to a different version
                let available_versions = versions
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let more = if versions.len() > 5 {
                    format!(" (and {} more)", versions.len() - 5)
                } else {
                    String::new()
                };

                return Err(CratonsError::NoSatisfyingVersion {
                    package: name.clone(),
                    constraint: format!(
                        "{} (available: {}{})",
                        version_req, available_versions, more
                    ),
                });
            };

            debug!(
                "Selected {}@{} (constraint: {})",
                name, version, version_req
            );

            // Emit finish event
            cratons_core::BuildEvent::PackageResolveFinished {
                ecosystem: ecosystem.to_string(),
                package: name.clone(),
                version: version.clone(),
                cached: false, // For now, we don't track resolution caching strictly here
            }
            .emit();

            graph.set_resolved_version(&name, ecosystem, version.clone());

            // Fetch metadata to get transitive dependencies
            let metadata = self
                .fetch_metadata_cached(&name, ecosystem, &version, &mut metadata_cache)
                .await?;

            // M-16: Create set of bundled dependencies to skip from resolution
            // Bundled dependencies are included in the package tarball, so don't resolve them separately
            let bundled_set: std::collections::HashSet<&String> =
                metadata.bundled_dependencies.iter().collect();

            // Queue transitive dependencies (regular), excluding bundled deps
            for (dep_name, dep_version_str) in &metadata.dependencies {
                // Skip bundled dependencies - they're included in the package tarball
                if bundled_set.contains(dep_name) {
                    debug!(
                        "Skipping bundled dependency: {} (bundled with {})",
                        dep_name, name
                    );
                    continue;
                }

                let dep_req =
                    VersionReq::parse(dep_version_str, ecosystem).unwrap_or(VersionReq::Any);

                if !processed.contains(&(dep_name.clone(), ecosystem)) {
                    queue.push_back((
                        dep_name.clone(),
                        ecosystem,
                        dep_req,
                        false,
                        Some(name.clone()),
                        DependencyKind::Normal,
                    ));
                }
            }

            // Queue optional dependencies only if explicitly requested
            for (dep_name, dep_version_str) in &metadata.optional_dependencies {
                let dep_key = (ecosystem, dep_name.clone());
                // Only resolve if this optional dep was explicitly requested
                if requested_optional.contains(&dep_key) {
                    let dep_req =
                        VersionReq::parse(dep_version_str, ecosystem).unwrap_or(VersionReq::Any);

                    if !processed.contains(&(dep_name.clone(), ecosystem)) {
                        queue.push_back((
                            dep_name.clone(),
                            ecosystem,
                            dep_req,
                            false,
                            Some(name.clone()),
                            DependencyKind::Optional,
                        ));
                    }
                }
            }

            // Queue peer dependencies (npm-specific behavior)
            // Peer dependencies are resolved but with special handling:
            // - They don't fail resolution if unmet (just warn)
            // - They expect the parent to provide them
            // M-16: Use peerDependenciesMeta to determine if peer dep is optional
            for (dep_name, dep_version_str) in &metadata.peer_dependencies {
                let dep_req =
                    VersionReq::parse(dep_version_str, ecosystem).unwrap_or(VersionReq::Any);

                // M-16: Check if this peer dep is optional via peerDependenciesMeta
                let is_optional = metadata
                    .peer_dependencies_meta
                    .get(dep_name)
                    .map(|m| m.optional)
                    .unwrap_or(false);

                let kind = if is_optional {
                    DependencyKind::PeerOptional
                } else {
                    DependencyKind::Peer
                };

                // Track the peer requirement for validation
                peer_requirements
                    .entry((ecosystem, dep_name.clone()))
                    .or_default()
                    .push((name.clone(), dep_req.clone()));

                if !processed.contains(&(dep_name.clone(), ecosystem)) {
                    queue.push_back((
                        dep_name.clone(),
                        ecosystem,
                        dep_req,
                        false,
                        Some(name.clone()),
                        kind, // Use PeerOptional or Peer based on metadata
                    ));
                }
            }

            processed.insert(key);
        }

        info!(
            "Resolution complete: {} packages after {} iterations",
            processed.len(),
            iterations
        );

        // Check for dependency cycles using Tarjan's algorithm
        if graph.has_cycles() {
            if let Some(cycle_description) = graph.describe_cycles() {
                return Err(CratonsError::DependencyCycle(cycle_description));
            }
            // Fallback if we detect cycles but can't describe them
            return Err(CratonsError::DependencyCycle(
                "Circular dependencies detected in the dependency graph".to_string(),
            ));
        }

        // Validate peer dependencies
        // Peer dependencies should be provided by the parent package or as direct dependencies
        for ((ecosystem, peer_name), requesters) in &peer_requirements {
            if let Some(node) = graph.get_package(peer_name, *ecosystem) {
                if let Some(ref resolved_version) = node.resolved_version {
                    let ver = Version::parse(resolved_version, *ecosystem).ok();
                    // Check if the resolved version satisfies all peer requirements
                    for (requester, version_req) in requesters {
                        if let Some(ref v) = ver {
                            if !version_req.matches(v) {
                                warn!(
                                    "Peer dependency {}:{} resolved to {} but {} requires {}",
                                    ecosystem, peer_name, resolved_version, requester, version_req
                                );
                            }
                        }
                    }
                }
            } else {
                // Peer dependency not found in resolution
                for (requester, version_req) in requesters {
                    warn!(
                        "Unmet peer dependency: {} requires {}:{}@{}",
                        requester, ecosystem, peer_name, version_req
                    );
                }
            }
        }

        // Apply MVS to handle any version conflicts
        self.apply_mvs(&mut graph, manifest)?;

        self.ensure_final_metadata(
            &mut graph,
            &mut metadata_cache,
            manifest,
            &requested_optional,
        )
        .await?;

        if graph.has_cycles() {
            if let Some(cycle_description) = graph.describe_cycles() {
                return Err(CratonsError::DependencyCycle(cycle_description));
            }
            return Err(CratonsError::DependencyCycle(
                "Circular dependencies detected in the dependency graph".to_string(),
            ));
        }

        // Convert graph to resolution with full metadata
        let final_nodes = graph
            .packages()
            .filter_map(|node| {
                if node.name == "__root__" {
                    None
                } else {
                    node.resolved_version
                        .as_ref()
                        .map(|version| (node.name.clone(), node.ecosystem, version.clone()))
                }
            })
            .collect::<Vec<_>>();

        for (name, ecosystem, version) in final_nodes {
            let metadata = self
                .fetch_metadata_cached(&name, ecosystem, &version, &mut metadata_cache)
                .await?;

            let resolved = ResolvedPackage {
                name: name.clone(),
                version,
                ecosystem,
                source: metadata.dist_url,
                integrity: metadata.integrity,
                resolved_hash: None,
                direct: graph
                    .dependents(&name, ecosystem)
                    .iter()
                    .any(|(_, e)| e.direct),
                features: vec![],
                dependencies: graph
                    .dependencies(&name, ecosystem)
                    .iter()
                    .filter_map(|(dep, _)| {
                        dep.resolved_version
                            .as_ref()
                            .map(|v| (dep.name.clone(), v.clone()))
                    })
                    .collect(),
            };

            resolution.packages.push(resolved);
        }

        resolution.graph = graph;

        info!("Resolved {} packages total", resolution.packages.len());
        Ok(resolution)
    }

    /// Resolve dependencies with an existing lockfile.
    #[tracing::instrument(level = "debug", skip(self, manifest, lockfile))]
    pub async fn resolve_with_lockfile(
        &self,
        manifest: &Manifest,
        lockfile: &Lockfile,
    ) -> Result<Resolution> {
        // Start with locked versions
        let mut resolution = Resolution::new();
        let mut graph = DependencyGraph::new();
        resolution.packages = lockfile
            .packages
            .iter()
            .map(|pkg| ResolvedPackage {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                ecosystem: pkg.ecosystem,
                source: pkg.source.clone(),
                integrity: pkg.integrity.clone(),
                resolved_hash: pkg.resolved_hash.clone(),
                direct: pkg.direct,
                features: pkg.features.clone(),
                dependencies: pkg
                    .dependencies
                    .iter()
                    .map(|dep| (dep.name.clone(), dep.version.clone()))
                    .collect(),
            })
            .collect();

        // Add locked packages
        for pkg in &lockfile.packages {
            if graph.get_package(&pkg.name, pkg.ecosystem).is_none() {
                let _idx = graph.add_package(&pkg.name, pkg.ecosystem);
                graph.set_versions(&pkg.name, pkg.ecosystem, vec![pkg.version.clone()]);
                graph.set_resolved_version(&pkg.name, pkg.ecosystem, pkg.version.clone());
            }
        }

        for pkg in &lockfile.packages {
            for dep in &pkg.dependencies {
                if let Some(dep_pkg) =
                    lockfile.find_package_exact(&dep.name, pkg.ecosystem, &dep.version)
                {
                    graph.add_dependency(
                        &pkg.name,
                        pkg.ecosystem,
                        &dep_pkg.name,
                        dep_pkg.ecosystem,
                        VersionReq::parse(&dep.version, dep_pkg.ecosystem)
                            .unwrap_or_else(|_| VersionReq::Exact(dep.version.clone())),
                        false,
                        vec![],
                        DependencyKind::Normal,
                    );
                }
            }
        }

        // Check for new/updated dependencies in manifest
        for ecosystem in Ecosystem::all() {
            let deps = manifest.dependencies.for_ecosystem(*ecosystem);
            for (name, dep) in deps {
                let Some(locked) = lockfile.find_direct_package(name, *ecosystem) else {
                    return Err(CratonsError::Lockfile(format!(
                        "Lockfile is missing direct dependency {ecosystem}:{name}"
                    )));
                };

                if let Some(req_str) = dep.version() {
                    let req = VersionReq::parse(req_str, *ecosystem)?;
                    let version = Version::parse(&locked.version, *ecosystem)?;
                    if !req.matches(&version) {
                        return Err(CratonsError::NoSatisfyingVersion {
                            package: name.clone(),
                            constraint: format!(
                                "locked version {} does not satisfy manifest requirement {}",
                                locked.version, req
                            ),
                        });
                    }
                }
            }
        }

        resolution.graph = graph;
        Ok(resolution)
    }

    /// Resolve dependencies and generate a lockfile.
    ///
    /// This method:
    /// 1. Checks for an existing lockfile
    /// 2. If lockfile exists and is fresh, uses locked versions
    /// 3. Otherwise, performs full resolution
    /// 4. Generates and saves the lockfile
    #[tracing::instrument(level = "debug", skip(self, manifest), fields(manifest_path = %manifest_path.display()))]
    pub async fn resolve_and_lock(
        &self,
        manifest: &Manifest,
        manifest_path: &Path,
    ) -> Result<(Resolution, Lockfile)> {
        let manifest_hash = compute_manifest_hash(manifest);
        let lockfile_path = manifest_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(LOCKFILE_NAME);

        // Check for existing lockfile
        let existing_lockfile = Lockfile::load(&lockfile_path).ok();

        let resolution = if let Some(ref lockfile) = existing_lockfile {
            if lockfile.is_fresh(&manifest_hash) {
                info!("Lockfile is up to date, using locked versions");
                self.resolve_with_lockfile(manifest, lockfile).await?
            } else {
                info!("Manifest changed, re-resolving dependencies");
                self.resolve(manifest).await?
            }
        } else {
            info!("No lockfile found, resolving dependencies");
            self.resolve(manifest).await?
        };

        // Generate lockfile from resolution
        let lockfile = resolution.to_lockfile(manifest_hash);

        // Save lockfile
        lockfile.save(&lockfile_path)?;
        info!("Wrote lockfile to {}", lockfile_path.display());

        Ok((resolution, lockfile))
    }

    /// Apply resolution strategy (MVS or MaxSatisfying) to the graph.
    fn apply_mvs(&self, graph: &mut DependencyGraph, manifest: &Manifest) -> Result<()> {
        // Collect all version requirements per package
        let mut requirements: BTreeMap<(Ecosystem, String), Vec<VersionReq>> = BTreeMap::new();

        for node in graph.packages() {
            if node.name == "__root__" {
                continue;
            }

            // Get all version requirements from dependents
            for (_, edge) in graph.dependents(&node.name, node.ecosystem) {
                requirements
                    .entry((node.ecosystem, node.name.clone()))
                    .or_default()
                    .push(edge.version_req.clone());
            }
        }

        // For each package, select version satisfying all requirements based on strategy
        for ((ecosystem, name), reqs) in requirements {
            if let Some(node) = graph.get_package(&name, ecosystem) {
                let versions = node.versions.clone();
                let strategy = manifest
                    .resolution
                    .get(&ecosystem)
                    .cloned()
                    .unwrap_or_else(|| ecosystem.default_resolution_strategy());

                let predicate = |v: &String| {
                    let version = Version::parse(v, ecosystem).ok();
                    version.as_ref().map_or(false, |ver| {
                        // Check for override
                        let override_req = manifest
                            .overrides
                            .for_ecosystem(ecosystem)
                            .get(&name)
                            .and_then(|d| d.version())
                            .and_then(|v| VersionReq::parse(v, ecosystem).ok());

                        if let Some(o) = override_req {
                            // If overridden, only check the override constraint
                            o.matches(ver)
                        } else {
                            // Otherwise check all requirements
                            reqs.iter().all(|req| req.matches(ver))
                        }
                    })
                };

                // Find version satisfying all requirements
                let selected = match strategy {
                    ResolutionStrategy::Minimal => versions.into_iter().find(predicate),
                    ResolutionStrategy::MaxSatisfying => versions.into_iter().rfind(predicate),
                };

                if let Some(version) = selected {
                    debug!("Strategy {:?} selected {}@{}", strategy, name, version);
                    graph.set_resolved_version(&name, ecosystem, version);
                } else if !reqs.is_empty() {
                    return Err(CratonsError::NoSatisfyingVersion {
                        package: name.clone(),
                        constraint: reqs
                            .iter()
                            .map(|r| r.to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                    });
                }
            }
        }

        Ok(())
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_creation() {
        let resolver = Resolver::new(false);
        // Resolver starts with defaults
        assert!(!resolver.registry().is_empty());
    }

    #[test]
    fn test_resolver_with_defaults() {
        let resolver = Resolver::with_defaults(false).unwrap();
        // Should have clients for all 5 ecosystems
        assert!(!resolver.registry().is_empty());
        assert_eq!(resolver.registry().client_count(), 5);
    }
}
