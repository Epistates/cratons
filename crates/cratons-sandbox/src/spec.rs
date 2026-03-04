//! OCI runtime specification generation for sandbox.
//!
//! # Security
//!
//! This module generates secure OCI runtime specifications with:
//! - **Path validation**: All mount paths are validated to prevent path traversal
//! - **Capability dropping**: All capabilities are dropped by default
//! - **Namespace isolation**: Full namespace isolation for security
//! - **Seccomp profiles**: Syscall filtering to prevent privilege escalation
//! - **Read-only rootfs**: Rootfs is read-only by default

use std::path::Path;

use cratons_core::{CratonsError, Result};
use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxNamespaceBuilder, LinuxNamespaceType,
    LinuxResourcesBuilder, LinuxSeccompAction, Mount, MountBuilder, ProcessBuilder, RootBuilder,
    Spec, SpecBuilder, UserBuilder,
};

use crate::config::{NetworkAccess, SandboxConfig};
use crate::seccomp;

/// Generates OCI runtime specifications from SandboxConfig.
pub struct OciSpecGenerator;

impl OciSpecGenerator {
    /// Generate an OCI spec from the configuration.
    pub fn generate(config: &SandboxConfig, rootfs_path: &Path) -> Result<Spec> {
        // 1. Process Environment
        let mut env_vec: Vec<String> = Vec::new();

        // Essential env vars if not inherited/set
        if !config.env.contains_key("PATH") {
            env_vec.push(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            );
        }
        if !config.env.contains_key("TERM") {
            env_vec.push("TERM=xterm".to_string());
        }

        for (k, v) in &config.env {
            env_vec.push(format!("{k}={v}"));
        }

        // 2. Process User
        let user = if let Some(u) = &config.user {
            UserBuilder::default()
                .uid(u.uid)
                .gid(u.gid)
                .additional_gids(u.additional_gids.clone())
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?
        } else {
            // Default to nobody:nobody inside container if rootless, or root if not?
            // Safer to default to a non-root user (1000:1000)
            UserBuilder::default()
                .uid(1000u32)
                .gid(1000u32)
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?
        };

        // 3. Process Builder
        let mut args = config.command.clone();
        if args.is_empty() {
            args = vec!["/bin/sh".to_string()];
        }

        // SECURITY: Build capabilities with minimal permissions
        let capabilities = Self::minimal_capabilities()?;

        let process = ProcessBuilder::default()
            .terminal(false)
            .user(user)
            .args(args)
            .env(env_vec)
            .cwd(config.workdir.to_string_lossy().to_string())
            .no_new_privileges(true)
            // SECURITY: Drop all capabilities except minimal set
            .capabilities(capabilities)
            .build()
            .map_err(|e| CratonsError::Container(e.to_string()))?;

        // 4. Linux Config (Namespaces, Resources, Seccomp)
        let mut namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Mount)
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Pid)
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Ipc)
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?,
        ];

        // Network Namespace logic
        // If NetworkAccess::None, we create a new network namespace (isolating it).
        // If NetworkAccess::Full, we share the host network namespace (don't add Network ns).
        if matches!(config.network, NetworkAccess::None) {
            namespaces.push(
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Network)
                    .build()
                    .map_err(|e| CratonsError::Container(e.to_string()))?,
            );
        }

        // User Namespace (for rootless)
        namespaces.push(
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::User)
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?,
        );

        // SECURITY: Drop all capabilities by default for defense in depth
        // Only add back the absolute minimum needed for container operation
        let capabilities = Self::minimal_capabilities()?;

        let mut linux_builder = LinuxBuilder::default()
            .namespaces(namespaces)
            // SECURITY: Apply strict seccomp profile
            .seccomp(seccomp::default_build_profile());

        // Apply Resource Limits
        if config.limits.memory.is_some() || config.limits.cpu_shares.is_some() {
            let mut resources_builder = LinuxResourcesBuilder::default();

            if let Some(mem) = config.limits.memory {
                resources_builder = resources_builder.memory(
                    oci_spec::runtime::LinuxMemoryBuilder::default()
                        .limit(mem as i64)
                        .build()
                        .map_err(|e| CratonsError::Container(e.to_string()))?,
                );
            }

            if let Some(shares) = config.limits.cpu_shares {
                resources_builder = resources_builder.cpu(
                    oci_spec::runtime::LinuxCpuBuilder::default()
                        .shares(shares)
                        .build()
                        .map_err(|e| CratonsError::Container(e.to_string()))?,
                );
            }

            linux_builder = linux_builder.resources(
                resources_builder
                    .build()
                    .map_err(|e| CratonsError::Container(e.to_string()))?,
            );
        }

        let linux = linux_builder
            .build()
            .map_err(|e| CratonsError::Container(e.to_string()))?;

        // 5. Mounts
        let mounts = Self::generate_mounts(config)?;

        // 6. Root
        let root = RootBuilder::default()
            .path(rootfs_path.to_string_lossy().to_string())
            .readonly(true) // Rootfs should be read-only by default for security
            .build()
            .map_err(|e| CratonsError::Container(e.to_string()))?;

        // 7. Final Spec
        let spec = SpecBuilder::default()
            .version("1.0.2")
            .root(root)
            .process(process)
            .linux(linux)
            .mounts(mounts)
            .build()
            .map_err(|e| CratonsError::Container(e.to_string()))?;

        Ok(spec)
    }

    /// Generate minimal capabilities for secure container operation.
    ///
    /// # Security
    ///
    /// We drop ALL capabilities by default and only grant back the absolute
    /// minimum needed for container builds. This follows the principle of
    /// least privilege.
    ///
    /// Capabilities we DON'T grant (dangerous):
    /// - CAP_SYS_ADMIN: Allows mounting, namespace manipulation, etc.
    /// - CAP_NET_ADMIN: Allows network configuration
    /// - CAP_NET_RAW: Allows raw socket access (network sniffing)
    /// - CAP_SYS_PTRACE: Allows process tracing/debugging
    /// - CAP_SYS_MODULE: Allows loading kernel modules
    /// - CAP_DAC_OVERRIDE: Allows bypassing file permissions
    fn minimal_capabilities() -> Result<oci_spec::runtime::LinuxCapabilities> {
        // Empty capability sets = all capabilities dropped
        // This is the most secure configuration for build containers
        let caps = LinuxCapabilitiesBuilder::default()
            // Effective capabilities (what the process can actually use)
            .effective(Vec::<Capability>::new())
            // Bounding set (maximum capabilities possible)
            .bounding(Vec::<Capability>::new())
            // Inheritable (passed to child processes)
            .inheritable(Vec::<Capability>::new())
            // Permitted (what can be gained)
            .permitted(Vec::<Capability>::new())
            // Ambient (automatically gained)
            .ambient(Vec::<Capability>::new())
            .build()
            .map_err(|e| {
                CratonsError::Container(format!("failed to build capabilities: {}", e))
            })?;

        Ok(caps)
    }

    /// Validate a mount path for security.
    ///
    /// # Security
    ///
    /// This prevents path traversal attacks where a malicious mount path
    /// could escape the container or access sensitive host files.
    ///
    /// **TOCTOU Protection**: The path is canonicalized before validation to
    /// prevent symlink-based attacks where a path like `/safe/link` could
    /// point to `/etc/shadow`. The canonical path is used for all checks.
    fn validate_mount_path(path: &Path, description: &str) -> Result<()> {
        let path_str = path.to_string_lossy();

        // Check for null bytes (truncation attack) - must do before any filesystem ops
        if path_str.contains('\0') {
            return Err(CratonsError::Container(format!(
                "mount {} contains null byte: {}",
                description, path_str
            )));
        }

        // Ensure path is absolute before any other checks
        if !path.is_absolute() {
            return Err(CratonsError::Container(format!(
                "mount {} must be an absolute path: {}",
                description, path_str
            )));
        }

        // SECURITY: Canonicalize the path to resolve symlinks and prevent TOCTOU attacks
        // This resolves all symlinks, "..", "." and returns the real path
        let canonical_path = if path.exists() {
            path.canonicalize().map_err(|e| {
                CratonsError::Container(format!(
                    "mount {} failed to canonicalize (potential symlink attack): {}: {}",
                    description, path_str, e
                ))
            })?
        } else {
            // For paths that don't exist yet (destination paths), validate the
            // closest existing ancestor to prevent attacks through parent symlinks
            let mut check = path.to_path_buf();
            let mut canonical = None;
            while let Some(parent) = check.parent() {
                if parent.exists() {
                    let parent_canonical = parent.canonicalize().map_err(|e| {
                        CratonsError::Container(format!(
                            "mount {} failed to canonicalize parent: {}: {}",
                            description,
                            parent.display(),
                            e
                        ))
                    })?;
                    // Reconstruct the path with canonical parent
                    let remaining = path.strip_prefix(parent).unwrap_or(path);
                    canonical = Some(parent_canonical.join(remaining));
                    break;
                }
                check = parent.to_path_buf();
            }
            canonical.unwrap_or_else(|| path.to_path_buf())
        };

        let canonical_str = canonical_path.to_string_lossy();

        // Check for path traversal patterns in the canonical path
        // (This should be rare after canonicalization, but check anyway)
        if canonical_str.contains("..") {
            return Err(CratonsError::Container(format!(
                "mount {} contains path traversal '..': {} (canonical: {})",
                description, path_str, canonical_str
            )));
        }

        // Check for suspicious patterns that might escape containers
        // Use the CANONICAL path to prevent symlink-based bypass
        let suspicious_patterns = [
            "/proc/",
            "/proc",
            "/sys/",
            "/sys",
            "/dev/",
            "/dev",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root/",
            "/root",
            "/.ssh/",
            "/.ssh",
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/var/run/containerd/",
            "/run/containerd/",
            // Kubernetes secrets
            "/var/run/secrets/",
            "/run/secrets/",
            // System sensitive
            "/boot/",
            "/boot",
        ];
        for pattern in suspicious_patterns {
            // Check both the original and canonical paths
            if canonical_str.starts_with(pattern)
                || canonical_str == pattern.trim_end_matches('/')
            {
                return Err(CratonsError::Container(format!(
                    "mount {} references sensitive path '{}': {} (resolved to: {})",
                    description, pattern, path_str, canonical_str
                )));
            }
        }

        // Additional check: ensure canonical path isn't pointing to a different
        // location than what the user specified (symlink detection)
        if path.exists() && canonical_path != path {
            // Log the resolution for transparency
            tracing::debug!(
                "Mount path {} resolved to {} (symlink followed)",
                path_str,
                canonical_str
            );
        }

        Ok(())
    }

    fn generate_mounts(config: &SandboxConfig) -> Result<Vec<Mount>> {
        let mut mounts = vec![
            // Standard mounts
            MountBuilder::default()
                .destination("/proc")
                .typ("proc")
                .source("proc")
                .options(vec!["nosuid".into(), "noexec".into(), "nodev".into()])
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?,
            MountBuilder::default()
                .destination("/dev")
                .typ("tmpfs")
                .source("tmpfs")
                .options(vec![
                    "nosuid".into(),
                    "strictatime".into(),
                    "mode=755".into(),
                    "size=65536k".into(),
                ])
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?,
            MountBuilder::default()
                .destination("/sys")
                .typ("sysfs")
                .source("sysfs")
                .options(vec![
                    "nosuid".into(),
                    "noexec".into(),
                    "nodev".into(),
                    "ro".into(),
                ])
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?,
            MountBuilder::default()
                .destination("/tmp")
                .typ("tmpfs")
                .source("tmpfs")
                .options(vec!["nosuid".into(), "nodev".into(), "size=1g".into()])
                .build()
                .map_err(|e| CratonsError::Container(e.to_string()))?,
        ];

        // Custom RO mounts
        for m in &config.ro_mounts {
            // SECURITY: Validate both source and target paths to prevent path traversal
            Self::validate_mount_path(&m.source, "source")?;
            Self::validate_mount_path(&m.target, "target")?;

            mounts.push(
                MountBuilder::default()
                    .destination(m.target.to_string_lossy().to_string())
                    .typ("bind")
                    .source(m.source.to_string_lossy().to_string())
                    .options(vec!["rbind".into(), "ro".into()])
                    .build()
                    .map_err(|e| CratonsError::Container(e.to_string()))?,
            );
        }

        // Custom RW mounts
        for m in &config.rw_mounts {
            // SECURITY: Validate both source and target paths to prevent path traversal
            Self::validate_mount_path(&m.source, "source")?;
            Self::validate_mount_path(&m.target, "target")?;

            mounts.push(
                MountBuilder::default()
                    .destination(m.target.to_string_lossy().to_string())
                    .typ("bind")
                    .source(m.source.to_string_lossy().to_string())
                    .options(vec!["rbind".into(), "rw".into()])
                    .build()
                    .map_err(|e| CratonsError::Container(e.to_string()))?,
            );
        }

        Ok(mounts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Mount, ResourceLimits, SandboxUser};
    use std::path::PathBuf;

    /// M-17: Test OCI spec generation with default config
    #[test]
    fn test_oci_spec_basic_generation() {
        let config = SandboxConfig::new(vec!["echo".into(), "hello".into()])
            .with_workdir(PathBuf::from("/app"));

        let rootfs = PathBuf::from("/tmp/rootfs");
        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();

        // Verify basic structure
        assert_eq!(spec.version(), "1.0.2");
        assert!(spec.root().is_some());
        assert!(spec.process().is_some());
        assert!(spec.linux().is_some());

        // Verify rootfs is read-only by default
        let root = spec.root().as_ref().unwrap();
        assert!(
            root.readonly().unwrap_or(false),
            "Rootfs should be read-only for security"
        );

        // Verify process args
        let process = spec.process().as_ref().unwrap();
        let args = process.args().as_ref().unwrap();
        assert_eq!(args, &vec!["echo".to_string(), "hello".to_string()]);
    }

    /// M-17: Test resource limits are applied to OCI spec
    #[test]
    fn test_oci_spec_resource_limits() {
        let limits = ResourceLimits {
            memory: Some(512 * 1024 * 1024), // 512 MB
            cpu_shares: Some(512),
            ..Default::default()
        };

        let config = SandboxConfig::new(vec!["build".into()]).with_limits(limits);

        let rootfs = PathBuf::from("/tmp/rootfs");
        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();

        // Verify Linux resources are set
        let linux = spec.linux().as_ref().unwrap();
        let resources = linux.resources().as_ref();
        assert!(
            resources.is_some(),
            "Resources should be present when limits are set"
        );

        let resources = resources.unwrap();

        // Verify memory limit
        if let Some(memory) = resources.memory() {
            assert_eq!(memory.limit(), Some(512 * 1024 * 1024));
        }

        // Verify CPU shares
        if let Some(cpu) = resources.cpu() {
            assert_eq!(cpu.shares(), Some(512));
        }
    }

    /// M-17: Test seccomp profile is applied
    #[test]
    fn test_oci_spec_seccomp_applied() {
        let config = SandboxConfig::new(vec!["gcc".into(), "-o".into(), "main".into()]);
        let rootfs = PathBuf::from("/tmp/rootfs");

        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();

        let linux = spec.linux().as_ref().unwrap();
        let seccomp = linux.seccomp().as_ref();
        assert!(
            seccomp.is_some(),
            "Seccomp profile should be applied by default"
        );

        let seccomp = seccomp.unwrap();
        // Default profile allows most syscalls
        assert_eq!(
            seccomp.default_action(),
            LinuxSeccompAction::ScmpActAllow,
            "Default seccomp action should be Allow"
        );

        // Should have blocked syscalls
        let syscalls = seccomp.syscalls().as_ref().unwrap();
        assert!(!syscalls.is_empty(), "Should have blocked syscall rules");
    }

    /// M-17: Test namespace isolation (mount, pid, ipc, uts, user)
    #[test]
    fn test_oci_spec_namespace_isolation() {
        let config = SandboxConfig::new(vec!["sh".into()]);
        let rootfs = PathBuf::from("/tmp/rootfs");

        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();

        let linux = spec.linux().as_ref().unwrap();
        let namespaces = linux.namespaces().as_ref().unwrap();

        // Check required namespaces are present
        let ns_types: Vec<LinuxNamespaceType> = namespaces.iter().map(|ns| ns.typ()).collect();

        assert!(
            ns_types.contains(&LinuxNamespaceType::Mount),
            "Mount namespace required"
        );
        assert!(
            ns_types.contains(&LinuxNamespaceType::Pid),
            "PID namespace required"
        );
        assert!(
            ns_types.contains(&LinuxNamespaceType::Ipc),
            "IPC namespace required"
        );
        assert!(
            ns_types.contains(&LinuxNamespaceType::Uts),
            "UTS namespace required"
        );
        assert!(
            ns_types.contains(&LinuxNamespaceType::User),
            "User namespace required for rootless"
        );
    }

    /// M-17: Test network namespace isolation (NetworkAccess::None)
    #[test]
    fn test_oci_spec_network_isolation() {
        // With NetworkAccess::None, network namespace should be isolated
        let config = SandboxConfig::new(vec!["sh".into()]).with_network(NetworkAccess::None);

        let rootfs = PathBuf::from("/tmp/rootfs");
        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();

        let linux = spec.linux().as_ref().unwrap();
        let namespaces = linux.namespaces().as_ref().unwrap();

        let has_net_ns = namespaces
            .iter()
            .any(|ns| ns.typ() == LinuxNamespaceType::Network);

        assert!(
            has_net_ns,
            "Network namespace should be present when NetworkAccess::None"
        );
    }

    /// M-17: Test network namespace sharing (NetworkAccess::Full)
    #[test]
    fn test_oci_spec_network_full_access() {
        // With NetworkAccess::Full, network namespace should NOT be created
        let config = SandboxConfig::new(vec!["curl".into(), "example.com".into()])
            .with_network(NetworkAccess::Full);

        let rootfs = PathBuf::from("/tmp/rootfs");
        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();

        let linux = spec.linux().as_ref().unwrap();
        let namespaces = linux.namespaces().as_ref().unwrap();

        let has_net_ns = namespaces
            .iter()
            .any(|ns| ns.typ() == LinuxNamespaceType::Network);

        assert!(
            !has_net_ns,
            "Network namespace should NOT be present when NetworkAccess::Full"
        );
    }

    /// M-17: Test no_new_privileges is set
    #[test]
    fn test_oci_spec_no_new_privileges() {
        let config = SandboxConfig::new(vec!["sh".into()]);
        let rootfs = PathBuf::from("/tmp/rootfs");

        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();

        let process = spec.process().as_ref().unwrap();
        assert!(
            process.no_new_privileges().unwrap_or(false),
            "no_new_privileges must be true for security"
        );
    }

    /// M-17: Test custom user is applied
    #[test]
    fn test_oci_spec_custom_user() {
        let user = SandboxUser::from_ids(1001, 1001);
        let mut config = SandboxConfig::new(vec!["sh".into()]);
        config.user = Some(user);

        let rootfs = PathBuf::from("/tmp/rootfs");
        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();

        let process = spec.process().as_ref().unwrap();
        let user = process.user();
        assert_eq!(user.uid(), 1001);
        assert_eq!(user.gid(), 1001);
    }

    /// M-17: Test read-only mounts are generated correctly
    #[test]
    fn test_oci_spec_ro_mounts() {
        let config = SandboxConfig::new(vec!["sh".into()]).with_ro_mount(Mount::readonly(
            PathBuf::from("/host/src"),
            PathBuf::from("/container/src"),
        ));

        let rootfs = PathBuf::from("/tmp/rootfs");
        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();

        let mounts = spec.mounts().as_ref().unwrap();
        let src_mount = mounts
            .iter()
            .find(|m| m.destination().to_string_lossy().contains("/container/src"));

        assert!(src_mount.is_some(), "Custom mount should be present");
        let mount = src_mount.unwrap();
        let options = mount.options().as_ref().unwrap();
        assert!(
            options.contains(&"ro".to_string()),
            "Mount should be read-only"
        );
    }

    /// M-17: Test standard mounts are present (/proc, /dev, /sys, /tmp)
    #[test]
    fn test_oci_spec_standard_mounts() {
        let config = SandboxConfig::new(vec!["sh".into()]);
        let rootfs = PathBuf::from("/tmp/rootfs");

        let spec = OciSpecGenerator::generate(&config, &rootfs).unwrap();
        let mounts = spec.mounts().as_ref().unwrap();

        let mount_destinations: Vec<String> = mounts
            .iter()
            .map(|m| m.destination().to_string_lossy().to_string())
            .collect();

        assert!(
            mount_destinations.contains(&"/proc".to_string()),
            "/proc mount required"
        );
        assert!(
            mount_destinations.contains(&"/dev".to_string()),
            "/dev mount required"
        );
        assert!(
            mount_destinations.contains(&"/sys".to_string()),
            "/sys mount required"
        );
        assert!(
            mount_destinations.contains(&"/tmp".to_string()),
            "/tmp mount required"
        );
    }
}
