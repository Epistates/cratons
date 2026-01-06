//! OCI runtime specification builder.

use cratons_core::Result;
use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxNamespaceBuilder, LinuxNamespaceType,
    LinuxResourcesBuilder, MountBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
    UserBuilder,
};
use std::collections::HashMap;
use std::path::Path;

/// Default user/group ID for container processes.
const DEFAULT_UID: u32 = 1000;
const DEFAULT_GID: u32 = 1000;

/// Builder for OCI runtime specifications.
pub struct OciSpecBuilder {
    workdir: String,
    script: String,
    env: HashMap<String, String>,
    memory_limit: Option<u64>,
    cpu_limit: Option<f32>,
    output_dir: Option<String>,
    /// User ID for the container process (L-09: configurable instead of hardcoded)
    uid: u32,
    /// Group ID for the container process
    gid: u32,
}

impl OciSpecBuilder {
    /// Create a new spec builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            workdir: "/src".to_string(),
            script: String::new(),
            env: HashMap::new(),
            memory_limit: None,
            cpu_limit: None,
            output_dir: None,
            uid: DEFAULT_UID,
            gid: DEFAULT_GID,
        }
    }

    /// Set the user ID for the container process.
    #[must_use]
    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    /// Set the group ID for the container process.
    #[must_use]
    pub fn gid(mut self, gid: u32) -> Self {
        self.gid = gid;
        self
    }

    /// Set the working directory.
    #[must_use]
    pub fn workdir(mut self, workdir: &str) -> Self {
        self.workdir = workdir.to_string();
        self
    }

    /// Set the build script.
    #[must_use]
    pub fn script(mut self, script: &str) -> Self {
        self.script = script.to_string();
        self
    }

    /// Set environment variables.
    #[must_use]
    pub fn env(mut self, env: &HashMap<String, String>) -> Self {
        self.env = env.clone();
        self
    }

    /// Set memory limit.
    #[must_use]
    pub fn memory_limit(mut self, limit: Option<u64>) -> Self {
        self.memory_limit = limit;
        self
    }

    /// Set CPU limit.
    #[must_use]
    pub fn cpu_limit(mut self, limit: Option<f32>) -> Self {
        self.cpu_limit = limit;
        self
    }

    /// Set output directory.
    #[must_use]
    pub fn output_dir(mut self, dir: &Path) -> Self {
        self.output_dir = Some(dir.to_string_lossy().to_string());
        self
    }

    /// Build the OCI spec.
    pub fn build(&self) -> Result<Spec> {
        // Build environment variables
        let mut env_vec: Vec<String> = vec![
            "PATH=/toolchain/bin:/usr/local/bin:/usr/bin:/bin".to_string(),
            "HOME=/tmp".to_string(),
            "TERM=xterm".to_string(),
        ];
        for (k, v) in &self.env {
            env_vec.push(format!("{k}={v}"));
        }

        // Build minimal capability set for build processes
        // Only allow capabilities absolutely necessary for typical builds:
        // - CHOWN: for npm/pip that may try to change ownership
        // - FOWNER: for operations on files regardless of ownership
        // - SETGID/SETUID: for tools that need to drop privileges
        // - KILL: to clean up child processes
        // All dangerous capabilities (NET_*, SYS_*, MKNOD, etc.) are dropped
        use std::collections::HashSet;
        let minimal_caps: HashSet<Capability> = [
            Capability::Chown,
            Capability::Fowner,
            Capability::Setgid,
            Capability::Setuid,
            Capability::Kill,
        ]
        .into_iter()
        .collect();

        // L-11 FIX: Add descriptive context to error messages
        let capabilities = LinuxCapabilitiesBuilder::default()
            .bounding(minimal_caps.clone())
            .effective(minimal_caps.clone())
            .permitted(minimal_caps.clone())
            .inheritable(HashSet::<Capability>::new()) // No inheritable caps
            .ambient(HashSet::<Capability>::new()) // No ambient caps
            .build()
            .map_err(|e| {
                cratons_core::CratonsError::Container(format!(
                    "failed to build Linux capabilities: {e}"
                ))
            })?;

        // Build process
        let process = ProcessBuilder::default()
            .terminal(false)
            .user(
                UserBuilder::default()
                    .uid(self.uid)
                    .gid(self.gid)
                    .build()
                    .map_err(|e| {
                        cratons_core::CratonsError::Container(format!(
                            "failed to build container user (uid={}, gid={}): {e}",
                            self.uid, self.gid
                        ))
                    })?,
            )
            .args(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                self.script.clone(),
            ])
            .env(env_vec)
            .cwd(self.workdir.clone())
            .no_new_privileges(true)
            .capabilities(capabilities)
            .build()
            .map_err(|e| {
                cratons_core::CratonsError::Container(format!(
                    "failed to build container process (workdir={}): {e}",
                    self.workdir
                ))
            })?;

        // Build Linux config with namespaces
        let namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Mount)
                .build()
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build mount namespace: {e}"
                    ))
                })?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Pid)
                .build()
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build pid namespace: {e}"
                    ))
                })?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network) // No network!
                .build()
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build network namespace: {e}"
                    ))
                })?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Ipc)
                .build()
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build ipc namespace: {e}"
                    ))
                })?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .build()
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build uts namespace: {e}"
                    ))
                })?,
        ];

        let mut linux_builder = LinuxBuilder::default().namespaces(namespaces);

        // Add resource limits if specified
        if self.memory_limit.is_some() || self.cpu_limit.is_some() {
            let mut resources_builder = LinuxResourcesBuilder::default();

            if let Some(mem) = self.memory_limit {
                resources_builder = resources_builder.memory(
                    oci_spec::runtime::LinuxMemoryBuilder::default()
                        .limit(mem as i64)
                        .build()
                        .map_err(|e| {
                            cratons_core::CratonsError::Container(format!(
                                "failed to build memory limit ({mem} bytes): {e}"
                            ))
                        })?,
                );
            }

            if let Some(cpu_fraction) = self.cpu_limit {
                // CPU limit is expressed as a fraction of total CPU (e.g., 1.5 = 1.5 cores)
                // OCI uses quota/period for CPU limits
                // period is typically 100ms (100000 microseconds)
                // quota = cpu_fraction * period
                let period: u64 = 100_000; // 100ms in microseconds
                let quota: i64 = (cpu_fraction as f64 * period as f64) as i64;

                resources_builder = resources_builder.cpu(
                    oci_spec::runtime::LinuxCpuBuilder::default()
                        .period(period)
                        .quota(quota)
                        .build()
                        .map_err(|e| cratons_core::CratonsError::Container(
                            format!("failed to build CPU limit ({cpu_fraction} cores, quota={quota}): {e}")
                        ))?
                );
            }

            linux_builder = linux_builder.resources(resources_builder.build().map_err(|e| {
                cratons_core::CratonsError::Container(format!(
                    "failed to build resource limits: {e}"
                ))
            })?);
        }

        let linux = linux_builder.build().map_err(|e| {
            cratons_core::CratonsError::Container(format!(
                "failed to build Linux container config: {e}"
            ))
        })?;

        // Build mounts
        let mounts = self.build_mounts()?;

        // Build root
        let root = RootBuilder::default()
            .path("rootfs")
            .readonly(false)
            .build()
            .map_err(|e| {
                cratons_core::CratonsError::Container(format!(
                    "failed to build container root filesystem: {e}"
                ))
            })?;

        // Build final spec
        let spec = SpecBuilder::default()
            .version("1.0.2")
            .root(root)
            .process(process)
            .linux(linux)
            .mounts(mounts)
            .build()
            .map_err(|e| {
                cratons_core::CratonsError::Container(format!("failed to build OCI spec: {e}"))
            })?;

        Ok(spec)
    }

    /// Build mount points.
    fn build_mounts(&self) -> Result<Vec<oci_spec::runtime::Mount>> {
        // L-11 FIX: Add context to mount build errors
        let mut mounts = vec![
            // /proc
            MountBuilder::default()
                .destination("/proc")
                .typ("proc")
                .source("proc")
                .options(vec!["nosuid".into(), "noexec".into(), "nodev".into()])
                .build()
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build /proc mount: {e}"
                    ))
                })?,
            // /dev (minimal)
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
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build /dev mount: {e}"
                    ))
                })?,
            // /dev/pts
            MountBuilder::default()
                .destination("/dev/pts")
                .typ("devpts")
                .source("devpts")
                .options(vec![
                    "nosuid".into(),
                    "noexec".into(),
                    "newinstance".into(),
                    "ptmxmode=0666".into(),
                    "mode=0620".into(),
                ])
                .build()
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build /dev/pts mount: {e}"
                    ))
                })?,
            // /dev/shm
            MountBuilder::default()
                .destination("/dev/shm")
                .typ("tmpfs")
                .source("tmpfs")
                .options(vec![
                    "nosuid".into(),
                    "noexec".into(),
                    "nodev".into(),
                    "mode=1777".into(),
                    "size=65536k".into(),
                ])
                .build()
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build /dev/shm mount: {e}"
                    ))
                })?,
            // /sys (read-only)
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
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build /sys mount: {e}"
                    ))
                })?,
            // /tmp
            MountBuilder::default()
                .destination("/tmp")
                .typ("tmpfs")
                .source("tmpfs")
                .options(vec!["nosuid".into(), "nodev".into(), "size=1g".into()])
                .build()
                .map_err(|e| {
                    cratons_core::CratonsError::Container(format!(
                        "failed to build /tmp mount: {e}"
                    ))
                })?,
        ];

        // Output directory mount if specified
        if let Some(ref out_dir) = self.output_dir {
            mounts.push(
                MountBuilder::default()
                    .destination("/out")
                    .typ("bind")
                    .source(out_dir.clone())
                    .options(vec!["rbind".into(), "rw".into()])
                    .build()
                    .map_err(|e| {
                        cratons_core::CratonsError::Container(format!(
                            "failed to build /out bind mount to {out_dir}: {e}"
                        ))
                    })?,
            );
        }

        Ok(mounts)
    }
}

impl Default for OciSpecBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spec_builder() {
        let spec = OciSpecBuilder::new()
            .workdir("/src")
            .script("echo hello")
            .build()
            .unwrap();

        assert_eq!(spec.version(), "1.0.2");
        assert!(spec.process().is_some());
        assert!(spec.linux().is_some());
    }
}
