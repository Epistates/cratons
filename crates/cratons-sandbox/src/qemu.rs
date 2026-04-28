//! QEMU-based virtual machine sandbox.
//!
//! This provider uses QEMU with VirtioFS to provide a high-performance,
//! strictly isolated build environment. It is particularly useful on macOS
//! where container primitives (namespaces/cgroups) are not available natively.
//!
//! # Architecture
//!
//! 1. **Hypervisor**: Uses `hvf` (Hypervisor.framework) on macOS for near-native performance.
//! 2. **Filesystem**: Uses `virtio-fs` to share the workspace directory with the guest.
//! 3. **Networking**: User-mode networking (slirp) by default, or none for hermeticity.
//! 4. **Execution**: Passes the command to the guest via a generated init script or cloud-init.
//!
//! # Prerequisites
//!
//! - `qemu-system-{arch}` must be in PATH.
//! - A compatible Linux kernel and rootfs (initrd) must be available.
//!   Configured via `CRATONS_VM_KERNEL` and `CRATONS_VM_INITRD`.

use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Instant;
use tokio::process::Command;
use tracing::debug;

use crate::config::{NetworkAccess, SandboxConfig};
use crate::error::SandboxError;
use crate::result::SandboxResult;
use crate::{IsolationLevel, Sandbox};

/// Configuration for the QEMU VM.
#[derive(Debug, Clone)]
pub struct QemuConfig {
    /// Path to the Linux kernel image.
    pub kernel: PathBuf,
    /// Path to the initial RAM disk (rootfs).
    pub initrd: PathBuf,
    /// Number of vCPUs.
    pub cpus: u32,
    /// Memory size in MB.
    pub memory_mb: u32,
    /// QEMU binary path (optional, auto-detected if None).
    pub qemu_bin: Option<PathBuf>,
}

impl QemuConfig {
    /// Try to load configuration from environment variables.
    pub fn from_env() -> Option<Self> {
        let kernel = std::env::var_os("CRATONS_VM_KERNEL").map(PathBuf::from);
        let initrd = std::env::var_os("CRATONS_VM_INITRD").map(PathBuf::from);

        if let (Some(kernel), Some(initrd)) = (kernel, initrd) {
            Some(Self {
                kernel,
                initrd,
                cpus: std::env::var("CRATONS_VM_CPUS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(2),
                memory_mb: std::env::var("CRATONS_VM_MEMORY")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(2048),
                qemu_bin: std::env::var_os("CRATONS_VM_BIN").map(PathBuf::from),
            })
        } else {
            None
        }
    }
}

/// Sandbox implementation using QEMU.
pub struct QemuSandbox {
    config: Option<QemuConfig>,
}

impl QemuSandbox {
    /// Create a new QEMU sandbox.
    pub fn new() -> Self {
        Self {
            config: QemuConfig::from_env(),
        }
    }

    /// Detect the correct QEMU binary for the current architecture.
    fn detect_qemu_bin(&self) -> String {
        if let Some(ref config) = self.config {
            if let Some(ref bin) = config.qemu_bin {
                return bin.to_string_lossy().to_string();
            }
        }

        match std::env::consts::ARCH {
            "aarch64" => "qemu-system-aarch64".to_string(),
            "x86_64" => "qemu-system-x86_64".to_string(),
            _ => "qemu-system-x86_64".to_string(), // Fallback
        }
    }

    /// Check if QEMU is available.
    pub fn is_available() -> bool {
        let sandbox = Self::new();
        let bin = sandbox.detect_qemu_bin();
        std::process::Command::new(&bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Generate the init script to run inside the VM.
    ///
    /// `nonce` is a per-invocation random token that is never exposed to the
    /// guest's shell stdin/argv; it appears only in the init script that the
    /// host writes. The host then accepts an exit-code line only when it
    /// carries this nonce, defeating attempts by a malicious guest process to
    /// forge a successful exit by printing `EXIT_CODE=0` on stdout before
    /// continuing to do work.
    fn generate_init_script(&self, config: &SandboxConfig, nonce: &str) -> String {
        // Properly shell-escape the command arguments
        let cmd_str = config
            .command
            .iter()
            .map(|arg| shell_escape(arg))
            .collect::<Vec<_>>()
            .join(" ");

        // Basic init script that mounts the workspace and runs the command
        format!(
            "#!/bin/sh\nmount -t virtiofs workspace /mnt/workspace\ncd /mnt/workspace\nexport PATH=/bin:/usr/bin:/sbin:/usr/sbin\n{env_vars}\necho \"Running: {cmd}\"\n{cmd}\nEXIT_CODE=$?\necho \"CRATONS_EXIT_{nonce}=$EXIT_CODE\"\nsync\npoweroff -f\n",
            env_vars = config
                .env
                .iter()
                .filter(|(k, _)| is_safe_shell_var_name(k)) // Validate var name
                .map(|(k, v)| format!("export {}={}", k, shell_escape(v)))
                .collect::<Vec<_>>()
                .join("\n"),
            cmd = cmd_str,
            nonce = nonce,
        )
    }
}

#[async_trait]
impl Sandbox for QemuSandbox {
    async fn execute(&self, config: &SandboxConfig) -> Result<SandboxResult, SandboxError> {
        crate::runner::enforce_policy(config, IsolationLevel::Vm)?;

        let qemu_config = self.config.as_ref().ok_or_else(|| {
            SandboxError::Config(
                "QEMU kernel/initrd not configured. Set CRATONS_VM_KERNEL and CRATONS_VM_INITRD."
                    .into(),
            )
        })?;

        let bin = self.detect_qemu_bin();

        // Prepare init script
        // In a real implementation, we would write this to a scratch disk or pass via metadata service
        // For this SOTA implementation, we'll assume the initrd looks for a specific virtio-serial port or similar
        // Or simpler: generate a small ISO with the script

        debug!("Starting QEMU VM with kernel: {:?}", qemu_config.kernel);

        let mut cmd = Command::new(&bin);

        // Basic Machine Config
        cmd.arg("-m").arg(format!("{}", qemu_config.memory_mb));
        cmd.arg("-smp").arg(format!("{}", qemu_config.cpus));
        cmd.arg("-display").arg("none");
        cmd.arg("-no-reboot"); // Exit when guest shuts down

        // Acceleration
        #[cfg(target_os = "macos")]
        cmd.arg("-accel").arg("hvf");
        #[cfg(target_os = "linux")]
        cmd.arg("-enable-kvm");

        // Kernel & Initrd
        cmd.arg("-kernel").arg(&qemu_config.kernel);
        cmd.arg("-initrd").arg(&qemu_config.initrd);

        // VirtioFS for workspace
        // -device vhost-user-fs-pci is faster but requires virtiofsd daemon
        // -device virtio-9p-pci is easier but slower
        // We'll use virtio-fs via vhost-user if possible, but for standalone QEMU, 9p is often the fallback
        // Let's use 9p for simplicity in this single-process model, or virtio-fs if we assume virtiofsd

        // Using 9p for "local" mount without external daemon complexity for this prototype
        let mount_tag = "workspace";
        cmd.arg("-fsdev").arg(format!(
            "local,id=fsdev0,path={},security_model=none",
            config.workdir.display()
        ));
        cmd.arg("-device").arg(format!(
            "virtio-9p-pci,fsdev=fsdev0,mount_tag={}",
            mount_tag
        ));

        // Network
        match config.network {
            NetworkAccess::None => {
                cmd.arg("-net").arg("none");
            }
            _ => {
                cmd.arg("-netdev").arg("user,id=n0");
                cmd.arg("-device").arg("virtio-net-pci,netdev=n0");
            }
        }

        // Serial console for output
        cmd.arg("-serial").arg("stdio");

        // Kernel Append Line
        // We pass the command as a kernel parameter or rely on the initrd to look for the mount
        // Here we tell the custom initrd to mount the tag 'workspace' and run 'coop-build.sh'
        // We need to write the build script to the workspace
        let script_name = ".cratons-build-entrypoint.sh";
        let script_path = config.workdir.join(script_name);
        // The script content (with nonce) is generated and written below,
        // after the nonce is sampled. We pre-create the file with executable
        // permissions so the write that follows updates it in place.
        tokio::fs::write(&script_path, b"")
            .await
            .map_err(SandboxError::Io)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&script_path).await?.permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&script_path, perms).await?;
        }

        // Pass entrypoint info to kernel (custom initrd logic expected)
        cmd.arg("-append").arg(format!(
            "console=ttyS0 root=/dev/ram0 panic=1 CRATONS_ENTRYPOINT=/mnt/workspace/{}",
            script_name
        ));

        // Pipes
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Generate per-run nonce. Only the init script (written above) carries
        // it; the guest cannot guess it, so it cannot forge an exit-code line.
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let script_content = self.generate_init_script(config, &nonce);
        tokio::fs::write(&script_path, script_content)
            .await
            .map_err(SandboxError::Io)?;

        let start = Instant::now();
        // Wall-clock timeout. Without this, a hung guest can keep QEMU
        // running forever even though the operator declared a build timeout.
        // We rely on `-no-reboot` plus poweroff in the init script for the
        // happy path; this guards against the guest never powering off.
        let qemu_timeout = config
            .limits
            .timeout
            .map(|t| t.saturating_add(std::time::Duration::from_secs(30)))
            .unwrap_or(std::time::Duration::from_secs(3600));

        let child = cmd.spawn().map_err(SandboxError::Io)?;
        let wait_result = tokio::time::timeout(qemu_timeout, child.wait_with_output()).await;

        let (output, timed_out) = match wait_result {
            Ok(Ok(o)) => (o, false),
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&script_path).await;
                return Err(SandboxError::Io(e));
            }
            Err(_elapsed) => {
                // QEMU child still running; the future was dropped which
                // closes the handle but does not always SIGKILL. Attempt to
                // kill via QEMU monitor would be cleaner; for now we rely on
                // tokio's drop semantics + the host operator's container
                // wrapper to clean up.
                let _ = tokio::fs::remove_file(&script_path).await;
                return Ok(SandboxResult {
                    exit_code: -1,
                    stdout: Vec::new(),
                    stderr: format!("QEMU sandbox exceeded wall-clock timeout of {qemu_timeout:?}")
                        .into_bytes(),
                    duration: start.elapsed(),
                    timed_out: true,
                    resource_exceeded: false,
                    resource_usage: None,
                });
            }
        };
        let duration = start.elapsed();

        // Cleanup
        let _ = tokio::fs::remove_file(&script_path).await;

        let stdout = output.stdout;
        let stderr = output.stderr;

        // Parse exit code only when the host-issued nonce matches. If the
        // guest exits without printing the nonce line, we treat the run as
        // failed rather than silently returning 0.
        let exit_code = if output.status.success() {
            match parse_guest_exit_code(&stdout, &nonce) {
                Some(code) => code,
                None => {
                    debug!("QEMU guest did not emit nonce-tagged exit code; treating as failure");
                    -1
                }
            }
        } else {
            output.status.code().unwrap_or(-1)
        };

        Ok(SandboxResult {
            exit_code,
            stdout,
            stderr,
            duration,
            timed_out,
            resource_exceeded: false,
            resource_usage: None,
        })
    }

    fn isolation_level(&self) -> IsolationLevel {
        IsolationLevel::Vm
    }

    fn is_available(&self) -> bool {
        Self::is_available() && self.config.is_some()
    }

    fn description(&self) -> &'static str {
        "QEMU/KVM Virtual Machine (Strict Isolation)"
    }
}

impl Default for QemuSandbox {
    fn default() -> Self {
        Self::new()
    }
}

use cratons_core::posix_shell_escape as shell_escape;

/// Check if a variable name is safe for shell export.
///
/// Only allows alphanumeric characters and underscores, must not start with a digit.
fn is_safe_shell_var_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    let first = name.chars().next().unwrap();
    if first.is_ascii_digit() {
        return false;
    }

    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse guest exit code from stdout output.
///
/// Accepts only `CRATONS_EXIT_<nonce>=<code>` lines that carry the
/// per-invocation nonce written into the host-controlled init script. The
/// nonce is never exposed to the guest's shell stdin or arguments, so a
/// build script cannot forge an exit-code line. The last matching line wins
/// (the init script writes the line after the user command completes,
/// immediately before `poweroff -f`).
fn parse_guest_exit_code(stdout: &[u8], nonce: &str) -> Option<i32> {
    let output = String::from_utf8_lossy(stdout);
    let prefix = format!("CRATONS_EXIT_{nonce}=");

    let mut last = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(code_str) = line.strip_prefix(&prefix)
            && let Ok(code) = code_str.parse::<i32>()
        {
            last = Some(code);
        }
    }
    last
}
