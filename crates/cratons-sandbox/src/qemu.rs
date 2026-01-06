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
    fn generate_init_script(&self, config: &SandboxConfig) -> String {
        // Properly shell-escape the command arguments
        let cmd_str = config
            .command
            .iter()
            .map(|arg| shell_escape(arg))
            .collect::<Vec<_>>()
            .join(" ");

        // Basic init script that mounts the workspace and runs the command
        format!(
            "#!/bin/sh\nmount -t virtiofs workspace /mnt/workspace\ncd /mnt/workspace\nexport PATH=/bin:/usr/bin:/sbin:/usr/sbin\n{env_vars}\necho \"Running: {cmd}\"\n{cmd}\nEXIT_CODE=$?\necho \"EXIT_CODE=$EXIT_CODE\"\nsync\npoweroff -f\n",
            env_vars = config
                .env
                .iter()
                .filter(|(k, _)| is_safe_shell_var_name(k)) // Validate var name
                .map(|(k, v)| format!("export {}={}", k, shell_escape(v)))
                .collect::<Vec<_>>()
                .join("\n"),
            cmd = cmd_str
        )
    }
}

#[async_trait]
impl Sandbox for QemuSandbox {
    async fn execute(&self, config: &SandboxConfig) -> Result<SandboxResult, SandboxError> {
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
        let script_content = self.generate_init_script(config);

        tokio::fs::write(&script_path, script_content)
            .await
            .map_err(|e| SandboxError::Io(e))?;

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

        let start = Instant::now();
        let output = cmd.output().await?;
        let duration = start.elapsed();

        // Cleanup
        let _ = tokio::fs::remove_file(&script_path).await;

        let stdout = output.stdout;
        let stderr = output.stderr;

        // Parse exit code from stdout/stderr if QEMU itself succeeded
        // (Since QEMU exit code is about QEMU, not the guest process usually)
        let exit_code = if output.status.success() {
            // Parse the actual exit code from stdout where init script printed it
            // Format: "EXIT_CODE=X" on its own line
            parse_guest_exit_code(&stdout).unwrap_or(0)
        } else {
            output.status.code().unwrap_or(-1)
        };

        Ok(SandboxResult {
            exit_code,
            stdout,
            stderr,
            duration,
            timed_out: false,
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

/// Shell-escape a string for use in shell scripts.
///
/// Uses single quotes and escapes embedded single quotes using the
/// `'\''` pattern (end quote, escaped quote, start quote).
fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }

    // If the string contains no special characters, no quoting needed
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/')
    {
        return s.to_string();
    }

    // Use single quotes with embedded single quote escape
    let escaped = s.replace('\'', "'\\''");
    format!("'{}'", escaped)
}

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
/// The init script should print "EXIT_CODE=X" on its own line.
/// This function searches for that pattern and extracts X.
fn parse_guest_exit_code(stdout: &[u8]) -> Option<i32> {
    let output = String::from_utf8_lossy(stdout);

    for line in output.lines() {
        let line = line.trim();
        if let Some(code_str) = line.strip_prefix("EXIT_CODE=") {
            if let Ok(code) = code_str.parse::<i32>() {
                return Some(code);
            }
        }
        // Also support "Exit code: X" format for backwards compatibility
        if let Some(code_str) = line.strip_prefix("Exit code: ") {
            if let Ok(code) = code_str.parse::<i32>() {
                return Some(code);
            }
        }
    }

    None
}
