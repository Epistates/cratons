//! # cratons-sandbox
//!
//! Cross-platform sandboxed execution for hermetic builds.
//!
//! This crate provides isolated execution environments with:
//! - Full OCI container isolation on Linux (using youki concepts)
//! - sandbox-exec on macOS
//! - Job Objects/AppContainer on Windows
//! - Graceful degradation to process isolation where needed

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod result;
pub mod runner;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub mod seccomp;

#[cfg(target_os = "linux")]
pub mod spec;

#[cfg(target_os = "linux")]
pub mod container;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
pub mod apple_virt;

#[cfg(target_os = "windows")]
pub mod windows;

pub mod qemu;

mod process;

use async_trait::async_trait;

pub use config::{Mount, NetworkAccess, ResourceLimits, SandboxConfig};
pub use error::SandboxError;
pub use result::SandboxResult;

/// The target platform for the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxTarget {
    /// Run on the host OS (native).
    Native,
    /// Run in a Linux environment (Native on Linux, VM elsewhere).
    Linux,
}

/// The level of isolation provided by the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Full OCI container with namespaces, cgroups, seccomp (Linux)
    Container,
    /// Lightweight Virtual Machine (e.g. QEMU/VirtioFS, Apple Virtualization)
    Vm,
    /// OS-level sandbox (Windows Job Objects/AppContainer, macOS sandbox-exec)
    OsSandbox,
    /// Process isolation with restricted environment
    Process,
    /// No isolation available - direct execution
    None,
}

impl IsolationLevel {
    /// Check if this isolation level provides filesystem isolation.
    #[must_use]
    pub fn has_filesystem_isolation(&self) -> bool {
        matches!(self, Self::Container | Self::Vm | Self::OsSandbox)
    }

    /// Check if this isolation level provides network isolation.
    #[must_use]
    pub fn has_network_isolation(&self) -> bool {
        matches!(self, Self::Container | Self::Vm)
    }

    /// Check if this isolation level provides resource limits.
    #[must_use]
    pub fn has_resource_limits(&self) -> bool {
        matches!(self, Self::Container | Self::Vm | Self::OsSandbox)
    }
}

/// Platform-agnostic sandbox interface.
///
/// This trait abstracts over different sandboxing mechanisms on various platforms.
#[async_trait]
pub trait Sandbox: Send + Sync {
    /// Execute a command in the sandbox.
    async fn execute(&self, config: &SandboxConfig) -> Result<SandboxResult, SandboxError>;

    /// Get the isolation level provided by this sandbox.
    fn isolation_level(&self) -> IsolationLevel;

    /// Check if the sandbox is available on this system.
    fn is_available(&self) -> bool;

    /// Get a human-readable description of the sandbox.
    fn description(&self) -> &'static str;

    /// Check if the sandbox has partial capabilities (e.g., missing network/FS isolation).
    ///
    /// Returns `true` if the sandbox cannot enforce all requested isolation guarantees
    /// (common on Windows Job Objects or simple process sandboxes).
    fn is_partial(&self) -> bool {
        false
    }
}

/// Create the best available sandbox for the current platform (Native target).
#[must_use]
pub fn create_sandbox() -> Box<dyn Sandbox> {
    create_sandbox_for_target(SandboxTarget::Native)
}

/// Create a sandbox for a specific target platform.
#[must_use]
pub fn create_sandbox_for_target(target: SandboxTarget) -> Box<dyn Sandbox> {
    match target {
        SandboxTarget::Native => {
            #[cfg(target_os = "linux")]
            {
                if linux::LinuxSandbox::is_container_available() {
                    return Box::new(linux::LinuxSandbox::new());
                }
            }

            #[cfg(target_os = "macos")]
            {
                // Prefer native macOS sandbox for native builds
                if macos::MacOsSandbox::is_available() {
                    return Box::new(macos::MacOsSandbox::new());
                }
            }

            #[cfg(target_os = "windows")]
            {
                return Box::new(windows::WindowsSandbox::new());
            }
        }
        SandboxTarget::Linux => {
            #[cfg(target_os = "linux")]
            {
                // Linux on Linux is just a container
                if linux::LinuxSandbox::is_container_available() {
                    return Box::new(linux::LinuxSandbox::new());
                }
            }

            #[cfg(target_os = "macos")]
            {
                // Try Apple Virtualization first (if 'container' tool is present)
                if apple_virt::AppleContainerSandbox::is_available() {
                    return Box::new(apple_virt::AppleContainerSandbox::new());
                }

                // Fallback to QEMU
                if qemu::QemuSandbox::is_available() {
                    return Box::new(qemu::QemuSandbox::new());
                }
            }

            // On Windows/others, try QEMU
            if qemu::QemuSandbox::is_available() {
                return Box::new(qemu::QemuSandbox::new());
            }
        }
    }

    // Fallback to process-based isolation
    Box::new(process::ProcessSandbox::new())
}

/// Create a sandbox with a specific isolation level.
///
/// Returns `None` if the requested isolation level is not available.
#[must_use]
pub fn create_sandbox_with_level(level: IsolationLevel) -> Option<Box<dyn Sandbox>> {
    match level {
        IsolationLevel::Container => {
            #[cfg(target_os = "linux")]
            {
                if linux::LinuxSandbox::is_container_available() {
                    return Some(Box::new(linux::LinuxSandbox::new()));
                }
            }
            None
        }
        IsolationLevel::Vm => {
            #[cfg(target_os = "macos")]
            {
                if apple_virt::AppleContainerSandbox::is_available() {
                    return Some(Box::new(apple_virt::AppleContainerSandbox::new()));
                }
            }

            if qemu::QemuSandbox::is_available() {
                Some(Box::new(qemu::QemuSandbox::new()))
            } else {
                None
            }
        }
        IsolationLevel::OsSandbox => {
            #[cfg(target_os = "windows")]
            return Some(Box::new(windows::WindowsSandbox::new()));

            #[cfg(target_os = "macos")]
            return Some(Box::new(macos::MacOsSandbox::new()));

            #[allow(unreachable_code)]
            None
        }
        IsolationLevel::Process => Some(Box::new(process::ProcessSandbox::new())),
        IsolationLevel::None => Some(Box::new(process::ProcessSandbox::new())),
    }
}

/// Get the best available isolation level on this platform.
#[must_use]
pub fn best_isolation_level() -> IsolationLevel {
    // Check for VM first (highest isolation on non-Linux)
    if qemu::QemuSandbox::is_available() {
        return IsolationLevel::Vm;
    }

    #[cfg(target_os = "linux")]
    {
        if linux::LinuxSandbox::is_container_available() {
            return IsolationLevel::Container;
        }
    }

    #[allow(unreachable_code)]
    #[cfg(target_os = "macos")]
    {
        return IsolationLevel::OsSandbox;
    }

    #[cfg(target_os = "windows")]
    {
        return IsolationLevel::OsSandbox;
    }

    #[allow(unreachable_code)]
    IsolationLevel::Process
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolation_level_properties() {
        assert!(IsolationLevel::Container.has_filesystem_isolation());
        assert!(IsolationLevel::Container.has_network_isolation());
        assert!(IsolationLevel::Container.has_resource_limits());

        assert!(IsolationLevel::Vm.has_filesystem_isolation());
        assert!(IsolationLevel::Vm.has_network_isolation());
        assert!(IsolationLevel::Vm.has_resource_limits());

        assert!(IsolationLevel::OsSandbox.has_filesystem_isolation());
        assert!(!IsolationLevel::OsSandbox.has_network_isolation());
        assert!(IsolationLevel::OsSandbox.has_resource_limits());

        assert!(!IsolationLevel::Process.has_filesystem_isolation());
        assert!(!IsolationLevel::Process.has_network_isolation());
        assert!(!IsolationLevel::Process.has_resource_limits());
    }

    #[test]
    fn test_create_sandbox() {
        let sandbox = create_sandbox();
        assert!(sandbox.description().len() > 0);
    }

    #[test]
    fn test_best_isolation_level() {
        let level = best_isolation_level();
        // Should always return something
        assert!(matches!(
            level,
            IsolationLevel::Container
                | IsolationLevel::OsSandbox
                | IsolationLevel::Process
                | IsolationLevel::None
        ));
    }
}
