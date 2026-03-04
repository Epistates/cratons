//! Windows sandbox implementation using Job Objects.
//!
//! This provides sandbox isolation using:
//! - Job Objects for resource limits (memory, CPU, process count)
//! - Process isolation with kill-on-job-close
//! - Resource usage tracking via job accounting
//!
//! ## Job Objects Capabilities
//!
//! | Feature | Support |
//! |---------|---------|
//! | Memory limits | Full (per-process and total job) |
//! | CPU time limits | Full (per-process user-mode time) |
//! | CPU rate control | Full (Windows 8+) |
//! | Process count limit | Full |
//! | Kill on close | Full |
//! | Network isolation | Not supported (requires Windows Firewall or AppContainer) |
//! | Filesystem isolation | Not supported (use process working directory) |
//!
//! ## References
//!
//! - [JOBOBJECT_EXTENDED_LIMIT_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)
//! - [JOBOBJECT_BASIC_LIMIT_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information)

use std::io;
use std::mem::{self, MaybeUninit};
use std::path::PathBuf;
use std::process::Stdio;
use std::ptr;
use std::time::Instant;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, instrument, warn};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

use crate::config::SandboxConfig;
use crate::error::SandboxError;
use crate::result::{ResourceUsage, SandboxResult};
use crate::{IsolationLevel, Sandbox};

/// Windows sandbox using Job Objects for process isolation and resource limits.
///
/// Job Objects provide:
/// - Memory limits (per-process and total)
/// - CPU time limits (user-mode time)
/// - Process count limits
/// - Automatic cleanup (kill all processes when job closes)
///
/// Note: Network and filesystem isolation require additional Windows features
/// (Windows Firewall, AppContainer) which are not implemented here.
pub struct WindowsSandbox {
    /// Job Object configuration
    config: JobConfig,
}

/// Configuration for the Windows Job Object.
#[derive(Debug, Clone, Default)]
struct JobConfig {
    /// Kill all processes when the job handle is closed
    kill_on_close: bool,
}

/// RAII wrapper for a Windows Job Object handle.
struct JobObject {
    handle: HANDLE,
}

impl JobObject {
    /// Create a new anonymous Job Object.
    fn create() -> Result<Self, SandboxError> {
        // SAFETY: Creating an anonymous job object with no security attributes
        let handle = unsafe { CreateJobObjectW(None, None) }
            .map_err(|e| SandboxError::Internal(format!("Failed to create job object: {e}")))?;

        if handle.is_invalid() {
            return Err(SandboxError::Internal(
                "CreateJobObjectW returned invalid handle".into(),
            ));
        }

        Ok(Self { handle })
    }

    /// Configure the job with extended limits.
    #[instrument(skip(self, config), level = "debug")]
    fn configure(&self, config: &SandboxConfig) -> Result<(), SandboxError> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        // Memory limits
        if let Some(memory_limit) = config.limits.memory {
            // Set both per-process and total job memory limits
            info.ProcessMemoryLimit = memory_limit as usize;
            info.JobMemoryLimit = memory_limit as usize;
            limit_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
            debug!(memory_limit, "Setting memory limit");
        }

        // CPU time limit (converted from Duration to 100-nanosecond ticks)
        if let Some(timeout) = config.limits.timeout {
            // Per-process user-mode time limit
            let ticks = (timeout.as_nanos() / 100) as i64;
            info.BasicLimitInformation.PerProcessUserTimeLimit = ticks;
            limit_flags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
            debug!(timeout_ms = timeout.as_millis(), "Setting CPU time limit");
        }

        // Process count limit
        if let Some(pids) = config.limits.pids {
            info.BasicLimitInformation.ActiveProcessLimit = pids as u32;
            limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            debug!(pids, "Setting active process limit");
        }

        info.BasicLimitInformation.LimitFlags = limit_flags;

        // SAFETY: Setting job information with properly sized structure
        unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                ptr::addr_of!(info).cast(),
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| SandboxError::Internal(format!("Failed to set job limits: {e}")))?;
        }

        Ok(())
    }

    /// Assign a process to this job by PID.
    fn assign_process(&self, pid: u32) -> Result<(), SandboxError> {
        // SAFETY: Opening process with required access rights
        let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }
            .map_err(|e| SandboxError::Internal(format!("Failed to open process {pid}: {e}")))?;

        // SAFETY: Assigning valid process handle to job
        let result = unsafe { AssignProcessToJobObject(self.handle, process_handle) };

        // Close the process handle regardless of success
        // SAFETY: Closing valid handle
        let _ = unsafe { CloseHandle(process_handle) };

        result.map_err(|e| {
            SandboxError::Internal(format!("Failed to assign process {pid} to job: {e}"))
        })?;

        debug!(pid, "Assigned process to job");
        Ok(())
    }

    /// Query resource usage accounting from the job.
    fn query_accounting(&self) -> Result<ResourceUsage, SandboxError> {
        let mut info = MaybeUninit::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>::uninit();
        let mut return_length = 0u32;

        // SAFETY: Querying job information with properly sized buffer
        unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectBasicAccountingInformation,
                info.as_mut_ptr().cast(),
                mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                Some(&mut return_length),
            )
            .map_err(|e| SandboxError::Internal(format!("Failed to query job accounting: {e}")))?;
        }

        // SAFETY: QueryInformationJobObject succeeded, info is initialized
        let info = unsafe { info.assume_init() };

        // Convert 100-nanosecond ticks to milliseconds
        let user_time_ms = (info.TotalUserTime / 10_000) as u64;
        let kernel_time_ms = (info.TotalKernelTime / 10_000) as u64;

        Ok(ResourceUsage {
            user_time_ms: Some(user_time_ms),
            system_time_ms: Some(kernel_time_ms),
            cpu_time_ms: Some(user_time_ms + kernel_time_ms),
            peak_memory: None, // Would need JobObjectExtendedLimitInformation query
            context_switches: None,
            io_read_bytes: Some(info.ReadTransferCount as u64),
            io_write_bytes: Some(info.WriteTransferCount as u64),
        })
    }

    /// Query peak memory usage from extended limit info.
    fn query_peak_memory(&self) -> Option<u64> {
        let mut info = MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::uninit();
        let mut return_length = 0u32;

        // SAFETY: Querying job information with properly sized buffer
        let result = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                info.as_mut_ptr().cast(),
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                Some(&mut return_length),
            )
        };

        if result.is_ok() {
            // SAFETY: Query succeeded
            let info = unsafe { info.assume_init() };
            Some(info.PeakJobMemoryUsed as u64)
        } else {
            None
        }
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: Closing valid handle; kill-on-close will terminate processes
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

impl WindowsSandbox {
    /// Create a new Windows sandbox with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: JobConfig {
                kill_on_close: true,
            },
        }
    }

    /// Check if the sandbox has only partial isolation capabilities.
    ///
    /// On Windows, Job Objects provide memory and CPU limits but do NOT provide
    /// network or filesystem isolation. This method returns true to indicate
    /// that full hermetic isolation is not available.
    pub fn is_isolation_partial(&self) -> bool {
        true
    }

    /// Execute a command with Job Object limits applied.
    #[instrument(skip(self, config), fields(cmd = ?config.command.first()), level = "debug")]
    async fn execute_with_job(
        &self,
        config: &SandboxConfig,
    ) -> Result<SandboxResult, SandboxError> {
        let program = &config.command[0];
        let args = &config.command[1..];

        // Create the job object first
        let job = JobObject::create()?;
        job.configure(config)?;

        // Build the command
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.current_dir(&config.workdir);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Environment handling
        if !config.inherit_env {
            cmd.env_clear();
        }
        for (key, value) in &config.env {
            cmd.env(key, value);
        }

        let start = Instant::now();

        // Spawn the process
        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                SandboxError::CommandNotFound(program.clone())
            } else {
                SandboxError::Io(e)
            }
        })?;

        // Get the PID and assign to job
        let pid = child
            .id()
            .ok_or_else(|| SandboxError::Internal("Failed to get process ID after spawn".into()))?;

        // Assign to job - this applies all the limits
        job.assign_process(pid)?;

        // Wait for completion with optional timeout
        let output = if let Some(timeout_duration) = config.limits.timeout {
            match timeout(timeout_duration, child.wait_with_output()).await {
                Ok(result) => result?,
                Err(_) => {
                    // Timeout - job will be dropped, killing all processes
                    warn!(pid, timeout = ?timeout_duration, "Process timed out, terminating via job");
                    return Ok(SandboxResult {
                        exit_code: 124,
                        stdout: Vec::new(),
                        stderr: b"Process timed out".to_vec(),
                        duration: start.elapsed(),
                        timed_out: true,
                        resource_exceeded: false,
                        resource_usage: None,
                    });
                }
            }
        } else {
            child.wait_with_output().await?
        };

        let duration = start.elapsed();

        // Query resource usage from job
        let mut resource_usage = job.query_accounting().ok();
        if let Some(ref mut usage) = resource_usage {
            usage.peak_memory = job.query_peak_memory();
        }

        // Check if process was killed due to CPU time limit
        let resource_exceeded = output.status.code().is_none() && !output.status.success();

        Ok(SandboxResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
            duration,
            timed_out: false,
            resource_exceeded,
            resource_usage,
        })
    }
}

impl Default for WindowsSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Sandbox for WindowsSandbox {
    #[instrument(skip(self, config), fields(cmd = ?config.command.first()), level = "debug")]
    async fn execute(&self, config: &SandboxConfig) -> Result<SandboxResult, SandboxError> {
        if config.command.is_empty() {
            return Err(SandboxError::Config("No command specified".into()));
        }

        // Log network/mount warnings - not supported on Windows via Job Objects
        if !matches!(config.network, crate::config::NetworkAccess::Full) {
            warn!(
                "Network isolation not supported on Windows via Job Objects - \
                 requires Windows Firewall or AppContainer"
            );
        }
        if !config.ro_mounts.is_empty() || !config.rw_mounts.is_empty() {
            warn!(
                "Filesystem mounts not supported on Windows - \
                 use working directory for isolation"
            );
        }

        self.execute_with_job(config).await
    }

    fn isolation_level(&self) -> IsolationLevel {
        // Windows Job Objects only provide resource limits (memory, CPU, process count)
        // and automatic cleanup (kill-on-close). They do NOT provide filesystem or
        // network isolation. Therefore, we report Process-level isolation rather than
        // OsSandbox, which would incorrectly imply filesystem isolation is available.
        // For full OsSandbox on Windows, AppContainer would be required.
        IsolationLevel::Process
    }

    fn is_available(&self) -> bool {
        // Job Objects are available on all Windows versions
        true
    }

    fn description(&self) -> &'static str {
        "Windows Job Objects sandbox (memory/CPU/process limits, kill-on-close)"
    }

    fn is_partial(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_simple_command() {
        let sandbox = WindowsSandbox::new();
        let config = SandboxConfig::new(vec![
            "cmd".into(),
            "/c".into(),
            "echo".into(),
            "hello".into(),
        ])
        .with_workdir(std::env::current_dir().unwrap());

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.success());
        assert!(result.stdout_str().contains("hello"));
    }

    #[tokio::test]
    async fn test_with_memory_limit() {
        let sandbox = WindowsSandbox::new();
        let limits = crate::config::ResourceLimits {
            memory: Some(100 * 1024 * 1024), // 100 MB
            ..Default::default()
        };

        let config = SandboxConfig::new(vec![
            "cmd".into(),
            "/c".into(),
            "echo".into(),
            "limited".into(),
        ])
        .with_workdir(std::env::current_dir().unwrap())
        .with_limits(limits);

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.success());
    }

    #[tokio::test]
    async fn test_with_process_limit() {
        let sandbox = WindowsSandbox::new();
        let limits = crate::config::ResourceLimits {
            pids: Some(10),
            ..Default::default()
        };

        let config = SandboxConfig::new(vec![
            "cmd".into(),
            "/c".into(),
            "echo".into(),
            "process_limited".into(),
        ])
        .with_workdir(std::env::current_dir().unwrap())
        .with_limits(limits);

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.success());
    }

    #[tokio::test]
    async fn test_timeout() {
        let sandbox = WindowsSandbox::new();
        let limits = crate::config::ResourceLimits {
            timeout: Some(Duration::from_millis(100)),
            ..Default::default()
        };

        let config = SandboxConfig::new(vec![
            "cmd".into(),
            "/c".into(),
            "ping".into(),
            "-n".into(),
            "100".into(),
            "127.0.0.1".into(),
        ])
        .with_workdir(std::env::current_dir().unwrap())
        .with_limits(limits);

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.timed_out);
        assert_eq!(result.exit_code, 124);
    }

    #[test]
    fn test_sandbox_properties() {
        let sandbox = WindowsSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.isolation_level(), IsolationLevel::OsSandbox);
        assert!(!sandbox.description().is_empty());
    }

    #[tokio::test]
    async fn test_resource_usage_tracking() {
        let sandbox = WindowsSandbox::new();
        let config = SandboxConfig::new(vec!["cmd".into(), "/c".into(), "dir".into()])
            .with_workdir(std::env::current_dir().unwrap());

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.success());

        // Resource usage should be tracked
        if let Some(usage) = &result.resource_usage {
            // At least some metrics should be available
            assert!(usage.user_time_ms.is_some() || usage.io_read_bytes.is_some());
        }
    }

    #[tokio::test]
    async fn test_environment_isolation() {
        let sandbox = WindowsSandbox::new();

        // Test with cleared environment
        let config = SandboxConfig::new(vec![
            "cmd".into(),
            "/c".into(),
            "echo".into(),
            "%TEST_VAR%".into(),
        ])
        .with_workdir(std::env::current_dir().unwrap())
        .with_env("TEST_VAR", "isolated_value");

        let result = sandbox.execute(&config).await.unwrap();
        assert!(result.success());
        assert!(result.stdout_str().contains("isolated_value"));
    }
}
