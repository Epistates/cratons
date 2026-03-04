# cratons-sandbox

Cross-platform sandboxed execution for hermetic builds.

## Overview

`cratons-sandbox` provides a unified interface for running processes in isolated environments across different platforms. It supports multiple isolation levels with graceful degradation based on platform capabilities.

## Features

- **Cross-Platform Support**: Linux, macOS, Windows with appropriate isolation
- **Graceful Degradation**: Automatically falls back to available isolation levels
- **Configurable Mounts**: Read-only and read-write bind mounts
- **Network Control**: Block, allow-list, or full network access
- **Resource Limits**: CPU, memory, and timeout constraints
- **Async Execution**: Built on tokio for async/await support

## Isolation Levels

| Level | Description | Platforms |
|-------|-------------|-----------|
| `Container` | Full OCI container isolation | Linux |
| `OsSandbox` | OS-level sandbox | macOS (sandbox-exec), Windows (Job Objects) |
| `Process` | Minimal process isolation | All platforms |
| `None` | No isolation | All platforms |

## Usage

```rust
use cratons_sandbox::{create_sandbox, SandboxConfig, NetworkAccess};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the best available sandbox for this platform
    let sandbox = create_sandbox();

    println!("Using: {} ({})",
        sandbox.description(),
        sandbox.isolation_level()
    );

    // Configure the sandbox
    let config = SandboxConfig::new(vec!["python".into(), "build.py".into()])
        .with_workdir(PathBuf::from("/project"))
        .with_ro_mount(cratons_sandbox::config::Mount::readonly(
            PathBuf::from("/opt/toolchain"),
            PathBuf::from("/toolchain"),
        ))
        .with_rw_mount(cratons_sandbox::config::Mount::bind(
            PathBuf::from("/project/output"),
            false,
        ))
        .with_network(NetworkAccess::None)
        .with_timeout(std::time::Duration::from_secs(300))
        .with_memory_limit(1024 * 1024 * 1024); // 1GB

    // Execute
    let result = sandbox.execute(&config).await?;

    if result.success() {
        println!("Build completed in {:?}", result.duration);
        println!("Output: {}", result.stdout_str());
    } else {
        eprintln!("Build failed: {}", result.stderr_str());
    }

    Ok(())
}
```

## Platform-Specific Details

### Linux

Uses namespace isolation inspired by OCI runtimes:
- User namespace for unprivileged operation
- Mount namespace for filesystem isolation
- Network namespace for network isolation
- PID namespace for process isolation
- Cgroup limits for resource control

```rust
use cratons_sandbox::linux::LinuxSandbox;

let sandbox = LinuxSandbox::new()?;
if sandbox.is_available() {
    // Full container isolation available
}
```

### macOS

Uses `sandbox-exec` with custom SBPL (Sandbox Profile Language) profiles:
- Filesystem access control via path rules
- Process and signal restrictions
- Network access control (all-or-nothing)

```rust
use cratons_sandbox::macos::MacOsSandbox;

let sandbox = MacOsSandbox::new();
if MacOsSandbox::is_sandbox_available() {
    // sandbox-exec is available
}
```

### Windows

Uses Job Objects for process isolation:
- Process group management
- Resource limits
- UI restrictions

### Fallback

When no platform-specific sandbox is available, `ProcessSandbox` provides:
- Environment variable isolation
- Working directory control
- Timeout enforcement

## Configuration

### SandboxConfig Builder

```rust
let config = SandboxConfig::new(vec!["cmd".into(), "arg1".into()])
    // Working directory
    .with_workdir(PathBuf::from("/work"))

    // Environment variables
    .with_env("KEY", "value")
    .with_envs(hashmap)
    .inherit_env()  // Inherit parent environment

    // Mounts
    .with_ro_mount(mount)  // Read-only
    .with_rw_mount(mount)  // Read-write

    // Network
    .with_network(NetworkAccess::None)
    .with_network(NetworkAccess::Full)
    .with_network(NetworkAccess::AllowList(vec!["api.example.com".into()]))

    // Resource limits
    .with_timeout(Duration::from_secs(60))
    .with_memory_limit(1024 * 1024 * 512)  // 512MB
    .with_cpu_limit(2.0);  // 2 CPU cores
```

### Mount Types

```rust
use cratons_sandbox::config::Mount;

// Read-only bind mount (same path)
let ro = Mount::readonly(source, target);

// Read-write bind mount
let rw = Mount::bind(path, read_only);

// Tmpfs mount
let tmp = Mount::tmpfs(target, size_bytes);
```

## Error Handling

```rust
use cratons_sandbox::SandboxError;

match sandbox.execute(&config).await {
    Ok(result) => {
        if result.timed_out {
            println!("Process timed out after {:?}", result.duration);
        }
        if result.resource_exceeded {
            println!("Resource limits exceeded");
        }
    }
    Err(SandboxError::Unavailable(msg)) => {
        println!("Sandbox not available: {}", msg);
    }
    Err(SandboxError::ExecutionFailed { reason, exit_code }) => {
        println!("Execution failed: {} (exit: {:?})", reason, exit_code);
    }
    Err(e) => {
        println!("Error: {}", e);
    }
}
```

## Security Considerations

- **Linux**: Requires either root or unprivileged user namespaces
- **macOS**: SIP may restrict sandbox-exec functionality
- **Windows**: Administrator may be required for some Job Object features
- Always validate inputs before executing in sandbox
- Use read-only mounts for toolchains and dependencies
- Disable network access for reproducible builds

## Security Hardening (January 2026)

The sandbox has been hardened following a comprehensive security audit:

### Linux (seccomp.rs, linux.rs)
- **Syscall Filtering**: Blocks dangerous syscalls: `unshare`, `mount`, `umount`, `pivot_root`, `ptrace`, `setns`
- **Full OCI Support**: Container sandbox via `container.rs` with crun/runc runtime
- **Environment Blocklist**: 100+ dangerous variables blocked including:
  - Glibc exploitation: `GCONV_PATH`, `MALLOC_CHECK_`, `MALLOC_TRACE`, `GLIBC_TUNABLES`
  - DNS/Network hijacking: `HOSTALIASES`, `LOCALDOMAIN`, `RES_OPTIONS`, `RESOLV_HOST_CONF`
  - Locale/i18n hijacking: `NLSPATH`, `LOCPATH`, `LANGUAGE`, `LC_ALL`
  - Terminal hijacking: `TERMINFO`, `TERMINFO_DIRS`, `TERMCAP`
  - Shell exploits: `BASH_ENV`, `ENV`, `ZDOTDIR`, `SHELLOPTS`
  - Credential leakage: `AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN`, `DOCKER_*`

### macOS (macos.rs)
- **Process Execution Restriction**: Strict whitelist of system binaries only:
  - Core: `/bin/sh`, `/bin/bash`, `/usr/bin/env`, `/usr/bin/python3`
  - Build tools: Xcode.app, CommandLineTools paths
  - **Removed**: `/usr/local/bin`, `/opt/homebrew/bin` (too permissive)
- **Network-Aware Binaries**: `curl`, `nc`, `nslookup`, `dig`, `host` only available when `NetworkAccess::Full`
- **Environment Sanitization**: Same 100+ variable blocklist as Linux
- **Reproducible Locale**: Forces `LANG=C.UTF-8` for consistent builds

### Windows (windows.rs)
- **Accurate Isolation Level**: Reports `IsolationLevel::Process` (not `OsSandbox`)
- Job Objects provide resource limits but not filesystem/network isolation
- Same environment variable sanitization as other platforms

### All Platforms
- Environment variable validation (alphanumeric + underscore only)
- TOCTOU-safe mount path validation with symlink canonicalization
- Blocklist of 100+ sensitive variables (credentials, injection vectors, locale hijacking)

## Testing

```bash
# Run all tests
cargo test -p cratons-sandbox

# Run with output (for debugging)
cargo test -p cratons-sandbox -- --nocapture
```

Note: Some tests may be skipped on platforms where sandbox features are unavailable or restricted (e.g., macOS with SIP).

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
