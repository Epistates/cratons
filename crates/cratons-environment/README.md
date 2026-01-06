# cratons-environment

Hermetic environment management for the Cratons package manager.

## Overview

`cratons-environment` creates isolated, reproducible development environments that:
- Are compatible with existing tools (IDEs, linters, language servers)
- Work alongside system installations without conflicts
- Support multiple programming languages and ecosystems
- Generate activation scripts for various shells

## Features

- **venv-Compatible Python**: Standard `pyvenv.cfg` structure recognized by IDEs
- **Node.js Shims**: Isolated node/npm/npx binaries
- **Rust/Cargo Isolation**: Separate CARGO_HOME per project
- **Go Environment**: Project-specific GOPATH
- **Java/Maven**: Isolated Maven repository
- **Multi-Shell Support**: bash, fish, PowerShell activation scripts

## Usage

### With the Installer

```rust
use cratons_installer::Installer;

// Installation automatically sets up the environment
let result = installer.install(&lockfile, &project_dir).await?;

if result.environment_setup {
    println!("Activate with: source {}",
        result.activation_script.unwrap().display());
}
```

### Direct Usage

```rust
use cratons_environment::{Environment, EnvironmentManager};
use cratons_sandbox::create_sandbox;
use cratons_store::Store;
use std::sync::Arc;

// Create environment manager
let store = Arc::new(Store::open_default()?);
let sandbox = Arc::new(create_sandbox());
let manager = EnvironmentManager::new(store, sandbox);

// Set up environment from lockfile
let env = manager.setup(&lockfile, &project_dir)?;

// Get environment variables
let vars = env.env_vars();
println!("PATH additions: {:?}", vars.get("PATH"));

// Run a command in the sandboxed environment
let result = manager.run(&env, &project_dir,
    vec!["python".into(), "-c".into(), "print('hello')".into()]
).await?;
```

### Loading Existing Environment

```rust
use cratons_environment::EnvironmentManager;

// Load from existing .cratons/env directory
let env = EnvironmentManager::load(&project_dir)?;

// Use the environment variables
for (key, value) in env.env_vars() {
    std::env::set_var(key, value);
}
```

## Directory Structure

After `cratons install`, the project will have:

```
project/
├── .cratons/
│   ├── activate          # bash/zsh activation script
│   ├── activate.fish     # fish activation script
│   ├── activate.ps1      # PowerShell activation script
│   └── env/
│       ├── python/       # Python environment
│       │   ├── pyvenv.cfg
│       │   ├── bin/
│       │   │   ├── python -> /toolchain/python
│       │   │   ├── pip
│       │   │   └── python3
│       │   └── lib/
│       │       └── python3.12/
│       │           └── site-packages/
│       ├── node/         # Node.js environment
│       │   └── bin/
│       │       ├── node -> /toolchain/node
│       │       ├── npm
│       │       └── npx
│       ├── rust/         # Rust environment
│       │   └── cargo/
│       │       ├── bin/
│       │       └── registry/
│       ├── go/           # Go environment
│       │   └── gopath/
│       │       ├── bin/
│       │       ├── pkg/
│       │       └── src/
│       └── java/         # Java environment
│           └── repository/
└── cratons.toml
```

## Activation Scripts

### Bash/Zsh

```bash
source .cratons/activate

# Environment is now active
python --version  # Uses hermetic Python
npm --version     # Uses hermetic npm

# Deactivate when done
deactivate
```

### Fish

```fish
source .cratons/activate.fish

# Use hermetic tools
python --version

# Deactivate
deactivate
```

### PowerShell

```powershell
. .cratons\activate.ps1

# Use hermetic tools
python --version

# Deactivate
deactivate
```

## Environment Variables

When activated, the following variables are set:

| Variable | Description |
|----------|-------------|
| `CRATONS_ENV` | Set to `1` indicating active environment |
| `CRATONS_ENV_ROOT` | Path to `.cratons/env` directory |
| `PATH` | Prepended with hermetic bin directories |
| `VIRTUAL_ENV` | Python venv path (for IDE compatibility) |
| `PYTHONNOUSERSITE` | Prevents user site-packages |
| `NODE_PATH` | Node.js module path |
| `CARGO_HOME` | Rust cargo home |
| `GOPATH` | Go workspace path |
| `GO111MODULE` | Enables Go modules |

## Ecosystem-Specific Details

### Python (PythonEnv)

Creates a venv-compatible structure that:
- Is recognized by PyCharm, VS Code, and other IDEs
- Isolates site-packages from system Python
- Symlinks to toolchain Python interpreter

```rust
use cratons_environment::PythonEnv;

let python = PythonEnv::setup(&env_root, &store)?;
println!("Python bin: {}", python.bin_dir().display());
println!("Site-packages: {}", python.site_packages().display());
```

### Node.js (NodeEnv)

Creates bin shims for node, npm, and npx:

```rust
use cratons_environment::NodeEnv;

let node = NodeEnv::setup(&env_root, &project_dir, &store)?;
println!("Node version: {}", node.version());
println!("node_modules: {}", node.node_modules().display());
```

### Rust (RustEnv)

Isolates cargo home for per-project crate caching:

```rust
use cratons_environment::RustEnv;

let rust = RustEnv::setup(&env_root, &store)?;
// CARGO_HOME set to .cratons/env/rust/cargo
```

### Go (GoEnv)

Sets up project-specific GOPATH:

```rust
use cratons_environment::GoEnv;

let go = GoEnv::setup(&env_root, &store)?;
// GOPATH set to .cratons/env/go/gopath
// GO111MODULE=on
```

### Java (JavaEnv)

Isolates Maven repository:

```rust
use cratons_environment::JavaEnv;

let java = JavaEnv::setup(&env_root, &store)?;
// MAVEN_OPTS set to use local repository
```

## Integration with CLI

The `cratons` CLI provides commands for working with environments:

```bash
# Install packages and set up environment
cratons install

# Start a shell with the environment activated
cratons shell

# Run a script in the environment
cratons run build

# Run arbitrary commands
cratons run -- python -m pytest
```

## API Reference

### Environment

```rust
pub struct Environment {
    pub python: Option<PythonEnv>,
    pub node: Option<NodeEnv>,
    pub rust: Option<RustEnv>,
    pub go: Option<GoEnv>,
    pub java: Option<JavaEnv>,
}

impl Environment {
    /// Create a new empty environment
    pub fn new(root: PathBuf) -> Self;

    /// Get the root directory
    pub fn root(&self) -> &Path;

    /// Get all environment variables
    pub fn env_vars(&self) -> HashMap<String, String>;

    /// Get list of active ecosystems
    pub fn ecosystems(&self) -> Vec<Ecosystem>;
}
```

### EnvironmentManager

```rust
pub struct EnvironmentManager {
    store: Arc<Store>,
    sandbox: Arc<dyn Sandbox>,
}

impl EnvironmentManager {
    /// Create a new manager
    pub fn new(store: Arc<Store>, sandbox: Arc<dyn Sandbox>) -> Self;

    /// Set up environment from lockfile
    pub fn setup(&self, lockfile: &Lockfile, project_dir: &Path)
        -> Result<Environment>;

    /// Load existing environment
    pub fn load(project_dir: &Path) -> Result<Environment>;

    /// Run command in sandboxed environment
    pub async fn run(&self, env: &Environment, project_dir: &Path,
        command: Vec<String>) -> Result<SandboxResult>;
}
```

### Activation Script Generation

```rust
use cratons_environment::activation;

// Generate all activation scripts
activation::generate_scripts(&env, &project_dir)?;

// Creates:
// - .cratons/activate (bash/zsh)
// - .cratons/activate.fish
// - .cratons/activate.ps1
```

## Error Handling

```rust
use cratons_environment::EnvironmentError;

match manager.setup(&lockfile, &project_dir) {
    Ok(env) => println!("Environment ready"),
    Err(EnvironmentError::NotFound(path)) => {
        println!("Environment not found at {}", path.display());
    }
    Err(EnvironmentError::IoError(e)) => {
        println!("IO error: {}", e);
    }
    Err(EnvironmentError::SandboxError(msg)) => {
        println!("Sandbox error: {}", msg);
    }
    Err(e) => println!("Error: {}", e),
}
```

## Testing

```bash
# Run tests
cargo test -p cratons-environment

# Run with output
cargo test -p cratons-environment -- --nocapture
```

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
