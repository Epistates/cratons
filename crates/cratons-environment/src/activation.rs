//! Activation script generation.
//!
//! Generates shell-specific activation scripts for interactive use.
//! These scripts set up the environment so that tools like python, node, etc.
//! use the hermetic versions managed by Cratons.

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::{ENV_DIR, Environment, Result};

/// Generate activation scripts for all supported shells.
pub fn generate_scripts(env: &Environment, project_dir: &Path) -> Result<()> {
    let cratons_dir = project_dir.join(ENV_DIR);
    fs::create_dir_all(&cratons_dir)?;

    // Generate bash/zsh activation script
    generate_bash_script(env, &cratons_dir)?;

    // Generate fish activation script
    generate_fish_script(env, &cratons_dir)?;

    // Generate PowerShell activation script
    generate_powershell_script(env, &cratons_dir)?;

    Ok(())
}

/// Generate bash/zsh activation script.
fn generate_bash_script(env: &Environment, cratons_dir: &Path) -> Result<()> {
    let script_path = cratons_dir.join("activate");
    let mut file = File::create(&script_path)?;

    // Collect PATH components
    let mut path_components = Vec::new();
    if let Some(ref python) = env.python {
        path_components.push(python.bin_dir().to_string_lossy().to_string());
    }
    if let Some(ref node) = env.node {
        path_components.push(node.bin_dir().to_string_lossy().to_string());
    }
    if let Some(ref rust) = env.rust {
        path_components.push(rust.bin_dir().to_string_lossy().to_string());
    }
    if let Some(ref go) = env.go {
        path_components.push(go.bin_dir().to_string_lossy().to_string());
    }

    // Use platform-specific PATH separator: ";" on Windows, ":" on Unix
    let separator = if cfg!(windows) { ";" } else { ":" };
    let path_additions = path_components.join(separator);
    let env_root = env.root().to_string_lossy();

    let mut script = format!(
        r#"# Cratons environment activation script
# Source this file to activate the environment: source .cratons/activate

_cratons_deactivate() {{
    if [ -n "${{_CRATONS_OLD_PATH:-}}" ]; then
        PATH="${{_CRATONS_OLD_PATH}}"
        export PATH
        unset _CRATONS_OLD_PATH
    fi

    if [ -n "${{_CRATONS_OLD_PS1:-}}" ]; then
        PS1="${{_CRATONS_OLD_PS1}}"
        export PS1
        unset _CRATONS_OLD_PS1
    fi

    unset CRATONS_ENV
    unset CRATONS_ENV_ROOT
    unset VIRTUAL_ENV
    unset PYTHONNOUSERSITE
    unset NODE_PATH
    unset CARGO_HOME
    unset GOPATH

    if [ ! "${{1:-}}" = "nondestructive" ]; then
        unset -f _cratons_deactivate
    fi
}}

# Deactivate any existing environment
_cratons_deactivate nondestructive

# Save old PATH
_CRATONS_OLD_PATH="${{PATH}}"

# Set new PATH
PATH="{path_additions}:${{PATH}}"
export PATH

# Set environment marker
CRATONS_ENV="1"
CRATONS_ENV_ROOT="{env_root}"
export CRATONS_ENV CRATONS_ENV_ROOT
"#,
        path_additions = path_additions,
        env_root = env_root,
    );

    // Add Python-specific variables
    if let Some(ref python) = env.python {
        script.push_str(&format!(
            r#"\n# Python environment
VIRTUAL_ENV="{}"
PYTHONNOUSERSITE="1"
export VIRTUAL_ENV PYTHONNOUSERSITE
"#,
            python.root().display()
        ));
    }

    // Add Node.js-specific variables
    if let Some(ref node) = env.node {
        if node.node_modules().exists() {
            script.push_str(&format!(
                r#"\n# Node.js environment
NODE_PATH="{}"
export NODE_PATH
"#,
                node.node_modules().display()
            ));
        }
    }

    // Add Rust-specific variables
    if let Some(ref rust) = env.rust {
        script.push_str(&format!(
            r#"\n# Rust environment
CARGO_HOME="{}"
export CARGO_HOME
"#,
            // L-15: Use unwrap_or to avoid panic on missing parent
            rust.bin_dir().parent().unwrap_or(rust.root()).display()
        ));
    }

    // Add Go-specific variables
    if let Some(ref go) = env.go {
        script.push_str(&format!(
            r#"\n# Go environment
GOPATH="{}"
GO111MODULE="on"
export GOPATH GO111MODULE
"#,
            // L-15: Use unwrap_or to avoid panic on missing parent
            go.bin_dir().parent().unwrap_or(go.root()).display()
        ));
    }

    write!(file, "{}", script)?;

    // Add prompt modification
    writeln!(
        file,
        r#"\n# Modify prompt
if [ -z "${{CRATONS_ENV_DISABLE_PROMPT:-}}" ]; then
    _CRATONS_OLD_PS1="${{PS1:-}}"
    PS1="(mei) ${{PS1:-}}"
    export PS1
fi

# Provide deactivate command
alias deactivate='_cratons_deactivate'

echo "Cratons environment activated"
echo "  Run 'deactivate' to exit"
"#
    )?;

    // Make executable
    let mut perms = fs::metadata(&script_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms)?;

    Ok(())
}

/// Generate fish shell activation script.
fn generate_fish_script(env: &Environment, cratons_dir: &Path) -> Result<()> {
    let script_path = cratons_dir.join("activate.fish");
    let mut file = File::create(&script_path)?;

    let mut path_components = Vec::new();
    if let Some(ref python) = env.python {
        path_components.push(python.bin_dir().to_string_lossy().to_string());
    }
    if let Some(ref node) = env.node {
        path_components.push(node.bin_dir().to_string_lossy().to_string());
    }
    if let Some(ref rust) = env.rust {
        path_components.push(rust.bin_dir().to_string_lossy().to_string());
    }
    if let Some(ref go) = env.go {
        path_components.push(go.bin_dir().to_string_lossy().to_string());
    }

    // L-06: Quote paths for fish to handle spaces correctly
    let path_additions: Vec<String> = path_components
        .iter()
        .map(|p| format!("\"{}\"", p))
        .collect();

    writeln!(
        file,
        r#"# Cratons environment activation script for fish
# Source this file: source .cratons/activate.fish

function _cratons_deactivate
    if set -q _CRATONS_OLD_PATH
        set -gx PATH $_CRATONS_OLD_PATH
        set -e _CRATONS_OLD_PATH
    end

    set -e CRATONS_ENV
    set -e CRATONS_ENV_ROOT
    set -e VIRTUAL_ENV
    set -e PYTHONNOUSERSITE
    set -e NODE_PATH
    set -e CARGO_HOME
    set -e GOPATH

    functions -e _cratons_deactivate
    functions -e deactivate
end

# Deactivate any existing environment
if functions -q _cratons_deactivate
    _cratons_deactivate
end

# Save old PATH
set -g _CRATONS_OLD_PATH $PATH

# Add to PATH
set -gx PATH {path_additions} $PATH

# Set environment markers
set -gx CRATONS_ENV "1"
set -gx CRATONS_ENV_ROOT "{env_root}"

function deactivate
    _cratons_deactivate
end

echo "Cratons environment activated (fish)"
echo "  Run 'deactivate' to exit"
"#,
        path_additions = path_additions.join(" "),
        env_root = env.root().display(),
    )?;

    let mut perms = fs::metadata(&script_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms)?;

    Ok(())
}

/// Generate PowerShell activation script.
fn generate_powershell_script(env: &Environment, cratons_dir: &Path) -> Result<()> {
    let script_path = cratons_dir.join("activate.ps1");
    let mut file = File::create(&script_path)?;

    let mut path_components = Vec::new();
    if let Some(ref python) = env.python {
        path_components.push(python.bin_dir().to_string_lossy().to_string());
    }
    if let Some(ref node) = env.node {
        path_components.push(node.bin_dir().to_string_lossy().to_string());
    }
    if let Some(ref rust) = env.rust {
        path_components.push(rust.bin_dir().to_string_lossy().to_string());
    }
    if let Some(ref go) = env.go {
        path_components.push(go.bin_dir().to_string_lossy().to_string());
    }

    let path_additions = path_components.join(";");

    writeln!(
        file,
        r#"# Cratons environment activation script for PowerShell
# Run: . .cratons\activate.ps1

function global:deactivate {{
    if (Test-Path env:_CRATONS_OLD_PATH) {{
        $env:PATH = $env:_CRATONS_OLD_PATH
        Remove-Item env:_CRATONS_OLD_PATH
    }}

    Remove-Item env:CRATONS_ENV -ErrorAction SilentlyContinue
    Remove-Item env:CRATONS_ENV_ROOT -ErrorAction SilentlyContinue
    Remove-Item env:VIRTUAL_ENV -ErrorAction SilentlyContinue
    Remove-Item env:PYTHONNOUSERSITE -ErrorAction SilentlyContinue
    Remove-Item env:NODE_PATH -ErrorAction SilentlyContinue
    Remove-Item env:CARGO_HOME -ErrorAction SilentlyContinue
    Remove-Item env:GOPATH -ErrorAction SilentlyContinue

    Remove-Item function:deactivate
}}

# Save old PATH
$env:_CRATONS_OLD_PATH = $env:PATH

# Set new PATH
$env:PATH = "{path_additions};$env:PATH"

# Set environment markers
$env:CRATONS_ENV = "1"
$env:CRATONS_ENV_ROOT = "{env_root}"

Write-Host "Cratons environment activated (PowerShell)"
Write-Host "  Run 'deactivate' to exit"
"#,
        path_additions = path_additions,
        env_root = env.root().display(),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::python::PythonEnv;
    use tempfile::tempdir;

    /// M-22 FIX: Test activation scripts with empty environment.
    #[test]
    fn test_generate_scripts_empty_env() {
        let project_dir = tempdir().unwrap();
        let env_root = project_dir.path().join(".cratons").join("env");
        fs::create_dir_all(&env_root).unwrap();

        // Empty environment (no Python/Node/etc)
        let env = Environment::new(env_root.clone());

        let result = generate_scripts(&env, project_dir.path());
        assert!(result.is_ok());

        // Verify scripts were created
        let activate_path = project_dir.path().join(".cratons/activate");
        assert!(activate_path.exists(), "activate script should exist");

        let activate_content = fs::read_to_string(&activate_path).unwrap();
        assert!(
            activate_content.contains("CRATONS_ENV"),
            "should set CRATONS_ENV"
        );
    }

    /// M-22 FIX: Test activation scripts with Python environment.
    #[test]
    fn test_generate_scripts_with_python() {
        let project_dir = tempdir().unwrap();
        let env_root = project_dir.path().join(".cratons").join("env");
        fs::create_dir_all(&env_root).unwrap();

        // Create Python environment structure
        let python_root = env_root.join("python");
        let python_bin = python_root.join("bin");
        fs::create_dir_all(&python_bin).unwrap();

        // Create mock Python environment using test constructor
        let python_env = PythonEnv::new_for_test(python_root.clone(), "3.12.0".to_string());

        // Create environment with Python
        let mut env = Environment::new(env_root.clone());
        env.python = Some(python_env);

        let result = generate_scripts(&env, project_dir.path());
        assert!(result.is_ok());

        // Verify activate script contains Python path
        let activate_content =
            fs::read_to_string(project_dir.path().join(".cratons/activate")).unwrap();
        assert!(
            activate_content.contains("python/bin"),
            "should add Python bin to PATH"
        );
        assert!(
            activate_content.contains("VIRTUAL_ENV"),
            "should set VIRTUAL_ENV"
        );
    }

    /// M-22 FIX: Test that all shell scripts are generated.
    #[test]
    fn test_generate_all_shell_scripts() {
        let project_dir = tempdir().unwrap();
        let env_root = project_dir.path().join(".cratons").join("env");
        fs::create_dir_all(&env_root).unwrap();

        let env = Environment::new(env_root.clone());

        let result = generate_scripts(&env, project_dir.path());
        assert!(result.is_ok());

        // Check all script types
        let cratons_dir = project_dir.path().join(".cratons");
        assert!(
            cratons_dir.join("activate").exists(),
            "bash activate script"
        );
        assert!(
            cratons_dir.join("activate.fish").exists(),
            "fish activate script"
        );
        assert!(
            cratons_dir.join("activate.ps1").exists(),
            "powershell activate script"
        );
    }

    /// M-22 FIX: Test snapshot of activation scripts for regression detection.
    #[test]
    fn test_generate_scripts_snapshot() {
        let project_dir = tempdir().unwrap();
        let env_root = project_dir.path().join(".cratons").join("env");
        fs::create_dir_all(&env_root).unwrap();

        // Create Python environment structure
        let python_root = env_root.join("python");
        let python_bin = python_root.join("bin");
        fs::create_dir_all(&python_bin).unwrap();

        let python_env = PythonEnv::new_for_test(python_root.clone(), "3.12.0".to_string());

        let mut env = Environment::new(env_root.clone());
        env.python = Some(python_env);

        let result = generate_scripts(&env, project_dir.path());
        assert!(result.is_ok());

        let activate_content =
            fs::read_to_string(project_dir.path().join(".cratons/activate")).unwrap();

        // Normalize paths for snapshot consistency
        let activate_content =
            activate_content.replace(project_dir.path().to_str().unwrap(), "/tmp/project");

        insta::assert_snapshot!("activate_script", activate_content);
    }
}
