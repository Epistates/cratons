//! Activation script generation.
//!
//! Generates shell-specific activation scripts for interactive use.
//! These scripts set up the environment so that tools like python, node, etc.
//! use the hermetic versions managed by Cratons.

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cratons_core::{posix_shell_escape, powershell_single_quote_escape};

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

    // SECURITY: All filesystem paths interpolated into the script must be
    // POSIX-shell-escaped. Project directories may contain spaces, `$`,
    // backticks, or quotes that would otherwise break the script or allow
    // command substitution.
    let mut path_components: Vec<String> = Vec::new();
    if let Some(ref python) = env.python {
        path_components.push(posix_shell_escape(&python.bin_dir().to_string_lossy()));
    }
    if let Some(ref node) = env.node {
        path_components.push(posix_shell_escape(&node.bin_dir().to_string_lossy()));
    }
    if let Some(ref rust) = env.rust {
        path_components.push(posix_shell_escape(&rust.bin_dir().to_string_lossy()));
    }
    if let Some(ref go) = env.go {
        path_components.push(posix_shell_escape(&go.bin_dir().to_string_lossy()));
    }

    // Build a colon-joined PATH expression where each segment is independently
    // quoted (so spaces inside individual paths don't bleed across segments).
    let path_expr = if path_components.is_empty() {
        "\"${PATH}\"".to_string()
    } else {
        format!("{}:\"${{PATH}}\"", path_components.join(":"))
    };
    let env_root = posix_shell_escape(&env.root().to_string_lossy());

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
PATH={path_expr}
export PATH

# Set environment marker
CRATONS_ENV="1"
CRATONS_ENV_ROOT={env_root}
export CRATONS_ENV CRATONS_ENV_ROOT
"#
    );

    // Add Python-specific variables
    if let Some(ref python) = env.python {
        script.push_str(&format!(
            "\n# Python environment\nVIRTUAL_ENV={}\nPYTHONNOUSERSITE=\"1\"\nexport VIRTUAL_ENV PYTHONNOUSERSITE\n",
            posix_shell_escape(&python.root().to_string_lossy())
        ));
    }

    // Add Node.js-specific variables
    if let Some(ref node) = env.node
        && node.node_modules().exists()
    {
        script.push_str(&format!(
            "\n# Node.js environment\nNODE_PATH={}\nexport NODE_PATH\n",
            posix_shell_escape(&node.node_modules().to_string_lossy())
        ));
    }

    // Add Rust-specific variables
    if let Some(ref rust) = env.rust {
        let cargo_home = rust.bin_dir().parent().unwrap_or(rust.root()).to_path_buf();
        script.push_str(&format!(
            "\n# Rust environment\nCARGO_HOME={}\nexport CARGO_HOME\n",
            posix_shell_escape(&cargo_home.to_string_lossy())
        ));
    }

    // Add Go-specific variables
    if let Some(ref go) = env.go {
        let gopath = go.bin_dir().parent().unwrap_or(go.root()).to_path_buf();
        script.push_str(&format!(
            "\n# Go environment\nGOPATH={}\nGO111MODULE=\"on\"\nexport GOPATH GO111MODULE\n",
            posix_shell_escape(&gopath.to_string_lossy())
        ));
    }

    write!(file, "{}", script)?;

    // Add prompt modification
    writeln!(
        file,
        r#"
# Modify prompt
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

    // SECURITY: Single-quoting in fish disables all expansion. Embedded
    // single quotes are escaped as `\'`.
    let fish_quote = |s: &str| -> String {
        let escaped = s.replace('\\', r"\\").replace('\'', r"\'");
        format!("'{escaped}'")
    };

    let mut path_components: Vec<String> = Vec::new();
    if let Some(ref python) = env.python {
        path_components.push(fish_quote(&python.bin_dir().to_string_lossy()));
    }
    if let Some(ref node) = env.node {
        path_components.push(fish_quote(&node.bin_dir().to_string_lossy()));
    }
    if let Some(ref rust) = env.rust {
        path_components.push(fish_quote(&rust.bin_dir().to_string_lossy()));
    }
    if let Some(ref go) = env.go {
        path_components.push(fish_quote(&go.bin_dir().to_string_lossy()));
    }

    let path_additions = path_components.join(" ");
    let env_root = fish_quote(&env.root().to_string_lossy());

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
set -gx CRATONS_ENV_ROOT {env_root}

function deactivate
    _cratons_deactivate
end

echo "Cratons environment activated (fish)"
echo "  Run 'deactivate' to exit"
"#,
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

    // SECURITY: Build the PATH expression by single-quoting each segment so
    // shell metacharacters in paths cannot leak into PowerShell parsing.
    let mut path_segments: Vec<String> = Vec::new();
    if let Some(ref python) = env.python {
        path_segments.push(powershell_single_quote_escape(
            &python.bin_dir().to_string_lossy(),
        ));
    }
    if let Some(ref node) = env.node {
        path_segments.push(powershell_single_quote_escape(
            &node.bin_dir().to_string_lossy(),
        ));
    }
    if let Some(ref rust) = env.rust {
        path_segments.push(powershell_single_quote_escape(
            &rust.bin_dir().to_string_lossy(),
        ));
    }
    if let Some(ref go) = env.go {
        path_segments.push(powershell_single_quote_escape(
            &go.bin_dir().to_string_lossy(),
        ));
    }

    let path_expr = if path_segments.is_empty() {
        "$env:PATH".to_string()
    } else {
        format!(
            "({} -join ';') + ';' + $env:PATH",
            format_args!("@({})", path_segments.join(", "))
        )
    };
    let env_root = powershell_single_quote_escape(&env.root().to_string_lossy());

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
$env:PATH = {path_expr}

# Set environment markers
$env:CRATONS_ENV = "1"
$env:CRATONS_ENV_ROOT = {env_root}

Write-Host "Cratons environment activated (PowerShell)"
Write-Host "  Run 'deactivate' to exit"
"#,
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
