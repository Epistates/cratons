use clap::Args;
use cratons_workspace::{Workspace, WorkspaceFilter};
use miette::{IntoDiagnostic, Result};
use owo_colors::OwoColorize;
use std::path::Path;

#[derive(Args, Debug, Clone)]
pub struct WorkspaceOpts {
    /// Select packages matching the given glob pattern or name
    #[arg(long, short = 'F')]
    pub filter: Vec<String>,

    /// Select all packages in the workspace
    #[arg(long)]
    pub all: bool,

    /// Include dependencies of selected packages
    #[arg(long)]
    pub include_deps: bool,

    /// Include dependents of selected packages
    #[arg(long)]
    pub include_dependents: bool,
}

impl WorkspaceOpts {
    pub fn to_filter(&self) -> Result<WorkspaceFilter> {
        let mut filter = WorkspaceFilter::new();

        if self.all {
            // Empty filter matches all, unless specific excludes are added (not supported in opts yet)
            // But if 'all' is explicitly set, we might want to ensure we don't accidentally limit if filter is also set?
            // Usually --all overrides specific filters or acts as a base.
            // For now, if all is set, we return empty filter (match all).
            return Ok(filter);
        }

        if !self.filter.is_empty() {
            // We treat filters as a mix of names and patterns
            for f in &self.filter {
                if f.contains('*') || f.contains('?') || f.contains('[') {
                    filter = filter.with_pattern(f).into_diagnostic()?;
                } else {
                    filter = filter.with_names([f]);
                }
            }
        }

        if self.include_deps {
            filter = filter.with_dependencies();
        }

        if self.include_dependents {
            filter = filter.with_dependents();
        }

        Ok(filter)
    }
}

/// List workspace members.
pub fn list(json: bool) -> Result<()> {
    let workspace = Workspace::load(Path::new("."))
        .map_err(|e| miette::miette!("Failed to load workspace: {}", e))?;

    if json {
        let members: Vec<_> = workspace
            .members
            .iter()
            .map(|m| {
                serde_json::json!({
                    "name": m.manifest.package.name,
                    "version": m.manifest.package.version,
                    "path": m.path,
                    "private": m.manifest.package.private,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&members).into_diagnostic()?
        );
    } else {
        println!(
            "{} Found {} workspace members:",
            "→".blue(),
            workspace.members.len().cyan()
        );
        println!();

        // Sort by path for display
        let mut members = workspace.members.clone();
        members.sort_by(|a, b| a.path.cmp(&b.path));

        for member in members {
            let relative_path =
                pathdiff::diff_paths(&member.path, &workspace.root_path).unwrap_or(member.path);

            println!(
                "  {} {} {}",
                member.manifest.package.name.bold(),
                member.manifest.package.version.dimmed(),
                format!("({})", relative_path.display()).dimmed()
            );
        }
    }

    Ok(())
}

/// Show workspace dependency graph.
pub fn graph(dot: bool) -> Result<()> {
    let workspace = Workspace::load(Path::new("."))
        .map_err(|e| miette::miette!("Failed to load workspace: {}", e))?;

    if dot {
        println!("digraph workspace {{");
        println!("  node [shape=box, style=filled, fillcolor=\"#eeeeee\"];");

        for member in &workspace.members {
            let name = &member.manifest.package.name;
            // Clean name for ID
            let id = name.replace(['@', '/', '-'], "_");
            println!("  {} [label=\"{} \"];", id, name);

            let deps = workspace.workspace_dependencies_of(name);
            for dep in deps {
                let dep_name = &dep.manifest.package.name;
                let dep_id = dep_name.replace(['@', '/', '-'], "_");
                println!("  {} -> {};", id, dep_id);
            }
        }
        println!("}} ");
    } else {
        println!("{} Workspace Graph", "→".blue());

        let members = workspace
            .all_topological()
            .map_err(|e| miette::miette!("{}", e))?;

        for member in members {
            let name = &member.manifest.package.name;
            let deps = workspace.workspace_dependencies_of(name);

            println!("  {}", name.cyan());
            for (i, dep) in deps.iter().enumerate() {
                let is_last = i == deps.len() - 1;
                let prefix = if is_last { "└──" } else { "├──" };
                println!("    {} {}", prefix.dimmed(), dep.manifest.package.name);
            }
        }
    }

    Ok(())
}
