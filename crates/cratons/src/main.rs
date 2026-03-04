//! # cratons
//!
//! A language-agnostic package manager with hermetic builds.
//!
//! Inspired by the Cratons effect in superconductivity - the expulsion of
//! magnetic fields to create a perfect state of zero resistance.

use clap::{Parser, Subcommand};
use miette::Result;
use owo_colors::OwoColorize;
use tracing::{debug, info_span};

mod commands;
pub mod config;
pub mod exit_code;
mod observability;

use exit_code::ExitCode;

/// Cratons - A language-agnostic package manager with hermetic builds
#[derive(Parser)]
#[command(name = "cts")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Disable color output
    #[arg(long, global = true)]
    no_color: bool,

    /// Offline mode - do not access network
    #[arg(long, global = true)]
    offline: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new project
    Init {
        /// Project name
        #[arg(default_value = ".")]
        path: String,
    },

    /// Add dependencies
    Add {
        /// Dependencies to add (format: ecosystem:name@version)
        #[arg(required = true)]
        deps: Vec<String>,

        /// Add as development dependency
        #[arg(short = 'D', long)]
        dev: bool,

        /// Add as build dependency
        #[arg(short = 'B', long)]
        build: bool,
    },

    /// Remove dependencies
    Remove {
        /// Dependencies to remove
        #[arg(required = true)]
        deps: Vec<String>,
    },

    /// Install dependencies
    Install {
        /// Force reinstall
        #[arg(short, long)]
        force: bool,

        /// Use frozen lockfile (fail if outdated)
        #[arg(long)]
        frozen: bool,
    },

    /// Update dependencies
    Update {
        /// Specific packages to update
        packages: Vec<String>,
    },

    /// Build the project
    Build {
        /// Build in release mode
        #[arg(long)]
        release: bool,

        /// Skip cache lookup
        #[arg(long)]
        no_cache: bool,

        #[command(flatten)]
        workspace: commands::workspace::WorkspaceOpts,
    },

    /// Run a script
    Run {
        /// Script name
        script: String,

        /// Arguments to pass to the script
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        #[command(flatten)]
        workspace: commands::workspace::WorkspaceOpts,
    },

    /// Execute a tool transiently (npx-style)
    Exec {
        /// Package to run (e.g. npm:cowsay@latest)
        package: String,

        /// Arguments to pass to the tool
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Start an interactive shell with the hermetic environment
    Shell,

    /// Workspace management
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommands,
    },

    /// Show dependency tree
    Tree {
        /// Show all dependencies (including transitive)
        #[arg(short, long)]
        all: bool,

        /// Maximum depth to display
        #[arg(short, long)]
        depth: Option<usize>,
    },

    /// Explain why a package is installed
    Why {
        /// Package name
        package: String,
    },

    /// Show outdated dependencies
    Outdated,

    /// Security audit
    Audit {
        /// Fail on vulnerabilities of this severity or higher
        #[arg(long, default_value = "high")]
        fail_on: String,
    },

    /// Garbage collect unused artifacts
    Gc {
        /// Keep artifacts from the last N days
        #[arg(long, default_value = "30")]
        keep_days: u32,
    },

    /// Show store information
    Store {
        #[command(subcommand)]
        command: StoreCommands,
    },

    /// Remote build cache operations
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum WorkspaceCommands {
    /// List workspace members
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show workspace dependency graph
    Graph {
        /// Output as DOT format
        #[arg(long)]
        dot: bool,
    },
}

#[derive(Subcommand)]
enum StoreCommands {
    /// Show store location and size
    Info,
    /// List cached artifacts
    List,
    /// Remove specific artifact
    Remove {
        /// Artifact hash
        hash: String,
    },
}

#[derive(Subcommand)]
enum CacheCommands {
    /// Show remote cache configuration
    Info,

    /// Push local artifacts to remote cache
    Push {
        /// Push all artifacts (not just recent)
        #[arg(long)]
        all: bool,

        /// Specific artifact hash to push
        hash: Option<String>,
    },

    /// Fetch artifact from remote cache
    Fetch {
        /// Artifact hash to fetch
        hash: String,
    },

    /// Configure remote cache
    Config {
        /// Backend type: s3, filesystem, http
        #[arg(long)]
        backend: Option<String>,

        /// Backend URL or path
        #[arg(long)]
        url: Option<String>,

        /// Show current configuration
        #[arg(long)]
        show: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    // Initialize observability
    let obs_config = observability::ObservabilityConfig::from_flags(cli.verbose, cli.quiet);
    if let Err(e) = observability::init(obs_config) {
        eprintln!("warning: failed to initialize logging: {}", e);
    }

    debug!(
        "mei {} started with args: {:?}",
        env!("CARGO_PKG_VERSION"),
        std::env::args().collect::<Vec<_>>()
    );

    // Print banner for interactive commands
    if !cli.quiet && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        println!(
            "{} {} - Language-agnostic package manager",
            "cts".bold().cyan(),
            env!("CARGO_PKG_VERSION").dimmed()
        );
        println!();
    }

    // Run command and handle errors (M-29: per-command tracing spans)
    let result: Result<()> = match cli.command {
        Commands::Init { path } => {
            let _span = info_span!("cmd_init", path = %path).entered();
            commands::init(&path)
        }
        Commands::Add { deps, dev, build } => {
            let _span = info_span!("cmd_add", deps_count = deps.len(), dev, build).entered();
            commands::add(&deps, dev, build)
        }
        Commands::Remove { deps } => {
            let _span = info_span!("cmd_remove", deps_count = deps.len()).entered();
            commands::remove(&deps)
        }
        Commands::Install { force, frozen } => {
            let _span = info_span!("cmd_install", force, frozen, offline = cli.offline).entered();
            commands::install(force, frozen, cli.offline)
        }
        Commands::Update { packages } => {
            let _span = info_span!(
                "cmd_update",
                packages_count = packages.len(),
                offline = cli.offline
            )
            .entered();
            commands::update(&packages, cli.offline)
        }
        Commands::Build {
            release,
            no_cache,
            workspace,
        } => {
            let _span = info_span!("cmd_build", release, no_cache).entered();
            commands::build(release, no_cache, workspace)
        }
        Commands::Run {
            script,
            args,
            workspace,
        } => {
            let _span = info_span!("cmd_run", script = %script, args_count = args.len()).entered();
            commands::run(&script, &args, workspace)
        }
        Commands::Exec { package, args } => {
            let _span = info_span!("cmd_exec", package = %package, offline = cli.offline).entered();
            commands::exec(&package, &args, cli.offline)
        }
        Commands::Shell => {
            let _span = info_span!("cmd_shell").entered();
            commands::shell()
        }
        Commands::Workspace { command } => match command {
            WorkspaceCommands::List { json } => {
                let _span = info_span!("cmd_workspace_list", json).entered();
                commands::workspace::list(json)
            }
            WorkspaceCommands::Graph { dot } => {
                let _span = info_span!("cmd_workspace_graph", dot).entered();
                commands::workspace::graph(dot)
            }
        },
        Commands::Tree { all, depth } => {
            let _span = info_span!("cmd_tree", all, depth = ?depth).entered();
            commands::tree(all, depth)
        }
        Commands::Why { package } => {
            let _span = info_span!("cmd_why", package = %package).entered();
            commands::why(&package)
        }
        Commands::Outdated => {
            let _span = info_span!("cmd_outdated", offline = cli.offline).entered();
            commands::outdated(cli.offline)
        }
        Commands::Audit { fail_on } => {
            let _span = info_span!("cmd_audit", fail_on = %fail_on).entered();
            commands::audit(&fail_on)
        }
        Commands::Gc { keep_days } => {
            let _span = info_span!("cmd_gc", keep_days).entered();
            commands::gc(keep_days)
        }
        Commands::Store { command } => match command {
            StoreCommands::Info => {
                let _span = info_span!("cmd_store_info").entered();
                commands::store_info()
            }
            StoreCommands::List => {
                let _span = info_span!("cmd_store_list").entered();
                commands::store_list()
            }
            StoreCommands::Remove { hash } => {
                let _span = info_span!("cmd_store_remove", hash = %hash).entered();
                commands::store_remove(&hash)
            }
        },
        Commands::Cache { command } => match command {
            CacheCommands::Info => {
                let _span = info_span!("cmd_cache_info").entered();
                commands::cache_info()
            }
            CacheCommands::Push { all, hash } => {
                let _span = info_span!("cmd_cache_push", all, hash = ?hash).entered();
                commands::cache_push(all, hash.as_deref())
            }
            CacheCommands::Fetch { hash } => {
                let _span = info_span!("cmd_cache_fetch", hash = %hash).entered();
                commands::cache_fetch(&hash)
            }
            CacheCommands::Config { backend, url, show } => {
                let _span =
                    info_span!("cmd_cache_config", backend = ?backend, url = ?url, show).entered();
                commands::cache_config(backend.as_deref(), url.as_deref(), show)
            }
        },
        Commands::Completions { shell } => {
            let _span = info_span!("cmd_completions", shell = ?shell).entered();
            commands::completions(shell);
            Ok(())
        }
    };

    // Determine exit code and handle errors
    let exit_code = ExitCode::from_result(&result);

    if let Err(ref e) = result {
        tracing::error!("command failed: {:?}", e);
        // Print error to stderr using miette's nice formatting
        eprintln!("{:?}", e);
    }

    std::process::exit(exit_code.into());
}
