use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process;
use taintguard::policy::{DEFAULT_POLICY_TOML, PolicyConfig};
use taintguard::proxy::run_mcp_proxy;
use taintguard::sim::{check_trace_file, run_demo};

#[derive(Parser)]
#[command(
    name = "taintguard",
    version,
    about = "Deterministic Information-Flow Control (IFC) & taint-tracking security firewall for MCP AI agents."
)]
struct Cli {
    /// Path to a custom taintguard.toml policy file (uses built-in default if omitted)
    #[arg(short, long, global = true)]
    policy: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a transparent stdio MCP proxy enforcing IFC taint rules before every tools/call
    Proxy {
        /// Optional path to write the SHA-256 hash-chained JSONL audit log
        #[arg(long)]
        audit_log: Option<PathBuf>,

        /// Upstream MCP server command and arguments (e.g. -- npx -y @modelcontextprotocol/server-filesystem .)
        #[arg(last = true, required = true)]
        upstream: Vec<String>,
    },

    /// Run built-in exploit & benign workflow scenarios (Indirect Prompt Injection, .env Exfiltration, Benign)
    Demo,

    /// Evaluate a recorded JSONL agent trace against the IFC policy (exits non-zero on violations)
    Check {
        /// Path to a JSONL file of `{ "tool": "...", "args": {...}, "output": "..." }` steps
        trace: PathBuf,
    },

    /// Write a starter `taintguard.toml` policy file to the current directory
    Init {
        #[arg(short, long, default_value = "taintguard.toml")]
        out: PathBuf,
    },
}

fn load_policy(path: Option<PathBuf>) -> PolicyConfig {
    match path {
        Some(p) => PolicyConfig::from_file(&p).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            process::exit(1);
        }),
        None => PolicyConfig::default_policy(),
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { out } => {
            if let Err(e) = fs::write(&out, DEFAULT_POLICY_TOML) {
                eprintln!("error writing {}: {}", out.display(), e);
                process::exit(1);
            }
            println!("Wrote default IFC policy to {}", out.display());
        }
        Commands::Demo => {
            let policy = load_policy(cli.policy);
            run_demo(policy);
        }
        Commands::Check { trace } => {
            let policy = load_policy(cli.policy);
            match check_trace_file(policy, &trace) {
                Ok(0) => {
                    println!("\nPASS: 0 IFC policy violations detected.");
                }
                Ok(n) => {
                    eprintln!("\nFAIL: {} IFC policy violation(s) detected.", n);
                    process::exit(2);
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Proxy {
            audit_log,
            upstream,
        } => {
            let policy = load_policy(cli.policy);
            if let Err(e) = run_mcp_proxy(policy, &upstream, audit_log) {
                eprintln!("error: {}", e);
                process::exit(1);
            }
        }
    }
}
