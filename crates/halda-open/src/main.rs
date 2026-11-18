//! `halda`, the free tool. Everything runs on this machine and nothing is sent
//! anywhere, except the read-only GitHub and Microsoft lookups `map` makes when
//! asked to.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use halda_scan::catalog::Catalog;
use halda_scan::{report, Level, ScanOptions};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "halda",
    version,
    about = "Find every AI agent and add-on on this machine, see what a hijacked one could get out, and replay what your agents did. Free and local."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Find AI agents, MCP servers, skills, plugins, hooks and extensions, and explain what each can do.
    Scan {
        /// Print JSON.
        #[arg(long, conflicts_with = "sarif")]
        json: bool,
        /// Print SARIF, for code scanning tools.
        #[arg(long)]
        sarif: bool,
        /// Check against an approved catalog file.
        #[arg(long)]
        catalog: Option<PathBuf>,
        /// Exit non-zero if anything at this level or above is found.
        #[arg(long, value_parser = ["high", "medium", "low"])]
        fail_on: Option<String>,
        /// Add this item at its current version to the catalog file.
        #[arg(long, requires = "catalog")]
        approve: Option<String>,
    },
    /// Show every agent found, what it can reach, and what the map cannot see.
    Map {
        /// Print JSON.
        #[arg(long)]
        json: bool,
        /// Also read the GitHub Actions workflows of this owner's repositories. Read-only.
        /// Uses GH_TOKEN, GITHUB_TOKEN or a `gh` login. Repeatable.
        #[arg(long = "github", value_name = "OWNER")]
        github: Vec<String>,
        /// Also read AI apps and their grants from Microsoft 365, using the token in
        /// MICROSOFT_GRAPH_TOKEN. Read-only.
        #[arg(long)]
        microsoft: bool,
    },
    /// Play a hijacked agent on this machine and show which ways get a secret out.
    /// Uses a fake secret and a local listener. Nothing leaves the machine.
    Exposure {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Judge the commands your agents really ran, from Claude Code's history. Read-only.
    Replay {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `halda scan | head` closes the pipe early. Printing then fails, and Rust's
/// print macros panic on that. End quietly instead, as other command-line tools do.
fn quiet_when_the_reader_leaves() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let text = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        if text.contains("Broken pipe") {
            std::process::exit(0);
        }
        default(info);
    }));
}

fn main() -> ExitCode {
    quiet_when_the_reader_leaves();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan {
            json,
            sarif,
            catalog,
            fail_on,
            approve,
        } => scan(
            json,
            sarif,
            catalog.as_deref(),
            fail_on.as_deref(),
            approve.as_deref(),
        ),
        Command::Map {
            json,
            github,
            microsoft,
        } => map(json, &github, microsoft),
        Command::Exposure { json } => exposure(json),
        Command::Replay { json } => replay(json),
    };
    result.unwrap_or_else(|error| {
        eprintln!("halda: {error:#}");
        ExitCode::FAILURE
    })
}

const FULL_PRODUCT: &str =
    "Halda's full product does this for every machine, cloud and AI agent in your company, and stops what it finds: https://haldalabs.xyz";

fn colour() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout()) && std::env::var_os("NO_COLOR").is_none()
}

/// The person recorded when an item is approved.
fn login() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

fn scan(
    json_out: bool,
    sarif: bool,
    catalog_path: Option<&Path>,
    fail_on: Option<&str>,
    approve: Option<&str>,
) -> Result<ExitCode> {
    let mut result = halda_scan::scan(&ScanOptions::from_env());
    if let Some(path) = catalog_path {
        let mut catalog = match std::fs::read_to_string(path) {
            Ok(text) => Catalog::from_toml(&text)
                .with_context(|| format!("{} is not a valid catalog", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Catalog::default(),
            Err(e) => return Err(e.into()),
        };
        if let Some(name) = approve {
            let item = result
                .items
                .iter()
                .find(|i| i.name == name)
                .with_context(|| format!("nothing named {name} was found"))?;
            catalog.approve(item, &login());
            std::fs::write(path, catalog.to_toml()?)?;
            println!("{name} approved at its current version.");
        }
        catalog.apply(&mut result);
    }
    if json_out {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if sarif {
        println!("{}", serde_json::to_string_pretty(&report::sarif(&result))?);
    } else {
        print!("{}", report::table(&result, colour()));
        println!("\n{FULL_PRODUCT}");
    }
    if let Some(level) = fail_on {
        let threshold = match level {
            "high" => Level::High,
            "medium" => Level::Medium,
            _ => Level::Low,
        };
        if result.items.iter().any(|i| i.level >= threshold) {
            return Ok(ExitCode::from(3));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn github_token() -> Result<String> {
    for name in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(token) = std::env::var(name) {
            if !token.is_empty() {
                return Ok(token);
            }
        }
    }
    let output = std::process::Command::new("gh")
        .args(["auth", "token"])
        .stderr(std::process::Stdio::null())
        .output()
        .context("--github needs GH_TOKEN, GITHUB_TOKEN or a `gh` login")?;
    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() || token.is_empty() {
        bail!("--github needs GH_TOKEN, GITHUB_TOKEN or a `gh` login");
    }
    Ok(token)
}

/// A read-only GET. The error says only what happened, so the token stays out of it.
fn fetch_json(url: &str, token: &str) -> Result<serde_json::Value, String> {
    let response = ureq::get(url)
        .timeout(std::time::Duration::from_secs(30))
        .set("authorization", &format!("Bearer {token}"))
        .set("user-agent", "halda-map")
        .call();
    match response {
        Ok(response) => response
            .into_json()
            .map_err(|_| "unreadable reply".to_string()),
        Err(ureq::Error::Status(code, _)) => Err(format!("status {code}")),
        Err(_) => Err("could not connect".to_string()),
    }
}

fn map(json_out: bool, github: &[String], microsoft: bool) -> Result<ExitCode> {
    use halda_scan::connectors::{github_workflows, microsoft_grants};
    use halda_scan::map::{build, MapOptions};
    let options = ScanOptions::from_env();
    let report = halda_scan::scan(&options);
    let mut here = build(&report, &options, &MapOptions::from_env(&options));
    if !github.is_empty() {
        let token = github_token()?;
        let fetch = |url: &str| fetch_json(url, &token);
        for owner in github {
            if !owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                bail!("{owner} is not a GitHub owner name");
            }
            let found = github_workflows("https://api.github.com", owner, &fetch);
            here.entries.extend(found.entries);
            here.gaps.extend(found.gaps);
        }
    }
    if microsoft {
        let token = std::env::var("MICROSOFT_GRAPH_TOKEN")
            .context("--microsoft needs a token in MICROSOFT_GRAPH_TOKEN")?;
        let found = microsoft_grants("https://graph.microsoft.com", &|url: &str| {
            fetch_json(url, &token)
        });
        here.entries.extend(found.entries);
        here.gaps.extend(found.gaps);
    }
    if json_out {
        println!("{}", serde_json::to_string_pretty(&here)?);
    } else {
        print!("{}", halda_scan::map::table(&here));
        println!("\n{FULL_PRODUCT}");
    }
    Ok(ExitCode::SUCCESS)
}

fn exposure(json_out: bool) -> Result<ExitCode> {
    if !json_out {
        println!("Playing a hijacked agent. Fake secret, local listener, throwaway folders.\n");
    }
    let report = halda_scan::exposure::run(&mut |row| {
        if !json_out {
            let note = row["note"].as_str().unwrap_or_default();
            let note = if note.is_empty() {
                String::new()
            } else {
                format!(" ({note})")
            };
            println!(
                "  {:<56} {}{note}",
                row["route"].as_str().unwrap_or_default(),
                row["result"].as_str().unwrap_or_default()
            );
        }
    })?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "\n{} of {} ways got the fake secret out, with nothing in the way.",
        report["got_out"], report["run"]
    );
    let reach: Vec<&str> = report["credential_files_in_reach"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| f.as_str())
        .collect();
    if !reach.is_empty() {
        println!(
            "\nReal credential files any agent running as you can open ({}). Checked that they exist, never opened:",
            reach.len()
        );
        for file in reach {
            println!("  ~/{file}");
        }
    }
    println!("\nAn agent that reads one poisoned file, issue or web page can be told to do any of these. {FULL_PRODUCT}");
    Ok(ExitCode::SUCCESS)
}

fn replay(json_out: bool) -> Result<ExitCode> {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let result = halda_scan::replay::replay(&home);
    if json_out {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        halda_scan::replay::print(&result, &home);
        println!("\n{FULL_PRODUCT}");
    }
    Ok(ExitCode::SUCCESS)
}
