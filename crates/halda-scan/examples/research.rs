//! Scans unpacked npm packages with the same rules `halda scan` uses, for
//! Halda's published research. It reads files only: nothing is installed or run.
//!
//! Usage: `cargo run -p halda-scan --example research -- servers.json pkgs/ > out.jsonl`
//! where `servers.json` lists packages (`name`, `slug`-able name, `monthly`) and
//! each package is unpacked at `pkgs/<name with / as __>/package`.

use halda_scan::{assess, Item, Kind, Level};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(list), Some(pkgs)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: research <servers.json> <pkgs dir>");
        std::process::exit(2);
    };
    let text = std::fs::read_to_string(list).expect("read the package list");
    let servers: Vec<serde_json::Value> = serde_json::from_str(&text).expect("parse the list");
    for server in servers {
        let name = server["name"].as_str().unwrap_or_default().to_string();
        let root = PathBuf::from(pkgs)
            .join(name.replace('/', "__"))
            .join("package");
        if !root.is_dir() {
            continue;
        }
        let mut item = Item {
            name: name.clone(),
            kind: Kind::Mcp,
            source: "npm".into(),
            agent: String::new(),
            command: format!("npx -y {name}"),
            findings: Vec::new(),
            level: Level::Info,
            pin: String::new(),
            catalog: None,
            code_path: Some(root),
        };
        assess::assess(&mut item);
        let rules: Vec<&str> = item.findings.iter().map(|f| f.rule.as_str()).collect();
        println!(
            "{}",
            serde_json::json!({
                "name": name,
                "version": server["version"],
                "monthly": server["monthly"],
                "level": item.level,
                "rules": rules,
                "findings": item.findings,
            })
        );
    }
}
