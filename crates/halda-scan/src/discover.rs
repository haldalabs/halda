//! Finds agents and add-ons from their config files.

use crate::{Item, Kind, Level, ScanOptions};
use halda_core::redact::redact;
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const AGENT_BINARIES: &[(&str, &str)] = &[
    ("claude", "Claude Code"),
    ("cursor", "Cursor"),
    ("cursor-agent", "Cursor"),
    ("codex", "Codex"),
    ("aider", "Aider"),
    ("gemini", "Gemini CLI"),
    ("goose", "Goose"),
    ("amp", "Amp"),
    ("windsurf", "Windsurf"),
];

fn blank(name: &str, kind: Kind, source: &Path, agent: &str) -> Item {
    Item {
        name: name.to_string(),
        kind,
        source: source.display().to_string(),
        agent: agent.to_string(),
        command: String::new(),
        findings: Vec::new(),
        level: Level::Low,
        pin: String::new(),
        catalog: None,
        code_path: None,
    }
}

/// Reads one MCP server entry.
fn mcp_item(name: &str, entry: &Value, source: &Path, agent: &str) -> Item {
    let mut item = blank(name, Kind::Mcp, source, agent);
    let command = entry.get("command").and_then(Value::as_str).unwrap_or("");
    let args: Vec<String> =
        entry
            .get("args")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            });
    let url = entry
        .get("url")
        .or_else(|| entry.get("serverUrl"))
        .or_else(|| entry.get("httpUrl"))
        .and_then(Value::as_str)
        .unwrap_or("");
    item.command = redact(&if url.is_empty() {
        format!("{command} {}", args.join(" ")).trim().to_string()
    } else {
        url.to_string()
    });
    // Stored for assessment under fixed keys. Values never leave this struct's
    // redacted fields: assess reads names and whether a value looks secret.
    let mut secrets = Vec::new();
    for section in ["env", "headers", "http_headers"] {
        if let Some(map) = entry.get(section).and_then(Value::as_object) {
            for (key, value) in map {
                let text = value.as_str().unwrap_or("");
                let is_reference =
                    text.starts_with("${") || text.starts_with('$') || text.is_empty();
                let looks_secret = halda_core::redact::contains_secret(&format!("{key}={text}"))
                    || halda_core::redact::contains_secret(text);
                if looks_secret && !is_reference {
                    secrets.push(key.clone());
                }
            }
        }
    }
    if !secrets.is_empty() {
        item.findings.push(crate::Finding::new(
            "mcp.plaintext_secret",
            Level::High,
            format!(
                "keeps a long-lived secret in plain text ({})",
                secrets.join(", ")
            ),
        ));
    }
    // Credentials on the command line or in a URL are plain text too.
    let carries_secret = args
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(url))
        .any(halda_core::redact::contains_secret);
    if carries_secret {
        item.findings.push(crate::Finding::new(
            "mcp.secret_in_args",
            Level::High,
            "has a password or key written into its command line, which any local process can read",
        ));
    }
    // A local script: its code can be read.
    for candidate in std::iter::once(command).chain(args.iter().map(String::as_str)) {
        let path = Path::new(candidate);
        // Files only. A directory argument is usually data the server may touch,
        // such as a filesystem server's root, not the server's code.
        if path.is_absolute() && path.is_file() {
            item.code_path = Some(path.to_path_buf());
            break;
        }
    }
    item
}

fn mcp_servers(root: &Value, source: &Path, agent: &str, out: &mut Vec<Item>) {
    for key in ["mcpServers", "servers", "mcp_servers"] {
        if let Some(map) = root.get(key).and_then(Value::as_object) {
            for (name, entry) in map {
                out.push(mcp_item(name, entry, source, agent));
            }
        }
    }
}

pub(crate) fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn json_config(path: &Path, agent: &str, out: &mut Vec<Item>) {
    let Some(root) = read_json(path) else { return };
    mcp_servers(&root, path, agent, out);
    // Claude Code keeps per-project servers under `projects`.
    if let Some(projects) = root.get("projects").and_then(Value::as_object) {
        for project in projects.values() {
            mcp_servers(project, path, agent, out);
        }
    }
}

fn codex_config(path: &Path, out: &mut Vec<Item>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(parsed) = toml::from_str::<toml::Value>(&text) else {
        return;
    };
    let Ok(json) = serde_json::to_value(&parsed) else {
        return;
    };
    mcp_servers(&json, path, "Codex", out);
}

fn hooks(path: &Path, agent: &str, out: &mut Vec<Item>) {
    let Some(root) = read_json(path) else { return };
    let Some(map) = root.get("hooks").and_then(Value::as_object) else {
        return;
    };
    for (event, groups) in map {
        for group in groups.as_array().into_iter().flatten() {
            let inner = group
                .get("hooks")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| vec![group.clone()]);
            for hook in inner {
                if let Some(command) = hook.get("command").and_then(Value::as_str) {
                    let mut item = blank(&format!("hook:{event}"), Kind::Hook, path, agent);
                    item.command = redact(command);
                    out.push(item);
                }
            }
        }
    }
}

fn skills_in(dir: &Path, agent: &str, out: &mut Vec<Item>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let is_skill = path.is_dir() && path.join("SKILL.md").exists();
        if is_skill || path.extension().is_some_and(|x| x == "md") {
            let mut item = blank(&name, Kind::Skill, &path, agent);
            item.code_path = Some(path);
            out.push(item);
        }
    }
}

fn plugins_in(dir: &Path, agent: &str, out: &mut Vec<Item>) {
    // A plugin is any directory holding a plugin manifest.
    let walker = WalkDir::new(dir)
        .max_depth(5)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.file_name() != "node_modules" && e.file_name() != ".git");
    for entry in walker.filter_map(Result::ok) {
        if entry.file_name() == "plugin.json" {
            let Some(parent) = entry.path().parent() else {
                continue;
            };
            let root = if parent.file_name().is_some_and(|n| n == ".claude-plugin") {
                parent.parent().unwrap_or(parent)
            } else {
                parent
            };
            let name = read_json(entry.path())
                .and_then(|v| v.get("name").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| {
                    root.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                });
            let mut item = blank(&name, Kind::Plugin, root, agent);
            item.code_path = Some(root.to_path_buf());
            out.push(item);
        }
    }
}

fn agents_on_path(path: Option<&std::ffi::OsString>, out: &mut Vec<Item>) {
    let Some(path) = path else { return };
    let dirs: Vec<PathBuf> = std::env::split_paths(path).collect();
    let mut seen = HashSet::new();
    for (binary, label) in AGENT_BINARIES {
        if let Some(found) = dirs.iter().map(|d| d.join(binary)).find(|p| p.is_file()) {
            if seen.insert(*label) {
                let mut item = blank(label, Kind::Agent, &found, label);
                item.command = binary.to_string();
                out.push(item);
            }
        }
    }
}

/// Settings that turn off an agent's own checks altogether.
fn bypass_modes(options: &ScanOptions, out: &mut Vec<Item>) {
    for path in [
        options.home.join(".claude/settings.json"),
        options.project.join(".claude/settings.json"),
        options.project.join(".claude/settings.local.json"),
    ] {
        let Some(root) = read_json(&path) else {
            continue;
        };
        if root
            .pointer("/permissions/defaultMode")
            .and_then(Value::as_str)
            == Some("bypassPermissions")
        {
            let mut item = blank("permission bypass", Kind::Hook, &path, "Claude Code");
            item.command = "defaultMode: bypassPermissions".to_string();
            item.findings.push(crate::Finding::new(
                "agent.bypass_mode",
                Level::High,
                "Claude Code runs every tool without asking anyone",
            ));
            out.push(item);
        }
    }
    for path in [
        options.home.join(".codex/config.toml"),
        options.project.join(".codex/config.toml"),
    ] {
        let Some(root) = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| toml::from_str::<toml::Value>(&t).ok())
        else {
            continue;
        };
        let full_access =
            root.get("sandbox_mode").and_then(toml::Value::as_str) == Some("danger-full-access");
        let never_asks = root.get("approval_policy").and_then(toml::Value::as_str) == Some("never");
        if full_access || never_asks {
            let mut item = blank("permission bypass", Kind::Hook, &path, "Codex");
            item.command = if full_access {
                "sandbox_mode: danger-full-access"
            } else {
                "approval_policy: never"
            }
            .to_string();
            item.findings.push(crate::Finding::new(
                "agent.bypass_mode",
                Level::High,
                if full_access {
                    "Codex runs with no sandbox"
                } else {
                    "Codex runs commands without asking anyone"
                },
            ));
            out.push(item);
        }
    }
}

/// Everything found under `options`.
pub fn discover(options: &ScanOptions) -> Vec<Item> {
    let home = &options.home;
    let project = &options.project;
    let mut out = Vec::new();
    agents_on_path(options.path.as_ref(), &mut out);
    bypass_modes(options, &mut out);

    for (path, agent) in [
        (home.join(".claude.json"), "Claude Code"),
        (home.join(".claude/settings.json"), "Claude Code"),
        (project.join(".mcp.json"), "Claude Code"),
        (
            home.join("Library/Application Support/Claude/claude_desktop_config.json"),
            "Claude Desktop",
        ),
        (
            home.join(".config/Claude/claude_desktop_config.json"),
            "Claude Desktop",
        ),
        (home.join(".cursor/mcp.json"), "Cursor"),
        (project.join(".cursor/mcp.json"), "Cursor"),
        (home.join(".codeium/windsurf/mcp_config.json"), "Windsurf"),
        (project.join(".vscode/mcp.json"), "VS Code"),
        (home.join(".gemini/settings.json"), "Gemini CLI"),
    ] {
        json_config(&path, agent, &mut out);
    }
    codex_config(&home.join(".codex/config.toml"), &mut out);
    codex_config(&project.join(".codex/config.toml"), &mut out);

    for path in [
        home.join(".claude/settings.json"),
        project.join(".claude/settings.json"),
        project.join(".claude/settings.local.json"),
    ] {
        hooks(&path, "Claude Code", &mut out);
    }
    hooks(&home.join(".cursor/hooks.json"), "Cursor", &mut out);
    hooks(&project.join(".cursor/hooks.json"), "Cursor", &mut out);

    for base in [home.join(".claude"), project.join(".claude")] {
        skills_in(&base.join("skills"), "Claude Code", &mut out);
        skills_in(&base.join("commands"), "Claude Code", &mut out);
    }
    plugins_in(&home.join(".claude/plugins"), "Claude Code", &mut out);
    plugins_in(&project.join(".claude/plugins"), "Claude Code", &mut out);
    crate::extensions::agent_extensions(home, &mut out);
    crate::extensions::implant_traces(home, &mut out);
    crate::browsers::browser_ai(
        home,
        &[PathBuf::from("/Applications"), home.join("Applications")],
        &mut out,
    );

    // The same server can be listed by several configs.
    let mut unique = HashSet::new();
    out.retain(|i| unique.insert((i.name.clone(), i.command.clone())));
    out
}
