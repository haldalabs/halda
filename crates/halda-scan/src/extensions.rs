//! Agents that live inside an editor as an extension. The editor updates them on
//! its own, so a bad release reaches every laptop without anyone running an
//! install. In October 2026 a trojanized Claude Code build on Open VSX did that:
//! it opened a reverse SSH tunnel from developer Macs the moment it activated.

use crate::{Finding, Item, Kind, Level};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Extension ids that are agents, and the agent each one is.
pub(crate) const AGENT_EXTENSIONS: &[(&str, &str)] = &[
    ("github.copilot", "GitHub Copilot"),
    ("github.copilot-chat", "GitHub Copilot"),
    ("anthropic.claude-code", "Claude Code"),
    ("openai.chatgpt", "Codex"),
    ("saoudrizwan.claude-dev", "Cline"),
    ("rooveterinaryinc.roo-cline", "Roo Code"),
    ("continue.continue", "Continue"),
    ("google.geminicodeassist", "Gemini Code Assist"),
    ("amazonwebservices.amazon-q-vscode", "Amazon Q"),
    ("sourcegraph.amp", "Amp"),
];

/// Where each editor keeps extensions, under the home directory, and whether it
/// installs them from Open VSX rather than Microsoft's marketplace.
pub(crate) const EDITORS: &[(&str, &str, bool)] = &[
    (".vscode/extensions", "VS Code", false),
    (".vscode-insiders/extensions", "VS Code Insiders", false),
    (".cursor/extensions", "Cursor", true),
    (".windsurf/extensions", "Windsurf", true),
    (".vscode-oss/extensions", "VSCodium", true),
];

/// Builds that were published with malware in them.
const KNOWN_BAD: &[(&str, &str, &str)] = &[(
    "anthropic.claude-code",
    "2.1.313",
    "a trojanized build found on Open VSX in October 2026 that installs a fake Apple launch agent, adds an SSH key and opens a reverse SSH tunnel (OpenSourceMalware and Daylight, 2026-10-30)",
)];

/// Text in an extension's own code that only a backdoor needs.
const BACKDOOR_SIGNS: &[(&str, &str)] = &[
    ("autossh", "keeps an SSH tunnel open"),
    (
        "localhost:22",
        "forwards this machine's SSH login to another host",
    ),
    (
        "StrictHostKeyChecking=no",
        "connects over SSH without checking who answers",
    ),
    (
        "authorized_keys",
        "adds a key that lets someone log in to this machine",
    ),
    (
        "LaunchAgents/com.apple.",
        "installs a startup task disguised as part of macOS",
    ),
    (
        "getremotelogin",
        "checks whether this Mac accepts remote logins",
    ),
];

/// Files the October 2026 implant leaves behind, under the home directory.
const IMPLANT_FILES: &[&str] = &[
    "Library/LaunchAgents/com.apple.sysmond.plist",
    ".config/.smt",
    ".config/.smtk",
];

/// Largest code file read for backdoor signs. Real extension bundles run to a
/// few megabytes.
const MAX_BUNDLE_BYTES: u64 = 32 * 1024 * 1024;

/// One extension folder, such as `anthropic.claude-code-2.1.325-darwin-arm64`.
struct Installed {
    id: String,
    version: String,
    folder: PathBuf,
    manifest: Value,
}

fn read_installed(folder: &Path) -> Option<Installed> {
    let manifest = crate::discover::read_json(&folder.join("package.json"))?;
    let field = |k: &str| manifest.get(k).and_then(Value::as_str).map(str::to_string);
    Some(Installed {
        id: format!("{}.{}", field("publisher")?, field("name")?).to_ascii_lowercase(),
        version: field("version")?,
        folder: folder.to_path_buf(),
        manifest,
    })
}

/// Marketplace categories that only AI extensions use.
const AI_CATEGORIES: &[&str] = &["AI", "Chat"];

/// Parts of the editor an extension can add to that only matter to AI.
const AI_CONTRIBUTIONS: &[&str] = &[
    "chatParticipants",
    "languageModelTools",
    "languageModelChatProviders",
    "mcpServerDefinitionProviders",
];

/// The agent an extension is: a known one by id, or any other that says it is AI.
fn agent_name(installed: &Installed) -> Option<String> {
    if let Some((_, name)) = AGENT_EXTENSIONS.iter().find(|(id, _)| *id == installed.id) {
        return Some((*name).to_string());
    }
    let manifest = &installed.manifest;
    let by_category = manifest
        .get("categories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|c| AI_CATEGORIES.contains(&c));
    let contributes = manifest.get("contributes");
    let by_contribution = AI_CONTRIBUTIONS
        .iter()
        .any(|k| contributes.and_then(|c| c.get(*k)).is_some());
    if !by_category && !by_contribution {
        return None;
    }
    let shown = manifest
        .get("displayName")
        .and_then(Value::as_str)
        .unwrap_or("");
    // `%key%` names live in package.nls.json.
    let shown = match shown.strip_prefix('%').and_then(|k| k.strip_suffix('%')) {
        Some(key) => crate::discover::read_json(&installed.folder.join("package.nls.json"))
            .and_then(|nls| nls.get(key).and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default(),
        None => shown.to_string(),
    };
    Some(if shown.is_empty() {
        installed.id.clone()
    } else {
        shown
    })
}

pub(crate) fn version_key(version: &str) -> Vec<u64> {
    version
        .split(['.', '-'])
        .map_while(|part| part.parse().ok())
        .collect()
}

/// The code an extension runs on activation: its top-level scripts and the
/// usual build folders. The webview is the page it shows, not what it runs.
fn bundle_files(folder: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in [
        folder.to_path_buf(),
        folder.join("dist"),
        folder.join("out"),
    ] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_script = path
                .extension()
                .is_some_and(|x| x == "js" || x == "cjs" || x == "mjs");
            if is_script && path.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn backdoor_signs(folder: &Path) -> Vec<&'static str> {
    let mut found = Vec::new();
    for path in bundle_files(folder) {
        if std::fs::metadata(&path).map_or(true, |m| m.len() > MAX_BUNDLE_BYTES) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for (needle, meaning) in BACKDOOR_SIGNS {
            if text.contains(needle) && !found.contains(meaning) {
                found.push(*meaning);
            }
        }
    }
    found
}

/// Every AI extension in every editor, one item per editor and extension: the known
/// agents by id, and any other whose manifest says it is AI.
/// Older versions left on disk are checked too: a bad build that was later
/// updated away can leave its backdoor running.
pub(crate) fn agent_extensions(home: &Path, out: &mut Vec<Item>) {
    for (dir, editor, open_registry) in EDITORS {
        let base = home.join(dir);
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        let mut by_id: BTreeMap<String, Vec<Installed>> = BTreeMap::new();
        for entry in entries.flatten() {
            if let Some(installed) = read_installed(&entry.path()) {
                by_id
                    .entry(installed.id.clone())
                    .or_default()
                    .push(installed);
            }
        }
        for (id, mut versions) in by_id {
            versions.sort_by_key(|v| version_key(&v.version));
            let Some(newest) = versions.last() else {
                continue;
            };
            let Some(agent) = agent_name(newest) else {
                continue;
            };
            let mut item = Item {
                name: format!("{id} in {editor}"),
                kind: Kind::Extension,
                source: newest.folder.display().to_string(),
                agent,
                command: format!("{id}@{}", newest.version),
                findings: vec![Finding::new(
                    "extension.present",
                    Level::Info,
                    format!("runs inside {editor} with your login and keys"),
                )],
                level: Level::Low,
                pin: String::new(),
                catalog: None,
                code_path: None,
            };
            for installed in &versions {
                if let Some((_, _, why)) = KNOWN_BAD
                    .iter()
                    .find(|(bad, version, _)| *bad == id && *version == installed.version)
                {
                    let when = if std::ptr::eq(installed, newest) {
                        "is installed"
                    } else {
                        "was installed here and is still on disk"
                    };
                    item.findings.push(Finding::new(
                        "extension.known_bad",
                        Level::High,
                        format!(
                            "version {} {when}: {why}. Treat this machine as compromised: rebuild it and rotate every key this user can reach",
                            installed.version
                        ),
                    ));
                }
            }
            let signs = backdoor_signs(&newest.folder);
            if !signs.is_empty() {
                item.findings.push(Finding::new(
                    "extension.backdoor",
                    Level::High,
                    format!("its code {}", signs.join(", and ")),
                ));
            }
            let contributes = newest.manifest.get("contributes");
            if contributes
                .and_then(|c| c.get("mcpServerDefinitionProviders"))
                .is_some()
            {
                item.findings.push(Finding::new(
                    "extension.mcp_provider",
                    Level::Medium,
                    "adds MCP servers to the editor's AI from its own code, where no config file shows them",
                ));
            }
            if contributes
                .and_then(|c| c.get("languageModelTools"))
                .is_some()
            {
                item.findings.push(Finding::new(
                    "extension.model_tools",
                    Level::Medium,
                    "gives the editor's AI tools that it can call on its own",
                ));
            }
            if *open_registry {
                item.findings.push(Finding::new(
                    "extension.open_registry",
                    Level::Medium,
                    format!(
                        "{editor} installs and updates it from Open VSX, where anyone can publish; approve its version in the catalog so a changed build is noticed"
                    ),
                ));
            }
            out.push(item);
        }
    }
}

/// The files the October 2026 implant leaves, whichever extension brought it.
pub(crate) fn implant_traces(home: &Path, out: &mut Vec<Item>) {
    let mut found: Vec<String> = IMPLANT_FILES
        .iter()
        .filter(|f| home.join(f).exists())
        .map(|f| format!("~/{f}"))
        .collect();
    let keys = home.join(".ssh/authorized_keys");
    if std::fs::read_to_string(&keys).is_ok_and(|t| t.contains("svc-telemetry")) {
        found.push("an svc-telemetry key in ~/.ssh/authorized_keys".to_string());
    }
    if found.is_empty() {
        return;
    }
    out.push(Item {
        name: "implant traces".to_string(),
        kind: Kind::Extension,
        source: home.display().to_string(),
        agent: "Claude Code".to_string(),
        command: found.join(", "),
        findings: vec![Finding::new(
            "host.known_implant",
            Level::High,
            format!(
                "files left by the trojanized Claude Code extension are on this machine ({}). Treat it as compromised: isolate it, rebuild it and rotate every key this user can reach",
                found.join(", ")
            ),
        )],
        level: Level::Low,
        pin: String::new(),
        catalog: None,
        code_path: None,
    });
}
