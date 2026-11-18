//! The map: every agent found, with one of three labels.
//!
//! - **Seen**: known to Halda, and nothing holds it back.
//! - **Limited**: it starts inside the wall, with real keys out of reach and the
//!   network closed.
//! - **Gated**: limited, and a check that fails closed decides before it acts.
//!
//! A hook alone is not a label. It sees what an agent reports, not what a command
//! does once it runs, so an agent with only a hook stays Seen. Read-only and local,
//! like the scan: it checks whether credential files exist and never opens them.

use crate::discover::read_json;
use crate::{Item, Kind, Level, Report, ScanOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Marks a command made by `halda confine`, which starts an agent inside the wall.
pub const CONFINED_MARK: &str = "# halda-confined";

/// Credential files an agent running as this user could open.
const CREDENTIAL_FILES: &[&str] = &[
    ".aws/credentials",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".config/gh/hosts.yml",
    ".config/gcloud/application_default_credentials.json",
    ".azure/msal_token_cache.json",
    ".kube/config",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".vault-token",
    ".pgpass",
];

const APPS: &[(&str, &str)] = &[
    ("Cursor.app", "Cursor"),
    ("Claude.app", "Claude Desktop"),
    ("ChatGPT.app", "ChatGPT Desktop"),
    ("Codex.app", "Codex"),
    ("Windsurf.app", "Windsurf"),
];

/// Text in a CI workflow that means an agent runs there.
pub(crate) const CI_AGENTS: &[(&str, &str)] = &[
    ("anthropics/claude-code-action", "Claude Code"),
    ("claude -p", "Claude Code"),
    ("openai/codex-action", "Codex"),
    ("codex exec", "Codex"),
    ("google-github-actions/run-gemini-cli", "Gemini CLI"),
    ("cursor-agent ", "Cursor"),
    ("aider ", "Aider"),
];

/// The three labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Label {
    /// Known, and nothing holds it back.
    Seen,
    /// Keys out of reach and network closed.
    Limited,
    /// Limited, with a check that fails closed before it acts.
    Gated,
}

impl Label {
    /// Word for the table.
    pub fn word(self) -> &'static str {
        match self {
            Label::Seen => "SEEN",
            Label::Limited => "LIMITED",
            Label::Gated => "GATED",
        }
    }
}

/// What holds an agent back. The label comes from these and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Controls {
    /// No credential file is within its reach.
    pub keys_out: bool,
    /// Its outbound traffic is denied by default. Halda cannot do this yet.
    pub network_closed: bool,
    /// A Halda check stops it if the check itself fails.
    pub check_fails_closed: bool,
}

impl Controls {
    /// The label these controls earn.
    pub fn label(self) -> Label {
        match (
            self.keys_out && self.network_closed,
            self.check_fails_closed,
        ) {
            (true, true) => Label::Gated,
            (true, false) => Label::Limited,
            (false, _) => Label::Seen,
        }
    }
}

/// Whether a Halda hook is set up for an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
    /// No Halda hook.
    None,
    /// Set up, and the agent carries on if the hook fails.
    FailsOpen,
    /// Set up, and the agent stops if the hook fails.
    FailsClosed,
    /// This agent has no hook Halda can use, such as in CI.
    NotApplicable,
}

impl Hook {
    fn text(self) -> &'static str {
        match self {
            Hook::None => "No Halda hook",
            Hook::FailsOpen => "Halda hook on, but the agent carries on if it fails",
            Hook::FailsClosed => "Halda hook on, and the agent stops if it fails",
            Hook::NotApplicable => "No Halda check here",
        }
    }
}

/// Where an agent runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Place {
    /// This computer.
    ThisMachine,
    /// CI for a repository.
    Ci,
    /// Runs at its vendor. Only its grant can be seen or narrowed from outside.
    Hosted,
}

impl Place {
    fn text(self) -> &'static str {
        match self {
            Place::ThisMachine => "this machine",
            Place::Ci => "CI",
            Place::Hosted => "hosted by its vendor",
        }
    }
}

/// One agent on the map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Its name.
    pub name: String,
    /// Where it runs.
    pub place: Place,
    /// The label.
    pub label: Label,
    /// What the label was worked out from.
    pub controls: Controls,
    /// Who answers for it. `None` when nothing says.
    pub owner: Option<String>,
    /// Whether a Halda hook is set up.
    pub hook: Hook,
    /// Whether starting it by name starts it inside the wall.
    pub confined: bool,
    /// Whether its command starts inside the wall, even if an app or extension does not.
    #[serde(default)]
    pub command_confined: bool,
    /// Apps and extensions of this agent that do not start through the wall.
    #[serde(default)]
    pub outside_wall: Vec<String>,
    /// How it was found.
    pub found_in: Vec<String>,
    /// MCP servers, skills and plugins it can use.
    pub add_ons: usize,
    /// Of its MCP servers, how many run through the Halda proxy.
    pub mcp_through_halda: usize,
    /// The most serious things it can do, as the scan states them.
    pub high_risk: Vec<String>,
    /// Names of CI secrets its workflow can read. Names only.
    pub secret_names: Vec<String>,
}

/// A part of the company this map cannot see.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blind {
    /// The part.
    pub place: String,
    /// What seeing it would take.
    pub needs: String,
}

/// The whole map of one machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Map {
    /// The machine it describes.
    #[serde(default)]
    pub machine: String,
    /// Every agent found.
    pub entries: Vec<Entry>,
    /// Credential files any agent on this machine could open. Never opened here.
    pub credential_files: Vec<String>,
    /// What this map does not cover.
    pub not_covered: Vec<Blind>,
    /// What a connection could not read this time.
    #[serde(default)]
    pub gaps: Vec<String>,
}

impl Map {
    /// How many agents have this label.
    pub fn count(&self, label: Label) -> usize {
        self.entries.iter().filter(|e| e.label == label).count()
    }
}

/// What the map needs beyond the scan.
#[derive(Debug, Clone, Default)]
pub struct MapOptions {
    /// This machine's name.
    pub machine: String,
    /// Who is logged in. Taken as the owner of what runs on this machine.
    pub login: String,
    /// True if the installed Claude Code honours a hook's `onFailure: block`.
    pub claude_can_fail_closed: bool,
    /// Folders that hold desktop apps.
    pub app_folders: Vec<PathBuf>,
}

impl MapOptions {
    /// What is true of this machine now.
    pub fn from_env(scan: &ScanOptions) -> Self {
        Self {
            machine: machine_name(),
            login: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_default(),
            claude_can_fail_closed: claude_can_fail_closed(),
            app_folders: vec![
                PathBuf::from("/Applications"),
                scan.home.join("Applications"),
            ],
        }
    }
}

fn machine_name() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "this machine".to_string())
}

/// Claude Code versions before this cannot be told to block when a hook fails.
const CLAUDE_FAIL_CLOSED_VERSION: (u32, u32, u32) = (2, 1, 295);

fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let word = text.split_whitespace().next()?;
    let mut parts = word.split('.').map(|p| p.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

/// True if the Claude Code on this machine honours `onFailure: block`.
pub fn claude_can_fail_closed() -> bool {
    Command::new("claude")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| parse_version(&String::from_utf8_lossy(&out.stdout)))
        .is_some_and(|version| version >= CLAUDE_FAIL_CLOSED_VERSION)
}

/// Credential files within reach under `home`. Checks they exist, never opens them.
pub fn credentials_in_reach(home: &Path) -> Vec<&'static str> {
    CREDENTIAL_FILES
        .iter()
        .copied()
        .filter(|file| home.join(file).is_file())
        .collect()
}

fn is_halda_hook(hook: &Value) -> bool {
    hook.get("command")
        .and_then(Value::as_str)
        .is_some_and(|c| c.contains("halda") && c.contains(" hook "))
}

/// Every hook entry in a settings file, wherever the agent's format nests it.
fn hook_entries(root: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for groups in root
        .get("hooks")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|map| map.values())
    {
        for group in groups.as_array().into_iter().flatten() {
            match group.get("hooks").and_then(Value::as_array) {
                Some(inner) => out.extend(inner.iter().cloned()),
                None => out.push(group.clone()),
            }
        }
    }
    out
}

fn hook_state(agent: &str, scan: &ScanOptions, options: &MapOptions) -> Hook {
    let files: Vec<PathBuf> = match agent {
        "Claude Code" => vec![
            scan.home.join(".claude/settings.json"),
            scan.project.join(".claude/settings.json"),
            scan.project.join(".claude/settings.local.json"),
        ],
        "Cursor" => vec![
            scan.home.join(".cursor/hooks.json"),
            scan.project.join(".cursor/hooks.json"),
        ],
        "Codex" => vec![
            scan.home.join(".codex/hooks.json"),
            scan.project.join(".codex/hooks.json"),
        ],
        _ => return Hook::None,
    };
    let entries: Vec<Value> = files
        .iter()
        .filter_map(|path| read_json(path))
        .flat_map(|root| hook_entries(&root))
        .filter(is_halda_hook)
        .collect();
    if entries.is_empty() {
        return Hook::None;
    }
    let closes = match agent {
        "Claude Code" => {
            options.claude_can_fail_closed
                && entries
                    .iter()
                    .any(|h| h.get("onFailure").and_then(Value::as_str) == Some("block"))
        }
        "Cursor" => entries
            .iter()
            .all(|h| h.get("failClosed").and_then(Value::as_bool) == Some(true)),
        // Codex has no option for this.
        _ => false,
    };
    if closes {
        Hook::FailsClosed
    } else {
        Hook::FailsOpen
    }
}

fn found_outside_config(scan: &ScanOptions, options: &MapOptions) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for folder in &options.app_folders {
        for (app, name) in APPS {
            let path = folder.join(app);
            if path.exists() {
                found
                    .entry((*name).to_string())
                    .or_default()
                    .push(path.display().to_string());
            }
        }
    }
    for (dir, _, _) in crate::extensions::EDITORS {
        let Ok(entries) = std::fs::read_dir(scan.home.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let folder_name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if let Some((_, name)) = crate::extensions::AGENT_EXTENSIONS
                .iter()
                .find(|(start, _)| folder_name.starts_with(start))
            {
                let list = found.entry((*name).to_string()).or_default();
                let text = format!("extension {folder_name}");
                if !list.contains(&text) {
                    list.push(text);
                }
            }
        }
    }
    found
}

fn workflow_files(project: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(project.join(".github/workflows"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .collect();
    files.push(project.join(".gitlab-ci.yml"));
    files.sort();
    files
}

/// `secrets.NAME` references. Workflows hold names, never values.
pub(crate) fn secret_names(text: &str) -> Vec<String> {
    let mut names: Vec<String> = text
        .split("secrets.")
        .skip(1)
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .filter(|name| !name.is_empty())
        .collect();
    names.sort();
    names.dedup();
    names
}

fn ci_entries(project: &Path) -> Vec<Entry> {
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    for path in workflow_files(project) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (marker, name) in CI_AGENTS {
            if !text.contains(marker) {
                continue;
            }
            let entry = entries.entry((*name).to_string()).or_insert_with(|| {
                let controls = Controls::default();
                Entry {
                    name: (*name).to_string(),
                    place: Place::Ci,
                    label: controls.label(),
                    controls,
                    owner: None,
                    hook: Hook::NotApplicable,
                    confined: false,
                    command_confined: false,
                    outside_wall: Vec::new(),
                    found_in: Vec::new(),
                    add_ons: 0,
                    mcp_through_halda: 0,
                    high_risk: Vec::new(),
                    secret_names: Vec::new(),
                }
            });
            let shown = path.display().to_string();
            if !entry.found_in.contains(&shown) {
                entry.found_in.push(shown);
            }
            entry.secret_names.extend(secret_names(&text));
            entry.secret_names.sort();
            entry.secret_names.dedup();
        }
    }
    entries.into_values().collect()
}

fn is_confined_command(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.len() < 4096)
        && std::fs::read_to_string(path).is_ok_and(|text| text.contains(CONFINED_MARK))
}

fn add_on(item: &Item) -> bool {
    matches!(item.kind, Kind::Mcp | Kind::Skill | Kind::Plugin)
}

fn not_covered() -> Vec<Blind> {
    [
        (
            "Other people's laptops",
            "`halda map --json` on each, then `halda map --import`. No automatic fleet scanner yet",
        ),
        (
            "AI in Firefox and Safari, and native bridges installed for every user",
            "reading Firefox's packed extensions, Safari's app extensions and /Library, not built. Chromium browsers are read",
        ),
        (
            "What people type into AI websites",
            "the Halda browser extension on each machine, rolled out by IT",
        ),
        ("Cloud workloads", "cloud connectors, not built"),
        (
            "CI in other repositories",
            "a GitHub or GitLab connection, not built",
        ),
        (
            "Connectors added through a vendor account, such as Claude.ai connectors",
            "a connection to that vendor, not built",
        ),
        (
            "Vendor-hosted agents such as Copilot Studio, Agentforce and ChatGPT Enterprise",
            "a connection to each vendor's admin. `--microsoft` reads Microsoft 365 grants, and has never run against a real tenant. Others are not built",
        ),
    ]
    .into_iter()
    .map(|(place, needs)| Blind {
        place: place.to_string(),
        needs: needs.to_string(),
    })
    .collect()
}

/// Builds the map from a scan and what else is on the machine.
pub fn build(report: &Report, scan: &ScanOptions, options: &MapOptions) -> Map {
    let credential_files = credentials_in_reach(&scan.home);
    let outside = found_outside_config(scan, options);

    let mut names: Vec<String> = report
        .items
        .iter()
        .map(|i| i.agent.clone())
        .chain(outside.keys().cloned())
        .collect();
    names.sort();
    names.dedup();

    let mut entries: Vec<Entry> = names
        .into_iter()
        .map(|name| {
            let mine: Vec<&Item> = report.items.iter().filter(|i| i.agent == name).collect();
            let hook = hook_state(&name, scan, options);
            // Only the command that comes first on PATH counts. A desktop app or an
            // editor extension is not started through it, so it is never confined.
            let command_confined = mine
                .iter()
                .any(|i| i.kind == Kind::Agent && is_confined_command(&i.source));
            let confined = command_confined && !outside.contains_key(&name);
            let mut outside_wall: Vec<String> =
                outside.get(&name).cloned().into_iter().flatten().collect();
            outside_wall.sort();
            outside_wall.dedup();
            let controls = Controls {
                keys_out: confined || credential_files.is_empty(),
                network_closed: confined,
                check_fails_closed: hook == Hook::FailsClosed,
            };
            let mut found_in: Vec<String> = mine
                .iter()
                .filter(|i| i.kind == Kind::Agent)
                .map(|i| i.source.clone())
                .collect();
            found_in.extend(outside.get(&name).into_iter().flatten().cloned());
            if found_in.is_empty() {
                found_in.extend(mine.iter().take(1).map(|i| i.source.clone()));
            }
            let mut high_risk: Vec<String> = mine
                .iter()
                .flat_map(|i| i.findings.iter())
                .filter(|f| f.level == Level::High)
                .map(|f| f.text.clone())
                .collect();
            high_risk.sort();
            high_risk.dedup();
            Entry {
                label: controls.label(),
                place: Place::ThisMachine,
                controls,
                owner: (!options.login.is_empty()).then(|| options.login.clone()),
                hook,
                confined,
                command_confined,
                outside_wall,
                found_in,
                add_ons: mine.iter().filter(|i| add_on(i)).count(),
                mcp_through_halda: mine
                    .iter()
                    .filter(|i| {
                        i.kind == Kind::Mcp
                            && i.command.contains("halda")
                            && i.command.contains("mcp-proxy")
                    })
                    .count(),
                high_risk,
                secret_names: Vec::new(),
                name,
            }
        })
        .collect();
    entries.extend(ci_entries(&scan.project));

    Map {
        machine: options.machine.clone(),
        entries,
        credential_files: credential_files.into_iter().map(str::to_string).collect(),
        not_covered: not_covered(),
        gaps: Vec::new(),
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// The map as text.
pub fn table(map: &Map) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}: {} gated, {} limited, {} seen only.\n",
        plural(map.entries.len(), "agent", "agents"),
        map.count(Label::Gated),
        map.count(Label::Limited),
        map.count(Label::Seen),
    );
    for entry in &map.entries {
        let _ = writeln!(
            out,
            "{:<8}{}  ({}, owner: {})",
            entry.label.word(),
            entry.name,
            entry.place.text(),
            entry.owner.as_deref().unwrap_or("none on record"),
        );
        let mut facts = vec![entry.hook.text().to_string()];
        if entry.confined {
            facts.insert(0, "Inside the wall when started by name".to_string());
        }
        if entry.add_ons > 0 {
            let mut add_ons = plural(entry.add_ons, "add-on", "add-ons");
            if entry.mcp_through_halda > 0 {
                let _ = write!(add_ons, ", {} through Halda", entry.mcp_through_halda);
            }
            facts.push(add_ons);
        }
        let _ = writeln!(out, "        {}", facts.join(". "));
        for risk in &entry.high_risk {
            let _ = writeln!(out, "        High risk: {risk}");
        }
        if !entry.secret_names.is_empty() {
            let _ = writeln!(
                out,
                "        Workflow can read secrets: {}",
                entry.secret_names.join(", ")
            );
        }
    }
    if map.entries.is_empty() {
        let _ = writeln!(out, "No agents found.");
    }
    if !map.credential_files.is_empty() {
        let _ = writeln!(
            out,
            "\nAny agent on this machine could open these credential files (checked that they exist, never opened):"
        );
        for file in &map.credential_files {
            let _ = writeln!(out, "  ~/{file}");
        }
    }
    if map
        .entries
        .iter()
        .any(|e| !e.confined && e.place == Place::ThisMachine)
    {
        let _ = writeln!(
            out,
            "\nTo move an agent up, run `halda confine <command>`. Limited means real keys out of reach and the network closed by default. Gated also needs a hook that stops the agent if it fails. A hook alone does not count, because `halda breach-test` gets past it. Desktop apps and editor extensions cannot be confined yet."
        );
    }
    if map.entries.iter().any(|e| e.confined) {
        let _ = writeln!(
            out,
            "\nThe wall applies when an agent is started by name from this PATH. Starting it by its full path skips the wall. `halda breach-test --confined` shows what it holds."
        );
    }
    for gap in &map.gaps {
        let _ = writeln!(out, "\nIncomplete: {gap}");
    }
    let _ = writeln!(out, "\nNot on this map:");
    for blind in &map.not_covered {
        let _ = writeln!(out, "  {}: needs {}", blind.place, blind.needs);
    }
    let _ = writeln!(
        out,
        "\nOwner on this machine is the logged-in user, not a confirmed owner. Agents are found by known names, so one Halda has no name for will not appear."
    );
    out
}

/// Maps of several machines, as a first step to the whole company.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Fleet {
    /// One map per machine, by name. Importing a machine again replaces it.
    pub machines: Vec<Map>,
}

impl Fleet {
    /// Adds a machine, replacing any earlier map with the same name.
    pub fn add(&mut self, map: Map) {
        self.machines.retain(|m| m.machine != map.machine);
        self.machines.push(map);
        self.machines.sort_by(|a, b| a.machine.cmp(&b.machine));
    }

    /// How many agents across every machine have this label.
    pub fn count(&self, label: Label) -> usize {
        self.machines.iter().map(|m| m.count(label)).sum()
    }

    /// How many agents across every machine.
    pub fn agents(&self) -> usize {
        self.machines.iter().map(|m| m.entries.len()).sum()
    }

    /// Reads every map in a folder. Files that are not maps are named, not ignored.
    pub fn read(folder: &Path) -> (Self, Vec<String>) {
        let mut fleet = Self::default();
        let mut problems = Vec::new();
        let Ok(entries) = std::fs::read_dir(folder) else {
            return (fleet, problems);
        };
        for path in entries.flatten().map(|e| e.path()) {
            if path.extension().is_none_or(|x| x != "json") {
                continue;
            }
            match std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<Map>(&text).ok())
            {
                Some(map) if !map.machine.is_empty() => fleet.add(map),
                _ => problems.push(path.display().to_string()),
            }
        }
        (fleet, problems)
    }

    /// The fleet as text.
    pub fn table(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} on {}: {} gated, {} limited, {} seen only.\n",
            plural(self.agents(), "agent", "agents"),
            plural(self.machines.len(), "machine", "machines"),
            self.count(Label::Gated),
            self.count(Label::Limited),
            self.count(Label::Seen),
        );
        for map in &self.machines {
            let _ = writeln!(
                out,
                "{}: {}, {} gated, {} limited, {} seen only",
                map.machine,
                plural(map.entries.len(), "agent", "agents"),
                map.count(Label::Gated),
                map.count(Label::Limited),
                map.count(Label::Seen),
            );
            for entry in &map.entries {
                let _ = writeln!(
                    out,
                    "  {:<8}{}, owner: {}",
                    entry.label.word(),
                    entry.name,
                    entry.owner.as_deref().unwrap_or("none on record"),
                );
            }
        }
        let _ = writeln!(
            out,
            "\nThese are the maps that were imported, each as of when it was made. A machine nobody ran it on is not here."
        );
        out
    }
}

/// Who answers for an agent, as a person wrote it down. A login does not count.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Owner {
    /// The agent's name on the map.
    pub agent: String,
    /// Who answers for it.
    pub owner: String,
    /// Who reviews it when it gets something wrong.
    pub reviewer: String,
}

/// One agent against the owner test: what it can access, which of its actions are
/// irreversible, and who reviews it when it gets something wrong.
#[derive(Debug, Clone, Serialize)]
pub struct OwnerAnswer {
    /// The agent's name.
    pub agent: String,
    /// Where it runs.
    pub place: Place,
    /// Its label.
    pub label: Label,
    /// Who answers for it. `None` unless a person named them.
    pub owner: Option<String>,
    /// What it can reach.
    pub access: Vec<String>,
    /// What can happen that cannot be undone, and what stands in the way.
    pub irreversible: Vec<String>,
    /// Who reviews it. `None` unless a person named them.
    pub reviewer: Option<String>,
    /// True only if a person named both.
    pub passes: bool,
}

/// Answers the owner test for every agent on a map.
pub fn owner_test(map: &Map, owners: &[Owner]) -> Vec<OwnerAnswer> {
    map.entries
        .iter()
        .map(|entry| {
            let named = owners.iter().find(|o| o.agent == entry.name);
            let mut access = Vec::new();
            if entry.controls.keys_out {
                access.push("No credential files found in reach".to_string());
            } else if entry.place == Place::ThisMachine {
                access.extend(
                    map.credential_files
                        .iter()
                        .map(|f| format!("Credential file: ~/{f}")),
                );
            }
            access.extend(
                entry
                    .secret_names
                    .iter()
                    .map(|name| format!("CI secret: {name}")),
            );
            access.push(if entry.controls.network_closed {
                "Network: closed, except what is allowed".to_string()
            } else {
                "Network: open".to_string()
            });
            if entry.add_ons > 0 {
                access.push(format!(
                    "Add-ons: {}, of which {} go through Halda",
                    entry.add_ons, entry.mcp_through_halda
                ));
            }
            let mut irreversible = entry.high_risk.clone();
            irreversible.push(if entry.controls.check_fails_closed {
                "Risky actions stop for a decision, and stop if Halda is down".to_string()
            } else {
                "Nothing stops an irreversible action before it runs".to_string()
            });
            let owner = named.map(|o| o.owner.clone()).filter(|o| !o.is_empty());
            let reviewer = named.map(|o| o.reviewer.clone()).filter(|r| !r.is_empty());
            OwnerAnswer {
                agent: entry.name.clone(),
                place: entry.place,
                label: entry.label,
                passes: owner.is_some() && reviewer.is_some(),
                owner,
                access,
                irreversible,
                reviewer,
            }
        })
        .collect()
}

/// The owner test as text.
pub fn owner_table(answers: &[OwnerAnswer]) -> String {
    use std::fmt::Write;
    let passed = answers.iter().filter(|a| a.passes).count();
    let mut out = format!(
        "Owner test: {passed} of {} agents have a named owner and reviewer.\n",
        answers.len()
    );
    for a in answers {
        let _ = writeln!(
            out,
            "\n{} ({:?}, {}): {}",
            a.agent,
            a.place,
            format!("{:?}", a.label).to_lowercase(),
            if a.passes { "passes" } else { "FAILS" }
        );
        let _ = writeln!(
            out,
            "  Owner: {}",
            a.owner.as_deref().unwrap_or("nobody named")
        );
        let _ = writeln!(out, "  What it can access:");
        for line in &a.access {
            let _ = writeln!(out, "    {line}");
        }
        let _ = writeln!(out, "  What it can do that cannot be undone:");
        for line in &a.irreversible {
            let _ = writeln!(out, "    {line}");
        }
        let _ = writeln!(
            out,
            "  Who reviews it when it gets something wrong: {}",
            a.reviewer.as_deref().unwrap_or("nobody named")
        );
    }
    out
}
