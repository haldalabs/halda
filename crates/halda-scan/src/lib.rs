//! The scanner. Read-only and local: it reads config files and add-on code, and
//! sends nothing anywhere. It never starts an add-on, and secret values it comes
//! across are reported by name only.

pub mod assess;
pub mod browsers;
pub mod catalog;
pub mod connectors;
pub mod discover;
pub mod exposure;
pub mod extensions;
pub mod map;
pub mod replay;
pub mod report;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How serious an item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Present, and nothing wrong found. Inventory, not a finding.
    Info,
    /// Read-only or narrow.
    Low,
    /// Can change or send something.
    Medium,
    /// Can delete, run anything, move money, or leak.
    High,
}

impl Level {
    /// Label for the table.
    pub fn label(self) -> &'static str {
        match self {
            Level::Info => "",
            Level::Low => "LOW",
            Level::Medium => "MED",
            Level::High => "HIGH",
        }
    }
}

/// What kind of thing was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A coding agent installed on this machine.
    Agent,
    /// An MCP server an agent can call.
    Mcp,
    /// A skill or command.
    Skill,
    /// A plugin.
    Plugin,
    /// A hook an agent runs automatically.
    Hook,
    /// An agent installed inside an editor.
    Extension,
    /// AI inside a web browser: an extension, the native program it can start, or a
    /// browser that is an agent itself.
    Browser,
}

/// One thing the scanner found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: Kind,
    /// Where it was configured.
    pub source: String,
    /// Which agent uses it.
    pub agent: String,
    /// What runs, with secrets removed.
    pub command: String,
    /// Plain-English statements of what it can do, most serious first.
    pub findings: Vec<Finding>,
    /// The highest level among its findings.
    pub level: Level,
    /// Hash of its configuration and code, for pinning.
    pub pin: String,
    /// Catalog status, when a catalog was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog: Option<catalog::CatalogStatus>,
    /// Where its code lives, when it is on this machine.
    #[serde(skip)]
    pub code_path: Option<PathBuf>,
}

/// One statement about an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule id.
    pub rule: String,
    /// How serious.
    pub level: Level,
    /// Plain English.
    pub text: String,
}

impl Finding {
    /// Builds a finding.
    pub fn new(rule: &str, level: Level, text: impl Into<String>) -> Self {
        Self {
            rule: rule.to_string(),
            level,
            text: text.into(),
        }
    }
}

/// Everything a scan found.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Report {
    /// Items, most serious first.
    pub items: Vec<Item>,
}

impl Report {
    /// How many items at this level.
    pub fn count(&self, level: Level) -> usize {
        self.items.iter().filter(|i| i.level == level).count()
    }
}

/// Where to look.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Home directory.
    pub home: PathBuf,
    /// Project directory.
    pub project: PathBuf,
    /// PATH to look for agents on.
    pub path: Option<std::ffi::OsString>,
}

impl ScanOptions {
    /// Uses this machine's home, the current directory and PATH.
    pub fn from_env() -> Self {
        Self {
            home: PathBuf::from(std::env::var_os("HOME").unwrap_or_default()),
            project: std::env::current_dir().unwrap_or_default(),
            path: std::env::var_os("PATH"),
        }
    }
}

/// Runs a scan.
pub fn scan(options: &ScanOptions) -> Report {
    let mut items = discover::discover(options);
    for item in &mut items {
        assess::assess(item);
    }
    items.sort_by(|a, b| b.level.cmp(&a.level).then_with(|| a.name.cmp(&b.name)));
    Report { items }
}
