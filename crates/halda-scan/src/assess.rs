//! Works out what an item can do. Code wins over names: if the code is on this
//! machine it is read, so a "notes" plugin that opens sockets says so.

use crate::{Finding, Item, Kind, Level};
use halda_analyze::classify::analyze_shell;
use halda_analyze::memory;
use halda_core::Risk;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::OnceLock;
use walkdir::WalkDir;

const MAX_FILES: usize = 400;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

struct NameRule {
    words: &'static [&'static str],
    rule: &'static str,
    level: Level,
    text: &'static str,
}

const NAME_RULES: &[NameRule] = &[
    NameRule {
        words: &[
            "postgres",
            "mysql",
            "mariadb",
            "sqlite",
            "mongo",
            "redis",
            "supabase",
            "neon",
            "database",
            "bigquery",
            "snowflake",
        ],
        rule: "mcp.database",
        level: Level::High,
        text: "can change data in a database, and may DROP tables",
    },
    NameRule {
        words: &[
            "shell",
            "terminal",
            "bash",
            "exec",
            "desktop-commander",
            "command-runner",
            "ssh",
        ],
        rule: "mcp.shell",
        level: Level::High,
        text: "can run any command",
    },
    NameRule {
        words: &["stripe", "payment", "billing", "paypal", "plaid"],
        rule: "mcp.money",
        level: Level::High,
        text: "can move money",
    },
    NameRule {
        words: &[
            "aws",
            "gcp",
            "azure",
            "kubernetes",
            "k8s",
            "terraform",
            "cloudflare",
            "vercel",
            "heroku",
        ],
        rule: "mcp.cloud",
        level: Level::High,
        text: "can change cloud infrastructure",
    },
    NameRule {
        words: &["github", "gitlab", "bitbucket"],
        rule: "mcp.code",
        level: Level::Medium,
        text: "can change code and repositories",
    },
    NameRule {
        words: &["filesystem", "file-system", "files"],
        rule: "mcp.files",
        level: Level::Medium,
        text: "can read and write files",
    },
    NameRule {
        words: &[
            "slack", "discord", "teams", "gmail", "email", "mail", "sendgrid", "twilio",
        ],
        rule: "mcp.message",
        level: Level::Medium,
        text: "can send messages as you",
    },
    NameRule {
        words: &["browser", "puppeteer", "playwright", "chrome", "selenium"],
        rule: "mcp.browser",
        level: Level::Medium,
        text: "can act in a browser with your logins",
    },
    NameRule {
        words: &[
            "notion",
            "linear",
            "jira",
            "confluence",
            "drive",
            "docs",
            "sheets",
            "calendar",
        ],
        rule: "mcp.workspace",
        level: Level::Medium,
        text: "can read and change company documents",
    },
];

fn code_rules() -> &'static [(Regex, &'static str, Level, &'static str)] {
    static RULES: OnceLock<Vec<(Regex, &'static str, Level, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        [
            (r"\b(child_process|subprocess|os\.system|os\.popen|execSync|spawnSync|Runtime\.getRuntime|ProcessBuilder|std::process::Command|exec\.Command)\b", "code.exec", Level::High, "its code runs other programs"),
            (r"\beval\s*\(|\bnew Function\s*\(", "code.eval", Level::High, "its code runs text as code"),
            (r"\b(rmtree|rimraf|unlinkSync|fs\.rm|os\.remove|remove_dir_all|DROP\s+TABLE|TRUNCATE\s+TABLE)\b", "code.delete", Level::High, "its code deletes files or data"),
            (r"(\.env\b|\.ssh/|\.aws/credentials|id_rsa|keychain|process\.env\[|os\.environ\[)", "code.secrets", Level::High, "its code reads secrets or credentials"),
            (r"\b(requests\.(get|post|put)|urllib|http\.client|axios|node-fetch|\bfetch\s*\(|net\.Socket|socket\.socket|reqwest|ureq::|http\.Post|curl\s)", "code.network", Level::Medium, "its code sends data over the network"),
            (r"(?i)\b(curl|wget)\b[^\n|]{0,200}\|\s*(ba|z|da|k)?sh\b", "code.remote_exec", Level::High, "it runs code downloaded from the internet"),
        ]
        .iter()
        .filter_map(|(p, r, l, t)| Regex::new(p).ok().map(|re| (re, *r, *l, *t)))
        .collect()
    })
}

fn add(item: &mut Item, finding: Finding) {
    if !item.findings.iter().any(|f| f.rule == finding.rule) {
        item.findings.push(finding);
    }
}

pub(crate) fn host_of(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', ':'])
        .next()
        .unwrap_or(url)
}

fn word_in(haystack: &str, word: &str) -> bool {
    haystack.match_indices(word).any(|(i, _)| {
        let before = haystack[..i].chars().last();
        let after = haystack[i + word.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

fn assess_mcp(item: &mut Item) {
    let text = format!("{} {}", item.name, item.command).to_ascii_lowercase();
    let read_only = [
        "read-only",
        "readonly",
        "read_only",
        "reader",
        "--read-only",
    ]
    .iter()
    .any(|w| text.contains(w));
    for rule in NAME_RULES {
        if rule.words.iter().any(|w| word_in(&text, w)) {
            let (level, sentence) = if read_only {
                (Level::Low, "read-only".to_string())
            } else {
                (rule.level, rule.text.to_string())
            };
            add(item, Finding::new(rule.rule, level, sentence));
        }
    }
    if text.contains("http://") && !text.contains("localhost") && !text.contains("127.0.0.1") {
        add(
            item,
            Finding::new(
                "mcp.cleartext",
                Level::High,
                format!("talks to {} without encryption", host_of(&item.command)),
            ),
        );
    } else if text.contains("https://") {
        add(
            item,
            Finding::new(
                "mcp.remote",
                Level::Medium,
                format!(
                    "sends what the agent gives it to {}",
                    host_of(&item.command)
                ),
            ),
        );
    }
    let runner = item.command.split_whitespace().next().unwrap_or("");
    if matches!(runner, "npx" | "uvx" | "bunx" | "pnpx" | "pipx") {
        let unpinned = !item
            .command
            .split_whitespace()
            .skip(1)
            .filter(|w| !w.starts_with('-'))
            .any(|w| {
                w.rsplit_once('@').is_some_and(|(pkg, ver)| {
                    !pkg.is_empty()
                        && ver != "latest"
                        && ver.chars().next().is_some_and(|c| c.is_ascii_digit())
                }) || w.contains("==")
            });
        if unpinned {
            add(item, Finding::new("mcp.unpinned", Level::Medium, "installs its newest version on every start, so a bad release reaches you automatically"));
        }
    }
    if text.contains("filesystem")
        && item
            .command
            .split_whitespace()
            .any(|w| w == "/" || w == "~" || w == "/Users" || w == "/home")
    {
        add(
            item,
            Finding::new(
                "mcp.files_everything",
                Level::High,
                "can read and write every file you can",
            ),
        );
    }
}

fn assess_hook(item: &mut Item) {
    let analysis = analyze_shell(&item.command, "");
    let finding = match analysis.risk {
        Risk::Forbidden => Finding::new(
            "hook.dangerous",
            Level::High,
            format!(
                "runs automatically and {}",
                analysis
                    .signals
                    .first()
                    .map_or("is dangerous", |s| s.detail.as_str())
            ),
        ),
        Risk::Safe => Finding::new("hook.quiet", Level::Low, "runs automatically, read-only"),
        _ if analysis.signals.iter().any(|s| s.code.starts_with("network")) => Finding::new(
            "hook.network",
            Level::High,
            "runs automatically and reaches the network, so it can send data out on every event",
        ),
        _ => Finding::new(
            "hook.runs",
            Level::Medium,
            "runs a command automatically on every matching event",
        ),
    };
    add(item, finding);
}

fn looks_like_text(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "" | "md"
            | "txt"
            | "js"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "py"
            | "sh"
            | "bash"
            | "zsh"
            | "rb"
            | "go"
            | "rs"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
            | "pl"
            | "lua"
            | "php"
    )
}

/// True for text an agent reads as instructions: a skill, a command, an agent
/// definition or a rules file. Not a package's README, changelog or licence.
fn is_agent_instructions(kind: Kind, relative: &Path) -> bool {
    let name = relative
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let stem = name.split('.').next().unwrap_or("");
    if matches!(
        stem,
        "readme"
            | "changelog"
            | "changes"
            | "history"
            | "license"
            | "licence"
            | "contributing"
            | "security"
            | "code_of_conduct"
            | "notice"
            | "authors"
    ) {
        return false;
    }
    if matches!(
        name.as_str(),
        "skill.md" | "agents.md" | "claude.md" | "gemini.md" | "copilot-instructions.md"
    ) {
        return true;
    }
    let in_instruction_folder = relative.parent().is_some_and(|parent| {
        parent.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some("skills" | "commands" | "agents" | "rules" | "prompts")
            )
        })
    });
    in_instruction_folder || matches!(kind, Kind::Skill | Kind::Plugin)
}

fn read_code(item: &mut Item, root: &Path, hasher: &mut Sha256) {
    let mut seen = 0;
    // A published package often ships only its built code, so build output is read
    // unless the sources sit beside it.
    let has_sources = root.join("src").is_dir();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| match e.file_name().to_str() {
            Some("node_modules" | ".git" | "__pycache__" | "target" | ".venv") => false,
            Some("dist" | "build") => !has_sources,
            _ => true,
        });
    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() || !looks_like_text(entry.path()) {
            continue;
        }
        seen += 1;
        if seen > MAX_FILES {
            add(
                item,
                Finding::new(
                    "scan.partial",
                    Level::Medium,
                    format!(
                        "too large to read fully; only the first {MAX_FILES} files were checked"
                    ),
                ),
            );
            break;
        }
        if entry.metadata().map_or(true, |m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        hasher.update(
            entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .as_bytes(),
        );
        hasher.update(text.as_bytes());
        let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());
        let is_doc = entry
            .path()
            .extension()
            .is_some_and(|x| x == "md" || x == "txt");
        // A README tells people how to install it; only text an agent loads is
        // judged as instructions.
        if is_doc && !is_agent_instructions(item.kind, relative) {
            continue;
        }
        for (re, rule, level, sentence) in code_rules() {
            // Instruction files describe commands rather than run them, so only
            // the patterns that matter in prose apply.
            if is_doc && *rule != "code.remote_exec" {
                continue;
            }
            if re.is_match(&text) {
                add(item, Finding::new(rule, *level, *sentence));
            }
        }
        if is_doc {
            // Skills tell agents what to run, so judge the commands they contain.
            for line in text
                .lines()
                .map(str::trim)
                .map(|l| l.trim_start_matches("$ ").trim_matches('`'))
            {
                if !line.starts_with(|c: char| c.is_ascii_lowercase()) {
                    continue;
                }
                let analysis = analyze_shell(line, "");
                if analysis.signals.iter().any(|s| {
                    matches!(
                        s.code.as_str(),
                        "git.force_push"
                            | "terraform.destroy"
                            | "sql.write"
                            | "cloud.write"
                            | "exec.remote_code"
                            | "exfil.secret_to_network"
                            | "host.destroy_home"
                            | "agent.bypass"
                    )
                }) {
                    add(
                        item,
                        Finding::new(
                            "skill.dangerous_command",
                            Level::High,
                            format!(
                                "its instructions tell agents to run: {}",
                                halda_core::redact::redact(line)
                            ),
                        ),
                    );
                    break;
                }
            }
            if let Some(why) = memory::find_injection(&text) {
                // Only an attack in the file's own voice is high. Documentation
                // quotes attacks ("watch for 'ignore previous instructions'"), uses
                // <system> as a placeholder, and ordinary guidance matches other
                // wording ("don't show the user the logo yet"), so those ask for a
                // read. Found by reading the 1,000 most-downloaded MCP servers.
                let certain = memory::is_certain_injection(&text);
                let finding = if certain {
                    Finding::new(
                        "skill.injection",
                        Level::High,
                        format!("its instructions: {why}"),
                    )
                } else {
                    Finding::new(
                        "skill.injection_wording",
                        Level::Medium,
                        format!("its instructions have wording attacks use ({why}); read them before trusting it"),
                    )
                };
                add(item, finding);
            }
        }
        if entry.file_name() == "package.json" {
            if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&text) {
                let scripts = pkg.get("scripts");
                if ["preinstall", "install", "postinstall"]
                    .iter()
                    .any(|k| scripts.and_then(|s| s.get(k)).is_some())
                {
                    add(
                        item,
                        Finding::new(
                            "code.install_script",
                            Level::High,
                            "runs code the moment it is installed",
                        ),
                    );
                }
            }
        }
    }
}

/// Fills in `findings`, `level` and `pin`.
pub fn assess(item: &mut Item) {
    let mut hasher = Sha256::new();
    hasher.update(item.name.as_bytes());
    hasher.update(item.command.as_bytes());
    match item.kind {
        Kind::Agent => add(
            item,
            Finding::new(
                "agent.present",
                Level::Info,
                "runs with your login and keys",
            ),
        ),
        Kind::Mcp => assess_mcp(item),
        Kind::Hook => assess_hook(item),
        Kind::Skill | Kind::Plugin | Kind::Extension | Kind::Browser => {}
    }
    if let Some(path) = item.code_path.clone() {
        read_code(item, &path, &mut hasher);
    }
    if item.findings.is_empty() {
        let text = match item.kind {
            Kind::Skill | Kind::Plugin => "no risky behaviour found in its code",
            _ => "nothing in its name or settings says what it can do",
        };
        let level = if matches!(item.kind, Kind::Skill | Kind::Plugin) {
            Level::Low
        } else {
            Level::Medium
        };
        add(item, Finding::new("scan.nothing", level, text));
    }
    item.findings.sort_by_key(|f| std::cmp::Reverse(f.level));
    item.level = item
        .findings
        .iter()
        .map(|f| f.level)
        .max()
        .unwrap_or(Level::Low);
    item.pin = hex::encode(hasher.finalize());
}
