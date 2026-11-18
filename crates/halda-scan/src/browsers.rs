//! AI inside web browsers. A browser extension runs with every site its person is
//! signed in to: mail, admin consoles, internal tools. An AI one sends what it reads
//! to a model, and a page it reads can steer it. Browser agents go further and click,
//! type and submit as that person. None of this shows up in an agent's config file.
//!
//! Read-only, like the rest of the scan: it reads extension manifests and the files
//! that register native bridges, never history, cookies or saved logins.

use crate::discover::read_json;
use crate::{Finding, Item, Kind, Level};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where Chromium-based browsers keep their profiles, under the home directory.
const BROWSERS: &[(&str, &str)] = &[
    ("Library/Application Support/Google/Chrome", "Chrome"),
    (
        "Library/Application Support/Google/Chrome Beta",
        "Chrome Beta",
    ),
    (
        "Library/Application Support/Google/Chrome Canary",
        "Chrome Canary",
    ),
    ("Library/Application Support/Microsoft Edge", "Edge"),
    (
        "Library/Application Support/BraveSoftware/Brave-Browser",
        "Brave",
    ),
    ("Library/Application Support/Arc/User Data", "Arc"),
    ("Library/Application Support/Chromium", "Chromium"),
    ("Library/Application Support/Vivaldi", "Vivaldi"),
    (
        "Library/Application Support/com.operasoftware.Opera",
        "Opera",
    ),
    (".config/google-chrome", "Chrome"),
    (".config/google-chrome-beta", "Chrome Beta"),
    (".config/chromium", "Chromium"),
    (".config/microsoft-edge", "Edge"),
    (".config/BraveSoftware/Brave-Browser", "Brave"),
    (".config/vivaldi", "Vivaldi"),
];

/// Browser extensions known to be agents, by store id.
const KNOWN_AI: &[(&str, &str)] = &[("fcoeoabgfenejglbffodgkkbkcdhcgfn", "Claude in Chrome")];

/// Words in an extension's name or description that mean it is AI.
const AI_WORDS: &[&str] = &[
    "ai",
    "gpt",
    "chatgpt",
    "openai",
    "claude",
    "anthropic",
    "gemini",
    "copilot",
    "llm",
    "perplexity",
    "deepseek",
    "mistral",
    "grok",
];

/// Model providers. An extension allowed to reach one talks to a model.
const AI_HOSTS: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "claude.ai",
    "generativelanguage.googleapis.com",
    "gemini.google.com",
    "perplexity.ai",
    "mistral.ai",
    "groq.com",
    "openrouter.ai",
    "deepseek.com",
    "x.ai",
    "cohere.ai",
];

/// Host patterns that mean every site.
const EVERY_SITE: &[&str] = &["<all_urls>", "*://*/*", "http://*/*", "https://*/*"];

/// Update addresses of the browsers' own stores, which review what they publish.
const STORE_UPDATES: &[&str] = &[
    "clients2.google.com",
    "edge.microsoft.com",
    "extension-updates.opera.com",
];

/// Browsers whose built-in agent acts on sites as their person, as installed apps.
const AGENTIC_BROWSERS: &[(&str, &str)] = &[
    ("Comet.app", "Comet"),
    ("ChatGPT Atlas.app", "ChatGPT Atlas"),
    ("Dia.app", "Dia"),
];

/// One installed extension: its newest version on disk.
struct Installed {
    id: String,
    version: String,
    folder: PathBuf,
    manifest: Value,
    browser: &'static str,
}

/// The profiles of one browser: the folder itself for Opera, which has no profiles,
/// and each subfolder that holds extensions.
fn profiles(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::iter::once(root.to_path_buf())
        .chain(
            std::fs::read_dir(root)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path()),
        )
        .filter(|p| p.join("Extensions").is_dir())
        .collect();
    found.sort();
    found
}

fn newest_version(dir: &Path) -> Option<(String, PathBuf)> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("manifest.json").is_file())
        .filter_map(|p| {
            let name = p.file_name()?.to_string_lossy().into_owned();
            // Chrome names the folder after the version, with an install count after `_`.
            let version = name.split('_').next().unwrap_or(&name).to_string();
            Some((version, p))
        })
        .max_by_key(|(version, _)| crate::extensions::version_key(version))
}

/// A manifest string, with `__MSG_name__` looked up in the default locale.
fn text(manifest: &Value, folder: &Path, key: &str) -> String {
    let raw = manifest.get(key).and_then(Value::as_str).unwrap_or("");
    let Some(message) = raw
        .strip_prefix("__MSG_")
        .and_then(|r| r.strip_suffix("__"))
    else {
        return raw.to_string();
    };
    let locale = manifest
        .get("default_locale")
        .and_then(Value::as_str)
        .unwrap_or("en");
    read_json(&folder.join("_locales").join(locale).join("messages.json"))
        .and_then(|messages| {
            messages.as_object().and_then(|m| {
                m.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(message))
                    .and_then(|(_, v)| v.get("message").and_then(Value::as_str))
                    .map(str::to_string)
            })
        })
        .unwrap_or_default()
}

fn strings(manifest: &Value, key: &str) -> Vec<String> {
    manifest
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

/// Every site pattern it may read or run on.
fn hosts(manifest: &Value) -> Vec<String> {
    let mut all = strings(manifest, "host_permissions");
    // Manifest version 2 mixes sites into `permissions`.
    all.extend(
        strings(manifest, "permissions")
            .into_iter()
            .filter(|p| p.contains("://") || p == "<all_urls>"),
    );
    for script in manifest
        .get("content_scripts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        all.extend(strings(script, "matches"));
    }
    all.sort();
    all.dedup();
    all
}

fn has_word(text: &str, word: &str) -> bool {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| w == word)
}

fn installed(home: &Path) -> Vec<Installed> {
    let mut out = Vec::new();
    for (dir, browser) in BROWSERS {
        for profile in profiles(&home.join(dir)) {
            for entry in std::fs::read_dir(profile.join("Extensions"))
                .into_iter()
                .flatten()
                .flatten()
            {
                let id = entry.file_name().to_string_lossy().into_owned();
                let Some((version, folder)) = newest_version(&entry.path()) else {
                    continue;
                };
                let Some(manifest) = read_json(&folder.join("manifest.json")) else {
                    continue;
                };
                out.push(Installed {
                    id,
                    version,
                    folder,
                    manifest,
                    browser,
                });
            }
        }
    }
    out
}

/// The agent an extension is, if it is AI at all.
fn ai_name(ext: &Installed) -> Option<String> {
    if let Some((_, name)) = KNOWN_AI.iter().find(|(id, _)| *id == ext.id) {
        return Some((*name).to_string());
    }
    let name = text(&ext.manifest, &ext.folder, "name");
    let about = format!("{name} {}", text(&ext.manifest, &ext.folder, "description"));
    let by_words = AI_WORDS.iter().any(|w| has_word(&about, w));
    let by_hosts = hosts(&ext.manifest)
        .iter()
        .any(|h| AI_HOSTS.iter().any(|ai| h.contains(ai)));
    (by_words || by_hosts).then(|| {
        if name.is_empty() {
            ext.id.clone()
        } else {
            name
        }
    })
}

/// One native bridge: a program on this machine that extensions may start.
struct Bridge {
    name: String,
    path: String,
    origins: Vec<String>,
    source: PathBuf,
}

fn bridges(home: &Path) -> Vec<Bridge> {
    let mut out = Vec::new();
    for (dir, _) in BROWSERS {
        for entry in std::fs::read_dir(home.join(dir).join("NativeMessagingHosts"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let source = entry.path();
            let Some(root) = read_json(&source) else {
                continue;
            };
            let field = |k: &str| {
                root.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            out.push(Bridge {
                name: field("name"),
                path: field("path"),
                origins: strings(&root, "allowed_origins"),
                source,
            });
        }
    }
    out
}

fn finding(rule: &str, level: Level, text: impl Into<String>) -> Finding {
    Finding::new(rule, level, text)
}

/// AI extensions in every browser profile, the native programs they can start, and
/// browsers that are agents themselves.
pub(crate) fn browser_ai(home: &Path, app_folders: &[PathBuf], out: &mut Vec<Item>) {
    let all_bridges = bridges(home);
    // Which AI extension each id is, for naming the bridges that serve it.
    let mut ai_ids: BTreeMap<String, String> = BTreeMap::new();
    for ext in installed(home) {
        let Some(agent) = ai_name(&ext) else {
            continue;
        };
        ai_ids.insert(ext.id.clone(), agent.clone());
        let permissions = strings(&ext.manifest, "permissions");
        let has = |p: &str| permissions.iter().any(|x| x == p);
        let site_patterns = hosts(&ext.manifest);
        let mut findings = vec![finding(
            "browser.ai_extension",
            Level::Info,
            format!(
                "runs inside {} with every site you are signed in to",
                ext.browser
            ),
        )];
        if site_patterns
            .iter()
            .any(|h| EVERY_SITE.contains(&h.as_str()))
        {
            findings.push(finding(
                "browser.every_site",
                Level::High,
                "can read and change every page you open, with your logins: mail, admin consoles, internal tools. Any page it reads can carry instructions for it",
            ));
        }
        if has("debugger") {
            findings.push(finding(
                "browser.drives_browser",
                Level::High,
                "can drive the browser itself: click, type and submit on any site as you",
            ));
        }
        if has("cookies") {
            findings.push(finding(
                "browser.cookies",
                Level::High,
                "can read the cookies that keep you signed in, which are enough to sign in as you elsewhere",
            ));
        }
        if has("clipboardRead") {
            findings.push(finding(
                "browser.clipboard",
                Level::Medium,
                "can read your clipboard, where passwords and keys often pass through",
            ));
        }
        if has("nativeMessaging") {
            let origin = format!("chrome-extension://{}/", ext.id);
            let mut programs: Vec<&str> = all_bridges
                .iter()
                .filter(|b| b.origins.contains(&origin))
                .map(|b| b.path.as_str())
                .collect();
            // Every browser registers its own copy of the same bridge.
            programs.sort_unstable();
            programs.dedup();
            findings.push(finding(
                "browser.native",
                Level::Medium,
                if programs.is_empty() {
                    "can talk to programs on this machine, outside the browser's sandbox"
                        .to_string()
                } else {
                    format!(
                        "can start {} on this machine, outside the browser's sandbox",
                        programs.join(" and ")
                    )
                },
            ));
        }
        let update = ext
            .manifest
            .get("update_url")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !STORE_UPDATES.iter().any(|store| update.contains(store)) {
            findings.push(finding(
                "browser.off_store",
                Level::Medium,
                if update.is_empty() {
                    "did not come from a browser store, so no store reviewed it".to_string()
                } else {
                    format!(
                        "updates from {}, outside the browser stores' review",
                        crate::assess::host_of(update)
                    )
                },
            ));
        }
        let ai_hosts: Vec<&str> = AI_HOSTS
            .iter()
            .copied()
            .filter(|ai| site_patterns.iter().any(|h| h.contains(ai)))
            .collect();
        if !ai_hosts.is_empty() && !findings.iter().any(|f| f.rule == "browser.every_site") {
            findings.push(finding(
                "browser.model",
                Level::Medium,
                format!("sends what it reads to a model at {}", ai_hosts.join(", ")),
            ));
        }
        out.push(Item {
            name: if agent.ends_with(&format!(" in {}", ext.browser)) {
                agent.clone()
            } else {
                format!("{agent} in {}", ext.browser)
            },
            kind: Kind::Browser,
            source: ext.folder.display().to_string(),
            agent,
            command: format!("{}@{}", ext.id, ext.version),
            findings,
            level: Level::Low,
            pin: String::new(),
            catalog: None,
            code_path: None,
        });
    }

    // Bridges that an AI extension can use. Others, such as a password manager's,
    // are not agents and stay out of this report.
    let mut seen = std::collections::HashSet::new();
    for bridge in &all_bridges {
        let served: Vec<&String> = ai_ids
            .iter()
            .filter(|(id, _)| {
                bridge
                    .origins
                    .contains(&format!("chrome-extension://{id}/"))
            })
            .map(|(_, name)| name)
            .collect();
        let named_ai = AI_WORDS
            .iter()
            .any(|w| has_word(&bridge.name.replace('_', " "), w));
        if (served.is_empty() && !named_ai)
            || !seen.insert((bridge.name.clone(), bridge.path.clone()))
        {
            continue;
        }
        let agent = served
            .first()
            .map_or_else(|| bridge.name.clone(), |s| (*s).clone());
        let mut findings = vec![finding(
            "browser.bridge",
            Level::Medium,
            format!(
                "lets {} start {} on this machine, with your full access and outside the browser's sandbox",
                if served.is_empty() {
                    "a browser extension".to_string()
                } else {
                    served
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(" and ")
                },
                bridge.path
            ),
        )];
        if !bridge.path.is_empty() && !Path::new(&bridge.path).exists() {
            findings.push(finding(
                "browser.bridge_missing",
                Level::High,
                format!(
                    "points at {}, which does not exist. Whoever creates it is run when the extension calls",
                    bridge.path
                ),
            ));
        }
        out.push(Item {
            name: format!("bridge {}", bridge.name),
            kind: Kind::Browser,
            source: bridge.source.display().to_string(),
            agent,
            command: bridge.path.clone(),
            findings,
            level: Level::Low,
            pin: String::new(),
            catalog: None,
            code_path: None,
        });
    }

    for folder in app_folders {
        for (app, name) in AGENTIC_BROWSERS {
            let path = folder.join(app);
            if !path.exists() {
                continue;
            }
            out.push(Item {
                name: (*name).to_string(),
                kind: Kind::Browser,
                source: path.display().to_string(),
                agent: (*name).to_string(),
                command: (*app).to_string(),
                findings: vec![finding(
                    "browser.agentic",
                    Level::High,
                    "a browser with an agent built in: it reads pages and acts on any site you are signed in to, so a page can steer it into your mail, bank or admin consoles",
                )],
                level: Level::Low,
                pin: String::new(),
                catalog: None,
                code_path: None,
            });
        }
    }
}
