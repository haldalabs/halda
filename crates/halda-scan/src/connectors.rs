//! Read-only connections that add agents this machine cannot see. Each takes a function
//! that fetches a URL, so it can be tested without the real service.
//!
//! Nothing here changes anything at the service, and only names, scopes and workflow
//! text are read. Tokens stay with the caller.

use crate::map::{Controls, Entry, Hook, Place, CI_AGENTS};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Fetches a URL as JSON. Errors are plain words, and never contain the token.
pub type Fetch<'a> = &'a (dyn Fn(&str) -> Result<Value, String> + Sync);

/// Stops a very large account from running forever. Reaching it is reported.
const MAX_PAGES: usize = 20;
/// Repositories read at once.
const WORKERS: usize = 8;

/// What a connection found, and what it could not read.
#[derive(Debug, Clone, Default)]
pub struct Found {
    /// The agents.
    pub entries: Vec<Entry>,
    /// Plain statements of what is missing from this result.
    pub gaps: Vec<String>,
}

fn entry(name: String, place: Place) -> Entry {
    let controls = Controls::default();
    Entry {
        name,
        place,
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
}

/// Agents in the GitHub Actions workflows of an owner's repositories.
pub fn github_workflows(api: &str, owner: &str, fetch: Fetch<'_>) -> Found {
    let mut found = Found::default();
    let mut repos = Vec::new();
    let mut reached_the_end = false;
    for page in 1..=MAX_PAGES {
        let url = format!("{api}/users/{owner}/repos?per_page=100&page={page}&type=owner");
        match fetch(&url) {
            Ok(Value::Array(list)) => {
                let last = list.len() < 100;
                // A fork's workflows are usually someone else's, and an archived
                // repository runs nothing.
                repos.extend(
                    list.iter()
                        .filter(|r| {
                            r.get("fork").and_then(Value::as_bool) != Some(true)
                                && r.get("archived").and_then(Value::as_bool) != Some(true)
                        })
                        .filter_map(|r| r.get("name")?.as_str().map(str::to_string)),
                );
                if last {
                    reached_the_end = true;
                    break;
                }
            }
            Ok(_) | Err(_) => {
                found
                    .gaps
                    .push(format!("Could not list every repository of {owner}."));
                reached_the_end = true;
                break;
            }
        }
    }
    if !reached_the_end {
        found.gaps.push(format!(
            "Stopped at {} repositories of {owner}.",
            repos.len()
        ));
    }
    let next = AtomicUsize::new(0);
    let collected = Mutex::new((BTreeMap::new(), 0_usize));
    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            scope.spawn(|| {
                while let Some(repo) = repos.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let (found, unread) = scan_repo(api, owner, repo, fetch);
                    if let Ok(mut all) = collected.lock() {
                        all.0.extend(found);
                        all.1 += unread;
                    }
                }
            });
        }
    });
    let (by_repo_agent, unread): (BTreeMap<(String, String), Entry>, usize) =
        collected.into_inner().unwrap_or_default();
    if unread > 0 {
        found
            .gaps
            .push(format!("{unread} workflow files could not be read."));
    }
    found.entries = by_repo_agent.into_values().collect();
    found
}

fn scan_repo(
    api: &str,
    owner: &str,
    repo: &str,
    fetch: Fetch<'_>,
) -> (BTreeMap<(String, String), Entry>, usize) {
    let mut by_repo_agent = BTreeMap::new();
    let mut unread = 0;
    // No workflows folder comes back as an error too, so that is not a gap.
    let Ok(Value::Array(listing)) = fetch(&format!(
        "{api}/repos/{owner}/{repo}/contents/.github/workflows"
    )) else {
        return (by_repo_agent, unread);
    };
    for file in listing {
        let Some(name) = file.get("name").and_then(Value::as_str) else {
            continue;
        };
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        let path = format!("{api}/repos/{owner}/{repo}/contents/.github/workflows/{name}");
        let Some(text) = fetch(&path).ok().and_then(|v| decoded_content(&v)) else {
            unread += 1;
            continue;
        };
        for (marker, agent) in CI_AGENTS {
            if !text.contains(marker) {
                continue;
            }
            let item: &mut Entry = by_repo_agent
                .entry((repo.to_string(), (*agent).to_string()))
                .or_insert_with(|| entry(format!("{agent} in {owner}/{repo}"), Place::Ci));
            let shown = format!("{owner}/{repo}/.github/workflows/{name}");
            if !item.found_in.contains(&shown) {
                item.found_in.push(shown);
            }
            item.secret_names.extend(crate::map::secret_names(&text));
            item.secret_names.sort();
            item.secret_names.dedup();
        }
    }
    (by_repo_agent, unread)
}

/// GitHub returns file contents as base64 with line breaks.
fn decoded_content(value: &Value) -> Option<String> {
    let text: String = value
        .get("content")?
        .as_str()?
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut bytes = Vec::with_capacity(text.len() / 4 * 3);
    let mut buffer = 0_u32;
    let mut bits = 0;
    for c in text.chars().filter(|c| *c != '=') {
        let digit = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Names that mark a Microsoft 365 app as an AI agent or assistant. Found by name, so
/// one that is not listed will not appear.
const MICROSOFT_AGENT_NAMES: &[&str] = &[
    "copilot",
    "chatgpt",
    "openai",
    "claude",
    "anthropic",
    "gemini",
    "cursor",
    "glean",
    "notion ai",
    "perplexity",
    "otter",
    "fireflies",
    "agent",
];

/// Permissions that let an app read or change a lot, in plain words.
const MICROSOFT_WIDE_SCOPES: &[(&str, &str)] = &[
    ("mail.read", "can read mail"),
    ("mail.readwrite", "can read and change mail"),
    ("mail.send", "can send mail as someone"),
    ("files.read.all", "can read every file the user can"),
    ("files.readwrite.all", "can change every file the user can"),
    ("sites.read.all", "can read every SharePoint site"),
    ("sites.readwrite.all", "can change every SharePoint site"),
    ("calendars.readwrite", "can change calendars"),
    ("chat.read", "can read Teams chats"),
    ("directory.read.all", "can read the whole directory"),
    ("directory.readwrite.all", "can change the directory"),
    ("user.readwrite.all", "can change every user"),
];

fn all_pages(start: &str, base: &str, fetch: Fetch<'_>) -> Result<(Vec<Value>, bool), String> {
    let mut items = Vec::new();
    let mut next = start.to_string();
    for _ in 0..MAX_PAGES {
        let page = fetch(&next)?;
        if let Some(values) = page.get("value").and_then(Value::as_array) {
            items.extend(values.iter().cloned());
        }
        match page.get("@odata.nextLink").and_then(Value::as_str) {
            // The token must not follow a link to anywhere else.
            Some(link) if link.starts_with(base) => next = link.to_string(),
            Some(_) => return Err("the next page pointed at another host".to_string()),
            None => return Ok((items, true)),
        }
    }
    Ok((items, false))
}

/// AI apps someone has granted access to in a Microsoft 365 tenant, from Microsoft
/// Graph. Needs `Application.Read.All` and `DelegatedPermissionGrant.Read.All`, which
/// can only read. These agents run at their vendor, so most can only ever be Seen.
pub fn microsoft_grants(graph: &str, fetch: Fetch<'_>) -> Found {
    let mut found = Found::default();
    let principals = format!(
        "{graph}/v1.0/servicePrincipals?$select=id,displayName,appOwnerOrganizationId&$top=999"
    );
    let (apps, complete) = match all_pages(&principals, graph, fetch) {
        Ok(result) => result,
        Err(error) => {
            found
                .gaps
                .push(format!("Could not read Microsoft apps: {error}."));
            return found;
        }
    };
    if !complete {
        found
            .gaps
            .push("Stopped before reading every Microsoft app.".to_string());
    }
    let grants_url = format!("{graph}/v1.0/oauth2PermissionGrants?$top=999");
    let grants = match all_pages(&grants_url, graph, fetch) {
        Ok((grants, complete)) => {
            if !complete {
                found
                    .gaps
                    .push("Stopped before reading every Microsoft grant.".to_string());
            }
            grants
        }
        Err(error) => {
            found
                .gaps
                .push(format!("Could not read Microsoft grants: {error}."));
            Vec::new()
        }
    };
    for app in &apps {
        let (Some(id), Some(name)) = (
            app.get("id").and_then(Value::as_str),
            app.get("displayName").and_then(Value::as_str),
        ) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if !MICROSOFT_AGENT_NAMES
            .iter()
            .any(|known| lower.contains(known))
        {
            continue;
        }
        let mine: Vec<&Value> = grants
            .iter()
            .filter(|g| g.get("clientId").and_then(Value::as_str) == Some(id))
            .collect();
        let mut item = entry(name.to_string(), Place::Hosted);
        item.found_in.push("Microsoft 365 tenant".to_string());
        for grant in &mine {
            let everyone =
                grant.get("consentType").and_then(Value::as_str) == Some("AllPrincipals");
            for scope in grant
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or("")
                .split_whitespace()
            {
                let scope = scope.to_ascii_lowercase();
                if let Some((_, words)) = MICROSOFT_WIDE_SCOPES.iter().find(|(s, _)| *s == scope) {
                    let who = if everyone {
                        "for everyone"
                    } else {
                        "for some users"
                    };
                    item.high_risk.push(format!("{words}, {who}"));
                }
            }
        }
        item.high_risk.sort();
        item.high_risk.dedup();
        found.entries.push(item);
    }
    found.entries.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base64(text: &str) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in text.as_bytes().chunks(3) {
            let n = chunk
                .iter()
                .fold(0_u32, |acc, b| (acc << 8) | u32::from(*b))
                << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
        out
    }

    fn fake(routes: Vec<(&'static str, Value)>) -> impl Fn(&str) -> Result<Value, String> + Sync {
        move |url: &str| {
            routes
                .iter()
                .find(|(path, _)| url.ends_with(path) || url.contains(&format!("{path}?")))
                .map(|(_, value)| value.clone())
                .ok_or_else(|| "not found".to_string())
        }
    }

    #[test]
    fn workflows_with_agents_are_found_with_their_secret_names() {
        let workflow = "steps:\n  - uses: anthropics/claude-code-action@v1\n    with:\n      k: ${{ secrets.ANTHROPIC_API_KEY }}\n      d: ${{ secrets.DEPLOY_KEY }}\n";
        let fetch = fake(vec![
            (
                "/users/acme/repos",
                json!([{"name": "api"}, {"name": "web"}]),
            ),
            (
                "/repos/acme/api/contents/.github/workflows",
                json!([{"name": "review.yml"}, {"name": "README.md"}]),
            ),
            (
                "/repos/acme/api/contents/.github/workflows/review.yml",
                json!({"content": base64(workflow)}),
            ),
        ]);
        let found = github_workflows("https://api.test", "acme", &fetch);
        assert_eq!(found.entries.len(), 1);
        let agent = &found.entries[0];
        assert_eq!(agent.name, "Claude Code in acme/api");
        assert_eq!(agent.owner, None);
        assert_eq!(agent.secret_names, ["ANTHROPIC_API_KEY", "DEPLOY_KEY"]);
        assert!(found.gaps.is_empty());
    }

    #[test]
    fn an_owner_it_cannot_list_is_a_stated_gap_not_an_empty_result() {
        let fetch = fake(vec![]);
        let found = github_workflows("https://api.test", "acme", &fetch);
        assert!(found.entries.is_empty());
        assert!(found.gaps[0].contains("Could not list"));
    }

    #[test]
    fn microsoft_ai_apps_appear_with_what_they_can_do() {
        let fetch = fake(vec![
            (
                "/v1.0/servicePrincipals",
                json!({"value": [
                    {"id": "1", "displayName": "ChatGPT Connector"},
                    {"id": "2", "displayName": "Payroll"},
                    {"id": "3", "displayName": "Microsoft 365 Copilot"},
                ]}),
            ),
            (
                "/v1.0/oauth2PermissionGrants",
                json!({"value": [
                    {"clientId": "1", "consentType": "AllPrincipals", "scope": "openid Files.Read.All Mail.Send"},
                    {"clientId": "2", "consentType": "AllPrincipals", "scope": "Directory.ReadWrite.All"},
                    {"clientId": "3", "consentType": "Principal", "scope": "User.Read"},
                ]}),
            ),
        ]);
        let found = microsoft_grants("https://graph.test", &fetch);
        let names: Vec<&str> = found.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["ChatGPT Connector", "Microsoft 365 Copilot"]);
        let chatgpt = &found.entries[0];
        assert_eq!(chatgpt.place, Place::Hosted);
        assert_eq!(chatgpt.high_risk.len(), 2);
        assert!(chatgpt
            .high_risk
            .iter()
            .any(|r| r.contains("send mail") && r.contains("everyone")));
        assert!(found.entries[1].high_risk.is_empty());
    }

    #[test]
    fn the_token_never_follows_a_link_to_another_host() {
        let seen = Mutex::new(Vec::new());
        let fetch = |url: &str| {
            seen.lock().expect("lock").push(url.to_string());
            Ok(json!({"value": [], "@odata.nextLink": "https://evil.test/next"}))
        };
        let found = microsoft_grants("https://graph.test", &fetch);
        assert_eq!(
            seen.lock().expect("lock").len(),
            1,
            "the other host was never asked"
        );
        assert!(found.gaps[0].contains("another host"));
    }

    #[test]
    fn a_service_it_cannot_reach_is_a_stated_gap() {
        let fetch = |_: &str| Err("401".to_string());
        let found = microsoft_grants("https://graph.test", &fetch);
        assert!(found.entries.is_empty());
        assert!(found.gaps[0].contains("Could not read Microsoft apps"));
    }

    #[test]
    fn content_decodes_with_line_breaks() {
        let value = json!({"content": format!("{}\n", base64("hello there"))});
        assert_eq!(decoded_content(&value).as_deref(), Some("hello there"));
    }
}
