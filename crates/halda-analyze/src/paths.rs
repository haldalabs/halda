//! Paths that matter: secrets, and the files that control Halda itself.

use regex::Regex;
use std::sync::OnceLock;

fn sensitive_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?ix)(^|[/\s=@'\x22])(
                \.env(\.[a-z0-9_-]+)?
              | \.aws/(credentials|config)
              | \.ssh/[^\s]*
              | id_(rsa|dsa|ecdsa|ed25519)(\.[a-z]+)?
              | \.netrc | \.pgpass | \.npmrc | \.pypirc | \.git-credentials | \.vault-token
              | \.kube/config | \.docker/config\.json | \.gnupg/[^\s]*
              | [^\s/'\x22]+\.(pem|p12|pfx|key|keystore|tfvars)
              | credentials(\.json)? | secrets?\.(ya?ml|json|toml|txt)
              | service[-_]account[^\s/]*\.json
              | terraform\.tfstate(\.backup)?
            )($|[\s'\x22;|&)])",
        )
        .expect("valid sensitive path pattern")
    })
}

fn harmless_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\.env\.(example|sample|template|dist|defaults?)\b|[^\s/'\x22]*\.pub\b|[^\s/'\x22]*(cert|cacert|ca-bundle|fullchain|chain|ca-certificates)[^\s/'\x22]*\.pem\b")
            .expect("valid harmless path pattern")
    })
}

fn control_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(^|[/\s=@'\x22~])(
                \.halda(/|$|[\s'\x22])
              | \.claude/settings(\.local)?\.json
              | \.claude/hooks
              | \.cursor/hooks(\.json)?
              | \.codex/config\.toml
              | haldad(\b|$)
            )"
            .replace(['\n', ' '], "")
            .as_str(),
        )
        .expect("valid control path pattern")
    })
}

fn agent_config_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(^|[/\s=@'\x22~])(
                \.mcp\.json
              | \.claude/(settings|hooks|plugins|commands|agents|skills)
              | \.claude\.json
              | \.cursor/
              | \.cursorignore
              | \.vscode/(settings|tasks|mcp|launch)\.json
              | \.gemini/
              | \.codex/
              | \.windsurf/
              | \.codeium/
              | \.git/(config|hooks)
              | \.gitconfig($|[\s'\x22])
              | \.gitattributes($|[\s'\x22])
              | \.gitmodules($|[\s'\x22])
              | \.husky/
              | \.pre-commit-config\.ya?ml
              | \.envrc($|[\s'\x22])
              | \.github/(copilot-instructions|instructions|hooks)
              | \.(bash|zsh|profile|bash_profile|zprofile|zshenv|zlogin)rc?($|[\s'\x22])
              | \.profile($|[\s'\x22])
              | \.ssh/(authorized_keys|config)
            )"
            .replace(['\n', ' '], "")
            .as_str(),
        )
        .expect("valid agent config pattern")
    })
}

/// True if changing `text` would change how an agent or git behaves: where
/// approvals get switched off and where code gets run automatically. Agents have
/// used each of these to escalate, so an agent may read them but not write them.
pub fn is_agent_config(text: &str) -> bool {
    agent_config_re().is_match(text)
}

fn is_harmless(text: &str) -> bool {
    // Only exempt when nothing sensitive remains once the harmless names are gone.
    let stripped = harmless_re().replace_all(text, "");
    !sensitive_re().is_match(&stripped)
}

/// True if `text` names a file that holds secrets.
pub fn is_sensitive(text: &str) -> bool {
    sensitive_re().is_match(text) && !is_harmless(text)
}

/// True if `text` names a file or process that controls Halda or an agent's hooks.
pub fn is_control_path(text: &str) -> bool {
    control_re().is_match(text)
}

/// Temporary directories: scratch space, nothing anyone needs back.
fn is_scratch(path: &str) -> bool {
    [
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/var/folders/",
        "/private/var/folders/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}

/// True if `path` stays inside `cwd` or a temporary directory. Relative paths are
/// judged by their `..` components; absolute paths must start with `cwd`.
pub fn inside_workspace(path: &str, cwd: &str) -> bool {
    let absolute = path.starts_with('/') || path.starts_with('~');
    if absolute && is_scratch(path) && !path.split('/').any(|c| c == "..") {
        return true;
    }
    if absolute {
        return !cwd.is_empty()
            && (path == cwd || path.starts_with(&format!("{}/", cwd.trim_end_matches('/'))))
            && !path.split('/').any(|c| c == "..");
    }
    let mut depth = 0i32;
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    true
}

/// True if a `rm`-style target would wipe a whole machine or home directory.
pub fn is_catastrophic_target(path: &str) -> bool {
    let p = path.trim_end_matches('*').trim_end_matches('/');
    matches!(
        p,
        "" | "~"
            | "$HOME"
            | "${HOME}"
            | "/etc"
            | "/usr"
            | "/var"
            | "/bin"
            | "/sbin"
            | "/lib"
            | "/opt"
            | "/home"
            | "/Users"
            | "/System"
            | "/Library"
            | "/Applications"
            | "/boot"
            | "/root"
    ) || path == "/*"
        || path == "/"
        || (p.starts_with("/Users/") || p.starts_with("/home/")) && p.matches('/').count() == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_secret_files() {
        for p in [
            ".env",
            "./.env",
            "app/.env.production",
            "~/.ssh/id_rsa",
            "/home/a/.aws/credentials",
            "prod.pem",
            "config/secrets.yaml",
            ".git-credentials",
            "terraform.tfstate",
        ] {
            assert!(is_sensitive(p), "{p} should be sensitive");
        }
    }

    #[test]
    fn does_not_flag_ordinary_or_template_files() {
        for p in [
            ".env.example",
            "src/env.rs",
            "README.md",
            "id_rsa.pub",
            "environment.ts",
            "credentials_test.rs",
            "docs/keys.md",
        ] {
            assert!(!is_sensitive(p), "{p} should not be sensitive");
        }
    }

    #[test]
    fn recognizes_control_paths() {
        for p in [
            "~/.halda/keys/receipt",
            ".claude/settings.json",
            "/x/.claude/settings.local.json",
            "~/.cursor/hooks.json",
        ] {
            assert!(is_control_path(p), "{p} should be control");
        }
        assert!(!is_control_path("src/halda.rs"));
        assert!(!is_control_path(".claude/agents/x.md"));
    }

    #[test]
    fn recognizes_agent_config_that_changes_behaviour() {
        for p in [
            ".mcp.json",
            ".vscode/settings.json",
            ".vscode/tasks.json",
            ".cursor/mcp.json",
            ".gemini/settings.json",
            ".codex/config.toml",
            ".git/config",
            ".git/hooks/pre-commit",
            "~/.gitconfig",
            ".claude/settings.json",
            ".claude/commands/x.md",
            "~/.claude.json",
            ".husky/pre-push",
            ".envrc",
            "~/.zshrc",
            "~/.ssh/authorized_keys",
            ".github/copilot-instructions.md",
        ] {
            assert!(is_agent_config(p), "{p}");
        }
        for p in [
            "/w/.claude/worktrees/agent-1/src/main.rs",
            ".claude/projects/x/session.jsonl",
            "src/main.rs",
            ".vscode/extensions.json",
            "docs/.gitconfig.md",
            "git/config.rs",
            "README.md",
        ] {
            assert!(!is_agent_config(p), "{p}");
        }
    }

    #[test]
    fn workspace_containment() {
        assert!(inside_workspace("a/b", "/w"));
        assert!(inside_workspace("a/../b", "/w"));
        assert!(!inside_workspace("../b", "/w"));
        assert!(!inside_workspace("a/../../b", "/w"));
        assert!(inside_workspace("/w/a", "/w"));
        assert!(!inside_workspace("/w2/a", "/w"));
        assert!(!inside_workspace("/w/../x", "/w"));
        assert!(!inside_workspace("~/x", "/w"));
        assert!(inside_workspace("/tmp/scratch/a.py", "/w"));
        assert!(inside_workspace("/private/tmp/s/a.py", "/w"));
        assert!(!inside_workspace("/tmp/../etc/hosts", "/w"));
    }

    #[test]
    fn catastrophic_targets() {
        for p in [
            "/",
            "/*",
            "~",
            "~/",
            "$HOME",
            "/etc",
            "/Users/jordan",
            "/home/jordan/",
        ] {
            assert!(is_catastrophic_target(p), "{p}");
        }
        for p in ["build", "./target", "/Users/jordan/project", "/tmp/x"] {
            assert!(!is_catastrophic_target(p), "{p}");
        }
    }
}
