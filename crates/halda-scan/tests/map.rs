//! Builds fake machines and maps them.

use halda_scan::map::{self, Controls, Fleet, Hook, Label, Map, MapOptions, Place};
use halda_scan::{scan, ScanOptions};
use std::fs;
use std::path::Path;

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, text).expect("write");
}

fn machine() -> (tempfile::TempDir, ScanOptions, MapOptions) {
    let dir = tempfile::tempdir().expect("tmp");
    let scan_options = ScanOptions {
        home: dir.path().join("home"),
        project: dir.path().join("proj"),
        path: None,
    };
    fs::create_dir_all(&scan_options.home).expect("mk");
    fs::create_dir_all(&scan_options.project).expect("mk");
    let options = MapOptions {
        machine: "laptop-1".into(),
        login: "dev".into(),
        claude_can_fail_closed: true,
        app_folders: vec![dir.path().join("Applications")],
    };
    (dir, scan_options, options)
}

fn map_of(scan_options: &ScanOptions, options: &MapOptions) -> Map {
    map::build(&scan(scan_options), scan_options, options)
}

fn entry<'a>(map: &'a Map, name: &str) -> &'a map::Entry {
    map.entries
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("{name} not on the map"))
}

const HALDA_HOOK: &str = r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/bin/halda hook claude-code","onFailure":"block"}]}]}}"#;

#[test]
fn labels_follow_the_controls_and_a_hook_alone_earns_nothing() {
    let controls = |keys_out, network_closed, check_fails_closed| Controls {
        keys_out,
        network_closed,
        check_fails_closed,
    };
    assert_eq!(controls(false, false, false).label(), Label::Seen);
    assert_eq!(controls(false, false, true).label(), Label::Seen);
    assert_eq!(controls(true, false, true).label(), Label::Seen);
    assert_eq!(controls(false, true, true).label(), Label::Seen);
    assert_eq!(controls(true, true, false).label(), Label::Limited);
    assert_eq!(controls(true, true, true).label(), Label::Gated);
}

#[test]
fn an_agent_with_a_fail_closed_hook_and_no_keys_nearby_is_still_only_seen() {
    let (_d, s, o) = machine();
    write(&s.home.join(".claude/settings.json"), HALDA_HOOK);
    let map = map_of(&s, &o);
    let claude = entry(&map, "Claude Code");
    assert_eq!(claude.hook, Hook::FailsClosed);
    assert!(claude.controls.keys_out);
    assert_eq!(claude.label, Label::Seen, "the network is not closed");
    assert!(!claude.confined);
    assert_eq!(claude.owner.as_deref(), Some("dev"));
}

#[test]
fn an_old_claude_code_cannot_fail_closed_whatever_its_settings_say() {
    let (_d, s, mut o) = machine();
    write(&s.home.join(".claude/settings.json"), HALDA_HOOK);
    o.claude_can_fail_closed = false;
    assert_eq!(entry(&map_of(&s, &o), "Claude Code").hook, Hook::FailsOpen);
}

#[test]
fn codex_hooks_always_fail_open() {
    let (_d, s, o) = machine();
    write(
        &s.home.join(".codex/hooks.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"command":"/bin/halda hook codex","onFailure":"block"}]}]}}"#,
    );
    write(
        &s.home.join(".vscode/extensions/openai.chatgpt-1.0.0/x"),
        "",
    );
    assert_eq!(entry(&map_of(&s, &o), "Codex").hook, Hook::FailsOpen);
}

#[test]
fn someone_elses_hook_does_not_count_as_halda() {
    let (_d, s, o) = machine();
    write(
        &s.home.join(".claude/settings.json"),
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"command":"/bin/lint hook x","onFailure":"block"}]}]}}"#,
    );
    write(
        &s.home.join(".claude.json"),
        r#"{"mcpServers":{"a":{"command":"node"}}}"#,
    );
    assert_eq!(entry(&map_of(&s, &o), "Claude Code").hook, Hook::None);
}

#[test]
fn finds_apps_extensions_and_config_without_a_binary() {
    let (d, s, o) = machine();
    write(&d.path().join("Applications/Cursor.app/x"), "");
    write(
        &s.home
            .join(".vscode/extensions/github.copilot-chat-0.1.0/x"),
        "",
    );
    write(
        &s.home.join(".vscode/extensions/github.copilot-1.0.0/x"),
        "",
    );
    write(
        &s.home.join(".vscode/extensions/eamodio.gitlens-1.0.0/x"),
        "",
    );
    write(
        &s.home.join(".claude.json"),
        r#"{"mcpServers":{"a":{"command":"node"}}}"#,
    );
    let map = map_of(&s, &o);
    assert!(entry(&map, "Cursor").found_in[0].ends_with("Cursor.app"));
    assert_eq!(entry(&map, "GitHub Copilot").found_in.len(), 2);
    assert_eq!(entry(&map, "Claude Code").add_ons, 1);
    assert_eq!(map.entries.len(), 3, "gitlens is not an agent");
}

#[test]
fn counts_servers_that_run_through_the_proxy() {
    let (_d, s, o) = machine();
    write(
        &s.home.join(".claude.json"),
        r#"{"mcpServers":{"a":{"command":"halda","args":["mcp-proxy","a","--","node"]},"b":{"command":"node"}}}"#,
    );
    let map = map_of(&s, &o);
    let claude = entry(&map, "Claude Code");
    assert_eq!(claude.add_ons, 2);
    assert_eq!(claude.mcp_through_halda, 1);
}

#[test]
fn credential_files_are_reported_by_name_and_their_contents_never_appear() {
    let (_d, s, o) = machine();
    write(&s.home.join(".aws/credentials"), "VERY-SECRET-VALUE");
    write(
        &s.home.join(".claude.json"),
        r#"{"mcpServers":{"a":{"command":"node"}}}"#,
    );
    let map = map_of(&s, &o);
    assert_eq!(map.credential_files, [".aws/credentials"]);
    assert!(!entry(&map, "Claude Code").controls.keys_out);
    let shown = map::table(&map) + &serde_json::to_string(&map).expect("json");
    assert!(!shown.contains("VERY-SECRET-VALUE"));
}

#[test]
fn agents_in_ci_are_seen_with_no_owner_and_their_secret_names() {
    let (_d, s, o) = machine();
    write(
        &s.project.join(".github/workflows/review.yml"),
        "jobs:\n  r:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          key: ${{ secrets.ANTHROPIC_API_KEY }}\n          other: ${{ secrets.DEPLOY_TOKEN }}\n",
    );
    write(
        &s.project.join(".github/workflows/ci.yml"),
        "jobs:\n  t:\n    steps:\n      - run: make test\n        env:\n          K: ${{ secrets.NOT_FOR_AGENTS }}\n",
    );
    let map = map_of(&s, &o);
    let ci = map
        .entries
        .iter()
        .find(|e| e.place == Place::Ci)
        .expect("CI agent");
    assert_eq!(ci.name, "Claude Code");
    assert_eq!(ci.label, Label::Seen);
    assert_eq!(ci.owner, None);
    assert_eq!(ci.hook, Hook::NotApplicable);
    assert_eq!(ci.secret_names, ["ANTHROPIC_API_KEY", "DEPLOY_TOKEN"]);
    assert_eq!(map.entries.len(), 1);
}

#[test]
fn the_map_says_what_it_cannot_see() {
    let (_d, s, o) = machine();
    let map = map_of(&s, &o);
    let text = map::table(&map);
    assert!(text.contains("0 agents: 0 gated, 0 limited, 0 seen only."));
    assert!(text.contains("No agents found."));
    for place in ["laptops", "Cloud", "Vendor-hosted"] {
        assert!(text.contains(place), "{place}");
    }
}

#[test]
fn the_owner_test_fails_on_a_login_and_passes_only_when_a_person_names_both() {
    let (_d, s, o) = machine();
    write(&s.home.join(".aws/credentials"), "VERY-SECRET-VALUE");
    write(
        &s.home.join(".claude.json"),
        r#"{"mcpServers":{"a":{"command":"node"}}}"#,
    );
    let map = map_of(&s, &o);
    let answers = map::owner_test(&map, &[]);
    assert!(
        !answers[0].passes,
        "the logged-in user is not a named owner"
    );
    assert_eq!(answers[0].owner, None);
    assert!(answers[0]
        .access
        .iter()
        .any(|a| a.contains(".aws/credentials")));
    assert!(answers[0]
        .irreversible
        .iter()
        .any(|a| a.contains("Nothing stops")));

    let half = map::Owner {
        agent: "Claude Code".into(),
        owner: "sam".into(),
        reviewer: String::new(),
    };
    assert!(!map::owner_test(&map, std::slice::from_ref(&half))[0].passes);
    let whole = map::Owner {
        reviewer: "alex".into(),
        ..half
    };
    let passed = map::owner_test(&map, &[whole]);
    assert!(passed[0].passes);
    let shown = map::owner_table(&passed);
    assert!(shown.contains("1 of 1") && !shown.contains("VERY-SECRET-VALUE"));
}

fn on_path(s: &mut ScanOptions, dir: &Path, name: &str, text: &str) {
    write(&dir.join(name), text);
    s.path = Some(dir.as_os_str().to_owned());
}

#[test]
fn a_confined_agent_is_limited_and_a_fail_closed_hook_makes_it_gated() {
    let (d, mut s, o) = machine();
    let shim = format!(
        "#!/bin/sh\n{}\nexec halda run -- /real/claude\n",
        map::CONFINED_MARK
    );
    on_path(&mut s, &d.path().join("bin"), "claude", &shim);
    let map = map_of(&s, &o);
    let claude = entry(&map, "Claude Code");
    assert!(claude.confined);
    assert_eq!(claude.label, Label::Limited);

    write(&s.home.join(".claude/settings.json"), HALDA_HOOK);
    assert_eq!(entry(&map_of(&s, &o), "Claude Code").label, Label::Gated);
}

#[test]
fn only_a_command_made_by_halda_counts_as_confined() {
    let (d, mut s, o) = machine();
    on_path(
        &mut s,
        &d.path().join("bin"),
        "claude",
        "#!/bin/sh\nexec /real/claude\n",
    );
    write(&s.home.join(".claude/settings.json"), HALDA_HOOK);
    let map = map_of(&s, &o);
    assert!(!entry(&map, "Claude Code").confined);
    assert_eq!(entry(&map, "Claude Code").label, Label::Seen);
}

#[test]
fn an_agent_also_installed_as_an_app_is_not_called_confined() {
    let (d, mut s, o) = machine();
    let shim = format!("#!/bin/sh\n{}\n", map::CONFINED_MARK);
    on_path(&mut s, &d.path().join("bin"), "cursor", &shim);
    write(&d.path().join("Applications/Cursor.app/x"), "");
    let cursor = entry(&map_of(&s, &o), "Cursor").clone();
    assert_eq!(cursor.label, Label::Seen);
    assert!(cursor.command_confined, "the command itself is in the wall");
    assert_eq!(
        cursor.outside_wall.len(),
        1,
        "and the app is named as outside"
    );
}

#[test]
fn a_fleet_adds_up_machines_and_a_new_map_replaces_the_old_one() {
    let (_d, s, mut o) = machine();
    write(
        &s.home.join(".claude.json"),
        r#"{"mcpServers":{"a":{"command":"node"}}}"#,
    );
    let mut fleet = Fleet::default();
    fleet.add(map_of(&s, &o));
    o.machine = "laptop-2".into();
    fleet.add(map_of(&s, &o));
    fleet.add(map_of(&s, &o));
    assert_eq!(fleet.machines.len(), 2);
    assert_eq!(fleet.agents(), 2);
    assert_eq!(fleet.count(Label::Seen), 2);
    let text = fleet.table();
    assert!(text.contains("2 agents on 2 machines"), "{text}");
    assert!(
        text.contains("A machine nobody ran it on is not here"),
        "{text}"
    );
}

#[test]
fn a_fleet_folder_names_what_it_could_not_read() {
    let (d, s, o) = machine();
    let folder = d.path().join("fleet");
    write(
        &folder.join("good.json"),
        &serde_json::to_string(&map_of(&s, &o)).expect("json"),
    );
    write(&folder.join("bad.json"), "not a map");
    write(&folder.join("ignored.txt"), "x");
    let (fleet, problems) = Fleet::read(&folder);
    assert_eq!(fleet.machines.len(), 1);
    assert_eq!(problems.len(), 1);
    assert!(problems[0].ends_with("bad.json"));
}
