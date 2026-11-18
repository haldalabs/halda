//! Renders a report as a table, SARIF, or JSON.

use crate::{Level, Report};
use serde_json::{json, Value};

/// Shows a path under the home folder as `~/...`, so a shared screenshot does not
/// carry the user's name.
fn shorten_home(path: &str) -> String {
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() && path.starts_with(&home) => {
            format!("~{}", &path[home.len()..])
        }
        _ => path.to_string(),
    }
}

/// The terminal report: findings first, each with where it came from and what to do,
/// then what was merely present. Severity is only ever given to evidence of a problem.
pub fn table(report: &Report, colour: bool) -> String {
    let paint = |code: &str, text: &str| -> String {
        if colour {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    };
    let tone = |level: Level| match level {
        Level::High => "1;31",
        Level::Medium => "33",
        _ => "2",
    };
    if report.items.is_empty() {
        return "No agents or add-ons found.\n".to_string();
    }
    let mut out = String::from("Read local config only. Started nothing, sent nothing.\n");
    let findings: Vec<&crate::Item> = report
        .items
        .iter()
        .filter(|i| i.level > Level::Info)
        .collect();
    for item in &findings {
        out.push_str(&format!(
            "\n{}  {}",
            paint(tone(item.level), &format!("{:<4}", item.level.label())),
            paint("1", &item.name)
        ));
        out.push_str(&paint(
            "2",
            &format!("  {} · {}", kind_name(item.kind), item.agent),
        ));
        if let Some(status) = item.catalog {
            out.push_str(&format!(
                "  [{}]",
                serde_json::to_value(status)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default()
            ));
        }
        out.push('\n');
        for finding in &item.findings {
            out.push_str(&format!("      {}\n", finding.text));
        }
        out.push_str(&format!(
            "      {}\n",
            paint("2", &shorten_home(&item.source))
        ));
    }
    let present: Vec<&crate::Item> = report
        .items
        .iter()
        .filter(|i| i.level == Level::Info)
        .collect();
    if !present.is_empty() {
        let names: Vec<&str> = present.iter().map(|i| i.name.as_str()).collect();
        out.push_str(&format!(
            "\n{}  {}. {}\n",
            paint("2", "Also found"),
            names.join(", "),
            paint("2", "Each runs with your login and keys.")
        ));
    }
    out.push_str(&format!(
        "\n{} findings ({} high, {} medium, {} low) · {} inventoried\n",
        findings.len(),
        report.count(Level::High),
        report.count(Level::Medium),
        report.count(Level::Low),
        present.len()
    ));
    out
}

fn kind_name(kind: crate::Kind) -> &'static str {
    match kind {
        crate::Kind::Agent => "agent",
        crate::Kind::Mcp => "MCP server",
        crate::Kind::Skill => "skill",
        crate::Kind::Plugin => "plugin",
        crate::Kind::Hook => "hook",
        crate::Kind::Extension => "editor extension",
        crate::Kind::Browser => "browser AI",
    }
}

/// SARIF 2.1.0, for code scanning tools.
pub fn sarif(report: &Report) -> Value {
    let mut results = Vec::new();
    let mut rules = std::collections::BTreeMap::new();
    for item in &report.items {
        for finding in &item.findings {
            rules.entry(finding.rule.clone()).or_insert_with(
                || json!({"id": finding.rule, "shortDescription": {"text": finding.text}}),
            );
            let level = match finding.level {
                Level::High => "error",
                Level::Medium => "warning",
                Level::Low | Level::Info => "note",
            };
            results.push(json!({
                "ruleId": finding.rule,
                "level": level,
                "message": {"text": format!("{}: {}", item.name, finding.text)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.source}}}],
            }));
        }
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "halda-scan", "rules": rules.into_values().collect::<Vec<_>>()}},
            "results": results,
        }],
    })
}
