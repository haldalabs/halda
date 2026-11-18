//! Signed receipts as OpenTelemetry logs (OTLP/JSON), the format SIEMs and
//! observability tools take in directly or through an OpenTelemetry Collector.
//!
//! One receipt is one log record. Standard attribute names are used where they exist
//! (`gen_ai.agent.name`, `gen_ai.tool.name`, `user.name`, `host.name`, `session.id`),
//! and everything Halda adds is under `halda.`. The receipt's hash, the hash before
//! it and its signature travel with it, so a copy in a SIEM can still be checked
//! against the public key.

use crate::receipt::Receipt;
use crate::Verdict;
use serde_json::{json, Value};

/// Where the logs come from.
#[derive(Debug, Clone)]
pub struct Source {
    /// The machine or gate that wrote the receipts.
    pub host: String,
    /// Halda's version.
    pub version: String,
    /// The receipt signing key, hex, so a reader can verify without asking.
    pub public_key: String,
}

fn text(key: &str, value: &str) -> Value {
    json!({"key": key, "value": {"stringValue": value}})
}

fn number(key: &str, value: u64) -> Value {
    // OTLP/JSON carries 64-bit integers as strings.
    json!({"key": key, "value": {"intValue": value.to_string()}})
}

fn flag(key: &str, value: bool) -> Value {
    json!({"key": key, "value": {"boolValue": value}})
}

/// OpenTelemetry severity: a refusal is a warning, a wait is notable, the rest is
/// information. Nothing Halda decides is an error in its own operation.
fn severity(verdict: Verdict) -> (u8, &'static str) {
    match verdict {
        Verdict::Block | Verdict::Retry => (13, "WARN"),
        Verdict::Ask => (10, "INFO2"),
        Verdict::Allow | Verdict::Fix => (9, "INFO"),
    }
}

/// One receipt as one OTLP log record.
pub fn record(receipt: &Receipt) -> Value {
    let b = &receipt.body;
    let (number_severity, severity_text) = severity(b.enforced);
    let body_text = match &b.consequence {
        Some(c) if !c.summary.is_empty() => format!("{}: {}", b.enforced.as_str(), c.summary),
        _ => format!("{}: {}", b.enforced.as_str(), b.reason),
    };
    let mut attributes = vec![
        text("event.name", "halda.decision"),
        text("halda.verdict", b.verdict.as_str()),
        text("halda.enforced", b.enforced.as_str()),
        text("halda.reason", &b.reason),
        text("gen_ai.agent.name", &b.actor.agent),
        text("user.name", &b.actor.principal),
        text("host.name", &b.actor.host),
        text("session.id", &b.actor.session),
        flag("halda.agent.attested", b.actor.attested),
        text("gen_ai.tool.name", &b.tool),
        text("halda.action", &b.action),
        text("halda.action.fingerprint", &b.action_fingerprint),
        text("halda.decision.id", &b.decision_id),
        text("halda.policy.hash", &b.policy_hash),
        number("halda.receipt.seq", b.seq),
        text("halda.receipt.hash", &receipt.hash),
        text("halda.receipt.prev_hash", &b.prev_hash),
        text("halda.receipt.key_id", &receipt.key_id),
        text("halda.receipt.signature", &receipt.signature),
    ];
    if b.actor.chain.len() > 1 {
        attributes.push(text("halda.agent.chain", &b.actor.chain.join(" > ")));
    }
    if let Some(rule) = &b.rule {
        attributes.push(text("halda.rule", rule));
    }
    if let Some(c) = &b.consequence {
        attributes.push(text("halda.effect", &c.summary));
        attributes.push(text("halda.effect.simulator", &c.simulator));
        let fidelity = serde_json::to_value(c.fidelity)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        attributes.push(text("halda.effect.fidelity", &fidelity));
        if let Some(why) = &c.inconclusive {
            attributes.push(text("halda.effect.inconclusive", why));
        }
    }
    if let Some(a) = &b.approval {
        attributes.push(text("halda.approval.by", &a.by));
        attributes.push(flag("halda.approval.approved", a.approved));
        attributes.push(text("halda.approval.via", &a.via));
        attributes.push(number("halda.approval.at_ms", a.at_ms));
    }
    let nanos = (u128::from(b.at_ms) * 1_000_000).to_string();
    json!({
        "timeUnixNano": nanos,
        "observedTimeUnixNano": nanos,
        "severityNumber": number_severity,
        "severityText": severity_text,
        "body": {"stringValue": body_text},
        "attributes": attributes,
    })
}

/// Receipts as one OTLP/JSON `LogsData` document, ready to POST to `/v1/logs`.
pub fn logs(receipts: &[Receipt], source: &Source) -> Value {
    json!({
        "resourceLogs": [{
            "resource": {"attributes": [
                text("service.name", "halda"),
                text("service.version", &source.version),
                text("host.name", &source.host),
                text("halda.receipt.public_key", &source.public_key),
            ]},
            "scopeLogs": [{
                "scope": {"name": "halda.receipts", "version": source.version},
                "logRecords": receipts.iter().map(record).collect::<Vec<_>>(),
            }],
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{ApprovalRecord, ReceiptBody};
    use crate::{Actor, Consequence};

    fn receipt(verdict: Verdict, approval: Option<ApprovalRecord>) -> Receipt {
        Receipt {
            body: ReceiptBody {
                seq: 7,
                at_ms: 1_763_300_000_123,
                prev_hash: "p".into(),
                decision_id: "d".into(),
                actor: Actor {
                    agent: "claude-code".into(),
                    principal: "jordan".into(),
                    host: "laptop".into(),
                    session: "s1".into(),
                    chain: vec!["claude-code".into(), "claimed-principal:priya".into()],
                    attested: true,
                },
                tool: "Bash".into(),
                action: "terraform destroy".into(),
                action_fingerprint: "f".into(),
                consequence: Some(Consequence {
                    summary: "Deletes 1 database in production.".into(),
                    simulator: "terraform".into(),
                    ..Consequence::default()
                }),
                verdict,
                enforced: verdict,
                reason: "irreversible".into(),
                rule: Some("P-DATA-1".into()),
                approval,
                policy_hash: "ph".into(),
            },
            hash: "h".into(),
            key_id: "k".into(),
            signature: "sig".into(),
        }
    }

    fn find_attribute<'a>(record: &'a Value, key: &str) -> Option<&'a Value> {
        record["attributes"]
            .as_array()?
            .iter()
            .find(|a| a["key"] == key)
            .map(|a| &a["value"])
    }

    fn attribute<'a>(record: &'a Value, key: &str) -> &'a Value {
        find_attribute(record, key).unwrap_or_else(|| panic!("no {key}"))
    }

    #[test]
    fn a_refusal_is_a_warning_with_its_effect_and_proof() {
        let r = record(&receipt(Verdict::Block, None));
        assert_eq!(r["severityNumber"], 13);
        assert_eq!(r["severityText"], "WARN");
        assert_eq!(r["timeUnixNano"], "1763300000123000000");
        assert_eq!(
            r["body"]["stringValue"],
            "block: Deletes 1 database in production."
        );
        assert_eq!(
            attribute(&r, "gen_ai.agent.name")["stringValue"],
            "claude-code"
        );
        assert_eq!(attribute(&r, "user.name")["stringValue"], "jordan");
        assert_eq!(attribute(&r, "halda.rule")["stringValue"], "P-DATA-1");
        assert_eq!(attribute(&r, "halda.receipt.seq")["intValue"], "7");
        assert_eq!(
            attribute(&r, "halda.receipt.signature")["stringValue"],
            "sig"
        );
        assert_eq!(
            attribute(&r, "halda.agent.chain")["stringValue"],
            "claude-code > claimed-principal:priya"
        );
        assert!(find_attribute(&r, "halda.approval.by").is_none());
    }

    #[test]
    fn an_approval_says_who_and_how() {
        let r = record(&receipt(
            Verdict::Allow,
            Some(ApprovalRecord {
                by: "priya".into(),
                approved: true,
                at_ms: 5,
                via: "slack".into(),
            }),
        ));
        assert_eq!(r["severityText"], "INFO");
        assert_eq!(attribute(&r, "halda.approval.by")["stringValue"], "priya");
        assert_eq!(attribute(&r, "halda.approval.approved")["boolValue"], true);
    }

    #[test]
    fn logs_are_one_resource_with_one_record_per_receipt() {
        let source = Source {
            host: "laptop".into(),
            version: "0.1.0".into(),
            public_key: "abc".into(),
        };
        let all = logs(
            &[receipt(Verdict::Ask, None), receipt(Verdict::Allow, None)],
            &source,
        );
        let scope = &all["resourceLogs"][0]["scopeLogs"][0];
        assert_eq!(scope["logRecords"].as_array().map_or(0, Vec::len), 2);
        assert_eq!(scope["scope"]["name"], "halda.receipts");
        let resource = &all["resourceLogs"][0]["resource"]["attributes"];
        assert!(resource
            .as_array()
            .expect("attributes")
            .iter()
            .any(|a| a["key"] == "service.name" && a["value"]["stringValue"] == "halda"));
    }
}
