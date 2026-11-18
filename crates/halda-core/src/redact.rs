//! Removes secrets from text before it reaches Slack, a receipt, or a log.
//!
//! Redaction is deterministic and errs towards over-matching: hiding a harmless
//! value costs a human a moment, leaking a key costs a rotation everywhere.

use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Replacement text. Stable, so a redacted action still hashes consistently.
pub const MASK: &str = "[REDACTED]";

fn patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            // Private key blocks.
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
            // Vendor tokens with recognizable prefixes.
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bASIA[0-9A-Z]{16}\b",
            r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
            r"\bglpat-[A-Za-z0-9_\-]{16,}\b",
            r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b",
            r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b",
            r"\bsk-[A-Za-z0-9_\-]{20,}\b",
            r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b",
            r"\bAIza[0-9A-Za-z_\-]{30,}\b",
            r"\bnpm_[A-Za-z0-9]{30,}\b",
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b",
            // Credentials embedded in URLs.
            r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)[^\s@/]+(@)",
            // Authorization headers.
            r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token)?\s*)[^\s'\x22]+",
            r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=\-]{12,}",
            // NAME=value assignments for names that look like secrets.
            r"(?i)\b([A-Z0-9_\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|credential)[A-Z0-9_\-]*\s*[=:]\s*)('[^']*'|\x22[^\x22]*\x22|[^\s'\x22,;&]+)",
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
    })
}

/// Returns `text` with anything that looks like a secret replaced by [`MASK`].
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for re in patterns() {
        out = re
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                let prefix = caps.get(1).map_or("", |m| m.as_str());
                // The URL pattern captures what surrounds the password; keep both sides.
                let suffix = if caps.len() == 3 && caps.get(2).is_some_and(|m| m.as_str() == "@") {
                    "@"
                } else {
                    ""
                };
                format!("{prefix}{MASK}{suffix}")
            })
            .into_owned();
    }
    out
}

/// What [`inspect`] found and masked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Found {
    /// Keys, tokens, passwords and private keys.
    pub secrets: usize,
    /// Payment card numbers that pass the Luhn check, and US Social Security numbers.
    pub personal: usize,
}

impl Found {
    /// True if nothing was found.
    pub fn is_empty(self) -> bool {
        self.secrets == 0 && self.personal == 0
    }

    /// Adds another count to this one.
    pub fn add(&mut self, other: Found) {
        self.secrets += other.secrets;
        self.personal += other.personal;
    }
}

/// The last pattern masks `NAME=value` for secret-sounding names. In prose, such as a
/// prompt, its value must look like a secret too: eight characters or more, and not
/// a plain lowercase word, so "token: limits" is left alone.
fn looks_secret(value: &str) -> bool {
    let bare = value.trim_matches(|c| c == '\'' || c == '"');
    bare.len() >= 8 && !bare.chars().all(|c| c.is_ascii_lowercase()) && !bare.starts_with('$')
}

/// A pattern, and the check a match must also pass.
type Checked = (Regex, fn(&str) -> bool);

fn personal_patterns() -> &'static [Checked] {
    static PATTERNS: OnceLock<Vec<Checked>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let card: fn(&str) -> bool = |m| {
            let digits: Vec<u32> = m.chars().filter_map(|c| c.to_digit(10)).collect();
            (13..=19).contains(&digits.len())
                && digits
                    .iter()
                    .rev()
                    .enumerate()
                    .map(|(i, d)| {
                        if i % 2 == 1 {
                            let x = d * 2;
                            if x > 9 {
                                x - 9
                            } else {
                                x
                            }
                        } else {
                            *d
                        }
                    })
                    .sum::<u32>()
                    % 10
                    == 0
        };
        let ssn: fn(&str) -> bool = |m| {
            let area = &m[..3];
            area != "000"
                && area != "666"
                && !area.starts_with('9')
                && &m[4..6] != "00"
                && &m[7..] != "0000"
        };
        [
            (r"\b\d(?:[ -]?\d){12,18}\b", card),
            (r"\b\d{3}-\d{2}-\d{4}\b", ssn),
        ]
        .into_iter()
        .filter_map(|(p, check)| Regex::new(p).ok().map(|re| (re, check)))
        .collect()
    })
}

/// Masks secrets and personal numbers in text a person or agent wrote, such as a
/// prompt to a model, and says how many of each. Stricter than [`redact`] about
/// `NAME=value` prose, because here masking a harmless word changes what is said.
pub fn inspect(text: &str) -> (String, Found) {
    let mut found = Found::default();
    let mut out = text.to_string();
    let all = patterns();
    for (index, re) in all.iter().enumerate() {
        let assignment = index + 1 == all.len();
        out = re
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                let whole = caps.get(0).map_or("", |m| m.as_str());
                if whole.contains(MASK) {
                    return whole.to_string();
                }
                if assignment && !caps.get(2).is_some_and(|v| looks_secret(v.as_str())) {
                    return whole.to_string();
                }
                found.secrets += 1;
                let prefix = caps.get(1).map_or("", |m| m.as_str());
                let suffix = if caps.len() == 3 && caps.get(2).is_some_and(|m| m.as_str() == "@") {
                    "@"
                } else {
                    ""
                };
                format!("{prefix}{MASK}{suffix}")
            })
            .into_owned();
    }
    for (re, check) in personal_patterns() {
        out = re
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                let whole = caps.get(0).map_or("", |m| m.as_str());
                if check(whole) {
                    found.personal += 1;
                    MASK.to_string()
                } else {
                    whole.to_string()
                }
            })
            .into_owned();
    }
    (out, found)
}

/// True if `text` contains something that looks like a secret.
pub fn contains_secret(text: &str) -> bool {
    patterns().iter().any(|re| re.is_match(text))
}

/// Redacts every string inside a JSON value.
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact(s)),
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_json(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_vendor_tokens() {
        for secret in [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_0123456789abcdefghijABCDEFGHIJ012345",
            "xoxb-123456789012-abcdefghijkl",
            "sk-ant-api03-abcdefghijklmnop",
            "sk_live_abcdefghijklmnop1234",
        ] {
            let out = redact(&format!("token is {secret} ok"));
            assert!(!out.contains(secret), "{secret} survived: {out}");
            assert!(out.contains(MASK));
            assert!(contains_secret(secret));
        }
    }

    #[test]
    fn redacts_assignments_and_keeps_the_name() {
        let out = redact("PGPASSWORD=hunter2 psql -h db");
        assert_eq!(out, "PGPASSWORD=[REDACTED] psql -h db");
    }

    #[test]
    fn redacts_passwords_in_urls_and_keeps_the_host() {
        let out = redact("psql postgres://admin:s3cret@db.internal:5432/app");
        assert!(!out.contains("s3cret"));
        assert!(out.contains("db.internal"));
        assert!(out.contains("postgres://admin:"));
    }

    #[test]
    fn redacts_private_keys() {
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----";
        assert!(!redact(key).contains("MIIEabc"));
    }

    #[test]
    fn leaves_ordinary_commands_alone() {
        for text in [
            "terraform destroy -target=aws_db_instance.prod",
            "git push origin main",
            "ls -la",
        ] {
            assert_eq!(redact(text), text);
            assert!(!contains_secret(text));
        }
    }

    /// The cases the browser extension's detector is held to as well.
    #[test]
    fn catches_every_secret_in_the_shared_corpus() {
        let corpus: Value =
            serde_json::from_str(include_str!("../../../tests/corpus/secrets.json"))
                .expect("corpus");
        for secret in corpus["secrets"].as_array().expect("secrets") {
            let text = secret.as_str().expect("text");
            assert!(contains_secret(text), "missed: {text}");
        }
        for clean in corpus["clean"].as_array().expect("clean") {
            let text = clean.as_str().expect("text");
            assert!(!contains_secret(text), "flagged: {text}");
        }
    }

    #[test]
    fn inspect_masks_secrets_and_personal_numbers_and_counts_them() {
        let (out, found) = inspect(
            "key AKIAIOSFODNN7EXAMPLE, card 4111 1111 1111 1111, ssn 123-45-6789, DB_PASSWORD=s3cr3t-Pa55word",
        );
        assert_eq!(
            out,
            "key [REDACTED], card [REDACTED], ssn [REDACTED], DB_PASSWORD=[REDACTED]"
        );
        assert_eq!(
            found,
            Found {
                secrets: 2,
                personal: 2
            }
        );
    }

    #[test]
    fn inspect_leaves_prose_and_ordinary_numbers_alone() {
        let corpus: Value =
            serde_json::from_str(include_str!("../../../tests/corpus/secrets.json"))
                .expect("corpus");
        for text in corpus["clean"]
            .as_array()
            .into_iter()
            .chain(corpus["clean_prose"].as_array())
            .flatten()
            .filter_map(Value::as_str)
            .chain([
                "Order 1234567890123 shipped",
                "Call 555-0123 or +1 415 555 0123 later",
                "Build 20261116 passed in 4111 ms",
            ])
        {
            let (out, found) = inspect(text);
            assert_eq!(out, text, "changed: {text}");
            assert!(found.is_empty(), "{text}");
        }
        for secret in corpus["secrets"].as_array().expect("secrets") {
            let text = secret.as_str().expect("text");
            assert!(inspect(text).1.secrets > 0, "missed: {text}");
        }
    }

    #[test]
    fn redacts_inside_json() {
        let v = redact_json(&json!({"a": ["AKIAIOSFODNN7EXAMPLE"], "n": 1}));
        assert_eq!(v, json!({"a": ["[REDACTED]"], "n": 1}));
    }
}
