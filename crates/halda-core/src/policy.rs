//! Company policy: ordered rules over simulated effects and analyzer signals.
//!
//! Rules are data. They are evaluated first-match per effect, and the most
//! severe result across all effects wins. There is deliberately no expression
//! language: a policy a security lead can read is worth more than a clever one.

use crate::model::{Domain, Effect, EffectVerb, Environment, Fidelity, Signal, Verdict};
use serde::{Deserialize, Serialize};

/// Whether Halda enforces its decisions or only records them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Decisions apply.
    #[default]
    Enforce,
    /// Nothing is stopped; receipts show what would have been.
    Watch,
}

/// Who may approve and for how long an approval lasts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApprovalPolicy {
    /// Minutes an approval stays usable.
    pub ttl_minutes: u64,
    /// May the person the agent works for approve their own agent's action?
    pub allow_self_approval: bool,
    /// Approver identities. Empty means anyone with the approver token.
    pub approvers: Vec<String>,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            ttl_minutes: 15,
            allow_self_approval: false,
            approvers: Vec::new(),
        }
    }
}

/// Session-level limits enforced by the Watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WatcherPolicy {
    /// Refusals of the same action in one session before the session is halted.
    /// Also the number of different wordings of one action a person may be asked
    /// about before the session is halted.
    pub max_repeat_refusals: u32,
    /// Refusals of any kind in one session before the session is halted.
    pub max_session_refusals: u32,
}

impl Default for WatcherPolicy {
    fn default() -> Self {
        Self {
            max_repeat_refusals: 10,
            max_session_refusals: 30,
        }
    }
}

/// One rule. Every field that is set must match; an unset field matches anything.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable id, recorded on receipts.
    pub id: String,
    /// Result when this rule matches.
    pub verdict: Verdict,
    /// Plain-English reason shown to agents and humans.
    pub reason: String,
    /// Match effects with one of these verbs.
    #[serde(default)]
    pub verb: Vec<EffectVerb>,
    /// Match effects of one of these kinds.
    #[serde(default)]
    pub kind: Vec<String>,
    /// Match effects in one of these environments.
    #[serde(default)]
    pub environment: Vec<Environment>,
    /// Match on whether the effect can be undone.
    #[serde(default)]
    pub irreversible: Option<bool>,
    /// Match effects touching at least this many things.
    #[serde(default)]
    pub min_count: Option<u64>,
    /// Match effects touching at most this many things.
    #[serde(default)]
    pub max_count: Option<u64>,
    /// Match only actions in these domains.
    #[serde(default)]
    pub domain: Vec<Domain>,
    /// Match when the analyzer raised this signal. A rule with `signal` set is
    /// evaluated against the action rather than against each effect.
    #[serde(default)]
    pub signal: Option<String>,
    /// Match simulations at or below this fidelity.
    #[serde(default)]
    pub fidelity_at_most: Option<Fidelity>,
    /// Permits `verdict = "allow"` on an irreversible effect. Without this, the
    /// gate raises such an allow to `ask`: irreversible actions need a hard rule
    /// or a human, and this field is what makes a rule hard.
    #[serde(default)]
    pub allow_irreversible: bool,
}

impl Rule {
    /// Does this effect match?
    pub fn matches_effect(&self, effect: &Effect, domain: Domain, fidelity: Fidelity) -> bool {
        self.signal.is_none()
            && (self.domain.is_empty() || self.domain.contains(&domain))
            && (self.verb.is_empty() || self.verb.contains(&effect.verb))
            && (self.kind.is_empty() || self.kind.iter().any(|k| k == &effect.kind))
            && (self.environment.is_empty()
                || self.environment.contains(&effect.environment)
                // An unknown environment is treated as production.
                || (effect.environment == Environment::Unknown
                    && self.environment.contains(&Environment::Production)))
            && self.irreversible.is_none_or(|v| v == effect.irreversible)
            && self.min_count.is_none_or(|c| effect.count >= c)
            && self.max_count.is_none_or(|c| effect.count <= c)
            && self.fidelity_at_most.is_none_or(|f| fidelity <= f)
    }

    /// Does this signal match?
    pub fn matches_signal(&self, signals: &[Signal], domain: Domain) -> bool {
        let Some(code) = &self.signal else {
            return false;
        };
        (self.domain.is_empty() || self.domain.contains(&domain))
            && signals.iter().any(|s| &s.code == code)
    }
}

/// Describes effects a promise looks for. Every field that is set must match;
/// at least one must be set, so a matcher never matches everything by accident.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectMatch {
    /// Match effects with one of these verbs.
    #[serde(default)]
    pub verb: Vec<EffectVerb>,
    /// Match effects of one of these kinds.
    #[serde(default)]
    pub kind: Vec<String>,
    /// Match effects in one of these environments. Unknown counts as production.
    #[serde(default)]
    pub environment: Vec<Environment>,
    /// Match targets by name. A trailing `*` matches a prefix: `prod-*`.
    #[serde(default)]
    pub target: Vec<String>,
    /// Match on whether the effect can be undone.
    #[serde(default)]
    pub irreversible: Option<bool>,
    /// Match effects touching at least this many things.
    #[serde(default)]
    pub min_count: Option<u64>,
}

impl EffectMatch {
    fn is_empty(&self) -> bool {
        self.verb.is_empty()
            && self.kind.is_empty()
            && self.environment.is_empty()
            && self.target.is_empty()
            && self.irreversible.is_none()
            && self.min_count.is_none()
    }

    /// Does this effect match?
    pub fn matches(&self, effect: &Effect) -> bool {
        (self.verb.is_empty() || self.verb.contains(&effect.verb))
            && (self.kind.is_empty() || self.kind.iter().any(|k| k == &effect.kind))
            && (self.environment.is_empty()
                || self.environment.contains(&effect.environment)
                || (effect.environment == Environment::Unknown
                    && self.environment.contains(&Environment::Production)))
            && (self.target.is_empty()
                || self
                    .target
                    .iter()
                    .any(|pattern| match pattern.strip_suffix('*') {
                        Some(prefix) => effect.target.starts_with(prefix),
                        None => pattern == &effect.target,
                    }))
            && self.irreversible.is_none_or(|v| v == effect.irreversible)
            && self.min_count.is_none_or(|c| effect.count >= c)
    }
}

/// Something a company promises will never happen, whatever any rule allows.
///
/// Rules judge one effect at a time. A promise judges the action as a whole: it
/// is broken when every matcher in `when` finds an effect in the same action.
/// "A database and its backups are never destroyed together" needs two effects
/// at once, which no single rule can see.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Promise {
    /// Stable id, such as `P-DATA-1`. Shown to approvers and recorded on receipts.
    pub id: String,
    /// The promise in plain words, as the company would say it.
    pub text: String,
    /// Result when it would be broken: `ask` or `block`.
    #[serde(default = "default_promise_verdict")]
    pub verdict: Verdict,
    /// Effects that together break the promise.
    pub when: Vec<EffectMatch>,
}

fn default_promise_verdict() -> Verdict {
    Verdict::Block
}

impl Promise {
    /// True if these effects, taken together, break the promise.
    pub fn broken_by(&self, effects: &[Effect]) -> bool {
        !self.when.is_empty()
            && self
                .when
                .iter()
                .all(|m| effects.iter().any(|effect| m.matches(effect)))
    }
}

/// A complete policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Schema version. Currently 1.
    pub version: u32,
    /// Enforce or watch.
    #[serde(default)]
    pub mode: Mode,
    /// Approval rules.
    #[serde(default)]
    pub approvals: ApprovalPolicy,
    /// Watcher limits.
    #[serde(default)]
    pub watcher: WatcherPolicy,
    /// Verdict for an effect no rule matched. Values below `ask` are refused at load.
    #[serde(default = "default_verdict")]
    pub default_effect_verdict: Verdict,
    /// Tools Halda cannot judge by name, which this company has decided to trust.
    /// A trailing `*` matches a prefix: `mcp__notion__*`. What a tool carries is
    /// still checked: this never clears a nested command or SQL.
    #[serde(default)]
    pub trusted_tools: Vec<String>,
    /// Ordered rules. First match wins per effect.
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    /// Things that must never happen. Checked after the rules, and can only raise.
    #[serde(default, rename = "promise")]
    pub promises: Vec<Promise>,
}

fn default_verdict() -> Verdict {
    Verdict::Ask
}

/// A policy that cannot be loaded. Halda refuses to start rather than run with
/// a partly understood policy.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// Malformed TOML, or an unknown field.
    #[error("policy is not valid: {0}")]
    Parse(#[from] toml::de::Error),
    /// Parsed, but unsafe or inconsistent.
    #[error("policy is not valid: {0}")]
    Invalid(String),
}

impl Policy {
    /// The policy that ships with Halda.
    pub const DEFAULT_TOML: &'static str = include_str!("../../../policies/default.toml");

    /// Parses and validates a policy.
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        let policy: Policy = toml::from_str(text)?;
        policy.validate()?;
        Ok(policy)
    }

    /// The built-in default policy.
    pub fn default_policy() -> Self {
        // Covered by a test: the shipped policy always parses.
        Self::from_toml(Self::DEFAULT_TOML).unwrap_or_else(|_| Self {
            version: 1,
            mode: Mode::Enforce,
            approvals: ApprovalPolicy::default(),
            watcher: WatcherPolicy::default(),
            default_effect_verdict: Verdict::Ask,
            trusted_tools: Vec::new(),
            rules: Vec::new(),
            promises: Vec::new(),
        })
    }

    fn validate(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return Err(PolicyError::Invalid(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.default_effect_verdict < Verdict::Ask {
            return Err(PolicyError::Invalid(
                "default_effect_verdict must be ask, retry or block: an effect no rule covers may not run unattended".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.id.is_empty() {
                return Err(PolicyError::Invalid("a rule has an empty id".into()));
            }
            if !seen.insert(&rule.id) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate rule id {}",
                    rule.id
                )));
            }
        }
        for promise in &self.promises {
            if promise.id.is_empty() || promise.text.is_empty() {
                return Err(PolicyError::Invalid(
                    "a promise needs an id and its text".into(),
                ));
            }
            if !seen.insert(&promise.id) {
                return Err(PolicyError::Invalid(format!("duplicate id {}", promise.id)));
            }
            if promise.verdict < Verdict::Ask {
                return Err(PolicyError::Invalid(format!(
                    "promise {} must ask or block: a promise cannot allow anything",
                    promise.id
                )));
            }
            if promise.when.is_empty() || promise.when.iter().any(EffectMatch::is_empty) {
                return Err(PolicyError::Invalid(format!(
                    "promise {} needs at least one effect to look for, and each must say what to match",
                    promise.id
                )));
            }
        }
        Ok(())
    }

    /// True if the policy trusts this tool by name.
    pub fn trusts_tool(&self, tool: &str) -> bool {
        self.trusted_tools
            .iter()
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => tool.starts_with(prefix),
                None => pattern == tool,
            })
    }

    /// Applies the trust list to an analysis. Only a tool whose sole problem is an
    /// unfamiliar name changes: nothing else is ever lowered.
    pub fn apply_trust(&self, tool: &str, analysis: &mut crate::Analysis) {
        if analysis.risk == crate::Risk::Ambiguous
            && analysis.signals.len() == 1
            && matches!(
                analysis.signals[0].code.as_str(),
                "mcp.unknown" | "tool.unknown"
            )
            && self.trusts_tool(tool)
        {
            analysis.risk = crate::Risk::Safe;
            analysis.signals[0] = crate::Signal::new(
                "local.dev",
                format!("{tool} is on this company's trusted list"),
            );
        }
    }

    /// Stable hash, recorded on every receipt so an auditor knows which policy applied.
    pub fn hash(&self) -> String {
        crate::canon::hash_canonical(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_policy_is_valid() {
        let policy = Policy::from_toml(Policy::DEFAULT_TOML).expect("default policy parses");
        assert!(!policy.rules.is_empty());
        assert_eq!(policy.mode, Mode::Enforce);
    }

    #[test]
    fn the_trust_list_only_clears_an_unfamiliar_name() {
        let p = Policy::from_toml("version = 1\ntrusted_tools = [\"mcp__notion__*\", \"Exact\"]\n")
            .expect("policy");
        let unknown = |code: &str| crate::Analysis {
            risk: crate::Risk::Ambiguous,
            signals: vec![crate::Signal::new(code, "d")],
            ..crate::Analysis::default()
        };
        let mut a = unknown("mcp.unknown");
        p.apply_trust("mcp__notion__frobnicate", &mut a);
        assert_eq!(a.risk, crate::Risk::Safe);
        let mut b = unknown("mcp.unknown");
        p.apply_trust("mcp__other__frobnicate", &mut b);
        assert_eq!(b.risk, crate::Risk::Ambiguous, "not listed");
        let mut c = unknown("sql.opaque");
        p.apply_trust("mcp__notion__frobnicate", &mut c);
        assert_eq!(
            c.risk,
            crate::Risk::Ambiguous,
            "what a tool carries is still checked"
        );
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(Policy::from_toml("version = 1\ntypo_field = true\n").is_err());
    }

    #[test]
    fn a_permissive_default_is_refused() {
        let err = Policy::from_toml("version = 1\ndefault_effect_verdict = \"allow\"\n");
        assert!(err.is_err());
    }

    #[test]
    fn a_promise_must_be_specific_and_cannot_allow() {
        let with = |body: &str| Policy::from_toml(&format!("version = 1\n[[promise]]\n{body}"));
        assert!(with(
            "id = \"P-1\"\ntext = \"t\"\nwhen = [{ verb = [\"delete\"], kind = [\"volume\"] }]"
        )
        .is_ok());
        assert!(
            with("id = \"P-1\"\ntext = \"t\"\nwhen = [{}]").is_err(),
            "matches everything"
        );
        assert!(
            with("id = \"P-1\"\ntext = \"t\"\nwhen = []").is_err(),
            "matches nothing"
        );
        assert!(
            with("id = \"P-1\"\ntext = \"t\"\nverdict = \"allow\"\nwhen = [{ kind = [\"x\"] }]")
                .is_err(),
            "a promise cannot allow"
        );
        assert!(
            with("id = \"\"\ntext = \"t\"\nwhen = [{ kind = [\"x\"] }]").is_err(),
            "needs an id"
        );
    }

    #[test]
    fn a_promise_and_a_rule_cannot_share_an_id() {
        let text = r#"
            version = 1
            [[rule]]
            id = "same"
            verdict = "ask"
            reason = "x"
            [[promise]]
            id = "same"
            text = "y"
            when = [{ kind = ["volume"] }]
        "#;
        assert!(Policy::from_toml(text).is_err());
    }

    #[test]
    fn duplicate_rule_ids_are_refused() {
        let text = r#"
            version = 1
            [[rule]]
            id = "a"
            verdict = "ask"
            reason = "x"
            [[rule]]
            id = "a"
            verdict = "block"
            reason = "y"
        "#;
        assert!(Policy::from_toml(text).is_err());
    }
}
