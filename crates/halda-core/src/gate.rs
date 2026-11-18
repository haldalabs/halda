//! The gate: the only place in Halda where a verdict is made.
//!
//! Invariants, each covered by a property test below:
//!
//! 1. A forbidden action, or a tripped kill switch, is never allowed.
//! 2. Evidence only raises a verdict; nothing a sub-agent says can lower one.
//! 3. Evidence from an LLM alone cannot refuse an action outright: it can raise
//!    to `ask`, which puts a human in the loop, and no further.
//! 4. A non-safe action with no conclusive simulation is at least `ask`.
//! 5. An irreversible effect is at least `ask` unless a hard rule says otherwise.
//! 6. The function is pure: same inputs, same output.

use crate::model::{Analysis, Consequence, Evidence, Fidelity, Risk, Severity, Verdict};
use crate::policy::Policy;
use serde::{Deserialize, Serialize};

/// Everything the gate looks at.
#[derive(Debug, Clone, Copy)]
pub struct GateInput<'a> {
    /// Company policy.
    pub policy: &'a Policy,
    /// Static analysis.
    pub analysis: &'a Analysis,
    /// Simulated effect, if a simulator ran.
    pub consequence: Option<&'a Consequence>,
    /// Sub-agent findings.
    pub evidence: &'a [Evidence],
    /// Is the kill switch tripped?
    pub killed: bool,
}

/// The gate's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateOutcome {
    /// The verdict.
    pub verdict: Verdict,
    /// Why.
    pub reason: String,
    /// The rule responsible, if one was.
    pub rule: Option<String>,
}

fn outcome(verdict: Verdict, reason: impl Into<String>, rule: Option<&str>) -> GateOutcome {
    GateOutcome {
        verdict,
        reason: reason.into(),
        rule: rule.map(str::to_string),
    }
}

/// Decides. Pure and total: every input produces a verdict.
pub fn decide(input: GateInput<'_>) -> GateOutcome {
    let GateInput {
        policy,
        analysis,
        consequence,
        evidence,
        killed,
    } = input;

    if killed && !analysis.is_read_only() {
        return outcome(
            Verdict::Block,
            "The kill switch is on. Only read-only actions run until a human resumes Halda.",
            Some("core.kill_switch"),
        );
    }
    if analysis.risk == Risk::Forbidden {
        let why = analysis
            .signals
            .first()
            .map_or("This action is never permitted.", |s| s.detail.as_str());
        return outcome(Verdict::Block, why, Some("core.forbidden"));
    }

    let base = if analysis.risk == Risk::Safe && consequence.is_none() {
        let reason = match analysis.signals.iter().find(|s| {
            matches!(
                s.code.as_str(),
                "local.dev" | "network.read" | "memory.write"
            )
        }) {
            Some(signal) => format!("Allowed without a simulation: {}.", signal.detail),
            None => "Read-only action.".to_string(),
        };
        outcome(Verdict::Allow, reason, Some("core.fast_path"))
    } else {
        evaluate(policy, analysis, consequence)
    };
    apply_evidence(apply_promises(base, policy, consequence), evidence)
}

/// A broken promise raises the verdict, whatever the rules said. Like evidence,
/// it can never lower one.
fn apply_promises(
    mut result: GateOutcome,
    policy: &Policy,
    consequence: Option<&Consequence>,
) -> GateOutcome {
    let Some(c) = consequence else {
        return result;
    };
    for promise in &policy.promises {
        if promise.verdict > result.verdict && promise.broken_by(&c.effects) {
            result = outcome(
                promise.verdict,
                format!("Breaks promise {}: {}", promise.id, promise.text),
                Some(&promise.id),
            );
        }
    }
    result
}

fn evaluate(
    policy: &Policy,
    analysis: &Analysis,
    consequence: Option<&Consequence>,
) -> GateOutcome {
    // Signal rules apply to the action as a whole.
    let mut best: Option<GateOutcome> = None;
    let mut raise = |candidate: GateOutcome| {
        if best.as_ref().is_none_or(|b| candidate.verdict > b.verdict) {
            best = Some(candidate);
        }
    };
    for rule in &policy.rules {
        if rule.matches_signal(&analysis.signals, analysis.domain) {
            raise(outcome(rule.verdict, rule.reason.clone(), Some(&rule.id)));
        }
    }

    let unknown_effect =
        |why: String| outcome(Verdict::Ask, why, Some("core.no_conclusive_simulation"));
    match consequence {
        // A deterministic correction exists, so nothing unknown goes out.
        None if analysis.fixed_input.is_some() => raise(outcome(
            Verdict::Fix,
            "A secret was redacted from this request.",
            Some("core.fixed_input"),
        )),
        None => raise(unknown_effect(match analysis.signals.first() {
            Some(signal) => format!("Nothing simulated this: {}.", signal.detail),
            None => "No simulator could check this action, so a human decides.".to_string(),
        })),
        Some(c) if c.inconclusive.is_some() => raise(unknown_effect(c.summary.clone())),
        Some(c) if c.effects.is_empty() => {
            // A clean result only counts if something actually ran.
            if c.fidelity >= Fidelity::Twin {
                raise(outcome(
                    Verdict::Allow,
                    format!("Simulated: {}", c.summary),
                    Some("core.no_effect"),
                ));
            } else {
                raise(unknown_effect(format!(
                    "Reading the action shows no effect, but nothing was run: {}",
                    c.summary
                )));
            }
        }
        Some(c) => {
            for effect in &c.effects {
                let matched = policy
                    .rules
                    .iter()
                    .find(|r| r.matches_effect(effect, analysis.domain, c.fidelity));
                let candidate = match matched {
                    Some(rule)
                        if rule.verdict == Verdict::Allow
                            && effect.irreversible
                            && !rule.allow_irreversible =>
                    {
                        outcome(
                            Verdict::Ask,
                            format!("{} Irreversible, so a human decides.", rule.reason),
                            Some(&rule.id),
                        )
                    }
                    Some(rule) => outcome(rule.verdict, rule.reason.clone(), Some(&rule.id)),
                    None => outcome(
                        policy.default_effect_verdict,
                        format!("No rule covers this effect: {}", c.summary),
                        Some("core.default_effect"),
                    ),
                };
                raise(candidate);
            }
        }
    }

    // `raise` was always called at least once above.
    best.unwrap_or_else(|| outcome(Verdict::Ask, "Undetermined.", Some("core.default_effect")))
}

fn apply_evidence(mut result: GateOutcome, evidence: &[Evidence]) -> GateOutcome {
    for item in evidence {
        let wanted = match item.severity {
            Severity::Info | Severity::Warn => continue,
            Severity::High => Verdict::Ask,
            Severity::Critical if item.deterministic => Verdict::Block,
            Severity::Critical => Verdict::Ask,
        };
        if wanted > result.verdict {
            result = outcome(
                wanted,
                format!("{}: {}", item.agent, item.finding),
                Some(&format!("evidence.{}", item.agent)),
            );
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use proptest::prelude::*;

    fn policy() -> Policy {
        Policy::default_policy()
    }

    fn analysis(risk: Risk) -> Analysis {
        Analysis {
            risk,
            domain: Domain::Terraform,
            ..Analysis::default()
        }
    }

    fn effect(verb: EffectVerb, kind: &str, irreversible: bool) -> Effect {
        Effect {
            verb,
            kind: kind.into(),
            target: "t".into(),
            count: 1,
            environment: Environment::Production,
            irreversible,
        }
    }

    fn conseq(effects: Vec<Effect>, fidelity: Fidelity) -> Consequence {
        Consequence {
            summary: "s".into(),
            effects,
            fidelity,
            simulator: "test".into(),
            ..Consequence::default()
        }
    }

    #[test]
    fn deleting_a_production_database_needs_a_human() {
        let p = policy();
        let a = analysis(Risk::Risky);
        let c = conseq(
            vec![effect(EffectVerb::Delete, "database", true)],
            Fidelity::Planned,
        );
        let out = decide(GateInput {
            policy: &p,
            analysis: &a,
            consequence: Some(&c),
            evidence: &[],
            killed: false,
        });
        assert_eq!(out.verdict, Verdict::Ask);
    }

    #[test]
    fn an_action_with_no_simulator_is_never_allowed() {
        let p = policy();
        let a = analysis(Risk::Ambiguous);
        let out = decide(GateInput {
            policy: &p,
            analysis: &a,
            consequence: None,
            evidence: &[],
            killed: false,
        });
        assert_eq!(out.verdict, Verdict::Ask);
    }

    #[test]
    fn a_clean_reading_of_text_alone_is_not_enough() {
        let p = policy();
        let a = analysis(Risk::Risky);
        let c = conseq(vec![], Fidelity::Static);
        let out = decide(GateInput {
            policy: &p,
            analysis: &a,
            consequence: Some(&c),
            evidence: &[],
            killed: false,
        });
        assert_eq!(out.verdict, Verdict::Ask);
    }

    #[test]
    fn a_clean_simulation_allows() {
        let p = policy();
        let a = analysis(Risk::Ambiguous);
        let c = conseq(vec![], Fidelity::Executed);
        let out = decide(GateInput {
            policy: &p,
            analysis: &a,
            consequence: Some(&c),
            evidence: &[],
            killed: false,
        });
        assert_eq!(out.verdict, Verdict::Allow);
    }

    #[test]
    fn an_llm_cannot_block_on_its_own_but_fixed_logic_can() {
        let p = policy();
        let a = analysis(Risk::Safe);
        let llm = [Evidence {
            agent: "grader".into(),
            severity: Severity::Critical,
            finding: "x".into(),
            deterministic: false,
        }];
        let fixed = [Evidence {
            agent: "watcher".into(),
            severity: Severity::Critical,
            finding: "x".into(),
            deterministic: true,
        }];
        let base = GateInput {
            policy: &p,
            analysis: &a,
            consequence: None,
            evidence: &llm,
            killed: false,
        };
        assert_eq!(decide(base).verdict, Verdict::Ask);
        assert_eq!(
            decide(GateInput {
                evidence: &fixed,
                ..base
            })
            .verdict,
            Verdict::Block
        );
    }

    #[test]
    fn a_hard_rule_can_allow_an_irreversible_effect_and_only_a_hard_rule() {
        let soft = Policy::from_toml(
            r#"version = 1
            [[rule]]
            id = "soft"
            verdict = "allow"
            reason = "ok"
            kind = ["file"]"#,
        )
        .expect("valid");
        let hard = Policy::from_toml(
            r#"version = 1
            [[rule]]
            id = "hard"
            verdict = "allow"
            reason = "ok"
            kind = ["file"]
            allow_irreversible = true"#,
        )
        .expect("valid");
        let a = analysis(Risk::Risky);
        let c = conseq(
            vec![effect(EffectVerb::Delete, "file", true)],
            Fidelity::Executed,
        );
        let run = |p: &Policy| {
            decide(GateInput {
                policy: p,
                analysis: &a,
                consequence: Some(&c),
                evidence: &[],
                killed: false,
            })
            .verdict
        };
        assert_eq!(run(&soft), Verdict::Ask);
        assert_eq!(run(&hard), Verdict::Allow);
    }

    fn targeted(verb: EffectVerb, kind: &str, target: &str) -> Effect {
        Effect {
            target: target.into(),
            ..effect(verb, kind, true)
        }
    }

    #[test]
    fn destroying_a_volume_and_its_backups_together_breaks_the_shipped_promise() {
        // PocketOS, April 2026: one call deleted the production volume and the
        // backups stored with it.
        let p = policy();
        let a = analysis(Risk::Risky);
        let both = conseq(
            vec![
                targeted(EffectVerb::Delete, "volume", "prod-data"),
                targeted(EffectVerb::Delete, "snapshot", "prod-data-backup"),
            ],
            Fidelity::Planned,
        );
        let out = decide(GateInput {
            policy: &p,
            analysis: &a,
            consequence: Some(&both),
            evidence: &[],
            killed: false,
        });
        assert_eq!(out.verdict, Verdict::Block);
        assert_eq!(out.rule.as_deref(), Some("P-DATA-1"));
        assert!(out.reason.starts_with("Breaks promise P-DATA-1:"));

        // Either one alone is a decision for a person, not a broken promise.
        let one = conseq(
            vec![targeted(EffectVerb::Delete, "volume", "prod-data")],
            Fidelity::Planned,
        );
        let out = decide(GateInput {
            policy: &p,
            analysis: &a,
            consequence: Some(&one),
            evidence: &[],
            killed: false,
        });
        assert_eq!(out.verdict, Verdict::Ask);
    }

    #[test]
    fn a_promise_overrides_a_rule_that_allows() {
        let p = Policy::from_toml(
            r#"version = 1
            [[rule]]
            id = "anything-goes"
            verdict = "allow"
            reason = "ok"
            allow_irreversible = true
            [[promise]]
            id = "P-MAIN-1"
            text = "main is never rewritten."
            when = [{ verb = ["delete"], kind = ["commit"], target = ["main"] }]"#,
        )
        .expect("valid");
        let a = analysis(Risk::Risky);
        let run = |target: &str| {
            let c = conseq(
                vec![targeted(EffectVerb::Delete, "commit", target)],
                Fidelity::Executed,
            );
            decide(GateInput {
                policy: &p,
                analysis: &a,
                consequence: Some(&c),
                evidence: &[],
                killed: false,
            })
        };
        assert_eq!(run("main").verdict, Verdict::Block);
        assert_eq!(run("feature-x").verdict, Verdict::Allow);
    }

    fn any_risk() -> impl Strategy<Value = Risk> {
        prop_oneof![
            Just(Risk::Safe),
            Just(Risk::Risky),
            Just(Risk::Ambiguous),
            Just(Risk::Forbidden)
        ]
    }
    fn any_fidelity() -> impl Strategy<Value = Fidelity> {
        prop_oneof![
            Just(Fidelity::None),
            Just(Fidelity::Static),
            Just(Fidelity::Recorded),
            Just(Fidelity::Twin),
            Just(Fidelity::Planned),
            Just(Fidelity::Executed)
        ]
    }
    fn any_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Info),
            Just(Severity::Warn),
            Just(Severity::High),
            Just(Severity::Critical)
        ]
    }
    fn any_effect() -> impl Strategy<Value = Effect> {
        (
            prop_oneof![
                Just(EffectVerb::Delete),
                Just(EffectVerb::Modify),
                Just(EffectVerb::Create),
                Just(EffectVerb::Send),
                Just(EffectVerb::Charge),
                Just(EffectVerb::Read)
            ],
            prop_oneof![
                Just("database"),
                Just("rows"),
                Just("file"),
                Just("commit"),
                Just("weird-kind")
            ],
            prop_oneof![
                Just(Environment::Production),
                Just(Environment::Nonproduction),
                Just(Environment::Unknown)
            ],
            any::<bool>(),
            0u64..1_000_000,
        )
            .prop_map(|(verb, kind, environment, irreversible, count)| Effect {
                verb,
                kind: kind.into(),
                target: "t".into(),
                count,
                environment,
                irreversible,
            })
    }
    fn any_evidence() -> impl Strategy<Value = Vec<Evidence>> {
        prop::collection::vec(
            (any_severity(), any::<bool>(), ".{0,20}").prop_map(
                |(severity, deterministic, finding)| Evidence {
                    agent: "a".into(),
                    severity,
                    finding,
                    deterministic,
                },
            ),
            0..4,
        )
    }
    fn any_consequence() -> impl Strategy<Value = Option<Consequence>> {
        prop::option::of(
            (
                prop::collection::vec(any_effect(), 0..4),
                any_fidelity(),
                any::<bool>(),
            )
                .prop_map(|(effects, fidelity, inconclusive)| Consequence {
                    summary: "s".into(),
                    effects,
                    fidelity,
                    inconclusive: inconclusive.then(|| "why".to_string()),
                    simulator: "p".into(),
                    duration_ms: 0,
                }),
        )
    }

    proptest! {
        #[test]
        fn forbidden_and_killed_are_never_allowed(risk in any_risk(), c in any_consequence(), e in any_evidence(), killed in any::<bool>()) {
            let p = policy();
            let a = Analysis { risk, ..Analysis::default() };
            let out = decide(GateInput { policy: &p, analysis: &a, consequence: c.as_ref(), evidence: &e, killed });
            if risk == Risk::Forbidden || (killed && risk != Risk::Safe) {
                prop_assert_eq!(out.verdict, Verdict::Block);
            }
        }

        #[test]
        fn while_killed_only_true_reads_pass(c in any_consequence(), e in any_evidence()) {
            let p = policy();
            for code in ["local.dev", "network.read", "memory.write"] {
                let a = Analysis { risk: Risk::Safe, signals: vec![Signal::new(code, "d")], ..Analysis::default() };
                let out = decide(GateInput { policy: &p, analysis: &a, consequence: c.as_ref(), evidence: &e, killed: true });
                prop_assert_eq!(out.verdict, Verdict::Block);
            }
        }

        #[test]
        fn evidence_only_ever_raises(risk in any_risk(), c in any_consequence(), e in any_evidence()) {
            let p = policy();
            let a = Analysis { risk, ..Analysis::default() };
            let without = decide(GateInput { policy: &p, analysis: &a, consequence: c.as_ref(), evidence: &[], killed: false });
            let with = decide(GateInput { policy: &p, analysis: &a, consequence: c.as_ref(), evidence: &e, killed: false });
            prop_assert!(with.verdict >= without.verdict);
        }

        #[test]
        fn llm_evidence_never_reaches_past_ask(risk in any_risk(), c in any_consequence(), e in any_evidence()) {
            let p = policy();
            let a = Analysis { risk, ..Analysis::default() };
            let llm: Vec<Evidence> = e.into_iter().map(|mut x| { x.deterministic = false; x }).collect();
            let without = decide(GateInput { policy: &p, analysis: &a, consequence: c.as_ref(), evidence: &[], killed: false });
            let with = decide(GateInput { policy: &p, analysis: &a, consequence: c.as_ref(), evidence: &llm, killed: false });
            prop_assert!(with.verdict == without.verdict || with.verdict == Verdict::Ask);
        }

        #[test]
        fn unsafe_without_conclusive_simulation_is_at_least_ask(risk in prop_oneof![Just(Risk::Risky), Just(Risk::Ambiguous)], fidelity in any_fidelity(), inconclusive in any::<bool>()) {
            let p = policy();
            let a = Analysis { risk, ..Analysis::default() };
            let c = Consequence { summary: "s".into(), fidelity, inconclusive: inconclusive.then(|| "x".to_string()), ..Consequence::default() };
            let conclusive_run = !inconclusive && fidelity >= Fidelity::Twin;
            let out = decide(GateInput { policy: &p, analysis: &a, consequence: Some(&c), evidence: &[], killed: false });
            if !conclusive_run {
                prop_assert!(out.verdict >= Verdict::Ask);
            }
        }

        #[test]
        fn irreversible_is_never_silently_allowed_by_the_shipped_policy(effects in prop::collection::vec(any_effect(), 1..4), fidelity in any_fidelity()) {
            let p = policy();
            let a = Analysis { risk: Risk::Risky, ..Analysis::default() };
            let c = Consequence { summary: "s".into(), effects: effects.clone(), fidelity, ..Consequence::default() };
            let out = decide(GateInput { policy: &p, analysis: &a, consequence: Some(&c), evidence: &[], killed: false });
            if effects.iter().any(|x| x.irreversible) {
                prop_assert!(out.verdict >= Verdict::Ask);
            }
        }

        #[test]
        fn promises_only_ever_raise(risk in any_risk(), c in any_consequence(), e in any_evidence()) {
            let with = policy();
            let mut without = with.clone();
            without.promises.clear();
            let a = Analysis { risk, ..Analysis::default() };
            let kept = decide(GateInput { policy: &with, analysis: &a, consequence: c.as_ref(), evidence: &e, killed: false });
            let bare = decide(GateInput { policy: &without, analysis: &a, consequence: c.as_ref(), evidence: &e, killed: false });
            prop_assert!(kept.verdict >= bare.verdict);
        }

        #[test]
        fn the_gate_is_deterministic(risk in any_risk(), c in any_consequence(), e in any_evidence(), killed in any::<bool>()) {
            let p = policy();
            let a = Analysis { risk, ..Analysis::default() };
            let input = GateInput { policy: &p, analysis: &a, consequence: c.as_ref(), evidence: &e, killed };
            prop_assert_eq!(decide(input), decide(input));
        }
    }
}
