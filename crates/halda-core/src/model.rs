//! The vocabulary shared by every part of Halda.

use crate::canon;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The five answers Halda can give. The order is severity: the gate may only
/// ever move a verdict rightwards when it combines inputs.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Run it.
    Allow,
    /// Run a corrected version (for example with a secret redacted).
    Fix,
    /// Wait for a human.
    #[default]
    Ask,
    /// Refuse, and tell the agent how to do it safely.
    Retry,
    /// Refuse.
    Block,
}

impl Verdict {
    /// Lower-case name used in logs and on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Fix => "fix",
            Verdict::Ask => "ask",
            Verdict::Retry => "retry",
            Verdict::Block => "block",
        }
    }
}

/// Who is acting and for whom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Actor {
    /// The agent, such as `claude-code`.
    pub agent: String,
    /// The person whose login the agent is using.
    pub principal: String,
    /// The machine it is running on.
    #[serde(default)]
    pub host: String,
    /// The agent's session id.
    #[serde(default)]
    pub session: String,
    /// Delegation chain, outermost first: `["claude-code", "subagent:reviewer"]`.
    #[serde(default)]
    pub chain: Vec<String>,
    /// True when `agent` was confirmed from the process tree rather than taken
    /// from what the caller claimed.
    #[serde(default)]
    pub attested: bool,
}

impl Actor {
    /// "claude-code, working for jordan"
    pub fn label(&self) -> String {
        format!("{}, working for {}", self.agent, self.principal)
    }
}

/// A tool call an agent proposes to make.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActionRequest {
    /// Who proposes it.
    pub actor: Actor,
    /// Tool name, such as `Bash`, `Write` or `mcp__postgres__query`.
    pub tool: String,
    /// Tool arguments, as the agent sent them.
    pub input: Value,
    /// Working directory.
    #[serde(default)]
    pub cwd: String,
    /// What the agent was asked to do, when known. Used by the Grader.
    #[serde(default)]
    pub task: Option<String>,
}

impl ActionRequest {
    /// Identifies this exact action. An approval is bound to this value, so any
    /// change to the tool, arguments or directory voids it.
    pub fn fingerprint(&self) -> String {
        canon::hash_canonical(&json!({
            "tool": self.tool,
            "input": self.input,
            "cwd": self.cwd,
        }))
        .unwrap_or_default()
    }

    /// The action as written, for people to read. Not redacted.
    pub fn display_text(&self) -> String {
        match self.shell_command() {
            Some(command) => command.to_string(),
            None => format!("{} {}", self.tool, self.input),
        }
    }

    /// The shell command, when this action is one.
    pub fn shell_command(&self) -> Option<&str> {
        self.input.get("command").and_then(Value::as_str)
    }
}

/// What the fixed rules concluded before any simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    /// Read-only or local development. Takes the fast path.
    Safe,
    /// Known to change something that matters. Must be simulated.
    Risky,
    /// Could not be understood. Treated as risky, never as safe.
    #[default]
    Ambiguous,
    /// Must never happen, whatever a simulation says.
    Forbidden,
}

/// Which simulator understands this action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Domain {
    /// No specific system.
    #[default]
    None,
    /// A shell command with no better simulator.
    Shell,
    /// Terraform or OpenTofu.
    Terraform,
    /// SQL against a database.
    Sql,
    /// Git history.
    Git,
    /// A cloud or cluster control plane (AWS, GCP, Azure, Kubernetes).
    Cloud,
    /// Stripe.
    Stripe,
    /// GitHub.
    Github,
    /// Files on disk.
    File,
    /// Outbound network traffic.
    Network,
    /// Shared agent memory.
    Memory,
    /// A third-party MCP tool.
    Mcp,
}

/// A single fact the analyzer established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// Stable machine-readable code, such as `exfil.secret_to_network`.
    pub code: String,
    /// Plain-English explanation.
    pub detail: String,
}

impl Signal {
    /// Builds a signal.
    pub fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            detail: detail.into(),
        }
    }
}

/// Result of static analysis of an action.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Analysis {
    /// Fixed-rule classification.
    pub risk: Risk,
    /// Simulator to route to.
    pub domain: Domain,
    /// Why.
    pub signals: Vec<Signal>,
    /// The action in normal form: shell wrappers removed, quoting resolved.
    /// Rewordings of one command normalize to the same string.
    pub normalized: String,
    /// SQL statements found in the action, for the database simulator.
    #[serde(default)]
    pub sql: Vec<String>,
    /// A corrected tool input, when one can be produced deterministically.
    #[serde(default)]
    pub fixed_input: Option<Value>,
}

impl Analysis {
    /// True only for actions that change nothing and send nothing. Narrower than
    /// [`Risk::Safe`], which also covers local builds and tests: those are fine in
    /// normal running, and not while Halda is stopped or down.
    pub fn is_read_only(&self) -> bool {
        const CHANGES_OR_SENDS: &[&str] = &["local.dev", "network.read", "memory.write"];
        self.risk == Risk::Safe
            && !self
                .signals
                .iter()
                .any(|s| CHANGES_OR_SENDS.contains(&s.code.as_str()))
    }

    /// True if a signal with this code was raised.
    pub fn has_signal(&self, code: &str) -> bool {
        self.signals.iter().any(|s| s.code == code)
    }
}

/// How much a consequence can be trusted, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Fidelity {
    /// Nothing was simulated.
    #[default]
    None,
    /// Read from the action's text only.
    Static,
    /// Read from a recorded plan, not produced just now.
    Recorded,
    /// Run against a stateful twin of an API.
    Twin,
    /// Produced by the real tool's planner (`terraform plan`).
    Planned,
    /// Actually executed against a copy (database branch, sandboxed files).
    Executed,
}

/// What an effect does to its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EffectVerb {
    /// Reads data.
    Read,
    /// Creates something new.
    Create,
    /// Changes something in place.
    Modify,
    /// Destroys something.
    Delete,
    /// Destroys and recreates something.
    Replace,
    /// Sends data out of the company.
    Send,
    /// Moves money.
    Charge,
    /// Runs code somewhere else.
    Execute,
}

/// Where the target lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Production.
    Production,
    /// Staging, development or a sandbox.
    Nonproduction,
    /// Could not be determined. Rules treat this as production unless they say otherwise.
    #[default]
    Unknown,
}

/// One observed result of a simulated action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    /// What happens.
    pub verb: EffectVerb,
    /// Broad type: `database`, `snapshot`, `table`, `rows`, `file`, `commit`, `refund` ...
    pub kind: String,
    /// The specific target: `aws_db_instance.prod`, `orders`, `main`.
    pub target: String,
    /// How many of `kind` are affected.
    pub count: u64,
    /// Where the target lives.
    #[serde(default)]
    pub environment: Environment,
    /// True if this cannot be undone.
    #[serde(default)]
    pub irreversible: bool,
}

/// What an action would do, according to a simulator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Consequence {
    /// The effect in plain words: the sentence a human reads in Slack.
    pub summary: String,
    /// Structured effects the policy evaluates.
    pub effects: Vec<Effect>,
    /// How this was obtained.
    pub fidelity: Fidelity,
    /// Which simulator produced it.
    pub simulator: String,
    /// Set when the simulator could not reach a conclusion. The gate never
    /// allows on an inconclusive consequence.
    #[serde(default)]
    pub inconclusive: Option<String>,
    /// Wall-clock simulation time.
    #[serde(default)]
    pub duration_ms: u64,
}

impl Consequence {
    /// An explicit "I could not tell" from a simulator.
    pub fn inconclusive(simulator: &str, why: impl Into<String>) -> Self {
        let why = why.into();
        Self {
            summary: format!("Could not determine the effect: {why}"),
            simulator: simulator.to_string(),
            inconclusive: Some(why),
            ..Self::default()
        }
    }

    /// A stable hash of what the action would do. Timing is excluded, so the
    /// same effect re-simulated gives the same value. An approval is void if
    /// this changes between the approval and the run.
    pub fn fingerprint(&self) -> String {
        canon::hash_canonical(&json!({
            "effects": self.effects,
            "fidelity": self.fidelity,
            "inconclusive": self.inconclusive,
        }))
        .unwrap_or_default()
    }
}

/// How strongly a sub-agent feels about its finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// For the record.
    #[default]
    Info,
    /// Worth surfacing to a human reviewer.
    Warn,
    /// A human should look before this runs.
    High,
    /// This should stop.
    Critical,
}

/// A sub-agent's finding. Evidence, never an instruction: the gate reads
/// `severity` and nothing in `finding` can change a decision.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Evidence {
    /// Which sub-agent.
    pub agent: String,
    /// How serious.
    pub severity: Severity,
    /// Plain-English finding. Shown to humans, never parsed.
    pub finding: String,
    /// True when computed by fixed logic. Evidence from an LLM has this false
    /// and can raise a decision at most to [`Verdict::Ask`].
    #[serde(default)]
    pub deterministic: bool,
}

/// The core's answer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Decision {
    /// Unique id of this decision.
    pub id: String,
    /// What the policy decided.
    pub verdict: Verdict,
    /// What actually applies: differs from `verdict` only in watch mode.
    pub enforced: Verdict,
    /// Why, in plain words.
    pub reason: String,
    /// The policy rule that produced this, if any.
    pub rule: Option<String>,
    /// Safe way forward, from the Advisor.
    #[serde(default)]
    pub guidance: Option<String>,
    /// Corrected tool input when the verdict is `fix`.
    #[serde(default)]
    pub fixed_input: Option<Value>,
    /// Who.
    pub actor: Actor,
    /// Normal form of the action, as Halda understood it.
    pub normalized: String,
    /// The action as the agent wrote it, with secrets removed. This is what a
    /// person reads: the normal form is an interpretation, and can be wrong.
    #[serde(default)]
    pub original: String,
    /// Fingerprint the approval binds to.
    pub action_fingerprint: String,
    /// Static analysis result.
    pub analysis: Analysis,
    /// Simulated effect, if simulated.
    pub consequence: Option<Consequence>,
    /// What the sub-agents found.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Open approval, when the verdict is `ask`.
    #[serde(default)]
    pub approval_id: Option<String>,
    /// A one-action credential lease granted with this decision.
    #[serde(default)]
    pub lease_id: Option<String>,
    /// How long the decision took, end to end.
    #[serde(default)]
    pub duration_ms: u64,
    /// When it was made, in Unix milliseconds.
    #[serde(default)]
    pub at_ms: u64,
}
