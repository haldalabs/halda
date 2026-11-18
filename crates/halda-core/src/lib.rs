//! The deterministic core of Halda.
//!
//! Everything in this crate is a pure function of its inputs: no network, no
//! filesystem, no clock, no LLM. That is the property the rest of the product
//! rests on. Sub-agents produce [`model::Evidence`]; only [`gate::decide`] turns
//! evidence and simulated consequences into a [`model::Verdict`].

pub mod canon;
pub mod gate;
pub mod model;
pub mod otel;
pub mod policy;
pub mod receipt;
pub mod redact;

pub use gate::{decide, GateInput, GateOutcome};
pub use model::*;
pub use policy::Policy;
