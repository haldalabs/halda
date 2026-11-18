//! The fast path: fixed rules that say what an action really is, in microseconds.
//!
//! The analyzer never allows anything that it does not positively recognize as
//! read-only or local. Anything else goes on to simulation. Its output is
//! [`halda_core::Analysis`], and it is a pure function of the action.

pub mod classify;
pub mod memory;
pub mod paths;
pub mod shell;
pub mod sql;
pub mod tool;

pub use tool::analyze;
