//! Narrated demonstration scenarios for the UniDPP core (P4 pilot).
//!
//! Each scenario replays one the UniDPP design framework storyline against the real crates
//! (`unidpp-model`, `unidpp-transform`, `unidpp-event`, `unidpp-tier-a`,
//! `unidpp-verdict`) and prints a step-by-step trace: the event, its
//! commitment, the state change, and a one-line rationale citing the
//! design invariants I1-I14 of `the UniDPP design framework`.
//!
//! Determinism: every timestamp is fixed, every salt is derived from the
//! run seed through [`unidpp_event::salt_from_seed`], and no wall-clock
//! time is read. Two runs with the same seed produce byte-identical
//! output (asserted by the integration tests).
//!
//! Scenarios:
//! - [`battery_loop`]: cells -> pack (combine with as-of state hashes) ->
//!   split harvest -> blind install into a car -> theft taint propagation
//!   -> end-of-waste -> Tier-A packing -> graded verdicts.
//! - [`car`]: parent car passport + battery child passport, blind
//!   installation edge, predicate-based (locally evaluated) recall, and
//!   the as-of verification readings.
//! - [`laptop`]: one neutral core under two jurisdiction profiles (EU
//!   ESPR electronics + JP METI PSE), custody transfer, firmware update,
//!   part replacement, and per-lens coverage verdicts.

pub mod battery_loop;
pub mod car;
pub mod laptop;
pub mod trace;

use std::io::Write;

use unidpp_model::Hash;
use unidpp_verdict::{Degradation, Failure, Outcome, Verdict};

pub use trace::Trace;

/// Names of the available scenarios, in stable order.
pub const SCENARIOS: &[&str] = &["battery-loop", "car", "laptop"];

/// One-line descriptions of the scenarios (for `--list`).
pub const SCENARIO_BLURBS: &[(&str, &str)] = &[
    (
        "battery-loop",
        "cells -> pack (combine) -> split harvest -> blind install -> theft taint \
         -> end-of-waste -> Tier A -> graded verdicts",
    ),
    (
        "car",
        "parent car + battery child passports, blind install edge, predicate-based \
         recall, as-of verification readings",
    ),
    (
        "laptop",
        "one neutral core, EU + JP profiles, custody, firmware update, part replace, \
         per-lens coverage verdicts",
    ),
];

/// Errors of a demonstration run. Write failures are kept distinct from
/// logical failures so the CLI can treat a closed pipe (`... | head`) as
/// a normal end of output rather than an error.
#[derive(Debug)]
pub enum DemoError {
    Msg(String),
    WriteFailed(std::io::Error),
}

impl DemoError {
    pub fn msg(m: impl Into<String>) -> DemoError {
        DemoError::Msg(m.into())
    }

    /// Whether the consumer of the output stream closed it early.
    pub fn is_broken_pipe(&self) -> bool {
        matches!(self, DemoError::WriteFailed(e) if e.kind() == std::io::ErrorKind::BrokenPipe)
    }
}

impl std::fmt::Display for DemoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemoError::Msg(m) => write!(f, "demo failure: {m}"),
            DemoError::WriteFailed(e) => write!(f, "write failure: {e}"),
        }
    }
}

impl std::error::Error for DemoError {}

impl From<std::io::Error> for DemoError {
    fn from(e: std::io::Error) -> DemoError {
        DemoError::WriteFailed(e)
    }
}

/// Run a scenario by name, writing the narrated trace to `out`.
pub fn run(scenario: &str, out: &mut dyn Write, seed: u64) -> Result<(), DemoError> {
    match scenario {
        "battery-loop" => battery_loop::run(out, seed),
        "car" => car::run(out, seed),
        "laptop" => laptop::run(out, seed),
        other => Err(DemoError::msg(format!(
            "unknown scenario `{other}` (available: {})",
            SCENARIOS.join(", ")
        ))),
    }
}

/// First 16 hex characters of a commitment (readable short form).
pub fn short_hash(h: &Hash) -> String {
    format!("{}..", &h.hex()[..16])
}

/// Derive a deterministic, purpose-labelled salt from the run seed.
/// Demo-only: production salts must come from a CSPRNG.
pub fn salt_for(seed: u64, purpose: &[u8]) -> [u8; 32] {
    let mut material = Vec::with_capacity(8 + purpose.len());
    material.extend_from_slice(&seed.to_be_bytes());
    material.extend_from_slice(purpose);
    unidpp_event::salt_from_seed(&material)
}

/// Human-readable rendering of a trigger predicate (the upstream
/// `describe()` leaks `Debug` formatting for fact values).
pub fn fmt_predicate(p: &unidpp_model::TriggerPredicate) -> String {
    use unidpp_model::{FactValue, TriggerPredicate as TP};
    fn val(v: &FactValue) -> String {
        match v {
            FactValue::Str(s) => format!("\"{s}\""),
            FactValue::Num(n) => n.to_string(),
            FactValue::Bool(b) => b.to_string(),
            FactValue::List(l) => format!("[{}]", l.join(", ")),
        }
    }
    fn walk(p: &TP) -> String {
        match p {
            TP::Any => "any".into(),
            TP::All(ps) => {
                format!(
                    "all({})",
                    ps.iter().map(walk).collect::<Vec<_>>().join(" and ")
                )
            }
            TP::AnyOf(ps) => {
                format!(
                    "any-of({})",
                    ps.iter().map(walk).collect::<Vec<_>>().join(" or ")
                )
            }
            TP::Not(p) => format!("not({})", walk(p)),
            TP::FactEq { path, value } => format!("{path} == {}", val(value)),
            TP::FactNe { path, value } => format!("{path} != {}", val(value)),
            TP::FactGt { path, value } => format!("{path} > {}", val(value)),
            TP::FactGe { path, value } => format!("{path} >= {}", val(value)),
            TP::FactLt { path, value } => format!("{path} < {}", val(value)),
            TP::FactLe { path, value } => format!("{path} <= {}", val(value)),
            TP::FactContains { path, needle } => format!("{path} contains \"{needle}\""),
            TP::AgeAtLeast { years } => format!("age >= {years}y"),
            TP::MarketStatusIs { status } => format!("market-status == {status}"),
        }
    }
    walk(p)
}

/// Human-readable rendering of a verdict outcome on the degradation
/// ladder (I9/I13: pass / degraded-with-reason / fail — never a bare
/// boolean).
pub fn fmt_outcome(v: &Verdict) -> String {
    match &v.outcome {
        Outcome::Pass => "PASS".to_string(),
        Outcome::Degraded(d) => format!("DEGRADED ({})", fmt_degradation(d)),
        Outcome::Fail(f) => format!("FAIL ({})", fmt_failure(f)),
    }
}

fn fmt_degradation(d: &Degradation) -> String {
    match d {
        Degradation::StaleData { as_of } => {
            format!("stale-data as-of {as_of}")
        }
        Degradation::NoFreshnessEvidence => "no-freshness-evidence".to_string(),
        Degradation::OfflineNoAnchor => "offline-no-anchor".to_string(),
        Degradation::SignaturesFramedOnly => "signatures-framed-only".to_string(),
        Degradation::CoverageIncomplete { missing } => {
            format!("coverage-incomplete, missing {missing:?}")
        }
    }
}

fn fmt_failure(f: &Failure) -> String {
    match f {
        Failure::BrokenChain => "broken-chain".to_string(),
        Failure::AnchorMismatch => "anchor-mismatch".to_string(),
    }
}

/// Print a verdict block: reading answered, freshness, coverage, trust
/// marker, and the ladder outcome.
pub fn print_verdict(tr: &mut Trace<'_>, label: &str, v: &Verdict) -> Result<(), DemoError> {
    tr.kv(
        label,
        &format!(
            "reading {}; freshness {}; coverage {}/{}; trust {}; outcome {}",
            v.reading_answered.as_str(),
            v.freshness.label(),
            v.evidentiary.coverage.present.len(),
            v.evidentiary.coverage.required.len(),
            v.trust_marker.as_str(),
            fmt_outcome(v),
        ),
    )?;
    if v.current_state.voids_ab_initio {
        tr.kv(
            "  current state",
            "VOIDS AB INITIO: retroactive taint present (fraud laundering prevented)",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hash_is_stable() {
        let h = unidpp_model::sha256(&[b"x"]);
        assert_eq!(short_hash(&h).len(), 18);
        assert_eq!(short_hash(&h), short_hash(&h));
    }

    #[test]
    fn unknown_scenario_is_an_error() {
        let mut buf: Vec<u8> = Vec::new();
        let err = run("nope", &mut buf, 0).unwrap_err();
        assert!(err.to_string().contains("unknown scenario"));
        assert!(!err.is_broken_pipe());
    }

    #[test]
    fn scenarios_and_blurbs_agree() {
        assert_eq!(SCENARIOS.len(), SCENARIO_BLURBS.len());
        for (i, name) in SCENARIOS.iter().enumerate() {
            assert_eq!(SCENARIO_BLURBS[i].0, *name);
        }
    }
}
