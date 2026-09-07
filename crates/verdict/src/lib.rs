//! Graded verification (invariant I9 / I13).
//!
//! Three verification readings, because law needs all three (PLAN.md):
//! - *evidentiary*: what could a diligent verifier know at T, given the
//!   then-current trust state — protects good-faith actors; their stamps
//!   are the proof of diligence;
//! - *current-state*: fraud voids ab initio — prevents laundering
//!   fraudulent goods (taint propagates through the graph);
//! - *cryptographic*: signature/chain validity alone.
//!
//! Verdicts state which reading they answer. Coverage reports are
//! first-class (never a boolean). Freshness verdicts degrade explicitly:
//! stale/offline data never silently passes.

pub mod coverage;
pub mod freshness;
pub mod readings;
pub mod verdict;

pub use coverage::CoverageReport;
pub use freshness::{evaluate_freshness, FreshnessVerdict};
pub use readings::{CryptographicReading, CurrentStateReading, EvidentiaryReading, SigStatus};
pub use verdict::{Degradation, Failure, Outcome, Reading, Verdict, VerdictBuilder};
