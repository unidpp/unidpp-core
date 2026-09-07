//! UniDPP transformation algebra (crate `unidpp-transform`).
//!
//! the UniDPP design framework, "Semantic exchange, stamps, and the transformation algebra":
//! - Split (1->N): recorded in the parent's log by its custodian; children
//!   are new passports with `derivedFrom` + quantity carve-outs;
//!   sum(children) <= parent (remainder semantics).
//! - Combine/transformation (N->1): the output passport's issuance event
//!   carries `inputReferences` [(passport, quantity, as-of-state hash)...];
//!   quantities are *new measured facts* with provenance "computed by
//!   transformation event E" — mass balance in - out = loss, auditable —
//!   never copies. Inputs transition to `consumed/transformed`
//!   (historical, still verifiable).
//! - Graph taint: marking a passport fraudulent traverses the provenance
//!   DAG downstream, tainting derived passports; mass-balance accounting
//!   carries taint explicitly.

pub mod combine;
pub mod provenance;
pub mod quantity;
pub mod rng;
pub mod split;
pub mod taint;

pub use combine::{combine, CombineOutcome, CombineSpec, InputReference, StampContextRef};
pub use provenance::ProvenanceGraph;
pub use quantity::{Dimension, Quantity, Unit, UnitDef, UnitRegistry};
pub use rng::Rng;
pub use split::{split, CarveOut, SplitOutcome, SplitSpec};
pub use taint::{Taint, TaintKind, TaintSet};

use std::fmt;

use unidpp_model::{Decimal, ModelError, PassportId};

/// Errors of the transformation algebra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformError {
    UnknownUnit(String),
    DimensionMismatch {
        left: String,
        right: String,
    },
    OverCarve {
        requested: Decimal,
        available: Decimal,
    },
    OverConsumption {
        input: PassportId,
        requested: Decimal,
        available: Decimal,
    },
    NegativeBalance {
        total_in: Decimal,
        output: Decimal,
    },
    Empty(String),
    Registry(String),
    Provenance(String),
    Model(ModelError),
}

impl fmt::Display for TransformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransformError::UnknownUnit(u) => write!(f, "unit `{u}` not registered"),
            TransformError::DimensionMismatch { left, right } => {
                write!(f, "dimension mismatch: {left} vs {right}")
            }
            TransformError::OverCarve { requested, available } => write!(
                f,
                "over-carve: requested {requested} but only {available} available (sum(children) <= parent)"
            ),
            TransformError::OverConsumption {
                input,
                requested,
                available,
            } => write!(
                f,
                "over-consumption of {input}: requested {requested}, available {available}"
            ),
            TransformError::NegativeBalance { total_in, output } => write!(
                f,
                "mass balance violated: in {total_in} < out {output} (in - out = loss >= 0)"
            ),
            TransformError::Empty(m) => write!(f, "{m}"),
            TransformError::Registry(m) => write!(f, "unit registry: {m}"),
            TransformError::Provenance(m) => write!(f, "provenance: {m}"),
            TransformError::Model(e) => write!(f, "model error: {e}"),
        }
    }
}

impl std::error::Error for TransformError {}

impl From<ModelError> for TransformError {
    fn from(e: ModelError) -> TransformError {
        TransformError::Model(e)
    }
}
