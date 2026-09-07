//! Tier-A packer (invariant I13: degradation ladder).
//!
//! Tier A is the carrier-embedded minimum viable passport: product ID,
//! resolver URI, passport ID, EO ID, status, critical safety/recall flag,
//! validity, as-of stamp, log head, and multi-suite compressed signature
//! framing (ECDSA / SM2 / ML-DSA), sized to EN 18220-style carriers via a
//! QR byte-capacity model (ISO/IEC 18004). Stale/offline data degrades
//! explicitly (freshness verdicts live in `unidpp-verdict`), never
//! silently passes.

pub mod packer;
pub mod payload;
pub mod qr;

pub use packer::{PackedTierA, TierAPacker};
pub use payload::TierAPayload;
pub use qr::{byte_capacity, min_version_for, EcLevel};

/// Errors of the Tier-A packer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierAError {
    /// The projected payload (with signature reserves) exceeds the
    /// carrier capacity at the configured EC level / max version.
    OverBudget {
        projected: usize,
        capacity: u32,
        ec: crate::qr::EcLevel,
        max_version: u8,
    },
    Decode(String),
    Encode(String),
    Model(unidpp_model::ModelError),
}

impl std::fmt::Display for TierAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TierAError::OverBudget {
                projected,
                capacity,
                ec,
                max_version,
            } => write!(
                f,
                "Tier-A payload projects to {projected} bytes but the QR carrier holds at most \
                 {capacity} bytes (EC {ec}, version <= {max_version}): shrink the resolver URI or \
                 drop signature suites"
            ),
            TierAError::Decode(m) => write!(f, "Tier-A decode failure: {m}"),
            TierAError::Encode(m) => write!(f, "Tier-A encode failure: {m}"),
            TierAError::Model(e) => write!(f, "model error: {e}"),
        }
    }
}

impl std::error::Error for TierAError {}

impl From<unidpp_model::ModelError> for TierAError {
    fn from(e: unidpp_model::ModelError) -> TierAError {
        TierAError::Model(e)
    }
}
