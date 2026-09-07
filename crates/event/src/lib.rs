//! UniDPP event crate: typed post-sale events, the append-only
//! hash-chained event log, and salted commitments with blind-edge
//! support.
//!
//! the UniDPP design framework invariants implemented here:
//! - I4 append-only event sourcing: the distributed, log-anchored event
//!   log is the authoritative record; nothing is ever edited in place —
//!   every post-first-sale change is an appended event.
//! - I12 enumeration resistance: logs anchor commitments (hashes), never
//!   facts; blind edges by default where households/sites are revealed;
//!   proof-of-binding != knowledge-of-parent.
//! - The post-sale event taxonomy (E1-E15) plus the transformation
//!   vocabulary (custody / split / combine / install / uninstall / stamp /
//!   correction / status change / flag / decompose / end-of-waste) and
//!   the edge-visibility classes.

pub mod commitment;
pub mod event_type;
pub mod log;
pub mod payload;
pub mod status;

pub use commitment::{event_commitment, parent_commitment, salt_from_seed, verify_parent_binding};
pub use event_type::EventType;
pub use log::{EventLog, SaltStore, SealedEvent};
pub use payload::{
    BlindInstallRef, BlindInstallSpec, DisclosureCeremony, EscrowEnvelope, EventPayload,
    InstallTarget, RepairAuthorization, SecurityFlagKind, Stamp, StampMode, TypedEvent,
    UninstallOutcome,
};
pub use status::{can_transition, Status};

use std::fmt;

/// Errors of the event crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    /// The hash chain does not verify at this sequence number.
    ChainBroken { seq: u64 },
    /// The log head does not match the transparency anchor.
    AnchorMismatch { expected: String, actual: String },
    /// Non-monotonic append (append-only, no gaps).
    Seq { expected: u64, got: u64 },
    /// Payload variant does not match the event class.
    TypeMismatch { event: String, payload: String },
    /// Illegal state-machine transition (I6).
    IllegalTransition { from: Status, to: Status },
    /// Serialization failure.
    Serialization(String),
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventError::ChainBroken { seq } => {
                write!(f, "hash chain broken at event {seq}")
            }
            EventError::AnchorMismatch { expected, actual } => write!(
                f,
                "log head does not match anchor: expected {expected}, got {actual}"
            ),
            EventError::Seq { expected, got } => write!(
                f,
                "append-only violation: expected seq {expected}, got {got}"
            ),
            EventError::TypeMismatch { event, payload } => {
                write!(
                    f,
                    "payload `{payload}` does not match event class `{event}`"
                )
            }
            EventError::IllegalTransition { from, to } => {
                write!(f, "illegal status transition {from} -> {to}")
            }
            EventError::Serialization(m) => write!(f, "serialization failure: {m}"),
        }
    }
}

impl std::error::Error for EventError {}

unidpp_model::str_enum! {
    /// Critical safety / recall flag carried on Tier-A payloads.
    pub enum SafetyFlag {
        None => "none",
        RecallActive => "recall-active",
        SecurityFlagged => "security-flagged",
    }
}
