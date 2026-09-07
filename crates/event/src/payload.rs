//! Typed event payloads: one struct variant per event class, with
//! blind-edge support for installations.

use std::collections::BTreeMap;

use unidpp_model::{
    Decimal, Hash, InstallMethod, Interval, Pairing, PassportId, PassportLink, ProfileId,
    Recoverability, Timestamp, TriggerPredicate, TrustMarker, VisibilityClass,
};
use unidpp_transform::{CarveOut, InputReference, Quantity};

use crate::commitment::parent_commitment;
use crate::event_type::EventType;
use crate::status::{can_transition, Status};
use crate::EventError;

unidpp_model::str_enum! {
    /// Outcome of an uninstall (part replacement = uninstall + install).
    pub enum UninstallOutcome {
        Harvested => "harvested",
        Destroyed => "destroyed",
        Reused => "reused",
    }
}

unidpp_model::str_enum! {
    /// Repair authorization class (E3).
    pub enum RepairAuthorization {
        Authorized => "authorized",
        Independent => "independent",
        Diy => "diy",
    }
}

unidpp_model::str_enum! {
    /// Disclosure ceremony for escrowed blind edges.
    pub enum DisclosureCeremony {
        Court => "court",
        Regulator => "regulator",
        Consent => "consent",
    }
}

unidpp_model::str_enum! {
    /// Stamp mode (lens-scoped attestation).
    pub enum StampMode {
        Live => "live",
        Snapshot => "snapshot",
    }
}

/// Security flag kind (E12). `Other` carries a free description.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SecurityFlagKind {
    Known(KnownSecurityFlag),
    Other(String),
}

unidpp_model::str_enum! {
    /// Known security flag kinds.
    pub enum KnownSecurityFlag {
        Theft => "theft",
        Loss => "loss",
    }
}

impl From<KnownSecurityFlag> for SecurityFlagKind {
    fn from(k: KnownSecurityFlag) -> SecurityFlagKind {
        SecurityFlagKind::Known(k)
    }
}

impl SecurityFlagKind {
    pub fn as_str(&self) -> String {
        match self {
            SecurityFlagKind::Known(k) => k.as_str().to_string(),
            SecurityFlagKind::Other(s) => {
                format!("other:{}", unidpp_model::normalization::normalize_token(s))
            }
        }
    }
}

/// A lens-scoped attestation (stamp): attester signature over
/// {subject, subject state commitment, lens ID+version, mode
/// (live/snapshot), verdict + coverage report, log-anchored time}. Stamps
/// accrete append-only and may carry quantity context inherited by
/// downstream transformations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Stamp {
    pub attester: String,
    pub subject: PassportId,
    pub subject_state_commitment: Hash,
    pub lens: ProfileId,
    pub lens_version: String,
    pub mode: StampMode,
    pub verdict_summary: Option<String>,
    pub coverage_report: Option<Hash>,
    pub log_anchored_at: Timestamp,
    pub quantity_context: Option<Quantity>,
}

/// Opaque escrow envelope held by a threshold trustee.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EscrowEnvelope {
    pub trustee: String,
    pub envelope: Vec<u8>,
}

/// Blind installation reference: a salted commitment to the parent (+
/// optional escrow envelope). The parent identity and the salt are never
/// stored here — proof-of-binding without knowledge-of-parent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlindInstallRef {
    pub commitment: Hash,
    pub escrow: Option<EscrowEnvelope>,
    pub interval: Interval,
    pub slot_id: Option<String>,
    pub pairing: Pairing,
    pub recoverability: Recoverability,
    pub method: InstallMethod,
}

/// Parameter object for [`EventPayload::blind_install`]: everything the
/// blind edge records besides the (consumed) parent identity and salt.
#[derive(Debug, Clone)]
pub struct BlindInstallSpec {
    pub interval: Interval,
    pub method: InstallMethod,
    pub recoverability: Recoverability,
    pub pairing: Pairing,
    pub slot_id: Option<String>,
    pub escrow: Option<EscrowEnvelope>,
}

/// Installation target: open edge (full link) or blind edge.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InstallTarget {
    Open(PassportLink),
    Blind(BlindInstallRef),
}

/// Payloads: nothing is ever edited in place; every change is an
/// appended, typed event.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum EventPayload {
    Issuance {
        derived: bool,
        /// `inputReferences` for derived (combine) issuance.
        inputs: Vec<InputReference>,
    },
    CustodyTransfer {
        from: String,
        to: String,
        counterparty_signed: bool,
    },
    Split {
        carve_outs: Vec<CarveOut>,
        remainder: Quantity,
        parent_consumed: bool,
    },
    Combine {
        inputs: Vec<InputReference>,
        output_quantity: Quantity,
        loss: Quantity,
    },
    EndOfWaste {
        evidence_ref: String,
        outputs: Vec<CarveOut>,
    },
    Decompose {
        outputs: Vec<CarveOut>,
        accredited_for_claims: bool,
    },
    Install {
        target: InstallTarget,
    },
    Uninstall {
        link: PassportLink,
        outcome: UninstallOutcome,
    },
    PartReplace {
        removed: PassportId,
        added: PassportId,
        like_for_like: bool,
    },
    ConsumableReplace {
        removed: PassportId,
        added: PassportId,
    },
    RepairPerform {
        authorization: RepairAuthorization,
        consumed_parts: Vec<PassportId>,
    },
    ProductModify {
        description: String,
        /// May spawn a derived type (E4b).
        derived_type: Option<String>,
        /// Modifications trigger profile re-evaluation.
        reevaluation_required: bool,
    },
    SoftwareUpdate {
        versions: BTreeMap<String, String>,
        unlocked_features: Vec<String>,
    },
    RefurbishRemanufacture {
        remanufacture: bool,
        condition_grade: String,
    },
    RecallCampaign {
        campaign: String,
        /// The recall set is never enumerated centrally: the predicate is
        /// published; each custodian evaluates it locally.
        predicate: TriggerPredicate,
    },
    Correction {
        field: String,
        prior_value: String,
        new_value: String,
        reason: String,
    },
    StatusChange {
        from: Status,
        to: Status,
        authority: String,
    },
    FlagSecurity {
        kind: SecurityFlagKind,
        reference: String,
    },
    InspectionStamp {
        stamp: Stamp,
    },
    MilestoneRecord {
        counters: BTreeMap<String, Decimal>,
    },
    EdgeVisibilityChange {
        link_to: PassportId,
        new_visibility: VisibilityClass,
        ceremony: Option<String>,
    },
    EscrowDisclosure {
        commitment_seq: u64,
        disclosed_to: String,
        ceremony: DisclosureCeremony,
    },
}

impl EventPayload {
    /// The event class this payload belongs to (type agreement is
    /// enforced by [`TypedEvent::new`]).
    pub fn event_type(&self) -> EventType {
        match self {
            EventPayload::Issuance { .. } => EventType::Issuance,
            EventPayload::CustodyTransfer { .. } => EventType::CustodyTransfer,
            EventPayload::Split { .. } => EventType::Split,
            EventPayload::Combine { .. } => EventType::Combine,
            EventPayload::EndOfWaste { .. } => EventType::EndOfWaste,
            EventPayload::Decompose { .. } => EventType::Decompose,
            EventPayload::Install { .. } => EventType::Install,
            EventPayload::Uninstall { .. } => EventType::Uninstall,
            EventPayload::PartReplace { .. } => EventType::PartReplace,
            EventPayload::ConsumableReplace { .. } => EventType::ConsumableReplace,
            EventPayload::RepairPerform { .. } => EventType::RepairPerform,
            EventPayload::ProductModify { .. } => EventType::ProductModify,
            EventPayload::SoftwareUpdate { .. } => EventType::SoftwareUpdate,
            EventPayload::RefurbishRemanufacture { .. } => EventType::RefurbishRemanufacture,
            EventPayload::RecallCampaign { .. } => EventType::RecallCampaign,
            EventPayload::Correction { .. } => EventType::Correction,
            EventPayload::StatusChange { .. } => EventType::StatusChange,
            EventPayload::FlagSecurity { .. } => EventType::FlagSecurity,
            EventPayload::InspectionStamp { .. } => EventType::InspectionStamp,
            EventPayload::MilestoneRecord { .. } => EventType::MilestoneRecord,
            EventPayload::EdgeVisibilityChange { .. } => EventType::EdgeVisibilityChange,
            EventPayload::EscrowDisclosure { .. } => EventType::EscrowDisclosure,
        }
    }

    /// Build a blind installation payload. The parent identity and the
    /// salt are consumed here and appear only as `H(salt || parent)` in
    /// the stored payload.
    pub fn blind_install(
        parent: &PassportId,
        salt: &[u8; 32],
        spec: BlindInstallSpec,
    ) -> EventPayload {
        EventPayload::Install {
            target: InstallTarget::Blind(BlindInstallRef {
                commitment: parent_commitment(parent, salt),
                escrow: spec.escrow,
                interval: spec.interval,
                slot_id: spec.slot_id,
                pairing: spec.pairing,
                recoverability: spec.recoverability,
                method: spec.method,
            }),
        }
    }

    /// Build an open installation payload (visible parent edge).
    pub fn open_install(link: PassportLink) -> Result<EventPayload, EventError> {
        if let Err(e) = link.validate() {
            return Err(EventError::Serialization(e.to_string()));
        }
        Ok(EventPayload::Install {
            target: InstallTarget::Open(link),
        })
    }
}

/// A typed event with its trust marker. The canonical body (what the
/// commitment hashes) is the deterministic JSON serialization of this
/// value: struct fields in declaration order, sorted maps, integer and
/// string scalars only.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TypedEvent {
    pub seq: u64,
    pub occurred_at: Timestamp,
    pub actor_role: String,
    pub actor_id: String,
    pub event_type: EventType,
    pub payload: EventPayload,
    pub trust: TrustMarker,
}

impl TypedEvent {
    pub fn new(
        seq: u64,
        occurred_at: Timestamp,
        actor_role: &str,
        actor_id: &str,
        event_type: EventType,
        payload: EventPayload,
        trust: TrustMarker,
    ) -> Result<TypedEvent, EventError> {
        let declared = payload.event_type();
        if declared != event_type {
            return Err(EventError::TypeMismatch {
                event: event_type.to_string(),
                payload: declared.to_string(),
            });
        }
        if let EventPayload::StatusChange { from, to, .. } = &payload {
            if !can_transition(*from, *to) {
                return Err(EventError::IllegalTransition {
                    from: *from,
                    to: *to,
                });
            }
        }
        Ok(TypedEvent {
            seq,
            occurred_at,
            actor_role: actor_role.to_string(),
            actor_id: actor_id.to_string(),
            event_type,
            payload,
            trust,
        })
    }

    /// Deterministic canonical body for commitment hashing.
    pub fn canonical_body(&self) -> Result<Vec<u8>, EventError> {
        serde_json::to_vec(self).map_err(|e| EventError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_agreement_enforced() {
        let err = TypedEvent::new(
            0,
            Timestamp::from_secs(1),
            "custodian",
            "actor-1",
            EventType::Split,
            EventPayload::CustodyTransfer {
                from: "a".into(),
                to: "b".into(),
                counterparty_signed: true,
            },
            TrustMarker::Unsigned,
        )
        .unwrap_err();
        assert!(matches!(err, EventError::TypeMismatch { .. }));
    }

    #[test]
    fn illegal_transitions_rejected_at_construction() {
        let err = TypedEvent::new(
            0,
            Timestamp::from_secs(1),
            "regulator",
            "reg-1",
            EventType::StatusChange,
            EventPayload::StatusChange {
                from: Status::Invalidated,
                to: Status::Issued,
                authority: "reg".into(),
            },
            TrustMarker::Attested,
        )
        .unwrap_err();
        assert!(matches!(err, EventError::IllegalTransition { .. }));
    }

    #[test]
    fn blind_install_never_stores_parent() {
        let parent = PassportId::new("urn:unidpp:passport:car-secret").unwrap();
        let salt = [7u8; 32];
        let payload = EventPayload::blind_install(
            &parent,
            &salt,
            BlindInstallSpec {
                interval: Interval::starting(Timestamp::from_secs(10)),
                method: InstallMethod::Known(unidpp_model::KnownMethod::Keyed),
                recoverability: Recoverability::Harvestable,
                pairing: Pairing::Firmware,
                slot_id: Some("slot-1".into()),
                escrow: None,
            },
        );
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains(parent.as_str()), "parent leaked: {json}");
        assert!(!json.contains("07070707"), "salt leaked: {json}");
        let rt: EventPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, payload);
        if let EventPayload::Install {
            target: InstallTarget::Blind(b),
        } = &rt
        {
            assert!(crate::commitment::verify_parent_binding(
                &parent,
                &salt,
                &b.commitment
            ));
        } else {
            panic!("expected blind install");
        }
    }
}
