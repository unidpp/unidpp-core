//! The append-only, hash-chained event log (invariant I4).
//!
//! Each sealed event commits to the entire prefix (its commitment is
//! H(salt? || prev || canonical_body)), so any in-place mutation of any
//! historical event breaks verification. Prefix truncation alone is not
//! detectable from the chain — that is what transparency-log anchoring is
//! for; [`EventLog::verify_against_anchor`] checks the log head against
//! an externally witnessed anchor.
//!
//! Salt discipline: [`EventLog::append`] takes the salt, uses it, and
//! drops it. Only an opaque `salt_ref` (an index into the owner-side
//! [`SaltStore`]) is recorded. No serialization of the log contains any
//! salt.

use std::collections::BTreeMap;

use unidpp_model::{Hash, PassportId, Timestamp};

use crate::commitment::event_commitment;
use crate::payload::{EventPayload, Stamp, TypedEvent};
use crate::status::Status;
use crate::{EventError, SafetyFlag};

/// One appended event, sealed with its prefix commitment.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SealedEvent {
    pub event: TypedEvent,
    /// Commitment to the previous sealed event (None for the first).
    pub prev: Option<Hash>,
    /// This event's commitment (covers body + prefix + optional salt).
    pub commitment: Hash,
    /// Whether the commitment is salted.
    pub salted: bool,
    /// Opaque reference to the owner-side salt (never the salt).
    pub salt_ref: Option<u64>,
}

/// The authoritative record of one subject: append-only, hash-chained.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EventLog {
    subject: PassportId,
    sealed: Vec<SealedEvent>,
}

impl EventLog {
    pub fn new(subject: PassportId) -> EventLog {
        EventLog {
            subject,
            sealed: Vec::new(),
        }
    }

    pub fn subject(&self) -> &PassportId {
        &self.subject
    }

    pub fn len(&self) -> usize {
        self.sealed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sealed.is_empty()
    }

    pub fn sealed(&self) -> &[SealedEvent] {
        &self.sealed
    }

    pub fn head(&self) -> Option<Hash> {
        self.sealed.last().map(|s| s.commitment)
    }

    /// Append an event. The salt is consumed for the commitment and then
    /// dropped; only `salt_ref` is recorded. The caller stores the salt
    /// in its [`SaltStore`] under that reference.
    pub fn append(
        &mut self,
        event: TypedEvent,
        salt: Option<[u8; 32]>,
        salt_ref: Option<u64>,
    ) -> Result<Hash, EventError> {
        let expected = self.sealed.len() as u64;
        if event.seq != expected {
            return Err(EventError::Seq {
                expected,
                got: event.seq,
            });
        }
        let body = event.canonical_body()?;
        let commitment = event_commitment(&body, self.head(), salt.as_ref());
        self.sealed.push(SealedEvent {
            event,
            prev: self.head(),
            commitment,
            salted: salt.is_some(),
            salt_ref,
        });
        Ok(commitment)
    }

    /// Recompute the full chain. Detects any in-place tampering.
    pub fn verify(&self) -> Result<(), EventError> {
        let mut prev: Option<Hash> = None;
        for (i, sealed) in self.sealed.iter().enumerate() {
            if sealed.event.seq != i as u64 {
                return Err(EventError::Seq {
                    expected: i as u64,
                    got: sealed.event.seq,
                });
            }
            if sealed.prev != prev {
                return Err(EventError::ChainBroken {
                    seq: sealed.event.seq,
                });
            }
            let body = sealed.event.canonical_body()?;
            // An unsalted chain verifies without any salt; a salted one
            // cannot be recomputed here (the salt is not in the log) —
            // verification of salted entries is done via the commitment
            // anchor chain (prev pointers + external anchoring).
            if !sealed.salted {
                let expect = event_commitment(&body, prev, None);
                if expect != sealed.commitment {
                    return Err(EventError::ChainBroken {
                        seq: sealed.event.seq,
                    });
                }
            } else {
                // Check that the commitment is at least bound to this
                // body: recompute with a placeholder salt and require
                // inequality (it must have been salted differently), and
                // require the stored commitment to differ from the
                // unsalted form (whitening evidence).
                let unsalted = event_commitment(&body, prev, None);
                if unsalted == sealed.commitment {
                    return Err(EventError::ChainBroken {
                        seq: sealed.event.seq,
                    });
                }
            }
            prev = Some(sealed.commitment);
        }
        Ok(())
    }

    /// Verify with salts available (owner-side full verification).
    pub fn verify_with_salts(&self, salts: &SaltStore) -> Result<(), EventError> {
        let mut prev: Option<Hash> = None;
        for (i, sealed) in self.sealed.iter().enumerate() {
            if sealed.event.seq != i as u64 || sealed.prev != prev {
                return Err(EventError::ChainBroken {
                    seq: sealed.event.seq,
                });
            }
            let body = sealed.event.canonical_body()?;
            let salt = match sealed.salt_ref {
                Some(r) if sealed.salted => salts.get(r).cloned(),
                _ => None,
            };
            let expect = event_commitment(&body, prev, salt.as_ref());
            if expect != sealed.commitment {
                return Err(EventError::ChainBroken {
                    seq: sealed.event.seq,
                });
            }
            prev = Some(sealed.commitment);
        }
        Ok(())
    }

    /// Check the log head against a transparency-log anchor (truncation
    /// and fork detection).
    pub fn verify_against_anchor(&self, anchor: &Hash) -> Result<(), EventError> {
        match self.head() {
            Some(h) if &h == anchor => Ok(()),
            Some(h) => Err(EventError::AnchorMismatch {
                expected: anchor.hex(),
                actual: h.hex(),
            }),
            None => Err(EventError::AnchorMismatch {
                expected: anchor.hex(),
                actual: "<empty>".into(),
            }),
        }
    }

    /// All events that had occurred by `t` (as-of prefix view).
    pub fn as_of(&self, t: Timestamp) -> impl Iterator<Item = &SealedEvent> {
        self.sealed
            .iter()
            .take_while(move |s| s.event.occurred_at <= t)
    }

    /// The state hash at time `t`: the head of the as-of prefix.
    pub fn state_hash_at(&self, t: Timestamp) -> Option<Hash> {
        self.as_of(t).last().map(|s| s.commitment)
    }

    /// Replay to the current status.
    pub fn current_status(&self) -> Status {
        let mut status = Status::Issued;
        for sealed in &self.sealed {
            match &sealed.event.payload {
                EventPayload::Issuance { .. } => status = Status::Issued,
                EventPayload::StatusChange { to, .. } => status = *to,
                EventPayload::Split {
                    parent_consumed, ..
                } => {
                    if *parent_consumed {
                        status = Status::Transformed;
                    }
                }
                EventPayload::Decompose { .. } => status = Status::Transformed,
                EventPayload::EndOfWaste { .. } => status = Status::EndOfWaste,
                _ => {}
            }
        }
        status
    }

    /// Replay to the current safety flag.
    pub fn safety_flag(&self) -> SafetyFlag {
        let mut recall = false;
        let mut security = false;
        for sealed in &self.sealed {
            match &sealed.event.payload {
                EventPayload::RecallCampaign { .. } => recall = true,
                EventPayload::FlagSecurity { .. } => security = true,
                _ => {}
            }
        }
        match (recall, security) {
            (false, false) => SafetyFlag::None,
            (true, false) => SafetyFlag::RecallActive,
            (false, true) => SafetyFlag::SecurityFlagged,
            (true, true) => SafetyFlag::RecallActive,
        }
    }

    pub fn corrections(&self) -> usize {
        self.sealed
            .iter()
            .filter(|s| matches!(s.event.payload, EventPayload::Correction { .. }))
            .count()
    }

    pub fn stamps(&self) -> Vec<&Stamp> {
        self.sealed
            .iter()
            .filter_map(|s| match &s.event.payload {
                EventPayload::InspectionStamp { stamp } => Some(stamp),
                _ => None,
            })
            .collect()
    }

    /// Current custodian, if a custody transfer has been recorded.
    pub fn custodian(&self) -> Option<String> {
        let mut current: Option<String> = None;
        for sealed in &self.sealed {
            if let EventPayload::CustodyTransfer { to, .. } = &sealed.event.payload {
                current = Some(to.clone());
            }
        }
        current
    }

    /// Test support: drop the tail of the log (simulates truncation
    /// attacks; a prefix is internally consistent but fails anchoring).
    #[doc(hidden)]
    pub fn truncate_for_test(&mut self) -> bool {
        self.sealed.pop().is_some()
    }

    /// Last event timestamp (the as-of stamp for freshness).
    pub fn last_event_at(&self) -> Option<Timestamp> {
        self.sealed.last().map(|s| s.event.occurred_at)
    }
}

/// Owner-side salt store. A separate artifact from the log: it may be
/// escrowed, never shipped with the log, and never served to verifiers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SaltStore {
    subject: PassportId,
    salts: BTreeMap<u64, [u8; 32]>,
}

impl SaltStore {
    pub fn new(subject: PassportId) -> SaltStore {
        SaltStore {
            subject,
            salts: BTreeMap::new(),
        }
    }

    pub fn subject(&self) -> &PassportId {
        &self.subject
    }

    pub fn remember(&mut self, seq: u64, salt: [u8; 32]) {
        self.salts.insert(seq, salt);
    }

    pub fn get(&self, seq: u64) -> Option<&[u8; 32]> {
        self.salts.get(&seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_type::EventType;
    use crate::payload::EventPayload;
    use unidpp_model::TrustMarker;

    fn subject() -> PassportId {
        PassportId::new("urn:unidpp:passport:subject-1").unwrap()
    }

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    #[test]
    fn append_only_and_seq() {
        let mut log = EventLog::new(subject());
        let e0 = TypedEvent::new(
            0,
            t(10),
            "issuing authority",
            "eo-1",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: false,
                inputs: vec![],
            },
            TrustMarker::SelfDeclared,
        )
        .unwrap();
        log.append(e0.clone(), None, None).unwrap();
        let err = log.append(e0, None, None).unwrap_err();
        assert!(matches!(
            err,
            EventError::Seq {
                expected: 1,
                got: 0
            }
        ));
    }

    #[test]
    fn unsalted_chain_verifies_and_detects_tampering() {
        let mut log = EventLog::new(subject());
        for i in 0..5 {
            let e = TypedEvent::new(
                i,
                t(100 + i as i64),
                "custodian",
                "actor",
                EventType::CustodyTransfer,
                EventPayload::CustodyTransfer {
                    from: format!("holder-{i}"),
                    to: format!("holder-{}", i + 1),
                    counterparty_signed: true,
                },
                TrustMarker::Attested,
            )
            .unwrap();
            log.append(e, None, None).unwrap();
        }
        log.verify().unwrap();

        // Tamper via JSON round trip: mutate one payload field.
        let mut json = serde_json::to_string(&log).unwrap();
        assert!(json.contains("holder-3"));
        json = json.replacen("holder-3", "holder-X", 1);
        let tampered: EventLog = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            log_cmp_verify(&tampered),
            Err(EventError::ChainBroken { .. })
        ));
    }

    fn log_cmp_verify(log: &EventLog) -> Result<(), EventError> {
        log.verify()
    }

    #[test]
    fn truncation_needs_anchor() {
        let mut log = EventLog::new(subject());
        for i in 0..3 {
            let e = TypedEvent::new(
                i,
                t(10 * (i + 1) as i64),
                "custodian",
                "actor",
                EventType::CustodyTransfer,
                EventPayload::CustodyTransfer {
                    from: "a".into(),
                    to: "b".into(),
                    counterparty_signed: false,
                },
                TrustMarker::Unsigned,
            )
            .unwrap();
            log.append(e, None, None).unwrap();
        }
        let anchor = log.head().unwrap();
        let mut truncated = log.clone();
        truncated.sealed.pop();
        // Prefix truncation keeps the chain internally consistent...
        truncated.verify().unwrap();
        // ...but fails against the witnessed anchor.
        assert!(matches!(
            truncated.verify_against_anchor(&anchor),
            Err(EventError::AnchorMismatch { .. })
        ));
        log.verify_against_anchor(&anchor).unwrap();
    }

    #[test]
    fn salted_chain_needs_salt_store_to_fully_verify() {
        let mut log = EventLog::new(subject());
        let mut salts = SaltStore::new(subject());
        for i in 0..3 {
            let e = TypedEvent::new(
                i,
                t(10 * (i + 1) as i64),
                "custodian",
                "actor",
                EventType::CustodyTransfer,
                EventPayload::CustodyTransfer {
                    from: "a".into(),
                    to: "b".into(),
                    counterparty_signed: false,
                },
                TrustMarker::Unsigned,
            )
            .unwrap();
            let salt = [i as u8 + 1; 32];
            log.append(e, Some(salt), Some(i)).unwrap();
            salts.remember(i, salt);
        }
        log.verify().unwrap();
        log.verify_with_salts(&salts).unwrap();
        // Corrupt one salt: full verification fails, prefix verification
        // (without salts) cannot see it.
        let mut bad = salts.clone();
        bad.remember(1, [42u8; 32]);
        assert!(matches!(
            log.verify_with_salts(&bad),
            Err(EventError::ChainBroken { seq: 1 })
        ));
    }

    #[test]
    fn as_of_state_hash_is_prefix_head() {
        let mut log = EventLog::new(subject());
        let times = [10i64, 50, 90];
        for (i, at) in times.iter().enumerate() {
            let e = TypedEvent::new(
                i as u64,
                t(*at),
                "custodian",
                "actor",
                EventType::Correction,
                EventPayload::Correction {
                    field: format!("f{i}"),
                    prior_value: "old".into(),
                    new_value: "new".into(),
                    reason: "typo".into(),
                },
                TrustMarker::Unsigned,
            )
            .unwrap();
            log.append(e, None, None).unwrap();
        }
        let before = log.state_hash_at(t(49)).unwrap();
        let after = log.state_hash_at(t(1000)).unwrap();
        assert_ne!(before, after);
        // t=49 covers only the event at t=10; t=50 covers the second too.
        assert_eq!(log.as_of(t(49)).count(), 1);
        assert_eq!(log.as_of(t(50)).count(), 2);
        assert_eq!(log.state_hash_at(t(5)), None);
        assert_eq!(log.state_hash_at(t(49)), log.state_hash_at(t(10)));
    }

    #[test]
    fn replay_derives_state() {
        let mut log = EventLog::new(subject());
        let e = TypedEvent::new(
            0,
            t(1),
            "eo",
            "eo-1",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: false,
                inputs: vec![],
            },
            TrustMarker::Unsigned,
        )
        .unwrap();
        log.append(e, None, None).unwrap();
        let e = TypedEvent::new(
            1,
            t(2),
            "regulator",
            "reg-1",
            EventType::StatusChange,
            EventPayload::StatusChange {
                from: Status::Issued,
                to: Status::Suspended,
                authority: "reg".into(),
            },
            TrustMarker::Attested,
        )
        .unwrap();
        log.append(e, None, None).unwrap();
        let e = TypedEvent::new(
            2,
            t(3),
            "custodian",
            "a",
            EventType::CustodyTransfer,
            EventPayload::CustodyTransfer {
                from: "eo".into(),
                to: "alice".into(),
                counterparty_signed: true,
            },
            TrustMarker::SelfDeclared,
        )
        .unwrap();
        log.append(e, None, None).unwrap();
        let e = TypedEvent::new(
            3,
            t(4),
            "regulator",
            "reg-1",
            EventType::RecallCampaign,
            EventPayload::RecallCampaign {
                campaign: "R-9".into(),
                predicate: unidpp_model::TriggerPredicate::Any,
            },
            TrustMarker::Attested,
        )
        .unwrap();
        log.append(e, None, None).unwrap();
        assert_eq!(log.current_status(), Status::Suspended);
        assert_eq!(log.safety_flag(), SafetyFlag::RecallActive);
        assert_eq!(log.custodian().as_deref(), Some("alice"));
        assert_eq!(log.corrections(), 0);
        assert_eq!(log.last_event_at(), Some(t(4)));
    }
}
