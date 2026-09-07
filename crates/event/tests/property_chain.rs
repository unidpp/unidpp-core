//! Property: hash-chain consistency on random event streams; tamper and
//! truncation detection; append-only sequence enforcement.

use unidpp_event::{EventError, EventLog, EventPayload, EventType, SaltStore, Status, TypedEvent};
use unidpp_model::{PassportId, ProfileId, Timestamp, TriggerPredicate, TrustMarker};
use unidpp_transform::Rng;

fn pid() -> PassportId {
    PassportId::new("urn:unidpp:passport:subject-1").unwrap()
}

fn random_event(rng: &mut Rng, seq: u64, at: i64) -> TypedEvent {
    let t = Timestamp::from_secs(at);
    let marker = [
        TrustMarker::Unsigned,
        TrustMarker::SelfDeclared,
        TrustMarker::Attested,
    ][rng.range(0, 3) as usize];
    match rng.range(0, 7) {
        0 => TypedEvent::new(
            seq,
            t,
            "custodian",
            "actor-1",
            EventType::CustodyTransfer,
            EventPayload::CustodyTransfer {
                from: format!("from-{}", rng.range(0, 100)),
                to: format!("to-{}", rng.range(0, 100)),
                counterparty_signed: rng.bool(),
            },
            marker,
        ),
        1 => TypedEvent::new(
            seq,
            t,
            "eo",
            "eo-1",
            EventType::Correction,
            EventPayload::Correction {
                field: format!("field-{}", rng.range(0, 20)),
                prior_value: format!("v-{}", rng.range(0, 1000)),
                new_value: format!("v-{}", rng.range(0, 1000)),
                reason: "administrative".into(),
            },
            marker,
        ),
        2 => {
            let legal = [
                (Status::Issued, Status::Suspended),
                (Status::Issued, Status::NonConformant),
                (Status::Suspended, Status::Issued),
                (Status::NonConformant, Status::Issued),
                (Status::Issued, Status::Consumed),
                (Status::Issued, Status::Transformed),
                (Status::Issued, Status::EndOfWaste),
                (Status::EndOfWaste, Status::Issued),
            ];
            let (from, to) = legal[rng.range(0, legal.len() as u64) as usize];
            TypedEvent::new(
                seq,
                t,
                "regulator",
                "reg-1",
                EventType::StatusChange,
                EventPayload::StatusChange {
                    from,
                    to,
                    authority: "reg".into(),
                },
                marker,
            )
        }
        3 => TypedEvent::new(
            seq,
            t,
            "device",
            "bms",
            EventType::MilestoneRecord,
            EventPayload::MilestoneRecord {
                counters: [
                    ("cycles".to_string(), format!("{}", rng.range(0, 100_000))),
                    ("km".to_string(), format!("{}", rng.range(0, 300_000))),
                ]
                .into_iter()
                .map(|(k, v)| (k, v.parse().unwrap()))
                .collect(),
            },
            marker,
        ),
        4 => TypedEvent::new(
            seq,
            t,
            "issuing authority",
            "eo-1",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: rng.bool(),
                inputs: vec![],
            },
            marker,
        ),
        5 => TypedEvent::new(
            seq,
            t,
            "regulator",
            "reg-1",
            EventType::RecallCampaign,
            EventPayload::RecallCampaign {
                campaign: format!("R-{}", rng.range(0, 999)),
                predicate: TriggerPredicate::Any,
            },
            marker,
        ),
        _ => TypedEvent::new(
            seq,
            t,
            "any verifier",
            "verifier-1",
            EventType::InspectionStamp,
            EventPayload::InspectionStamp {
                stamp: unidpp_event::Stamp {
                    attester: format!("attester-{}", rng.range(0, 50)),
                    subject: pid(),
                    subject_state_commitment: unidpp_model::Hash::ZERO,
                    lens: ProfileId::new("urn:unidpp:profile:lens-1").unwrap(),
                    lens_version: "1.2.3".into(),
                    mode: if rng.bool() {
                        unidpp_event::StampMode::Live
                    } else {
                        unidpp_event::StampMode::Snapshot
                    },
                    verdict_summary: Some("ok".into()),
                    coverage_report: None,
                    log_anchored_at: t,
                    quantity_context: None,
                },
            },
            marker,
        ),
    }
    .unwrap()
}

fn build_log(rng: &mut Rng, salted: bool) -> (EventLog, SaltStore) {
    let mut log = EventLog::new(pid());
    let mut salts = SaltStore::new(pid());
    let n = rng.range(1, 30);
    for seq in 0..n {
        let event = random_event(rng, seq, 1_000_000 + seq as i64 * 600);
        let salt = if salted && rng.bool() {
            let s = rng.bytes32();
            salts.remember(seq, s);
            Some(s)
        } else {
            None
        };
        log.append(event, salt, if salt.is_some() { Some(seq) } else { None })
            .unwrap();
    }
    (log, salts)
}

#[test]
fn random_chains_verify_and_round_trip() {
    for seed in 1..=20u64 {
        let mut rng = Rng::new(seed.wrapping_mul(0xA076_1D64_78BD_642F));
        for salted in [false, true] {
            let (log, salts) = build_log(&mut rng, salted);
            assert!(
                log.verify().is_ok(),
                "chain must verify (seed {seed}, salted {salted})"
            );
            assert!(log.verify_with_salts(&salts).is_ok());
            // Serialization round trip preserves the chain.
            let json = serde_json::to_string(&log).unwrap();
            let rt: EventLog = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, log);
            assert!(rt.verify().is_ok());
            // Determinism: same events -> same commitments.
            let json2 = serde_json::to_string(&rt).unwrap();
            assert_eq!(json, json2);
        }
    }
}

#[test]
fn tampering_is_detected() {
    /// Deterministic tamper: flip the actor_id of the last event.
    fn mutate_last_actor(json: &str) -> String {
        let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
        let sealed = v.get_mut("sealed").unwrap().as_array_mut().unwrap();
        let last = sealed.last_mut().unwrap();
        let actor = last.get_mut("event").unwrap().get_mut("actor_id").unwrap();
        let s = actor.as_str().unwrap().to_string();
        *actor = serde_json::Value::String(format!("TAMPERED-{s}"));
        serde_json::to_string(&v).unwrap()
    }

    for seed in 100..=110u64 {
        let mut rng = Rng::new(seed);
        // Unsalted: the body is recomputable, verify() catches it.
        let (log, _salts) = build_log(&mut rng, false);
        let json = serde_json::to_string(&log).unwrap();
        let tampered: EventLog = serde_json::from_str(&mutate_last_actor(&json)).unwrap();
        assert!(matches!(
            tampered.verify(),
            Err(EventError::ChainBroken { .. })
        ));

        // Salted: salt-aware verification catches it.
        let (log2, salts2) = build_log(&mut rng, true);
        let json2 = serde_json::to_string(&log2).unwrap();
        let tampered2: EventLog = serde_json::from_str(&mutate_last_actor(&json2)).unwrap();
        assert!(
            tampered2.verify_with_salts(&salts2).is_err(),
            "salt-aware verification must detect body tampering (seed {seed})"
        );
    }
}

#[test]
fn truncation_detected_against_anchor() {
    let mut rng = Rng::new(0xC0_FF_EE);
    let (log, _salts) = build_log(&mut rng, false);
    let anchor = log.head().unwrap();
    let mut shorter = log.clone();
    while shorter.len() > 1 {
        assert!(shorter.truncate_for_test());
        // A prefix is internally consistent...
        assert!(shorter.verify().is_ok());
        // ...but not against the witnessed anchor.
        assert!(matches!(
            shorter.verify_against_anchor(&anchor),
            Err(EventError::AnchorMismatch { .. })
        ));
    }
    // The full log matches the anchor.
    assert!(log.verify_against_anchor(&anchor).is_ok());
}

#[test]
fn append_only_sequence_enforced() {
    let mut rng = Rng::new(7);
    let (mut log, _salts) = build_log(&mut rng, false);
    let next_seq = log.len() as u64;
    let bad = random_event(&mut rng, next_seq + 5, 2_000_000);
    assert!(matches!(
        log.append(bad, None, None),
        Err(EventError::Seq { .. })
    ));
    let good = random_event(&mut rng, next_seq, 2_000_000);
    log.append(good, None, None).unwrap();
    log.verify().unwrap();
}
