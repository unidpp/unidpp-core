//! Property: blind-edge commitments never leak parent identity (salt
//! discipline).
//!
//! For random parent identities and salts:
//! - no serialization of the child's log contains the parent id or the
//!   salt;
//! - the salt store is a separate artifact and the log never embeds it;
//! - commitments are deterministic per (parent, salt) and whitened across
//!   salts (dictionary attacks gain nothing);
//! - binding verification succeeds only with the correct pair.

use unidpp_event::{BlindInstallSpec, 
    parent_commitment, verify_parent_binding, EventLog, EventType, EventPayload, SaltStore, TypedEvent,
};
use unidpp_model::{
    InstallMethod, Interval, Pairing, PassportId, Recoverability, Timestamp, TrustMarker,
};
use unidpp_transform::Rng;

fn child_pid(n: u64) -> PassportId {
    PassportId::new(&format!("urn:unidpp:passport:bms-{n:04}")).unwrap()
}

#[test]
fn blind_edges_never_leak_parent_or_salt() {
    let mut rng = Rng::new(0xB11D_ED6E);
    let mut seen_commitments = std::collections::BTreeSet::new();
    for i in 0..200u64 {
        let parent = PassportId::new(&format!(
            "urn:unidpp:passport:car-{}-{}",
            rng.range(0, 1_000_000),
            rng.range(0, 1_000_000)
        ))
        .unwrap();
        let salt = rng.bytes32();

        let mut log = EventLog::new(child_pid(i));
        let issuance = TypedEvent::new(
            0,
            Timestamp::from_secs(1_800_000_000),
            "issuing authority",
            "cell-maker",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: false,
                inputs: vec![],
            },
            TrustMarker::SelfDeclared,
        )
        .unwrap();
        log.append(issuance, None, None).unwrap();

        let install = TypedEvent::new(
            1,
            Timestamp::from_secs(1_800_100_000),
            "installer",
            "repairer-9",
            EventType::Install,
            EventPayload::blind_install(
                &parent,
                &salt,
                BlindInstallSpec {
                    interval: Interval::starting(Timestamp::from_secs(1_800_100_000)),
                    method: InstallMethod::Known(unidpp_model::KnownMethod::Keyed),
                    recoverability: Recoverability::Harvestable,
                    pairing: Pairing::Firmware,
                    slot_id: Some(format!("slot-{}", rng.range(0, 8))),
                    escrow: None,
                },
            ),
            TrustMarker::Attested,
        )
        .unwrap();
        log.append(install, Some(salt), Some(1)).unwrap();

        // Salt discipline: the owner-side store holds the salt...
        let mut salts = SaltStore::new(child_pid(i));
        salts.remember(1, salt);

        let log_json = serde_json::to_string(&log).unwrap();
        // 1. Parent identity never appears.
        assert!(
            !log_json.contains(parent.as_str()),
            "parent identity leaked into log JSON (iteration {i})"
        );
        // 2. Salt bytes never appear in any encoding.
        let salt_hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !log_json.contains(&salt_hex),
            "salt leaked into log JSON (iteration {i})"
        );
        let log_bytes = serde_json::to_vec(&log).unwrap();
        assert!(!log_bytes
            .windows(salt.len())
            .any(|w| w == salt));
        // 3. The salt store is a separate artifact (and it does hold the
        //    salt — that is exactly why it must never ship with the log).
        let salt_json = serde_json::to_string(&salts).unwrap();
        let salts_rt: SaltStore = serde_json::from_str(&salt_json).unwrap();
        assert_eq!(salts_rt.get(1), Some(&salt));
        assert!(!log_json.contains("\"salts\""));
        // 4. Chain still verifies.
        assert!(log.verify().is_ok());
        assert!(log.verify_with_salts(&salts).is_ok());

        // 5. Whitening: distinct (parent, salt) pairs give distinct
        //    commitments (enumeration resistance).
        let c = parent_commitment(&parent, &salt);
        assert!(seen_commitments.insert(c), "commitment collision at {i}");
        // Determinism.
        assert_eq!(c, parent_commitment(&parent, &salt));
        // 6. Binding verification.
        assert!(verify_parent_binding(&parent, &salt, &c));
        let other_parent = PassportId::new(&format!("urn:unidpp:passport:car-{}", rng.range(0, 1_000_000)))
            .unwrap();
        assert!(!verify_parent_binding(&other_parent, &salt, &c));
        let other_salt = rng.bytes32();
        assert!(!verify_parent_binding(&parent, &other_salt, &c));
        // 7. Same salt, different parent -> different commitment.
        assert_ne!(c, parent_commitment(&other_parent, &salt));
    }
}

#[test]
fn enumeration_resistance_over_a_pool() {
    // A verifier holding many child logs cannot correlate any of them to
    // any parent in a known pool (byte-level search).
    let mut rng = Rng::new(0xE11E);
    let pool: Vec<PassportId> = (0..50)
        .map(|i| PassportId::new(&format!("urn:unidpp:passport:pool-{i}")).unwrap())
        .collect();
    let mut haystack = String::new();
    for i in 0..20u64 {
        let parent = rng.pick(&pool).unwrap().clone();
        let salt = rng.bytes32();
        let mut log = EventLog::new(child_pid(10_000 + i));
        let install = TypedEvent::new(
            0,
            Timestamp::from_secs(1),
            "installer",
            "r",
            EventType::Install,
            EventPayload::blind_install(
                &parent,
                &salt,
                BlindInstallSpec {
                    interval: Interval::starting(Timestamp::from_secs(1)),
                    method: InstallMethod::Known(unidpp_model::KnownMethod::Fastened),
                    recoverability: Recoverability::Restorable,
                    pairing: Pairing::None,
                    slot_id: None,
                    escrow: None,
                },
            ),
            TrustMarker::Unsigned,
        )
        .unwrap();
        log.append(install, Some(salt), Some(0)).unwrap();
        haystack.push_str(&serde_json::to_string(&log).unwrap());
    }
    for parent in &pool {
        assert!(
            !haystack.contains(parent.as_str()),
            "pool identity {} found in blind logs",
            parent
        );
    }
}
