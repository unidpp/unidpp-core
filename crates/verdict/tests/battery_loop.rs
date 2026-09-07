//! Integration scene: the battery loop (P4 pilot shape).
//!
//! cells -> pack (combine with mass balance and stamp-context
//! inheritance) -> blind installation into a car -> theft flag on a cell
//! -> taint propagation -> end-of-waste -> Tier-A packing and graded
//! verdicts (fresh, stale, offline).

use std::collections::{BTreeMap, BTreeSet};

use unidpp_event::{
    EventLog, EventType, EventPayload, Status, TypedEvent,
};
use unidpp_model::{
    CapabilityClass, DataPointRef, Decimal, FactValue, FreshnessRequirement, InstallMethod,
    Interval, Pairing, PassportId, ProductIdentifier, ProfileAxes, ProfileId, ProfileManifest,
    Resolution, SigSlot, SignatureSuite, Timestamp, Traversal, TriggerPredicate, TrustMarker,
    TwinFacts, VisibilityClass,
};
use unidpp_tier_a::{TierAPacker, TierAPayload};
use unidpp_transform::{
    combine, split, taint::KnownTaint, CarveOut, CombineSpec, InputReference, ProvenanceGraph,
    Quantity,
    SplitSpec, StampContextRef, Taint, TaintKind, TaintSet, UnitRegistry,
};
use unidpp_verdict::{Degradation, Failure, Outcome, Reading, VerdictBuilder};

fn pid(n: &str) -> PassportId {
    PassportId::new(&format!("urn:unidpp:passport:{n}")).unwrap()
}

fn t(secs: i64) -> Timestamp {
    Timestamp::from_secs(secs)
}

fn qty(amount: &str, uom: &str, reg: &UnitRegistry) -> Quantity {
    Quantity::parse(amount, uom, reg).unwrap()
}

fn battery_profile() -> ProfileManifest {
    let p = ProfileManifest {
        id: ProfileId::new("urn:unidpp:profile:eu-battery-v3").unwrap(),
        axes: ProfileAxes::jurisdiction("EU").with_sector("batteries"),
        trigger: TriggerPredicate::FactGe {
            path: "battery.capacity-kwh".into(),
            value: FactValue::Num("2".parse().unwrap()),
        },
        min_capability: CapabilityClass::Silent,
        freshness: FreshnessRequirement::Static,
        effective: Interval::starting(t(0)),
        data_points: vec![
            DataPointRef::new("ferin:eu", "carbon-footprint", Some("3.1")).unwrap(),
            DataPointRef::new("ferin:eu", "recycled-content", None).unwrap(),
        ],
        crypto_suites: vec![SignatureSuite::EcdsaP256, SignatureSuite::Sm2],
        confidential: false,
        resolution: Resolution::Public,
        edge_visibility: VisibilityClass::Blind,
        traversal: Traversal::RoleScoped,
    };
    p.validate().unwrap();
    p
}

fn issue_log(id: &str, at: i64) -> EventLog {
    let mut log = EventLog::new(pid(id));
    let e = TypedEvent::new(
        0,
        t(at),
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
    log.append(e, None, None).unwrap();
    log
}

#[test]
fn battery_loop_end_to_end() {
    let reg = UnitRegistry::iso80000();

    // --- Cells (dormant-to-live: lot-level inputs at finest granularity).
    let cell_a = issue_log("cell-a", 1_700_000_000);
    let cell_b = issue_log("cell-b", 1_700_000_100);
    let as_of_a = cell_a.head().unwrap();
    let as_of_b = cell_b.head().unwrap();

    // --- Combine: pack issuance with inputReferences (as-of state hashes).
    let spec = CombineSpec {
        output: pid("pack-1"),
        output_quantity: qty("24.2", "kg", &reg),
        inputs: vec![
            InputReference {
                input: pid("cell-a"),
                quantity: qty("12000", "g", &reg),
                as_of_state_hash: as_of_a,
            },
            InputReference {
                input: pid("cell-b"),
                quantity: qty("13", "kg", &reg),
                as_of_state_hash: as_of_b,
            },
        ],
        available: BTreeMap::from([
            (pid("cell-a"), qty("12", "kg", &reg)),
            (pid("cell-b"), qty("13", "kg", &reg)),
        ]),
        stamp_contexts: vec![StampContextRef {
            attester: "notified-body.example".into(),
            quantity: qty("12", "kg", &reg),
            as_of: t(1_700_000_000),
        }],
    };
    let outcome = combine(&spec, &reg).unwrap();
    assert_eq!(outcome.loss.convert_to(&reg.unit("kg").unwrap(), &reg).unwrap().amount, "0.8".parse::<Decimal>().unwrap());

    // The pack's log: derived issuance carrying the inputReferences.
    let mut pack_log = EventLog::new(pid("pack-1"));
    let e = TypedEvent::new(
        0,
        t(1_700_100_000),
        "issuing authority",
        "pack-maker",
        EventType::Issuance,
        EventPayload::Issuance {
            derived: true,
            inputs: spec.inputs.clone(),
        },
        TrustMarker::Attested,
    )
    .unwrap();
    pack_log.append(e, None, None).unwrap();
    let e = TypedEvent::new(
        1,
        t(1_700_100_050),
        "custodian (transformer)",
        "pack-maker",
        EventType::Combine,
        EventPayload::Combine {
            inputs: spec.inputs.clone(),
            output_quantity: qty("24.2", "kg", &reg),
            loss: outcome.loss.clone(),
        },
        TrustMarker::Attested,
    )
    .unwrap();
    pack_log.append(e, None, None).unwrap();
    assert!(pack_log.verify().is_ok());

    // --- Split: harvest into modules (carve-outs + remainder).
    let split_spec = SplitSpec {
        parent: pid("pack-1"),
        parent_available: qty("24.2", "kg", &reg),
        carve_outs: vec![CarveOut {
            child: pid("mod-1"),
            quantity: qty("10", "kg", &reg),
        }],
    };
    let so = split(&split_spec, &reg).unwrap();
    assert_eq!(so.remainder.amount, "14.2".parse::<Decimal>().unwrap());
    assert!(!so.parent_consumed);
    let e = TypedEvent::new(
        2,
        t(1_700_200_000),
        "custodian",
        "harvester",
        EventType::Split,
        EventPayload::Split {
            carve_outs: split_spec.carve_outs.clone(),
            remainder: so.remainder.clone(),
            parent_consumed: so.parent_consumed,
        },
        TrustMarker::Attested,
    )
    .unwrap();
    pack_log.append(e, None, None).unwrap();

    // --- Blind installation of the pack into a car. The CHILD's log
    // records its installation interval; the parent appears only as a
    // salted commitment (proof-of-binding without knowledge-of-parent).
    let car = pid("car-eu-42");
    let install_salt = [0x5A; 32];
    let e = TypedEvent::new(
        3,
        t(1_700_300_000),
        "installer",
        "repairer-9",
        EventType::Install,
        EventPayload::blind_install(
            &car,
            &install_salt,
            Interval::starting(t(1_700_300_000)),
            InstallMethod::Known(unidpp_model::KnownMethod::Keyed),
            unidpp_model::Recoverability::Harvestable,
            Pairing::Firmware,
            Some("battery-slot-1".into()),
            None,
        ),
        TrustMarker::Attested,
    )
    .unwrap();
    pack_log.append(e, Some(install_salt), Some(3)).unwrap();
    let pack_json = serde_json::to_string(&pack_log).unwrap();
    assert!(!pack_json.contains(car.as_str()), "blind edge leaked the car identity");
    let salt_hex: String = install_salt.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!pack_json.contains(&salt_hex), "blind edge leaked the salt");
    assert!(pack_log.verify().is_ok());

    // --- Theft flag on cell A: taint propagates downstream.
    let mut taint_index: BTreeMap<PassportId, TaintSet> = BTreeMap::new();
    let mut ts = TaintSet::new();
    ts.add(Taint {
        source: pid("cell-a"),
        kind: TaintKind::Known(KnownTaint::Fraud),
        reason: "stolen cells".into(),
        at: t(1_700_400_000),
        window: Some(Interval::starting(t(1_690_000_000))),
    });
    taint_index.insert(pid("cell-a"), ts);
    let mut graph = ProvenanceGraph::new();
    graph.record_combine(pid("pack-1"), &[pid("cell-a"), pid("cell-b")]);
    graph.record_split(pid("pack-1"), &[pid("mod-1")]);
    let pack_taints = graph.taints_of(&pid("pack-1"), &taint_index);
    assert!(pack_taints.voids_ab_initio(), "stolen material taints the derived pack");
    assert!(graph.taints_of(&pid("mod-1"), &taint_index).voids_ab_initio());
    assert!(!graph.taints_of(&pid("cell-b"), &taint_index).voids_ab_initio());
    let recall_set = graph.recall_set(&pid("cell-a"));
    assert!(recall_set.contains(&pid("pack-1")) && recall_set.contains(&pid("mod-1")));

    // --- End of waste on the pack.
    let e = TypedEvent::new(
        4,
        t(1_700_500_000),
        "accredited actor",
        "recycler",
        EventType::EndOfWaste,
        EventPayload::EndOfWaste {
            evidence_ref: "eow-cert-9".into(),
            outputs: vec![],
        },
        TrustMarker::Attested,
    )
    .unwrap();
    pack_log.append(e, None, None).unwrap();
    assert_eq!(pack_log.current_status(), Status::EndOfWaste);

    // --- Tier A: pack the pack's log; multi-suite framing; budgeting.
    let payload = TierAPayload::from_log(
        &pack_log,
        ProductIdentifier::parse("sgtin:4006381333931+21+PACK1").unwrap(),
        "https://dpp.unidpp.org/r/pack-1",
        "eo-de-042",
        Interval::between(t(1_700_100_000), t(1_900_000_000)).unwrap(),
        vec![
            SigSlot::placeholder(SignatureSuite::EcdsaP256, "k-ecdsa"),
            SigSlot::placeholder(SignatureSuite::Sm2, "k-sm2"),
        ],
    );
    let packer = TierAPacker::new(unidpp_tier_a::EcLevel::M, 40);
    let packed = packer.pack(&payload).unwrap();
    assert!(packed.margin() >= 0);
    let decoded = TierAPacker::decode(packed.as_slice()).unwrap();
    assert_eq!(decoded.product_id, payload.product_id);
    assert_eq!(decoded.signatures.len(), 2);
    // ML-DSA-65 does not fit alongside the rest at EC M... it does (3309
    // + overhead < 2331? No: 2331 < 3309 + overhead). It must overflow.
    let big = TierAPayload {
        signatures: vec![SigSlot::placeholder(SignatureSuite::MlDsa65, "k-pq")],
        ..payload.clone()
    };
    assert!(packer.pack(&big).is_err(), "ML-DSA-65 must overflow a v40-M QR budget");

    // --- Verdicts.
    let profile = battery_profile();
    let provided: BTreeSet<String> = ["ferin:eu/carbon-footprint@3.1", "ferin:eu/recycled-content"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let now_fresh = t(1_700_500_100);
    let v = VerdictBuilder::new(&pack_log, now_fresh)
        .with_profile(&profile)
        .with_provided(provided.clone())
        .with_signatures(vec![
            SigSlot::placeholder(SignatureSuite::EcdsaP256, "k1"),
            SigSlot::placeholder(SignatureSuite::Sm2, "k2"),
        ])
        .attested_by_third_party(true)
        .with_anchor(pack_log.head().unwrap())
        .with_taints(pack_taints.clone())
        .answering(Reading::CurrentState)
        .build();
    // Framing-only signatures degrade explicitly (never silently pass).
    assert!(matches!(v.outcome, Outcome::Degraded(Degradation::SignaturesFramedOnly)));
    assert!(v.current_state.voids_ab_initio);

    // Freshness: bounded window goes stale.
    let live_profile = ProfileManifest {
        freshness: FreshnessRequirement::FreshWithin { max_age_secs: 3_600 },
        ..profile.clone()
    };
    let v_stale = VerdictBuilder::new(&pack_log, t(1_700_510_000))
        .with_profile(&live_profile)
        .with_provided(provided)
        .with_anchor(pack_log.head().unwrap())
        .build();
    assert!(matches!(v_stale.outcome, Outcome::Degraded(Degradation::StaleData { .. })));

    // Offline (no anchor) degrades, broken chain fails.
    let v_offline = VerdictBuilder::new(&pack_log, now_fresh).build();
    assert!(matches!(v_offline.outcome, Outcome::Degraded(Degradation::OfflineNoAnchor)));
    let mut json = serde_json::to_string(&pack_log).unwrap();
    json = json.replacen("eow-cert-9", "eow-cert-X", 1);
    let tampered: EventLog = serde_json::from_str(&json).unwrap();
    // The EndOfWaste event is unsalted, so its commitment is recomputable
    // and the tampering breaks the chain.
    let v_fail = VerdictBuilder::new(&tampered, now_fresh).build();
    assert!(matches!(v_fail.outcome, Outcome::Fail(Failure::BrokenChain)));

    // Applicability: the profile triggers on capacity (predicate).
    let facts = TwinFacts::new().set(
        "battery.capacity-kwh",
        FactValue::Num("2.5".parse().unwrap()),
    );
    assert!(profile.applies_to(&facts, now_fresh));
    let _ = qty("1", "kg", &reg);
}
