//! Scenario `battery-loop`: the P4 pilot loop, replayed step by step.
//!
//! cells -> pack (combine with mass balance and as-of state hashes) ->
//! split harvest -> blind installation into a car -> theft flag on a cell
//! -> taint propagation -> end-of-waste -> Tier-A packing and the graded
//! verdicts (fresh / stale / offline / tampered).
//!
//! The semantics mirror `crates/verdict/tests/battery_loop.rs`; this
//! module narrates each step against the same crates and asserts the
//! load-bearing outcomes as it goes.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use unidpp_event::{
    verify_parent_binding, BlindInstallSpec, EventLog, EventPayload, EventType, SaltStore, Status,
    TypedEvent,
};
use unidpp_model::{
    CapabilityClass, DataPointRef, Decimal, FactValue, FreshnessRequirement, InstallMethod,
    Interval, IssuerClass, KnownMethod, Pairing, PassportId, ProductIdentifier, ProfileAxes,
    ProfileId, ProfileManifest, Recoverability, Resolution, SigSlot, SignatureSuite, Timestamp,
    Traversal, TriggerPredicate, TrustMarker, TwinFacts, VisibilityClass,
};
use unidpp_tier_a::{EcLevel, TierAPacker, TierAPayload};
use unidpp_transform::{
    combine, split, taint::KnownTaint, CarveOut, CombineSpec, InputReference, ProvenanceGraph,
    Quantity, SplitSpec, StampContextRef, Taint, TaintKind, TaintSet, UnitRegistry,
};
use unidpp_verdict::{Degradation, Failure, Outcome, Reading, VerdictBuilder};

use crate::{print_verdict, salt_for, short_hash, DemoError, Trace};

fn pid(n: &str) -> PassportId {
    PassportId::new(&format!("urn:unidpp:passport:{n}")).expect("valid passport id")
}

fn t(secs: i64) -> Timestamp {
    Timestamp::from_secs(secs)
}

fn qty(amount: &str, uom: &str, reg: &UnitRegistry) -> Quantity {
    Quantity::parse(amount, uom, reg).expect("valid quantity")
}

fn battery_profile() -> ProfileManifest {
    let p = ProfileManifest {
        id: ProfileId::new("urn:unidpp:profile:eu-battery-v3").unwrap(),
        issuer_class: IssuerClass::Law,
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

/// Run the narrated battery loop.
pub fn run(out: &mut dyn Write, seed: u64) -> Result<(), DemoError> {
    let reg = UnitRegistry::iso80000();
    let mut tr = Trace::new(out);
    tr.header("battery-loop", seed)?;
    tr.scene(
        "Two cell passports (cell-a holding 12 kg, cell-b holding 13 kg) are \
         issued at lot/serial granularity; a pack-maker combines them into pack-1, \
         a harvester splits a module out, an installer mounts the pack into a car, \
         a theft is discovered on a cell, the loop closes at end-of-waste, and the \
         result is packed onto a Tier-A carrier and graded.",
    )?;

    // --- Steps 1-2: cell issuance (finest recorded granularity).
    let cell_a = issue_cell(&mut tr, "cell-a", "cell-maker", 1_700_000_000)?;
    let cell_b = issue_cell(&mut tr, "cell-b", "cell-maker", 1_700_000_100)?;
    let as_of_a = cell_a.head().unwrap();
    let as_of_b = cell_b.head().unwrap();

    // --- Step 3: combine (N -> 1) with as-of state hashes.
    tr.step("Combine (N -> 1): cells -> pack-1")?;
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
    tr.kv(
        "spec",
        &format!(
            "pack-1 <- [cell-a 12000 g @ state {}, cell-b 13 kg @ state {}], \
             available [cell-a 12 kg, cell-b 13 kg], stamp context \
             notified-body.example 12 kg",
            short_hash(&as_of_a),
            short_hash(&as_of_b),
        ),
    )?;
    let outcome = combine(&spec, &reg).map_err(|e| DemoError::msg(e.to_string()))?;
    let total_in_kg = outcome
        .total_in
        .convert_to(&reg.unit("kg").unwrap(), &reg)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "state",
        &format!(
            "mass balance {} in, {} out, loss {} (in - out = loss, auditable)",
            total_in_kg, outcome.output_quantity, outcome.loss
        ),
    )?;
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
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let c0 = pack_log
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
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
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let c1 = pack_log
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "Issuance (derived, carrying inputReferences) then Combine, both by \
         pack-maker, trust marker attested",
    )?;
    tr.kv(
        "commitment",
        &format!(
            "issuance {}, combine {} (unsalted; H(prev || canonical body))",
            short_hash(&c0),
            short_hash(&c1)
        ),
    )?;
    tr.kv(
        "state",
        &format!(
            "pack-1: 0 -> 2 sealed events; status {}; chain verify: OK",
            pack_log.current_status()
        ),
    )?;
    tr.note(
        "The output passport's issuance event carries inputReferences \
         [(passport, quantity, as-of state hash)], so pack-1 hash-links its \
         sources in a Git-merge topology; output quantities are new measured \
         facts computed by the transformation, never copies, and the inputs \
         transition to consumed while remaining verifiable for as-of queries \
         (I4, I8).",
    )?;

    // --- Step 4: split harvest.
    tr.step("Split (1 -> N): harvest module mod-1 from pack-1")?;
    let split_spec = SplitSpec {
        parent: pid("pack-1"),
        parent_available: qty("24.2", "kg", &reg),
        carve_outs: vec![CarveOut {
            child: pid("mod-1"),
            quantity: qty("10", "kg", &reg),
        }],
    };
    let so = split(&split_spec, &reg).map_err(|e| DemoError::msg(e.to_string()))?;
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
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let c2 = pack_log
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "Split by harvester (custodian), trust marker attested",
    )?;
    tr.kv("commitment", &short_hash(&c2).to_string())?;
    tr.kv(
        "state",
        &format!(
            "carve-out mod-1 10 kg; remainder {} stays with pack-1; parent \
             consumed: {}",
            so.remainder, so.parent_consumed
        ),
    )?;
    tr.note(
        "Sum of children is bounded by the parent (remainder semantics): \
         mod-1 departs as a new passport with derivedFrom + carve-out, while \
         pack-1 retains the remainder and its full history (I4).",
    )?;

    // --- Step 5: blind installation into the car.
    tr.step("Blind installation: pack-1 -> car-eu-42 (consumer edge)")?;
    let car = pid("car-eu-42");
    let other_parent = pid("car-eu-99");
    let install_salt = salt_for(seed, b"battery-loop:pack-1:install");
    let e = TypedEvent::new(
        3,
        t(1_700_300_000),
        "installer",
        "repairer-9",
        EventType::Install,
        EventPayload::blind_install(
            &car,
            &install_salt,
            BlindInstallSpec {
                interval: Interval::starting(t(1_700_300_000)),
                method: InstallMethod::Known(KnownMethod::Keyed),
                recoverability: Recoverability::Harvestable,
                pairing: Pairing::Firmware,
                slot_id: Some("battery-slot-1".into()),
                escrow: None,
            },
        ),
        TrustMarker::Attested,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let c3 = pack_log
        .append(e, Some(install_salt), Some(3))
        .map_err(|e| DemoError::msg(e.to_string()))?;
    let mut salts = SaltStore::new(pid("pack-1"));
    salts.remember(3, install_salt);
    let pack_json = serde_json::to_string(&pack_log).map_err(|e| DemoError::msg(e.to_string()))?;
    let salt_hex: String = install_salt.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !pack_json.contains(car.as_str()),
        "blind edge leaked the car identity"
    );
    assert!(!pack_json.contains(&salt_hex), "blind edge leaked the salt");
    let blind_ref = match &pack_log.sealed()[3].event.payload {
        EventPayload::Install {
            target: unidpp_event::InstallTarget::Blind(b),
        } => b,
        other => {
            return Err(DemoError::msg(format!(
                "expected blind install, got {other:?}"
            )))
        }
    };
    let proof_ok = verify_parent_binding(&car, &install_salt, &blind_ref.commitment);
    let proof_wrong = verify_parent_binding(&other_parent, &install_salt, &blind_ref.commitment);
    tr.kv(
        "event",
        "Install (blind edge) by repairer-9, trust marker attested",
    )?;
    tr.kv(
        "commitment",
        &format!(
            "{} (salted; H(salt || prev || body)); the parent appears only \
             as H(salt || car-eu-42)",
            short_hash(&c3)
        ),
    )?;
    tr.kv(
        "state",
        &format!(
            "pack-1: 3 -> 4 sealed events; salt dropped after use, only \
             salt_ref 3 recorded; serialized log leaks car id: NO, salt: NO; \
             chain verify OK: {}, verify_with_salts OK: {}",
            pack_log.verify().is_ok(),
            pack_log.verify_with_salts(&salts).is_ok(),
        ),
    )?;
    tr.kv(
        "binding proof",
        &format!(
            "verify_parent_binding(car-eu-42, salt) -> {}; \
             verify_parent_binding(car-eu-99, salt) -> {}",
            proof_ok, proof_wrong
        ),
    )?;
    tr.note(
        "Proof-of-binding is not knowledge-of-parent: the child satisfies the \
         parent-knowledge requirement cryptographically, so the installation \
         is verifiable as validly mounted in some parent without revealing \
         the household that holds the car; the log anchors commitments, never \
         facts (I12).",
    )?;

    // --- Step 6: theft flag on cell A; taint propagates downstream.
    tr.step("Theft discovered on cell-a: taint propagation through the DAG")?;
    let mut cell_a = cell_a;
    let e = TypedEvent::new(
        1,
        t(1_700_400_000),
        "authority",
        "police-registry",
        EventType::FlagSecurity,
        EventPayload::FlagSecurity {
            kind: unidpp_event::SecurityFlagKind::Known(
                unidpp_event::payload::KnownSecurityFlag::Theft,
            ),
            reference: "police-report-77".into(),
        },
        TrustMarker::Attested,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let ct = cell_a
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
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
    let recall_set = graph.recall_set(&pid("cell-a"));
    let short = |p: &PassportId| p.as_str().rsplit(':').next().unwrap().to_string();
    let recall_names: Vec<String> = recall_set.iter().map(short).collect();
    tr.kv(
        "event",
        "FlagSecurity (theft, police-report-77) on cell-a, trust marker attested",
    )?;
    tr.kv("commitment", &short_hash(&ct).to_string())?;
    tr.kv(
        "state",
        &format!(
            "taint {{fraud, source cell-a, window from 2023-07-14}} propagates: \
             pack-1 voids ab initio: {}, mod-1 voids ab initio: {}, cell-b \
             voids ab initio: {}; recall set of cell-a = [{}]",
            graph
                .taints_of(&pid("pack-1"), &taint_index)
                .voids_ab_initio(),
            graph
                .taints_of(&pid("mod-1"), &taint_index)
                .voids_ab_initio(),
            graph
                .taints_of(&pid("cell-b"), &taint_index)
                .voids_ab_initio(),
            recall_names.join(", "),
        ),
    )?;
    tr.note(
        "Revocation reason determines retroactivity: theft and fraud void \
         validity ab initio over an explicit window, so the derived pack and \
         the harvested module cannot be laundered through transformation, \
         while the untainted cell-b branch stays clean; marking a passport \
         fraudulent is a graph event, not merely a trust-list event (I9).",
    )?;

    // --- Step 7: end of waste.
    tr.step("End-of-waste: pack-1 re-enters commerce as secondary material")?;
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
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let c4 = pack_log
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "EndOfWaste (evidence eow-cert-9) by recycler, trust marker attested",
    )?;
    tr.kv("commitment", &short_hash(&c4).to_string())?;
    tr.kv(
        "state",
        &format!(
            "pack-1 status {} -> {} (legal transition; replayed from the log)",
            Status::Issued,
            pack_log.current_status()
        ),
    )?;
    tr.note(
        "Status changes are normative state-machine transitions with dated \
         applicability; the passport is never rewritten, only appended to \
         (I6, I4).",
    )?;

    // --- Step 8: Tier-A packing.
    tr.step("Tier-A packing: the offline minimum vs the QR budget")?;
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
    let packer = TierAPacker::new(EcLevel::M, 40);
    let packed = packer
        .pack(&payload)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "fields",
        &format!(
            "product id {}, resolver {}, passport {}, eo {}, status {}, \
             safety {}, as-of {}, log head {}",
            payload.product_id,
            payload.resolver_uri,
            payload.passport_id,
            payload.eo_id,
            payload.status,
            payload.safety,
            payload.as_of,
            payload
                .log_head
                .as_ref()
                .map(short_hash)
                .unwrap_or_default(),
        ),
    )?;
    let budget_rows: Vec<String> = TierAPacker::budget_report(&payload)
        .iter()
        .map(|(f, n)| format!("{f} {n}B"))
        .collect();
    tr.kv(
        "budget",
        &format!(
            "{}; encoded {} B, projected {} B (signature placeholders counted \
             at canonical suite lengths) into QR v{} EC m capacity {} B: \
             margin +{} B",
            budget_rows.join(", "),
            packed.used,
            packed.projected,
            packed.version,
            packed.capacity,
            packed.margin()
        ),
    )?;
    let decoded =
        TierAPacker::decode(packed.as_slice()).map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "round trip",
        &format!(
            "decode reproduces product id {} and {} signature slots (framed only)",
            decoded.product_id,
            decoded.signatures.len()
        ),
    )?;
    let big = TierAPayload {
        signatures: vec![SigSlot::placeholder(SignatureSuite::MlDsa65, "k-pq")],
        ..payload.clone()
    };
    let overflow = packer.pack(&big).expect_err("ML-DSA-65 must overflow");
    tr.kv(
        "budget wall",
        &format!(
            "replacing the suites with ML-DSA-65 (a 3309 B signature) is \
             rejected, never silently truncated: {}",
            overflow
        ),
    )?;
    tr.note(
        "Tier A is the carrier-embedded minimum viable passport, budgeted \
         against the ISO/IEC 18004 byte-capacity tables; over-budget payloads \
         fail loudly instead of quietly shrinking the offline minimum (I13).",
    )?;

    // --- Step 9: applicability (predicate trigger).
    tr.step("Profile applicability: predicate trigger on twin facts")?;
    let profile = battery_profile();
    let facts = TwinFacts::new().set(
        "battery.capacity-kwh",
        FactValue::Num("2.5".parse::<Decimal>().unwrap()),
    );
    tr.kv(
        "state",
        &format!(
            "profile {} on axes {} triggers where {}; twin fact \
             battery.capacity-kwh = 2.5 -> applies: {}",
            profile.id,
            profile.axes,
            crate::fmt_predicate(&profile.trigger),
            profile.applies_to(&facts, t(1_700_500_100))
        ),
    )?;
    tr.note(
        "Profiles attach by predicate over twin facts on the jurisdiction x \
         sector axes; the lens selects and transforms but never redefines the \
         canonical facts (I10, I2).",
    )?;

    // --- Step 10: the graded verdicts.
    tr.step("Graded verdicts: fresh, stale, offline, tampered")?;
    let provided: BTreeSet<String> = ["ferin:eu/carbon-footprint@3.1", "ferin:eu/recycled-content"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let now_fresh = t(1_700_500_100);
    let head = pack_log.head().unwrap();
    let v = VerdictBuilder::new(&pack_log, now_fresh)
        .with_profile(&profile)
        .with_provided(provided.clone())
        .with_signatures(vec![
            SigSlot::placeholder(SignatureSuite::EcdsaP256, "k1"),
            SigSlot::placeholder(SignatureSuite::Sm2, "k2"),
        ])
        .attested_by_third_party(true)
        .with_anchor(head)
        .with_taints(pack_taints.clone())
        .with_active_links(1)
        .answering(Reading::CurrentState)
        .build();
    print_verdict(&mut tr, "verdict 1", &v)?;
    let live_profile = ProfileManifest {
        freshness: FreshnessRequirement::FreshWithin {
            max_age_secs: 3_600,
        },
        ..profile.clone()
    };
    let v_stale = VerdictBuilder::new(&pack_log, t(1_700_510_000))
        .with_profile(&live_profile)
        .with_provided(provided)
        .with_anchor(head)
        .answering(Reading::Evidentiary)
        .build();
    print_verdict(&mut tr, "verdict 2", &v_stale)?;
    // Genuinely offline: the verifier holds the log but no cached
    // transparency-log anchor.
    let v_offline = VerdictBuilder::new(&pack_log, now_fresh)
        .answering(Reading::Evidentiary)
        .build();
    print_verdict(&mut tr, "verdict 3", &v_offline)?;
    let mut json = serde_json::to_string(&pack_log).map_err(|e| DemoError::msg(e.to_string()))?;
    json = json.replacen("eow-cert-9", "eow-cert-X", 1);
    let tampered: EventLog =
        serde_json::from_str(&json).map_err(|e| DemoError::msg(e.to_string()))?;
    let v_fail = VerdictBuilder::new(&tampered, now_fresh)
        .answering(Reading::Cryptographic)
        .build();
    print_verdict(&mut tr, "verdict 4", &v_fail)?;
    tr.kv(
        "tampering",
        "one character of the end-of-waste evidence reference was edited in \
         the serialized log; the unsalted commitment no longer recomputes",
    )?;
    tr.note(
        "Verification is graded, never boolean: framing-only signatures \
         degrade explicitly with a stated reason, offline verification \
         without a cached anchor degrades rather than fails, bounded \
         freshness goes stale on the ladder, and any in-place mutation of \
         history fails outright against the hash chain (I9, I13, I4).",
    )?;

    // The narrated guarantees, asserted (release builds included).
    assert!(packed.margin() >= 0);
    assert!(matches!(
        v.outcome,
        Outcome::Degraded(Degradation::SignaturesFramedOnly)
    ));
    assert!(v.current_state.voids_ab_initio);
    assert!(matches!(
        v_stale.outcome,
        Outcome::Degraded(Degradation::StaleData { .. })
    ));
    assert!(matches!(
        v_offline.outcome,
        Outcome::Degraded(Degradation::OfflineNoAnchor)
    ));
    assert!(matches!(
        v_fail.outcome,
        Outcome::Fail(Failure::BrokenChain)
    ));

    tr.blank()?;
    tr.done()?;
    Ok(())
}

fn issue_cell(tr: &mut Trace<'_>, name: &str, maker: &str, at: i64) -> Result<EventLog, DemoError> {
    tr.step(&format!("Issuance of {name} (finest recorded granularity)"))?;
    let mut log = EventLog::new(pid(name));
    let e = TypedEvent::new(
        0,
        t(at),
        "issuing authority",
        maker,
        EventType::Issuance,
        EventPayload::Issuance {
            derived: false,
            inputs: vec![],
        },
        TrustMarker::SelfDeclared,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let c = log
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        &format!("Issuance by issuing authority / {maker}, trust marker self-declared"),
    )?;
    tr.kv(
        "commitment",
        &format!(
            "{} (unsalted; commits to the canonical body)",
            short_hash(&c)
        ),
    )?;
    tr.kv(
        "state",
        &format!(
            "{name}: 0 -> 1 sealed events; status issued; as-of state hash {}",
            short_hash(&c)
        ),
    )?;
    tr.note(
        "A passport issues where legal duty attaches, and inputs are recorded \
         at the finest identifier granularity available even when no passport \
         regime yet exists behind them (dormant identifiers) (I7, I3).",
    )?;
    Ok(log)
}
