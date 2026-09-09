//! Scenario `car`: a composite product is a federation of passports.
//!
//! The car has one passport; the traction battery — independently
//! regulated — has its own, joined by a typed child reference recorded as
//! a blind installation edge in the child's log (proof-of-binding without
//! knowledge-of-parent). A regulator publishes a predicate-based recall;
//! each custodian evaluates it locally against the device-reported twin
//! facts; the verdict layer shows the as-of (evidentiary) reading versus
//! the current-state reading of the same log.
//!
//! Identities and timestamps are ported from the TypeScript fixture
//! `unidpp-ts/packages/model/src/fixtures/car.ts`.

use std::io::Write;

use unidpp_event::{
    verify_parent_binding, BlindInstallSpec, EventLog, EventPayload, EventType, InstallTarget,
    TypedEvent,
};
use unidpp_model::{
    CapabilityClass, DataPointRef, Decimal, FactValue, FreshnessRequirement, InstallMethod,
    Interval, IssuerClass, Pairing, PassportId, ProductIdentifier, ProfileAxes, ProfileId,
    ProfileManifest, Recoverability, Resolution, SigSlot, SignatureSuite, Timestamp, Traversal,
    TriggerPredicate, TrustMarker, TwinFacts, VisibilityClass,
};
use unidpp_tier_a::{EcLevel, TierAPacker, TierAPayload};
use unidpp_verdict::{Reading, VerdictBuilder};

use crate::{print_verdict, salt_for, short_hash, DemoError, Trace};

const BATTERY_PID: &str = "urn:unidpp:passport:battery-pack-bp52-000841";
const CAR_PID: &str = "urn:iso:std:iso-iec:15459:unidpp:passport:car-wvwzzz1jzxw000841";
const RESOLVER: &str = "https://dpp.unidpp.org/r/battery-pack-bp52-000841";

fn pid(s: &str) -> PassportId {
    PassportId::new(s).expect("valid passport id")
}

fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("fixed fixture timestamp parses")
}

/// The EU battery profile (Reg (EU) 2023/1542 shape).
fn eu_battery_profile() -> ProfileManifest {
    let p = ProfileManifest {
        id: ProfileId::new("urn:unidpp:profile:eu-battery-2023-1542").unwrap(),
        issuer_class: IssuerClass::Law,
        axes: ProfileAxes::jurisdiction("EU").with_sector("batteries"),
        trigger: TriggerPredicate::Any,
        min_capability: CapabilityClass::LoggedContact,
        freshness: FreshnessRequirement::Static,
        effective: Interval::starting(ts("2026-09-01T11:30:00Z")),
        data_points: vec![
            DataPointRef::new("ferin:eu", "de.dpp.operator-id", Some("1.0.0")).unwrap(),
            DataPointRef::new("ferin:eu", "de.battery.chemistry", Some("1.0.0")).unwrap(),
            DataPointRef::new("ferin:eu", "de.battery.carbon-footprint", Some("1.3.0")).unwrap(),
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

/// The recall predicate published by market surveillance: evaluated
/// locally by every custodian, never enumerated centrally.
fn recall_predicate() -> TriggerPredicate {
    TriggerPredicate::All(vec![
        TriggerPredicate::FactLt {
            path: "battery.firmware".into(),
            value: FactValue::Str("2.3.1".into()),
        },
        TriggerPredicate::FactGt {
            path: "battery.cycle-count".into(),
            value: FactValue::Num("800".parse::<Decimal>().unwrap()),
        },
    ])
}

/// Run the narrated car scenario.
pub fn run(out: &mut dyn Write, seed: u64) -> Result<(), DemoError> {
    let mut tr = Trace::new(out);
    tr.header("car", seed)?;
    tr.scene(
        "A composite product is a federation of passports, not one \
         mega-passport: the car (VIN WVWZZZ1JZXW000841) carries one passport; \
         the traction battery (SGTIN 9506000134352 + serial BP52-000841), \
         independently regulated, carries its own. The battery's log records \
         its installation as a blind edge. Inside the pack, cell lots are \
         recorded as dormant identifiers (urn:unidpp:id:cell-lot-c75-2026b-0001 \
         and -0002, welded module assembly, absorbing): no cell-passport \
         regime exists yet, so none is minted, but the build record is \
         tomorrow's issuance evidence.",
    )?;

    // --- Step 1: battery issuance.
    tr.step("Issuance of the battery passport (independently regulated child)")?;
    let mut bat = EventLog::new(pid(BATTERY_PID));
    let e = TypedEvent::new(
        0,
        ts("2026-09-01T11:30:00Z"),
        "issuing authority",
        "cellco-eu",
        EventType::Issuance,
        EventPayload::Issuance {
            derived: false,
            inputs: vec![],
        },
        TrustMarker::Attested,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let b0 = bat
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "Issuance by issuing authority / cellco-eu, trust marker attested, \
         binding profile urn:unidpp:profile:eu-battery-2023-1542",
    )?;
    tr.kv("commitment", &short_hash(&b0).to_string())?;
    tr.kv(
        "state",
        "battery-pack-bp52-000841: 0 -> 1 sealed events; status issued",
    )?;
    tr.note(
        "The battery needs its own carrier precisely because it is \
         independently placed on the market and regulated; children join by \
         identity reference, never by data copying (I7, I3).",
    )?;

    // --- Step 2: car issuance.
    tr.step("Issuance of the car passport (parent)")?;
    let mut car_log = EventLog::new(pid(CAR_PID));
    let e = TypedEvent::new(
        0,
        ts("2026-09-12T08:00:00Z"),
        "issuing authority",
        "oem-autowerke",
        EventType::Issuance,
        EventPayload::Issuance {
            derived: false,
            inputs: vec![],
        },
        TrustMarker::Attested,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let c0 = car_log
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "Issuance by issuing authority / oem-autowerke, trust marker attested, \
         binding profile urn:unidpp:profile:eu-vehicle-type-approval",
    )?;
    tr.kv("commitment", &short_hash(&c0).to_string())?;
    tr.kv(
        "state",
        "car-wvwzzz1jzxw000841: 0 -> 1 sealed events; status issued",
    )?;
    tr.note(
        "One passport per placed-on-market product identity; the parent \
         manifest lists the battery as a typed child reference resolvable at \
         another service, and roll-up views are computed from references (I1, I8).",
    )?;

    // --- Step 3: blind installation of the battery into the car.
    tr.step("Blind installation: battery -> car (child-side edge)")?;
    let car_id = pid(CAR_PID);
    let install_salt = salt_for(seed, b"car:bp52-000841:install");
    let e = TypedEvent::new(
        1,
        ts("2026-09-12T08:05:00Z"),
        "installer",
        "oem-autowerke",
        EventType::Install,
        EventPayload::blind_install(
            &car_id,
            &install_salt,
            BlindInstallSpec {
                interval: Interval::starting(ts("2026-09-12T08:05:00Z")),
                method: InstallMethod::Other("bolted-busbar".into()),
                recoverability: Recoverability::Harvestable,
                pairing: Pairing::Firmware,
                slot_id: Some("traction-battery-1".into()),
                escrow: None,
            },
        ),
        TrustMarker::Attested,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let b1 = bat
        .append(e, Some(install_salt), Some(1))
        .map_err(|e| DemoError::msg(e.to_string()))?;
    let bat_json = serde_json::to_string(&bat).map_err(|e| DemoError::msg(e.to_string()))?;
    let salt_hex: String = install_salt.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !bat_json.contains(CAR_PID),
        "blind edge leaked the parent identity"
    );
    assert!(!bat_json.contains(&salt_hex), "blind edge leaked the salt");
    let blind = match &bat.sealed()[1].event.payload {
        EventPayload::Install {
            target: InstallTarget::Blind(b),
        } => b,
        other => {
            return Err(DemoError::msg(format!(
                "expected blind install, got {other:?}"
            )))
        }
    };
    let proof_ok = verify_parent_binding(&car_id, &install_salt, &blind.commitment);
    tr.kv(
        "event",
        "Install (blind edge) by oem-autowerke: slot traction-battery-1, \
         method bolted-busbar, pairing firmware, recoverability harvestable, \
         trust marker attested",
    )?;
    tr.kv(
        "commitment",
        &format!(
            "{} (salted event commitment); parent binding recorded as \
             H(salt || car-id) = {}",
            short_hash(&b1),
            short_hash(&blind.commitment)
        ),
    )?;
    tr.kv(
        "state",
        &format!(
            "battery: 1 -> 2 sealed events; serialized log leaks car id: NO, \
             salt: NO; disclosure ceremony recomputes the binding: {}",
            proof_ok
        ),
    )?;
    tr.note(
        "An installed component is a different legal object from the \
         standalone one: the binding's recoverability spectrum fixes identity \
         continuity (harvestable: recovered but altered, continuing with \
         parent history), and the child-to-parent edge is blind by default \
         because it reveals where a thing is (I5, I12).",
    )?;

    // --- Step 4: custody transfer of the car (consumer edge).
    tr.step("Custody transfer: car delivered to a consumer (retail sale)")?;
    let e = TypedEvent::new(
        1,
        ts("2026-10-01T16:20:00Z"),
        "custodian",
        "dealer-lyon",
        EventType::CustodyTransfer,
        EventPayload::CustodyTransfer {
            from: "urn:unidpp:actor:oem-autowerke".into(),
            to: "consumer-anon-2".into(),
            counterparty_signed: true,
        },
        TrustMarker::SelfDeclared,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let c1 = car_log
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "CustodyTransfer by dealer-lyon to consumer-anon-2, counterparty \
         signed, trust marker self-declared",
    )?;
    tr.kv("commitment", &short_hash(&c1).to_string())?;
    tr.kv(
        "state",
        "car: 1 -> 2 sealed events; custodian now consumer-anon-2; the \
             custody edge carries visibility class blind (object-to-household \
             linkage is personal data)",
    )?;
    tr.note(
        "Post-sale custody extends the event chain, never overwrites it: the \
         transfer is a signed ceremony, the trail survives multiple owners, \
         and even consumer edges default to blind (I4, I12).",
    )?;

    // --- Step 5: BMS milestone (edge segment).
    tr.step("Milestone record: the BMS publishes device-measured counters")?;
    let e = TypedEvent::new(
        2,
        ts("2027-03-04T06:12:00Z"),
        "device",
        "urn:unidpp:device:bms-bp52-000841",
        EventType::MilestoneRecord,
        EventPayload::MilestoneRecord {
            counters: [
                (
                    "battery.cycle-count".to_string(),
                    "815".parse::<Decimal>().unwrap(),
                ),
                (
                    "battery.soh-percent".to_string(),
                    "91.5".parse::<Decimal>().unwrap(),
                ),
            ]
            .into_iter()
            .collect(),
        },
        TrustMarker::SelfDeclared,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let b2 = bat
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "MilestoneRecord by the battery management system (device role), trust \
         marker self-declared",
    )?;
    tr.kv("commitment", &short_hash(&b2).to_string())?;
    tr.kv(
        "state",
        "battery: 2 -> 3 sealed events; counters cycle-count 815, soh 91.5",
    )?;
    tr.note(
        "The device is a tier of the passport system, not a client: lifecycle \
         events originate on-device, and the union of custodian-held segments \
         is joined by identity and commitment hashes (I4, I8).",
    )?;

    // --- Step 6: predicate-based recall.
    tr.step("Predicate-based recall: published predicate, local evaluation")?;
    let predicate = recall_predicate();
    let holdings = TwinFacts::new()
        .set("battery.firmware", FactValue::Str("2.2.0".into()))
        .set(
            "battery.cycle-count",
            FactValue::Num("815".parse().unwrap()),
        );
    let updated = TwinFacts::new()
        .set("battery.firmware", FactValue::Str("2.3.2".into()))
        .set(
            "battery.cycle-count",
            FactValue::Num("815".parse().unwrap()),
        );
    let now_recall = ts("2027-06-15T09:00:00Z");
    let e = TypedEvent::new(
        3,
        now_recall,
        "regulator",
        "eu-market-surveillance",
        EventType::RecallCampaign,
        EventPayload::RecallCampaign {
            campaign: "urn:eu:recall:2027-06-batt-bp52".into(),
            predicate: predicate.clone(),
        },
        TrustMarker::Attested,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let b3 = bat
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "RecallCampaign urn:eu:recall:2027-06-batt-bp52 by eu-market-surveillance, \
         trust marker attested",
    )?;
    tr.kv("commitment", &short_hash(&b3).to_string())?;
    tr.kv(
        "predicate",
        &format!(
            "published as {}; the recall set is never enumerated centrally",
            crate::fmt_predicate(&predicate)
        ),
    )?;
    tr.kv(
        "local eval",
        &format!(
            "custodian holdings {{firmware 2.2.0, cycle-count 815}} -> match: {}; \
             updated holdings {{firmware 2.3.2}} -> match: {}",
            predicate.eval(&holdings, now_recall),
            predicate.eval(&updated, now_recall),
        ),
    )?;
    tr.kv(
        "state",
        &format!(
            "battery: 3 -> 4 sealed events; replayed safety flag: {}",
            bat.safety_flag()
        ),
    )?;
    tr.note(
        "Enumeration resistance is a system property: the predicate is \
         published, each custodian (including dark holdings under national \
         procedure) evaluates it locally against their own facts, and the \
         manufacturer receives aggregates or nothing (I12).",
    )?;

    // --- Step 7: as-of readings.
    tr.step("As-of readings: what a diligent verifier knew, then and now")?;
    let profile = eu_battery_profile();
    let head = bat.head().unwrap();
    let before = ts("2027-01-15T00:00:00Z");
    let after = ts("2027-07-01T00:00:00Z");
    let v_then = VerdictBuilder::new(&bat, before)
        .with_anchor(head)
        .answering(Reading::Evidentiary)
        .build();
    print_verdict(&mut tr, "as-of 2027-01-15", &v_then)?;
    tr.kv(
        "  evidence",
        &format!(
            "as-of prefix contains {} events, {} recalls; the campaign of \
             2027-06-15 is invisible to it",
            v_then.evidentiary.events_total, v_then.evidentiary.recalls
        ),
    )?;
    let v_now = VerdictBuilder::new(&bat, after)
        .with_profile(&profile)
        .with_signatures(vec![
            SigSlot::placeholder(SignatureSuite::EcdsaP256, "k-eu"),
            SigSlot::placeholder(SignatureSuite::Sm2, "k-cn"),
        ])
        .attested_by_third_party(true)
        .with_anchor(head)
        .answering(Reading::CurrentState)
        .build();
    print_verdict(&mut tr, "as-of 2027-07-01", &v_now)?;
    tr.kv(
        "  evidence",
        &format!(
            "as-of prefix contains {} events, {} recall; replayed safety flag \
             {}; multi-suite framing degrades explicitly rather than passing",
            v_now.evidentiary.events_total, v_now.evidentiary.recalls, v_now.current_state.safety,
        ),
    )?;
    tr.note(
        "Law needs all three readings: the evidentiary reading protects \
         good-faith actors who verified before the campaign, the \
         current-state reading carries the recall forward, and the \
         cryptographic reading certifies the chain itself (I9).",
    )?;

    // --- Step 8: Tier-A packing of the battery.
    tr.step("Tier-A packing: the recall flag rides the offline minimum")?;
    let payload = TierAPayload::from_log(
        &bat,
        ProductIdentifier::parse("sgtin:9506000134352+21+BP52-000841").unwrap(),
        RESOLVER,
        "urn:unidpp:actor:cellco-eu",
        Interval::between(ts("2026-09-01T11:30:00Z"), ts("2036-09-01T11:30:00Z")).unwrap(),
        vec![
            SigSlot::placeholder(SignatureSuite::EcdsaP256, "k-eu"),
            SigSlot::placeholder(SignatureSuite::Sm2, "k-cn"),
        ],
    );
    let packer = TierAPacker::new(EcLevel::M, 40);
    let packed = packer
        .pack(&payload)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    let budget_rows: Vec<String> = TierAPacker::budget_report(&payload)
        .iter()
        .map(|(f, n)| format!("{f} {n}B"))
        .collect();
    tr.kv(
        "fields",
        &format!(
            "product id {}, status {}, safety {}, as-of {}, log head {}",
            payload.product_id,
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
    tr.kv(
        "budget",
        &format!(
            "{}; encoded {} B, projected {} B into QR v{} EC m capacity {} B: \
             margin +{} B",
            budget_rows.join(", "),
            packed.used,
            packed.projected,
            packed.version,
            packed.capacity,
            packed.margin()
        ),
    )?;
    tr.note(
        "The single QR on the car resolves the car's identity; the battery's \
         Tier-A carrier is the offline minimum, and the critical safety flag \
         is fixed membership of that minimum, not an optional field (I13).",
    )?;

    assert!(predicate.eval(&holdings, now_recall));
    assert!(!predicate.eval(&updated, now_recall));
    assert_eq!(bat.safety_flag(), unidpp_event::SafetyFlag::RecallActive);
    assert_eq!(v_then.evidentiary.recalls, 0);
    assert_eq!(v_now.evidentiary.recalls, 1);
    assert!(packed.margin() >= 0);

    tr.blank()?;
    tr.done()?;
    Ok(())
}
