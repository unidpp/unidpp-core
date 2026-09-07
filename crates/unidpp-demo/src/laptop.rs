//! Scenario `laptop`: one neutral core, two jurisdiction profiles.
//!
//! A laptop instance carries EU (ESPR electronics) and JP (METI PSE)
//! profiles on a single neutral-core passport: no region is the universal
//! envelope, profiles constrain and transform but never redefine, and
//! inter-profile disagreement is expected and auditable. The battery
//! child joins by a blind installation edge; a retail custody transfer, a
//! firmware update, and a memory-module replacement extend the log
//! append-only; the glued display module is recorded as a dormant lot
//! identifier. The two lenses then grade the same passport independently.
//!
//! Identities and timestamps are ported from the TypeScript fixture
//! `unidpp-ts/packages/model/src/fixtures/laptop.ts`.

use std::collections::BTreeSet;
use std::io::Write;

use unidpp_event::{BlindInstallSpec, verify_parent_binding, EventLog, EventType, EventPayload, InstallTarget, TypedEvent};
use unidpp_model::{
    CapabilityClass, DataPointRef, FactValue, FreshnessRequirement, InstallMethod, Interval,
    Pairing, PassportId, ProductIdentifier, ProfileAxes, ProfileId, ProfileManifest,
    Recoverability, Resolution, SigSlot, SignatureSuite, Timestamp, Traversal, TriggerPredicate,
    TrustMarker, TwinFacts, VisibilityClass,
};
use unidpp_tier_a::{EcLevel, TierAPacker, TierAPayload};
use unidpp_verdict::{Degradation, Outcome, Reading, VerdictBuilder};

use crate::{print_verdict, short_hash, salt_for, DemoError, Trace};

const LAPTOP_PID: &str = "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345";
const BATTERY_PID: &str = "urn:unidpp:passport:battery-pack-bp52-000841";
const SODIMM_REMOVED: &str = "urn:unidpp:passport:sodimm-16g-aa117-0042";
const SODIMM_ADDED: &str = "urn:unidpp:passport:sodimm-32g-aa119-0007";
const DISPLAY_LOT: &str = "urn:unidpp:id:display-lot-d14-2026q3";

fn pid(s: &str) -> PassportId {
    PassportId::new(s).expect("valid passport id")
}

fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("fixed fixture timestamp parses")
}

/// EU ESPR electronics lens.
fn eu_profile() -> ProfileManifest {
    let p = ProfileManifest {
        id: ProfileId::new("urn:unidpp:profile:eu-espr-electronics").unwrap(),
        axes: ProfileAxes::jurisdiction("EU").with_sector("electronics"),
        trigger: TriggerPredicate::Any,
        min_capability: CapabilityClass::Silent,
        freshness: FreshnessRequirement::Static,
        effective: Interval::starting(ts("2027-01-01T00:00:00Z")),
        data_points: vec![
            DataPointRef::new("ferin:eu", "de.dpp.operator-id", Some("1.0.0")).unwrap(),
            DataPointRef::new("ferin:eu", "de.dpp.reparability-score", Some("1.1.0")).unwrap(),
            DataPointRef::new("ferin:eu", "de.dpp.carbon-footprint", Some("1.2.0")).unwrap(),
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

/// JP METI PSE lens.
fn jp_profile() -> ProfileManifest {
    let p = ProfileManifest {
        id: ProfileId::new("urn:unidpp:profile:jp-meti-pse").unwrap(),
        axes: ProfileAxes::jurisdiction("JP").with_sector("electronics"),
        trigger: TriggerPredicate::FactContains {
            path: "subject.markets".into(),
            needle: "JP".into(),
        },
        min_capability: CapabilityClass::Silent,
        freshness: FreshnessRequirement::Static,
        effective: Interval::starting(ts("2026-10-01T00:00:00Z")),
        data_points: vec![
            DataPointRef::new("ferin:jp", "de.dpp.operator-id", Some("1.0.0")).unwrap(),
            DataPointRef::new("ferin:jp", "de.jp.pse-mark", Some("2.0.0")).unwrap(),
            DataPointRef::new("ferin:jp", "de.jp.top-runner-class", Some("2026.1")).unwrap(),
        ],
        crypto_suites: vec![SignatureSuite::EcdsaP256],
        confidential: false,
        resolution: Resolution::Public,
        edge_visibility: VisibilityClass::Blind,
        traversal: Traversal::RoleScoped,
    };
    p.validate().unwrap();
    p
}

/// Run the narrated laptop scenario.
pub fn run(out: &mut dyn Write, seed: u64) -> Result<(), DemoError> {
    let mut tr = Trace::new(out);
    tr.header("laptop", seed)?;
    tr.scene(
        "One laptop instance (ISO/IEC 15459 identifier \
         urn:...:inst:84120099012345, hw-rev-b, configuration vector \
         ram-2x16g + ssd-512g + display-14) carries a single neutral-core \
         passport. Two jurisdiction lenses bind to it: EU ESPR electronics \
         (from 2027-01-01) and JP METI PSE (from 2026-10-01, when the unit \
         ships to Japan). The battery child joins by a blind installation \
         edge; a glued display module is absorbed under the current regime \
         and recorded as a dormant lot identifier.",
    )?;

    // --- Step 1: laptop issuance.
    tr.step("Issuance of the laptop passport (neutral core)")?;
    let mut lap = EventLog::new(pid(LAPTOP_PID));
    let e = TypedEvent::new(
        0,
        ts("2026-08-03T09:15:00Z"),
        "issuing authority",
        "urn:unidpp:actor:oem-nordwave",
        EventType::Issuance,
        EventPayload::Issuance {
            derived: false,
            inputs: vec![],
        },
        TrustMarker::Attested,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let l0 = lap
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "Issuance by oem-nordwave (economic operator), trust marker attested, \
         binding urn:unidpp:profile:eu-espr-electronics",
    )?;
    tr.kv("commitment", &short_hash(&l0).to_string())?;
    tr.kv("state", "laptop 84120099012345: 0 -> 1 sealed events; status issued")?;
    tr.note(
        "The instance references its exact type version (hw-rev-b is \
         visible, eliminating silent revisions) and overrides with \
         instance-measured facts per precedence rules; the core is neutral \
         and no region is the universal envelope (I1, I2).",
    )?;

    // --- Step 2: JP profile binding (dated binding, not a new identity).
    tr.step("Profile-set growth: JP lens binds by dated binding")?;
    let eu = eu_profile();
    let jp = jp_profile();
    let facts = TwinFacts::new().set(
        "subject.markets",
        FactValue::List(vec!["EU".into(), "JP".into()]),
    );
    let now_check = ts("2027-02-11T10:44:00Z");
    tr.kv(
        "state",
        &format!(
            "no event is appended and no identity is minted: \
             urn:unidpp:profile:jp-meti-pse (effective 2026-10-01) is a \
             registry applicability event with an effective window; at {} \
             EU lens applies: {}, JP lens applies: {}",
            now_check,
            eu.applies_to(&facts, now_check),
            jp.applies_to(&facts, now_check),
        ),
    )?;
    tr.note(
        "Adding a jurisdiction to an existing model is dated binding, not a \
         new identity: the manifest history is as-of reconstructable, and \
         profile growth never changes identity (I6, I10).",
    )?;

    // --- Step 3: blind installation of the battery child.
    tr.step("Blind installation: battery -> laptop (consumer edge)")?;
    let mut bat = EventLog::new(pid(BATTERY_PID));
    let laptop_id = pid(LAPTOP_PID);
    let install_salt = salt_for(seed, b"laptop:bp52-000841:install");
    let e = TypedEvent::new(
        0,
        ts("2026-08-03T09:15:00Z"),
        "installer",
        "urn:unidpp:actor:oem-nordwave",
        EventType::Install,
        EventPayload::blind_install(
            &laptop_id,
            &install_salt,
            BlindInstallSpec {
                interval: Interval::starting(ts("2026-08-03T09:15:00Z")),
                method: InstallMethod::Other("socketed-latch".into()),
                recoverability: Recoverability::Harvestable,
                pairing: Pairing::Firmware,
                slot_id: Some("battery-bay-1".into()),
                escrow: None,
            },
        ),
        TrustMarker::Attested,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let b0 = bat
        .append(e, Some(install_salt), Some(0))
        .map_err(|e| DemoError::msg(e.to_string()))?;
    let bat_json = serde_json::to_string(&bat).map_err(|e| DemoError::msg(e.to_string()))?;
    let salt_hex: String = install_salt.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !bat_json.contains(LAPTOP_PID),
        "blind edge leaked the parent identity"
    );
    assert!(!bat_json.contains(&salt_hex), "blind edge leaked the salt");
    let blind = match &bat.sealed()[0].event.payload {
        EventPayload::Install {
            target: InstallTarget::Blind(b),
        } => b,
        other => return Err(DemoError::msg(format!("expected blind install, got {other:?}"))),
    };
    let proof_ok = verify_parent_binding(&laptop_id, &install_salt, &blind.commitment);
    tr.kv(
        "event",
        "Install (blind edge): slot battery-bay-1, method socketed-latch, \
         pairing firmware, recoverability harvestable, trust marker attested",
    )?;
    tr.kv(
        "commitment",
        &format!(
            "{} (salted); parent binding H(salt || laptop-id) = {}",
            short_hash(&b0),
            short_hash(&blind.commitment)
        ),
    )?;
    tr.kv(
        "state",
        &format!(
            "battery: 0 -> 1 sealed events; serialized log leaks laptop id: \
             NO, salt: NO; disclosure ceremony recomputes the binding: {}",
            proof_ok
        ),
    )?;
    tr.note(
        "The consumer install edge is personal data by default: the child \
         proves valid installation without disclosing the household, and \
         full disclosure happens only by ceremony (court, regulator, \
         consent) (I12).",
    )?;

    // --- Step 4: custody transfer (retail sale).
    tr.step("Custody transfer: retail sale in Kyoto")?;
    let e = TypedEvent::new(
        1,
        ts("2026-08-20T14:02:00Z"),
        "custodian",
        "urn:unidpp:actor:retailer-kyoto-denshi",
        EventType::CustodyTransfer,
        EventPayload::CustodyTransfer {
            from: "urn:unidpp:actor:oem-nordwave".into(),
            to: "consumer-anon-1".into(),
            counterparty_signed: true,
        },
        TrustMarker::SelfDeclared,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let l1 = lap
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "CustodyTransfer by retailer-kyoto-denshi to consumer-anon-1, \
         counterparty signed, trust marker self-declared",
    )?;
    tr.kv("commitment", &short_hash(&l1).to_string())?;
    tr.kv("state", "laptop: 1 -> 2 sealed events; custodian now consumer-anon-1")?;
    tr.note(
        "Custody is a social edge orthogonal to structure: ownership changes \
         while composition stays fixed, and the signed ceremony survives \
         subsequent owners (I5, I4).",
    )?;

    // --- Step 5: software update.
    tr.step("Software update: system firmware 1.04 -> 1.07")?;
    let e = TypedEvent::new(
        2,
        ts("2026-11-05T02:30:00Z"),
        "economic operator",
        "urn:unidpp:actor:oem-nordwave",
        EventType::SoftwareUpdate,
        EventPayload::SoftwareUpdate {
            versions: [("system-firmware".to_string(), "1.07".to_string())]
                .into_iter()
                .collect(),
            unlocked_features: vec![],
        },
        TrustMarker::SelfDeclared,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let l2 = lap
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "SoftwareUpdate (system-firmware 1.04 -> 1.07) by oem-nordwave, trust \
         marker self-declared",
    )?;
    tr.kv("commitment", &short_hash(&l2).to_string())?;
    tr.kv("state", "laptop: 2 -> 3 sealed events; firmware vector updated")?;
    tr.note(
        "Capability enablement changes declared characteristics with no \
         physical change; nothing is edited in place, and such events can \
         trigger profile re-evaluation where a lens demands it (I4, I10).",
    )?;

    // --- Step 6: part replacement.
    tr.step("Part replacement: SODIMM upgrade (not like-for-like)")?;
    let e = TypedEvent::new(
        3,
        ts("2027-02-11T10:44:00Z"),
        "repairer",
        "urn:unidpp:actor:repair-shibuya",
        EventType::PartReplace,
        EventPayload::PartReplace {
            removed: pid(SODIMM_REMOVED),
            added: pid(SODIMM_ADDED),
            like_for_like: false,
        },
        TrustMarker::Attested,
    )
    .map_err(|e| DemoError::msg(e.to_string()))?;
    let l3 = lap
        .append(e, None, None)
        .map_err(|e| DemoError::msg(e.to_string()))?;
    tr.kv(
        "event",
        "PartReplace (sodimm-0042 out, sodimm-32g-0007 in, like-for-like \
         false) by repair-shibuya, trust marker attested",
    )?;
    tr.kv("commitment", &short_hash(&l3).to_string())?;
    tr.kv(
        "state",
        "laptop: 3 -> 4 sealed events; BoM-instance updated; the removed \
         module's own passport history is untouched",
    )?;
    tr.note(
        "Part replacement is uninstall plus install: the old child reference \
         is marked removed, the new one added, and regulated children keep \
         their own passports through it (I5, I4).",
    )?;

    // --- Step 7: dormant display lot.
    tr.step("Absorbed component: the glued display is a dormant identifier")?;
    tr.kv(
        "state",
        &format!(
            "{DISPLAY_LOT} recorded in the build data with binding \
             bonded-adhesive, recoverability absorbing, visibility \
             restricted (regulator); no passport minted"
        ),
    )?;
    tr.note(
        "Absorption records at the finest available granularity, always: the \
         regulatory ratchet turns one way only (finer, never coarser), and \
         when a display-passport regime lands it adopts the recorded dormant \
         identifiers instead of minting fresh ones that would orphan the \
         installed base (I3, I1).",
    )?;

    // --- Step 8: per-lens verdicts.
    tr.step("Two lenses, two verdicts: disagreement is expected and auditable")?;
    let now = ts("2027-02-11T11:00:00Z");
    let head = lap.head().unwrap();
    let provided_eu: BTreeSet<String> = [
        "ferin:eu/de.dpp.operator-id@1.0.0",
        "ferin:eu/de.dpp.reparability-score@1.1.0",
        "ferin:eu/de.dpp.carbon-footprint@1.2.0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let provided_jp: BTreeSet<String> = [
        "ferin:jp/de.dpp.operator-id@1.0.0",
        "ferin:jp/de.jp.pse-mark@2.0.0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let v_eu = VerdictBuilder::new(&lap, now)
        .with_profile(&eu)
        .with_provided(provided_eu)
        .with_anchor(head)
        .answering(Reading::Evidentiary)
        .build();
    print_verdict(&mut tr, "EU lens", &v_eu)?;
    let v_jp = VerdictBuilder::new(&lap, now)
        .with_profile(&jp)
        .with_provided(provided_jp)
        .with_anchor(head)
        .answering(Reading::Evidentiary)
        .build();
    print_verdict(&mut tr, "JP lens", &v_jp)?;
    tr.kv(
        "divergence",
        "the same passport passes the EU lens and degrades under the JP lens \
         because the top-runner-class data point is not yet provided; both \
         verdicts stand side by side, neither overrides the other",
    )?;
    tr.note(
        "Single definition, many constraints: profiles constrain and \
         transform, never redefine; inter-profile disagreement is resolved \
         to canonical facts plus the rules of each lens, never to one true \
         classification, and coverage reports make the gap explicit (I2, I9).",
    )?;

    // --- Step 9: Tier-A packing.
    tr.step("Tier-A packing: the offline minimum for the laptop")?;
    let payload = TierAPayload::from_log(
        &lap,
        ProductIdentifier::parse("cpid:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345")
            .unwrap(),
        "https://dpp.unidpp.org/r/84120099012345",
        "urn:unidpp:actor:oem-nordwave",
        Interval::between(ts("2026-08-03T09:15:00Z"), ts("2036-08-03T09:15:00Z")).unwrap(),
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
        "The carrier embeds the identity, resolver pointer, and log head of \
         the neutral core; every lens is served from Tier B above it, so \
         jurisdiction growth never touches the carrier (I13, I11).",
    )?;

    assert!(matches!(v_eu.outcome, Outcome::Pass));
    assert!(matches!(
        v_jp.outcome,
        Outcome::Degraded(Degradation::CoverageIncomplete { .. })
    ));
    assert!(eu.applies_to(&facts, now_check));
    assert!(jp.applies_to(&facts, now_check));
    assert!(packed.margin() >= 0);

    tr.blank()?;
    tr.done()?;
    Ok(())
}
