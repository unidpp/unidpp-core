//! CN-2 golden vectors: the canonical bytes and digests of the
//! grid's committed objects, pinned as versioned fixtures and
//! replayed in CI (spec Annex B, B.4). An implementation that
//! reproduces these digests is conformant; one that does not is not.
//!
//! The code below is the source of truth for the INPUTS; the files
//! pin the derived values. To change a canonicalization rule:
//! UNIDPP_UPDATE_FIXTURES=1 cargo test — the fixture diff IS the
//! rule change, review it like code.

use std::collections::BTreeMap;

use unidpp_grid::{PolicyObject, RevealClass, Segment, Spine};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn check(name: &str, value: serde_json::Value) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/canonical");
    let path = format!("{dir}/{name}");
    if std::env::var("UNIDPP_UPDATE_FIXTURES").is_ok() {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        return;
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("fixture {name} unreadable ({e}); regenerate with UNIDPP_UPDATE_FIXTURES=1")
        }))
        .unwrap();
    assert_eq!(
        pinned, value,
        "{name}: canonical-form drift — if intended, regenerate with \
         UNIDPP_UPDATE_FIXTURES=1 and review the diff"
    );
}

fn commitments() -> BTreeMap<String, [u8; 32]> {
    [
        ("cn-dynamic", b"cycle_count=412,voltage=3.71" as &[u8]),
        ("eu-static", b"cell_model=H-2231,capacity_Ah=52"),
        ("owner-private", b"owner_notes"),
    ]
    .into_iter()
    .map(|(id, state)| (id.to_string(), Segment::commit_state(state)))
    .collect()
}

#[test]
fn vector_segment_commitment() {
    let state = b"cycle_count=412,voltage=3.71,temp=28.4";
    check(
        "segment-commitment.json",
        serde_json::json!({
            "version": 1,
            "family": "grid/segment-commitment",
            "domain": "UNIDPP-GRID/SEGMENT-COMMITMENT",
            "state_hex": hex(state),
            "commitment_hex": hex(&Segment::commit_state(state)),
        }),
    );
}

#[test]
fn vector_policy_object() {
    let policy = PolicyObject {
        policy_id: "cn-dynamic-bms".into(),
        version: 1,
        authority: "cn-samr".into(),
        readers: vec!["cn-customs".into()],
        verifiers: vec!["cn-customs".into(), "de-zoll".into()],
        writers: vec!["weilian-shenzhen".into()],
        reveal: RevealClass::OriginSealed,
        suites: vec!["sm2".into()],
        valid_from: "2027-01-01T00:00:00Z".into(),
        valid_to: None,
        superseded_by: None,
    };
    check(
        "policy.json",
        serde_json::json!({
            "version": 1,
            "family": "grid/policy",
            "policy": serde_json::to_value(&policy).unwrap(),
            "canonical_hex": hex(&policy.canonical_bytes()),
            "digest_hex": hex(&policy.digest().0),
        }),
    );
}

#[test]
fn vector_spine_root_and_digest() {
    let spine = Spine::over(4, commitments());
    let commitment_map: serde_json::Map<String, serde_json::Value> = spine
        .commitments
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::json!(hex(v))))
        .collect();
    check(
        "spine.json",
        serde_json::json!({
            "version": spine.version,
            "family": "grid/spine",
            "domains": ["UNIDPP-GRID/SPINE-LEAF", "UNIDPP-GRID/SPINE-NODE", "UNIDPP-GRID/SPINE-DIGEST"],
            "commitments": commitment_map,
            "root_hex": hex(&spine.root),
            "digest_hex": hex(&spine.digest()),
        }),
    );
}

#[test]
fn vector_spine_inclusion_proof() {
    let spine = Spine::over(4, commitments());
    let proof = spine.proof("cn-dynamic").expect("segment present");
    assert!(proof.verifies_against(&spine.root));
    check(
        "spine-proof.json",
        serde_json::json!({
            "version": 1,
            "family": "grid/spine-proof",
            "segment_id": "cn-dynamic",
            "root_hex": hex(&spine.root),
            "proof": serde_json::to_value(&proof).unwrap(),
        }),
    );
}
