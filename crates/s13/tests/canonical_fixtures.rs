//! CN-2 golden vectors: the canonical bytes and digests of the S13
//! message objects, pinned as versioned fixtures and replayed in CI
//! (spec Annex B, B.4). Regeneration: UNIDPP_UPDATE_FIXTURES=1
//! cargo test — the fixture diff IS the rule change.

use unidpp_grid::{PolicyObject, RevealClass};
use unidpp_s13::{S13Request, S13Response};

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

fn request() -> S13Request {
    S13Request {
        verifier: "de-zoll".into(),
        subject: "urn:unidpp:passport:pack-0001".into(),
        profile: "urn:unidpp:profile:eu-battery".into(),
        segment: "cn-dynamic".into(),
        at: "2030-06-01T08:00:00Z".into(),
    }
}

fn policy() -> PolicyObject {
    PolicyObject {
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
    }
}

#[test]
fn vector_request() {
    let req = request();
    check(
        "request.json",
        serde_json::json!({
            "version": 1,
            "family": "s13/request",
            "request": serde_json::to_value(&req).unwrap(),
            "canonical_hex": hex(&req.canonical_bytes()),
            "digest_hex": hex(&req.digest()),
        }),
    );
}

#[test]
fn vector_response() {
    let resp = S13Response::evaluate(&request(), &policy(), "weilian-shenzhen");
    assert!(serde_json::to_string(&resp.outcome).unwrap().contains("attestation-offer"));
    check(
        "response.json",
        serde_json::json!({
            "version": 1,
            "family": "s13/response",
            "response": serde_json::to_value(&resp).unwrap(),
            "canonical_hex": hex(&resp.canonical_bytes()),
        }),
    );
}
