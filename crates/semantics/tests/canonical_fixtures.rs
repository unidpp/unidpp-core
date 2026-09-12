//! CN-2 golden vectors: the mapping discipline's canonical bytes
//! (SI-12 / Part 7), pinned as versioned fixtures and replayed in CI
//! (spec Annex B, B.4) — and reproduced by the foreign harness
//! (unidpp-py's F3 leg) from Annex B and the clause text alone.
//! Regeneration: UNIDPP_UPDATE_FIXTURES=1 cargo test.

use unidpp_semantics::mapping::{MappingChain, MappingItem, MappingKind};

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

fn tier1_hop(source: &str, target: &str, version: u64, transform: &str) -> MappingItem {
    MappingItem {
        source: source.into(),
        target: target.into(),
        version,
        kind: MappingKind::Deterministic {
            transform: transform.into(),
        },
    }
}

#[test]
fn vector_mapping_chain() {
    // The F3 class material as data: a two-hop tier-1 chain (EU →
    // CN → JP element sets), a tier-2 correspondence with declared
    // scope and residual, and a tier-3 divergence record — each with
    // its canonical bytes; the chain with its recorded versions.
    let hop_a = tier1_hop(
        "urn:unidpp:elements:eu-battery@3",
        "urn:unidpp:elements:cn-battery@2",
        1,
        "urn:unidpp:transform:eu-cn-mass@4",
    );
    let hop_b = tier1_hop(
        "urn:unidpp:elements:cn-battery@2",
        "urn:unidpp:elements:jp-battery@1",
        2,
        "urn:unidpp:transform:cn-jp-mass@1",
    );
    let chain = MappingChain::single(hop_a.clone())
        .expect("single")
        .then(hop_b.clone(), 8)
        .expect("compose");
    let correspondence = MappingItem {
        source: "urn:unidpp:elements:eu-battery@3".into(),
        target: "urn:unidpp:elements:us-battery@1".into(),
        version: 1,
        kind: MappingKind::Correspondence {
            scope: vec!["carbon-footprint".into(), "recycled-content".into()],
            residual: "recycled-content shares are not covered".into(),
            attester: "jp-meti".into(),
        },
    };
    let divergence = MappingItem {
        source: "urn:unidpp:elements:eu-battery@3".into(),
        target: "urn:unidpp:elements:kr-battery@1".into(),
        version: 1,
        kind: MappingKind::NoMapping {
            note: "divergent legal bases recorded, not reconciled".into(),
        },
    };
    check(
        "mapping-chain.json",
        serde_json::json!({
            "version": 1,
            "family": "semantics/mapping-chain",
            "chain": serde_json::to_value(&chain).unwrap(),
            "chain_versions": chain.versions(),
            "hop_a_canonical_hex": hex(&hop_a.canonical_bytes()),
            "hop_b_canonical_hex": hex(&hop_b.canonical_bytes()),
            "correspondence": serde_json::to_value(&correspondence).unwrap(),
            "correspondence_canonical_hex": hex(&correspondence.canonical_bytes()),
            "divergence": serde_json::to_value(&divergence).unwrap(),
            "divergence_canonical_hex": hex(&divergence.canonical_bytes()),
        }),
    );
}
