# unidpp-core
Part of UniDPP (github.com/unidpp).
Rust workspace implementing the international DPP framework per
the UniDPP design framework invariants I1–I14. License: Apache-2.0.

Crates: `model` (canonical types, hashing, identifiers), `event`
(typed event payloads, log, status machine), `transform` (split,
combine, taint, quantity algebra, roll-up attestations), `tier_a`
(the offline carrier), `verdict` (graded outcomes), `unidpp-demo`
(deterministic pilot fixtures).

## `transform::rollup` — signed roll-up attestations

Deep graphs are not served by flattening them: a parent's profile
view is an **aggregate over a committed traversal set** — the ordered
set of (child passport, version, state hash, labelled quantities)
the roll-up covers, hashed into a Merkle root
([`TraversalSet::root`]). [`RollupAttestation`] commits to that root,
the member count, the computed aggregates (labelled sums in canonical
units), and a cited method reference; any single member's inclusion
is spot-checkable from a sibling path
([`TraversalSet::inclusion_proof`] →
[`TraversalSet::verify_inclusion`]) without the rest of the set.

Layering: the crate is data + hashing + aggregation, with no
cryptographic dependencies — the attestation carries a core
[`SigSlot`] whose bytes cover [`RollupAttestation::canonical_body`],
and real signing lives in the trust layer (`unidpp-signatif`).
[`verify_rollup`] takes the slot check as a predicate, so structural
verification here is complete and testable on its own.

```rust
use unidpp_model::{sha256, PassportId};
use unidpp_transform::{rollup, Quantity, UnitRegistry};

let registry = UnitRegistry::iso80000();
let member = |tag: &str, grams: &str| rollup::TraversalMember {
    passport: PassportId::new(&format!("urn:unidpp:passport:{tag}")).unwrap(),
    version: 1,
    state_hash: sha256(&[tag.as_bytes()]),
    quantities: [(
        "recycled-content-mass".to_string(),
        Quantity::parse(grams, "g", &registry).unwrap(),
    )]
    .into_iter()
    .collect(),
};
let set = rollup::TraversalSet::new(vec![member("cell-1", "120"), member("cell-2", "80")])?;

let (mut attestation, body) = rollup::RollupAttestation::build(
    PassportId::new("urn:unidpp:passport:pack-7").unwrap(),
    &set,
    "urn:unidpp:transform:recycled-content-sum",
    "urn:unidpp:eo:attester-42",
    &registry,
)?;
// The trust layer signs `body` and installs the slot:
attestation.install_signature(my_trust_layer.sign(&body));

// Verifier side: recompute root, count, aggregates; then the slot.
let proof = set.inclusion_proof(0).unwrap();
let root = set.root();
assert!(rollup::TraversalSet::verify_inclusion(
    &set.members()[0],
    0,
    set.members().len(),
    &proof,
    &root
));
match rollup::verify_rollup(&attestation, &set, &registry, |slot, body| {
    my_trust_layer.verify(slot, body)
}) {
    rollup::RollupVerdict::Verified => {}
    other => { /* RootMismatch / MemberCountMismatch /
                  AggregateMismatch{..} / SignatureRejected(why) */ }
}
```

## `EventPayload::UpgradeInstall` — the E6 class

The typed payload set covers every event class of the taxonomy;
E6 (`upgrade.install`, "add component", installer-appended) carries
the reference of the added child:

```rust
use unidpp_event::{EventPayload, EventType};
use unidpp_model::PassportId;

let payload = EventPayload::UpgradeInstall {
    added: PassportId::new("urn:unidpp:passport:component-9").unwrap(),
};
assert_eq!(payload.event_type(), EventType::UpgradeInstall);
```

Every payload variant answers [`EventPayload::event_type`], so
serialization round-trips keep the taxonomy class without stringly
typing.
