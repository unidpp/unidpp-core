//! NF-1's third number: roll-ups over deep graphs verify without
//! full traversal.
//!
//! The requirement: a roll-up over a deep graph shall verify without
//! traversing the graph. The structure that guarantees it is the
//! traversal set's Merkle tree: a member's inclusion verifies by
//! folding its leaf through a sibling path of log₂(N) hashes — the
//! verifier touches the member and the path, never the other N−1
//! members and never the graph behind them.
//!
//! This bench makes both sides of the claim concrete over a graph
//! of 65 536 boundary members: the full traversal (hashing every
//! leaf) and the per-member inclusion verification. The structural
//! check — the proof length equals ⌈log₂ N⌉ — gates the exit code,
//! because sub-linearity is a property of the proof's SHAPE, not of
//! the machine's speed; the timings are reported for the record.
//!
//! Run: cargo run --release --example nf1_rollup_bench [-- <members>]

use std::time::Instant;

use unidpp_model::{sha256, Hash, PassportId};
use unidpp_transform::{TraversalMember, TraversalSet};

fn member(index: usize) -> TraversalMember {
    let mut quantities = std::collections::BTreeMap::new();
    quantities.insert(
        "recycled-content-mass".to_string(),
        unidpp_transform::Quantity::parse(
            &(index % 500).to_string(),
            "g",
            &unidpp_transform::UnitRegistry::iso80000(),
        )
        .expect("quantity"),
    );
    TraversalMember {
        passport: PassportId::new(&format!("urn:unidpp:passport:nf1-{index:06}"))
            .expect("passport id"),
        version: 1,
        state_hash: sha256(&[index.to_le_bytes().as_slice()]),
        quantities,
    }
}

fn main() {
    let members: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(1 << 16);
    assert!(
        members.is_power_of_two(),
        "a clean tree keeps the proof-length law exact"
    );

    let set: Vec<TraversalMember> = (0..members).map(member).collect();
    let set = TraversalSet::new(set).expect("set");

    // The full traversal: hash every leaf — what a verifier without
    // the traversal-set structure would have to do.
    let start = Instant::now();
    let mut acc: Vec<u8> = Vec::new();
    for leaf in set.members() {
        acc.extend_from_slice(&sha256(&[b"UNIDPP/ROLLUP/LEAF|", &leaf.leaf_bytes()]).0);
    }
    let full = start.elapsed();
    let full_us = full.as_micros();

    // The traversal-set verification: one member + its sibling path
    // + the root. The verifier never sees the other members.
    let root: Hash = set.root();
    let probes: Vec<usize> = (0..64).map(|i| i * members / 64 + members / 128).collect();
    let mut proofs = Vec::with_capacity(probes.len());
    for &index in &probes {
        proofs.push(set.inclusion_proof(index).expect("proof"));
    }
    let mut samples: Vec<u128> = Vec::with_capacity(probes.len() * 50);
    for _ in 0..50 {
        for (&index, proof) in probes.iter().zip(&proofs) {
            // The leaf AT the probe's index (the set is in canonical
            // passport-id order; the proof is for that position).
            let leaf = &set.members()[index];
            let start = Instant::now();
            let ok = TraversalSet::verify_inclusion(leaf, index, members, proof, &root);
            let elapsed = start.elapsed().as_micros();
            assert!(ok, "inclusion verification failed at index {index}");
            samples.push(elapsed);
        }
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p95 = samples[(samples.len() - 1) * 95 / 100];

    let proof_len = proofs[0].len();
    let log_n = members.trailing_zeros() as usize;

    println!("NF-1 roll-up verification ({members} boundary members, deep graph behind)");
    println!("  full traversal (all leaves)   {full_us:>9} µs");
    println!("  inclusion verify  p50         {p50:>9} µs");
    println!("  inclusion verify  p95         {p95:>9} µs");
    println!("  proof length    {proof_len} hashes == ceil(log2({members})) = {log_n}");
    println!(
        "  sub-linear by structure: verifier touches 1 member + {proof_len} path hashes, never the other {}",
        members - 1
    );

    // The structural gate: sub-linearity is the proof's shape.
    assert_eq!(
        proof_len, log_n,
        "the inclusion proof must be log2(N) hashes, not N — the shape IS the requirement"
    );
}
