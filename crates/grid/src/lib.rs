//! The grid: parallel sovereignty segments crossed with the universal
//! layered stack (ARCHITECTURE §1).
//!
//! A device DPP is ONE layered stack (identity ← log ← commitments ←
//! signatures ← verdicts) crossed with MANY parallel, policy-defined
//! segments. Segments are the federated lexicon: each governed by a
//! signed [`PolicyObject`](policy::PolicyObject) under its own
//! authority, independently versioned and revoked; verifying one
//! never opens another. Layers are the shared grammar: nothing above
//! repairs what is broken below.
//!
//! The [`Spine`](spine::Spine) is the cross-segment commitment root:
//! one root over every segment's sealed state commitment proving
//! existence, currency and append-only growth — without opening any
//! segment. The spine carries hashes, never facts.
//!
//! This crate is the pure model: canonical forms, reveal classes,
//! Merkle arithmetic, supersession. Signing lives one layer up
//! (unidpp-signatif's grid seam, over these canonical bytes); the
//! deployment-level sovereignty story (profiles, egress) is
//! unidpp-config's — different layer, different crate, one doctrine.

pub mod policy;
pub mod segment;
pub mod spine;

pub use policy::{PolicyObject, PolicyRef, PolicyVerdict, RevealClass};
pub use segment::Segment;
pub use spine::{Spine, SpineProof};
