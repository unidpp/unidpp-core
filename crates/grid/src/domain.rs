//! Hash-domain separation (CN-3): every hash kind in the grid
//! carries a distinct domain tag, framed `tag || 0x00 || canonical
//! payload` — the same framing rule as SIGNATIF's signature domains
//! (spec Annex B): one rule for every domain-separated operation.
//!
//! A value derived in one domain cannot be re-derived in another:
//! a segment commitment replayed as a spine input is rejected by
//! construction, not by convention.

use unidpp_model::{sha256, CanonicalWriter};

/// A segment's sealed-state commitment (the segment layer).
pub const SEGMENT_COMMITMENT: &[u8] = b"UNIDPP-GRID/SEGMENT-COMMITMENT";
/// A spine leaf over (segment id, state commitment).
pub const SPINE_LEAF: &[u8] = b"UNIDPP-GRID/SPINE-LEAF";
/// A spine pairing node over two child hashes.
pub const SPINE_NODE: &[u8] = b"UNIDPP-GRID/SPINE-NODE";
/// The spine's whole-object digest (what a transparency log anchors).
pub const SPINE_DIGEST: &[u8] = b"UNIDPP-GRID/SPINE-DIGEST";

/// Hash in a domain: `sha256(tag || 0x00 || canonical(parts))`, the
/// parts length-prefixed in order.
pub fn hash_in(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut w = CanonicalWriter::new();
    for p in parts {
        w.write_bytes(p);
    }
    sha256(&[domain, &[0u8], &w.into_bytes()]).0
}

#[cfg(test)]
mod tests {
    use super::*;

    // CN-3's verify: identical payload bytes hashed in different
    // domains yield different values — no domain's output can be
    // mistaken for another's.
    #[test]
    fn hash_domains_are_disjoint() {
        let x = b"some payload";
        let c = hash_in(SEGMENT_COMMITMENT, &[x]);
        let leaf = hash_in(SPINE_LEAF, &[x]);
        let node = hash_in(SPINE_NODE, &[x, x]);
        let digest = hash_in(SPINE_DIGEST, &[x]);
        let mut seen = vec![c, leaf, node, digest];
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 4, "domains overlap: {seen:?}");
    }

    // The framing rule is one rule: the tag prefix, a NUL, then the
    // canonical payload — restate it as bytes an independent
    // implementation can reproduce.
    #[test]
    fn framing_is_tag_nul_canonical_payload() {
        let mut w = CanonicalWriter::new();
        w.write_bytes(b"a");
        w.write_bytes(b"b");
        let mut expect = SEGMENT_COMMITMENT.to_vec();
        expect.push(0);
        expect.extend_from_slice(&w.into_bytes());
        assert_eq!(hash_in(SEGMENT_COMMITMENT, &[b"a", b"b"]), sha256(&[&expect]).0);
    }
}
