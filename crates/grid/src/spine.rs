//! The commitment spine — one root over every segment's state
//! commitment (SG-3): existence, currency, append-only growth,
//! provable without opening any segment.

use std::collections::BTreeMap;

use crate::domain::{hash_in, SPINE_DIGEST, SPINE_LEAF, SPINE_NODE};

fn hpair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    hash_in(SPINE_NODE, &[l, r])
}

fn leaf_hash(segment_id: &str, commitment: &[u8; 32]) -> [u8; 32] {
    hash_in(SPINE_LEAF, &[segment_id.as_bytes(), commitment])
}

/// The spine over a segment set: the map of segment ids to their
/// current state commitments, plus the Merkle root over the
/// sorted-leaf set. It carries hashes, never facts — SG-7's log
/// discipline at the grid level.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Spine {
    /// Monotone spine version (each publication increments).
    pub version: u64,
    pub commitments: BTreeMap<String, [u8; 32]>,
    pub root: [u8; 32],
}

impl Spine {
    /// Compute the spine over a commitment set (sorted by segment id
    /// — BTreeMap's order IS the canonical leaf order).
    pub fn over(version: u64, commitments: BTreeMap<String, [u8; 32]>) -> Spine {
        let root = merkle_root(
            &commitments
                .iter()
                .map(|(id, c)| leaf_hash(id, c))
                .collect::<Vec<_>>(),
        );
        Spine {
            version,
            commitments,
            root,
        }
    }

    /// Inclusion proof for one segment: the sibling path from its
    /// leaf to the root. Proves the segment's commitment is in THIS
    /// spine — existence and currency — without any other segment's
    /// data.
    pub fn proof(&self, segment_id: &str) -> Option<SpineProof> {
        let commitment = self.commitments.get(segment_id)?;
        let mut level: Vec<[u8; 32]> = self
            .commitments
            .iter()
            .map(|(id, c)| leaf_hash(id, c))
            .collect();
        // Track the target's INDEX level by level (pairing keeps no
        // names); the sibling at each level is the other half of the
        // pair, or the node itself for a dangling last leaf.
        let mut idx = self.commitments.keys().position(|k| k == segment_id)?;
        let mut path = Vec::new();
        while level.len() > 1 {
            let sib = if idx % 2 == 0 {
                *level.get(idx + 1).unwrap_or(&level[idx])
            } else {
                level[idx - 1]
            };
            path.push(sib);
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [a] => hpair(a, a),
                    [a, b] => hpair(&min_of(a, b), &max_of(a, b)),
                    _ => unreachable!(),
                })
                .collect();
            idx /= 2;
        }
        Some(SpineProof {
            segment_id: segment_id.to_string(),
            commitment: *commitment,
            root: self.root,
            siblings: path,
        })
    }

    /// Append-only growth (SG-3): this spine proves `prior` — every
    /// prior commitment is present UNCHANGED, and only additions
    /// explain the difference. No segment ever rewinds.
    pub fn proves_prefix(&self, prior: &Spine) -> bool {
        self.version >= prior.version
            && prior
                .commitments
                .iter()
                .all(|(id, c)| self.commitments.get(id) == Some(c))
    }

    /// The spine's digest (what a transparency log or a composite
    /// signature would anchor).
    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(8 + self.commitments.len() * 40);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.root);
        for (id, c) in &self.commitments {
            buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(c);
        }
        hash_in(SPINE_DIGEST, &[&buf])
    }
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [a] => hpair(a, a),
                // Order-insensitive pairing: the root must not depend
                // on which leaf hashes higher — proofs recompute the
                // same pairing from sibling hashes alone.
                [a, b] => hpair(&min_of(a, b), &max_of(a, b)),
                _ => unreachable!(),
            })
            .collect();
    }
    level[0]
}

fn min_of(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a <= b {
        *a
    } else {
        *b
    }
}

fn max_of(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a > b {
        *a
    } else {
        *b
    }
}

/// Inclusion proof: the sibling path from a segment's leaf to the
/// spine root. Contains ONLY hashes for the named segment — nothing
/// openable about any other segment.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpineProof {
    pub segment_id: String,
    pub commitment: [u8; 32],
    pub root: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

impl SpineProof {
    /// Validate against a spine root: recomputes the path from the
    /// segment's leaf. A forged commitment or a spliced path fails.
    pub fn verifies_against(&self, root: &[u8; 32]) -> bool {
        let mut node = leaf_hash(&self.segment_id, &self.commitment);
        for sib in &self.siblings {
            node = if &node <= sib {
                hpair(&node, sib)
            } else {
                hpair(sib, &node)
            };
        }
        node == *root && self.root == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spine_of(items: &[(&str, [u8; 32])], version: u64) -> Spine {
        let mut map = BTreeMap::new();
        for (id, c) in items {
            map.insert(id.to_string(), *c);
        }
        Spine::over(version, map)
    }

    fn c(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn proofs_validate_and_forges_fail() {
        // Adversarial commitments where leaf order != hash order —
        // pairing must be order-insensitive end to end (the G-GRID
        // demo's real commitments caught the positional bug).
        let hard = Spine::over(7, {
            let mut m = BTreeMap::new();
            m.insert("a".to_string(), [0xFF; 32]);
            m.insert("b".to_string(), [0x00; 32]);
            m
        });
        for id in ["a", "b"] {
            let proof = hard.proof(id).expect("proof");
            assert!(proof.verifies_against(&hard.root), "{id} adversarial");
        }
        let spine = spine_of(
            &[("cn-static", c(1)), ("cn-dynamic", c(2)), ("eu", c(3))],
            4,
        );
        for id in ["cn-static", "cn-dynamic", "eu"] {
            let proof = spine.proof(id).expect("proof exists");
            assert!(proof.verifies_against(&spine.root), "{id}");
        }
        // A forged commitment under a real path fails.
        let mut forged = spine.proof("cn-dynamic").unwrap();
        forged.commitment = c(99);
        assert!(!forged.verifies_against(&spine.root));
        // A spliced sibling path fails.
        let mut spliced = spine.proof("eu").unwrap();
        spliced.siblings[0] = c(98);
        assert!(!spliced.verifies_against(&spine.root));
    }

    // CN-3's verify: a segment commitment — a value derived in the
    // SEGMENT-COMMITMENT domain — replayed as a spine input (a
    // sibling node hash, or a leaf hash presented as a commitment)
    // is rejected. The domains are disjoint by construction; the
    // proof arithmetic confirms it end to end.
    #[test]
    fn cross_domain_substitution_is_rejected() {
        let commitments: BTreeMap<String, [u8; 32]> = [
            (
                "cn-static".to_string(),
                crate::segment::Segment::commit_state(b"a=1"),
            ),
            (
                "cn-dynamic".to_string(),
                crate::segment::Segment::commit_state(b"b=2"),
            ),
            (
                "eu".to_string(),
                crate::segment::Segment::commit_state(b"c=3"),
            ),
        ]
        .into_iter()
        .collect();
        let spine = Spine::over(4, commitments);

        // A commitment spliced in where a sibling NODE hash belongs.
        let eu_commitment = spine.commitments["eu"];
        let mut replayed = spine.proof("eu").unwrap();
        replayed.siblings[0] = eu_commitment;
        assert!(!replayed.verifies_against(&spine.root));

        // A leaf-hash value presented as a commitment (the reverse
        // replay): recompute eu's leaf hash and claim it as state.
        let leaf_eu = crate::domain::hash_in(
            crate::domain::SPINE_LEAF,
            &[b"eu", &spine.commitments["eu"]],
        );
        let mut reverse = spine.proof("eu").unwrap();
        reverse.commitment = leaf_eu;
        assert!(!reverse.verifies_against(&spine.root));

        // Distinctness, stated: no commitment equals any leaf hash,
        // and the spine digest is not the root.
        for (id, c) in &spine.commitments {
            let leaf = crate::domain::hash_in(crate::domain::SPINE_LEAF, &[id.as_bytes(), c]);
            assert_ne!(*c, leaf, "{id}");
        }
        assert_ne!(spine.digest(), spine.root);
    }

    #[test]
    fn growth_is_append_only_and_provable() {
        let v1 = spine_of(&[("cn-static", c(1)), ("cn-dynamic", c(2))], 1);
        let mut next = v1.commitments.clone();
        next.insert("eu".to_string(), c(3));
        let v2 = Spine::over(2, next);
        assert!(v2.proves_prefix(&v1), "growth proves the prior spine");
        assert!(!v1.proves_prefix(&v2), "rewinds prove nothing");
        // A CHANGED prior commitment is not a prefix (no rewrite).
        let mut forged = v1.commitments.clone();
        forged.insert("cn-dynamic".to_string(), c(42));
        let v2_bad = Spine::over(2, forged);
        assert!(!v2_bad.proves_prefix(&v1));
    }

    #[test]
    fn the_spine_wire_carries_no_facts() {
        let spine = spine_of(&[("owner", c(7))], 1);
        let json = serde_json::to_string(&spine).unwrap();
        assert!(json.contains("commitments"));
        assert!(!json.to_lowercase().contains("voltage"), "{json}");
        let proof = spine.proof("owner").unwrap();
        let pjson = serde_json::to_string(&proof).unwrap();
        assert!(!pjson.contains("state"), "proofs stay hash-shaped: {pjson}");
    }
}
