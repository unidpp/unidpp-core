//! Commitments: salted hashes for event chaining and blind edges.
//!
//! Salt discipline (the load-bearing rule, tested by property):
//! - the event commitment is H(salt? || prev || canonical_body);
//! - a blind parent reference is H(salt || parent_id) — proof-of-binding
//!   without knowledge-of-parent;
//! - salts live only in the owner-side [`crate::log::SaltStore`] (or an
//!   escrow envelope), never in the log, never in any serialization of it.

use unidpp_model::{sha256, Hash, PassportId};

/// Salted commitment to a parent identity (child-side installation edge).
pub fn parent_commitment(parent: &PassportId, salt: &[u8; 32]) -> Hash {
    sha256(&[salt, parent.as_str().as_bytes()])
}

/// Verify a parent binding under a disclosure ceremony (court, regulator,
/// consent): given the revealed parent and salt, recompute.
pub fn verify_parent_binding(parent: &PassportId, salt: &[u8; 32], commitment: &Hash) -> bool {
    parent_commitment(parent, salt) == *commitment
}

/// Event commitment: each event commits to the full prefix (hash chain)
/// and, when salted, whitens the body against dictionary attack.
pub fn event_commitment(body: &[u8], prev: Option<Hash>, salt: Option<&[u8; 32]>) -> Hash {
    let prev_bytes = prev.map(|h| h.0).unwrap_or([0u8; 32]);
    match salt {
        Some(s) => sha256(&[s, &prev_bytes, body]),
        None => sha256(&[&[], &prev_bytes, body]),
    }
}

/// Deterministic salt derivation from seed material (tests, escrow
/// ceremonies). Production salts must come from a CSPRNG.
pub fn salt_from_seed(seed: &[u8]) -> [u8; 32] {
    sha256(&[seed]).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic_and_salted() {
        let parent = PassportId::new("urn:unidpp:passport:car-42").unwrap();
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let c1 = parent_commitment(&parent, &s1);
        assert_eq!(c1, parent_commitment(&parent, &s1));
        // Salt whitens: same parent, different salt -> different commitment.
        assert_ne!(c1, parent_commitment(&parent, &s2));
        // Same salt, different parent -> different commitment.
        let other = PassportId::new("urn:unidpp:passport:car-43").unwrap();
        assert_ne!(c1, parent_commitment(&other, &s1));
        assert!(verify_parent_binding(&parent, &s1, &c1));
        assert!(!verify_parent_binding(&other, &s1, &c1));
        assert!(!verify_parent_binding(&parent, &s2, &c1));
    }

    #[test]
    fn chain_commitment_covers_prefix_and_body() {
        let body = b"canonical-body";
        let prev = sha256(&[b"prev"]);
        let unsalted = event_commitment(body, Some(prev), None);
        let salted = event_commitment(body, Some(prev), Some(&[9u8; 32]));
        assert_ne!(unsalted, salted);
        assert_ne!(
            event_commitment(body, Some(prev), None),
            event_commitment(b"canonical-body2", Some(prev), None)
        );
        assert_ne!(
            event_commitment(body, Some(prev), None),
            event_commitment(body, None, None)
        );
    }
}
