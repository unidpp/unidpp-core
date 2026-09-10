//! Segments — one custodian's policy-defined partition of a device
//! DPP (SG-1).

use crate::policy::{PolicyObject, PolicyRef, PolicyVerdict};

/// A segment: the sealed state commitment plus the policy that
/// governs it. The plaintext lives with the custodian; the grid sees
/// only this commitment — verification of segment k requires nothing
/// from any other segment (SG-1's verify condition).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Segment {
    pub segment_id: String,
    /// The subject (passport/thing id) this segment belongs to.
    pub subject: String,
    /// The governing policy, pinned at a version.
    pub policy: PolicyRef,
    /// The sealed-state commitment (canonical event-log prefix
    /// bytes hashed in the SEGMENT-COMMITMENT domain; the hash IS
    /// the interface — no facts here).
    pub state_commitment: [u8; 32],
    /// Monotone; commitment n+1 must extend commitment n (the spine's
    /// growth property rides this).
    pub sequence: u64,
}

impl Segment {
    /// Commit over the custodian's canonical state bytes.
    pub fn commit_state(state_bytes: &[u8]) -> [u8; 32] {
        crate::domain::hash_in(crate::domain::SEGMENT_COMMITMENT, &[state_bytes])
    }

    /// Policy freshness for THIS segment against the live policy
    /// object (graded: SG-2's stale detection).
    pub fn policy_status(&self, policy: &PolicyObject) -> PolicyVerdict {
        policy.status_for(&self.policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitments_are_over_bytes_only() {
        let a = Segment::commit_state(b"voltage=3.7,temp=28");
        let b = Segment::commit_state(b"voltage=3.7,temp=28");
        assert_eq!(a, b);
        assert_ne!(a, Segment::commit_state(b"voltage=3.8,temp=28"));
        // The segment type carries no field for plaintext — by
        // construction the grid cannot hold facts. Assert the wire
        // form stays commitment-shaped.
        let s = Segment {
            segment_id: "cn-dynamic".into(),
            subject: "urn:unidpp:passport:p1".into(),
            policy: PolicyRef {
                policy_id: "cn-dynamic-bms".into(),
                version: 1,
            },
            state_commitment: a,
            sequence: 7,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains("voltage"),
            "no facts on the segment wire: {json}"
        );
    }
}
