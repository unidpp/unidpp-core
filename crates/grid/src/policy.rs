//! Policy objects — a segment's constitution (SG-2).

use unidpp_model::{sha256, CanonicalWriter, Hash};

/// Length-prefixed canonical fields (the family's framing convention:
/// unambiguous, stable under re-serialization).
fn canonical_fields(parts: &[&[u8]]) -> Vec<u8> {
    let mut w = CanonicalWriter::new();
    for p in parts {
        w.write_bytes(p);
    }
    w.into_bytes()
}

/// How a segment's contents may be revealed, and to whom (SG-5's
/// classes; enforcement = policy + cryptography + attestability).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RevealClass {
    /// Public to any reader.
    Open,
    /// Revealed only to an authenticated pairing partner.
    PairingGated,
    /// Sealed to the origin; foreign verifiers receive attestations
    /// *about* the segment, never its plaintext (XB-2's substrate).
    OriginSealed,
    /// Decryptable only via a threshold-trustee escrow ceremony
    /// (TR-8's substrate).
    Escrowed,
}

impl RevealClass {
    pub fn token(self) -> &'static str {
        match self {
            RevealClass::Open => "open",
            RevealClass::PairingGated => "pairing-gated",
            RevealClass::OriginSealed => "origin-sealed",
            RevealClass::Escrowed => "escrowed",
        }
    }
}

/// A versioned reference to a policy object (what a segment pins).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyRef {
    pub policy_id: String,
    pub version: u64,
}

/// The segment's constitution: authority, roles, reveal rules, key
/// custody, suites, window. Signed by its authority (the signature
/// rides signatif's grid seam over [`PolicyObject::canonical_bytes`]).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PolicyObject {
    pub policy_id: String,
    pub version: u64,
    /// The segment authority (trust-graph node id).
    pub authority: String,
    /// Node ids permitted each action (read/verify see the segment's
    /// contents; write may extend it — custody of its keys follows
    /// the authority's chain, not this list).
    pub readers: Vec<String>,
    pub verifiers: Vec<String>,
    pub writers: Vec<String>,
    pub reveal: RevealClass,
    /// The suites this segment's signatures accept (agility is a
    /// policy property, TR-6's substrate).
    pub suites: Vec<String>,
    /// Effective window (RFC 3339), matching the event model's
    /// interval convention.
    pub valid_from: String,
    pub valid_to: Option<String>,
    /// Set when this policy has been superseded (SG-2: stale policy
    /// references are detectable at verification).
    pub superseded_by: Option<u64>,
}

impl PolicyObject {
    /// The canonical, signable form: every field in a fixed order,
    /// length-prefixed — stable across serializers and versions.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Roles and suites: canonical (sorted, deduplicated) so equal
        // policies serialize to equal bytes.
        let canon_list = |v: &[String]| -> Vec<u8> {
            let mut s: Vec<&str> = v.iter().map(|x| x.as_str()).collect();
            s.sort();
            s.dedup();
            s.join("\u{1f}").into_bytes()
        };
        let mut parts: Vec<Vec<u8>> = vec![
            self.policy_id.as_bytes().to_vec(),
            self.version.to_le_bytes().to_vec(),
            self.authority.as_bytes().to_vec(),
            self.reveal.token().as_bytes().to_vec(),
            self.valid_from.as_bytes().to_vec(),
            canon_list(&self.readers),
            canon_list(&self.verifiers),
            canon_list(&self.writers),
            canon_list(&self.suites),
        ];
        if let Some(to) = &self.valid_to {
            parts.push(to.as_bytes().to_vec());
        }
        if let Some(sup) = self.superseded_by {
            parts.push(sup.to_le_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        canonical_fields(&refs)
    }

    /// The policy's content digest (identity for spine-adjacent uses).
    pub fn digest(&self) -> Hash {
        sha256(&[&self.canonical_bytes()])
    }

    /// Whether a policy reference is stale against this object:
    /// exact-version match and not superseded (SG-2's detectability).
    pub fn status_for(&self, r: &PolicyRef) -> PolicyVerdict {
        if r.policy_id != self.policy_id {
            return PolicyVerdict::UnknownPolicy;
        }
        if self.superseded_by.is_some() {
            return PolicyVerdict::Stale {
                have: self.version,
                current: self.superseded_by.unwrap_or_default(),
            };
        }
        if r.version != self.version {
            return PolicyVerdict::VersionDrift {
                referenced: r.version,
                current: self.version,
            };
        }
        PolicyVerdict::Current
    }
}

/// What a policy check concluded — graded, never boolean (I9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    Current,
    Stale { have: u64, current: u64 },
    VersionDrift { referenced: u64, current: u64 },
    UnknownPolicy,
}

impl PolicyVerdict {
    pub fn is_current(&self) -> bool {
        matches!(self, PolicyVerdict::Current)
    }

    pub fn label(&self) -> &'static str {
        match self {
            PolicyVerdict::Current => "current",
            PolicyVerdict::Stale { .. } => "stale",
            PolicyVerdict::VersionDrift { .. } => "version-drift",
            PolicyVerdict::UnknownPolicy => "unknown-policy",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(version: u64) -> PolicyObject {
        PolicyObject {
            policy_id: "cn-dynamic-bms".into(),
            version,
            authority: "cn-samr".into(),
            readers: vec!["cn-customs".into(), "bms-oem".into()],
            verifiers: vec!["cn-customs".into()],
            writers: vec!["bms-oem".into()],
            reveal: RevealClass::OriginSealed,
            suites: vec!["sm2".into()],
            valid_from: "2027-01-01T00:00:00Z".into(),
            valid_to: None,
            superseded_by: None,
        }
    }

    #[test]
    fn canonical_bytes_are_order_insensitive_for_lists() {
        let mut a = policy(1);
        let mut b = policy(1);
        b.readers.reverse();
        b.suites.reverse();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        // Any content change changes the bytes.
        a.authority = "other".into();
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn supersession_and_drift_are_detectable() {
        let current = policy(1);
        assert!(current
            .status_for(&PolicyRef {
                policy_id: "cn-dynamic-bms".into(),
                version: 1
            })
            .is_current());
        assert_eq!(
            current.status_for(&PolicyRef {
                policy_id: "cn-dynamic-bms".into(),
                version: 2
            }),
            PolicyVerdict::VersionDrift {
                referenced: 2,
                current: 1
            }
        );
        let mut superseded = policy(1);
        superseded.superseded_by = Some(2);
        assert_eq!(
            superseded.status_for(&PolicyRef {
                policy_id: "cn-dynamic-bms".into(),
                version: 1
            }),
            PolicyVerdict::Stale {
                have: 1,
                current: 2
            }
        );
        assert_eq!(
            current.status_for(&PolicyRef {
                policy_id: "nope".into(),
                version: 1
            }),
            PolicyVerdict::UnknownPolicy
        );
    }

    #[test]
    fn policy_objects_round_trip_through_serde() {
        let p = policy(3);
        let json = serde_json::to_string(&p).unwrap();
        let back: PolicyObject = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        assert_eq!(p.canonical_bytes(), back.canonical_bytes());
    }
}
