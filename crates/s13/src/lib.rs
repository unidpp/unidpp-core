//! S13 — the system↔system seam under policy (ARCHITECTURE §4.2;
//! REQUIREMENTS XB-1): the cross-border choreography.
//!
//! A verifier requests a subject's segment view; the custodian's
//! POLICY answers. Four outcomes, machine-reproducible:
//!
//! | Reveal class (the governing policy) | Outcome |
//! |---|---|
//! | open | **Permit** (the segment is served) |
//! | pairing-gated | **Permit** scoped to the paired verifier |
//! | origin-sealed | **AttestationOffer** (substitution, XB-2) |
//! | escrowed | **Escalation** (the ceremony path, TR-8) |
//!
//! Denial is the absence of a governing policy or an explicit deny —
//! stated, never silent. Both messages are signed in the S13 domain;
//! the response cites the governing policy id + version (XB-3's
//! naming requirement starts here).

pub mod coverage;

use unidpp_grid::{PolicyObject, RevealClass};
use unidpp_model::{sha256, CanonicalWriter};

fn canonical_fields(parts: &[&[u8]]) -> Vec<u8> {
    let mut w = CanonicalWriter::new();
    for p in parts {
        w.write_bytes(p);
    }
    w.into_bytes()
}

/// The verifier's request (signed by the verifier in the S13 domain
/// by the caller — the seam mirrors SegmentPolicy/Profile).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct S13Request {
    /// The requesting node (trust-graph id).
    pub verifier: String,
    /// The subject whose view is requested.
    pub subject: String,
    /// The profile context the verifier verifies under.
    pub profile: String,
    /// The segment in question.
    pub segment: String,
    /// Request moment (RFC 3339).
    pub at: String,
}

impl S13Request {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_fields(&[
            self.verifier.as_bytes(),
            self.subject.as_bytes(),
            self.profile.as_bytes(),
            self.segment.as_bytes(),
            self.at.as_bytes(),
        ])
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.canonical_bytes()]).0
    }
}

/// What the policy evaluation concluded.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum S13Outcome {
    /// The segment is served (reveal: open).
    Permit,
    /// The segment is served to the named paired verifier only.
    PermitPaired { paired_with: String },
    /// The class is sealed: an attestation ABOUT it is offered (XB-2).
    AttestationOffer {
        /// The attestation service that signs substitutions.
        attestation_service: String,
    },
    /// The class is escrowed: threshold-trustee ceremony required.
    Escalation {
        /// The escrow quorum that may disclose.
        escrow_quorum: String,
    },
    /// No governing policy admits this verifier, or an explicit deny.
    Deny { reason: String },
}

/// The custodian's signed answer. Cites the governing policy.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct S13Response {
    /// sha256 of the request this answers (binding).
    pub request_digest: [u8; 32],
    pub outcome: S13Outcome,
    /// The governing policy (id + version) — XB-3 names it.
    pub governing_policy: String,
    pub governing_policy_version: u64,
    /// The answering custodian.
    pub custodian: String,
}

impl S13Outcome {
    /// The stable wire token (also the serde tag).
    pub fn token(&self) -> &'static str {
        match self {
            S13Outcome::Permit => "permit",
            S13Outcome::PermitPaired { .. } => "permit-paired",
            S13Outcome::AttestationOffer { .. } => "attestation-offer",
            S13Outcome::Escalation { .. } => "escalation",
            S13Outcome::Deny { .. } => "deny",
        }
    }

    /// The variant's payload fields, in declaration order (empty for
    /// the bare Permit) — canonical encoding never rides serde.
    fn payload(&self) -> Vec<&[u8]> {
        match self {
            S13Outcome::Permit => vec![],
            S13Outcome::PermitPaired { paired_with } => vec![paired_with.as_bytes()],
            S13Outcome::AttestationOffer {
                attestation_service,
            } => {
                vec![attestation_service.as_bytes()]
            }
            S13Outcome::Escalation { escrow_quorum } => vec![escrow_quorum.as_bytes()],
            S13Outcome::Deny { reason } => vec![reason.as_bytes()],
        }
    }
}

impl S13Response {
    /// The canonical form: request digest, outcome token, outcome
    /// payload fields, governing policy, custodian — all
    /// length-prefixed (CN-1: structural, never a serde artifact).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut parts: Vec<Vec<u8>> = vec![
            self.request_digest.to_vec(),
            self.outcome.token().as_bytes().to_vec(),
        ];
        for f in self.outcome.payload() {
            parts.push(f.to_vec());
        }
        parts.push(self.governing_policy.as_bytes().to_vec());
        parts.push(self.governing_policy_version.to_le_bytes().to_vec());
        parts.push(self.custodian.as_bytes().to_vec());
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        canonical_fields(&refs)
    }

    /// The policy evaluation (XB-1's core mapping: reveal class →
    /// outcome). No governing policy for this verifier → Deny,
    /// stated.
    pub fn evaluate(req: &S13Request, policy: &PolicyObject, custodian: &str) -> S13Response {
        let allowed = policy.verifiers.iter().any(|v| v == &req.verifier)
            || policy.verifiers.iter().any(|v| v == "any-verifier");
        let outcome = if !allowed {
            S13Outcome::Deny {
                reason: format!(
                    "verifier `{}` is not in policy `{}`'s verifier set",
                    req.verifier, policy.policy_id
                ),
            }
        } else {
            match policy.reveal {
                RevealClass::Open => S13Outcome::Permit,
                RevealClass::PairingGated => S13Outcome::PermitPaired {
                    paired_with: req.verifier.clone(),
                },
                RevealClass::OriginSealed => S13Outcome::AttestationOffer {
                    attestation_service: format!("{}-attestation", policy.authority),
                },
                RevealClass::Escrowed => S13Outcome::Escalation {
                    escrow_quorum: format!("{}-escrow", policy.authority),
                },
            }
        };
        S13Response {
            request_digest: req.digest(),
            outcome,
            governing_policy: policy.policy_id.clone(),
            governing_policy_version: policy.version,
            custodian: custodian.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> S13Request {
        S13Request {
            verifier: "de-zoll".into(),
            subject: "urn:unidpp:passport:pack-0001".into(),
            profile: "urn:unidpp:profile:eu-battery".into(),
            segment: "cn-dynamic".into(),
            at: "2030-06-01T08:00:00Z".into(),
        }
    }

    fn policy(reveal: RevealClass) -> PolicyObject {
        PolicyObject {
            policy_id: "cn-dynamic-bms".into(),
            version: 1,
            authority: "cn-samr".into(),
            readers: vec![],
            verifiers: vec!["any-verifier".into()],
            writers: vec![],
            reveal,
            suites: vec!["sm2".into()],
            valid_from: "2027-01-01T00:00:00Z".into(),
            valid_to: None,
            superseded_by: None,
        }
    }

    #[test]
    fn all_four_outcomes_machine_reproducible() {
        let req = request();
        for (reveal, token) in [
            (RevealClass::Open, "permit"),
            (RevealClass::PairingGated, "permit-paired"),
            (RevealClass::OriginSealed, "attestation-offer"),
            (RevealClass::Escrowed, "escalation"),
        ] {
            let resp = S13Response::evaluate(&req, &policy(reveal), "weilian-shenzhen");
            assert!(
                serde_json::to_string(&resp.outcome)
                    .unwrap()
                    .contains(token),
                "{reveal:?} -> {token}"
            );
            // XB-3's naming starts here: the governing policy is cited.
            assert_eq!(resp.governing_policy, "cn-dynamic-bms");
            assert_eq!(resp.governing_policy_version, 1);
            // The response is bound to the request.
            assert_eq!(resp.request_digest, req.digest());
        }
    }

    #[test]
    fn denial_is_stated_never_silent() {
        let mut p = policy(RevealClass::Open);
        p.verifiers = vec!["cn-customs".into()];
        let resp = S13Response::evaluate(&request(), &p, "weilian-shenzhen");
        match &resp.outcome {
            S13Outcome::Deny { reason } => {
                assert!(reason.contains("de-zoll"), "{reason}");
            }
            other => panic!("expected denial, got {other:?}"),
        }
    }

    #[test]
    fn responses_are_bound_and_tamper_evident() {
        let req = request();
        let mut resp = S13Response::evaluate(&req, &policy(RevealClass::OriginSealed), "cust");
        let before = resp.canonical_bytes();
        resp.governing_policy_version = 2; // a policy swap under the answer
        assert_ne!(before, resp.canonical_bytes());
        // A different request digests differently.
        let mut other = req.clone();
        other.segment = "eu-static".into();
        assert_ne!(other.digest(), req.digest());
    }
}
