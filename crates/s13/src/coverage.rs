//! The coverage report (XB-8): a first-class object — per data
//! class, the evidence kind backing it, the governing policy named,
//! the reading, the freshness — rendered by the same pipeline from
//! direct and substituted runs alike.
//!
//! The report is the verifier's OUTPUT: one object carrying every
//! class's tier (verified-direct for opened evidence,
//! attested-by-authority for accepted substitution,
//! explicitly-unavailable for sealed classes without admissible
//! evidence — stated, never silent). Its canonical bytes are
//! domain-framed digest material (CN-1): a report can be signed,
//! journaled, exchanged.

use unidpp_model::{sha256, CanonicalWriter};

/// The evidence kind backing one entry (XB-3's tiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// The verifier saw the evidence itself.
    VerifiedDirect,
    /// A named authority attests; accepted under the verifier's own
    /// anchors and acceptance policy.
    AttestedByAuthority,
    /// The class is sealed and no admissible attestation exists.
    ExplicitlyUnavailable,
}

impl EvidenceKind {
    pub fn token(self) -> &'static str {
        match self {
            EvidenceKind::VerifiedDirect => "verified-direct",
            EvidenceKind::AttestedByAuthority => "attested-by-authority",
            EvidenceKind::ExplicitlyUnavailable => "explicitly-unavailable",
        }
    }
}

/// One data class's coverage.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CoverageEntry {
    /// The data class (the segment or element-set id).
    pub class: String,
    /// The element set reference (the vocabulary this class's
    /// elements draw from).
    pub element_set: String,
    /// The evidence kind.
    pub evidence: EvidenceKind,
    /// The governing policy, named (XB-3's naming requirement).
    pub governing_policy: String,
    /// The governing policy's version.
    pub governing_policy_version: u64,
    /// The reading: what the evidence says (a verdict token, an
    /// observed value, or the reason unavailability is stated).
    pub reading: String,
    /// The as-of moment the evidence was evaluated at (RFC 3339).
    pub as_of: String,
}

/// The report: every class, one object, both tiers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CoverageReport {
    /// The subject (passport id).
    pub subject: String,
    /// The profile context the report was produced under.
    pub profile: String,
    /// The verification moment (RFC 3339).
    pub verified_at: String,
    /// One entry per data class, in class order.
    pub entries: Vec<CoverageEntry>,
}

impl CoverageReport {
    /// Begin a report (the one pipeline both run kinds feed).
    pub fn new(subject: &str, profile: &str, verified_at: &str) -> CoverageReport {
        CoverageReport {
            subject: subject.into(),
            profile: profile.into(),
            verified_at: verified_at.into(),
            entries: Vec::new(),
        }
    }

    /// Append an entry (callers keep entries in class order).
    pub fn entry(&mut self, entry: CoverageEntry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// The canonical, signable form (CN-1): header fields then
    /// entries in order, every field length-prefixed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(self.subject.as_bytes());
        w.write_bytes(self.profile.as_bytes());
        w.write_bytes(self.verified_at.as_bytes());
        let n = (self.entries.len() as u64).to_le_bytes();
        w.write_bytes(&n);
        for e in &self.entries {
            w.write_bytes(e.class.as_bytes());
            w.write_bytes(e.element_set.as_bytes());
            w.write_bytes(e.evidence.token().as_bytes());
            w.write_bytes(e.governing_policy.as_bytes());
            w.write_bytes(&e.governing_policy_version.to_le_bytes());
            w.write_bytes(e.reading.as_bytes());
            w.write_bytes(e.as_of.as_bytes());
        }
        w.into_bytes()
    }

    /// The report's digest (sha256 over the canonical bytes).
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.canonical_bytes()]).0
    }

    /// The one-line rendering — built FROM the object, the same
    /// rendering for direct and substituted runs alike.
    pub fn summary(&self) -> String {
        let parts: Vec<String> = self.entries.iter().map(entry_line).collect();
        format!(
            "{} under {} at {}: {}",
            self.subject,
            self.profile,
            self.verified_at,
            parts.join(" | ")
        )
    }
}

fn entry_line(e: &CoverageEntry) -> String {
    format!(
        "{}: {} (governing policy {} v{})",
        e.class,
        e.evidence.token(),
        e.governing_policy,
        e.governing_policy_version
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // XB-8's verify: direct and substituted runs produce
    // schema-valid reports from the same pipeline — the direct run
    // grades both classes verified-direct (the verifier saw them),
    // the substituted run keeps the static class direct and grades
    // the sealed class attested-by-authority.
    #[test]
    fn direct_and_substituted_runs_share_the_pipeline() {
        let direct = battery_report(EvidenceKind::VerifiedDirect);
        let substituted = battery_report(EvidenceKind::AttestedByAuthority);

        for report in [&direct, &substituted] {
            // Schema-valid: round-trips through its serialization
            // with every required field present and the governing
            // policies named.
            let json = serde_json::to_value(report).unwrap();
            let back: CoverageReport = serde_json::from_value(json).unwrap();
            assert_eq!(&back, report);
            for e in &report.entries {
                assert!(!e.governing_policy.is_empty());
                assert!(e.governing_policy_version >= 1);
                assert!(!e.element_set.is_empty());
            }
            // Canonical bytes stable across the round trip.
            assert_eq!(back.canonical_bytes(), report.canonical_bytes());
        }

        assert_eq!(direct.entries[0].evidence, EvidenceKind::VerifiedDirect);
        assert_eq!(
            substituted.entries[0].evidence,
            EvidenceKind::VerifiedDirect
        );
        assert_eq!(
            substituted.entries[1].evidence,
            EvidenceKind::AttestedByAuthority
        );
        // One rendering, both runs.
        assert!(direct.summary().contains("eu-static: verified-direct"));
        assert!(substituted
            .summary()
            .contains("cn-dynamic: attested-by-authority (governing policy cn-dynamic-bms v1)"));
    }

    // Unavailability is stated as an entry, never silent.
    #[test]
    fn unavailability_is_stated() {
        let mut report = CoverageReport::new(
            "urn:unidpp:passport:pack-0001",
            "urn:unidpp:profile:eu-battery",
            "2030-06-01T08:30:00Z",
        );
        report.entry(CoverageEntry {
            class: "cn-dynamic".into(),
            element_set: "urn:unidpp:elements:bms-dynamic".into(),
            evidence: EvidenceKind::ExplicitlyUnavailable,
            governing_policy: "cn-dynamic-bms".into(),
            governing_policy_version: 1,
            reading: "sealed: no admissible attestation".into(),
            as_of: "2030-06-01T08:30:00Z".into(),
        });
        assert!(report.summary().contains("explicitly-unavailable"));
        assert!(!report.canonical_bytes().is_empty());
    }

    fn battery_report(sealed_evidence: EvidenceKind) -> CoverageReport {
        let mut report = CoverageReport::new(
            "urn:unidpp:passport:pack-0001",
            "urn:unidpp:profile:eu-battery",
            "2030-06-01T08:30:00Z",
        );
        report.entry(CoverageEntry {
            class: "eu-static".into(),
            element_set: "urn:unidpp:elements:battery-static".into(),
            evidence: EvidenceKind::VerifiedDirect,
            governing_policy: "eu-static-open".into(),
            governing_policy_version: 1,
            reading: "conformant".into(),
            as_of: "2030-06-01T08:30:00Z".into(),
        });
        report.entry(CoverageEntry {
            class: "cn-dynamic".into(),
            element_set: "urn:unidpp:elements:bms-dynamic".into(),
            evidence: sealed_evidence,
            governing_policy: "cn-dynamic-bms".into(),
            governing_policy_version: 1,
            reading: "pass".into(),
            as_of: "2030-06-01T08:00:00Z".into(),
        });
        report
    }
}
