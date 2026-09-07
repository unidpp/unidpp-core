//! The graded verdict and its builder.

use std::collections::BTreeSet;

use unidpp_event::EventLog;
use unidpp_model::{FreshnessRequirement, Hash, ProfileManifest, SigSlot, Timestamp};
use unidpp_transform::TaintSet;

use crate::coverage::CoverageReport;
use crate::freshness::{evaluate_freshness, FreshnessVerdict};
use crate::readings::{CryptographicReading, CurrentStateReading, EvidentiaryReading};

// Which reading a verdict answers (verdicts state this explicitly).
unidpp_model::str_enum! {
    pub enum Reading {
        Cryptographic => "cryptographic",
        Evidentiary => "evidentiary",
        CurrentState => "current-state",
    }
}

/// Why a verdict degraded (explicit degradation, never silent).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Degradation {
    StaleData { as_of: Timestamp },
    NoFreshnessEvidence,
    OfflineNoAnchor,
    SignaturesFramedOnly,
    CoverageIncomplete { missing: Vec<String> },
}

/// Why a verdict failed outright.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Failure {
    BrokenChain,
    AnchorMismatch,
}

/// Overall outcome on the degradation ladder.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    Pass,
    Degraded(Degradation),
    Fail(Failure),
}

/// A graded verification result.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Verdict {
    pub reading_answered: Reading,
    pub freshness: FreshnessVerdict,
    pub cryptographic: CryptographicReading,
    pub evidentiary: EvidentiaryReading,
    pub current_state: CurrentStateReading,
    pub trust_marker: unidpp_model::TrustMarker,
    pub outcome: Outcome,
}

/// Builder for verdicts.
pub struct VerdictBuilder<'a> {
    log: &'a EventLog,
    now: Timestamp,
    profile: Option<&'a ProfileManifest>,
    provided: BTreeSet<String>,
    sigs: Vec<SigSlot>,
    attested_by_third_party: bool,
    anchor: Option<Hash>,
    taints: TaintSet,
    active_links: usize,
    reading: Reading,
}

impl<'a> VerdictBuilder<'a> {
    pub fn new(log: &'a EventLog, now: Timestamp) -> VerdictBuilder<'a> {
        VerdictBuilder {
            log,
            now,
            profile: None,
            provided: BTreeSet::new(),
            sigs: Vec::new(),
            attested_by_third_party: false,
            anchor: None,
            taints: TaintSet::new(),
            active_links: 0,
            reading: Reading::Evidentiary,
        }
    }

    pub fn with_profile(mut self, profile: &'a ProfileManifest) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn with_provided(mut self, provided: BTreeSet<String>) -> Self {
        self.provided = provided;
        self
    }

    pub fn with_signatures(mut self, sigs: Vec<SigSlot>) -> Self {
        self.sigs = sigs;
        self
    }

    pub fn attested_by_third_party(mut self, yes: bool) -> Self {
        self.attested_by_third_party = yes;
        self
    }

    pub fn with_anchor(mut self, anchor: Hash) -> Self {
        self.anchor = Some(anchor);
        self
    }

    pub fn with_taints(mut self, taints: TaintSet) -> Self {
        self.taints = taints;
        self
    }

    pub fn with_active_links(mut self, n: usize) -> Self {
        self.active_links = n;
        self
    }

    pub fn answering(mut self, reading: Reading) -> Self {
        self.reading = reading;
        self
    }

    pub fn build(self) -> Verdict {
        let crypto = CryptographicReading::evaluate(
            self.log,
            &self.sigs,
            self.attested_by_third_party,
            self.anchor.as_ref(),
        );
        let coverage = match self.profile {
            Some(p) => CoverageReport::from_profile(p, &self.provided),
            None => CoverageReport::empty(),
        };
        let evidentiary = EvidentiaryReading::evaluate(self.log, self.now, coverage);
        let current = CurrentStateReading::evaluate(self.log, self.taints, self.active_links);

        let requirement = self
            .profile
            .map(|p| p.freshness)
            .unwrap_or(FreshnessRequirement::Static);
        let as_of = self.log.last_event_at();
        let freshness = evaluate_freshness(self.now, as_of, requirement);

        // Degradation ladder: fail hard on integrity, degrade explicitly
        // on staleness/offline/framing/coverage, never silently pass.
        let outcome = if !crypto.chain_verified {
            Outcome::Fail(Failure::BrokenChain)
        } else if matches!(crypto.anchor_ok, Some(false)) {
            Outcome::Fail(Failure::AnchorMismatch)
        } else {
            let mut degraded: Option<Degradation> = None;
            match freshness {
                FreshnessVerdict::Stale { as_of } => {
                    degraded = Some(Degradation::StaleData { as_of })
                }
                FreshnessVerdict::Indeterminate => {
                    degraded = Some(Degradation::NoFreshnessEvidence)
                }
                FreshnessVerdict::Fresh { .. } => {}
            }
            if degraded.is_none() && crypto.anchor_ok.is_none() {
                degraded = Some(Degradation::OfflineNoAnchor);
            }
            if degraded.is_none()
                && !self.sigs.is_empty()
                && self.sigs.iter().all(|s| s.is_framed_only())
            {
                degraded = Some(Degradation::SignaturesFramedOnly);
            }
            if degraded.is_none() {
                let missing = evidentiary.coverage.missing();
                if !missing.is_empty() {
                    degraded = Some(Degradation::CoverageIncomplete {
                        missing: missing.into_iter().map(|s| s.to_string()).collect(),
                    });
                }
            }
            match degraded {
                Some(d) => Outcome::Degraded(d),
                None => Outcome::Pass,
            }
        };

        Verdict {
            reading_answered: self.reading,
            freshness,
            cryptographic: crypto.clone(),
            evidentiary,
            current_state: current,
            trust_marker: crypto.trust_marker,
            outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_event::{EventType, EventPayload, TypedEvent};
    use unidpp_model::{
        CapabilityClass, DataPointRef, Interval, PassportId, ProfileAxes, ProfileId, ProfileManifest,
        Resolution, SignatureSuite, TriggerPredicate, Traversal, TrustMarker, VisibilityClass,
    };

    fn pid() -> PassportId {
        PassportId::new("urn:unidpp:passport:subject-1").unwrap()
    }

    fn log_with_events() -> EventLog {
        let mut log = EventLog::new(pid());
        for i in 0..3u64 {
            let e = TypedEvent::new(
                i,
                Timestamp::from_secs(1_000_000 + i as i64 * 60),
                "custodian",
                "a",
                EventType::CustodyTransfer,
                EventPayload::CustodyTransfer {
                    from: "x".into(),
                    to: format!("holder-{i}"),
                    counterparty_signed: true,
                },
                TrustMarker::SelfDeclared,
            )
            .unwrap();
            log.append(e, None, None).unwrap();
        }
        log
    }

    fn profile() -> ProfileManifest {
        ProfileManifest {
            id: ProfileId::new("urn:unidpp:profile:test").unwrap(),
            axes: ProfileAxes::jurisdiction("EU"),
            trigger: TriggerPredicate::Any,
            min_capability: CapabilityClass::Silent,
            freshness: FreshnessRequirement::FreshWithin { max_age_secs: 3_600 },
            effective: Interval::starting(Timestamp::from_secs(0)),
            data_points: vec![DataPointRef::new("ferin:eu", "a", None).unwrap()],
            crypto_suites: vec![SignatureSuite::EcdsaP256],
            confidential: false,
            resolution: Resolution::Public,
            edge_visibility: VisibilityClass::Public,
            traversal: Traversal::Public,
        }
    }

    #[test]
    fn fresh_pass() {
        let log = log_with_events();
        let now = Timestamp::from_secs(1_000_150);
        let v = VerdictBuilder::new(&log, now)
            .with_profile(&profile())
            .with_provided(BTreeSet::from(["ferin:eu/a".to_string()]))
            .with_anchor(log.head().unwrap())
            .build();
        assert_eq!(v.outcome, Outcome::Pass);
        assert!(v.freshness.is_fresh());
        assert_eq!(v.trust_marker, TrustMarker::LogAnchored);
        assert_eq!(v.reading_answered, Reading::Evidentiary);
    }

    #[test]
    fn stale_degrades_explicitly() {
        let log = log_with_events();
        let now = Timestamp::from_secs(1_000_000 + 10 * 3_600);
        let v = VerdictBuilder::new(&log, now)
            .with_profile(&profile())
            .with_provided(BTreeSet::from(["ferin:eu/a".to_string()]))
            .with_anchor(log.head().unwrap())
            .build();
        assert!(matches!(
            v.outcome,
            Outcome::Degraded(Degradation::StaleData { .. })
        ));
        assert_eq!(v.freshness.label(), "stale");
    }

    #[test]
    fn offline_degrades() {
        let log = log_with_events();
        let now = Timestamp::from_secs(1_000_150);
        let v = VerdictBuilder::new(&log, now).build();
        assert!(matches!(
            v.outcome,
            Outcome::Degraded(Degradation::OfflineNoAnchor)
        ));
    }

    #[test]
    fn broken_chain_fails() {
        let log = log_with_events();
        let mut json = serde_json::to_string(&log).unwrap();
        json = json.replacen("holder-1", "holder-Z", 1);
        let tampered: EventLog = serde_json::from_str(&json).unwrap();
        let v = VerdictBuilder::new(&tampered, Timestamp::from_secs(1_000_150)).build();
        assert_eq!(v.outcome, Outcome::Fail(Failure::BrokenChain));
    }

    #[test]
    fn framed_only_degrades_and_unmarked_anchor_mismatch_fails() {
        let log = log_with_events();
        let now = Timestamp::from_secs(1_000_150);
        let v = VerdictBuilder::new(&log, now)
            .with_signatures(vec![unidpp_model::SigSlot::placeholder(
                SignatureSuite::EcdsaP256,
                "k1",
            )])
            .with_anchor(unidpp_model::Hash::ZERO)
            .build();
        assert!(matches!(v.outcome, Outcome::Fail(Failure::AnchorMismatch)));

        let v2 = VerdictBuilder::new(&log, now)
            .with_signatures(vec![unidpp_model::SigSlot::placeholder(
                SignatureSuite::EcdsaP256,
                "k1",
            )])
            .with_anchor(log.head().unwrap())
            .build();
        assert!(matches!(
            v2.outcome,
            Outcome::Degraded(Degradation::SignaturesFramedOnly)
        ));
        assert_eq!(v2.cryptographic.signatures.len(), 1);
    }

    #[test]
    fn coverage_incomplete_degrades() {
        let log = log_with_events();
        let now = Timestamp::from_secs(1_000_150);
        let v = VerdictBuilder::new(&log, now)
            .with_profile(&profile())
            .with_provided(BTreeSet::new())
            .with_anchor(log.head().unwrap())
            .build();
        assert!(matches!(
            v.outcome,
            Outcome::Degraded(Degradation::CoverageIncomplete { .. })
        ));
    }
}
