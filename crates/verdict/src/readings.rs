//! The three verification readings.

use unidpp_event::{EventLog, SafetyFlag, Status};
use unidpp_model::{Hash, SigSlot, SignatureSuite, Timestamp, TrustMarker};
use unidpp_transform::TaintSet;

use crate::coverage::CoverageReport;

/// Status of one framed signature slot. Signature *verification* itself
/// is delegated to the SIGNATIF layer; this reports framing state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SigStatus {
    pub suite: SignatureSuite,
    pub key_id: String,
    /// A signature value is present.
    pub present: bool,
    /// True when the slot is a placeholder (framing only).
    pub framed_only: bool,
}

/// Cryptographic reading: signature/chain validity alone.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CryptographicReading {
    pub chain_verified: bool,
    pub head: Option<Hash>,
    /// None: no anchor supplied (offline); Some(false): anchor mismatch.
    pub anchor_ok: Option<bool>,
    pub signatures: Vec<SigStatus>,
    pub trust_marker: TrustMarker,
}

impl CryptographicReading {
    pub fn evaluate(
        log: &EventLog,
        sigs: &[SigSlot],
        attested_by_third_party: bool,
        anchor: Option<&Hash>,
    ) -> CryptographicReading {
        let chain_verified = log.verify().is_ok();
        let anchor_ok = anchor.map(|a| log.verify_against_anchor(a).is_ok());
        let mut signatures = Vec::new();
        let mut distinct_suites: Vec<SignatureSuite> = Vec::new();
        let mut present_count = 0usize;
        for slot in sigs {
            let present = slot.signature.is_some();
            if present {
                present_count += 1;
                if !distinct_suites.contains(&slot.suite) {
                    distinct_suites.push(slot.suite);
                }
            }
            signatures.push(SigStatus {
                suite: slot.suite,
                key_id: slot.key_id.clone(),
                present,
                framed_only: slot.is_framed_only(),
            });
        }
        let trust_marker = TrustMarker::of(
            present_count,
            distinct_suites.len(),
            attested_by_third_party,
            anchor_ok.unwrap_or(false),
        );
        CryptographicReading {
            chain_verified,
            head: log.head(),
            anchor_ok,
            signatures,
            trust_marker,
        }
    }
}

/// Evidentiary reading: what could a diligent verifier know at T, given
/// the then-current trust state. T is the verification time of record;
/// the as-of prefix of the log is the evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EvidentiaryReading {
    pub as_of: Option<Timestamp>,
    pub chain_verified: bool,
    pub events_total: usize,
    pub corrections: usize,
    pub recalls: usize,
    pub security_flags: usize,
    pub stamps: usize,
    pub coverage: CoverageReport,
}

impl EvidentiaryReading {
    pub fn evaluate(log: &EventLog, at: Timestamp, coverage: CoverageReport) -> EvidentiaryReading {
        let mut corrections = 0;
        let mut recalls = 0;
        let mut security_flags = 0;
        let mut stamps = 0;
        let mut events_total = 0;
        for sealed in log.as_of(at) {
            events_total += 1;
            use unidpp_event::EventPayload;
            match &sealed.event.payload {
                EventPayload::Correction { .. } => corrections += 1,
                EventPayload::RecallCampaign { .. } => recalls += 1,
                EventPayload::FlagSecurity { .. } => security_flags += 1,
                EventPayload::InspectionStamp { .. } => stamps += 1,
                _ => {}
            }
        }
        EvidentiaryReading {
            as_of: log.state_hash_at(at).map(|_| at),
            chain_verified: log.verify().is_ok(),
            events_total,
            corrections,
            recalls,
            security_flags,
            stamps,
            coverage,
        }
    }
}

/// Current-state reading: fraud voids ab initio; taints propagate through
/// the graph and are reported, not hidden.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CurrentStateReading {
    pub status: Status,
    pub safety: SafetyFlag,
    pub custodian: Option<String>,
    pub taints: TaintSet,
    pub active_links: usize,
    pub voids_ab_initio: bool,
}

impl CurrentStateReading {
    pub fn evaluate(log: &EventLog, taints: TaintSet, active_links: usize) -> CurrentStateReading {
        let voids = taints.voids_ab_initio();
        CurrentStateReading {
            status: log.current_status(),
            safety: log.safety_flag(),
            custodian: log.custodian(),
            taints,
            active_links,
            voids_ab_initio: voids,
        }
    }
}
