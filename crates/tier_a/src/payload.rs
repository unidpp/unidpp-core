//! The Tier-A payload: the minimum viable passport.

use unidpp_event::{EventLog, SafetyFlag, Status};
use unidpp_model::{Hash, Interval, PassportId, ProductIdentifier, SigSlot, Timestamp};

/// Tier-A payload fields. The standard fixes exactly this subset; every
/// field is mandatory (there is no optional-field shrinking — that would
/// silently degrade the offline minimum).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TierAPayload {
    /// Scheme-agnostic product identifier (canonical display form).
    pub product_id: ProductIdentifier,
    /// Resolver URI for Tier-B serving.
    pub resolver_uri: String,
    pub passport_id: PassportId,
    /// Economic-operator identifier.
    pub eo_id: String,
    pub status: Status,
    /// Critical safety / recall flag.
    pub safety: SafetyFlag,
    /// Validity interval of the passport.
    pub validity: Interval,
    /// As-of stamp: when this projection was computed.
    pub as_of: Timestamp,
    /// Log head commitment (offline chain anchoring).
    pub log_head: Option<Hash>,
    /// Multi-suite signature framing (ECDSA / SM2 / ML-DSA slots).
    pub signatures: Vec<SigSlot>,
}

impl TierAPayload {
    /// Build the Tier-A view of a log: status and safety flag are
    /// replayed from the log; `as_of` is the last event time.
    pub fn from_log(
        log: &EventLog,
        product_id: ProductIdentifier,
        resolver_uri: &str,
        eo_id: &str,
        validity: Interval,
        signatures: Vec<SigSlot>,
    ) -> TierAPayload {
        TierAPayload {
            product_id,
            resolver_uri: resolver_uri.to_string(),
            passport_id: log.subject().clone(),
            eo_id: eo_id.to_string(),
            status: log.current_status(),
            safety: log.safety_flag(),
            validity,
            as_of: log.last_event_at().unwrap_or_else(Timestamp::now),
            log_head: log.head(),
            signatures,
        }
    }
}
