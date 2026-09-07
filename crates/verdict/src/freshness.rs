//! Freshness verdicts (Primmel doctrine: unbounded staleness becomes
//! bounded `fresh_within`; degradation is explicit, never silent).

use unidpp_model::{FreshnessRequirement, Timestamp};

/// Freshness of a projection relative to its as-of stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FreshnessVerdict {
    /// As-of stamp is present and within the profile's window.
    Fresh { as_of: Timestamp },
    /// Present but older than the window (degrade explicitly).
    Stale { as_of: Timestamp },
    /// No as-of information at all (offline with no anchor).
    Indeterminate,
}

impl FreshnessVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            FreshnessVerdict::Fresh { .. } => "fresh",
            FreshnessVerdict::Stale { .. } => "stale",
            FreshnessVerdict::Indeterminate => "indeterminate",
        }
    }

    pub fn is_fresh(&self) -> bool {
        matches!(self, FreshnessVerdict::Fresh { .. })
    }
}

/// Evaluate freshness: `as_of` is the projection's as-of stamp (e.g. the
/// Tier-A as-of time or the last log event), `now` the verification time.
pub fn evaluate_freshness(
    now: Timestamp,
    as_of: Option<Timestamp>,
    requirement: FreshnessRequirement,
) -> FreshnessVerdict {
    match requirement {
        FreshnessRequirement::None | FreshnessRequirement::Static => match as_of {
            Some(t) => FreshnessVerdict::Fresh { as_of: t },
            None => FreshnessVerdict::Indeterminate,
        },
        FreshnessRequirement::FreshWithin { max_age_secs } => match as_of {
            None => FreshnessVerdict::Indeterminate,
            Some(t) => {
                let age = now.signed_secs_since(t);
                if age <= max_age_secs {
                    FreshnessVerdict::Fresh { as_of: t }
                } else {
                    FreshnessVerdict::Stale { as_of: t }
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triad() {
        let now = Timestamp::from_secs(1_000_000);
        let as_of = Timestamp::from_secs(999_000);
        let req = FreshnessRequirement::FreshWithin { max_age_secs: 3_600 };
        assert_eq!(
            evaluate_freshness(now, Some(as_of), req).label(),
            "fresh"
        );
        let old = Timestamp::from_secs(900_000);
        assert!(matches!(
            evaluate_freshness(now, Some(old), req),
            FreshnessVerdict::Stale { .. }
        ));
        assert_eq!(
            evaluate_freshness(now, None, req).label(),
            "indeterminate"
        );
        // Static requirement never goes stale.
        assert!(evaluate_freshness(now, Some(old), FreshnessRequirement::Static)
            .is_fresh());
    }
}
