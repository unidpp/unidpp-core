//! Coverage reports: verification is coverage-report-based, not boolean.

use std::collections::BTreeSet;

use unidpp_model::ProfileManifest;

/// Which required data points are present in a render.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoverageReport {
    pub required: Vec<String>,
    pub present: Vec<String>,
}

impl CoverageReport {
    /// Compare the profile's bound data points against the provided set.
    pub fn from_profile(profile: &ProfileManifest, provided: &BTreeSet<String>) -> CoverageReport {
        let required: Vec<String> = profile
            .data_points
            .iter()
            .map(|dp| dp.to_string())
            .collect();
        let present = required
            .iter()
            .filter(|r| provided.contains(*r))
            .cloned()
            .collect();
        CoverageReport { required, present }
    }

    pub fn empty() -> CoverageReport {
        CoverageReport::default()
    }

    pub fn missing(&self) -> Vec<&str> {
        self.required
            .iter()
            .filter(|r| !self.present.contains(r))
            .map(|s| s.as_str())
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.required.len() == self.present.len()
    }

    pub fn ratio(&self) -> f64 {
        if self.required.is_empty() {
            1.0
        } else {
            self.present.len() as f64 / self.required.len() as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_model::{
        CapabilityClass, DataPointRef, FreshnessRequirement, Interval, IssuerClass, ProfileAxes,
        ProfileId, ProfileManifest, Resolution, SignatureSuite, Timestamp, Traversal,
        TriggerPredicate, VisibilityClass,
    };

    fn profile() -> ProfileManifest {
        ProfileManifest {
            id: ProfileId::new("urn:unidpp:profile:test").unwrap(),
            issuer_class: IssuerClass::Law,
            axes: ProfileAxes::jurisdiction("EU"),
            trigger: TriggerPredicate::Any,
            min_capability: CapabilityClass::Silent,
            freshness: FreshnessRequirement::Static,
            effective: Interval::starting(Timestamp::from_secs(0)),
            data_points: vec![
                DataPointRef::new("ferin:eu", "a", Some("1")).unwrap(),
                DataPointRef::new("ferin:eu", "b", None).unwrap(),
            ],
            crypto_suites: vec![SignatureSuite::EcdsaP256],
            confidential: false,
            resolution: Resolution::Public,
            edge_visibility: VisibilityClass::Public,
            traversal: Traversal::Public,
        }
    }

    #[test]
    fn coverage_counts_and_missing() {
        let p = profile();
        let provided: BTreeSet<String> = ["ferin:eu/a@1", "ferin:eu/c"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let report = CoverageReport::from_profile(&p, &provided);
        assert_eq!(report.missing(), vec!["ferin:eu/b"]);
        assert!(!report.is_complete());
        assert!((report.ratio() - 0.5).abs() < 1e-9);
        let full: BTreeSet<String> = ["ferin:eu/a@1", "ferin:eu/b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(CoverageReport::from_profile(&p, &full).is_complete());
    }
}
