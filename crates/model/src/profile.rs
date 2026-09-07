//! Profile manifests (invariant I10): profiles are jurisdiction x sector x
//! characteristic, predicate-triggered, each binding data points,
//! transforms, crypto suites, trust, access, presentation, carriers.
//!
//! Capability gating (the silent-object lesson): profiles' freshness and
//! verification requirements must be satisfiable by the subject's
//! capability class — S0 silent / S1 passive-auth / S2 logged-contact /
//! S3 connected. Demanding live freshness from an S0 product is an
//! unsatisfiable profile and fails validation.

use std::fmt;
use std::str::FromStr;

use crate::facts::{TriggerPredicate, TwinFacts};
use crate::ids::ProfileId;
use crate::link::VisibilityClass;
use crate::time::{Interval, Timestamp};
use crate::trust::SignatureSuite;
use crate::ModelError;

crate::str_enum! {
    /// Capability classes of subjects (S0-S3; declaration order = order).
    pub enum CapabilityClass {
        /// S0 silent: testimony-only, no connectivity, no keys.
        Silent => "silent",
        /// S1 passive-auth: NFC chip / PUF / IEC 61406 identity link.
        PassiveAuth => "passive-auth",
        /// S2 logged-contact: dumps on physical read, no comms.
        LoggedContact => "logged-contact",
        /// S3 connected: full edge segments.
        Connected => "connected",
    }
}

impl CapabilityClass {
    /// "S0".."S3".
    pub fn code(self) -> &'static str {
        match self {
            CapabilityClass::Silent => "S0",
            CapabilityClass::PassiveAuth => "S1",
            CapabilityClass::LoggedContact => "S2",
            CapabilityClass::Connected => "S3",
        }
    }
}

crate::str_enum! {
    /// Serving resolution scope (dark/confidential profiles).
    pub enum Resolution {
        None => "none",
        National => "national",
        Restricted => "restricted",
        Public => "public",
    }
}

crate::str_enum! {
    /// Traversal rights over edges under this profile.
    pub enum Traversal {
        None => "none",
        AuthorityOnly => "authority-only",
        RoleScoped => "role-scoped",
        Public => "public",
    }
}

/// The three profile axes.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ProfileAxes {
    /// Jurisdiction (uppercased: "EU", "DE", "JP").
    pub jurisdiction: Option<String>,
    /// Sector overlay (lowercased: "electronics", "batteries").
    pub sector: Option<String>,
    /// Characteristic profile (predicate-attached: "conflict-minerals",
    /// "heritage", "cites").
    pub characteristic: Option<String>,
}

impl ProfileAxes {
    pub fn jurisdiction(j: &str) -> ProfileAxes {
        ProfileAxes {
            jurisdiction: Some(j.trim().to_ascii_uppercase()),
            sector: None,
            characteristic: None,
        }
    }

    pub fn with_sector(mut self, s: &str) -> ProfileAxes {
        self.sector = Some(crate::normalization::normalize_token(s));
        self
    }

    pub fn with_characteristic(mut self, c: &str) -> ProfileAxes {
        self.characteristic = Some(crate::normalization::normalize_token(c));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.jurisdiction.is_none() && self.sector.is_none() && self.characteristic.is_none()
    }

    pub fn describe(&self) -> String {
        format!(
            "{} x {} x {}",
            self.jurisdiction.as_deref().unwrap_or("-"),
            self.sector.as_deref().unwrap_or("-"),
            self.characteristic.as_deref().unwrap_or("-")
        )
    }
}

impl fmt::Display for ProfileAxes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// Freshness requirement of the profile (Primmel doctrine: unbounded
/// staleness becomes bounded `fresh_within`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FreshnessRequirement {
    /// No freshness semantics (archival facts).
    None,
    /// Type-declared static data: document-lookup semantics.
    Static,
    /// Bounded staleness for live views.
    FreshWithin { max_age_secs: i64 },
}

impl fmt::Display for FreshnessRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FreshnessRequirement::None => f.write_str("none"),
            FreshnessRequirement::Static => f.write_str("static"),
            FreshnessRequirement::FreshWithin { max_age_secs } => {
                write!(f, "fresh-within:{max_age_secs}s")
            }
        }
    }
}

impl FromStr for FreshnessRequirement {
    type Err = ModelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        match crate::normalization::squash(t).as_str() {
            "none" => Ok(FreshnessRequirement::None),
            "static" => Ok(FreshnessRequirement::Static),
            _ => {
                let body = t
                    .strip_prefix("fresh-within:")
                    .or_else(|| t.strip_prefix("FRESH-WITHIN:"))
                    .ok_or_else(|| {
                        ModelError::Parse(format!("bad freshness requirement `{t}`"))
                    })?;
                let secs = body
                    .trim_end_matches('s')
                    .parse::<i64>()
                    .map_err(|_| ModelError::Parse(format!("bad freshness window `{t}`")))?;
                if secs <= 0 {
                    return Err(ModelError::Validation(
                        "freshness window must be positive".into(),
                    ));
                }
                Ok(FreshnessRequirement::FreshWithin { max_age_secs: secs })
            }
        }
    }
}

/// A FERIN-registered data point reference: (register, item, version).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct DataPointRef {
    pub register: String,
    pub item: String,
    pub version: Option<String>,
}

impl DataPointRef {
    pub fn new(register: &str, item: &str, version: Option<&str>) -> Result<DataPointRef, ModelError> {
        if register.trim().is_empty() || item.trim().is_empty() {
            return Err(ModelError::Validation(
                "data point reference needs register and item".into(),
            ));
        }
        Ok(DataPointRef {
            register: register.trim().to_string(),
            item: item.trim().to_string(),
            version: version.map(|v| v.trim().to_string()),
        })
    }
}

impl fmt::Display for DataPointRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(v) => write!(f, "{}/{}@{}", self.register, self.item, v),
            None => write!(f, "{}/{}", self.register, self.item),
        }
    }
}

/// A registered, versioned profile: the calibrated lens placed on the
/// digital twin. The manifest binds the axes, the trigger predicate, the
/// capability floor, data points, crypto suites, and the
/// sovereignty/traversal posture.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProfileManifest {
    pub id: ProfileId,
    pub axes: ProfileAxes,
    pub trigger: TriggerPredicate,
    pub min_capability: CapabilityClass,
    pub freshness: FreshnessRequirement,
    pub effective: Interval,
    pub data_points: Vec<DataPointRef>,
    pub crypto_suites: Vec<SignatureSuite>,
    pub confidential: bool,
    pub resolution: Resolution,
    pub edge_visibility: VisibilityClass,
    pub traversal: Traversal,
}

impl ProfileManifest {
    /// Does this profile apply to the given twin state at time `now`?
    /// (Effective interval AND trigger predicate.)
    pub fn applies_to(&self, facts: &TwinFacts, now: Timestamp) -> bool {
        self.effective.contains(now) && self.trigger.eval(facts, now)
    }

    /// Can a subject of capability `subject` satisfy this profile?
    pub fn is_satisfiable_by(&self, subject: CapabilityClass) -> bool {
        subject >= self.min_capability
    }

    /// Structural validation, including the unsatisfiable-profile rule:
    /// demanding bounded freshness from an S0 (silent) subject is a design
    /// error, not a data problem.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.axes.is_empty() {
            return Err(ModelError::Validation(format!(
                "profile {} must sit on at least one axis (jurisdiction x sector x characteristic)",
                self.id
            )));
        }
        if self.data_points.is_empty() {
            return Err(ModelError::Validation(format!(
                "profile {} binds no data points",
                self.id
            )));
        }
        if self.crypto_suites.is_empty() {
            return Err(ModelError::Validation(format!(
                "profile {} binds no crypto suites",
                self.id
            )));
        }
        if matches!(self.freshness, FreshnessRequirement::FreshWithin { .. })
            && self.min_capability == CapabilityClass::Silent
        {
            return Err(ModelError::Validation(format!(
                "unsatisfiable profile {}: bounded freshness demanded of an S0 (silent) subject",
                self.id
            )));
        }
        if !self.effective.is_open() && self.effective.to.is_none() {
            return Err(ModelError::Validation("effective interval malformed".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::FactValue;
    use crate::Hash;

    fn battery_profile() -> ProfileManifest {
        ProfileManifest {
            id: ProfileId::new("urn:unidpp:profile:eu-battery-v3").unwrap(),
            axes: ProfileAxes::jurisdiction("EU").with_sector("Batteries"),
            trigger: TriggerPredicate::FactGe {
                path: "battery.capacity-kwh".into(),
                value: FactValue::Num("2".parse().unwrap()),
            },
            min_capability: CapabilityClass::Silent,
            freshness: FreshnessRequirement::Static,
            effective: Interval::starting(Timestamp::from_secs(1_700_000_000)),
            data_points: vec![DataPointRef::new("ferin:eu", "carbon-footprint", Some("3.1")).unwrap()],
            crypto_suites: vec![SignatureSuite::EcdsaP256, SignatureSuite::Sm2, SignatureSuite::MlDsa65],
            confidential: false,
            resolution: Resolution::Public,
            edge_visibility: VisibilityClass::Restricted,
            traversal: Traversal::RoleScoped,
        }
    }

    #[test]
    fn applies_by_interval_and_predicate() {
        let now = Timestamp::from_secs(1_800_000_000);
        let p = battery_profile();
        let mut facts = TwinFacts::new();
        assert!(!p.applies_to(&facts, now));
        facts = facts.set("battery.capacity-kwh", FactValue::Num("2.0".parse().unwrap()));
        assert!(p.applies_to(&facts, now));
        let early = Timestamp::from_secs(1_600_000_000);
        assert!(!p.applies_to(&facts, early));
    }

    #[test]
    fn unsatisfiable_profile_rejected() {
        let mut p = battery_profile();
        p.freshness = FreshnessRequirement::FreshWithin { max_age_secs: 3_600 };
        let err = p.validate().unwrap_err();
        assert!(err.to_string().contains("unsatisfiable"));
        p.min_capability = CapabilityClass::LoggedContact;
        p.validate().unwrap();
    }

    #[test]
    fn validation_requires_axes_points_suites() {
        let mut p = battery_profile();
        p.axes = ProfileAxes::default();
        assert!(p.validate().is_err());
        p = battery_profile();
        p.data_points.clear();
        assert!(p.validate().is_err());
        p = battery_profile();
        p.crypto_suites.clear();
        assert!(p.validate().is_err());
    }

    #[test]
    fn capability_ordering() {
        assert!(CapabilityClass::Connected > CapabilityClass::Silent);
        assert_eq!(CapabilityClass::PassiveAuth.code(), "S1");
        assert_eq!(
            "LOGGED_CONTACT".parse::<CapabilityClass>().unwrap(),
            CapabilityClass::LoggedContact
        );
    }

    #[test]
    fn freshness_parsing() {
        assert_eq!(
            "fresh-within:3600s".parse::<FreshnessRequirement>().unwrap(),
            FreshnessRequirement::FreshWithin { max_age_secs: 3600 }
        );
        assert_eq!("STATIC".parse::<FreshnessRequirement>().unwrap(), FreshnessRequirement::Static);
        assert!("fresh-within:0s".parse::<FreshnessRequirement>().is_err());
        assert_eq!(
            FreshnessRequirement::FreshWithin { max_age_secs: 60 }.to_string(),
            "fresh-within:60s"
        );
    }

    #[test]
    fn axes_description() {
        let p = battery_profile();
        assert_eq!(p.axes.describe(), "EU x batteries x -");
        let _h: Hash = Hash::ZERO;
    }
}
