//! The passport relationship algebra (invariant I5).
//!
//! Passports are nodes; edges are typed, and the types have different
//! legal and lifecycle semantics:
//! - R1 Association (loose, navigational, free add/remove)
//! - R2 Derivation (ancestral, directional; governed by the transformation
//!   algebra in `unidpp-transform`)
//! - R3 Installation (structural, parent<->child, temporal — its own event
//!   class, not generic containment)
//! - R4 Type lineage (the identity lattice)
//! - R5 Profile-of (lens<->core; not a passport-to-passport edge)
//! - R6 Custody (social/control edges, orthogonal to structure)
//! - R7 Membership (group nodes: shipments, kits, recall sets)
//!
//! EXPRESS core shape (the UniDPP design framework):
//! `PassportLink {type, direction, interval, binding: {method,
//!  recoverability, visibility, slotId, pairing, alteration[]}}`.
//!
//! Identity-continuity rule: disassembly restores a marketable object with
//! identity continuity -> R3; identity dissolves -> R2.

use std::fmt;
use std::str::FromStr;

use crate::ids::PassportId;
use crate::time::{Interval, Timestamp};
use crate::{normalization, EnumParseError, ModelError};

crate::str_enum! {
    /// Typed relationship classes R1-R7 (R5 profile-of is lens<->core and
    /// not represented as a passport edge).
    pub enum LinkType {
        Association => "association",
        Derivation => "derivation",
        Installation => "installation",
        TypeLineage => "type-lineage",
        Custody => "custody",
        Membership => "membership",
    }
}

crate::str_enum! {
    /// Which side of the edge this record speaks from.
    pub enum Direction {
        Outgoing => "outgoing",
        Incoming => "incoming",
    }
}

crate::str_enum! {
    /// Recoverability spectrum of an installation; determines identity
    /// continuity.
    pub enum Recoverability {
        Restorable => "restorable",
        Harvestable => "harvestable",
        Destructive => "destructive",
        Absorbing => "absorbing",
    }
}

crate::str_enum! {
    /// Pairing/re-identification mode.
    pub enum Pairing {
        None => "none",
        Firmware => "firmware",
        Key => "key",
        Module => "module",
    }
}

crate::str_enum! {
    /// Edge visibility class (enumeration resistance, I12).
    pub enum VisibilityClass {
        Public => "public",
        Restricted => "restricted",
        Blind => "blind",
        Escrowed => "escrowed",
    }
}

/// What installation did to the child (permanent alterations).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Alteration {
    Known(KnownAlteration),
    Other(String),
}

crate::str_enum! {
    /// Known permanent alterations.
    pub enum KnownAlteration {
        Soldered => "soldered",
        Glued => "glued",
        Welded => "welded",
        Potted => "potted",
        TorqueToYield => "torque-to-yield",
        ConformalCoating => "conformal-coating",
    }
}

impl From<KnownAlteration> for Alteration {
    fn from(k: KnownAlteration) -> Alteration {
        Alteration::Known(k)
    }
}

impl fmt::Display for Alteration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Alteration::Known(k) => f.write_str(k.as_str()),
            Alteration::Other(s) => write!(f, "other:{}", normalization::normalize_token(s)),
        }
    }
}

impl FromStr for Alteration {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s
            .strip_prefix("other:")
            .or_else(|| s.strip_prefix("OTHER:"))
        {
            if !rest.trim().is_empty() {
                return Ok(Alteration::Other(rest.trim().to_string()));
            }
        }
        KnownAlteration::parse_token(s).map(Alteration::Known)
    }
}

/// How the child is attached to the parent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum InstallMethod {
    Known(KnownMethod),
    Other(String),
}

crate::str_enum! {
    /// Known installation methods.
    pub enum KnownMethod {
        Fastened => "fastened",
        Soldered => "soldered",
        Glued => "glued",
        Welded => "welded",
        Potted => "potted",
        TorqueToYield => "torque-to-yield",
        Coated => "coated",
        Keyed => "keyed",
    }
}

impl From<KnownMethod> for InstallMethod {
    fn from(k: KnownMethod) -> InstallMethod {
        InstallMethod::Known(k)
    }
}

impl fmt::Display for InstallMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstallMethod::Known(k) => f.write_str(k.as_str()),
            InstallMethod::Other(s) => write!(f, "other:{}", normalization::normalize_token(s)),
        }
    }
}

impl FromStr for InstallMethod {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s
            .strip_prefix("other:")
            .or_else(|| s.strip_prefix("OTHER:"))
        {
            if !rest.trim().is_empty() {
                return Ok(InstallMethod::Other(rest.trim().to_string()));
            }
        }
        KnownMethod::parse_token(s).map(InstallMethod::Known)
    }
}

/// Edge visibility: `visibility: {edge, escrow: none|trustee, audiences[]}`
/// (the UniDPP design framework visibility rules).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Visibility {
    pub edge: VisibilityClass,
    /// Trustee holding the escrow envelope for blind edges.
    pub escrow: Option<String>,
    /// Role-qualified audiences for restricted edges.
    pub audiences: Vec<String>,
}

impl Visibility {
    pub fn open() -> Visibility {
        Visibility {
            edge: VisibilityClass::Public,
            escrow: None,
            audiences: Vec::new(),
        }
    }

    pub fn blind(escrow_trustee: Option<&str>) -> Visibility {
        Visibility {
            edge: VisibilityClass::Blind,
            escrow: escrow_trustee.map(|t| t.to_string()),
            audiences: Vec::new(),
        }
    }

    pub fn restricted(audiences: Vec<String>) -> Visibility {
        Visibility {
            edge: VisibilityClass::Restricted,
            escrow: None,
            audiences,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        match self.edge {
            VisibilityClass::Escrowed if self.escrow.is_none() => Err(ModelError::Validation(
                "escrowed edge requires a trustee".into(),
            )),
            VisibilityClass::Blind => {
                // Consumer edges are personal data: blind is the default;
                // an escrow envelope is optional.
                Ok(())
            }
            VisibilityClass::Public if !self.audiences.is_empty() => Err(ModelError::Validation(
                "public edge cannot carry audiences".into(),
            )),
            _ => Ok(()),
        }
    }
}

/// Installation binding: method, recoverability, visibility, slot identity,
/// pairing, alterations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Binding {
    pub method: InstallMethod,
    pub recoverability: Recoverability,
    pub visibility: Visibility,
    pub slot_id: Option<String>,
    pub pairing: Pairing,
    pub alterations: Vec<Alteration>,
}

impl Binding {
    /// True when disassembly restores a marketable object with identity
    /// continuity (R3 semantics persist).
    pub fn marketable_identity_continues(&self) -> bool {
        matches!(
            self.recoverability,
            Recoverability::Restorable | Recoverability::Harvestable
        )
    }
}

/// Identity-flow consequence of a binding's recoverability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IdentityFlow {
    /// Child resumes standalone life.
    ContinuesStandalone,
    /// Recovered but altered — continues with harvested status + parent
    /// history (value-relevant provenance).
    ContinuesHarvested,
    /// Child ceases; flows to a material passport via R2.
    ToMaterialPassport,
    /// Identity dissolves (absorbing: paint, adhesive, the cell inside a
    /// certified power bank) — modeled as R2 transformation, regime-temporal.
    Dissolved,
}

/// A typed relationship edge held by one passport.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PassportLink {
    pub link_type: LinkType,
    /// The other passport on this edge (the parent for an incoming
    /// installation edge recorded in the child's log).
    pub other: PassportId,
    pub direction: Direction,
    pub interval: Interval,
    pub binding: Option<Binding>,
}

impl PassportLink {
    pub fn association(other: PassportId, at: Timestamp) -> PassportLink {
        PassportLink {
            link_type: LinkType::Association,
            other,
            direction: Direction::Outgoing,
            interval: Interval::starting(at),
            binding: None,
        }
    }

    /// This passport derives from `input` (R2, historical, directional).
    pub fn derivation_from(input: PassportId, at: Timestamp) -> PassportLink {
        PassportLink {
            link_type: LinkType::Derivation,
            other: input,
            direction: Direction::Incoming,
            interval: Interval::starting(at),
            binding: None,
        }
    }

    /// This child is installed in `parent` (R3): the child's event log
    /// records its installation interval (parent, slot, method).
    pub fn installation(parent: PassportId, binding: Binding, at: Timestamp) -> PassportLink {
        PassportLink {
            link_type: LinkType::Installation,
            other: parent,
            direction: Direction::Incoming,
            interval: Interval::starting(at),
            binding: Some(binding),
        }
    }

    pub fn custody(holder: PassportId, at: Timestamp) -> PassportLink {
        PassportLink {
            link_type: LinkType::Custody,
            other: holder,
            direction: Direction::Outgoing,
            interval: Interval::starting(at),
            binding: None,
        }
    }

    pub fn membership(group: PassportId, at: Timestamp) -> PassportLink {
        PassportLink {
            link_type: LinkType::Membership,
            other: group,
            direction: Direction::Outgoing,
            interval: Interval::starting(at),
            binding: None,
        }
    }

    /// Close the interval (uninstall/removal).
    pub fn close(&mut self, at: Timestamp) -> Result<(), ModelError> {
        self.interval = Interval::between(self.interval.from, at)?;
        Ok(())
    }

    pub fn is_active_at(&self, t: Timestamp) -> bool {
        self.interval.contains(t)
    }

    pub fn identity_flow(&self) -> Option<IdentityFlow> {
        self.binding.as_ref().map(|b| match b.recoverability {
            Recoverability::Restorable => IdentityFlow::ContinuesStandalone,
            Recoverability::Harvestable => IdentityFlow::ContinuesHarvested,
            Recoverability::Destructive => IdentityFlow::ToMaterialPassport,
            Recoverability::Absorbing => IdentityFlow::Dissolved,
        })
    }

    /// Structural validation of the edge per its type.
    pub fn validate(&self) -> Result<(), ModelError> {
        if let Some(b) = &self.binding {
            b.visibility.validate()?;
        }
        match self.link_type {
            LinkType::Installation => {
                if self.binding.is_none() {
                    return Err(ModelError::Validation(
                        "installation is its own event class: binding {method, recoverability, visibility, slotId, pairing, alteration[]} is required".into(),
                    ));
                }
            }
            LinkType::Association if self.binding.is_some() => {
                return Err(ModelError::Validation(
                    "association is navigational only and carries no binding".into(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(day: u64) -> Timestamp {
        Timestamp::from_secs(1_750_000_000i64 + day as i64 * 86_400)
    }

    fn binding(recoverability: Recoverability) -> Binding {
        Binding {
            method: InstallMethod::Known(KnownMethod::Fastened),
            recoverability,
            visibility: Visibility::blind(Some("trustee.example")),
            slot_id: Some("battery-slot-1".into()),
            pairing: Pairing::Firmware,
            alterations: vec![Alteration::Known(KnownAlteration::TorqueToYield)],
        }
    }

    #[test]
    fn installation_interval_and_flow() {
        let parent = PassportId::new("urn:unidpp:passport:car-1").unwrap();
        let mut link =
            PassportLink::installation(parent.clone(), binding(Recoverability::Harvestable), t(0));
        link.validate().unwrap();
        assert!(link.is_active_at(t(10)));
        // Open interval stays active into the future.
        assert!(link.is_active_at(t(100)));
        link.close(t(30)).unwrap();
        assert!(link.is_active_at(t(30)));
        assert!(!link.is_active_at(t(31)));
        assert_eq!(link.identity_flow(), Some(IdentityFlow::ContinuesHarvested));
    }

    #[test]
    fn identity_continuity_rule() {
        assert!(binding(Recoverability::Restorable).marketable_identity_continues());
        assert!(binding(Recoverability::Harvestable).marketable_identity_continues());
        assert!(!binding(Recoverability::Destructive).marketable_identity_continues());
        assert!(!binding(Recoverability::Absorbing).marketable_identity_continues());
        let parent = PassportId::new("urn:unidpp:passport:p").unwrap();
        let destructive =
            PassportLink::installation(parent, binding(Recoverability::Destructive), t(0));
        assert_eq!(
            destructive.identity_flow(),
            Some(IdentityFlow::ToMaterialPassport)
        );
    }

    #[test]
    fn association_has_no_binding() {
        let other = PassportId::new("urn:unidpp:passport:kit-1").unwrap();
        let mut a = PassportLink::association(other, t(0));
        a.validate().unwrap();
        a.binding = Some(binding(Recoverability::Restorable));
        assert!(a.validate().is_err());
        let mut b = PassportLink::membership(
            PassportId::new("urn:unidpp:passport:shipment-7").unwrap(),
            t(0),
        );
        b.link_type = LinkType::Installation;
        assert!(b.validate().is_err());
    }

    #[test]
    fn visibility_rules() {
        assert!(Visibility::open().validate().is_ok());
        assert!(Visibility::blind(None).validate().is_ok());
        let mut v = Visibility {
            edge: VisibilityClass::Escrowed,
            escrow: None,
            audiences: vec![],
        };
        assert!(v.validate().is_err());
        v.escrow = Some("trustee".into());
        assert!(v.validate().is_ok());
        assert!(Visibility::restricted(vec!["repairer".into()])
            .validate()
            .is_ok());
    }

    #[test]
    fn alteration_casing_round_trip() {
        let a: Alteration = "Torque_To_Yield".parse().unwrap();
        assert_eq!(a, Alteration::Known(KnownAlteration::TorqueToYield));
        assert_eq!(a.to_string(), "torque-to-yield");
        let o: Alteration = "other:Laser Marked".parse().unwrap();
        assert_eq!(o.to_string(), "other:laser-marked");
    }
}
