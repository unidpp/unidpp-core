//! UniDPP core model (crate `unidpp-model`).
//!
//! Implements the model-layer semantics of `the UniDPP design framework`:
//! - design invariants I1-I3 (identity never re-minted, finest recorded
//!   granularity, dormant identifiers allowed),
//! - I5 typed relationship algebra (association / derivation / installation /
//!   type-lineage / custody / membership with method-slot-pairing-alteration-
//!   recoverability-visibility),
//! - I10 three-axial profiles (jurisdiction x sector x characteristic,
//!   predicate-triggered, S0-S3 capability gating),
//! - I9 graded trust markers and multi-suite signature framing,
//! - I12 edge visibility classes (public / restricted / blind / escrowed).
//!
//! Casing discipline: EN 18223 legislated identifier casing (5.2.2); this
//! core instead accepts any casing/separator spelling and canonicalizes to
//! the normalization table's lowercase form (`normalization` module).

pub mod decimal;
pub mod digest;
pub mod facts;
pub mod identifier;
pub mod ids;
pub mod link;
pub mod normalization;
pub mod profile;
pub mod time;
pub mod trust;

pub use decimal::Decimal;
pub use digest::{sha256, CanonicalReader, CanonicalWriter, Hash};
pub use facts::{FactValue, TriggerPredicate, TwinFacts};
pub use identifier::{Granularity, IdScheme, ProductIdentifier};
pub use ids::{PassportId, ProfileId};
pub use link::{
    Alteration, Binding, Direction, IdentityFlow, InstallMethod, KnownAlteration, KnownMethod,
    LinkType, Pairing, PassportLink, Recoverability, Visibility, VisibilityClass,
};
pub use profile::{
    CapabilityClass, DataPointRef, FreshnessRequirement, IssuerClass, ProfileAxes, ProfileManifest,
    Resolution, Traversal, TrustGrade,
};
pub use time::{Interval, Timestamp};
pub use trust::{SigSlot, SignatureSuite, TrustMarker};

use std::fmt;

/// Error returned when a string does not name a member of a table-driven
/// enum after normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumParseError {
    pub input: String,
    pub kind: String,
}

impl fmt::Display for EnumParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` does not name a {} (after casing/separator normalization)",
            self.input, self.kind
        )
    }
}

impl std::error::Error for EnumParseError {}

/// Errors of the model crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    Parse(String),
    Validation(String),
    Overflow(String),
    DivideByZero,
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModelError::Parse(m) => write!(f, "parse error: {m}"),
            ModelError::Validation(m) => write!(f, "validation error: {m}"),
            ModelError::Overflow(m) => write!(f, "overflow: {m}"),
            ModelError::DivideByZero => write!(f, "division by zero"),
        }
    }
}

impl std::error::Error for ModelError {}

/// Declares a table-driven string enum.
///
/// Parsing is case- and separator-insensitive ("Model", "MODEL", "mo_del"
/// all parse) and canonicalizes to the lowercase table token; serialization
/// emits the canonical token. Declaration order is the canonical order
/// (used, e.g., for the capability and trust-marker ladders).
#[macro_export]
macro_rules! str_enum {
    (
        $(#[$m:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vm:meta])*
                $variant:ident => $canonical:expr
            ),+ $(,)?
        }
    ) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        $vis enum $name {
            $(
                $(#[$vm])*
                $variant
            ),+
        }

        impl $name {
            /// Canonical (normalized) wire token.
            $vis fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $canonical),+
                }
            }

            /// All variants, in canonical (declaration) order.
            $vis const ALL: &'static [Self] = &[ $(Self::$variant),+ ];

            /// Parse after normalization; accepts any casing/separator spelling.
            $vis fn parse_token(s: &str) -> Result<Self, $crate::EnumParseError> {
                let squashed = $crate::normalization::squash(s);
                $(
                    if squashed == $crate::normalization::squash($canonical) {
                        return Ok(Self::$variant);
                    }
                )+
                Err($crate::EnumParseError {
                    input: s.to_string(),
                    kind: stringify!($name).to_string(),
                })
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::EnumParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse_token(s)
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let s = <String as ::serde::Deserialize<'de>>::deserialize(deserializer)?;
                Self::parse_token(&s).map_err(::serde::de::Error::custom)
            }
        }
    };
}
