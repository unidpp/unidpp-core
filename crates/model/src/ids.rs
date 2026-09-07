//! Passport and profile identifiers (newtypes with normalization).
//!
//! Invariant I14: identities outlive their issuers and hosts — these ids
//! are location-free slugs (or URN forms), never resolver addresses.

use std::fmt;
use std::str::FromStr;

use crate::ModelError;

macro_rules! id_newtype {
    ($(#[$m:meta])* pub struct $name:ident, $expect:expr) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn new(raw: &str) -> Result<$name, ModelError> {
                let n = raw.trim().to_ascii_lowercase();
                if n.is_empty() {
                    return Err(ModelError::Validation(
                        concat!(stringify!($name), " must not be empty").to_string(),
                    ));
                }
                if n.len() > 128 {
                    return Err(ModelError::Validation(
                        concat!(stringify!($name), " too long (>128 chars)").to_string(),
                    ));
                }
                if !n.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(ModelError::Validation(
                        concat!(stringify!($name), " contains whitespace/control characters").to_string(),
                    ));
                }
                Ok($name(n))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $name::new(s)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let s = <String as serde::Deserialize>::deserialize(deserializer)?;
                $name::new(&s).map_err(serde::de::Error::custom)
            }
        }

        impl $name {
            /// Human-facing expectation, used in error messages.
            #[allow(dead_code)]
            pub fn expected_shape() -> &'static str {
                $expect
            }
        }
    };
}

id_newtype!(
    /// Passport identifier (e.g. `urn:unidpp:passport:eu-bp-000123`).
    pub struct PassportId,
    "urn:unidpp:passport:<slug>"
);
id_newtype!(
    /// Profile identifier (e.g. `urn:unidpp:profile:eu-espr-battery-v3`).
    pub struct ProfileId,
    "urn:unidpp:profile:<slug>"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_and_round_trip() {
        let a = PassportId::new("urn:unidpp:passport:EU-BP-42").unwrap();
        assert_eq!(a.as_str(), "urn:unidpp:passport:eu-bp-42");
        assert_eq!(a, PassportId::new("URN:UNIDPP:PASSPORT:eu-bp-42").unwrap());
        assert_eq!(a.to_string().parse::<PassportId>().unwrap(), a);
        assert!(PassportId::new("  ").is_err());
        assert!(PassportId::new("has space").is_err());
    }
}
