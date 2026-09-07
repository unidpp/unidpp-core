//! Scheme-agnostic product identifiers (ISO/IEC 15459 / EN 18219 style).
//!
//! Invariant I1/I3: one subject, one identity, never re-minted; inputs are
//! recorded at the finest identifier granularity available (model / batch /
//! item), and dormant identifiers are allowed even when no passport exists
//! behind them yet.
//!
//! Wire forms accepted (case-insensitive scheme tokens per the
//! normalization table):
//! - scheme-prefixed: `gtin:4006381333931`, `SGTIN:4006381333931+21+SN7`
//! - 15459/GS1 element string: `01+4006381333931+10+LOT42+21+SN7`
//!   (AIs: 01 key, 10 lot/batch, 21 serial; 11/17/240 accepted and ignored
//!   for identity purposes)
//! - bare digits (4..=14): GTIN
//! - http(s) URI: URI scheme
//! - issuer-local: `local:<tag>:<key>`
//!
//! Canonical display: element string for GS1 schemes (`01+K[+10+L][+21+S]`),
//! scheme-prefixed lowercase otherwise.

use std::fmt;
use std::str::FromStr;

use crate::normalization;
use crate::ModelError;

crate::str_enum! {
    /// Identifier granularity (I3: finest recorded granularity).
    pub enum Granularity {
        Model => "model",
        Batch => "batch",
        Item => "item",
    }
}

/// Identifier schemes carried by the neutral core. GS1 family + ISO/IEC
/// 15459 CPID + national/other carriers; `Local` covers issuer-scoped
/// schemes (normalized lowercase tag).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdScheme {
    Gtin,
    Sgtin,
    Gsrn,
    Gln,
    Cpid,
    Ssn,
    Upu,
    Vin,
    Handle,
    Doi,
    Uri,
    Local(String),
}

impl IdScheme {
    pub fn as_str(&self) -> String {
        match self {
            IdScheme::Gtin => "gtin".into(),
            IdScheme::Sgtin => "sgtin".into(),
            IdScheme::Gsrn => "gsrn".into(),
            IdScheme::Gln => "gln".into(),
            IdScheme::Cpid => "cpid".into(),
            IdScheme::Ssn => "ssn".into(),
            IdScheme::Upu => "upu".into(),
            IdScheme::Vin => "vin".into(),
            IdScheme::Handle => "handle".into(),
            IdScheme::Doi => "doi".into(),
            IdScheme::Uri => "uri".into(),
            IdScheme::Local(tag) => format!("local:{}", normalization::normalize_token(tag)),
        }
    }

    pub fn parse_token(s: &str) -> Result<IdScheme, ModelError> {
        let (head, rest) = match s.split_once(':') {
            Some((h, r)) => (h, Some(r)),
            None => (s, None),
        };
        match normalization::squash(head).as_str() {
            "gtin" => Ok(IdScheme::Gtin),
            "sgtin" => Ok(IdScheme::Sgtin),
            "gsrn" => Ok(IdScheme::Gsrn),
            "gln" => Ok(IdScheme::Gln),
            "cpid" => Ok(IdScheme::Cpid),
            "ssn" => Ok(IdScheme::Ssn),
            "upu" => Ok(IdScheme::Upu),
            "vin" => Ok(IdScheme::Vin),
            "handle" => Ok(IdScheme::Handle),
            "doi" => Ok(IdScheme::Doi),
            "uri" => Ok(IdScheme::Uri),
            "local" => {
                let tag = rest
                    .filter(|r| !r.trim().is_empty())
                    .ok_or_else(|| {
                        ModelError::Parse(
                            "local scheme requires an issuer tag (`local:<tag>`)".into(),
                        )
                    })?
                    .to_string();
                Ok(IdScheme::Local(normalization::normalize_token(&tag)))
            }
            _ => Err(ModelError::Parse(format!(
                "unknown identifier scheme `{s}`"
            ))),
        }
    }

    fn requires_digits(&self) -> bool {
        matches!(
            self,
            IdScheme::Gtin | IdScheme::Sgtin | IdScheme::Gsrn | IdScheme::Gln
        )
    }

    fn default_granularity(&self) -> Granularity {
        match self {
            IdScheme::Gtin
            | IdScheme::Gln
            | IdScheme::Handle
            | IdScheme::Doi
            | IdScheme::Uri
            | IdScheme::Local(_) => Granularity::Model,
            _ => Granularity::Item,
        }
    }
}

impl fmt::Display for IdScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl FromStr for IdScheme {
    type Err = ModelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IdScheme::parse_token(s)
    }
}

impl serde::Serialize for IdScheme {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for IdScheme {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        IdScheme::parse_token(&s).map_err(serde::de::Error::custom)
    }
}

/// A product identifier: scheme + key + optional lot/serial extensions,
/// with derived granularity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProductIdentifier {
    pub scheme: IdScheme,
    pub key: String,
    pub lot: Option<String>,
    pub serial: Option<String>,
    pub granularity: Granularity,
}

impl ProductIdentifier {
    pub fn new(scheme: IdScheme, key: &str) -> Result<ProductIdentifier, ModelError> {
        Self::build(scheme, key.to_string(), None, None)
    }

    pub fn with_lot(mut self, lot: &str) -> Result<ProductIdentifier, ModelError> {
        if lot.is_empty() {
            return Err(ModelError::Validation("empty lot".into()));
        }
        self.lot = Some(lot.to_string());
        self.recompute_granularity();
        Ok(self)
    }

    pub fn with_serial(mut self, serial: &str) -> Result<ProductIdentifier, ModelError> {
        if serial.is_empty() {
            return Err(ModelError::Validation("empty serial".into()));
        }
        self.serial = Some(serial.to_string());
        self.recompute_granularity();
        Ok(self)
    }

    fn build(
        scheme: IdScheme,
        key: String,
        lot: Option<String>,
        serial: Option<String>,
    ) -> Result<ProductIdentifier, ModelError> {
        if key.is_empty() {
            return Err(ModelError::Validation("identifier key is empty".into()));
        }
        if !key.bytes().all(|b| b.is_ascii_graphic() && b != b'+') {
            return Err(ModelError::Validation(format!(
                "identifier key `{key}` contains non-graphical or reserved characters"
            )));
        }
        if scheme.requires_digits() {
            let ok = key.len() <= 14 && key.bytes().all(|b| b.is_ascii_digit());
            if !ok {
                return Err(ModelError::Validation(format!(
                    "scheme {} requires up to 14 ASCII digits, got `{key}`",
                    scheme
                )));
            }
        }
        let mut id = ProductIdentifier {
            scheme,
            key,
            lot,
            serial,
            granularity: Granularity::Model,
        };
        id.recompute_granularity();
        Ok(id)
    }

    fn recompute_granularity(&mut self) {
        self.granularity = if self.serial.is_some() {
            Granularity::Item
        } else if self.lot.is_some() {
            Granularity::Batch
        } else {
            self.scheme.default_granularity()
        };
    }

    pub fn parse(input: &str) -> Result<ProductIdentifier, ModelError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(ModelError::Parse("empty identifier".into()));
        }
        if s.starts_with("01+") {
            return Self::parse_element_string(s);
        }
        if s.starts_with("http://") || s.starts_with("https://") {
            return Self::build(IdScheme::Uri, s.to_string(), None, None);
        }
        if let Some((head, rest)) = split_scheme_prefix(s) {
            if normalization::squash(head) == "local" {
                let (tag, keypart) = rest.split_once(':').ok_or_else(|| {
                    ModelError::Parse("local scheme requires `local:<tag>:<key>`".into())
                })?;
                let scheme = IdScheme::Local(normalization::normalize_token(tag));
                let (key, lot, serial) = split_key_extensions(keypart.to_string());
                return Self::build(scheme, key, lot, serial);
            }
            let mut scheme = IdScheme::parse_token(head)?;
            let (key, lot, serial) = split_key_extensions(rest.to_string());
            // Canonicalize the GS1 scheme by extension presence (a GTIN
            // with a serial is an SGTIN), matching element-string parses.
            if scheme == IdScheme::Gtin && serial.is_some() {
                scheme = IdScheme::Sgtin;
            }
            return Self::build(scheme, key, lot, serial);
        }
        if s.bytes().all(|b| b.is_ascii_digit()) && (4..=14).contains(&s.len()) {
            return Self::build(IdScheme::Gtin, s.to_string(), None, None);
        }
        Err(ModelError::Parse(format!(
            "unrecognized identifier form `{s}`"
        )))
    }

    fn parse_element_string(s: &str) -> Result<ProductIdentifier, ModelError> {
        let parts: Vec<&str> = s.split('+').collect();
        if parts.len() % 2 != 0 {
            return Err(ModelError::Parse(format!("malformed element string `{s}`")));
        }
        let mut key: Option<String> = None;
        let mut lot: Option<String> = None;
        let mut serial: Option<String> = None;
        let mut i = 0;
        while i < parts.len() {
            let ai = parts[i];
            let val = parts[i + 1];
            if val.is_empty() {
                return Err(ModelError::Parse(format!(
                    "empty value for AI {ai} in `{s}`"
                )));
            }
            match ai {
                "01" => key = Some(val.to_string()),
                "10" => lot = Some(val.to_string()),
                "21" => serial = Some(val.to_string()),
                "11" | "17" | "240" => { /* accepted, not part of identity */ }
                other => {
                    return Err(ModelError::Parse(format!(
                        "unsupported application identifier `{other}`"
                    )))
                }
            }
            i += 2;
        }
        let key = key.ok_or_else(|| {
            ModelError::Parse(format!("element string `{s}` lacks the AI 01 key"))
        })?;
        let scheme = if serial.is_some() {
            IdScheme::Sgtin
        } else {
            IdScheme::Gtin
        };
        Self::build(scheme, key, lot, serial)
    }

    pub fn is_item_level(&self) -> bool {
        self.granularity == Granularity::Item
    }

    /// GS1 check-digit validation when applicable (13/14-digit keys),
    /// computed with the standard mod-10 alternating 1/3 weights.
    pub fn gs1_check_digit_ok(&self) -> Option<bool> {
        if !matches!(self.scheme, IdScheme::Gtin | IdScheme::Sgtin)
            || !(13..=14).contains(&self.key.len())
        {
            return None;
        }
        let digits: Vec<u32> = self.key.bytes().map(|b| (b - b'0') as u32).collect();
        let check = *digits.last().unwrap();
        let body = &digits[..digits.len() - 1];
        let mut sum = 0u32;
        for (i, d) in body.iter().rev().enumerate() {
            sum += d * if i % 2 == 0 { 3 } else { 1 };
        }
        Some((10 - (sum % 10)) % 10 == check)
    }
}

impl fmt::Display for ProductIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scheme {
            IdScheme::Gtin | IdScheme::Sgtin => {
                write!(f, "01+{}", self.key)?;
            }
            _ => {
                write!(f, "{}:{}", self.scheme.as_str(), self.key)?;
            }
        }
        if let Some(lot) = &self.lot {
            write!(f, "+10+{lot}")?;
        }
        if let Some(serial) = &self.serial {
            write!(f, "+21+{serial}")?;
        }
        Ok(())
    }
}

impl FromStr for ProductIdentifier {
    type Err = ModelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ProductIdentifier::parse(s)
    }
}

impl serde::Serialize for ProductIdentifier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for ProductIdentifier {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        ProductIdentifier::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Split `<key>[+10+<lot>][+21+<serial>]` into components.
fn split_key_extensions(s: String) -> (String, Option<String>, Option<String>) {
    let parts: Vec<&str> = s.split('+').collect();
    let key = parts[0].to_string();
    let mut lot = None;
    let mut serial = None;
    let mut i = 1;
    while i + 1 < parts.len() {
        match parts[i] {
            "10" => lot = Some(parts[i + 1].to_string()),
            "21" => serial = Some(parts[i + 1].to_string()),
            _ => break,
        }
        i += 2;
    }
    (key, lot, serial)
}

fn split_scheme_prefix(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(':')?;
    let head = &s[..idx];
    if head.is_empty()
        || !head
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some((head, &s[idx + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EAN: &str = "4006381333931";

    #[test]
    fn prefixed_forms() {
        let a = ProductIdentifier::parse(&format!("gtin:{EAN}")).unwrap();
        assert_eq!(a.scheme, IdScheme::Gtin);
        assert_eq!(a.granularity, Granularity::Model);
        assert_eq!(a.to_string(), format!("01+{EAN}"));

        let b = ProductIdentifier::parse(&format!("GTIN:{EAN}")).unwrap();
        assert_eq!(a, b);

        let s = ProductIdentifier::parse(&format!("SGTIN:{EAN}+21+SN7")).unwrap();
        assert_eq!(s.scheme, IdScheme::Sgtin);
        assert_eq!(s.serial.as_deref(), Some("SN7"));
        assert_eq!(s.granularity, Granularity::Item);
        assert_eq!(s.to_string(), format!("01+{EAN}+21+SN7"));
    }

    #[test]
    fn element_string_form() {
        let e = ProductIdentifier::parse(&format!("01+{EAN}+10+LOT42+21+SN7")).unwrap();
        assert_eq!(e.scheme, IdScheme::Sgtin);
        assert_eq!(e.lot.as_deref(), Some("LOT42"));
        assert_eq!(e.serial.as_deref(), Some("SN7"));
        let rt = ProductIdentifier::parse(&e.to_string()).unwrap();
        assert_eq!(e, rt);
        let batch = ProductIdentifier::parse(&format!("01+{EAN}+10+LOT42")).unwrap();
        assert_eq!(batch.granularity, Granularity::Batch);
        assert_eq!(batch.scheme, IdScheme::Gtin);
    }

    #[test]
    fn bare_digits_and_uri() {
        assert_eq!(
            ProductIdentifier::parse("4006381333931").unwrap().scheme,
            IdScheme::Gtin
        );
        let uri = ProductIdentifier::parse("https://id.example.org/x/42").unwrap();
        assert_eq!(uri.scheme, IdScheme::Uri);
        assert_eq!(uri.to_string(), "uri:https://id.example.org/x/42");
        assert_eq!(ProductIdentifier::parse(&uri.to_string()).unwrap(), uri);
    }

    #[test]
    fn local_scheme() {
        let l = ProductIdentifier::parse("local:GB-T33993:XYZ-9").unwrap();
        assert_eq!(l.scheme, IdScheme::Local("gb-t33993".to_string()));
        assert_eq!(l.to_string(), "local:gb-t33993:XYZ-9");
        assert_eq!(ProductIdentifier::parse(&l.to_string()).unwrap(), l);
        let again = ProductIdentifier::parse("LOCAL:gb_t33993:XYZ-9").unwrap();
        assert_eq!(l, again);
    }

    #[test]
    fn check_digit() {
        let ok = ProductIdentifier::parse(&format!("gtin:{EAN}")).unwrap();
        assert_eq!(ok.gs1_check_digit_ok(), Some(true));
        let bad = ProductIdentifier::parse("gtin:4006381333932").unwrap();
        assert_eq!(bad.gs1_check_digit_ok(), Some(false));
        let short = ProductIdentifier::parse("gtin:1234").unwrap();
        assert_eq!(short.gs1_check_digit_ok(), None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(ProductIdentifier::parse("").is_err());
        assert!(ProductIdentifier::parse("gtin:").is_err());
        assert!(ProductIdentifier::parse("01+4006381333931+21+").is_err());
        assert!(ProductIdentifier::parse("gtin:ABC").is_err());
        assert!(ProductIdentifier::parse("unknown:x").is_err());
    }
}
