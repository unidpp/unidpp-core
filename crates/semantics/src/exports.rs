//! Parseable exports with stable identifiers (AI-1/2): every
//! registry item and profile exports a parseable, JSON-LD-shaped
//! document; every element carries a resolvable stable identifier.
//!
//! The export shape is deliberately minimal and machine-friendly:
//! `@context` (the registry's vocabulary base), `@id` (the item's
//! stable registry URI — register/item[@version]), `@type` (the
//! item class), and typed properties. Ids resolve BACK: the URI
//! shape parses to register, item and version, so a foreign
//! consumer that holds only the export can re-address the registry.

use serde_json::{json, Map, Value};

/// A registry item's exportable identity: what an `@id` carries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StableId {
    /// The register (e.g. `dpp`, `unt`, `profiles`).
    pub register: String,
    /// The item's local identifier.
    pub item: String,
    /// The pinned version (None: floating latest).
    pub version: Option<u64>,
}

impl StableId {
    /// The registry base URI for exports.
    pub const BASE: &'static str = "https://registry.unidpp.org";

    /// The stable URI: {base}/{register}/{item}[@{version}].
    pub fn uri(&self) -> String {
        match self.version {
            Some(v) => format!("{}/{}/{}@{v}", Self::BASE, self.register, self.item),
            None => format!("{}/{}/{}", Self::BASE, self.register, self.item),
        }
    }

    /// Parse a stable URI back to its parts (AI-2's resolution from
    /// the export back to the registry item).
    pub fn parse(uri: &str) -> Result<StableId, String> {
        let rest = uri
            .strip_prefix(Self::BASE)
            .ok_or_else(|| format!("`{uri}` is not under the registry base {}", Self::BASE))?;
        let rest = rest.trim_start_matches('/');
        let mut parts = rest.split('/');
        let register = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("`{uri}` names no register"))?;
        let tail = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("`{uri}` names no item"))?;
        if parts.next().is_some() {
            return Err(format!("`{uri}` has trailing path segments"));
        }
        let (item, version) = match tail.split_once('@') {
            Some((item, v)) => (
                item,
                Some(
                    v.parse::<u64>()
                        .map_err(|_| format!("`{uri}` has a malformed version `{v}`"))?,
                ),
            ),
            None => (tail, None),
        };
        Ok(StableId {
            register: register.into(),
            item: item.into(),
            version,
        })
    }
}

/// An exportable item: identity, class, and typed properties.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExportItem {
    /// The stable identity.
    pub id: StableId,
    /// The item class token (e.g. `DataElement`, `Profile`).
    pub class: String,
    /// Typed properties (string-keyed; values are JSON).
    pub properties: Map<String, Value>,
}

impl ExportItem {
    /// Render the JSON-LD-shaped export document.
    pub fn to_export(&self) -> Value {
        let mut doc = Map::new();
        doc.insert(
            "@context".into(),
            json!(format!("{}/vocab", StableId::BASE)),
        );
        doc.insert("@id".into(), json!(self.id.uri()));
        doc.insert("@type".into(), json!(self.class));
        for (k, v) in &self.properties {
            doc.insert(k.clone(), v.clone());
        }
        Value::Object(doc)
    }

    /// Parse an export document back into an item (the round-trip;
    /// the `@id` resolves to its parts).
    pub fn from_export(doc: &Value) -> Result<ExportItem, String> {
        let object = doc.as_object().ok_or("the export is not an object")?;
        let uri = object
            .get("@id")
            .and_then(Value::as_str)
            .ok_or("the export carries no @id")?;
        let id = StableId::parse(uri)?;
        let class = object
            .get("@type")
            .and_then(Value::as_str)
            .ok_or("the export carries no @type")?
            .to_string();
        let mut properties = Map::new();
        for (k, v) in object {
            if k != "@context" && k != "@id" && k != "@type" {
                properties.insert(k.clone(), v.clone());
            }
        }
        Ok(ExportItem {
            id,
            class,
            properties,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // AI-1/AI-2's verify: the export parses (here AND by a foreign
    // parser — the Python harness asserts the same bytes); ids
    // resolve from the export back to the registry item.
    #[test]
    fn exports_round_trip_and_ids_resolve_back() {
        let mut properties = Map::new();
        properties.insert("label".into(), json!("battery capacity"));
        properties.insert("unit".into(), json!("Ah"));
        properties.insert("quantityKind".into(), json!("capacity"));
        let item = ExportItem {
            id: StableId {
                register: "unt".into(),
                item: "battery-capacity".into(),
                version: Some(3),
            },
            class: "DataElement".into(),
            properties,
        };
        let export = item.to_export();
        assert_eq!(
            export["@id"],
            json!("https://registry.unidpp.org/unt/battery-capacity@3")
        );
        assert_eq!(export["@type"], json!("DataElement"));
        assert_eq!(export["unit"], json!("Ah"));

        // Round-trip through a serialized document.
        let text = serde_json::to_string(&export).unwrap();
        let back = ExportItem::from_export(&serde_json::from_str(&text).unwrap()).unwrap();
        assert_eq!(back, item);

        // The id resolves back to its parts.
        let parsed = StableId::parse("https://registry.unidpp.org/unt/battery-capacity@3").unwrap();
        assert_eq!(parsed.register, "unt");
        assert_eq!(parsed.item, "battery-capacity");
        assert_eq!(parsed.version, Some(3));
        let floating = StableId::parse("https://registry.unidpp.org/profiles/eu-battery").unwrap();
        assert_eq!(floating.version, None);

        // Malformed ids are stated failures.
        assert!(StableId::parse("https://example.org/unt/x").is_err());
        assert!(StableId::parse("https://registry.unidpp.org/unt").is_err());
        assert!(StableId::parse("https://registry.unidpp.org/unt/x@v2").is_err());
        assert!(StableId::parse("https://registry.unidpp.org/a/b/c").is_err());
    }
}
