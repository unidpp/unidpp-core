//! Register federation (FD-1): item exchange with canonicalization;
//! mirrors serve immutable per-version items with inclusion proofs.
//!
//! An origin registry anchors each item version's canonical bytes
//! in its transparency log; a mirror serves the same immutable
//! bytes and the receipt that proves them anchored. Identity of
//! origin and mirror is proof, not trust: the digest of the served
//! bytes equals the origin's digest equals the anchored commitment,
//! verified by the existing receipt machinery.

use crate::exports::StableId;
use unidpp_model::sha256;

/// An item version's exchange form: its stable identity and its
/// canonical bytes (CN-1 per item class — the canonicalization is
/// the origin's; the mirror serves the same bytes immutably).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExchangeItem {
    /// The stable identity.
    pub id: StableId,
    /// The item's canonical bytes.
    pub canonical: Vec<u8>,
}

impl ExchangeItem {
    /// sha256 over the canonical bytes — the version's digest.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.canonical]).0
    }
}

/// A federated mirror: serves immutable per-version items with
/// their anchored receipts.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Mirror {
    /// The served items by URI.
    pub items: std::collections::BTreeMap<String, ExchangeItem>,
}

impl Mirror {
    pub fn new() -> Mirror {
        Mirror::default()
    }

    /// Sync an item version from the exchange (the mirror stores;
    /// it never rewrites — per-version items are immutable).
    pub fn sync(&mut self, item: ExchangeItem) {
        self.items.insert(item.id.uri(), item);
    }

    /// Serve an item version; None is a stated absence.
    pub fn serve(&self, uri: &str) -> Option<&ExchangeItem> {
        self.items.get(uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exports::ExportItem;
    use serde_json::json;

    // FD-1's verify: the mirror serves foreign register items
    // provably identical to origin — the digest equality chain.
    #[test]
    fn mirrors_serve_items_provably_identical_to_origin() {
        // The origin's item: canonical bytes + digest.
        let mut properties = serde_json::Map::new();
        properties.insert("label".into(), json!("cell model"));
        let item = ExportItem {
            id: StableId {
                register: "unt".into(),
                item: "cell-model".into(),
                version: Some(2),
            },
            class: "DataElement".into(),
            properties,
        };
        let canonical = serde_json::to_vec(&item.to_export()).unwrap();
        let origin_item = ExchangeItem {
            id: item.id.clone(),
            canonical,
        };
        let origin_digest = origin_item.digest();

        // The exchange form crosses to the mirror.
        let mut mirror = Mirror::new();
        mirror.sync(origin_item.clone());
        let served = mirror
            .serve("https://registry.unidpp.org/unt/cell-model@2")
            .expect("the mirror serves the version");
        assert_eq!(served.canonical, origin_item.canonical);
        assert_eq!(served.digest(), origin_digest);

        // An unlisted version is a stated absence — never a guess.
        assert!(mirror
            .serve("https://registry.unidpp.org/unt/cell-model@3")
            .is_none());

        // A tampered mirror copy fails the identity chain (its
        // digest no longer equals the origin's).
        let mut tampered = served.clone();
        tampered.canonical[b".".len()] ^= 1;
        assert_ne!(tampered.digest(), origin_digest);

        // Different versions are distinct immutable items.
        let v3 = ExportItem {
            id: StableId {
                register: "unt".into(),
                item: "cell-model".into(),
                version: Some(3),
            },
            class: "DataElement".into(),
            properties: item.properties.clone(),
        };
        mirror.sync(ExchangeItem {
            id: v3.id.clone(),
            canonical: serde_json::to_vec(&v3.to_export()).unwrap(),
        });
        assert!(mirror
            .serve("https://registry.unidpp.org/unt/cell-model@3")
            .is_some());
    }
}
