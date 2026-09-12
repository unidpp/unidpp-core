//! Productness (PA-3): a dated, per-regime predicate, and the
//! re-entry classifier that distinguishes same-identity re-entry
//! from derived-identity re-entry.
//!
//! Productness is not a property of matter; it is a property a
//! REGIME ascribes, dated: the same object is a product here and
//! waste there, at different moments. End-of-waste re-qualifies the
//! SAME identity (the predicate toggles, dated — no new passport);
//! scrap issues a DERIVED passport (the derivation edge R2 — a new
//! identity). The two re-entries are distinguished, stated.

use std::collections::BTreeMap;

/// One productness evaluation under one regime.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProductnessRecord {
    /// The regime whose predicate decided (jurisdiction or program).
    pub regime: String,
    /// The moment the predicate was evaluated (RFC 3339).
    pub at: String,
    /// The outcome: is the subject a product under this regime?
    pub is_product: bool,
    /// The basis (the legal criterion satisfied or failed —
    /// end-of-waste criteria, product-law definition).
    pub basis: String,
}

/// A subject's productness ledger: per regime, the dated predicate
/// outcomes — the current standing is the latest per regime.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProductnessLedger {
    /// regime → dated records (append-only; history preserved).
    pub records: BTreeMap<String, Vec<ProductnessRecord>>,
}

impl ProductnessLedger {
    pub fn new() -> ProductnessLedger {
        ProductnessLedger::default()
    }

    /// Record one evaluation (append-only — corrections append, the
    /// history stays).
    pub fn record(&mut self, record: ProductnessRecord) -> &mut Self {
        self.records
            .entry(record.regime.clone())
            .or_default()
            .push(record);
        self
    }

    /// The current standing under one regime: the latest record.
    pub fn standing_under(&self, regime: &str) -> Option<&ProductnessRecord> {
        self.records.get(regime).and_then(|rs| rs.last())
    }

    /// The regimes currently holding the subject a product.
    pub fn product_regimes(&self) -> Vec<&str> {
        self.records
            .iter()
            .filter(|(_, rs)| rs.last().is_some_and(|r| r.is_product))
            .map(|(regime, _)| regime.as_str())
            .collect()
    }
}

/// The re-entry classifier's outcome.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "re-entry", rename_all = "kebab-case")]
pub enum ReEntry {
    /// Same identity: productness toggled under the regime (dated);
    /// NO new passport issues.
    SameIdentity {
        /// The regime whose predicate toggled.
        regime: String,
        /// The dated toggle record.
        record: ProductnessRecord,
    },
    /// Derived identity: a new passport issues following the
    /// derivation edge (R2) — the parent's identity does not
    /// re-qualify.
    DerivedIdentity {
        /// The new (derived) passport id.
        derived_passport: String,
        /// The parent passport id.
        parent: String,
        /// The derivation basis (scrap, split, decomposition).
        basis: String,
    },
}

/// Classify a re-entry into commerce (PA-3's verify: end-of-waste
/// re-qualifies the same identity; scrap issues a derived one).
///
/// The caller states the mode: `end_of_waste` (a legal state
/// transition — the regime's criteria were satisfied, so the SAME
/// identity re-qualifies, the predicate toggling dated) or `scrap`
/// (the material lost its identity — a derived passport follows
/// R2). The classifier records the toggle or names the derivation,
/// and never conflates them.
pub fn classify_re_entry(
    mode: &str,
    subject: &str,
    regime: &str,
    at: &str,
    derived_passport: Option<&str>,
    basis: &str,
) -> Result<ReEntry, String> {
    match mode {
        "end-of-waste" => Ok(ReEntry::SameIdentity {
            regime: regime.into(),
            record: ProductnessRecord {
                regime: regime.into(),
                at: at.into(),
                is_product: true,
                basis: basis.into(),
            },
        }),
        "scrap" => {
            let derived = derived_passport.ok_or_else(|| {
                "a derived-identity re-entry requires the derived passport id (R2)".to_string()
            })?;
            let _ = subject;
            Ok(ReEntry::DerivedIdentity {
                derived_passport: derived.into(),
                parent: subject.into(),
                basis: basis.into(),
            })
        }
        other => Err(format!(
            "unknown re-entry mode `{other}` (end-of-waste or scrap)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PA-3's verify: end-of-waste re-qualifies the SAME identity
    // (the predicate toggles, dated); scrap issues a DERIVED
    // passport (R2); the two are distinguished, stated.
    #[test]
    fn the_two_re_entries_are_distinguished() {
        let mut ledger = ProductnessLedger::new();

        // The subject leaves productness (waste status, EU WFD).
        ledger.record(ProductnessRecord {
            regime: "eu-wfd".into(),
            at: "2032-06-01T00:00:00Z".into(),
            is_product: false,
            basis: "waste status: discarded, awaiting end-of-waste criteria".into(),
        });
        assert!(ledger.standing_under("eu-wfd").unwrap().record_is_not());

        // End-of-waste: the criteria satisfied — the SAME identity
        // re-qualifies, the predicate toggling dated.
        let re_entry = classify_re_entry(
            "end-of-waste",
            "urn:unidpp:passport:pack-0001",
            "eu-wfd",
            "2033-01-15T00:00:00Z",
            None,
            "end-of-waste criteria met: processed, market-defined use, demand",
        )
        .unwrap();
        match &re_entry {
            ReEntry::SameIdentity { regime, record } => {
                assert_eq!(regime, "eu-wfd");
                assert!(record.is_product);
                assert_eq!(record.at, "2033-01-15T00:00:00Z");
            }
            other => panic!("expected same-identity, got {other:?}"),
        }
        // No new passport issues — the toggle is a record, not an
        // issuance; append it and the standing flips.
        if let ReEntry::SameIdentity { record, .. } = re_entry {
            ledger.record(record);
        }
        assert!(ledger.standing_under("eu-wfd").unwrap().is_product);
        // The history survives: two records under the regime.
        assert_eq!(ledger.records["eu-wfd"].len(), 2);
        assert_eq!(ledger.product_regimes(), ["eu-wfd"]);

        // Scrap: the material LOST its identity — a derived
        // passport follows R2; the parent does not re-qualify.
        let scrap = classify_re_entry(
            "scrap",
            "urn:unidpp:passport:pack-0001",
            "eu-wfd",
            "2033-01-15T00:00:00Z",
            Some("urn:unidpp:passport:scrap-lot-9"),
            "shredded: identity lost at part level, lot issued",
        )
        .unwrap();
        match &scrap {
            ReEntry::DerivedIdentity {
                derived_passport,
                parent,
                ..
            } => {
                assert_eq!(derived_passport, "urn:unidpp:passport:scrap-lot-9");
                assert_eq!(parent, "urn:unidpp:passport:pack-0001");
            }
            other => panic!("expected derived-identity, got {other:?}"),
        }
        // Scrap without the derived id is an error, stated.
        assert!(classify_re_entry("scrap", "x", "r", "now", None, "b").is_err());
        // Unknown modes are stated.
        assert!(classify_re_entry("rebirth", "x", "r", "now", None, "b").is_err());

        // Per-regime independence: another regime's predicate stands
        // on its own.
        ledger.record(ProductnessRecord {
            regime: "cn-miit".into(),
            at: "2033-01-20T00:00:00Z".into(),
            is_product: true,
            basis: "secondary raw material registered".into(),
        });
        assert_eq!(ledger.product_regimes().len(), 2);
    }

    /// Test-only helper: readable assertion on the record's outcome.
    trait RecordOutcome {
        fn record_is_not(&self) -> bool;
    }
    impl RecordOutcome for ProductnessRecord {
        fn record_is_not(&self) -> bool {
            !self.is_product
        }
    }
}
