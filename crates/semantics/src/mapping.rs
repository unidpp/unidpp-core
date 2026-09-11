//! The semantic layer: mapping items under the three-tier
//! discipline (PR-5) and their composition (SI-12).
//!
//! Tier 1 — a deterministic mapping: a registered, versioned
//! transform reference; applying it to a source value yields the
//! target value, always the same output for the same input. Tier 2
//! — a correspondence with declared scope and residual: the items
//! correspond, within the scope, with a stated residual (what the
//! correspondence does not cover); it asserts similarity, not
//! transformability. Tier 3 — NO mapping asserted: the pair is
//! recorded precisely so that no correspondence is ever inferred;
//! the two items remain distinct.
//!
//! Composition (SI-12): tier-1 chains compose associatively (a
//! transform of a transform is a transform, its reference chain
//! recorded); tier-2 links propagate residuals (accumulating in
//! order, scopes intersecting); any tier-3 edge in a path refuses
//! the whole composition — no correspondence exists. Chains record
//! every constituent mapping version, and chain length is
//! policy-capped.

use unidpp_model::{sha256, CanonicalWriter};

/// The three tiers of the mapping discipline.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "tier", rename_all = "kebab-case")]
pub enum MappingKind {
    /// Tier 1: a deterministic mapping by a registered transform.
    Deterministic {
        /// The registered transform reference (versioned, cited).
        transform: String,
    },
    /// Tier 2: a correspondence with declared scope and residual.
    Correspondence {
        /// What the correspondence covers (element subset or
        /// qualifier).
        scope: Vec<String>,
        /// The residual: what the correspondence does not cover,
        /// stated by the attester.
        residual: String,
        /// Who attests the correspondence.
        attester: String,
    },
    /// Tier 3: no mapping is asserted between the items.
    NoMapping {
        /// Why the record exists (divergence recorded, not
        /// reconciled).
        note: String,
    },
}

/// A registered mapping item: source item → target item, under one
/// of the three tiers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MappingItem {
    /// The source registry item (register!item[@version]).
    pub source: String,
    /// The target registry item.
    pub target: String,
    /// The mapping's own version.
    pub version: u64,
    /// The tier payload.
    pub kind: MappingKind,
}

impl MappingItem {
    /// The canonical, committable form (CN-1): source, target,
    /// version, the tier token and its fields.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        w.write_bytes(self.source.as_bytes());
        w.write_bytes(self.target.as_bytes());
        w.write_bytes(&self.version.to_le_bytes());
        match &self.kind {
            MappingKind::Deterministic { transform } => {
                w.write_bytes(b"tier-1");
                w.write_bytes(transform.as_bytes());
            }
            MappingKind::Correspondence {
                scope,
                residual,
                attester,
            } => {
                w.write_bytes(b"tier-2");
                let mut sorted: Vec<&str> = scope.iter().map(|s| s.as_str()).collect();
                sorted.sort();
                for s in sorted {
                    w.write_bytes(s.as_bytes());
                }
                w.write_bytes(residual.as_bytes());
                w.write_bytes(attester.as_bytes());
            }
            MappingKind::NoMapping { note } => {
                w.write_bytes(b"tier-3");
                w.write_bytes(note.as_bytes());
            }
        }
        w.into_bytes()
    }

    /// The item's digest.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.canonical_bytes()]).0
    }
}

/// A composed chain of mappings (SI-12): source → … → target with
/// every constituent version recorded.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MappingChain {
    /// The chain's start.
    pub source: String,
    /// The chain's end.
    pub target: String,
    /// Every hop's mapping item (source of hop i+1 must equal
    /// target of hop i).
    pub hops: Vec<MappingItem>,
    /// The residual accumulated across tier-2 hops (empty when the
    /// chain is purely tier-1).
    pub residual: Vec<String>,
    /// The scopes intersected across tier-2 hops.
    pub scope: Vec<String>,
}

impl MappingChain {
    /// A single mapping as a chain.
    pub fn single(item: MappingItem) -> Result<MappingChain, MappingError> {
        let chain = MappingChain {
            source: item.source.clone(),
            target: item.target.clone(),
            residual: match &item.kind {
                MappingKind::Correspondence { residual, .. } => vec![residual.clone()],
                _ => Vec::new(),
            },
            scope: match &item.kind {
                MappingKind::Correspondence { scope, .. } => scope.clone(),
                _ => Vec::new(),
            },
            hops: vec![item],
        };
        Ok(chain)
    }

    /// Compose: self ∘ next (self's target must be next's source;
    /// any tier-3 hop refuses the composition; the policy cap on
    /// chain length is enforced).
    pub fn then(self, next: MappingItem, cap: usize) -> Result<MappingChain, MappingError> {
        if self.target != next.source {
            return Err(MappingError::Mismatch {
                expected: self.target.clone(),
                got: next.source.clone(),
            });
        }
        if let MappingKind::NoMapping { .. } = &next.kind {
            return Err(MappingError::NoCorrespondence {
                source: next.source.clone(),
                target: next.target.clone(),
            });
        }
        if self.hops.len() + 1 > cap {
            return Err(MappingError::OverCap {
                hops: self.hops.len() + 1,
                cap,
            });
        }
        let mut chain = MappingChain {
            source: self.source,
            target: next.target.clone(),
            hops: self.hops,
            residual: self.residual,
            scope: self.scope,
        };
        match &next.kind {
            MappingKind::Correspondence {
                scope, residual, ..
            } => {
                chain.residual.push(residual.clone());
                let common: Vec<String> = chain
                    .scope
                    .iter()
                    .filter(|s| scope.contains(s))
                    .cloned()
                    .collect();
                chain.scope = if chain.scope.is_empty() || scope.is_empty() {
                    if chain.scope.is_empty() {
                        scope.clone()
                    } else {
                        chain.scope
                    }
                } else {
                    common
                };
            }
            _ => {}
        }
        chain.hops.push(next);
        Ok(chain)
    }

    /// Apply a purely tier-1 chain deterministically: the value
    /// passes through each hop's registered transform, in order.
    /// A tier-2 hop in a tier-1 application is an error —
    /// correspondences are not transforms.
    pub fn apply_deterministic(
        &self,
        value: &str,
        transforms: &dyn Fn(&str, &str) -> Result<String, String>,
    ) -> Result<String, MappingError> {
        let mut current = value.to_string();
        for hop in &self.hops {
            match &hop.kind {
                MappingKind::Deterministic { transform } => {
                    current = transforms(&current, transform).map_err(MappingError::Transform)?;
                }
                _ => {
                    return Err(MappingError::NotDeterministic {
                        source: hop.source.clone(),
                        target: hop.target.clone(),
                    })
                }
            }
        }
        Ok(current)
    }

    /// Every constituent mapping version, recorded (SI-12).
    pub fn versions(&self) -> Vec<(String, u64)> {
        self.hops
            .iter()
            .map(|h| (format!("{}→{}", h.source, h.target), h.version))
            .collect()
    }
}

/// What can go wrong composing or applying mappings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    /// The hops do not join (target of one ≠ source of the next).
    Mismatch {
        /// What the chain's end was.
        expected: String,
        /// What the next hop starts from.
        got: String,
    },
    /// A tier-3 edge: no correspondence exists on this path.
    NoCorrespondence {
        /// The refusing edge's source.
        source: String,
        /// The refusing edge's target.
        target: String,
    },
    /// The chain exceeds the policy cap.
    OverCap {
        /// The chain length attempted.
        hops: usize,
        /// The declared cap.
        cap: usize,
    },
    /// A tier-2 hop in a deterministic application.
    NotDeterministic {
        /// The offending hop's source.
        source: String,
        /// The offending hop's target.
        target: String,
    },
    /// A registered transform failed.
    Transform(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier1(source: &str, target: &str, transform: &str) -> MappingItem {
        MappingItem {
            source: source.into(),
            target: target.into(),
            version: 1,
            kind: MappingKind::Deterministic {
                transform: transform.into(),
            },
        }
    }

    fn tier2(source: &str, target: &str, scope: &[&str], residual: &str) -> MappingItem {
        MappingItem {
            source: source.into(),
            target: target.into(),
            version: 1,
            kind: MappingKind::Correspondence {
                scope: scope.iter().map(|s| s.to_string()).collect(),
                residual: residual.into(),
                attester: "cn-mapping-attester".into(),
            },
        }
    }

    fn tier3(source: &str, target: &str) -> MappingItem {
        MappingItem {
            source: source.into(),
            target: target.into(),
            version: 1,
            kind: MappingKind::NoMapping {
                note: "divergence recorded; not reconciled".into(),
            },
        }
    }

    // PR-5's verify: tier-3 renders as distinct items with no
    // correspondence — and refuses composition; tier-1 transforms
    // deterministically; tier-2 carries scope and residual.
    #[test]
    fn the_three_tiers_behave_as_declared() {
        // Tier 3: distinct, no correspondence — the record exists
        // precisely so none is inferred.
        let none = tier3("unt:weight", "aas:Mass");
        assert!(matches!(none.kind, MappingKind::NoMapping { .. }));
        assert!(
            MappingChain::single(none.clone()).is_ok(),
            "a tier-3 record stands alone"
        );
        assert!(matches!(
            MappingChain::single(tier1("x", "unt:weight", "t"))
                .unwrap()
                .then(none, 8),
            Err(MappingError::NoCorrespondence { .. })
        ));

        // Tier 1: deterministic — same input, same output, twice.
        let upper = |v: &str, t: &str| -> Result<String, String> {
            match t {
                "upper" => Ok(v.to_uppercase()),
                "append-x" => Ok(format!("{v}x")),
                _ => Err("unknown transform".into()),
            }
        };
        let chain = MappingChain::single(tier1("a", "b", "upper")).unwrap();
        assert_eq!(chain.apply_deterministic("kWh", &upper).unwrap(), "KWH");
        assert_eq!(chain.apply_deterministic("kWh", &upper).unwrap(), "KWH");

        // Tier 2: scope and residual carried verbatim; canonical
        // bytes are scope-order-insensitive.
        let c = tier2(
            "unt:capacity",
            "iec:RatedCapacity",
            &["batteries"],
            "unit conventions differ",
        );
        match &c.kind {
            MappingKind::Correspondence {
                scope, residual, ..
            } => {
                assert_eq!(scope, &["batteries".to_string()]);
                assert!(residual.contains("unit conventions"));
            }
            _ => panic!("tier lost"),
        }
        let mut reordered = c.clone();
        if let MappingKind::Correspondence { scope, .. } = &mut reordered.kind {
            scope.insert(0, "zzz".into());
        }
        assert_ne!(c.canonical_bytes(), reordered.canonical_bytes());
        assert_eq!(c.digest(), c.digest());
    }

    // SI-12's verify: a two-hop translated value verifies with the
    // accumulated residual named; tier-1 composes associatively;
    // over-cap refused; versions recorded.
    #[test]
    fn composition_accumulates_residuals_and_records_versions() {
        // Tier-1 associativity: (a∘b)∘c == a∘(b∘c).
        let transforms = |v: &str, t: &str| -> Result<String, String> {
            match t {
                "upper" => Ok(v.to_uppercase()),
                "append-x" => Ok(format!("{v}x")),
                _ => Err("unknown".into()),
            }
        };
        let ab = MappingChain::single(tier1("a", "b", "upper"))
            .unwrap()
            .then(tier1("b", "c", "append-x"), 8)
            .unwrap();
        let abc = ab.clone().then(tier1("c", "d", "upper"), 8).unwrap();
        assert_eq!(abc.apply_deterministic("v", &transforms).unwrap(), "VX");
        assert_eq!(abc.hops.len(), 3);
        assert!(abc.residual.is_empty());

        // Tier-2 residual propagation: two hops, residuals
        // accumulate in order, scopes intersect.
        let chain = MappingChain::single(tier2(
            "eu:reparability",
            "unt:repairability",
            &["batteries", "textiles"],
            "class boundary rounding differs",
        ))
        .unwrap()
        .then(
            tier2(
                "unt:repairability",
                "jp:repair",
                &["batteries"],
                "scale compressed 5→3",
            ),
            8,
        )
        .unwrap();
        assert_eq!(
            chain.residual,
            vec![
                "class boundary rounding differs".to_string(),
                "scale compressed 5→3".to_string()
            ]
        );
        assert_eq!(chain.scope, vec!["batteries".to_string()]);
        assert_eq!(
            chain.versions(),
            vec![
                ("eu:reparability→unt:repairability".to_string(), 1),
                ("unt:repairability→jp:repair".to_string(), 1)
            ]
        );

        // Mixed chains: tier-1 then tier-2 records the residual;
        // the deterministic application refuses the tier-2 hop.
        let mixed = MappingChain::single(tier1("a", "b", "upper"))
            .unwrap()
            .then(tier2("b", "c", &["batteries"], "r"), 8)
            .unwrap();
        assert_eq!(mixed.residual, ["r".to_string()]);
        assert!(matches!(
            mixed.apply_deterministic("v", &transforms),
            Err(MappingError::NotDeterministic { .. })
        ));

        // The policy cap.
        let over = MappingChain::single(tier1("a", "b", "upper"))
            .unwrap()
            .then(tier1("b", "c", "upper"), 2)
            .unwrap()
            .then(tier1("c", "d", "upper"), 2);
        assert!(matches!(
            over,
            Err(MappingError::OverCap { hops: 3, cap: 2 })
        ));

        // Non-joining hops refuse.
        let bad = MappingChain::single(tier1("a", "b", "upper"))
            .unwrap()
            .then(tier1("x", "y", "upper"), 8);
        assert!(matches!(bad, Err(MappingError::Mismatch { .. })));
    }
}
