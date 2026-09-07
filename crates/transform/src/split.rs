//! Split (1 -> N): quantity carve-outs with remainder semantics.
//!
//! Recorded in the parent's log by its custodian; children are new
//! passports with `derivedFrom` + carve-outs. Invariant:
//! sum(children) <= parent — the parent keeps the remainder.

use unidpp_model::{Decimal, PassportId};

use crate::quantity::{Quantity, UnitRegistry};
use crate::TransformError;

/// One child's carve-out.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CarveOut {
    pub child: PassportId,
    pub quantity: Quantity,
}

/// Split specification: parent + available quantity + carve-outs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SplitSpec {
    pub parent: PassportId,
    pub parent_available: Quantity,
    pub carve_outs: Vec<CarveOut>,
}

/// Split outcome: children (unchanged), the remainder left with the
/// parent, and whether the parent is fully consumed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SplitOutcome {
    pub carve_outs: Vec<CarveOut>,
    pub remainder: Quantity,
    /// sum(children) == parent: the parent transitions to
    /// consumed/transformed (historical, still verifiable).
    pub parent_consumed: bool,
}

/// Execute a split. Errors on dimension mismatch, negative carve-outs, or
/// over-carve (sum(children) > parent).
pub fn split(spec: &SplitSpec, registry: &UnitRegistry) -> Result<SplitOutcome, TransformError> {
    if spec.carve_outs.is_empty() {
        return Err(TransformError::Empty(
            "split needs at least one carve-out".into(),
        ));
    }
    let parent_canonical = spec.parent_available.canonical_amount(registry)?;
    let mut total = Decimal::zero();
    for carve in &spec.carve_outs {
        if carve.quantity.amount.is_negative() {
            return Err(TransformError::OverCarve {
                requested: carve.quantity.amount,
                available: parent_canonical,
            });
        }
        if !spec
            .parent_available
            .same_dimension(&carve.quantity, registry)?
        {
            return Err(TransformError::DimensionMismatch {
                left: spec.parent_available.unit.uom.clone(),
                right: carve.quantity.unit.uom.clone(),
            });
        }
        total = total
            .add(&carve.quantity.canonical_amount(registry)?)
            .map_err(TransformError::Model)?;
    }
    if total > parent_canonical {
        return Err(TransformError::OverCarve {
            requested: total,
            available: parent_canonical,
        });
    }
    let remainder_canonical = parent_canonical
        .sub(&total)
        .map_err(TransformError::Model)?;
    // Express the remainder in the parent's own unit (exact conversion).
    let remainder = Quantity::from_canonical(remainder_canonical, &spec.parent_available.unit, registry)?;
    let parent_consumed = remainder.is_zero();
    Ok(SplitOutcome {
        carve_outs: spec.carve_outs.clone(),
        remainder,
        parent_consumed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u64) -> PassportId {
        PassportId::new(&format!("urn:unidpp:passport:p{n}")).unwrap()
    }

    #[test]
    fn remainder_semantics() {
        let reg = UnitRegistry::iso80000();
        let spec = SplitSpec {
            parent: pid(0),
            parent_available: Quantity::parse("10", "kg", &reg).unwrap(),
            carve_outs: vec![
                CarveOut {
                    child: pid(1),
                    quantity: Quantity::parse("3", "kg", &reg).unwrap(),
                },
                CarveOut {
                    child: pid(2),
                    quantity: Quantity::parse("2500", "g", &reg).unwrap(),
                },
            ],
        };
        let out = split(&spec, &reg).unwrap();
        assert_eq!(out.remainder.amount, "4.5".parse::<Decimal>().unwrap());
        assert!(!out.parent_consumed);
    }

    #[test]
    fn over_carve_rejected() {
        let reg = UnitRegistry::iso80000();
        let spec = SplitSpec {
            parent: pid(0),
            parent_available: Quantity::parse("10", "kg", &reg).unwrap(),
            carve_outs: vec![CarveOut {
                child: pid(1),
                quantity: Quantity::parse("10001", "g", &reg).unwrap(),
            }],
        };
        assert!(matches!(
            split(&spec, &reg),
            Err(TransformError::OverCarve { .. })
        ));
    }

    #[test]
    fn exact_split_consumes_parent() {
        let reg = UnitRegistry::iso80000();
        let spec = SplitSpec {
            parent: pid(0),
            parent_available: Quantity::parse("1", "t", &reg).unwrap(),
            carve_outs: vec![
                CarveOut {
                    child: pid(1),
                    quantity: Quantity::parse("300", "kg", &reg).unwrap(),
                },
                CarveOut {
                    child: pid(2),
                    quantity: Quantity::parse("0.7", "t", &reg).unwrap(),
                },
            ],
        };
        let out = split(&spec, &reg).unwrap();
        assert!(out.parent_consumed);
        assert!(out.remainder.is_zero());
    }

    #[test]
    fn dimension_mismatch_rejected() {
        let reg = UnitRegistry::iso80000();
        let spec = SplitSpec {
            parent: pid(0),
            parent_available: Quantity::parse("10", "kg", &reg).unwrap(),
            carve_outs: vec![CarveOut {
                child: pid(1),
                quantity: Quantity::parse("3", "kWh", &reg).unwrap(),
            }],
        };
        assert!(matches!(
            split(&spec, &reg),
            Err(TransformError::DimensionMismatch { .. })
        ));
    }
}
