//! Combine / transformation (N -> 1): input references, mass balance,
//! taint and stamp-context inheritance.
//!
//! The output passport's issuance event carries `inputReferences`
//! [(passport, quantity, as-of-state hash)...]. Output quantities are new
//! measured facts ("computed by transformation event E"), never copies.
//! Mass balance: in - out = loss, auditable. Inputs transition to
//! consumed/transformed — historical, still verifiable, still needed for
//! as-of queries.

use std::collections::BTreeMap;

use unidpp_model::{Decimal, Hash, PassportId, Timestamp};

use crate::quantity::{Quantity, UnitRegistry};
use crate::taint::TaintSet;
use crate::TransformError;

/// One input of a transformation: passport, quantity taken, and the
/// as-of state hash of that passport at reference time (Git-merge
/// topology: the new passport hash-links its sources).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InputReference {
    pub input: PassportId,
    pub quantity: Quantity,
    pub as_of_state_hash: Hash,
}

/// Stamp quantity context ("verified 500 g of A at T") inherited by
/// downstream transformations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StampContextRef {
    pub attester: String,
    pub quantity: Quantity,
    pub as_of: Timestamp,
}

/// Combine specification.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CombineSpec {
    pub output: PassportId,
    /// The new measured fact produced by the transformation.
    pub output_quantity: Quantity,
    pub inputs: Vec<InputReference>,
    /// As-of available quantity per input passport (the caller's view of
    /// the world at reference time).
    pub available: BTreeMap<PassportId, Quantity>,
    /// Stamp contexts attached to the inputs, inherited by the output.
    pub stamp_contexts: Vec<StampContextRef>,
}

/// Combine outcome.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CombineOutcome {
    pub output: PassportId,
    pub output_quantity: Quantity,
    pub total_in: Quantity,
    /// in - out; must be >= 0 (auditable process loss).
    pub loss: Quantity,
    /// Inputs that transition to consumed/transformed.
    pub consumed: Vec<(PassportId, Quantity)>,
    /// Inherited stamp contexts.
    pub inherited_stamp_contexts: Vec<StampContextRef>,
}

/// Execute a combine. Checks per-input availability, dimension
/// consistency, and the mass balance (negative loss is an error).
pub fn combine(
    spec: &CombineSpec,
    registry: &UnitRegistry,
) -> Result<CombineOutcome, TransformError> {
    if spec.inputs.is_empty() {
        return Err(TransformError::Empty(
            "combine needs at least one input".into(),
        ));
    }
    let zero = Decimal::zero();
    for input in &spec.inputs {
        if input.quantity.amount.is_negative() {
            return Err(TransformError::OverConsumption {
                input: input.input.clone(),
                requested: input.quantity.amount,
                available: zero,
            });
        }
        if !spec
            .output_quantity
            .same_dimension(&input.quantity, registry)?
        {
            return Err(TransformError::DimensionMismatch {
                left: spec.output_quantity.unit.uom.clone(),
                right: input.quantity.unit.uom.clone(),
            });
        }
        match spec.available.get(&input.input) {
            None => {
                return Err(TransformError::OverConsumption {
                    input: input.input.clone(),
                    requested: input.quantity.canonical_amount(registry)?,
                    available: zero,
                })
            }
            Some(available) => {
                let avail_canonical = available.canonical_amount(registry)?;
                let req_canonical = input.quantity.canonical_amount(registry)?;
                if req_canonical > avail_canonical {
                    return Err(TransformError::OverConsumption {
                        input: input.input.clone(),
                        requested: req_canonical,
                        available: avail_canonical,
                    });
                }
            }
        }
    }
    let input_refs: Vec<&Quantity> = spec.inputs.iter().map(|i| &i.quantity).collect();
    let total_in = Quantity::sum(input_refs, registry)?;
    let out_canonical = spec.output_quantity.canonical_amount(registry)?;
    let in_canonical = total_in.canonical_amount(registry)?;
    if out_canonical > in_canonical {
        return Err(TransformError::NegativeBalance {
            total_in: in_canonical,
            output: out_canonical,
        });
    }
    let loss_canonical = in_canonical
        .sub(&out_canonical)
        .map_err(TransformError::Model)?;
    let loss = Quantity::from_canonical(loss_canonical, &spec.output_quantity.unit, registry)?;
    Ok(CombineOutcome {
        output: spec.output.clone(),
        output_quantity: spec.output_quantity.clone(),
        total_in,
        loss,
        consumed: spec
            .inputs
            .iter()
            .map(|i| (i.input.clone(), i.quantity.clone()))
            .collect(),
        inherited_stamp_contexts: spec.stamp_contexts.clone(),
    })
}

/// Union of taints carried by the inputs (mass-balance accounting must
/// carry taint explicitly).
pub fn inherit_taints(
    inputs: &[InputReference],
    taint_index: &BTreeMap<PassportId, TaintSet>,
) -> TaintSet {
    let mut out = TaintSet::new();
    for input in inputs {
        if let Some(t) = taint_index.get(&input.input) {
            out.merge(t);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u64) -> PassportId {
        PassportId::new(&format!("urn:unidpp:passport:p{n}")).unwrap()
    }

    fn spec(reg: &UnitRegistry) -> CombineSpec {
        let mut available = BTreeMap::new();
        available.insert(pid(1), Quantity::parse("10", "kg", reg).unwrap());
        available.insert(pid(2), Quantity::parse("0.5", "t", reg).unwrap());
        CombineSpec {
            output: pid(9),
            output_quantity: Quantity::parse("440", "kg", reg).unwrap(),
            inputs: vec![
                InputReference {
                    input: pid(1),
                    quantity: Quantity::parse("10", "kg", reg).unwrap(),
                    as_of_state_hash: Hash::ZERO,
                },
                InputReference {
                    input: pid(2),
                    quantity: Quantity::parse("0.5", "t", reg).unwrap(),
                    as_of_state_hash: Hash::ZERO,
                },
            ],
            available,
            stamp_contexts: vec![StampContextRef {
                attester: "verifier.example".into(),
                quantity: Quantity::parse("10", "kg", reg).unwrap(),
                as_of: Timestamp::from_secs(1_800_000_000),
            }],
        }
    }

    #[test]
    fn mass_balance_in_minus_out_is_loss() {
        let reg = UnitRegistry::iso80000();
        let out = combine(&spec(&reg), &reg).unwrap();
        assert_eq!(out.total_in.convert_to(&reg.unit("kg").unwrap(), &reg).unwrap().amount, "510".parse::<Decimal>().unwrap());
        assert_eq!(out.loss.amount, "70".parse::<Decimal>().unwrap());
        assert_eq!(out.consumed.len(), 2);
        assert_eq!(out.inherited_stamp_contexts.len(), 1);
    }

    #[test]
    fn negative_balance_rejected() {
        let reg = UnitRegistry::iso80000();
        let mut s = spec(&reg);
        s.output_quantity = Quantity::parse("511", "kg", &reg).unwrap();
        assert!(matches!(
            combine(&s, &reg),
            Err(TransformError::NegativeBalance { .. })
        ));
    }

    #[test]
    fn over_consumption_rejected() {
        let reg = UnitRegistry::iso80000();
        let mut s = spec(&reg);
        s.inputs[0].quantity = Quantity::parse("10.001", "kg", &reg).unwrap();
        assert!(matches!(
            combine(&s, &reg),
            Err(TransformError::OverConsumption { .. })
        ));
    }

    #[test]
    fn missing_availability_rejected() {
        let reg = UnitRegistry::iso80000();
        let mut s = spec(&reg);
        s.available.remove(&pid(1));
        assert!(matches!(
            combine(&s, &reg),
            Err(TransformError::OverConsumption { .. })
        ));
    }

    #[test]
    fn exact_combine_has_no_loss() {
        let reg = UnitRegistry::iso80000();
        let mut s = spec(&reg);
        s.output_quantity = Quantity::parse("510", "kg", &reg).unwrap();
        let out = combine(&s, &reg).unwrap();
        assert!(out.loss.is_zero());
    }
}
