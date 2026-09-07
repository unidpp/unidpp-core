//! Property: quantity conservation on random split/combine chains.
//!
//! For every chain of valid transformations, in every registered unit of
//! the mass dimension: total issued == sum(live quantities) + total loss.
//! Exact decimal arithmetic; random unit mixing exercises the conversion
//! factors.

use unidpp_model::{Decimal, PassportId};
use unidpp_transform::{
    combine, split, CarveOut, CombineSpec, InputReference, Quantity, Rng, SplitSpec,
    StampContextRef, UnitRegistry,
};

fn pid(n: u64) -> PassportId {
    PassportId::new(&format!("urn:unidpp:passport:p{n:04}")).unwrap()
}

/// Canonical amounts are carried as integer micro-kg (10^-6 kg).
fn micro(m: i128) -> Decimal {
    Decimal::new(m, -6).unwrap()
}

fn canonical_micro(q: &Quantity, reg: &UnitRegistry) -> i128 {
    let c = q.canonical_amount(reg).unwrap();
    // Exactly representable as micro-kg: assert the scale.
    let scaled = c.mul_ratio_exact(1_000_000, 1).unwrap();
    assert!(scaled.exp >= 0, "amount lost precision: {c}");
    scaled.mant * 10i128.pow(scaled.exp as u32)
}

fn qty_in_random_unit(micro_kg: i128, rng: &mut Rng, reg: &UnitRegistry) -> Quantity {
    let units = ["kg", "g", "t"];
    let uom = *rng.pick(&units).unwrap();
    Quantity::from_canonical(micro(micro_kg), &reg.unit(uom).unwrap(), reg).unwrap()
}

#[test]
fn quantity_conserved_across_random_split_combine_chains() {
    let reg = UnitRegistry::iso80000();
    for seed in 1..=25u64 {
        let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut next = 0u64;
        let mut live: Vec<(PassportId, i128)> = Vec::new();
        let mut total_issued: i128 = 0;
        let mut total_loss: i128 = 0;

        // Issue the root.
        let root_micro = rng.range(1, 5_000_000_000) as i128;
        let root = pid(next);
        next += 1;
        live.push((root, root_micro));
        total_issued += root_micro;
        assert_eq!(
            total_issued,
            live.iter().map(|(_, q)| q).sum::<i128>() + total_loss
        );

        for _step in 0..15 {
            match rng.range(0, 2) {
                0 => {
                    // ---- split ----
                    let candidates: Vec<usize> = live
                        .iter()
                        .enumerate()
                        .filter(|(_, (_, q))| *q > 0)
                        .map(|(i, _)| i)
                        .collect();
                    if candidates.is_empty() {
                        continue;
                    }
                    let idx = *rng.pick(&candidates).unwrap();
                    let (parent, parent_micro) = live[idx].clone();
                    let n = rng.range(1, 5) as usize;
                    let mut budget = parent_micro;
                    let mut carve_micros = Vec::new();
                    for _ in 0..n {
                        let amt = if budget == 0 {
                            0
                        } else {
                            rng.range(0, budget.min(1_000_000_000) as u64) as i128
                        };
                        carve_micros.push(amt);
                        budget -= amt;
                    }
                    let carve_outs: Vec<CarveOut> = carve_micros
                        .iter()
                        .map(|&m| {
                            let child = pid(next);
                            next += 1;
                            CarveOut {
                                child,
                                quantity: qty_in_random_unit(m, &mut rng, &reg),
                            }
                        })
                        .collect();
                    let spec = SplitSpec {
                        parent: parent.clone(),
                        parent_available: qty_in_random_unit(parent_micro, &mut rng, &reg),
                        carve_outs,
                    };
                    let outcome = split(&spec, &reg).expect("valid split must succeed");
                    let sum_children: i128 = carve_micros.iter().sum();
                    assert!(sum_children <= parent_micro);
                    let remainder_micro = canonical_micro(&outcome.remainder, &reg);
                    assert_eq!(remainder_micro, parent_micro - sum_children);
                    assert_eq!(outcome.parent_consumed, remainder_micro == 0);
                    live[idx].1 = remainder_micro;
                    for (i, m) in carve_micros.iter().enumerate() {
                        if *m > 0 {
                            live.push((spec.carve_outs[i].child.clone(), *m));
                        }
                    }
                    // Over-carve must be rejected (negative test).
                    if parent_micro >= 0 {
                        let bad = SplitSpec {
                            parent: parent.clone(),
                            parent_available: qty_in_random_unit(parent_micro, &mut rng, &reg),
                            carve_outs: vec![CarveOut {
                                child: pid(next),
                                quantity: qty_in_random_unit(parent_micro + 1, &mut rng, &reg),
                            }],
                        };
                        assert!(
                            split(&bad, &reg).is_err(),
                            "over-carve must be rejected (seed {seed})"
                        );
                        next += 1;
                    }
                }
                _ => {
                    // ---- combine ----
                    let candidates: Vec<usize> = live
                        .iter()
                        .enumerate()
                        .filter(|(_, (_, q))| *q > 0)
                        .map(|(i, _)| i)
                        .collect();
                    if candidates.is_empty() {
                        continue;
                    }
                    let k = rng.range(1, (candidates.len() as u64).min(4) + 1) as usize;
                    let mut chosen: Vec<usize> = Vec::new();
                    for ci in &candidates {
                        if chosen.len() == k {
                            break;
                        }
                        if rng.bool() || candidates.len() == 1 {
                            chosen.push(*ci);
                        }
                    }
                    if chosen.is_empty() {
                        chosen.push(candidates[0]);
                    }
                    let mut inputs = Vec::new();
                    let mut take_micros = Vec::new();
                    for &ci in &chosen {
                        let take = rng.range(0, live[ci].1 as u64) as i128;
                        take_micros.push(take);
                        inputs.push(InputReference {
                            input: live[ci].0.clone(),
                            quantity: qty_in_random_unit(take, &mut rng, &reg),
                            as_of_state_hash: unidpp_model::Hash::ZERO,
                        });
                    }
                    let sum_in: i128 = take_micros.iter().sum();
                    let out_micro = if sum_in == 0 {
                        0
                    } else {
                        rng.range(0, sum_in as u64) as i128
                    };
                    let output = pid(next);
                    next += 1;
                    let mut available = std::collections::BTreeMap::new();
                    for &ci in &chosen {
                        available.insert(
                            live[ci].0.clone(),
                            qty_in_random_unit(live[ci].1, &mut rng, &reg),
                        );
                    }
                    let spec = CombineSpec {
                        output: output.clone(),
                        output_quantity: qty_in_random_unit(out_micro, &mut rng, &reg),
                        inputs,
                        available,
                        stamp_contexts: vec![StampContextRef {
                            attester: "verifier.example".into(),
                            quantity: qty_in_random_unit(take_micros[0], &mut rng, &reg),
                            as_of: unidpp_model::Timestamp::from_secs(1),
                        }],
                    };
                    let outcome = combine(&spec, &reg).expect("valid combine must succeed");
                    let loss_micro = canonical_micro(&outcome.loss, &reg);
                    assert_eq!(loss_micro, sum_in - out_micro);
                    for (&ci, &take) in chosen.iter().zip(take_micros.iter()) {
                        live[ci].1 -= take;
                    }
                    if out_micro > 0 {
                        live.push((output, out_micro));
                    }
                    total_loss += loss_micro;
                }
            }
            // Global conservation invariant (exact integer micro-kg).
            let live_sum: i128 = live.iter().map(|(_, q)| q).sum();
            assert_eq!(
                total_issued,
                live_sum + total_loss,
                "conservation broken (seed {seed})"
            );
        }
    }
}
