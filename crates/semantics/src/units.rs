//! The units and measurement chain (UN-1/2/3): canonical units,
//! GUM uncertainty propagation, and ILAC-G8 decision rules.
//!
//! Measured values are stored in canonical units only — the unit a
//! quantity kind is registered under (the ISO 80000 / UnitsDB
//! choice per kind); a non-canonical unit is refused at intake with
//! the registered conversion offered. Every measured value carries
//! GUM uncertainty; transforms propagate it by the linear rule
//! (u(c·x) = |c|·u(x); independent terms combine in quadrature);
//! derived values without uncertainty are refused. Classification
//! thresholds declare their conformity decision rule — shared-risk
//! or guard-banded (ILAC-G8) — and a boundary measurement
//! classifies differently under the two rules, both correctly.

// NOTE: units errors are Validation-shaped; define locally to keep the
// crate free of trust-layer dependencies.
use std::fmt;

/// A units-chain error (intake refusal, propagation mismatch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitsError(pub String);

impl fmt::Display for UnitsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UnitsError {}

use std::collections::BTreeMap;

/// The canonical-unit table: which unit is canonical per quantity
/// kind, and the registered conversion for known non-canonical
/// units (value × factor + offset).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UnitTable {
    /// quantity kind → canonical unit symbol.
    pub canonical: BTreeMap<String, String>,
    /// non-canonical unit → (canonical unit, factor, offset):
    /// value_in_canonical = value × factor + offset.
    pub conversions: BTreeMap<String, (String, f64, f64)>,
}

impl UnitTable {
    /// The seeded reference table (the corpus's quantity kinds).
    pub fn seeded() -> UnitTable {
        let mut table = UnitTable::default();
        for (kind, unit) in [
            ("energy", "kWh"),
            ("mass", "kg"),
            ("length", "m"),
            ("power", "W"),
            ("capacity", "Ah"),
        ] {
            table.canonical.insert(kind.into(), unit.into());
        }
        for (from, (to, factor, offset)) in [
            ("Wh", ("kWh", 0.001, 0.0)),
            ("MWh", ("kWh", 1000.0, 0.0)),
            ("g", ("kg", 0.001, 0.0)),
            ("t", ("kg", 1000.0, 0.0)),
            ("cm", ("m", 0.01, 0.0)),
            ("mm", ("m", 0.001, 0.0)),
            ("kW", ("W", 1000.0, 0.0)),
            ("mWh", ("Wh", 0.001, 0.0)),
        ] {
            table
                .conversions
                .insert(from.into(), (to.into(), factor, offset));
        }
        table
    }
}

/// A measured value as offered at intake: magnitude + unit.
#[derive(Debug, Clone, PartialEq)]
pub struct OfferedValue {
    /// The magnitude.
    pub value: f64,
    /// The unit as offered.
    pub unit: String,
}

/// A stored measured value: canonical unit, uncertainty included.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MeasuredValue {
    /// The magnitude in the canonical unit.
    pub value: f64,
    /// The canonical unit symbol.
    pub unit: String,
    /// The GUM standard uncertainty (same unit).
    pub uncertainty: f64,
}

/// Intake (UN-1): accept the value only in the canonical unit for
/// its quantity kind; a non-canonical unit is refused with the
/// registered conversion offered (the caller may then apply it — a
/// registered transform — and re-offer).
pub fn intake(
    table: &UnitTable,
    kind: &str,
    offered: OfferedValue,
    uncertainty: Option<f64>,
) -> Result<MeasuredValue, UnitsError> {
    let canonical = table
        .canonical
        .get(kind)
        .ok_or_else(|| UnitsError(format!("unknown quantity kind `{kind}`")))?;
    let uncertainty = uncertainty.ok_or_else(|| {
        UnitsError(
            "measured values carry GUM uncertainty — a derived value without uncertainty is refused".into(),
        )
    })?;
    if &offered.unit == canonical {
        return Ok(MeasuredValue {
            value: offered.value,
            unit: offered.unit,
            uncertainty,
        });
    }
    match table.conversions.get(&offered.unit) {
        Some((to, factor, _)) if to == canonical => Err(UnitsError(format!(
            "unit `{}` is not canonical for `{}` — apply the registered conversion \
             (× {factor}, to `{to}`) and re-offer",
            offered.unit, kind
        ))),
        Some((to, _, _)) => Err(UnitsError(format!(
            "unit `{}` converts to `{to}`, which is not the canonical unit `{canonical}` \
             for `{}`",
            offered.unit, kind
        ))),
        None => Err(UnitsError(format!(
            "unit `{}` has no registered conversion — it is not admissible for `{}`",
            offered.unit, kind
        ))),
    }
}

/// Apply a registered conversion (intake's offered path): the value
/// converts, and the uncertainty scales by the same factor.
pub fn convert(
    table: &UnitTable,
    offered: OfferedValue,
    uncertainty: f64,
) -> Result<MeasuredValue, UnitsError> {
    let (to, factor, offset) = table
        .conversions
        .get(&offered.unit)
        .ok_or_else(|| UnitsError(format!("no registered conversion from `{}`", offered.unit)))?;
    Ok(MeasuredValue {
        value: offered.value * factor + offset,
        unit: to.clone(),
        uncertainty: uncertainty * factor.abs(),
    })
}

/// GUM propagation (UN-2) over the arithmetic the transforms use:
/// scale (u·|c|) and the sum/difference of INDEPENDENT terms
/// (quadrature).
pub mod propagate {
    use super::MeasuredValue;

    /// Scale a value by a constant: u(c·x) = |c|·u(x).
    pub fn scale(value: &MeasuredValue, factor: f64) -> MeasuredValue {
        MeasuredValue {
            value: value.value * factor,
            unit: value.unit.clone(),
            uncertainty: value.uncertainty * factor.abs(),
        }
    }

    /// Sum of independent values (quadrature). Units must agree.
    pub fn sum(a: &MeasuredValue, b: &MeasuredValue) -> Result<MeasuredValue, String> {
        if a.unit != b.unit {
            return Err(format!("unit mismatch: {} vs {}", a.unit, b.unit));
        }
        Ok(MeasuredValue {
            value: a.value + b.value,
            unit: a.unit.clone(),
            uncertainty: (a.uncertainty.powi(2) + b.uncertainty.powi(2)).sqrt(),
        })
    }

    /// Difference of independent values (quadrature).
    pub fn difference(a: &MeasuredValue, b: &MeasuredValue) -> Result<MeasuredValue, String> {
        if a.unit != b.unit {
            return Err(format!("unit mismatch: {} vs {}", a.unit, b.unit));
        }
        Ok(MeasuredValue {
            value: a.value - b.value,
            unit: a.unit.clone(),
            uncertainty: (a.uncertainty.powi(2) + b.uncertainty.powi(2)).sqrt(),
        })
    }
}

/// The conformity decision rule declared by a classification
/// threshold (UN-3, ILAC-G8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionRule {
    /// Shared risk: the measured value alone decides; the
    /// uncertainty is shared between the parties.
    SharedRisk,
    /// Guard-banded: conformity requires the value minus (or plus)
    /// the expanded margin to be inside the limit — nonconformity
    /// requires it outside by the margin.
    GuardBanded {
        /// The guard-band factor k (typically 1 or 2).
        k: u8,
    },
}

impl DecisionRule {
    pub fn token(&self) -> &'static str {
        match self {
            DecisionRule::SharedRisk => "shared-risk",
            DecisionRule::GuardBanded { .. } => "guard-banded",
        }
    }
}

/// The classification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conformity {
    /// Inside the limit under the rule.
    Conforms,
    /// Outside under the rule.
    DoesNotConform,
    /// Guard-banded only: neither side is established at this
    /// margin — the result is inconclusive, stated.
    Inconclusive,
}

/// Classify an upper-bounded limit (value ≤ limit) under the
/// declared rule.
pub fn classify_upper(rule: DecisionRule, value: &MeasuredValue, limit: f64) -> Conformity {
    match rule {
        DecisionRule::SharedRisk => {
            if value.value <= limit {
                Conformity::Conforms
            } else {
                Conformity::DoesNotConform
            }
        }
        DecisionRule::GuardBanded { k } => {
            let margin = value.uncertainty * f64::from(k);
            if value.value + margin <= limit {
                Conformity::Conforms
            } else if value.value - margin > limit {
                Conformity::DoesNotConform
            } else {
                Conformity::Inconclusive
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // UN-1: a non-canonical unit is refused at intake with the
    // registered conversion offered; the converted value is
    // admissible; unknown units are stated.
    #[test]
    fn non_canonical_units_are_refused_with_the_conversion_offered() {
        let table = UnitTable::seeded();
        // Canonical: accepted, uncertainty included.
        let ok = intake(
            &table,
            "energy",
            OfferedValue {
                value: 52.0,
                unit: "kWh".into(),
            },
            Some(0.5),
        )
        .unwrap();
        assert_eq!(ok.unit, "kWh");
        assert_eq!(ok.uncertainty, 0.5);

        // Non-canonical: refused, the conversion named.
        let err = intake(
            &table,
            "energy",
            OfferedValue {
                value: 52000.0,
                unit: "Wh".into(),
            },
            Some(5.0),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Wh") && err.contains("× 0.001"), "{err}");

        // The registered conversion applies — value and
        // uncertainty both scale.
        let converted = convert(
            &table,
            OfferedValue {
                value: 52000.0,
                unit: "Wh".into(),
            },
            5.0,
        )
        .unwrap();
        assert_eq!(converted.value, 52.0);
        assert_eq!(converted.unit, "kWh");
        assert!((converted.uncertainty - 0.005).abs() < 1e-12);

        // No uncertainty: refused (derived values carry GUM).
        let err = intake(
            &table,
            "energy",
            OfferedValue {
                value: 52.0,
                unit: "kWh".into(),
            },
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("uncertainty"), "{err}");

        // Unregistered unit: stated.
        assert!(intake(
            &table,
            "energy",
            OfferedValue {
                value: 1.0,
                unit: "BTU".into()
            },
            Some(0.1)
        )
        .is_err());
    }

    // UN-2: propagation equals the reference computation.
    #[test]
    fn uncertainty_propagates_by_the_linear_rule() {
        let a = MeasuredValue {
            value: 10.0,
            unit: "kg".into(),
            uncertainty: 0.1,
        };
        let b = MeasuredValue {
            value: 14.2,
            unit: "kg".into(),
            uncertainty: 0.2,
        };
        // Scale: u(c·x) = |c|·u(x).
        let scaled = propagate::scale(&a, 2.5);
        assert_eq!(scaled.value, 25.0);
        assert!((scaled.uncertainty - 0.25).abs() < 1e-12);
        // Sum (independent): quadrature.
        let sum = propagate::sum(&a, &b).unwrap();
        assert!((sum.value - 24.2).abs() < 1e-12);
        assert!((sum.uncertainty - (0.01f64 + 0.04).sqrt()).abs() < 1e-12);
        // Difference: quadrature, same.
        let diff = propagate::difference(&b, &a).unwrap();
        assert!((diff.value - 4.2).abs() < 1e-12);
        assert!((diff.uncertainty - sum.uncertainty).abs() < 1e-12);
        // Unit mismatch is stated.
        let c = MeasuredValue {
            value: 1.0,
            unit: "m".into(),
            uncertainty: 0.01,
        };
        assert!(propagate::sum(&a, &c).is_err());
    }

    // UN-3: a boundary measurement classifies differently under the
    // two declared rules — both correctly.
    #[test]
    fn boundary_measurements_classify_per_the_declared_rule() {
        // 10.0 ± 0.2 against limit 10.1.
        let boundary = MeasuredValue {
            value: 10.0,
            unit: "kg".into(),
            uncertainty: 0.2,
        };
        // Shared risk: 10.0 ≤ 10.1 → conforms.
        assert_eq!(
            classify_upper(DecisionRule::SharedRisk, &boundary, 10.1),
            Conformity::Conforms
        );
        // Guard-banded (k=1): 10.0 + 0.2 = 10.2 > 10.1 and
        // 10.0 − 0.2 = 9.8 ≤ 10.1 → inconclusive, stated.
        assert_eq!(
            classify_upper(DecisionRule::GuardBanded { k: 1 }, &boundary, 10.1),
            Conformity::Inconclusive
        );
        // Comfortably inside: both rules conform.
        let clear = MeasuredValue {
            value: 9.0,
            unit: "kg".into(),
            uncertainty: 0.2,
        };
        assert_eq!(
            classify_upper(DecisionRule::SharedRisk, &clear, 10.1),
            Conformity::Conforms
        );
        assert_eq!(
            classify_upper(DecisionRule::GuardBanded { k: 2 }, &clear, 10.1),
            Conformity::Conforms
        );
        // Comfortably outside: both rules do not conform.
        let out = MeasuredValue {
            value: 12.0,
            unit: "kg".into(),
            uncertainty: 0.2,
        };
        assert_eq!(
            classify_upper(DecisionRule::SharedRisk, &out, 10.1),
            Conformity::DoesNotConform
        );
        assert_eq!(
            classify_upper(DecisionRule::GuardBanded { k: 2 }, &out, 10.1),
            Conformity::DoesNotConform
        );
    }
}
