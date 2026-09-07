//! Quantities with registered units (ISO 80000 / UnitsDB-style registry).
//!
//! A unit is a `uom` symbol plus a registry URI; every registered unit
//! carries a dimension and an exact rational factor to the dimension's
//! canonical unit (kWh -> MJ is x 36/10 exactly; kg -> g x 1000). All
//! quantity arithmetic runs through [`Decimal`] so mass balance is exact.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use unidpp_model::{Decimal, ModelError};

use crate::TransformError;

/// Physical dimension of a registered unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dimension {
    Mass,
    Energy,
    Volume,
    Count,
    Dimensionless,
    Custom(String),
}

impl Dimension {
    pub fn as_str(&self) -> String {
        match self {
            Dimension::Mass => "mass".into(),
            Dimension::Energy => "energy".into(),
            Dimension::Volume => "volume".into(),
            Dimension::Count => "count".into(),
            Dimension::Dimensionless => "dimensionless".into(),
            Dimension::Custom(c) => {
                format!("custom:{}", unidpp_model::normalization::normalize_token(c))
            }
        }
    }
}

impl fmt::Display for Dimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl FromStr for Dimension {
    type Err = ModelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match unidpp_model::normalization::squash(s).as_str() {
            "mass" => Ok(Dimension::Mass),
            "energy" => Ok(Dimension::Energy),
            "volume" => Ok(Dimension::Volume),
            "count" => Ok(Dimension::Count),
            "dimensionless" => Ok(Dimension::Dimensionless),
            _ => {
                if let Some(rest) = s
                    .strip_prefix("custom:")
                    .or_else(|| s.strip_prefix("CUSTOM:"))
                {
                    if !rest.trim().is_empty() {
                        return Ok(Dimension::Custom(rest.trim().to_string()));
                    }
                }
                Err(ModelError::Parse(format!("unknown dimension `{s}`")))
            }
        }
    }
}

impl serde::Serialize for Dimension {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Dimension {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        s.parse::<Dimension>().map_err(serde::de::Error::custom)
    }
}

/// A unit: `uom` symbol + registry URI (UnitsML-style).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Unit {
    pub uom: String,
    pub registry_uri: String,
}

impl Unit {
    pub fn new(uom: &str, registry_uri: &str) -> Result<Unit, ModelError> {
        let uom = unidpp_model::normalization::normalize_token(uom);
        if uom.is_empty() {
            return Err(ModelError::Validation("empty uom".into()));
        }
        if registry_uri.trim().is_empty() {
            return Err(ModelError::Validation(format!(
                "unit `{uom}` lacks a registry URI"
            )));
        }
        Ok(Unit {
            uom,
            registry_uri: registry_uri.trim().to_string(),
        })
    }
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} <{}>", self.uom, self.registry_uri)
    }
}

/// A registered unit definition: dimension + exact factor to the
/// dimension's canonical unit (canonical = amount x factor_num/factor_den).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnitDef {
    pub unit: Unit,
    pub dimension: Dimension,
    pub factor_num: i128,
    pub factor_den: i128,
}

/// Registry of units. One definition per (normalized) `uom`; factors are
/// exact rationals.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UnitRegistry {
    defs: Vec<UnitDef>,
    index: BTreeMap<String, usize>,
}

pub const UNITSML: &str = "https://unitsml.org/units";

impl UnitRegistry {
    /// ISO 80000 / UnitsDB seed: mass (kg), energy (J), volume (m3),
    /// count, dimensionless.
    pub fn iso80000() -> UnitRegistry {
        let mut r = UnitRegistry::default();
        let raw: &[(&str, Dimension, i128, i128)] = &[
            ("kg", Dimension::Mass, 1, 1),
            ("g", Dimension::Mass, 1, 1000),
            ("mg", Dimension::Mass, 1, 1_000_000),
            ("t", Dimension::Mass, 1000, 1),
            ("lb", Dimension::Mass, 45_359_237, 100_000_000),
            ("J", Dimension::Energy, 1, 1),
            ("kJ", Dimension::Energy, 1000, 1),
            ("MJ", Dimension::Energy, 1_000_000, 1),
            ("Wh", Dimension::Energy, 3600, 1),
            ("kWh", Dimension::Energy, 3_600_000, 1),
            ("m3", Dimension::Volume, 1, 1),
            ("l", Dimension::Volume, 1, 1000),
            ("ml", Dimension::Volume, 1, 1_000_000),
            ("count", Dimension::Count, 1, 1),
            ("ratio", Dimension::Dimensionless, 1, 1),
            ("percent", Dimension::Dimensionless, 1, 100),
        ];
        for (uom, dim, num, den) in raw {
            r.register(uom, UNITSML, dim.clone(), *num, *den)
                .expect("seed units must register cleanly");
        }
        r
    }

    pub fn register(
        &mut self,
        uom: &str,
        registry_uri: &str,
        dimension: Dimension,
        factor_num: i128,
        factor_den: i128,
    ) -> Result<(), TransformError> {
        if factor_den == 0 {
            return Err(TransformError::Registry(format!(
                "unit `{uom}`: zero denominator"
            )));
        }
        if factor_num < 0 || factor_den < 0 {
            return Err(TransformError::Registry(format!(
                "unit `{uom}`: negative factors are not meaningful"
            )));
        }
        let unit = Unit::new(uom, registry_uri)?;
        let key = unit.uom.clone();
        let def = UnitDef {
            unit,
            dimension,
            factor_num,
            factor_den,
        };
        match self.index.get(&key) {
            Some(&i) => {
                if self.defs[i] == def {
                    Ok(())
                } else {
                    Err(TransformError::Registry(format!(
                        "conflicting redefinition of unit `{key}`"
                    )))
                }
            }
            None => {
                self.defs.push(def);
                self.index.insert(key, self.defs.len() - 1);
                Ok(())
            }
        }
    }

    pub fn lookup(&self, uom: &str) -> Result<&UnitDef, TransformError> {
        let key = unidpp_model::normalization::normalize_token(uom);
        self.index
            .get(&key)
            .map(|&i| &self.defs[i])
            .ok_or(TransformError::UnknownUnit(uom.to_string()))
    }

    pub fn unit(&self, uom: &str) -> Result<Unit, TransformError> {
        Ok(self.lookup(uom)?.unit.clone())
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    pub fn defs(&self) -> &[UnitDef] {
        &self.defs
    }
}

/// A quantity: exact decimal amount in a registered unit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Quantity {
    pub amount: Decimal,
    pub unit: Unit,
}

impl Quantity {
    pub fn new(amount: Decimal, unit: Unit) -> Quantity {
        Quantity { amount, unit }
    }

    pub fn parse(
        amount: &str,
        uom: &str,
        registry: &UnitRegistry,
    ) -> Result<Quantity, TransformError> {
        let amount: Decimal = amount.parse().map_err(TransformError::Model)?;
        let unit = registry.unit(uom)?;
        Ok(Quantity { amount, unit })
    }

    fn lookup_def<'a>(&self, registry: &'a UnitRegistry) -> Result<&'a UnitDef, TransformError> {
        registry.lookup(&self.unit.uom)
    }

    /// Amount expressed in the dimension's canonical unit (exact).
    pub fn canonical_amount(&self, registry: &UnitRegistry) -> Result<Decimal, TransformError> {
        let def = self.lookup_def(registry)?;
        self.amount
            .mul_ratio_exact(def.factor_num, def.factor_den)
            .map_err(TransformError::Model)
    }

    /// Exact conversion to another registered unit of the same dimension.
    pub fn convert_to(
        &self,
        target: &Unit,
        registry: &UnitRegistry,
    ) -> Result<Quantity, TransformError> {
        let tdef = registry.lookup(&target.uom)?;
        let sdef = self.lookup_def(registry)?;
        if sdef.dimension != tdef.dimension {
            return Err(TransformError::DimensionMismatch {
                left: sdef.dimension.to_string(),
                right: tdef.dimension.to_string(),
            });
        }
        let canonical = self.canonical_amount(registry)?;
        let amount = canonical
            .mul_ratio_exact(tdef.factor_den, tdef.factor_num)
            .map_err(TransformError::Model)?;
        Ok(Quantity {
            amount,
            unit: target.clone(),
        })
    }

    pub fn same_dimension(
        &self,
        other: &Quantity,
        registry: &UnitRegistry,
    ) -> Result<bool, TransformError> {
        Ok(self.lookup_def(registry)?.dimension == other.lookup_def(registry)?.dimension)
    }

    /// Build a quantity from a canonical-unit amount (exact conversion).
    pub fn from_canonical(
        canonical: Decimal,
        target: &Unit,
        registry: &UnitRegistry,
    ) -> Result<Quantity, TransformError> {
        let tdef = registry.lookup(&target.uom)?;
        let amount = canonical
            .mul_ratio_exact(tdef.factor_den, tdef.factor_num)
            .map_err(TransformError::Model)?;
        Ok(Quantity {
            amount,
            unit: target.clone(),
        })
    }

    /// Exact sum, expressed in `self`'s unit.
    pub fn add(
        &self,
        other: &Quantity,
        registry: &UnitRegistry,
    ) -> Result<Quantity, TransformError> {
        if !self.same_dimension(other, registry)? {
            let l = self.lookup_def(registry)?;
            let r = other.lookup_def(registry)?;
            return Err(TransformError::DimensionMismatch {
                left: l.dimension.to_string(),
                right: r.dimension.to_string(),
            });
        }
        let total = self
            .canonical_amount(registry)?
            .add(&other.canonical_amount(registry)?)
            .map_err(TransformError::Model)?;
        Quantity::from_canonical(total, &self.unit.clone(), registry)
    }

    /// Exact difference (`self - other`), expressed in `self`'s unit.
    pub fn sub(
        &self,
        other: &Quantity,
        registry: &UnitRegistry,
    ) -> Result<Quantity, TransformError> {
        let neg = Quantity {
            amount: other.amount.neg(),
            unit: other.unit.clone(),
        };
        self.add(&neg, registry)
    }

    /// Value comparison in canonical units.
    pub fn cmp_qty(
        &self,
        other: &Quantity,
        registry: &UnitRegistry,
    ) -> Result<Ordering, TransformError> {
        if !self.same_dimension(other, registry)? {
            let l = self.lookup_def(registry)?;
            let r = other.lookup_def(registry)?;
            return Err(TransformError::DimensionMismatch {
                left: l.dimension.to_string(),
                right: r.dimension.to_string(),
            });
        }
        Ok(self
            .canonical_amount(registry)?
            .cmp(&other.canonical_amount(registry)?))
    }

    /// Sum of quantities, expressed in the first quantity's unit.
    pub fn sum<'a, I: IntoIterator<Item = &'a Quantity>>(
        items: I,
        registry: &UnitRegistry,
    ) -> Result<Quantity, TransformError> {
        let mut iter = items.into_iter();
        let first = match iter.next() {
            Some(q) => q.clone(),
            None => return Err(TransformError::Empty("sum of no quantities".into())),
        };
        let mut acc = first;
        for q in iter {
            acc = acc.add(q, registry)?;
        }
        Ok(acc)
    }

    pub fn is_zero(&self) -> bool {
        self.amount.is_zero()
    }
}

impl fmt::Display for Quantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.amount, self.unit.uom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    #[test]
    fn iso_registry_conversions() {
        let reg = UnitRegistry::iso80000();
        // kWh -> MJ: x 3.6 exactly
        let q = Quantity::parse("5", "kWh", &reg).unwrap();
        let mj = q.convert_to(&reg.unit("MJ").unwrap(), &reg).unwrap();
        assert_eq!(mj.amount, dec("18"));
        let kg = Quantity::parse("1.5", "kg", &reg).unwrap();
        let g = kg.convert_to(&reg.unit("g").unwrap(), &reg).unwrap();
        assert_eq!(g.amount, dec("1500"));
        let t = Quantity::parse("2", "t", &reg).unwrap();
        let kg2 = t.convert_to(&reg.unit("kg").unwrap(), &reg).unwrap();
        assert_eq!(kg2.amount, dec("2000"));
    }

    #[test]
    fn dimension_mismatch_rejected() {
        let reg = UnitRegistry::iso80000();
        let energy = Quantity::parse("1", "kWh", &reg).unwrap();
        let mass = Quantity::parse("1", "kg", &reg).unwrap();
        assert!(matches!(
            energy.convert_to(&mass.unit, &reg),
            Err(TransformError::DimensionMismatch { .. })
        ));
        assert!(matches!(
            energy.add(&mass, &reg),
            Err(TransformError::DimensionMismatch { .. })
        ));
    }

    #[test]
    fn unknown_units_and_conflicts() {
        let mut reg = UnitRegistry::iso80000();
        assert!(matches!(
            reg.lookup("furlong"),
            Err(TransformError::UnknownUnit(_))
        ));
        assert!(reg
            .register("kg", "https://x.example", Dimension::Mass, 5, 1)
            .is_err());
        // Same definition re-registration is idempotent.
        reg.register("kg", UNITSML, Dimension::Mass, 1, 1).unwrap();
        // Custom dimension registration works and converts.
        reg.register(
            "furlong",
            "https://x.example",
            Dimension::Custom("length".into()),
            201_168,
            1000,
        )
        .unwrap();
        let f1 = Quantity::parse("1", "furlong", &reg).unwrap();
        let f2 = f1.convert_to(&reg.unit("furlong").unwrap(), &reg).unwrap();
        assert_eq!(f1, f2);
    }

    #[test]
    fn quantity_compare_across_units() {
        let reg = UnitRegistry::iso80000();
        let a = Quantity::parse("0.5", "t", &reg).unwrap();
        let b = Quantity::parse("400", "kg", &reg).unwrap();
        assert_eq!(a.cmp_qty(&b, &reg).unwrap(), Ordering::Greater);
        let c = Quantity::parse("400000", "g", &reg).unwrap();
        assert_eq!(b.cmp_qty(&c, &reg).unwrap(), Ordering::Equal);
        let s = Quantity::sum([&a, &b], &reg).unwrap();
        assert_eq!(
            s.convert_to(&reg.unit("kg").unwrap(), &reg).unwrap().amount,
            dec("900")
        );
    }
}
