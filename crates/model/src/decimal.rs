//! Exact fixed-point decimals for quantities and mass balance.
//!
//! Floats are never used for quantities: mass-balance conservation
//! (`in - out = loss`) and quantity carve-out checks (`sum(children) <=
//! parent`) are legal facts and must be exact. The representation is
//! `mant * 10^exp` with `|exp| <= 18`, normalized so trailing zeros are
//! stripped; equality and ordering are value-based.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use crate::ModelError;

const MAX_EXP: i32 = 18;
const MIN_EXP: i32 = -18;

#[derive(Debug, Clone, Copy)]
pub struct Decimal {
    pub mant: i128,
    pub exp: i32,
}

#[inline]
fn pow10(exp: u32) -> Option<i128> {
    10i128.checked_pow(exp)
}

/// Strip trailing zeros while the exponent stays within the cap; the result
/// is a canonical representation per value given the `|exp| <= 18` domain
/// invariant (see tests: two equal values always canonicalize identically).
fn normalized(mant: i128, exp: i32) -> (i128, i32) {
    let mut m = mant;
    let mut e = exp;
    while m != 0 && m % 10 == 0 && e < MAX_EXP {
        m /= 10;
        e += 1;
    }
    (m, e)
}

/// Exact magnitude comparison of `m1 * 10^e1` vs `m2 * 10^e2` via
/// zero-padded digit strings (no scaling overflow possible).
fn cmp_magnitudes(m1: i128, e1: i32, m2: i128, e2: i32) -> Ordering {
    if m1 == 0 && m2 == 0 {
        return Ordering::Equal;
    }
    if m1 == 0 {
        return Ordering::Less;
    }
    if m2 == 0 {
        return Ordering::Greater;
    }
    let s1 = m1.to_string();
    let s2 = m2.to_string();
    let l1 = s1.len() as i32 + e1;
    let l2 = s2.len() as i32 + e2;
    if l1 != l2 {
        return l1.cmp(&l2);
    }
    let n = s1.len().max(s2.len());
    let p1 = format!("{s1:0<n$}");
    let p2 = format!("{s2:0<n$}");
    p1.cmp(&p2)
}

/// Scale `m * 10^from` down to exponent `to` (to <= from), exactly.
fn scale_to(m: i128, from: i32, to: i32) -> Result<i128, ModelError> {
    debug_assert!(to <= from);
    if from == to {
        return Ok(m);
    }
    let factor = pow10((from - to) as u32)
        .ok_or_else(|| ModelError::Overflow("decimal scaling".into()))?;
    m.checked_mul(factor)
        .ok_or_else(|| ModelError::Overflow("decimal scaling".into()))
}

impl Decimal {
    pub fn zero() -> Decimal {
        Decimal { mant: 0, exp: 0 }
    }

    pub fn one() -> Decimal {
        Decimal { mant: 1, exp: 0 }
    }

    pub fn new(mant: i128, exp: i32) -> Result<Decimal, ModelError> {
        if !(MIN_EXP..=MAX_EXP).contains(&exp) {
            return Err(ModelError::Validation(format!(
                "decimal exponent {exp} outside [-18, 18]"
            )));
        }
        let (m, e) = normalized(mant, exp);
        Ok(Decimal { mant: m, exp: e })
    }

    pub fn from_i64(v: i64) -> Decimal {
        Decimal { mant: v as i128, exp: 0 }
    }

    pub fn is_zero(&self) -> bool {
        self.mant == 0
    }

    pub fn is_negative(&self) -> bool {
        self.mant < 0
    }

    pub fn abs(&self) -> Decimal {
        Decimal {
            mant: self.mant.abs(),
            exp: self.exp,
        }
    }

    pub fn neg(&self) -> Decimal {
        Decimal {
            mant: -self.mant,
            exp: self.exp,
        }
    }

    fn cmp_value(&self, other: &Decimal) -> Ordering {
        let a_neg = self.mant < 0;
        let b_neg = other.mant < 0;
        match (a_neg, b_neg) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            _ => {
                let ord = cmp_magnitudes(
                    self.mant.abs(),
                    self.exp,
                    other.mant.abs(),
                    other.exp,
                );
                if a_neg {
                    ord.reverse()
                } else {
                    ord
                }
            }
        }
    }

    fn align(&self, other: &Decimal) -> Result<(i128, i128, i32), ModelError> {
        let e = self.exp.min(other.exp);
        let ma = scale_to(self.mant, self.exp, e)?;
        let mb = scale_to(other.mant, other.exp, e)?;
        Ok((ma, mb, e))
    }

    pub fn add(&self, other: &Decimal) -> Result<Decimal, ModelError> {
        let (ma, mb, e) = self.align(other)?;
        let sum = ma
            .checked_add(mb)
            .ok_or_else(|| ModelError::Overflow("decimal addition".into()))?;
        Decimal::new(sum, e)
    }

    pub fn sub(&self, other: &Decimal) -> Result<Decimal, ModelError> {
        self.add(&other.neg())
    }

    pub fn mul(&self, other: &Decimal) -> Result<Decimal, ModelError> {
        let m = self
            .mant
            .checked_mul(other.mant)
            .ok_or_else(|| ModelError::Overflow("decimal multiplication".into()))?;
        Decimal::new(m, self.exp + other.exp)
    }

    /// Exact multiplication by the ratio `num/den` (e.g. unit factors:
    /// kWh->MJ is x 36/10). Errors if the result is not exactly
    /// representable.
    pub fn mul_ratio_exact(&self, num: i128, den: i128) -> Result<Decimal, ModelError> {
        if den == 0 {
            return Err(ModelError::DivideByZero);
        }
        let (num, den) = if den < 0 { (-num, -den) } else { (num, den) };
        for k in 0i32..=9 {
            let factor = match pow10(k as u32) {
                Some(f) => f,
                None => break,
            };
            let Some(scaled) = self.mant.checked_mul(factor) else {
                break;
            };
            let Some(v) = scaled.checked_mul(num) else {
                break;
            };
            if v % den == 0 {
                return Decimal::new(v / den, self.exp - k);
            }
        }
        Err(ModelError::Validation(format!(
            "inexact ratio conversion {self} x {num}/{den}"
        )))
    }

    pub fn sum<'a, I: IntoIterator<Item = &'a Decimal>>(items: I) -> Result<Decimal, ModelError> {
        let mut acc = Decimal::zero();
        for d in items {
            acc = acc.add(d)?;
        }
        Ok(acc)
    }
}

impl PartialEq for Decimal {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_value(other) == Ordering::Equal
    }
}

impl Eq for Decimal {}

impl PartialOrd for Decimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp_value(other))
    }
}

impl Ord for Decimal {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_value(other)
    }
}

impl Hash for Decimal {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let (m, e) = normalized(self.mant, self.exp);
        m.hash(state);
        e.hash(state);
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.mant == 0 {
            return f.write_str("0");
        }
        let neg = self.mant < 0;
        let digits = self.mant.abs().to_string();
        if neg {
            f.write_str("-")?;
        }
        if self.exp >= 0 {
            f.write_str(&digits)?;
            for _ in 0..self.exp {
                f.write_str("0")?;
            }
        } else {
            let point = digits.len() as i32 + self.exp;
            if point > 0 {
                let p = point as usize;
                f.write_str(&digits[..p])?;
                f.write_str(".")?;
                f.write_str(&digits[p..])?;
            } else {
                f.write_str("0.")?;
                for _ in 0..(-point) {
                    f.write_str("0")?;
                }
                f.write_str(&digits)?;
            }
        }
        Ok(())
    }
}

impl FromStr for Decimal {
    type Err = ModelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let mut mant_str = String::new();
        let mut frac_len: i32 = 0;
        let mut seen_dot = false;
        let mut seen_digit = false;
        for (i, c) in s.chars().enumerate() {
            match c {
                '-' if i == 0 => mant_str.push('-'),
                '+' if i == 0 => {}
                '0'..='9' => {
                    mant_str.push(c);
                    seen_digit = true;
                    if seen_dot {
                        frac_len += 1;
                    }
                }
                '.' if !seen_dot => seen_dot = true,
                _ => {
                    return Err(ModelError::Parse(format!(
                        "invalid decimal `{s}`"
                    )))
                }
            }
        }
        if !seen_digit {
            return Err(ModelError::Parse(format!("invalid decimal `{s}`")));
        }
        if frac_len > 18 {
            return Err(ModelError::Validation(format!(
                "decimal `{s}` has more than 18 fractional digits"
            )));
        }
        let mant: i128 = mant_str
            .parse()
            .map_err(|_| ModelError::Overflow(format!("decimal `{s}` overflows i128")))?;
        Decimal::new(mant, -frac_len)
    }
}

impl serde::Serialize for Decimal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Decimal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        s.parse::<Decimal>().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    #[test]
    fn equality_across_representations() {
        assert_eq!(d("1.50"), d("1.5"));
        assert_eq!(d("0.100"), d("0.1"));
        assert_ne!(d("1.5"), d("1.501"));
        assert_eq!(d("-0"), d("0"));
        // Hash consistent with Eq
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let h = |x: &Decimal| {
            let mut s = DefaultHasher::new();
            x.hash(&mut s);
            s.finish()
        };
        assert_eq!(h(&d("1.50")), h(&d("1.5")));
    }

    #[test]
    fn ordering() {
        assert!(d("2.5") > d("2.4999"));
        assert!(d("-1") < d("0.0001"));
        assert!(d("1000000000000") > d("999999999999.9"));
        assert!(d("0.000000000000000001") < d("0.000000000000000002"));
        assert!(d("10") < d("9.5").add(&d("0.6")).unwrap());
    }

    #[test]
    fn arithmetic() {
        assert_eq!(d("1.25").add(&d("2.5")).unwrap(), d("3.75"));
        assert_eq!(d("1.25").sub(&d("2.5")).unwrap(), d("-1.25"));
        assert_eq!(d("1.5").mul(&d("0.4")).unwrap(), d("0.6"));
        assert_eq!(Decimal::sum([&d("0.1"), &d("0.2"), &d("0.3")]).unwrap(), d("0.6"));
    }

    #[test]
    fn exact_ratios() {
        // kWh -> MJ: factor 3.6 = 36/10
        assert_eq!(d("5").mul_ratio_exact(36, 10).unwrap(), d("18"));
        // kg -> g
        assert_eq!(d("1.5").mul_ratio_exact(1000, 1).unwrap(), d("1500"));
        // lb -> kg (0.45359237 exactly, by SI definition): 100 lb
        assert_eq!(
            d("100").mul_ratio_exact(45359237, 100000000).unwrap(),
            d("45.359237")
        );
        assert!(d("1").mul_ratio_exact(1, 3).is_err());
        assert!(d("1").mul_ratio_exact(1, 0).is_err());
    }

    #[test]
    fn display_round_trip() {
        for s in ["0", "1", "-1", "1.5", "-0.000000001", "123456789012345678"] {
            assert_eq!(d(s).to_string(), s);
        }
        assert_eq!(d("1.500").to_string(), "1.5");
    }

    #[test]
    fn parse_errors() {
        assert!("abc".parse::<Decimal>().is_err());
        assert!("1.2.3".parse::<Decimal>().is_err());
        assert!("".parse::<Decimal>().is_err());
        assert!("-".parse::<Decimal>().is_err());
        assert!("0.1234567890123456789".parse::<Decimal>().is_err());
    }

    #[test]
    fn exp_bounds() {
        assert!(Decimal::new(1, 19).is_err());
        assert!(Decimal::new(1, -19).is_err());
        assert!(Decimal::new(10, 18).is_ok());
    }
}
