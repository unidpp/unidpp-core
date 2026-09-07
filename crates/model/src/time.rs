//! Deterministic UTC timestamps and intervals (ISO 8601 / RFC 3339).
//!
//! Hand-rolled on purpose: no external time dependency, exact integer
//! arithmetic (seconds + nanoseconds since the UNIX epoch), strict parsing,
//! canonical display with trailing-'Z'. All UniDPP dates are UTC; local
//! time is a presentation concern.

use std::fmt;
use std::str::FromStr;

use crate::ModelError;

/// Seconds in a Julian year (365.25 d) — the unit for clock-fired age
/// predicates (an object becoming >100 years old is an applicability event).
pub const JULIAN_YEAR_SECS: i64 = 31_557_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    pub secs: i64,
    pub nanos: u32,
}

impl Timestamp {
    pub const UNIX_EPOCH: Timestamp = Timestamp { secs: 0, nanos: 0 };

    pub fn from_secs(secs: i64) -> Timestamp {
        Timestamp { secs, nanos: 0 }
    }

    /// Current wall-clock time (test drivers should prefer explicit values).
    pub fn now() -> Timestamp {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Timestamp {
                secs: d.as_secs() as i64,
                nanos: d.subsec_nanos(),
            },
            Err(e) => {
                let d = e.duration();
                Timestamp {
                    secs: -(d.as_secs() as i64),
                    nanos: 0,
                }
            }
        }
    }

    /// Whole seconds from `earlier` to `self`, if `self >= earlier`.
    pub fn signed_secs_since(&self, earlier: Timestamp) -> i64 {
        self.secs - earlier.secs
    }

    /// Age in whole seconds at time `now` (0 if `now` is before this stamp).
    pub fn age_secs_at(&self, now: Timestamp) -> i64 {
        (now.secs - self.secs).max(0)
    }

    pub fn parse(input: &str) -> Result<Timestamp, ModelError> {
        let b = input.as_bytes();
        let err = |m: &str| ModelError::Parse(format!("timestamp `{input}`: {m}"));
        if b.len() < 10 {
            return Err(err("expected at least YYYY-MM-DD"));
        }
        let year = digits(b, 0, 4).ok_or_else(|| err("bad year"))?;
        if b[4] != b'-' {
            return Err(err("expected '-' after year"));
        }
        let month = digits(b, 5, 2).ok_or_else(|| err("bad month"))?;
        if b[7] != b'-' {
            return Err(err("expected '-' after month"));
        }
        let day = digits(b, 8, 2).ok_or_else(|| err("bad day"))?;
        if !(1..=12).contains(&month) {
            return Err(err("month out of range"));
        }
        if day < 1 || day > days_in_month(year, month as u32) as i64 {
            return Err(err("day out of range"));
        }
        let mut pos = 10;
        let (mut hour, mut min, mut sec, mut nanos) = (0i64, 0i64, 0i64, 0u32);
        if b.len() > pos && (b[pos] == b'T' || b[pos] == b't' || b[pos] == b' ') {
            if b.len() < pos + 9 {
                return Err(err("expected hh:mm:ss"));
            }
            hour = digits(b, pos + 1, 2).ok_or_else(|| err("bad hour"))?;
            if b[pos + 3] != b':' {
                return Err(err("expected ':' after hour"));
            }
            min = digits(b, pos + 4, 2).ok_or_else(|| err("bad minute"))?;
            if b[pos + 6] != b':' {
                return Err(err("expected ':' after minute"));
            }
            sec = digits(b, pos + 7, 2).ok_or_else(|| err("bad second"))?;
            if hour > 23 || min > 59 || sec > 59 {
                return Err(err("time component out of range"));
            }
            pos += 9;
            if b.len() > pos && b[pos] == b'.' {
                pos += 1;
                let start = pos;
                while pos < b.len() && b[pos].is_ascii_digit() {
                    pos += 1;
                }
                let frac_len = pos - start;
                if frac_len == 0 || frac_len > 9 {
                    return Err(err("bad fractional seconds"));
                }
                let mut val: u64 = 0;
                for i in start..pos {
                    val = val * 10 + (b[i] - b'0') as u64;
                }
                nanos = (val * 10u64.pow(9 - frac_len as u32)) as u32;
            }
        }
        // Zone: 'Z' | 'z' | +hh:mm | +hhmm | nothing (treated as UTC).
        let mut offset_secs: i64 = 0;
        if pos < b.len() {
            match b[pos] {
                b'Z' | b'z' => {
                    pos += 1;
                }
                b'+' | b'-' => {
                    let sign = if b[pos] == b'-' { -1i64 } else { 1i64 };
                    pos += 1;
                    let oh = digits(b, pos, 2).ok_or_else(|| err("bad offset hour"))?;
                    pos += 2;
                    if pos < b.len() && b[pos] == b':' {
                        pos += 1;
                    }
                    let om = digits(b, pos, 2).ok_or_else(|| err("bad offset minute"))?;
                    pos += 2;
                    if oh > 23 || om > 59 {
                        return Err(err("offset out of range"));
                    }
                    offset_secs = sign * (oh * 3600 + om * 60);
                }
                _ => return Err(err("trailing garbage")),
            }
            if pos != b.len() {
                return Err(err("trailing garbage after zone"));
            }
        }
        let days = days_from_civil(year, month as u32, day as u32);
        let secs = days * 86_400 + hour * 3_600 + min * 60 + sec - offset_secs;
        Ok(Timestamp { secs, nanos })
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.secs.div_euclid(86_400);
        let rem = self.secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            year,
            month,
            day,
            rem / 3_600,
            (rem % 3_600) / 60,
            rem % 60
        )?;
        if self.nanos > 0 {
            let frac = format!("{:09}", self.nanos);
            let trimmed = frac.trim_end_matches('0');
            write!(f, ".{trimmed}")?;
        }
        f.write_str("Z")
    }
}

impl FromStr for Timestamp {
    type Err = ModelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Timestamp::parse(s)
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Timestamp::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A half-open... closed interval [`from`, `to`] with an optional open end
/// ("ongoing"): installation intervals, profile effective dates, distrust
/// windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Interval {
    pub from: Timestamp,
    pub to: Option<Timestamp>,
}

impl Interval {
    pub fn starting(from: Timestamp) -> Interval {
        Interval { from, to: None }
    }

    pub fn between(from: Timestamp, to: Timestamp) -> Result<Interval, ModelError> {
        if to < from {
            return Err(ModelError::Validation(format!(
                "interval end {to} before start {from}"
            )));
        }
        Ok(Interval {
            from,
            to: Some(to),
        })
    }

    pub fn is_open(&self) -> bool {
        self.to.is_none()
    }

    pub fn contains(&self, t: Timestamp) -> bool {
        t >= self.from && self.to.map_or(true, |to| t <= to)
    }
}

impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to {
            Some(to) => write!(f, "[{}, {}]", self.from, to),
            None => write!(f, "[{}, open)", self.from),
        }
    }
}

fn digits(b: &[u8], pos: usize, len: usize) -> Option<i64> {
    if pos + len > b.len() {
        return None;
    }
    let mut v: i64 = 0;
    for &c in &b[pos..pos + len] {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as i64;
    }
    Some(v)
}

pub(crate) fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub(crate) fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Howard Hinnant's `days_from_civil` (proleptic Gregorian).
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m as i64 - 3 } else { m as i64 + 9 };
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Howard Hinnant's `civil_from_days` (proleptic Gregorian).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_round_trip() {
        let t = Timestamp::UNIX_EPOCH;
        assert_eq!(t.to_string(), "1970-01-01T00:00:00Z");
        assert_eq!(Timestamp::parse("1970-01-01T00:00:00Z").unwrap(), t);
    }

    #[test]
    fn date_only_and_time_forms() {
        assert_eq!(
            Timestamp::parse("2026-09-07").unwrap().to_string(),
            "2026-09-07T00:00:00Z"
        );
        let t = Timestamp::parse("2026-09-07T13:45:09").unwrap();
        assert_eq!(t.to_string(), "2026-09-07T13:45:09Z");
        assert_eq!(
            Timestamp::parse("2026-09-07 13:45:09Z").unwrap(),
            t
        );
    }

    #[test]
    fn fractional_and_offsets() {
        let t = Timestamp::parse("2026-09-07T13:45:09.250Z").unwrap();
        assert_eq!(t.nanos, 250_000_000);
        assert_eq!(t.to_string(), "2026-09-07T13:45:09.25Z");
        let off = Timestamp::parse("2026-09-07T13:45:09+02:00").unwrap();
        assert_eq!(off.secs, t.secs - 7_200);
        let neg = Timestamp::parse("2026-09-07T13:45:09-0530").unwrap();
        assert_eq!(neg.secs, t.secs + 19_800);
    }

    #[test]
    fn leap_year_validation() {
        assert!(Timestamp::parse("2024-02-29").is_ok());
        assert!(Timestamp::parse("2023-02-29").is_err());
        assert!(Timestamp::parse("2000-02-29").is_ok());
        assert!(Timestamp::parse("1900-02-29").is_err());
        assert!(Timestamp::parse("2026-13-01").is_err());
        assert!(Timestamp::parse("2026-04-31").is_err());
    }

    #[test]
    fn civil_conversion_known_values() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn interval_semantics() {
        let a = Timestamp::parse("2026-01-01T00:00:00Z").unwrap();
        let b = Timestamp::parse("2026-06-01T00:00:00Z").unwrap();
        let iv = Interval::between(a, b).unwrap();
        assert!(iv.contains(a) && iv.contains(b));
        assert!(Interval::between(b, a).is_err());
        let open = Interval::starting(a);
        assert!(open.is_open());
        assert!(open.contains(b));
    }
}
