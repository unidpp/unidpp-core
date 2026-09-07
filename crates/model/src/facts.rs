//! Twin facts and trigger predicates.
//!
//! Profiles attach by *predicate on twin facts* (jurisdiction x sector x
//! characteristic, PLAN.md L2): age, material content, heritage status,
//! market status. Time predicates are clock-fired applicability events
//! (an object becoming >100 years old) handled by the dated-binding
//! machinery, not by human declaration.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::time::{Timestamp, JULIAN_YEAR_SECS};
use crate::Decimal;

/// A typed fact value on the twin state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "t", content = "v")]
pub enum FactValue {
    Str(String),
    Num(Decimal),
    Bool(bool),
    List(Vec<String>),
}

impl FactValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            FactValue::Str(_) => "str",
            FactValue::Num(_) => "num",
            FactValue::Bool(_) => "bool",
            FactValue::List(_) => "list",
        }
    }
}

/// The testimonial twin state (silent objects S0 have no device segment —
/// these are testimonies *about* the thing, not sensor readings).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TwinFacts {
    pub facts: BTreeMap<String, FactValue>,
    /// Date of birth (production/first-registration) for clock-fired
    /// applicability predicates.
    pub born_on: Option<Timestamp>,
}

impl TwinFacts {
    pub fn new() -> TwinFacts {
        TwinFacts::default()
    }

    pub fn set(mut self, path: &str, value: FactValue) -> TwinFacts {
        self.facts.insert(path.to_string(), value);
        self
    }

    pub fn with_born_on(mut self, t: Timestamp) -> TwinFacts {
        self.born_on = Some(t);
        self
    }

    pub fn get(&self, path: &str) -> Option<&FactValue> {
        self.facts.get(path)
    }
}

fn cmp_values(a: &FactValue, b: &FactValue) -> Option<Ordering> {
    match (a, b) {
        (FactValue::Num(x), FactValue::Num(y)) => Some(x.cmp(y)),
        (FactValue::Str(x), FactValue::Str(y)) => Some(x.cmp(y)),
        (FactValue::Bool(x), FactValue::Bool(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

/// Trigger predicate AST over twin facts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TriggerPredicate {
    /// Always true.
    Any,
    All(Vec<TriggerPredicate>),
    AnyOf(Vec<TriggerPredicate>),
    Not(Box<TriggerPredicate>),
    FactEq { path: String, value: FactValue },
    FactNe { path: String, value: FactValue },
    FactGt { path: String, value: FactValue },
    FactGe { path: String, value: FactValue },
    FactLt { path: String, value: FactValue },
    FactLe { path: String, value: FactValue },
    /// Substring (Str) or membership (List).
    FactContains { path: String, needle: String },
    /// Clock-fired: the subject is at least `years` years old at `now`.
    AgeAtLeast { years: u32 },
    /// Market-status predicate (CITES / cultural-goods / AML triggers).
    MarketStatusIs { status: String },
}

impl TriggerPredicate {
    pub fn eval(&self, facts: &TwinFacts, now: Timestamp) -> bool {
        match self {
            TriggerPredicate::Any => true,
            TriggerPredicate::All(ps) => ps.iter().all(|p| p.eval(facts, now)),
            TriggerPredicate::AnyOf(ps) => ps.iter().any(|p| p.eval(facts, now)),
            TriggerPredicate::Not(p) => !p.eval(facts, now),
            TriggerPredicate::FactEq { path, value } => {
                facts.get(path) == Some(value)
            }
            TriggerPredicate::FactNe { path, value } => {
                facts.get(path).is_some_and(|v| v != value)
            }
            TriggerPredicate::FactGt { path, value } => facts
                .get(path)
                .and_then(|v| cmp_values(v, value)) == Some(Ordering::Greater),
            TriggerPredicate::FactGe { path, value } => facts
                .get(path)
                .and_then(|v| cmp_values(v, value))
                .is_some_and(|o| o != Ordering::Less),
            TriggerPredicate::FactLt { path, value } => facts
                .get(path)
                .and_then(|v| cmp_values(v, value)) == Some(Ordering::Less),
            TriggerPredicate::FactLe { path, value } => facts
                .get(path)
                .and_then(|v| cmp_values(v, value))
                .is_some_and(|o| o != Ordering::Greater),
            TriggerPredicate::FactContains { path, needle } => match facts.get(path) {
                Some(FactValue::Str(s)) => s.contains(needle),
                Some(FactValue::List(l)) => l.iter().any(|x| x == needle),
                _ => false,
            },
            TriggerPredicate::AgeAtLeast { years } => facts.born_on.is_some_and(|b| {
                now.signed_secs_since(b) >= *years as i64 * JULIAN_YEAR_SECS
            }),
            TriggerPredicate::MarketStatusIs { status } => matches!(
                facts.get("subject.market-status"),
                Some(FactValue::Str(s)) if s == status
            ),
        }
    }

    /// Human-readable description (logs, drift reports).
    pub fn describe(&self) -> String {
        match self {
            TriggerPredicate::Any => "any".into(),
            TriggerPredicate::All(ps) => format!(
                "all({})",
                ps.iter().map(|p| p.describe()).collect::<Vec<_>>().join(", ")
            ),
            TriggerPredicate::AnyOf(ps) => format!(
                "any-of({})",
                ps.iter().map(|p| p.describe()).collect::<Vec<_>>().join(", ")
            ),
            TriggerPredicate::Not(p) => format!("not({})", p.describe()),
            TriggerPredicate::FactEq { path, value } => format!("{path} == {value:?}"),
            TriggerPredicate::FactNe { path, value } => format!("{path} != {value:?}"),
            TriggerPredicate::FactGt { path, value } => format!("{path} > {value:?}"),
            TriggerPredicate::FactGe { path, value } => format!("{path} >= {value:?}"),
            TriggerPredicate::FactLt { path, value } => format!("{path} < {value:?}"),
            TriggerPredicate::FactLe { path, value } => format!("{path} <= {value:?}"),
            TriggerPredicate::FactContains { path, needle } => format!("{path} ~ {needle}"),
            TriggerPredicate::AgeAtLeast { years } => format!("age >= {years}y"),
            TriggerPredicate::MarketStatusIs { status } => format!("market-status == {status}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> TwinFacts {
        TwinFacts::new()
            .set("subject.age-years", FactValue::Num("120".parse().unwrap()))
            .set("subject.materials", FactValue::List(vec!["ivory".into(), "spruce".into()]))
            .set("subject.market-status", FactValue::Str("imported".into()))
            .with_born_on(Timestamp::from_secs(1_800_000_000))
    }

    #[test]
    fn age_predicate_is_clock_fired() {
        let now = Timestamp::from_secs(1_800_000_000 + 100 * JULIAN_YEAR_SECS + 5);
        let p = TriggerPredicate::AgeAtLeast { years: 100 };
        assert!(p.eval(&facts(), now));
        let early = Timestamp::from_secs(1_800_000_000 + 50 * JULIAN_YEAR_SECS);
        assert!(!p.eval(&facts(), early));
    }

    #[test]
    fn composition_and_membership() {
        let now = Timestamp::from_secs(2_000_000_000);
        let p = TriggerPredicate::All(vec![
            TriggerPredicate::FactContains {
                path: "subject.materials".into(),
                needle: "ivory".into(),
            },
            TriggerPredicate::MarketStatusIs {
                status: "imported".into(),
            },
        ]);
        assert!(p.eval(&facts(), now));
        let neg = TriggerPredicate::Not(Box::new(p.clone()));
        assert!(!neg.eval(&facts(), now));
    }

    #[test]
    fn numeric_comparisons_use_exact_decimals() {
        let now = Timestamp::from_secs(2_000_000_000);
        let gt = TriggerPredicate::FactGt {
            path: "subject.age-years".into(),
            value: FactValue::Num("119.999".parse().unwrap()),
        };
        assert!(gt.eval(&facts(), now));
        let le = TriggerPredicate::FactLe {
            path: "subject.age-years".into(),
            value: FactValue::Num("120".parse().unwrap()),
        };
        assert!(le.eval(&facts(), now));
        // Type mismatch is false, not an error.
        let bad = TriggerPredicate::FactGt {
            path: "subject.age-years".into(),
            value: FactValue::Str("120".into()),
        };
        assert!(!bad.eval(&facts(), now));
    }
}
