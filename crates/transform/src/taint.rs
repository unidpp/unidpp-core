//! Graph taint: marking a passport fraudulent is a graph event, not just a
//! trust-list event. It traverses the provenance DAG downstream (same
//! machinery as recalls, different cause), tainting derived passports.
//!
//! Revocation reason determines retroactivity: prospective reasons (key
//! compromise after T, cessation, supersession) leave prior as-of
//! verifications valid; retroactive reasons (misissuance, fraudulent
//! issuance, authority compromised during a window) void validity ab
//! initio — distrust declarations carry an explicit window [start, end].

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use unidpp_model::normalization;
use unidpp_model::time::Interval;
use unidpp_model::{EnumParseError, PassportId, Timestamp};

/// Kind of taint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TaintKind {
    Known(KnownTaint),
    Other(String),
}

unidpp_model::str_enum! {
    /// Known taint kinds.
    pub enum KnownTaint {
        Revoked => "revoked",
        Compromised => "compromised",
        Misissued => "misissued",
        Fraud => "fraud",
        NonConformant => "non-conformant",
        Contaminated => "contaminated",
        LegalHold => "legal-hold",
    }
}

impl From<KnownTaint> for TaintKind {
    fn from(k: KnownTaint) -> TaintKind {
        TaintKind::Known(k)
    }
}

impl fmt::Display for TaintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaintKind::Known(k) => f.write_str(k.as_str()),
            TaintKind::Other(s) => write!(f, "other:{}", normalization::normalize_token(s)),
        }
    }
}

impl FromStr for TaintKind {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("other:").or_else(|| s.strip_prefix("OTHER:")) {
            if !rest.trim().is_empty() {
                return Ok(TaintKind::Other(rest.trim().to_string()));
            }
        }
        KnownTaint::parse_token(s).map(TaintKind::Known)
    }
}

impl TaintKind {
    /// Whether this reason voids validity ab initio (vs prospectively).
    pub fn is_retroactive(&self) -> bool {
        matches!(
            self,
            TaintKind::Known(KnownTaint::Misissued) | TaintKind::Known(KnownTaint::Fraud)
        )
    }
}

/// A single taint entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct Taint {
    pub source: PassportId,
    pub kind: TaintKind,
    pub reason: String,
    pub at: Timestamp,
    /// Void window for retroactive distrust [start, end].
    pub window: Option<Interval>,
}

impl Taint {
    pub fn retroactive(&self) -> bool {
        self.kind.is_retroactive()
    }
}

impl fmt::Display for Taint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} at {}", self.source, self.kind, self.at)?;
        if let Some(w) = &self.window {
            write!(f, " window {w}")?;
        }
        Ok(())
    }
}

/// A set of taints (union semantics for propagation).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaintSet {
    entries: BTreeSet<Taint>,
}

impl TaintSet {
    pub fn new() -> TaintSet {
        TaintSet::default()
    }

    pub fn add(&mut self, taint: Taint) {
        self.entries.insert(taint);
    }

    pub fn merge(&mut self, other: &TaintSet) {
        for e in &other.entries {
            self.entries.insert(e.clone());
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &BTreeSet<Taint> {
        &self.entries
    }

    pub fn contains_source(&self, source: &PassportId) -> bool {
        self.entries.iter().any(|t| &t.source == source)
    }

    /// Whether any entry voids ab initio (fraud laundering prevention).
    pub fn voids_ab_initio(&self) -> bool {
        self.entries.iter().any(|t| t.retroactive())
    }
}

impl fmt::Display for TaintSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.entries.iter().map(|t| t.to_string()).collect();
        f.write_str(&format!("{{{}}}", parts.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retroactivity_by_reason() {
        assert!(TaintKind::Known(KnownTaint::Fraud).is_retroactive());
        assert!(TaintKind::Known(KnownTaint::Misissued).is_retroactive());
        assert!(!TaintKind::Known(KnownTaint::Revoked).is_retroactive());
        assert!(!TaintKind::Known(KnownTaint::Compromised).is_retroactive());
    }

    #[test]
    fn union_semantics() {
        let a = Taint {
            source: PassportId::new("urn:unidpp:passport:a").unwrap(),
            kind: TaintKind::Known(KnownTaint::Fraud),
            reason: "stolen material".into(),
            at: Timestamp::from_secs(100),
            window: Some(Interval::starting(Timestamp::from_secs(50))),
        };
        let mut s1 = TaintSet::new();
        s1.add(a.clone());
        s1.add(a.clone());
        assert_eq!(s1.len(), 1);
        let mut s2 = TaintSet::new();
        s2.add(Taint {
            source: PassportId::new("urn:unidpp:passport:b").unwrap(),
            kind: "OTHER: customs hold".parse().unwrap(),
            reason: "x".into(),
            at: Timestamp::from_secs(200),
            window: None,
        });
        s2.merge(&s1);
        assert_eq!(s2.len(), 2);
        assert!(s2.voids_ab_initio());
        assert!(s2.contains_source(&PassportId::new("urn:unidpp:passport:b").unwrap()));
    }

    #[test]
    fn taint_kind_casing() {
        let k: TaintKind = "LEGAL_HOLD".parse().unwrap();
        assert_eq!(k, TaintKind::Known(KnownTaint::LegalHold));
        assert_eq!(k.to_string(), "legal-hold");
    }
}
