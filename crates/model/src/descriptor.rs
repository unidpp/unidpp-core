//! The projection descriptor (PR-9, ARCHITECTURE §3.C): every
//! published projection carries its five-axis characterization
//! machine-readably. The axes are independent; each named projection
//! type lives on exactly one axis, concrete projections are tuples —
//! the served DPP view is `continuous·mixed·derived·native·instance`;
//! the cross-border battery attestation is
//! `point-in-time·dynamic·direct·translated·instance`, frozen.
//!
//! Two normative theorems ride the calculus: event sourcing ⇒
//! replayability (every point-in-time projection recomputes from the
//! log alone); freshness contract ⇒ honest degradation (a continuous
//! projection without a current freshness verdict degrades
//! explicitly, never passes silently).

/// Axis T — temporal: state at T (immutable once notarized;
/// derivable for any T from the log) vs state at now under a
/// freshness contract. Freeze turns continuous into point-in-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TemporalAxis {
    PointInTime,
    Continuous,
}

/// Axis C — content class: type-declared vs instance-measured facts
/// (per element; projections carry a mix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentAxis {
    Static,
    Dynamic,
    Mixed,
}

/// Axis D — derivation: selection vs computed (conversion,
/// aggregation, classification, decision); derived cites transform
/// refs + uncertainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DerivationAxis {
    Direct,
    Derived,
}

/// Axis X — exchange encoding: own-scheme structures vs
/// foreign-scheme structures via registered mapping items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExchangeAxis {
    Native,
    Translated,
}

/// Axis G — granularity: model facts; one subject; roll-up over a
/// committed traversal set; provenance-chain view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GranularityAxis {
    Type,
    Instance,
    Composite,
    Genealogy,
}

/// The five-axis descriptor every published projection carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProjectionDescriptor {
    /// T — point-in-time · continuous.
    pub temporal: TemporalAxis,
    /// C — static · dynamic · mixed.
    pub content: ContentAxis,
    /// D — direct · derived.
    pub derivation: DerivationAxis,
    /// X — native · translated.
    pub exchange: ExchangeAxis,
    /// G — type · instance · composite · genealogy.
    pub granularity: GranularityAxis,
}

impl ProjectionDescriptor {
    /// The wire form: `T·C·D·X·G` tokens in axis order.
    pub fn token(&self) -> String {
        let t = match self.temporal {
            TemporalAxis::PointInTime => "point-in-time",
            TemporalAxis::Continuous => "continuous",
        };
        let c = match self.content {
            ContentAxis::Static => "static",
            ContentAxis::Dynamic => "dynamic",
            ContentAxis::Mixed => "mixed",
        };
        let d = match self.derivation {
            DerivationAxis::Direct => "direct",
            DerivationAxis::Derived => "derived",
        };
        let x = match self.exchange {
            ExchangeAxis::Native => "native",
            ExchangeAxis::Translated => "translated",
        };
        let g = match self.granularity {
            GranularityAxis::Type => "type",
            GranularityAxis::Instance => "instance",
            GranularityAxis::Composite => "composite",
            GranularityAxis::Genealogy => "genealogy",
        };
        format!("{t}·{c}·{d}·{x}·{g}")
    }
}

/// The cross-border battery attestation's descriptor, frozen.
pub const BATTERY_FROZEN: ProjectionDescriptor = ProjectionDescriptor {
    temporal: TemporalAxis::PointInTime,
    content: ContentAxis::Dynamic,
    derivation: DerivationAxis::Direct,
    exchange: ExchangeAxis::Translated,
    granularity: GranularityAxis::Instance,
};

/// The served DPP view's descriptor.
pub const SERVED_VIEW: ProjectionDescriptor = ProjectionDescriptor {
    temporal: TemporalAxis::Continuous,
    content: ContentAxis::Mixed,
    derivation: DerivationAxis::Derived,
    exchange: ExchangeAxis::Native,
    granularity: GranularityAxis::Instance,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_tokens_are_stable_and_parseable() {
        assert_eq!(
            BATTERY_FROZEN.token(),
            "point-in-time·dynamic·direct·translated·instance"
        );
        assert_eq!(
            SERVED_VIEW.token(),
            "continuous·mixed·derived·native·instance"
        );
        // Round-trip: the token's parts are the axis values in order.
        let token = BATTERY_FROZEN.token();
        let parts: Vec<&str> = token.split('·').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "point-in-time");
        assert_eq!(parts[4], "instance");
    }

    #[test]
    fn descriptors_round_trip_through_serde() {
        let json = serde_json::to_string(&BATTERY_FROZEN).unwrap();
        let back: ProjectionDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back, BATTERY_FROZEN);
        assert!(json.contains("point-in-time"));
    }
}
