//! The semantic layer (Part 7): mapping tiers and composition,
//! units and measurement, multilingual values, and parseable
//! exports — the registry's model core.

pub mod exports;
pub mod federation;
pub mod lifecycle;
pub mod mapping;
pub mod multilingual;
pub mod onboarding;
pub mod resolution;
pub mod roles;
pub mod units;

pub use exports::{ExportItem, StableId};
pub use mapping::{MappingChain, MappingError, MappingItem, MappingKind};
pub use multilingual::{validate, LocalizedSet, LocalizedValue};
pub use units::{
    classify_upper, convert, intake, propagate, DecisionRule, MeasuredValue, OfferedValue,
    UnitTable, UnitsError,
};
