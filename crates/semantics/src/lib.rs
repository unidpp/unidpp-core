//! The semantic layer (Part 7): mapping tiers and composition,
//! units and measurement, multilingual values, and parseable
//! exports — the registry's model core.

pub mod mapping;
pub mod units;

pub use mapping::{MappingChain, MappingError, MappingItem, MappingKind};
pub use units::{
    classify_upper, convert, intake, propagate, DecisionRule, MeasuredValue, OfferedValue,
    UnitTable, UnitsError,
};
