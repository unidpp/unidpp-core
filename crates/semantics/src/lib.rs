//! The semantic layer (Part 7): mapping tiers and composition,
//! units and measurement, multilingual values, and parseable
//! exports — the registry's model core.

pub mod mapping;

pub use mapping::{MappingChain, MappingError, MappingItem, MappingKind};
