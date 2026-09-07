//! Casing / separator normalization (the UniDPP normalization table).
//!
//! The lens-model critique in the UniDPP design framework flags EN 18223 (5.2.2) for legislating
//! identifier casing: a 2026-EU deployment accident frozen into normative
//! text. This core does the opposite: every token (scheme, granularity,
//! relationship type, recoverability, capability class, ...) accepts any
//! casing and separator spelling and canonicalizes to the table's lowercase
//! form. The property tests exercise exactly this ("Model" and "model" are
//! both accepted and compare equal).

/// Squash to the comparison key: lowercase ASCII, alphanumerics only.
///
/// "Model", "MODEL", "mOdel", "mo_del" -> "model".
pub fn squash(input: &str) -> String {
    input
        .chars()
        .filter_map(|c| {
            let lc = c.to_ascii_lowercase();
            if lc.is_ascii_alphanumeric() {
                Some(lc)
            } else {
                None
            }
        })
        .collect()
}

/// Canonical display token: lowercase, leading/trailing separators dropped,
/// internal runs of separators collapsed to a single '-'.
pub fn normalize_token(input: &str) -> String {
    let mut out = String::new();
    let mut pending_sep = false;
    for c in input.trim().chars() {
        let lc = c.to_ascii_lowercase();
        if lc == '-' || lc == '_' || lc == ' ' || lc == '.' || lc == '+' {
            if !out.is_empty() && !pending_sep {
                out.push('-');
                pending_sep = true;
            }
        } else {
            out.push(lc);
            pending_sep = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// The normalization table: canonical lowercase tokens accepted by every
/// table-driven enum in the core (compared via [`squash`], so any casing or
/// separator spelling of these tokens parses).
pub const NORMALIZATION_TABLE: &[&str] = &[
    // granularity
    "model",
    "batch",
    "item",
    // relationship types R1-R7
    "association",
    "derivation",
    "installation",
    "type-lineage",
    "custody",
    "membership",
    // direction
    "outgoing",
    "incoming",
    // recoverability spectrum
    "restorable",
    "harvestable",
    "destructive",
    "absorbing",
    // pairing
    "none",
    "firmware",
    "key",
    "module",
    // edge visibility classes
    "public",
    "restricted",
    "blind",
    "escrowed",
    // trust markers (I9 ladder)
    "unsigned",
    "self-declared",
    "attested",
    "multi-signed",
    "log-anchored",
    // capability classes S0-S3
    "silent",
    "passive-auth",
    "logged-contact",
    "connected",
    // identifier schemes
    "gtin",
    "sgtin",
    "gsrn",
    "gln",
    "cpid",
    "ssn",
    "upu",
    "vin",
    "handle",
    "doi",
    "uri",
    "local",
    // signature suites
    "ecdsa-p256",
    "sm2",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    // passport statuses (I6 state machine)
    "issued",
    "suspended",
    "invalidated",
    "non-conformant",
    "consumed",
    "transformed",
    "end-of-waste",
    "archived",
    // freshness
    "fresh",
    "stale",
    "indeterminate",
    "static",
    // resolution / traversal
    "national",
    "role-scoped",
    "authority-only",
];

/// Canonical form of a known token, if any (case- and separator-insensitive).
pub fn canonical_token(input: &str) -> Option<&'static str> {
    let key = squash(input);
    NORMALIZATION_TABLE
        .iter()
        .copied()
        .find(|t| squash(t) == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn squash_drops_case_and_separators() {
        assert_eq!(squash("Model"), "model");
        assert_eq!(squash("MODEL"), "model");
        assert_eq!(squash("mO_del"), "model");
        assert_eq!(squash("type-lineage"), "typelineage");
    }

    #[test]
    fn normalize_token_collapses_separators() {
        assert_eq!(normalize_token(" Type_Lineage "), "type-lineage");
        assert_eq!(normalize_token("passive  AUTH"), "passive-auth");
    }

    #[test]
    fn table_covers_core_tokens() {
        assert_eq!(canonical_token("Model"), Some("model"));
        assert_eq!(canonical_token("LOG-ANCHORED"), Some("log-anchored"));
        assert_eq!(canonical_token("Connected"), Some("connected"));
        assert_eq!(canonical_token("nope-not-a-token"), None);
    }
}
