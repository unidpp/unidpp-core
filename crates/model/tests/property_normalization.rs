//! Property: casing normalization — "Model" and "model" (and "MODEL",
//! "mOdel", "mo_del", ...) all parse to the canonical lowercase token per
//! the normalization table; display round-trips; identifiers compare
//! equal across casings.

use std::str::FromStr;

use unidpp_model::{
    normalization, CapabilityClass, Granularity, IdScheme, KnownAlteration, LinkType,
    ProductIdentifier, Recoverability, TrustMarker, VisibilityClass,
};

/// Local xorshift64* (test-only; avoids a dev-dependency cycle).
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(hi > lo);
        lo + self.next_u64() % (hi - lo)
    }
    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

fn random_casing(rng: &mut Rng, s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match rng.range(0, 3) {
            0 => out.extend(c.to_uppercase()),
            1 => out.push(c),
            _ => out.extend(c.to_lowercase()),
        }
    }
    // Randomly swap separators.
    if out.contains('-') && rng.bool() {
        out = out.replace('-', if rng.bool() { "_" } else { " " });
    }
    out
}

macro_rules! assert_casing_invariant {
    ($ty:ty, $canonical:expr, $rng:expr) => {{
        let canonical = $canonical;
        let mangled = random_casing(&mut $rng, canonical);
        let parsed: $ty = mangled.parse().unwrap_or_else(|e| {
            panic!("`{mangled}` must parse as {}: {e}", stringify!($ty))
        });
        assert_eq!(parsed.to_string(), canonical, "canonical display must round-trip");
    }};
}

#[test]
fn all_table_tokens_accept_any_casing() {
    let mut rng = Rng::new(0xCA5E);
    for _round in 0..8 {
        for token in normalization::NORMALIZATION_TABLE {
            let mangled = random_casing(&mut rng, token);
            assert_eq!(
                normalization::canonical_token(&mangled),
                Some(*token),
                "`{mangled}` must canonicalize to `{token}`"
            );
        }
    }
}

#[test]
fn enum_parse_accepts_any_casing() {
    let mut rng = Rng::new(0x5EED);
    for _ in 0..50 {
        assert_casing_invariant!(Granularity, "model", rng);
        assert_casing_invariant!(LinkType, "type-lineage", rng);
        assert_casing_invariant!(Recoverability, "harvestable", rng);
        assert_casing_invariant!(VisibilityClass, "restricted", rng);
        assert_casing_invariant!(TrustMarker, "log-anchored", rng);
        assert_casing_invariant!(CapabilityClass, "passive-auth", rng);
        assert_casing_invariant!(KnownAlteration, "conformal-coating", rng);
    }
}

#[test]
fn identifiers_equal_across_casings_and_forms() {
    let mut rng = Rng::new(0x1D);
    const EAN: &str = "4006381333931";
    for _ in 0..200 {
        let scheme = ["GTIN", "gtin", "Gtin", "gTiN"][rng.range(0, 4) as usize];
        let a = ProductIdentifier::parse(&format!("{scheme}:{EAN}")).unwrap();
        let b = ProductIdentifier::parse(&format!("01+{EAN}")).unwrap();
        let c = ProductIdentifier::parse(EAN).unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a.scheme, IdScheme::Gtin);
        assert_eq!(a.to_string(), format!("01+{EAN}"));
        // Element string with extensions, in mixed case scheme form.
        let s1 = ProductIdentifier::parse(&format!("{scheme}:{EAN}+10+LOT42+21+SN7")).unwrap();
        let s2 = ProductIdentifier::parse(&format!("01+{EAN}+10+LOT42+21+SN7")).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.granularity, Granularity::Item);
        // serde round trip preserves the canonical form.
        let json = serde_json::to_string(&s1).unwrap();
        let rt: ProductIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, s1);
        assert_eq!(json, format!("\"{}\"", s1));
    }
}

#[test]
fn passport_ids_normalize_case() {
    let mut rng = Rng::new(0x9);
    for _ in 0..100 {
        let slug = format!("urn:unidpp:passport:EU-BP-{}", rng.range(0, 999_999));
        let a = unidpp_model::PassportId::new(&slug).unwrap();
        let upper = slug.to_ascii_uppercase();
        let lower = slug.to_ascii_lowercase();
        assert_eq!(a, unidpp_model::PassportId::new(&upper).unwrap());
        assert_eq!(a, unidpp_model::PassportId::new(&lower).unwrap());
        assert_eq!(a.as_str(), &slug.to_ascii_lowercase());
    }
}

#[test]
fn from_str_round_trips() {
    let g: Granularity = Granularity::from_str("ITEM").unwrap();
    assert_eq!(g, Granularity::Item);
    let t: TrustMarker = "multi_signed".parse().unwrap();
    assert_eq!(t, TrustMarker::MultiSigned);
    let v: VisibilityClass = "ESCROWED".parse().unwrap();
    assert_eq!(v, VisibilityClass::Escrowed);
}
