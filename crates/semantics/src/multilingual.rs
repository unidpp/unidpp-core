//! Multilingual values (PR-8): per-element language-tagged values
//! per BCP 47 — full tags, script subtags included.
//!
//! The cautionary example is EN 18223's own defect: a language
//! code element restricted to two characters cannot express `zh`
//! with the script subtag that distinguishes Simplified from
//! Traditional. This module validates well-formedness (language,
//! script, region, variants — the subtag registry itself is not
//! validated), keys values by tag, and retrieves by tag with
//! prefix fallback (zh → zh-Hans) and a stated miss.

use std::collections::BTreeMap;

/// A value tagged with a well-formed BCP 47 language tag.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalizedValue {
    /// The BCP 47 language tag (well-formed; canonical case:
    /// language lower, script Title, region UPPER).
    pub tag: String,
    /// The value in that language.
    pub value: String,
}

impl LocalizedValue {
    /// Construct, validating the tag's well-formedness.
    pub fn new(tag: &str, value: &str) -> Result<LocalizedValue, String> {
        let tag = tag.trim();
        validate(tag)?;
        Ok(LocalizedValue {
            tag: canonical_case(tag),
            value: value.into(),
        })
    }
}

/// The subtag the EN 18223 defect used for Greek: a two-letter
/// lowercase code (`gr`) in the second position — neither a
/// well-formed script (four letters) nor a region (UPPERCASE).
pub const DEFECT_SUBTAG: &str = "gr";

/// Validate a BCP 47 tag's well-formedness: 1–8 alphanumeric
/// subtags separated by `-`, the first 2–3 alphabetic; the second
/// subtag, when alphabetic, is a four-letter script or a
/// two-letter UPPERCASE region — the defect's lowercase two-letter
/// form is refused.
pub fn validate(tag: &str) -> Result<(), String> {
    if tag.is_empty() || tag.len() > 35 {
        return Err(format!("`{tag}` is not a well-formed BCP 47 tag"));
    }
    let subtags: Vec<&str> = tag.split('-').collect();
    if subtags.len() > 7 {
        return Err(format!("`{tag}` has too many subtags"));
    }
    for sub in &subtags {
        if sub.is_empty() || sub.len() > 8 || !sub.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(format!("`{tag}` contains a malformed subtag `{sub}`"));
        }
    }
    let language = subtags[0];
    if !(language.len() == 2 || language.len() == 3)
        || !language.chars().all(|c| c.is_ascii_alphabetic())
    {
        return Err(format!(
            "`{tag}`'s language subtag `{language}` is not 2–3 alphabetic"
        ));
    }
    if let Some(second) = subtags.get(1) {
        if second.chars().all(|c| c.is_ascii_alphabetic()) {
            let is_script = second.len() == 4;
            let is_region = second.len() == 2 && second.chars().all(|c| c.is_ascii_uppercase());
            let is_defect = second.len() == 2 && second == &DEFECT_SUBTAG;
            if is_defect {
                return Err(format!(
                    "`{tag}` uses the subtag `{second}` for a language — the EN 18223 defect \
                     (Greek is `el`); script subtags are four letters (e.g. zh-Hans)"
                ));
            }
            if !is_script && !is_region {
                return Err(format!(
                    "`{tag}`'s subtag `{second}` is not admissible in the second position \
                     (four-letter script or two-letter region)"
                ));
            }
        }
    }
    Ok(())
}

/// Canonical case: language lower-case, script Title-case, region
/// UPPER, variants lower.
pub fn canonical_case(tag: &str) -> String {
    tag.split('-')
        .enumerate()
        .map(|(i, sub)| match i {
            0 => sub.to_lowercase(),
            1 if sub.len() == 4 && sub.chars().all(|c| c.is_ascii_alphabetic()) => {
                let mut chars = sub.chars();
                match chars.next() {
                    Some(first) => {
                        first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                    }
                    None => sub.to_string(),
                }
            }
            2 if sub.len() == 2 => sub.to_uppercase(),
            _ => sub.to_lowercase(),
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// A per-element set of localized values, keyed by canonical tag.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalizedSet {
    /// The values by tag.
    pub values: BTreeMap<String, String>,
}

impl LocalizedSet {
    pub fn new() -> LocalizedSet {
        LocalizedSet::default()
    }

    /// Add a localized value (the tag is validated and
    /// canonically cased).
    pub fn add(&mut self, tag: &str, value: &str) -> Result<(), String> {
        let v = LocalizedValue::new(tag, value)?;
        self.values.insert(v.tag, v.value);
        Ok(())
    }

    /// Retrieve by tag with prefix fallback: exact, then any held
    /// tag extending the request, then `en`, then any held value.
    /// A miss is None — stated.
    pub fn get(&self, tag: &str) -> Option<&String> {
        let want = canonical_case(tag);
        if let Some(v) = self.values.get(&want) {
            return Some(v);
        }
        let prefix = format!("{want}-");
        let extending: Vec<&String> = self
            .values
            .iter()
            .filter(|(held, _)| held.starts_with(&prefix))
            .map(|(_, v)| v)
            .collect();
        if !extending.is_empty() {
            return extending.first().copied();
        }
        self.values
            .get("en")
            .or_else(|| self.values.iter().next().map(|(_, v)| v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PR-8's verify: zh-Hans and el round-trip; the EN 18223
    // defect and malformed tags are refused.
    #[test]
    fn full_tags_round_trip_and_the_defect_is_refused() {
        let mut set = LocalizedSet::new();
        set.add("zh-Hans", "电池护照").unwrap();
        set.add("zh-Hant", "電池護照").unwrap();
        set.add("el", "Διαβατήριο μπαταρίας").unwrap();
        set.add("en-GB", "Battery passport").unwrap();

        assert_eq!(set.get("zh-Hans").unwrap(), "电池护照");
        assert_eq!(set.get("zh-Hant").unwrap(), "電池護照");
        assert_eq!(set.get("el").unwrap(), "Διαβατήριο μπαταρίας");
        assert_eq!(set.get("ZH-hans").unwrap(), "电池护照");
        let got = set.get("zh").unwrap();
        assert!(got == "电池护照" || got == "電池護照", "a zh value");
        assert_eq!(set.get("en-GB").unwrap(), "Battery passport");
        assert_eq!(set.get("en").unwrap(), "Battery passport");
        assert_eq!(set.get("fr-FR"), set.values.iter().next().map(|(_, v)| v));

        // The EN 18223 defect: the lowercase two-letter subtag.
        let err = validate("zh-gr").unwrap_err();
        assert!(err.contains("EN 18223 defect"), "{err}");
        // Regions are fine in the second position.
        assert!(validate("en-GB").is_ok());
        // Malformed tags refused.
        assert!(validate("").is_err());
        assert!(validate("e").is_err());
        assert!(validate("en-").is_err());
        assert!(validate("en--GB").is_err());
        assert!(validate("aaa").is_ok()); // 3-letter language subtag is well-formed
        assert!(validate("1234").is_err());
        assert_eq!(canonical_case("ZH-HANS-CN"), "zh-Hans-CN");
    }
}
