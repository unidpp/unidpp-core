//! Resolution contexts (FD-2): linksets keyed by profile context,
//! role, language and request region — one identity, multiple
//! destinations, correct defaulting; dark identities never resolve
//! publicly.
//!
//! The linkset is the resolver's unit: for a subject and a context
//! key, the ordered destinations. The context dimensions come from
//! the retrieval interface (Part 10): the profile context the
//! client verifies under, its role, its language, and its request
//! region. Defaulting is explicit: each dimension may fall back to
//! `*` when no specific binding matches, and the fallback taken is
//! part of the served linkset (stated, never silent). Dark
//! identities have no public entry at all — their absence is
//! indistinguishable from an unknown identity.

use std::collections::BTreeMap;

/// One link in a linkset: a destination with its semantics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Link {
    /// The destination URI.
    pub href: String,
    /// What the destination serves (a representation token).
    pub rel: String,
}

/// The context key of a linkset (FD-2's four dimensions).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct ContextKey {
    /// The profile context.
    pub profile: String,
    /// The role (`*` = any).
    pub role: String,
    /// The language (`*` = any).
    pub language: String,
    /// The request region (`*` = any).
    pub region: String,
}

impl ContextKey {
    /// The fully general key.
    pub fn any() -> ContextKey {
        ContextKey {
            profile: "*".into(),
            role: "*".into(),
            language: "*".into(),
            region: "*".into(),
        }
    }
}

/// One subject's registered linksets, keyed by context, with an
/// as-of stamp for cacheability.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SubjectLinksets {
    /// The subject.
    pub subject: String,
    /// Context key → ordered links.
    pub contexts: BTreeMap<ContextKey, Vec<Link>>,
    /// The as-of stamp of this linkset generation (cache
    /// validators serve this).
    pub as_of: String,
    /// Whether the subject is dark: never resolvable publicly.
    pub dark: bool,
}

impl SubjectLinksets {
    /// Resolve for a concrete request: exact key, then per-dimension
    /// fallback to `*` (most-specific first: profile, then role,
    /// then region, then language); the fallback taken is reported.
    /// A dark subject resolves to None publicly.
    pub fn resolve(
        &self,
        profile: &str,
        role: &str,
        language: &str,
        region: &str,
    ) -> Option<(&[Link], String)> {
        if self.dark {
            return None;
        }
        let request = ContextKey {
            profile: profile.into(),
            role: role.into(),
            language: language.into(),
            region: region.into(),
        };
        if let Some(links) = self.contexts.get(&request) {
            return Some((links, "exact".into()));
        }
        // Per-dimension fallback, most-specific first: widen
        // language, then role, then both, then region, then
        // everything.
        let candidates = [
            (
                ContextKey {
                    language: "*".into(),
                    ..request.clone()
                },
                "language-fallback",
            ),
            (
                ContextKey {
                    role: "*".into(),
                    ..request.clone()
                },
                "role-fallback",
            ),
            (
                ContextKey {
                    role: "*".into(),
                    language: "*".into(),
                    ..request.clone()
                },
                "language+role-fallback",
            ),
            (
                ContextKey {
                    role: "*".into(),
                    language: "*".into(),
                    region: "*".into(),
                    ..request.clone()
                },
                "region-fallback",
            ),
            (ContextKey::any(), "general-fallback"),
        ];
        for (key, label) in candidates {
            if let Some(links) = self.contexts.get(&key) {
                return Some((links, label.to_string()));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eu_linksets() -> SubjectLinksets {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            ContextKey {
                profile: "urn:unidpp:profile:eu-battery".into(),
                role: "machine-verifier".into(),
                language: "en".into(),
                region: "EU".into(),
            },
            vec![Link {
                href: "https://eu-mirror.unidpp.org/dpp/pack-0001".into(),
                rel: "served-view".into(),
            }],
        );
        contexts.insert(
            ContextKey {
                profile: "urn:unidpp:profile:eu-battery".into(),
                role: "*".into(),
                language: "en".into(),
                region: "EU".into(),
            },
            vec![Link {
                href: "https://public.unidpp.org/dpp/pack-0001".into(),
                rel: "presentation".into(),
            }],
        );
        contexts.insert(
            ContextKey {
                profile: "urn:unidpp:profile:eu-battery".into(),
                role: "machine-verifier".into(),
                language: "*".into(),
                region: "EU".into(),
            },
            vec![Link {
                href: "https://eu-mirror.unidpp.org/dpp/pack-0001?lang=any".into(),
                rel: "served-view".into(),
            }],
        );
        contexts.insert(
            ContextKey::any(),
            vec![Link {
                href: "https://registry.unidpp.org/dpp/pack-0001".into(),
                rel: "served-view".into(),
            }],
        );
        SubjectLinksets {
            subject: "urn:unidpp:passport:pack-0001".into(),
            contexts,
            as_of: "2030-06-01T00:00:00Z".into(),
            dark: false,
        }
    }

    // FD-2's verify: one identity, multiple destinations, correct
    // defaulting; dark identities never resolve publicly.
    #[test]
    fn one_identity_multiple_destinations_with_stated_defaulting() {
        let sets = eu_linksets();
        // Exact: the EU mirror for the machine verifier.
        let (links, how) = sets
            .resolve(
                "urn:unidpp:profile:eu-battery",
                "machine-verifier",
                "en",
                "EU",
            )
            .unwrap();
        assert_eq!(how, "exact");
        assert_eq!(links[0].href, "https://eu-mirror.unidpp.org/dpp/pack-0001");

        // Role fallback: the any-role presentation for an unknown
        // role under the same profile and context.
        let (links, how) = sets
            .resolve("urn:unidpp:profile:eu-battery", "insurer", "en", "EU")
            .unwrap();
        assert_eq!(how, "role-fallback");
        assert_eq!(links[0].href, "https://public.unidpp.org/dpp/pack-0001");

        // Language fallback: the machine verifier in French widens
        // the language dimension.
        let (links, how) = sets
            .resolve(
                "urn:unidpp:profile:eu-battery",
                "machine-verifier",
                "fr",
                "EU",
            )
            .unwrap();
        assert_eq!(how, "language-fallback");
        assert_eq!(
            links[0].href,
            "https://eu-mirror.unidpp.org/dpp/pack-0001?lang=any"
        );

        // General fallback: an unknown profile takes the general
        // link (the registry itself).
        let (links, how) = sets
            .resolve("urn:unknown:profile", "anyone", "fr", "US")
            .unwrap();
        assert_eq!(how, "general-fallback");
        assert_eq!(links[0].href, "https://registry.unidpp.org/dpp/pack-0001");

        // The as-of stamp rides the linkset for cacheability.
        assert_eq!(sets.as_of, "2030-06-01T00:00:00Z");
    }

    // A dark identity is publicly unresolvable — its absence is
    // indistinguishable from an unknown subject.
    #[test]
    fn dark_identities_never_resolve_publicly() {
        let mut dark = eu_linksets();
        dark.dark = true;
        assert!(dark
            .resolve(
                "urn:unidpp:profile:eu-battery",
                "machine-verifier",
                "en",
                "EU"
            )
            .is_none());
        // And an unknown subject resolves nothing either.
        let mut unknown = eu_linksets();
        unknown.contexts.clear();
        assert!(unknown
            .resolve(
                "urn:unidpp:profile:eu-battery",
                "machine-verifier",
                "en",
                "EU"
            )
            .is_none());
    }
}
