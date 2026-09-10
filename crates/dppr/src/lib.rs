//! DPP-R — the client retrieval interface (Part 10, REQUIREMENTS
//! §U): how any client asks for a passport and how a deployment
//! answers.
//!
//! The most-hit interface: consumers, authenticated roles, machine
//! verifiers and officer terminals all speak it. One request shape
//! — `GET /dpp/{passport-id}` semantics carried as a typed object —
//! with profile context, as-of (absent meaning live), requested
//! data classes, representation negotiation (frozen view / served
//! view / Tier-A pack / presentation), language, and authorization
//! (absent meaning the anonymous public role). The response carries
//! its projection descriptor and, for anything WITHHELD, a coverage
//! entry or an attestation-offer pointer — never a bare refusal
//! without explanation. The error taxonomy is typed: 404 unknown
//! identity, 403 role insufficient (policy named), 410 archived
//! (Tier-C pointer), 406 context unsupported, 451 legal refusal
//! (jurisdiction and escalation reference).
//!
//! Serving is policy evaluation at retrieval time: the governing
//! segment policies' reveal classes decide what is served, withheld
//! with a pointer, or refused with a reason. Binding pluralism
//! (RT-7): an EN 18222-compatible API is ONE registered binding of
//! this capability, never the definition.

use unidpp_grid::{PolicyObject, RevealClass};
use unidpp_model::ProjectionDescriptor;

/// The negotiated representation (Accept).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Representation {
    /// A self-describing point-in-time frozen view (F1 verifiable
    /// offline).
    FrozenView,
    /// The served live view (freshness-labelled).
    ServedView,
    /// The carrier-embedded offline minimum (Tier A).
    TierAPack,
    /// A human-facing presentation per the profile's language list.
    Presentation,
}

impl Representation {
    /// The Accept token.
    pub fn token(self) -> &'static str {
        match self {
            Representation::FrozenView => "application/vnd.unidpp.frozen-view+json",
            Representation::ServedView => "application/vnd.unidpp.served-view+json",
            Representation::TierAPack => "application/vnd.unidpp.tier-a+cbor",
            Representation::Presentation => "text/html",
        }
    }
}

/// The client classes (RT-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientClass {
    /// Anonymous consumer: the public projection.
    AnonymousConsumer,
    /// An authenticated role, scoped per the role model.
    AuthenticatedRole,
    /// A machine verifier: the structured document plus anchors,
    /// through the one pipeline.
    MachineVerifier,
    /// An officer terminal: the Tier-A pack, fully offline.
    OfficerTerminal,
}

/// The retrieval request (`GET /dpp/{passport-id}` semantics).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetrievalRequest {
    /// The passport identifier.
    pub passport_id: String,
    /// The profile context the client verifies under (None: the
    /// default public context).
    pub profile_context: Option<String>,
    /// The as-of instant (None: the live view).
    pub as_of: Option<String>,
    /// The requested data classes (empty: all servable).
    pub data_classes: Vec<String>,
    /// The negotiated representation.
    pub representation: Representation,
    /// The requested language (BCP 47, script subtags included).
    pub language: Option<String>,
    /// The authorization token (None: the anonymous public role).
    pub authorization: Option<String>,
}

/// The typed error taxonomy (RT-5).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "error", rename_all = "kebab-case")]
pub enum RetrievalError {
    /// 404: the identity is unknown.
    UnknownIdentity,
    /// 403: the role is insufficient — the policy is named.
    RoleInsufficient {
        /// The policy that requires a stronger role.
        policy: String,
    },
    /// 410: the subject is archived; the Tier-C pointer is given.
    Archived {
        /// The archival package reference.
        tier_c_pointer: String,
    },
    /// 406: the requested context is not served.
    ContextUnsupported,
    /// 451: legal refusal — jurisdiction and escalation reference.
    LegalRefusal {
        /// The refusing jurisdiction.
        jurisdiction: String,
        /// Where to escalate.
        escalation: String,
    },
}

impl RetrievalError {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        match self {
            RetrievalError::UnknownIdentity => 404,
            RetrievalError::RoleInsufficient { .. } => 403,
            RetrievalError::Archived { .. } => 410,
            RetrievalError::ContextUnsupported => 406,
            RetrievalError::LegalRefusal { .. } => 451,
        }
    }
}

/// A withheld data class: the omission with its explanation — a
/// coverage entry, or an attestation-offer pointer when the policy
/// offers substitution (RT-4). Never a bare refusal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Withheld {
    /// The withheld data class.
    pub data_class: String,
    /// The governing policy, named.
    pub governing_policy: String,
    /// The governing policy's version.
    pub governing_policy_version: u64,
    /// The offer pointer (the attestation service), when the policy
    /// offers substitution.
    pub offer: Option<String>,
    /// The stated reason (the reveal class in force).
    pub reason: String,
}

/// The retrieval response (RT-3/RT-4).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RetrievalResponse {
    /// The passport served.
    pub passport_id: String,
    /// The representation served.
    pub representation: Representation,
    /// The projection's five-axis descriptor.
    pub descriptor: ProjectionDescriptor,
    /// The served data classes (their contents are the projection
    /// body — carried by the binding, not re-modelled here).
    pub served: Vec<String>,
    /// The withheld classes with their explanations.
    pub withheld: Vec<Withheld>,
    /// The as-of stamp of the served state (RFC 3339; the live view
    /// stamps its evaluation moment).
    pub as_of: String,
}

/// Serve one data class per its governing policy: open classes are
/// served; pairing-gated classes are served to authorized roles;
/// origin-sealed classes are withheld WITH an offer pointer; escrowed
/// classes are withheld with the escalation reference (RT-4's
/// policy evaluation at retrieval).
pub fn serve_class(
    request: &RetrievalRequest,
    data_class: &str,
    policy: &PolicyObject,
) -> Result<(), Withheld> {
    match policy.reveal {
        RevealClass::Open => Ok(()),
        RevealClass::PairingGated => {
            if request.authorization.is_some() {
                Ok(())
            } else {
                Err(Withheld {
                    data_class: data_class.to_string(),
                    governing_policy: policy.policy_id.clone(),
                    governing_policy_version: policy.version,
                    offer: None,
                    reason: "pairing-gated: an authenticated pairing role is required".into(),
                })
            }
        }
        RevealClass::OriginSealed => Err(Withheld {
            data_class: data_class.to_string(),
            governing_policy: policy.policy_id.clone(),
            governing_policy_version: policy.version,
            offer: Some(format!("{}-attestation", policy.authority)),
            reason: "origin-sealed: substitution by sovereign attestation is offered".into(),
        }),
        RevealClass::Escrowed => Err(Withheld {
            data_class: data_class.to_string(),
            governing_policy: policy.policy_id.clone(),
            governing_policy_version: policy.version,
            offer: Some(format!("{}-escrow", policy.authority)),
            reason: "escrowed: threshold-trustee ceremony required for disclosure".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(id: &str, reveal: RevealClass) -> PolicyObject {
        PolicyObject {
            policy_id: id.into(),
            version: 1,
            authority: "cn-samr".into(),
            readers: vec![],
            verifiers: vec![],
            writers: vec![],
            reveal,
            suites: vec![],
            valid_from: "2027-01-01T00:00:00Z".into(),
            valid_to: None,
            superseded_by: None,
        }
    }

    fn request() -> RetrievalRequest {
        RetrievalRequest {
            passport_id: "urn:unidpp:passport:pack-0001".into(),
            profile_context: Some("urn:unidpp:profile:eu-battery".into()),
            as_of: None,
            data_classes: vec![],
            representation: Representation::FrozenView,
            language: Some("en".into()),
            authorization: None,
        }
    }

    // RT-4: sealed classes yield omission with a coverage entry and
    // an attestation-offer pointer — never a bare refusal.
    #[test]
    fn sealed_classes_yield_omission_with_an_offer_pointer() {
        let sealed = policy("cn-dynamic-bms", RevealClass::OriginSealed);
        let err = serve_class(&request(), "cn-dynamic", &sealed).unwrap_err();
        assert_eq!(err.governing_policy, "cn-dynamic-bms");
        assert_eq!(err.governing_policy_version, 1);
        assert_eq!(err.offer.as_deref(), Some("cn-samr-attestation"));
        assert!(err.reason.contains("substitution"));

        // Escrowed classes point at the ceremony.
        let escrowed = policy("owner-private", RevealClass::Escrowed);
        let err = serve_class(&request(), "owner-private", &escrowed).unwrap_err();
        assert!(err.offer.as_deref().unwrap().contains("escrow"));

        // Open classes serve; pairing-gated serve to authorized
        // roles only (RT-2: each parameter changes the outcome).
        let open = policy("eu-static-open", RevealClass::Open);
        assert!(serve_class(&request(), "eu-static", &open).is_ok());
        let gated = policy("dealer-view", RevealClass::PairingGated);
        assert!(serve_class(&request(), "dealer-view", &gated).is_err());
        let mut authorized = request();
        authorized.authorization = Some("role:dealer".into());
        assert!(serve_class(&authorized, "dealer-view", &gated).is_ok());
    }

    // RT-5: the error taxonomy carries its statuses.
    #[test]
    fn the_error_taxonomy_is_typed_with_statuses() {
        assert_eq!(RetrievalError::UnknownIdentity.status(), 404);
        assert_eq!(
            RetrievalError::RoleInsufficient { policy: "p".into() }.status(),
            403
        );
        assert_eq!(
            RetrievalError::Archived {
                tier_c_pointer: "archive-42".into()
            }
            .status(),
            410
        );
        assert_eq!(RetrievalError::ContextUnsupported.status(), 406);
        assert_eq!(
            RetrievalError::LegalRefusal {
                jurisdiction: "CN".into(),
                escalation: "cn-samr-escrow".into()
            }
            .status(),
            451
        );
    }

    // RT-2/RT-3: the request parameters and the descriptor ride the
    // response; the Accept tokens are stable.
    #[test]
    fn representations_and_requests_round_trip() {
        assert_eq!(
            Representation::FrozenView.token(),
            "application/vnd.unidpp.frozen-view+json"
        );
        let json = serde_json::to_string(&request()).unwrap();
        assert!(json.contains("\"representation\":\"frozen-view\""));
        assert!(json.contains("\"authorization\":null"));
        let mut live = request();
        live.as_of = Some("2028-06-01T00:00:00Z".into());
        assert!(serde_json::to_string(&live).unwrap().contains("2028-06-01"));
        // The default descriptor of a frozen-view response is the
        // battery tuple's shape (point-in-time).
        let response = RetrievalResponse {
            passport_id: request().passport_id.clone(),
            representation: Representation::FrozenView,
            descriptor: unidpp_model::BATTERY_FROZEN,
            served: vec!["eu-static".into()],
            withheld: vec![],
            as_of: "2030-06-01T08:00:00Z".into(),
        };
        assert_eq!(
            response.descriptor.token(),
            "point-in-time·dynamic·direct·translated·instance"
        );
    }
}
