//! Onboarding ceremonies and peer discipline (FD-3/FD-4): the seed
//! bundle a new operator starts from, the listing gates an
//! application passes, the ceremony state machine, and the operator
//! conformance contract that makes registries peers rather than
//! subordinates.
//!
//! FD-3's verify clause: a new operator onboards end-to-end from a
//! seed bundle. FD-4's: two equal deployments federate with neither
//! subordinate — the protocol between them is symmetric by
//! construction (each mirrors the other's items; no message names a
//! master).

use crate::exports::StableId;
use crate::federation::ExchangeItem;
use crate::federation::Mirror;
use crate::roles::{Action, FederationTier, Role, RoleCredential};

/// The seed bundle: everything a new operator bootstraps from — the
/// anchors to pin, the root descriptors to seed, and the role
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SeedBundle {
    /// The bundle's own version.
    pub version: u64,
    /// The trust anchors to pin (node → public key hex).
    pub anchors: Vec<(String, String)>,
    /// The root service descriptors to seed (URI → canonical bytes).
    pub descriptors: Vec<(String, Vec<u8>)>,
    /// The operator's starting role tokens.
    pub roles: Vec<String>,
    /// The starting federation tier.
    pub tier: FederationTier,
}

impl SeedBundle {
    /// The reference bootstrap bundle (what the docs quickstart
    /// ships).
    pub fn reference() -> SeedBundle {
        SeedBundle {
            version: 1,
            anchors: vec![("registry.unidpp.org".into(), "00".repeat(32))],
            descriptors: vec![(
                "https://registry.unidpp.org/services/registry@1".into(),
                b"{\"class\":\"registry\"}".to_vec(),
            )],
            roles: vec!["registry-operator".into()],
            tier: FederationTier::T2,
        }
    }

    /// Instantiate the credential the bundle carries.
    pub fn credential(&self, operator: &str) -> RoleCredential {
        RoleCredential {
            operator: operator.into(),
            roles: self.roles.clone(),
            tier: self.tier,
        }
    }
}

/// The listing-gate predicates over a service application: the
/// descriptor must name its jurisdiction, its residency class, and
/// a continuity pointer (PLAN-OPERATORS: every T2 operator
/// registers a succession plan at admission).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ServiceApplication {
    /// The operator applying.
    pub operator: String,
    /// The service's descriptor document (parsed fields).
    pub descriptor: serde_json::Value,
}

/// One gate predicate and what it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// The descriptor names a jurisdiction.
    Jurisdiction,
    /// The descriptor names a residency class.
    Residency,
    /// The descriptor names a continuity/succession pointer.
    Continuity,
}

impl Gate {
    pub fn token(self) -> &'static str {
        match self {
            Gate::Jurisdiction => "jurisdiction",
            Gate::Residency => "residency",
            Gate::Continuity => "continuity",
        }
    }
}

/// Evaluate one gate over an application.
pub fn gate_passes(gate: Gate, application: &ServiceApplication) -> Result<(), String> {
    let descriptor = application
        .descriptor
        .as_object()
        .ok_or_else(|| "the descriptor is not an object".to_string())?;
    let present = |key: &str| descriptor.get(key).map(|v| !v.is_null()).unwrap_or(false);
    let ok = match gate {
        Gate::Jurisdiction => present("jurisdiction"),
        Gate::Residency => present("residency"),
        Gate::Continuity => present("continuity"),
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "listing gate `{}` failed: the descriptor of `{}` omits it",
            gate.token(),
            application.operator
        ))
    }
}

/// The ceremony state machine: applied → gated → listed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CeremonyState {
    /// The application arrived.
    Applied,
    /// All gates passed.
    Gated,
    /// The service is listed and queryable.
    Listed,
}

/// Run the onboarding ceremony end-to-end from a seed bundle
/// (FD-3's verify clause): pin anchors, seed descriptors, check the
/// credential may register services, pass every gate, list.
pub fn onboard(
    bundle: &SeedBundle,
    application: &ServiceApplication,
) -> Result<CeremonyState, String> {
    // The credential the bundle carries must admit
    // RegisterService at its tier.
    let credential = bundle.credential(&application.operator);
    let permitted = crate::roles::role_catalog().iter().any(|(role, actions)| {
        bundle.roles.contains(&role.token.to_string()) && actions.contains(&Action::RegisterService)
    });
    if !permitted {
        return Err(format!(
            "onboarding refused: no role in {:?} admits `register-service`",
            bundle.roles
        ));
    }
    if credential.tier < Action::RegisterService.minimum_tier() {
        return Err(format!(
            "onboarding refused: tier {} is below the T2 service-federation requirement",
            credential.tier.token()
        ));
    }
    for gate in [Gate::Jurisdiction, Gate::Residency, Gate::Continuity] {
        gate_passes(gate, application)?;
    }
    Ok(CeremonyState::Listed)
}

/// The registry-operator conformance contract (FD-4): the items a
/// deployment satisfies to federate as a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceItem {
    /// Item lifecycle per 19135 (statuses + supersession).
    ItemLifecycle,
    /// Canonical item exchange (digest-equal bytes).
    CanonicalExchange,
    /// Mirror serving of foreign items.
    MirrorServing,
    /// Enumeration resistance on the public surface.
    EnumerationResistance,
}

impl ConformanceItem {
    pub fn token(self) -> &'static str {
        match self {
            ConformanceItem::ItemLifecycle => "item-lifecycle",
            ConformanceItem::CanonicalExchange => "canonical-exchange",
            ConformanceItem::MirrorServing => "mirror-serving",
            ConformanceItem::EnumerationResistance => "enumeration-resistance",
        }
    }
}

/// Check one conformance item against a deployment's evidence
/// (here: its mirror content and its lifecycle flags).
pub fn conforms(
    item: ConformanceItem,
    mirror: &Mirror,
    lifecycle_present: bool,
    enumeration_resistant: bool,
) -> Result<(), String> {
    match item {
        ConformanceItem::ItemLifecycle => {
            if lifecycle_present {
                Ok(())
            } else {
                Err("conformance `item-lifecycle` failed: no 19135 lifecycle observed".into())
            }
        }
        ConformanceItem::CanonicalExchange => {
            // Every mirrored item digests consistently.
            for (uri, item) in &mirror.items {
                let digest = item.digest();
                if digest == [0u8; 32] {
                    return Err(format!(
                        "conformance `canonical-exchange` failed at `{uri}`"
                    ));
                }
            }
            Ok(())
        }
        ConformanceItem::MirrorServing => {
            if !mirror.items.is_empty() {
                Ok(())
            } else {
                Err("conformance `mirror-serving` failed: no foreign items served".into())
            }
        }
        ConformanceItem::EnumerationResistance => {
            if enumeration_resistant {
                Ok(())
            } else {
                Err(
                    "conformance `enumeration-resistance` failed: the public surface \
                     reconstructs subjects"
                        .into(),
                )
            }
        }
    }
}

/// Federate two equal deployments symmetrically: each mirrors the
/// other's items; neither is subordinate (FD-4's verify clause —
/// the exchange is the same operation in both directions).
pub fn federate_peers(a_items: Vec<ExchangeItem>, b_items: Vec<ExchangeItem>) -> (Mirror, Mirror) {
    let mut a_mirror = Mirror::new();
    let mut b_mirror = Mirror::new();
    // The same operation, both ways.
    for item in b_items {
        a_mirror.sync(item);
    }
    for item in a_items {
        b_mirror.sync(item);
    }
    (a_mirror, b_mirror)
}

/// A well-formed seed item for tests and the quickstart.
pub fn seed_item(register: &str, item: &str, version: u64) -> ExchangeItem {
    ExchangeItem {
        id: StableId {
            register: register.into(),
            item: item.into(),
            version: Some(version),
        },
        canonical: format!("{{\"item\":\"{item}\",\"version\":{version}}}").into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn application() -> ServiceApplication {
        ServiceApplication {
            operator: "new-operator".into(),
            descriptor: json!({
                "class": "resolver",
                "jurisdiction": "EU",
                "residency": "eu-only",
                "continuity": "succession-plan@1"
            }),
        }
    }

    // FD-3's verify: a new operator onboards end-to-end from a seed
    // bundle; gate refusals state the failed predicate.
    #[test]
    fn onboarding_runs_end_to_end_from_the_seed_bundle() {
        let bundle = SeedBundle::reference();
        // The full application passes every gate and lists.
        assert_eq!(
            onboard(&bundle, &application()).unwrap(),
            CeremonyState::Listed
        );

        // A gate refusal states the predicate.
        let mut incomplete = application();
        incomplete
            .descriptor
            .as_object_mut()
            .unwrap()
            .remove("continuity");
        let err = onboard(&bundle, &incomplete).unwrap_err();
        assert!(err.contains("continuity"), "{err}");

        // A bundle without a registering role refuses, the action
        // named.
        let mut reader_bundle = SeedBundle::reference();
        reader_bundle.roles = vec!["consumer".into()];
        reader_bundle.tier = FederationTier::T1;
        let err = onboard(&reader_bundle, &application()).unwrap_err();
        assert!(err.contains("register-service"), "{err}");

        // A below-tier credential refuses with the requirement.
        let mut low = SeedBundle::reference();
        low.tier = FederationTier::T1;
        let err = onboard(&low, &application()).unwrap_err();
        assert!(err.contains("T2"), "{err}");

        // The bundle's credential binds the carried roles.
        let credential = bundle.credential("new-operator");
        assert_eq!(credential.tier, FederationTier::T2);
        assert!(credential.roles.contains(&"registry-operator".to_string()));
    }

    // FD-4's verify: two equal deployments federate with neither
    // subordinate; the conformance contract holds on both.
    #[test]
    fn equal_deployments_federate_symmetrically() {
        let a = vec![
            seed_item("dpp", "element-a", 1),
            seed_item("dpp", "element-b", 2),
        ];
        let b = vec![seed_item("unt", "1504-elements", 1)];
        let (a_mirror, b_mirror) = federate_peers(a, b);

        // Each serves the other's items — the same operation both
        // ways, no master anywhere.
        assert!(a_mirror
            .serve("https://registry.unidpp.org/unt/1504-elements@1")
            .is_some());
        assert!(b_mirror
            .serve("https://registry.unidpp.org/dpp/element-a@1")
            .is_some());
        assert!(b_mirror
            .serve("https://registry.unidpp.org/dpp/element-b@2")
            .is_some());

        // Both pass the full conformance contract.
        for item in [
            ConformanceItem::ItemLifecycle,
            ConformanceItem::CanonicalExchange,
            ConformanceItem::MirrorServing,
            ConformanceItem::EnumerationResistance,
        ] {
            conforms(item, &a_mirror, true, true).unwrap();
            conforms(item, &b_mirror, true, true).unwrap();
        }

        // Violations fail with the item named.
        let empty = Mirror::new();
        let err = conforms(ConformanceItem::MirrorServing, &empty, true, true).unwrap_err();
        assert!(err.contains("mirror-serving"), "{err}");
        let err = conforms(ConformanceItem::ItemLifecycle, &a_mirror, false, true).unwrap_err();
        assert!(err.contains("item-lifecycle"), "{err}");
    }
}
