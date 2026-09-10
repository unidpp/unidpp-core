//! Verification routes (SI-11), the composition law (SI-10), and
//! the layer vector (SI-9) — how a verifier gets from a question to
//! a replayable verdict.
//!
//! The route is the verification PLAN: resolution, transport,
//! documents, mappings, loci and substitutions, computed from
//! anchors and policy; execution is deterministic; the executed
//! route is the coverage report's replayable trace — re-running the
//! recorded route reproduces the verdict byte-identically.
//!
//! The composition law fixes what interop a pair actually has:
//! effective level per (pair, direction, data class, time) is the
//! minimum over the layer caps and the policy/recognition cap;
//! the bottleneck layer is reported; a policy cap cannot be lifted
//! by any bridge. The layer vector describes the technical state of
//! a relationship per layer — same / bridged-by / gap.

use crate::coverage::{CoverageEntry, CoverageReport};
use unidpp_model::{sha256, CanonicalWriter};

/// The state of one layer of a relationship (SI-9).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkState {
    /// The pair shares the layer natively.
    Same,
    /// The layer is bridged by a registered mapping or transform
    /// (named by reference).
    BridgedBy(String),
    /// The layer is absent: no shared mechanism and no bridge.
    Gap,
}

/// The six layers of a relationship's technical state (SI-9).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LayerVector {
    /// How bytes travel (connected protocol, documents, relay).
    pub transport: LinkState,
    /// Whether the pair shares a request/response protocol.
    pub protocol: LinkState,
    /// Whether structures map (registered items).
    pub structure: LinkState,
    /// Whether semantics map (registered data elements).
    pub semantics: LinkState,
    /// Whether identities bridge (registered scheme bridges).
    pub identity: LinkState,
    /// Whether trust crosses (recognition of anchors).
    pub trust: LinkState,
}

/// The layers, in vector order.
pub const LAYERS: [&str; 6] = [
    "transport",
    "protocol",
    "structure",
    "semantics",
    "identity",
    "trust",
];

impl LayerVector {
    /// The vector's per-layer caps (the level each layer's state
    /// permits, before the policy cap).
    pub fn layer_caps(&self) -> [(&'static str, u8); 6] {
        let cap = |state: &LinkState| match state {
            LinkState::Same | LinkState::BridgedBy(_) => 5,
            LinkState::Gap => 0,
        };
        [
            ("transport", cap(&self.transport)),
            ("protocol", cap(&self.protocol)),
            ("structure", cap(&self.structure)),
            ("semantics", cap(&self.semantics)),
            ("identity", cap(&self.identity)),
            ("trust", cap(&self.trust)),
        ]
    }
}

/// What the composition law concluded for one (pair, class, time).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Composition {
    /// The effective harmonization level (0–5).
    pub level: u8,
    /// The layer that determined the level (None: the policy cap
    /// itself is the bottleneck).
    pub bottleneck: Option<String>,
    /// Whether the policy cap binds (a policy cap cannot be lifted
    /// by any bridge).
    pub policy_bound: bool,
}

/// The composition law (SI-10): the effective level is the minimum
/// over the layer caps and the policy/recognition cap. Bridges do
/// not lift a policy cap; a gap in any layer drops the level to
/// that layer alone.
pub fn compose(vector: &LayerVector, policy_cap: u8) -> Composition {
    let caps = vector.layer_caps();
    let mut level = policy_cap;
    let mut bottleneck = None;
    let mut policy_bound = true;
    for (layer, cap) in caps {
        if cap < level {
            level = cap;
            bottleneck = Some(layer.to_string());
            policy_bound = false;
        }
    }
    Composition {
        level,
        bottleneck,
        policy_bound,
    }
}

/// One step of a verification route (the plan, and — recorded with
/// its input digests — the replayable trace).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "step", rename_all = "kebab-case")]
pub enum RouteStep {
    /// Resolve the subject to its serving endpoints.
    Resolve {
        /// The subject being resolved.
        subject: String,
    },
    /// Carry the evidence by a transport mode (consulting the
    /// publisher's declaration — a refusal yields a gap step).
    Transport {
        /// The transport token (protocol / document / hub).
        mode: String,
        /// The counterpart the evidence travels to.
        counterpart: String,
    },
    /// Obtain a document (frozen view, dossier, attestation).
    Document {
        /// The document kind token.
        kind: String,
        /// sha256 of the document bytes obtained.
        digest: [u8; 32],
    },
    /// Substitute a sealed class with a sovereign attestation.
    Substitution {
        /// The sealed data class.
        data_class: String,
        /// The attestation service that signed the substitution.
        service: String,
    },
    /// Classify one data class into the report (the terminal step
    /// per class) — the entry as recorded, so that replay from the
    /// trace reproduces the report byte-identically.
    Classify {
        /// The entry this step recorded.
        entry: CoverageEntry,
    },
    /// A stated gap: the route could not cover this class, and the
    /// reason is part of the trace.
    Gap {
        /// The data class that could not be covered.
        data_class: String,
        /// Why (declaration refusal, missing bridge, outage…).
        reason: String,
    },
}

impl RouteStep {
    /// The step's canonical encoding (CN-1) — the trace bytes.
    fn write(&self, w: &mut CanonicalWriter) {
        match self {
            RouteStep::Resolve { subject } => {
                w.write_bytes(b"resolve");
                w.write_bytes(subject.as_bytes());
            }
            RouteStep::Transport { mode, counterpart } => {
                w.write_bytes(b"transport");
                w.write_bytes(mode.as_bytes());
                w.write_bytes(counterpart.as_bytes());
            }
            RouteStep::Document { kind, digest } => {
                w.write_bytes(b"document");
                w.write_bytes(kind.as_bytes());
                w.write_bytes(digest);
            }
            RouteStep::Substitution {
                data_class,
                service,
            } => {
                w.write_bytes(b"substitution");
                w.write_bytes(data_class.as_bytes());
                w.write_bytes(service.as_bytes());
            }
            RouteStep::Classify { entry } => {
                w.write_bytes(b"classify");
                entry.write_canonical(w);
            }
            RouteStep::Gap { data_class, reason } => {
                w.write_bytes(b"gap");
                w.write_bytes(data_class.as_bytes());
                w.write_bytes(reason.as_bytes());
            }
        }
    }
}

/// The executed route: the ordered steps. Attached to the coverage
/// report, it is the replayable trace; re-running the same steps
/// over the same inputs reproduces the verdict byte-identically.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct VerificationRoute {
    /// The steps, in execution order.
    pub steps: Vec<RouteStep>,
}

impl VerificationRoute {
    pub fn new() -> VerificationRoute {
        VerificationRoute::default()
    }

    /// Append a step.
    pub fn step(&mut self, step: RouteStep) -> &mut Self {
        self.steps.push(step);
        self
    }

    /// The route's canonical bytes (each step encoded in order).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = CanonicalWriter::new();
        let n = (self.steps.len() as u64).to_le_bytes();
        w.write_bytes(&n);
        for step in &self.steps {
            step.write(&mut w);
        }
        w.into_bytes()
    }

    /// The route's digest.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.canonical_bytes()]).0
    }

    /// Replay: re-derive the coverage report from the recorded
    /// trace alone. Deterministic — the same steps yield the same
    /// report bytes, so a re-run reproduces the verdict
    /// byte-identically (SI-11's verify clause).
    pub fn replay(&self, subject: &str, profile: &str, verified_at: &str) -> CoverageReport {
        let mut report = CoverageReport::new(subject, profile, verified_at);
        for step in &self.steps {
            if let RouteStep::Classify { entry } = step {
                report.entries.push(entry.clone());
            }
        }
        report.route = Some(self.clone());
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::EvidenceKind;

    fn battery_vector() -> LayerVector {
        LayerVector {
            transport: LinkState::Same,
            protocol: LinkState::Same,
            structure: LinkState::BridgedBy("urn:unidpp:mapping:eu-cn".into()),
            semantics: LinkState::BridgedBy("urn:unidpp:mapping:eu-cn".into()),
            identity: LinkState::Same,
            trust: LinkState::Same,
        }
    }

    // SI-10: the minimum over layers and the policy cap; the
    // bottleneck is reported; a policy cap is not lifted by bridges.
    #[test]
    fn the_composition_law_takes_the_minimum_and_names_the_bottleneck() {
        // Fully bridged vector with a generous policy: level 4 (the
        // policy binds — bridges do not lift a policy cap).
        let c = compose(&battery_vector(), 4);
        assert_eq!(c.level, 4);
        assert_eq!(c.bottleneck, None);
        assert!(c.policy_bound);

        // A structure gap drops the level to that layer only.
        let mut gapped = battery_vector();
        gapped.structure = LinkState::Gap;
        let c = compose(&gapped, 4);
        assert_eq!(c.level, 0);
        assert_eq!(c.bottleneck.as_deref(), Some("structure"));
        assert!(!c.policy_bound);

        // A transport gap is equally the bottleneck, even under an
        // open policy.
        let mut offline = battery_vector();
        offline.transport = LinkState::Gap;
        let c = compose(&offline, 5);
        assert_eq!(c.level, 0);
        assert_eq!(c.bottleneck.as_deref(), Some("transport"));
    }

    // SI-11's verify: re-running the recorded route reproduces the
    // verdict byte-identically — the report, and its digest, are
    // pure functions of the trace.
    #[test]
    fn the_recorded_route_replays_byte_identically() {
        let mut route = VerificationRoute::new();
        route
            .step(RouteStep::Resolve {
                subject: "urn:unidpp:passport:pack-0001".into(),
            })
            .step(RouteStep::Transport {
                mode: "document".into(),
                counterpart: "de-zoll".into(),
            })
            .step(RouteStep::Document {
                kind: "frozen-view".into(),
                digest: [7u8; 32],
            })
            .step(RouteStep::Substitution {
                data_class: "cn-dynamic".into(),
                service: "cn-attestation-service".into(),
            })
            .step(RouteStep::Classify {
                entry: CoverageEntry {
                    class: "eu-static".into(),
                    element_set: "urn:unidpp:elements:battery-static".into(),
                    evidence: EvidenceKind::VerifiedDirect,
                    governing_policy: "eu-static-open".into(),
                    governing_policy_version: 1,
                    reading: "conformant".into(),
                    as_of: "2030-06-01T08:30:00Z".into(),
                },
            })
            .step(RouteStep::Classify {
                entry: CoverageEntry {
                    class: "cn-dynamic".into(),
                    element_set: "urn:unidpp:elements:bms-dynamic".into(),
                    evidence: EvidenceKind::AttestedByAuthority,
                    governing_policy: "cn-dynamic-bms".into(),
                    governing_policy_version: 1,
                    reading: "pass".into(),
                    as_of: "2030-06-01T08:00:00Z".into(),
                },
            });

        let first = route.replay(
            "urn:unidpp:passport:pack-0001",
            "urn:unidpp:profile:eu-battery",
            "2030-06-01T08:30:00Z",
        );
        let second = route.replay(
            "urn:unidpp:passport:pack-0001",
            "urn:unidpp:profile:eu-battery",
            "2030-06-01T08:30:00Z",
        );
        assert_eq!(first, second);
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.entries.len(), 2);
        assert_eq!(first.entries[0].evidence, EvidenceKind::VerifiedDirect);
        assert_eq!(first.entries[1].evidence, EvidenceKind::AttestedByAuthority);
        // A gap step is part of the trace — stated, replayable.
        let mut refused = route.clone();
        refused.steps.push(RouteStep::Gap {
            data_class: "owner-private".into(),
            reason: "declaration refuses hub transport".into(),
        });
        assert_ne!(refused.digest(), route.digest());
        assert!(!refused
            .replay(
                "urn:unidpp:passport:pack-0001",
                "urn:unidpp:profile:eu-battery",
                "2030-06-01T08:30:00Z",
            )
            .canonical_bytes()
            .is_empty());
    }
}
