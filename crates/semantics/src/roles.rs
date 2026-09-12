//! The operator role model (FD-5, PLAN-OPERATORS §2): the thirty
//! roles in four families, each with its fixed rule row — what it
//! may issue, append, read, and operate — and the federation tiers
//! (T1 read, T2 service, T3 trust, T4 governance) that gate them.
//!
//! An operator credential binds roles and a tier; authorization
//! consults the catalog (first-class data — extend the table, never
//! the checking code) and refuses out-of-scope actions with the
//! role and the action named.

/// The action classes an operator can attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Issue a type passport (type tests, declared values, BoM).
    IssueTypePassport,
    /// Issue an instance or batch passport at placement.
    IssueInstancePassport,
    /// Append a lifecycle event to a passport.
    AppendEvent,
    /// Submit a recall predicate proposal (only authorities enact).
    SubmitRecallProposal,
    /// Enact a recall.
    EnactRecall,
    /// Attest conformity (as a conformity body).
    AttestConformity,
    /// Register a service in the discovery registry.
    RegisterService,
    /// Operate a registry (19135 governance).
    OperateRegistry,
    /// Operate a resolver.
    OperateResolver,
    /// Operate a transparency log.
    OperateLog,
    /// Read the full (non-blind) record of a subject.
    ReadFullRecord,
    /// Join the master list (trust federation admission).
    JoinMasterList,
    /// Sit on the dispute panel (governance).
    SitDisputePanel,
}

impl Action {
    /// The stable token.
    pub fn token(self) -> &'static str {
        match self {
            Action::IssueTypePassport => "issue-type-passport",
            Action::IssueInstancePassport => "issue-instance-passport",
            Action::AppendEvent => "append-event",
            Action::SubmitRecallProposal => "submit-recall-proposal",
            Action::EnactRecall => "enact-recall",
            Action::AttestConformity => "attest-conformity",
            Action::RegisterService => "register-service",
            Action::OperateRegistry => "operate-registry",
            Action::OperateResolver => "operate-resolver",
            Action::OperateLog => "operate-log",
            Action::ReadFullRecord => "read-full-record",
            Action::JoinMasterList => "join-master-list",
            Action::SitDisputePanel => "sit-dispute-panel",
        }
    }

    /// The minimum federation tier the action requires.
    pub fn minimum_tier(self) -> FederationTier {
        match self {
            Action::RegisterService => FederationTier::T2,
            Action::JoinMasterList => FederationTier::T3,
            Action::SitDisputePanel => FederationTier::T4,
            _ => FederationTier::T1,
        }
    }
}

/// The federation tiers (PLAN-OPERATORS §3).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum FederationTier {
    /// Read federation — anyone consumes.
    T1,
    /// Service federation — operators register services.
    T2,
    /// Trust federation — trust authorities join the master list.
    T3,
    /// Governance — registrars and control bodies.
    T4,
}

impl FederationTier {
    pub fn token(self) -> &'static str {
        match self {
            FederationTier::T1 => "t1-read",
            FederationTier::T2 => "t2-service",
            FederationTier::T3 => "t3-trust",
            FederationTier::T4 => "t4-governance",
        }
    }
}

/// The thirty roles in four families. The token is the catalog key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Role {
    /// The catalog token.
    pub token: &'static str,
}

impl Role {
    /// Construct a role reference by catalog token.
    pub const fn of(token: &'static str) -> Role {
        Role { token }
    }
}

// A. Issuance roles (1–8).
pub const MANUFACTURER: Role = Role::of("manufacturer");
pub const IMPORTER: Role = Role::of("importer");
pub const REGISTRAR: Role = Role::of("registrar");
pub const AUTHORIZED_REPRESENTATIVE: Role = Role::of("authorized-representative");
pub const TYPE_TEST_LAB: Role = Role::of("type-test-lab");
pub const CALIBRATION_BODY: Role = Role::of("calibration-body");
pub const BATCH_MAKER: Role = Role::of("batch-maker");
pub const COMPONENT_MAKER: Role = Role::of("component-maker");

// B. Lifecycle-event roles (9–16).
pub const DISTRIBUTOR: Role = Role::of("distributor");
pub const RETAILER: Role = Role::of("retailer");
pub const INDEPENDENT_REPAIRER: Role = Role::of("independent-repairer");
pub const REFURBISHER: Role = Role::of("refurbisher");
pub const RECYCLER: Role = Role::of("recycler");
pub const WASTE_OPERATOR: Role = Role::of("waste-operator");
pub const LOGISTICS_OPERATOR: Role = Role::of("logistics-operator");
pub const AUCTION_HOUSE: Role = Role::of("auction-house");

// C. Verification & attestation roles (17–23).
pub const MARKET_SURVEILLANCE: Role = Role::of("market-surveillance");
pub const CUSTOMS_AUTHORITY: Role = Role::of("customs-authority");
pub const CONFORMITY_BODY: Role = Role::of("conformity-body");
pub const NOTIFIED_BODY: Role = Role::of("notified-body");
pub const INSURER: Role = Role::of("insurer");
pub const APPRAISER: Role = Role::of("appraiser");
pub const CONSUMER: Role = Role::of("consumer");

// D. Infrastructure roles (24–30).
pub const REGISTRY_OPERATOR: Role = Role::of("registry-operator");
pub const RESOLVER_OPERATOR: Role = Role::of("resolver-operator");
pub const LOG_OPERATOR: Role = Role::of("log-operator");
pub const TRUST_AUTHORITY: Role = Role::of("trust-authority");
pub const ARCHIVE_PROVIDER: Role = Role::of("archive-provider");
pub const HOSTING_PROVIDER: Role = Role::of("hosting-provider");
pub const DISPUTE_PANELIST: Role = Role::of("dispute-panelist");

/// The catalog: role → the actions its rule row admits. First-class
/// data; adding a role extends the table, never the checker.
pub fn role_catalog() -> &'static [(Role, &'static [Action])] {
    &[
        (
            MANUFACTURER,
            &[
                Action::IssueTypePassport,
                Action::IssueInstancePassport,
                Action::AppendEvent,
                Action::SubmitRecallProposal,
                Action::RegisterService,
            ],
        ),
        (
            IMPORTER,
            &[Action::IssueInstancePassport, Action::AppendEvent],
        ),
        (
            REGISTRAR,
            &[Action::OperateRegistry, Action::SitDisputePanel],
        ),
        (
            AUTHORIZED_REPRESENTATIVE,
            &[Action::AppendEvent, Action::SubmitRecallProposal],
        ),
        (TYPE_TEST_LAB, &[Action::AttestConformity]),
        (CALIBRATION_BODY, &[Action::AttestConformity]),
        (
            BATCH_MAKER,
            &[Action::IssueInstancePassport, Action::AppendEvent],
        ),
        (
            COMPONENT_MAKER,
            &[Action::IssueInstancePassport, Action::AppendEvent],
        ),
        (DISTRIBUTOR, &[Action::AppendEvent]),
        (RETAILER, &[Action::AppendEvent]),
        (INDEPENDENT_REPAIRER, &[Action::AppendEvent]),
        (REFURBISHER, &[Action::AppendEvent]),
        (RECYCLER, &[Action::AppendEvent]),
        (WASTE_OPERATOR, &[Action::AppendEvent]),
        (LOGISTICS_OPERATOR, &[Action::AppendEvent]),
        (
            AUCTION_HOUSE,
            &[Action::AppendEvent, Action::ReadFullRecord],
        ),
        (
            MARKET_SURVEILLANCE,
            &[
                Action::ReadFullRecord,
                Action::EnactRecall,
                Action::SubmitRecallProposal,
            ],
        ),
        (CUSTOMS_AUTHORITY, &[Action::ReadFullRecord]),
        (CONFORMITY_BODY, &[Action::AttestConformity]),
        (NOTIFIED_BODY, &[Action::AttestConformity]),
        (INSURER, &[Action::ReadFullRecord]),
        (APPRAISER, &[Action::ReadFullRecord]),
        (CONSUMER, &[]),
        (
            REGISTRY_OPERATOR,
            &[Action::OperateRegistry, Action::RegisterService],
        ),
        (
            RESOLVER_OPERATOR,
            &[Action::OperateResolver, Action::RegisterService],
        ),
        (LOG_OPERATOR, &[Action::OperateLog, Action::RegisterService]),
        (
            TRUST_AUTHORITY,
            &[Action::JoinMasterList, Action::RegisterService],
        ),
        (ARCHIVE_PROVIDER, &[Action::RegisterService]),
        (HOSTING_PROVIDER, &[Action::RegisterService]),
        (DISPUTE_PANELIST, &[Action::SitDisputePanel]),
    ]
}

/// An operator's credential: the role tokens it holds and its
/// federation tier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleCredential {
    /// The credential holder (operator id).
    pub operator: String,
    /// The role tokens bound to this credential (catalog keys).
    pub roles: Vec<String>,
    /// The federation tier attained.
    pub tier: FederationTier,
}

/// What an authorization concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// Permitted (the admitting role named).
    Permitted(Role),
    /// Refused — no held role admits the action; the nearest
    /// holders are named for audit.
    NoRoleAdmits {
        /// The action attempted.
        action: &'static str,
    },
    /// Refused — a held role admits the action but the credential's
    /// federation tier is below the action's requirement.
    TierTooLow {
        /// The admitting role.
        role: Role,
        /// The required tier.
        required: FederationTier,
        /// The held tier.
        held: FederationTier,
    },
}

/// Authorize an action under a credential (FD-5's verify: refusal
/// names the role — here, the admitting role and the tier gap, or
/// the absence of any admitting role).
pub fn authorize(credential: &RoleCredential, action: Action) -> Authorization {
    let admitting = credential.roles.iter().find_map(|token| {
        role_catalog()
            .iter()
            .find(|(r, actions)| r.token == token && actions.contains(&action))
    });
    match admitting {
        Some((role, _)) => {
            let required = action.minimum_tier();
            if credential.tier >= required {
                Authorization::Permitted(*role)
            } else {
                Authorization::TierTooLow {
                    role: *role,
                    required,
                    held: credential.tier,
                }
            }
        }
        None => Authorization::NoRoleAdmits {
            action: action.token(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(roles: &[Role], tier: FederationTier) -> RoleCredential {
        RoleCredential {
            operator: "op-1".into(),
            roles: roles.iter().map(|r| r.token.to_string()).collect(),
            tier,
        }
    }

    // The catalog covers thirty roles in four families.
    #[test]
    fn the_catalog_covers_thirty_roles() {
        assert_eq!(role_catalog().len(), 30);
        let families = [
            (0, 8, "issuance"),
            (8, 16, "lifecycle"),
            (16, 23, "verification"),
            (23, 30, "infrastructure"),
        ];
        for (from, to, _name) in families {
            assert!(role_catalog()[from..to]
                .iter()
                .all(|(r, _)| !r.token.is_empty()));
        }
    }

    // FD-5's verify: in-scope actions pass with the role named;
    // out-of-scope refused with the action (and role) named; tier
    // gating holds.
    #[test]
    fn authorization_admits_and_refuses_with_names() {
        // The manufacturer issues type passports.
        let maker = credential(&[MANUFACTURER], FederationTier::T2);
        assert_eq!(
            authorize(&maker, Action::IssueTypePassport),
            Authorization::Permitted(MANUFACTURER)
        );

        // Out of scope: a repairer cannot issue passports.
        let repairer = credential(&[INDEPENDENT_REPAIRER], FederationTier::T2);
        match authorize(&repairer, Action::IssueTypePassport) {
            Authorization::NoRoleAdmits { action } => {
                assert_eq!(action, "issue-type-passport");
            }
            other => panic!("expected refusal, got {other:?}"),
        }
        // ...but appends lifecycle events.
        assert_eq!(
            authorize(&repairer, Action::AppendEvent),
            Authorization::Permitted(INDEPENDENT_REPAIRER)
        );

        // Tier gating: the trust authority's role admits
        // JoinMasterList, but a T2 credential is below T3.
        let immature = credential(&[TRUST_AUTHORITY], FederationTier::T2);
        match authorize(&immature, Action::JoinMasterList) {
            Authorization::TierTooLow {
                role,
                required,
                held,
            } => {
                assert_eq!(role, TRUST_AUTHORITY);
                assert_eq!(required, FederationTier::T3);
                assert_eq!(held, FederationTier::T2);
            }
            other => panic!("expected tier refusal, got {other:?}"),
        }
        // At T3 it passes.
        let mature = credential(&[TRUST_AUTHORITY], FederationTier::T3);
        assert_eq!(
            authorize(&mature, Action::JoinMasterList),
            Authorization::Permitted(TRUST_AUTHORITY)
        );

        // A T1 reader registers nothing.
        let reader = credential(&[RESOLVER_OPERATOR], FederationTier::T1);
        assert!(matches!(
            authorize(&reader, Action::RegisterService),
            Authorization::TierTooLow { .. }
        ));

        // Market surveillance enacts recalls; a manufacturer only
        // proposes them.
        let msa = credential(&[MARKET_SURVEILLANCE], FederationTier::T1);
        assert_eq!(
            authorize(&msa, Action::EnactRecall),
            Authorization::Permitted(MARKET_SURVEILLANCE)
        );
        assert!(matches!(
            authorize(&maker, Action::EnactRecall),
            Authorization::NoRoleAdmits { .. }
        ));
        assert_eq!(
            authorize(&maker, Action::SubmitRecallProposal),
            Authorization::Permitted(MANUFACTURER)
        );

        // The consumer holds no operational action — stated.
        let consumer = credential(&[CONSUMER], FederationTier::T1);
        assert!(matches!(
            authorize(&consumer, Action::AppendEvent),
            Authorization::NoRoleAdmits { .. }
        ));
    }
}
