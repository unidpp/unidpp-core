//! Signed roll-up attestations for deep-graph profiles.
//!
//! Deep graphs are not served by flattening them: a parent's profile
//! view is an **aggregate over a committed traversal set** — the
//! ordered set of (child passport, version, state hash) the roll-up
//! covers, hashed into a Merkle root. The attestation carries the
//! subject (the parent), the traversal-set root, the computed
//! aggregate values (sums over labelled member quantities), a cited
//! method reference, and one signature slot. Any single member's
//! inclusion is spot-checkable from a sibling path without the rest of
//! the set; a tampered member changes the leaf, the root, and the
//! attestation's binding to its set.
//!
//! Layering: this module is pure data + hashing + aggregation (no
//! cryptographic dependencies — the crate sits below the trust layer).
//! The signature slot is the core's [`SigSlot`] type; its bytes cover
//! [`RollupAttestation::canonical_body`]. Real signing and
//! verification live in `unidpp-signatif` (which depends on this
//! crate); [`verify_rollup`] takes the slot check as a predicate so
//! the structural verification here is complete and testable on its
//! own.

use unidpp_model::{sha256, Hash, PassportId, SigSlot, Timestamp};

use crate::quantity::{Quantity, UnitRegistry};
use crate::TransformError;

/// One member of a traversal set: the child passport, the version of
/// its passport document, the as-of state hash of its event log, and
/// the labelled quantities the roll-up aggregates over.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TraversalMember {
    pub passport: PassportId,
    pub version: u64,
    pub state_hash: Hash,
    /// Labelled measured quantities (label → quantity), e.g.
    /// `"recycled-content-mass" → 120 g`. Labels are data-point names;
    /// every member that contributes to an aggregate carries the same
    /// label.
    pub quantities: std::collections::BTreeMap<String, Quantity>,
}

impl TraversalMember {
    /// The canonical leaf bytes: everything about the member, in
    /// declaration order, length-prefixed so no field can bleed into
    /// the next.
    pub fn leaf_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        extend(&mut buf, self.passport.as_str().as_bytes());
        extend(&mut buf, &self.version.to_le_bytes());
        extend(&mut buf, &self.state_hash.0);
        for (label, quantity) in &self.quantities {
            extend(&mut buf, label.as_bytes());
            extend(&mut buf, quantity.amount.to_string().as_bytes());
            extend(&mut buf, quantity.unit.uom.as_bytes());
        }
        buf
    }
}

fn extend(buf: &mut Vec<u8>, part: &[u8]) {
    buf.extend_from_slice(&(part.len() as u64).to_le_bytes());
    buf.extend_from_slice(part);
}

/// The ordered traversal set a roll-up covers, plus its Merkle root.
///
/// Order is canonical (by passport id) so every party that lists the
/// same children derives the same root.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TraversalSet {
    members: Vec<TraversalMember>,
}

impl TraversalSet {
    /// Assemble a traversal set (duplicates by passport id are
    /// rejected; the set is stored in canonical passport-id order).
    pub fn new(mut members: Vec<TraversalMember>) -> Result<TraversalSet, TransformError> {
        if members.is_empty() {
            return Err(TransformError::Empty(
                "a traversal set needs at least one member".into(),
            ));
        }
        members.sort_by(|a, b| a.passport.as_str().cmp(b.passport.as_str()));
        for pair in members.windows(2) {
            if pair[0].passport == pair[1].passport {
                return Err(TransformError::Provenance(format!(
                    "duplicate traversal member {}",
                    pair[0].passport
                )));
            }
        }
        Ok(TraversalSet { members })
    }

    /// The members, canonical order.
    pub fn members(&self) -> &[TraversalMember] {
        &self.members
    }

    /// The Merkle root over the member leaves.
    pub fn root(&self) -> Hash {
        let mut level: Vec<Hash> = self
            .members
            .iter()
            .map(|m| sha256(&[b"UNIDPP/ROLLUP/LEAF|", &m.leaf_bytes()]))
            .collect();
        while level.len() > 1 {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for pair in level.chunks(2) {
                let (left, right) = match pair {
                    [l, r] => (l, r),
                    [l] => (l, l), // odd node promoted by duplication
                    _ => unreachable!("chunks(2) yields 1 or 2"),
                };
                next.push(sha256(&[b"UNIDPP/ROLLUP/NODE|", &left.0, &right.0]));
            }
            level = next;
        }
        level[0]
    }

    /// The sibling path proving member `index`'s inclusion in `root`
    /// (the co-path, leaf order — recompute leaf by leaf up the tree).
    pub fn inclusion_proof(&self, index: usize) -> Option<Vec<Hash>> {
        if index >= self.members.len() {
            return None;
        }
        let mut level: Vec<Hash> = self
            .members
            .iter()
            .map(|m| sha256(&[b"UNIDPP/ROLLUP/LEAF|", &m.leaf_bytes()]))
            .collect();
        let mut idx = index;
        let mut proof = Vec::new();
        while level.len() > 1 {
            let sibling = if idx % 2 == 0 {
                (idx + 1).min(level.len() - 1)
            } else {
                idx - 1
            };
            proof.push(level[sibling]);
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for pair in level.chunks(2) {
                let (l, r) = match pair {
                    [l, r] => (l, r),
                    [l] => (l, l),
                    _ => unreachable!(),
                };
                next.push(sha256(&[b"UNIDPP/ROLLUP/NODE|", &l.0, &r.0]));
            }
            level = next;
            idx /= 2;
        }
        Some(proof)
    }

    /// Spot-check one member's inclusion against a root without the
    /// rest of the set: fold the leaf through the sibling path.
    pub fn verify_inclusion(
        member: &TraversalMember,
        index: usize,
        set_size: usize,
        proof: &[Hash],
        root: &Hash,
    ) -> bool {
        let mut node = sha256(&[b"UNIDPP/ROLLUP/LEAF|", &member.leaf_bytes()]);
        let mut idx = index;
        let mut size = set_size;
        for sibling in proof {
            // Right sibling when the node is a left child; left
            // sibling otherwise (mirrors the construction, including
            // odd-node duplication at the tail).
            let is_left = idx % 2 == 0;
            let (l, r) = if is_left {
                (&node, sibling)
            } else {
                (sibling, &node)
            };
            node = sha256(&[b"UNIDPP/ROLLUP/NODE|", &l.0, &r.0]);
            idx /= 2;
            size = (size + 1) / 2;
        }
        size == 1 && &node == root
    }
}

/// One aggregate value carried by the attestation: a labelled sum over
/// the traversal set.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AggregateValue {
    /// The data-point label being aggregated (matches member quantity
    /// labels).
    pub label: String,
    /// The summed quantity.
    pub quantity: Quantity,
}

/// A signed roll-up attestation: the parent's committed view over its
/// traversal set.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RollupAttestation {
    /// The parent passport the roll-up describes.
    pub subject: PassportId,
    /// The Merkle root of the covered traversal set.
    pub traversal_set_root: Hash,
    /// The number of members in the covered set (binds the root to a
    /// set size; a different-size set with the same root is a
    /// different attestation).
    pub member_count: usize,
    /// The computed aggregates.
    pub aggregates: Vec<AggregateValue>,
    /// The cited method reference (the registered transform or the
    /// method standard the aggregation follows, e.g.
    /// `urn:unidpp:transform:recycled-content-sum` or an ISO clause
    /// URN). Aggregation without a method citation is not a roll-up.
    pub method_ref: String,
    /// The attester (passport or EO id of the signing party).
    pub attester: String,
    /// When the attestation was made.
    pub signed_at: Timestamp,
    /// The attester's signature over [`Self::canonical_body`] (the
    /// core slot type; signing happens in the trust layer).
    pub signature: SigSlot,
}

impl RollupAttestation {
    /// Build the unsigned attestation over a traversal set: commits to
    /// the root, the member count, and the computed aggregates (every
    /// label present on any member, summed across the set in canonical
    /// units). The signature slot starts as a placeholder for the
    /// attester's key id.
    pub fn build(
        subject: PassportId,
        set: &TraversalSet,
        method_ref: &str,
        attester: &str,
        registry: &UnitRegistry,
    ) -> Result<(RollupAttestation, Vec<u8>), TransformError> {
        if method_ref.trim().is_empty() {
            return Err(TransformError::Empty(
                "a roll-up cites its method (method_ref is required)".into(),
            ));
        }
        if attester.trim().is_empty() {
            return Err(TransformError::Empty("a roll-up names its attester".into()));
        }
        let aggregates = aggregate_set(set, registry)?;
        let attestation = RollupAttestation {
            subject,
            traversal_set_root: set.root(),
            member_count: set.members().len(),
            aggregates,
            method_ref: method_ref.trim().to_string(),
            attester: attester.trim().to_string(),
            signed_at: Timestamp::now(),
            signature: SigSlot::placeholder(unidpp_model::SignatureSuite::EcdsaP256, "unassigned"),
        };
        let body = attestation.canonical_body();
        Ok((attestation, body))
    }

    /// The canonical bytes the signature covers: every field that
    /// binds the attestation to its subject, set, aggregates, method,
    /// attester, and moment — length-prefixed, declaration order.
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        extend(&mut buf, self.subject.as_str().as_bytes());
        extend(&mut buf, &self.traversal_set_root.0);
        extend(&mut buf, &self.member_count.to_le_bytes());
        for aggregate in &self.aggregates {
            extend(&mut buf, aggregate.label.as_bytes());
            extend(&mut buf, aggregate.quantity.amount.to_string().as_bytes());
            extend(&mut buf, aggregate.quantity.unit.uom.as_bytes());
        }
        extend(&mut buf, self.method_ref.as_bytes());
        extend(&mut buf, self.attester.as_bytes());
        extend(&mut buf, self.signed_at.to_string().as_bytes());
        buf
    }

    /// Fill the signature slot (the trust layer signs the canonical
    /// body and installs the result here).
    pub fn install_signature(&mut self, slot: SigSlot) {
        self.signature = slot;
    }
}

/// Sum every label present on any member, in canonical units.
fn aggregate_set(
    set: &TraversalSet,
    registry: &UnitRegistry,
) -> Result<Vec<AggregateValue>, TransformError> {
    let mut labels: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for member in set.members() {
        labels.extend(member.quantities.keys().cloned());
    }
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        let mut total: Option<Quantity> = None;
        for member in set.members() {
            let Some(quantity) = member.quantities.get(&label) else {
                continue; // members without the label contribute nothing
            };
            total = Some(match total {
                None => quantity.clone(),
                Some(acc) => acc.add(quantity, registry)?,
            });
        }
        let quantity = total.ok_or_else(|| {
            TransformError::Provenance(format!("label `{label}` vanished during aggregation"))
        })?;
        out.push(AggregateValue { label, quantity });
    }
    Ok(out)
}

/// The structural verification outcome of [`verify_rollup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollupVerdict {
    /// Root, count, aggregates, and signature all hold.
    Verified,
    /// The attestation's root does not commit to this traversal set.
    RootMismatch,
    /// The attestation covers a different number of members.
    MemberCountMismatch { attested: usize, actual: usize },
    /// An aggregate does not recompute over the set.
    AggregateMismatch {
        label: String,
        attested: String,
        computed: String,
    },
    /// The signature predicate refused the slot (the trust layer's
    /// check: wrong anchor, invalid value, framed-only).
    SignatureRejected(String),
}

/// Verify a roll-up attestation against a traversal set: recompute the
/// root and the aggregates, then hand the signature slot and the
/// canonical body to `verify_signature` (the trust layer's real
/// cryptographic check — this crate has no crypto by design).
pub fn verify_rollup(
    attestation: &RollupAttestation,
    set: &TraversalSet,
    registry: &UnitRegistry,
    verify_signature: impl FnOnce(&SigSlot, &[u8]) -> Result<(), String>,
) -> RollupVerdict {
    if attestation.traversal_set_root != set.root() {
        return RollupVerdict::RootMismatch;
    }
    if attestation.member_count != set.members().len() {
        return RollupVerdict::MemberCountMismatch {
            attested: attestation.member_count,
            actual: set.members().len(),
        };
    }
    let computed = match aggregate_set(set, registry) {
        Ok(aggregates) => aggregates,
        Err(e) => {
            return RollupVerdict::AggregateMismatch {
                label: "*".to_string(),
                attested: "n/a".to_string(),
                computed: e.to_string(),
            }
        }
    };
    if attestation.aggregates.len() != computed.len() {
        return RollupVerdict::AggregateMismatch {
            label: "*".to_string(),
            attested: attestation.aggregates.len().to_string(),
            computed: computed.len().to_string(),
        };
    }
    for (attested, want) in attestation.aggregates.iter().zip(&computed) {
        if attested.label != want.label {
            return RollupVerdict::AggregateMismatch {
                label: attested.label.clone(),
                attested: attested.label.clone(),
                computed: want.label.clone(),
            };
        }
        if attested.quantity != want.quantity {
            return RollupVerdict::AggregateMismatch {
                label: attested.label.clone(),
                attested: attested.quantity.amount.to_string(),
                computed: want.quantity.amount.to_string(),
            };
        }
    }
    let body = attestation.canonical_body();
    if let Err(why) = verify_signature(&attestation.signature, &body) {
        return RollupVerdict::SignatureRejected(why);
    }
    RollupVerdict::Verified
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantity::{Quantity, UnitRegistry};

    fn registry() -> UnitRegistry {
        UnitRegistry::iso80000()
    }

    fn member(tag: &str, grams: &str) -> TraversalMember {
        let mut quantities = std::collections::BTreeMap::new();
        quantities.insert(
            "recycled-content-mass".to_string(),
            Quantity::parse(grams, "g", &UnitRegistry::iso80000()).unwrap(),
        );
        TraversalMember {
            passport: PassportId::new(&format!("urn:unidpp:passport:{tag}")).unwrap(),
            version: 1,
            state_hash: sha256(&[tag.as_bytes()]),
            quantities,
        }
    }

    fn three_child_set() -> TraversalSet {
        TraversalSet::new(vec![
            member("cell-a", "120"),
            member("cell-b", "80"),
            member("cell-c", "100"),
        ])
        .unwrap()
    }

    fn ok_signature(_slot: &SigSlot, _body: &[u8]) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn rollup_round_trip_verifies() {
        let set = three_child_set();
        let (mut attestation, body) = RollupAttestation::build(
            PassportId::new("urn:unidpp:passport:pack").unwrap(),
            &set,
            "urn:unidpp:transform:recycled-content-sum",
            "urn:unidpp:passport:recycler",
            &registry(),
        )
        .unwrap();
        assert_eq!(attestation.member_count, 3);
        assert_eq!(attestation.aggregates.len(), 1);
        assert_eq!(attestation.aggregates[0].label, "recycled-content-mass");
        assert_eq!(attestation.aggregates[0].quantity.amount.to_string(), "300");
        // The pre-signature body is exactly the canonical body of the
        // attestation it builds.
        assert_eq!(body, attestation.canonical_body());
        attestation.install_signature(SigSlot::placeholder(
            unidpp_model::SignatureSuite::EcdsaP256,
            "k-test",
        ));
        assert_eq!(
            verify_rollup(&attestation, &set, &registry(), ok_signature),
            RollupVerdict::Verified
        );
    }

    #[test]
    fn inclusion_proof_verifies_for_every_member() {
        let set = three_child_set();
        let root = set.root();
        for (index, member) in set.members().iter().enumerate() {
            let proof = set.inclusion_proof(index).unwrap();
            assert!(
                TraversalSet::verify_inclusion(member, index, set.members().len(), &proof, &root),
                "member {index} must prove inclusion"
            );
        }
    }

    #[test]
    fn tampered_member_breaks_the_root() {
        let set = three_child_set();
        let (mut attestation, _) = RollupAttestation::build(
            PassportId::new("urn:unidpp:passport:pack").unwrap(),
            &set,
            "urn:unidpp:transform:recycled-content-sum",
            "urn:unidpp:passport:recycler",
            &registry(),
        )
        .unwrap();
        attestation.install_signature(SigSlot::placeholder(
            unidpp_model::SignatureSuite::EcdsaP256,
            "k-test",
        ));
        // Tamper one child's quantity: same passports, same set size,
        // different member bytes — the root changes, so the attestation
        // no longer commits to the set.
        let mut tampered = member("cell-b", "999");
        tampered.version = set.members()[1].version;
        tampered.state_hash = set.members()[1].state_hash;
        let tampered_set = TraversalSet::new(vec![
            member("cell-a", "120"),
            tampered,
            member("cell-c", "100"),
        ])
        .unwrap();
        assert_eq!(
            verify_rollup(&attestation, &tampered_set, &registry(), ok_signature),
            RollupVerdict::RootMismatch
        );
        // And the old root does not prove the tampered member's
        // inclusion.
        let proof = tampered_set.inclusion_proof(1).unwrap();
        assert!(!TraversalSet::verify_inclusion(
            &set.members()[1],
            1,
            tampered_set.members().len(),
            &proof,
            &tampered_set.root(),
        ));
    }

    #[test]
    fn aggregate_mismatch_and_unknown_labels_are_caught() {
        let set = three_child_set();
        let (mut attestation, _) = RollupAttestation::build(
            PassportId::new("urn:unidpp:passport:pack").unwrap(),
            &set,
            "urn:unidpp:transform:recycled-content-sum",
            "urn:unidpp:passport:recycler",
            &registry(),
        )
        .unwrap();
        attestation.install_signature(SigSlot::placeholder(
            unidpp_model::SignatureSuite::EcdsaP256,
            "k-test",
        ));
        // Claim the wrong sum: caught before the signature.
        let mut wrong = attestation.clone();
        wrong.aggregates[0].quantity.amount = "301".parse().unwrap();
        assert_eq!(
            verify_rollup(&wrong, &set, &registry(), ok_signature),
            RollupVerdict::AggregateMismatch {
                label: "recycled-content-mass".to_string(),
                attested: "301".to_string(),
                computed: "300".to_string(),
            }
        );
        // A set member count change is caught even when the root
        // happens to match (defence in depth with the root check).
        let bigger = TraversalSet::new(vec![
            member("cell-a", "120"),
            member("cell-b", "80"),
            member("cell-c", "100"),
            member("cell-d", "0"),
        ])
        .unwrap();
        assert!(!matches!(
            verify_rollup(&attestation, &bigger, &registry(), ok_signature),
            RollupVerdict::Verified
        ));
    }

    #[test]
    fn signature_predicate_failure_is_reported_not_swallowed() {
        let set = three_child_set();
        let (mut attestation, _) = RollupAttestation::build(
            PassportId::new("urn:unidpp:passport:pack").unwrap(),
            &set,
            "urn:unidpp:transform:recycled-content-sum",
            "urn:unidpp:passport:recycler",
            &registry(),
        )
        .unwrap();
        attestation.install_signature(SigSlot::placeholder(
            unidpp_model::SignatureSuite::EcdsaP256,
            "k-test",
        ));
        let verdict = verify_rollup(&attestation, &set, &registry(), |slot, _| {
            Err(format!("anchor does not pin {}", slot.key_id))
        });
        assert_eq!(
            verdict,
            RollupVerdict::SignatureRejected("anchor does not pin k-test".to_string())
        );
    }

    #[test]
    fn empty_and_duplicate_members_are_rejected() {
        assert!(TraversalSet::new(vec![]).is_err());
        let a = member("cell-a", "1");
        let a_again = member("cell-a", "1");
        assert!(TraversalSet::new(vec![a, a_again]).is_err());
    }

    #[test]
    fn canonical_order_makes_the_set_order_independent() {
        let a = three_child_set();
        let b = TraversalSet::new(vec![
            member("cell-c", "100"),
            member("cell-a", "120"),
            member("cell-b", "80"),
        ])
        .unwrap();
        assert_eq!(a.root(), b.root());
        assert_eq!(a, b);
    }
}
