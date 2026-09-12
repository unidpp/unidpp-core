//! Personal-data rights, trusted time and archival (PD, TT, AR) —
//! Phase 6's lifecycle items.
//!
//! **PD** — personal data under append-only: erasure is
//! crypto-shredding — the segment's keys are destroyed; the
//! commitments remain (hashes are not facts), so the spine still
//! proves the history's shape while the plaintext is unrecoverable.
//! Minimization: personal data enters only owner-push segments.
//! Subject access: the held segment exports under the subject's
//! credential and round-trips.
//!
//! **TT** — trusted time: a notarization references verifiable time
//! (log inclusion or an external anchor); a verdict over
//! unanchorable time degrades with the reason named. Freshness
//! computations declare their clock assumption and degrade — never
//! pass — under drift beyond the declared bound.
//!
//! **AR** — archival, Tier C: a decommissioned subject exports to
//! an archival package with an integrity manifest; serializations
//! are renders (regeneration equals core state); media refresh
//! changes the media, never identity or content.

use unidpp_grid::Segment;
use unidpp_model::{sha256, CanonicalWriter};

// ---------------------------------------------------------------------------
// PD — erasure by key destruction, minimization, subject access
// ---------------------------------------------------------------------------

/// The disposition of a segment's plaintext after erasure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErasureOutcome {
    /// Erased: the keys are destroyed and the plaintext is
    /// unrecoverable; the commitment remains (the spine still
    /// proves the history's shape — hashes are not facts).
    Shredded {
        /// The segment whose keys were destroyed.
        segment: String,
        /// The commitment that remains provable.
        commitment: [u8; 32],
    },
    /// Refused: the segment is not owner-held — personal data lives
    /// in consumer-held or owner-push segments, and erasure applies
    /// only there.
    Refused {
        /// Why (the segment is shared).
        reason: String,
    },
}

/// Erase a segment by key destruction (PD-2): the caller supplies
/// the segment's sealed state and its key material; the erasure
/// destroys the keys and returns the outcome with the surviving
/// commitment. The spine is NOT rewritten — the history's shape
/// stays provable.
pub fn erase_by_shredding(
    segment_id: &str,
    sealed_state: &[u8],
    key_material: &mut Vec<u8>,
    owner_held: bool,
) -> ErasureOutcome {
    if !owner_held {
        return ErasureOutcome::Refused {
            reason: format!(
                "segment `{segment_id}` is not owner-held: personal data lives in \
                 consumer-held or owner-push segments, and erasure applies only there"
            ),
        };
    }
    // Destroy the key material (zeroized in place).
    key_material.fill(0);
    key_material.clear();
    ErasureOutcome::Shredded {
        segment: segment_id.into(),
        commitment: Segment::commit_state(sealed_state),
    }
}

/// Minimization check (PD-1): personal data may enter only
/// owner-push (or consumer-held) segments; a shared segment
/// carrying personal data is refused at intake.
pub fn minimization_ok(personal_data: bool, segment_is_owner_push: bool) -> Result<(), String> {
    if personal_data && !segment_is_owner_push {
        Err("personal data entered a shared segment: minimization requires consumer-held or owner-push segments".into())
    } else {
        Ok(())
    }
}

/// Subject access (PD-3): the held segment exports under the
/// subject's credential and round-trips.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SubjectExport {
    /// The subject.
    pub subject: String,
    /// The exported segment id.
    pub segment: String,
    /// The exported state bytes.
    pub state: Vec<u8>,
    /// sha256 under the subject's credential (binding the export to
    /// its holder).
    pub holder_binding: [u8; 32],
}

/// Export the subject's held segment.
pub fn export_subject_segment(
    subject: &str,
    segment: &str,
    state: &[u8],
    holder_credential: &[u8],
) -> SubjectExport {
    let mut w = CanonicalWriter::new();
    w.write_bytes(subject.as_bytes());
    w.write_bytes(segment.as_bytes());
    w.write_bytes(holder_credential);
    SubjectExport {
        subject: subject.into(),
        segment: segment.into(),
        state: state.to_vec(),
        holder_binding: sha256(&[&w.into_bytes()]).0,
    }
}

// ---------------------------------------------------------------------------
// TT — anchored time and clock bounds
// ---------------------------------------------------------------------------

/// What a notarization's time reference concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeStanding {
    /// Anchored: verifiable time (log inclusion or external
    /// anchor) backs the moment.
    Anchored {
        /// The anchor's kind (log-inclusion / rfc3161).
        kind: &'static str,
    },
    /// Unanchorable: the moment carries no verifiable time — the
    /// verdict over it degrades with this reason named.
    Unanchorable {
        /// Why.
        reason: String,
    },
}

/// Check a time reference (TT-1): a moment anchored by log
/// inclusion (an inclusion receipt exists) or an external anchor;
/// otherwise the verdict degrades.
pub fn time_standing(has_log_receipt: bool, has_external_anchor: bool) -> TimeStanding {
    if has_log_receipt {
        TimeStanding::Anchored {
            kind: "log-inclusion",
        }
    } else if has_external_anchor {
        TimeStanding::Anchored { kind: "rfc3161" }
    } else {
        TimeStanding::Unanchorable {
            reason: "the notarization carries no verifiable time reference: no log \
                     inclusion receipt and no external anchor"
                .into(),
        }
    }
}

/// A freshness computation's declared clock assumption (TT-2): the
/// maximum drift the verdict tolerates; beyond it the freshness
/// degrades — never passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockAssumption {
    /// The tolerated drift, in seconds.
    pub max_drift_secs: i64,
}

/// Evaluate freshness under a clock assumption: drift beyond the
/// bound degrades (stated), never silently passes.
pub fn freshness_under(
    assumption: ClockAssumption,
    observed_drift_secs: i64,
) -> Result<(), String> {
    if observed_drift_secs.abs() > assumption.max_drift_secs {
        Err(format!(
            "freshness degraded: observed drift {observed_drift_secs}s exceeds the declared \
             clock bound {}s — never pass under drift",
            assumption.max_drift_secs
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AR — archival, Tier C
// ---------------------------------------------------------------------------

/// A Tier-C archival package (AR-1): the decommissioned subject's
/// state with an integrity manifest.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ArchivalPackage {
    /// The subject.
    pub subject: String,
    /// The archived core state (canonical).
    pub core_state: Vec<u8>,
    /// The integrity manifest: sha256 over the core state.
    pub integrity_manifest: [u8; 32],
    /// The archival moment (RFC 3339).
    pub archived_at: String,
}

impl ArchivalPackage {
    /// Export a decommissioned subject to an archival package.
    pub fn export(subject: &str, core_state: &[u8], archived_at: &str) -> ArchivalPackage {
        ArchivalPackage {
            subject: subject.into(),
            core_state: core_state.to_vec(),
            integrity_manifest: sha256(&[core_state]).0,
            archived_at: archived_at.into(),
        }
    }

    /// Render a serialization from the package (AR-2: renders are
    /// regenerable — equality with a prior render proves it).
    pub fn render(&self) -> Vec<u8> {
        // AR-2: the render derives from identity and content only —
        // the archival MOMENT is package metadata, not content, so
        // a media refresh (AR-3) never changes a render.
        let mut w = CanonicalWriter::new();
        w.write_bytes(self.subject.as_bytes());
        w.write_bytes(&self.core_state);
        w.into_bytes()
    }

    /// Verify the package's integrity manifest.
    pub fn verify(&self) -> Result<(), String> {
        if sha256(&[&self.core_state]).0 == self.integrity_manifest {
            Ok(())
        } else {
            Err("archival package integrity failure: the manifest does not match the state".into())
        }
    }

    /// Media refresh (AR-3): repackage onto new media — the content
    /// and identity are unchanged, only the (out-of-band) medium.
    pub fn refresh_media(&self, refreshed_at: &str) -> ArchivalPackage {
        ArchivalPackage {
            subject: self.subject.clone(),
            core_state: self.core_state.clone(),
            integrity_manifest: self.integrity_manifest,
            archived_at: refreshed_at.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_grid::Spine;
    use unidpp_model::time::Timestamp;

    // PD-2's verify: post-erasure, plaintext is unrecoverable while
    // the spine still proves the history's shape.
    #[test]
    fn erasure_shreds_keys_and_keeps_the_shape_provable() {
        let sealed = b"owner-notes: charging telemetry, home address";
        let mut keys = vec![0x42u8; 32];
        match erase_by_shredding("owner-private", sealed, &mut keys, true) {
            ErasureOutcome::Shredded {
                segment,
                commitment,
            } => {
                assert_eq!(segment, "owner-private");
                assert_eq!(commitment, Segment::commit_state(sealed));
            }
            other => panic!("expected shredding, got {other:?}"),
        }
        // The key material is destroyed — the plaintext is
        // unrecoverable.
        assert!(keys.is_empty());
        // The spine still proves the shape: the commitment remains
        // an inclusion-provable leaf.
        let mut commitments = std::collections::BTreeMap::new();
        commitments.insert("owner-private".to_string(), Segment::commit_state(sealed));
        let spine = Spine::over(1, commitments);
        assert!(spine
            .proof("owner-private")
            .unwrap()
            .verifies_against(&spine.root));

        // A shared segment refuses erasure (PD-1's minimization is
        // the same boundary).
        let mut keys = vec![0x42u8; 32];
        match erase_by_shredding("shared-facts", sealed, &mut keys, false) {
            ErasureOutcome::Refused { reason } => {
                assert!(reason.contains("not owner-held"), "{reason}");
                assert!(!keys.is_empty(), "no keys destroyed on refusal");
            }
            other => panic!("expected refusal, got {other:?}"),
        }
        // Minimization: personal data only in owner-push segments.
        assert!(minimization_ok(true, true).is_ok());
        assert!(minimization_ok(false, false).is_ok());
        assert!(minimization_ok(true, false).is_err());
    }

    // PD-3's verify: the held segment exports under the subject's
    // credential and round-trips.
    #[test]
    fn subject_exports_round_trip_under_their_credential() {
        let export = export_subject_segment(
            "urn:unidpp:passport:pack-0001",
            "owner-private",
            b"telemetry",
            b"subject-credential-1",
        );
        let text = serde_json::to_string(&export).unwrap();
        let back: SubjectExport = serde_json::from_str(&text).unwrap();
        assert_eq!(back, export);
        // A different credential binds differently.
        let other = export_subject_segment(
            "urn:unidpp:passport:pack-0001",
            "owner-private",
            b"telemetry",
            b"subject-credential-2",
        );
        assert_ne!(other.holder_binding, export.holder_binding);
    }

    // TT-1's verify: a verdict over unanchorable time degrades with
    // the reason named. TT-2's: injected drift degrades freshness.
    #[test]
    fn unanchorable_time_and_drift_degrade_named() {
        assert!(matches!(
            time_standing(true, false),
            TimeStanding::Anchored {
                kind: "log-inclusion"
            }
        ));
        assert!(matches!(
            time_standing(false, true),
            TimeStanding::Anchored { kind: "rfc3161" }
        ));
        match time_standing(false, false) {
            TimeStanding::Unanchorable { reason } => {
                assert!(reason.contains("no verifiable time"), "{reason}")
            }
            other => panic!("expected degradation, got {other:?}"),
        }
        let clock = ClockAssumption { max_drift_secs: 30 };
        assert!(freshness_under(clock, 10).is_ok());
        let err = freshness_under(clock, 45).unwrap_err();
        assert!(err.contains("45s") && err.contains("30s"), "{err}");
        // Negative drift (a slow clock) degrades equally.
        assert!(freshness_under(clock, -45).is_err());
    }

    // AR-1..3: the package carries an integrity manifest; renders
    // are deterministic (regeneration equals the prior render);
    // media refresh changes nothing of content or identity.
    #[test]
    fn archival_packages_manifest_render_and_refresh() {
        let package = ArchivalPackage::export(
            "urn:unidpp:passport:pack-0001",
            b"core state bytes",
            "2033-01-01T00:00:00Z",
        );
        package.verify().unwrap();
        // Renders are regenerable: two renders are byte-equal.
        assert_eq!(package.render(), package.render());
        // A tampered package fails its manifest.
        let mut tampered = package.clone();
        tampered.core_state = b"edited".to_vec();
        assert!(tampered.verify().is_err());
        // Media refresh: identity and content unchanged.
        let refreshed = package.refresh_media("2040-01-01T00:00:00Z");
        assert_eq!(refreshed.integrity_manifest, package.integrity_manifest);
        assert_eq!(refreshed.core_state, package.core_state);
        assert_eq!(refreshed.render(), package.render());
        assert_ne!(refreshed.archived_at, package.archived_at);
        // The timestamps parse.
        assert!(Timestamp::parse(&package.archived_at).is_ok());
    }
}
