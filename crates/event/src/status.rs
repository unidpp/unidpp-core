//! Passport status state machine (invariant I6: normative statuses,
//! defined transitions, dated applicability).

unidpp_model::str_enum! {
    /// Normative passport statuses.
    pub enum Status {
        Issued => "issued",
        Suspended => "suspended",
        Invalidated => "invalidated",
        NonConformant => "non-conformant",
        Consumed => "consumed",
        Transformed => "transformed",
        EndOfWaste => "end-of-waste",
        Archived => "archived",
    }
}

/// Whether `from -> to` is a legal transition.
///
/// - suspend / invalidate / de-conform from issued;
/// - reinstate (suspended -> issued) and re-evaluation pass
///   (non-conformant -> issued);
/// - transformation consumes inputs (issued -> consumed / transformed);
/// - end-of-waste re-entry (end-of-waste -> issued) and archival.
pub fn can_transition(from: Status, to: Status) -> bool {
    use Status::*;
    matches!(
        (from, to),
        (Issued, Suspended)
            | (Issued, Invalidated)
            | (Issued, NonConformant)
            | (Issued, Consumed)
            | (Issued, Transformed)
            | (Issued, EndOfWaste)
            | (Issued, Archived)
            | (Suspended, Issued)
            | (Suspended, Invalidated)
            | (Suspended, Archived)
            | (NonConformant, Issued)
            | (NonConformant, Invalidated)
            | (NonConformant, Archived)
            | (EndOfWaste, Issued)
            | (EndOfWaste, Archived)
            | (Consumed, Archived)
            | (Transformed, Archived)
            | (Invalidated, Archived)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> Status {
        x.parse().unwrap()
    }

    #[test]
    fn legal_moves() {
        assert!(can_transition(s("issued"), s("suspended")));
        assert!(can_transition(s("suspended"), s("issued")));
        assert!(can_transition(s("issued"), s("non-conformant")));
        assert!(can_transition(s("non-conformant"), s("issued")));
        assert!(can_transition(s("issued"), s("transformed")));
        assert!(can_transition(s("end-of-waste"), s("issued")));
    }

    #[test]
    fn illegal_moves() {
        assert!(!can_transition(s("invalidated"), s("issued")));
        assert!(!can_transition(s("consumed"), s("issued")));
        assert!(!can_transition(s("transformed"), s("issued")));
        assert!(!can_transition(s("issued"), s("issued")));
    }

    #[test]
    fn casing_normalization() {
        assert_eq!(s("NON-CONFORMANT"), Status::NonConformant);
        assert_eq!(s("End_Of_Waste"), Status::EndOfWaste);
    }
}
