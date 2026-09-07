//! Graded trust markers and multi-suite signature framing (invariant I9).
//!
//! Trust markers (PLAN.md): every element/event carries one of
//! unsigned / self-declared / third-party attested / multi-signed /
//! log-anchored. Multi-suite co-signature model: ECDSA + SM2 + ML-DSA, so
//! every jurisdiction verifies under its own crypto policy.
//!
//! The signature slots here are *framing*: suite, key id, and the byte
//! layout of each suite's signature. Actual signature computation is
//! delegated to the SIGNATIF integration (`unidpp-signatif`); this core
//! guarantees the framing and budget math are exact.

use crate::ModelError;

crate::str_enum! {
    /// Graded trust marker ladder (declaration order = grade order).
    pub enum TrustMarker {
        Unsigned => "unsigned",
        SelfDeclared => "self-declared",
        Attested => "attested",
        MultiSigned => "multi-signed",
        LogAnchored => "log-anchored",
    }
}

impl TrustMarker {
    /// Numeric grade (0..=4) on the trust ladder.
    pub fn grade(self) -> u8 {
        match self {
            TrustMarker::Unsigned => 0,
            TrustMarker::SelfDeclared => 1,
            TrustMarker::Attested => 2,
            TrustMarker::MultiSigned => 3,
            TrustMarker::LogAnchored => 4,
        }
    }

    /// Whether this marker meets or exceeds a required minimum grade.
    pub fn meets(self, minimum: TrustMarker) -> bool {
        self.grade() >= minimum.grade()
    }

    /// Derive the marker from signing evidence.
    pub fn of(
        signatures_present: usize,
        distinct_suites: usize,
        attested_by_third_party: bool,
        log_anchored: bool,
    ) -> TrustMarker {
        if log_anchored {
            TrustMarker::LogAnchored
        } else if distinct_suites >= 2 && signatures_present >= 2 {
            TrustMarker::MultiSigned
        } else if attested_by_third_party && signatures_present >= 1 {
            TrustMarker::Attested
        } else if signatures_present >= 1 {
            TrustMarker::SelfDeclared
        } else {
            TrustMarker::Unsigned
        }
    }
}

crate::str_enum! {
    /// Crypto suites in the multi-suite co-signature model.
    pub enum SignatureSuite {
        EcdsaP256 => "ecdsa-p256",
        Sm2 => "sm2",
        MlDsa44 => "ml-dsa-44",
        MlDsa65 => "ml-dsa-65",
        MlDsa87 => "ml-dsa-87",
    }
}

impl SignatureSuite {
    /// One-byte wire code for carrier framing.
    pub fn code(self) -> u8 {
        match self {
            SignatureSuite::EcdsaP256 => 1,
            SignatureSuite::Sm2 => 2,
            SignatureSuite::MlDsa44 => 3,
            SignatureSuite::MlDsa65 => 4,
            SignatureSuite::MlDsa87 => 5,
        }
    }

    pub fn from_code(code: u8) -> Result<SignatureSuite, ModelError> {
        match code {
            1 => Ok(SignatureSuite::EcdsaP256),
            2 => Ok(SignatureSuite::Sm2),
            3 => Ok(SignatureSuite::MlDsa44),
            4 => Ok(SignatureSuite::MlDsa65),
            5 => Ok(SignatureSuite::MlDsa87),
            other => Err(ModelError::Parse(format!("unknown suite code {other}"))),
        }
    }

    /// Canonical signature length in bytes (ECDSA/SM2: r||s; ML-DSA per
    /// FIPS 204 parameter sets).
    pub fn signature_len(self) -> usize {
        match self {
            SignatureSuite::EcdsaP256 | SignatureSuite::Sm2 => 64,
            SignatureSuite::MlDsa44 => 2420,
            SignatureSuite::MlDsa65 => 3309,
            SignatureSuite::MlDsa87 => 4627,
        }
    }
}

/// One framed signature slot. `signature: None` marks a placeholder that
/// the SIGNATIF layer fills; budgeting always reserves the suite's full
/// canonical signature length.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SigSlot {
    pub suite: SignatureSuite,
    pub key_id: String,
    pub signature: Option<Vec<u8>>,
}

impl SigSlot {
    pub fn placeholder(suite: SignatureSuite, key_id: &str) -> SigSlot {
        SigSlot {
            suite,
            key_id: key_id.to_string(),
            signature: None,
        }
    }

    pub fn is_framed_only(&self) -> bool {
        self.signature.is_none()
    }

    /// Bytes the filled slot occupies on a carrier.
    pub fn projected_len(&self) -> usize {
        1 + 1 + self.key_id.len() + 2 + match &self.signature {
            Some(sig) => sig.len(),
            None => self.suite.signature_len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_order_and_meets() {
        assert!(TrustMarker::LogAnchored > TrustMarker::MultiSigned);
        assert!(TrustMarker::MultiSigned > TrustMarker::Attested);
        assert!(TrustMarker::Attested > TrustMarker::SelfDeclared);
        assert!(TrustMarker::SelfDeclared > TrustMarker::Unsigned);
        assert!(TrustMarker::Attested.meets(TrustMarker::Attested));
        assert!(!TrustMarker::Attested.meets(TrustMarker::MultiSigned));
    }

    #[test]
    fn marker_derivation() {
        assert_eq!(TrustMarker::of(0, 0, false, false), TrustMarker::Unsigned);
        assert_eq!(TrustMarker::of(1, 1, false, false), TrustMarker::SelfDeclared);
        assert_eq!(TrustMarker::of(1, 1, true, false), TrustMarker::Attested);
        assert_eq!(TrustMarker::of(2, 2, true, false), TrustMarker::MultiSigned);
        assert_eq!(TrustMarker::of(1, 1, false, true), TrustMarker::LogAnchored);
    }

    #[test]
    fn signature_lengths() {
        assert_eq!(SignatureSuite::EcdsaP256.signature_len(), 64);
        assert_eq!(SignatureSuite::Sm2.signature_len(), 64);
        assert_eq!(SignatureSuite::MlDsa65.signature_len(), 3309);
        assert_eq!(SignatureSuite::MlDsa87.signature_len(), 4627);
        let slot = SigSlot::placeholder(SignatureSuite::MlDsa65, "key-1");
        assert_eq!(slot.projected_len(), 1 + 1 + 5 + 2 + 3309);
        assert!(slot.is_framed_only());
    }
}
