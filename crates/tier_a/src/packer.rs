//! Tier-A packer: deterministic encoding, budgeting against the QR
//! capacity model, multi-suite signature framing.

use unidpp_model::{CanonicalReader, CanonicalWriter};
use unidpp_model::{ModelError, SignatureSuite};

use crate::payload::TierAPayload;
use crate::qr::{byte_capacity, min_version_for, EcLevel};
use crate::TierAError;

/// A packed Tier-A carrier payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedTierA {
    bytes: Vec<u8>,
    pub version: u8,
    pub ec: EcLevel,
    /// Actual encoded length.
    pub used: usize,
    /// Projected length: placeholders expanded to each suite's canonical
    /// signature length (budgeting is conservative).
    pub projected: usize,
    pub capacity: u32,
}

impl PackedTierA {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Free bytes under the QR capacity at the selected version.
    pub fn margin(&self) -> i64 {
        self.capacity as i64 - self.projected as i64
    }
}

/// Packer configuration.
#[derive(Debug, Clone)]
pub struct TierAPacker {
    pub ec: EcLevel,
    pub max_version: u8,
}

impl Default for TierAPacker {
    fn default() -> Self {
        TierAPacker {
            ec: EcLevel::M,
            max_version: 40,
        }
    }
}

// Canonical field tags (fixed Tier-A subset).
const TAG_PRODUCT_ID: u8 = 0x01;
const TAG_RESOLVER_URI: u8 = 0x02;
const TAG_PASSPORT_ID: u8 = 0x03;
const TAG_EO_ID: u8 = 0x04;
const TAG_STATUS: u8 = 0x05;
const TAG_SAFETY: u8 = 0x06;
const TAG_VALIDITY_FROM: u8 = 0x07;
const TAG_VALIDITY_TO: u8 = 0x08;
const TAG_AS_OF: u8 = 0x09;
const TAG_LOG_HEAD: u8 = 0x0A;
const TAG_SIG_COUNT: u8 = 0x0B;
const TAG_SIG_SLOT: u8 = 0x0C;
const SIG_PLACEHOLDER: u16 = 0xFFFF;

impl TierAPacker {
    pub fn new(ec: EcLevel, max_version: u8) -> TierAPacker {
        TierAPacker { ec, max_version }
    }

    /// Encode the payload to canonical bytes. Returns the bytes plus the
    /// projected length (signature placeholders counted at canonical
    /// suite lengths).
    pub fn encode(payload: &TierAPayload) -> Result<(Vec<u8>, usize), TierAError> {
        let mut w = CanonicalWriter::new();
        w.write_tag(TAG_PRODUCT_ID);
        w.write_str(&payload.product_id.to_string());
        w.write_tag(TAG_RESOLVER_URI);
        w.write_str(&payload.resolver_uri);
        w.write_tag(TAG_PASSPORT_ID);
        w.write_str(payload.passport_id.as_str());
        w.write_tag(TAG_EO_ID);
        w.write_str(&payload.eo_id);
        w.write_tag(TAG_STATUS);
        w.write_str(&payload.status.to_string());
        w.write_tag(TAG_SAFETY);
        w.write_str(&payload.safety.to_string());
        w.write_tag(TAG_VALIDITY_FROM);
        w.write_str(&payload.validity.from.to_string());
        w.write_tag(TAG_VALIDITY_TO);
        w.write_opt_str(&payload.validity.to.map(|t| t.to_string()));
        w.write_tag(TAG_AS_OF);
        w.write_str(&payload.as_of.to_string());
        w.write_tag(TAG_LOG_HEAD);
        w.write_opt_hash(&payload.log_head);
        w.write_tag(TAG_SIG_COUNT);
        let count = payload.signatures.len().min(255);
        w.write_tag(count as u8);
        let mut projected_extra = 0usize;
        for slot in payload.signatures.iter().take(255) {
            w.write_tag(TAG_SIG_SLOT);
            w.write_tag(slot.suite.code());
            w.write_bytes(slot.key_id.as_bytes());
            match &slot.signature {
                Some(sig) => {
                    if sig.len() > u16::MAX as usize {
                        return Err(TierAError::Encode(format!(
                            "signature of {} bytes exceeds u16 length framing",
                            sig.len()
                        )));
                    }
                    w.write_u16(sig.len() as u16);
                    w.write_bytes_raw(sig);
                }
                None => {
                    w.write_u16(SIG_PLACEHOLDER);
                    // Reserve, but do not emit, the canonical signature.
                    projected_extra += slot.suite.signature_len();
                }
            }
        }
        let bytes = w.into_bytes();
        let projected = bytes.len() + projected_extra;
        Ok((bytes, projected))
    }

    /// Decode canonical bytes back into a payload.
    pub fn decode(bytes: &[u8]) -> Result<TierAPayload, TierAError> {
        let mut r = CanonicalReader::new(bytes);
        let mut product_id = None;
        let mut resolver_uri = None;
        let mut passport_id = None;
        let mut eo_id = None;
        let mut status = None;
        let mut safety = None;
        let mut validity_from = None;
        let mut validity_to = None;
        let mut as_of = None;
        let mut log_head = None;
        let mut signatures = Vec::new();
        while r.remaining() > 0 {
            match r.read_tag()? {
                TAG_PRODUCT_ID => product_id = Some(r.read_str()?.parse().map_err(TierAError::Model)?),
                TAG_RESOLVER_URI => resolver_uri = Some(r.read_str()?),
                TAG_PASSPORT_ID => {
                    passport_id = Some(unidpp_model::PassportId::new(&r.read_str()?).map_err(TierAError::Model)?)
                }
                TAG_EO_ID => eo_id = Some(r.read_str()?),
                TAG_STATUS => status = Some(r.read_str()?.parse().map_err(|e: unidpp_model::EnumParseError| TierAError::Decode(e.to_string()))?),
                TAG_SAFETY => safety = Some(r.read_str()?.parse().map_err(|e: unidpp_model::EnumParseError| TierAError::Decode(e.to_string()))?),
                TAG_VALIDITY_FROM => {
                    validity_from = Some(r.read_str()?.parse().map_err(TierAError::Model)?)
                }
                TAG_VALIDITY_TO => {
                    let s = r.read_opt_str()?;
                    if let Some(s) = s {
                        validity_to = Some(s.parse().map_err(TierAError::Model)?);
                    }
                }
                TAG_AS_OF => as_of = Some(r.read_str()?.parse().map_err(TierAError::Model)?),
                TAG_LOG_HEAD => log_head = r.read_opt_hash()?,
                TAG_SIG_COUNT => {
                    let n = r.read_tag()? as usize;
                    for _ in 0..n {
                        expect_tag(&mut r, TAG_SIG_SLOT)?;
                        let code = r.read_tag()?;
                        let suite = SignatureSuite::from_code(code)
                            .map_err(|e: ModelError| TierAError::Decode(e.to_string()))?;
                        let key = r.read_bytes()?;
                        let key_id = String::from_utf8(key)
                            .map_err(|e| TierAError::Decode(e.to_string()))?;
                        let len = r.read_u16()?;
                        let signature = if len == SIG_PLACEHOLDER {
                            None
                        } else {
                            Some(read_raw(&mut r, len as usize)?)
                        };
                        signatures.push(unidpp_model::SigSlot {
                            suite,
                            key_id,
                            signature,
                        });
                    }
                }
                t => return Err(TierAError::Decode(format!("unknown field tag {t:#04x}"))),
            }
        }
        Ok(TierAPayload {
            product_id: product_id
                .ok_or_else(|| TierAError::Decode("missing product_id".into()))?,
            resolver_uri: resolver_uri
                .ok_or_else(|| TierAError::Decode("missing resolver_uri".into()))?,
            passport_id: passport_id
                .ok_or_else(|| TierAError::Decode("missing passport_id".into()))?,
            eo_id: eo_id.ok_or_else(|| TierAError::Decode("missing eo_id".into()))?,
            status: status.ok_or_else(|| TierAError::Decode("missing status".into()))?,
            safety: safety.ok_or_else(|| TierAError::Decode("missing safety".into()))?,
            validity: unidpp_model::Interval {
                from: validity_from
                    .ok_or_else(|| TierAError::Decode("missing validity.from".into()))?,
                to: validity_to,
            },
            as_of: as_of.ok_or_else(|| TierAError::Decode("missing as_of".into()))?,
            log_head,
            signatures,
        })
    }

    /// Pack: encode, budget against the QR capacity model, select the
    /// minimal version. Fails (never silently truncates) when the
    /// projected payload exceeds the carrier.
    pub fn pack(&self, payload: &TierAPayload) -> Result<PackedTierA, TierAError> {
        let (bytes, projected) = Self::encode(payload)?;
        let capacity = byte_capacity(self.max_version, self.ec);
        if projected as u64 > capacity as u64 {
            return Err(TierAError::OverBudget {
                projected,
                capacity,
                ec: self.ec,
                max_version: self.max_version,
            });
        }
        let version = min_version_for(projected, self.ec)
            .ok_or(TierAError::OverBudget {
                projected,
                capacity,
                ec: self.ec,
                max_version: self.max_version,
            })?
            .min(self.max_version);
        Ok(PackedTierA {
            capacity: byte_capacity(version, self.ec),
            version,
            ec: self.ec,
            used: bytes.len(),
            projected,
            bytes,
        })
    }

    /// Per-field budget report (bytes actually encoded).
    pub fn budget_report(payload: &TierAPayload) -> Vec<(&'static str, usize)> {
        let mut report = vec![
            ("product_id", payload.product_id.to_string().len()),
            ("resolver_uri", payload.resolver_uri.len()),
            ("passport_id", payload.passport_id.as_str().len()),
            ("eo_id", payload.eo_id.len()),
            ("status", payload.status.to_string().len()),
            ("safety", payload.safety.to_string().len()),
            (
                "validity",
                payload.validity.from.to_string().len()
                    + payload
                        .validity
                        .to
                        .as_ref()
                        .map(|t| t.to_string().len())
                        .unwrap_or(0),
            ),
            ("as_of", payload.as_of.to_string().len()),
            ("log_head", payload.log_head.map(|_| 64).unwrap_or(0)),
        ];
        for slot in &payload.signatures {
            report.push(("sig_slot", slot.projected_len()));
        }
        report
    }
}

fn expect_tag(r: &mut CanonicalReader<'_>, tag: u8) -> Result<(), TierAError> {
    match r.read_tag() {
        Ok(t) if t == tag => Ok(()),
        Ok(t) => Err(TierAError::Decode(format!(
            "expected tag {tag:#04x}, found {t:#04x}"
        ))),
        Err(e) => Err(TierAError::Decode(e.to_string())),
    }
}

fn read_raw(r: &mut CanonicalReader<'_>, len: usize) -> Result<Vec<u8>, TierAError> {
    r.read_raw(len).map_err(|e| TierAError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::TierAPayload;
    use unidpp_event::{EventLog, SafetyFlag, Status};
    use unidpp_model::{Interval, PassportId, ProductIdentifier, SigSlot, SignatureSuite, Timestamp};

    fn sample(signatures: Vec<unidpp_model::SigSlot>) -> TierAPayload {
        TierAPayload {
            product_id: ProductIdentifier::parse("gtin:4006381333931").unwrap(),
            resolver_uri: "https://dpp.unidpp.org/r/abc123".into(),
            passport_id: PassportId::new("urn:unidpp:passport:test-1").unwrap(),
            eo_id: "eo-de-000042".into(),
            status: Status::Issued,
            safety: SafetyFlag::None,
            validity: Interval::between(
                Timestamp::from_secs(1_750_000_000),
                Timestamp::from_secs(1_850_000_000),
            )
            .unwrap(),
            as_of: Timestamp::from_secs(1_800_000_000),
            log_head: Some(unidpp_model::Hash::ZERO),
            signatures,
        }
    }

    #[test]
    fn pack_and_decode_round_trip() {
        let packer = TierAPacker::new(EcLevel::M, 40);
        let payload = sample(vec![
            SigSlot::placeholder(SignatureSuite::EcdsaP256, "k1"),
            SigSlot::placeholder(SignatureSuite::Sm2, "k2"),
        ]);
        let packed = packer.pack(&payload).unwrap();
        assert!(packed.margin() >= 0);
        let decoded = TierAPacker::decode(packed.as_slice()).unwrap();
        assert_eq!(decoded.product_id, payload.product_id);
        assert_eq!(decoded.passport_id, payload.passport_id);
        assert_eq!(decoded.status, payload.status);
        assert_eq!(decoded.safety, payload.safety);
        assert_eq!(decoded.validity, payload.validity);
        assert_eq!(decoded.as_of, payload.as_of);
        assert_eq!(decoded.log_head, payload.log_head);
        assert_eq!(decoded.signatures.len(), 2);
        assert!(decoded.signatures[0].is_framed_only());
        // Projected reserves both 64-byte signatures.
        assert_eq!(
            packed.projected,
            packed.used + 64 + 64,
            "placeholder reserves must be counted"
        );
    }

    #[test]
    fn over_budget_rejected() {
        // ML-DSA-87 alone is 4627 bytes: over any QR capacity.
        let packer = TierAPacker::new(EcLevel::L, 40);
        let payload = sample(vec![SigSlot::placeholder(SignatureSuite::MlDsa87, "k1")]);
        let err = packer.pack(&payload).unwrap_err();
        match err {
            TierAError::OverBudget { projected, capacity, .. } => {
                assert!(projected > capacity as usize);
            }
            other => panic!("expected OverBudget, got {other:?}"),
        }
    }

    #[test]
    fn budget_report_lists_fields() {
        let payload = sample(vec![SigSlot::placeholder(SignatureSuite::EcdsaP256, "k1")]);
        let report = TierAPacker::budget_report(&payload);
        assert!(report.iter().any(|(f, _)| *f == "resolver_uri"));
        assert!(report.iter().any(|(f, _)| *f == "sig_slot"));
    }

    #[test]
    fn minimal_payload_fits_low_versions() {
        let packer = TierAPacker::new(EcLevel::L, 40);
        let payload = sample(vec![]);
        let packed = packer.pack(&payload).unwrap();
        assert!(packed.version <= 12, "minimal Tier-A must be small, got v{}", packed.version);
        let _ = EventLog::new(payload.passport_id.clone());
    }
}
