//! Commitment hashes and deterministic canonical byte serialization.
//!
//! PLAN.md: "logs anchor commitments (hashes), never facts — log operators
//! cannot correlate edges". Every hash in the core is a SHA-256 commitment
//! over canonically serialized bytes; salts are supplied by the caller and
//! never persisted alongside the commitment (salt discipline is enforced by
//! the event log, not here).

use std::fmt;
use std::str::FromStr;

use crate::ModelError;

use sha2::{Digest as ShaDigest, Sha256};

/// A SHA-256 commitment (32 bytes), displayed/stored as lowercase hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0u8; 32]);

    pub fn from_slice(bytes: &[u8]) -> Option<Hash> {
        if bytes.len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(bytes);
            Some(Hash(h))
        } else {
            None
        }
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn from_hex(s: &str) -> Option<Hash> {
        let s = s.trim();
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut h = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).unwrap();
            let lo = (chunk[1] as char).to_digit(16).unwrap();
            h[i] = ((hi << 4) | lo) as u8;
        }
        Some(Hash(h))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl FromStr for Hash {
    type Err = ModelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash::from_hex(s)
            .ok_or_else(|| ModelError::Parse(format!("not a 64-char hex hash: `{s}`")))
    }
}

impl serde::Serialize for Hash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.hex())
    }
}

impl<'de> serde::Deserialize<'de> for Hash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Hash::from_hex(&s).ok_or_else(|| {
            serde::de::Error::custom(format!("not a 64-char hex hash: `{s}`"))
        })
    }
}

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    Hash(h.finalize().into())
}

/// Length-prefixed deterministic byte writer.
///
/// Used for Tier-A carrier encoding; event commitments instead hash the
/// canonical JSON serialization of the typed event (deterministic because
/// every field is an integer, string, boolean, or ordered map).
pub struct CanonicalWriter {
    buf: Vec<u8>,
}

impl CanonicalWriter {
    pub fn new() -> CanonicalWriter {
        CanonicalWriter { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn write_tag(&mut self, tag: u8) {
        self.buf.push(tag);
    }

    pub fn write_bytes(&mut self, b: &[u8]) {
        self.write_u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }

    pub fn write_str(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    /// Raw bytes without a length prefix (length framed by the caller).
    pub fn write_bytes_raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn write_opt_str(&mut self, s: &Option<String>) {
        match s {
            Some(v) => {
                self.buf.push(1);
                self.write_str(v);
            }
            None => self.buf.push(0),
        }
    }

    pub fn write_opt_hash(&mut self, h: &Option<Hash>) {
        match h {
            Some(v) => {
                self.buf.push(1);
                self.buf.extend_from_slice(&v.0);
            }
            None => self.buf.push(0),
        }
    }

    pub fn write_hash(&mut self, h: &Hash) {
        self.buf.extend_from_slice(&h.0);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_bool(&mut self, v: bool) {
        self.buf.push(if v { 1 } else { 0 });
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for CanonicalWriter {
    fn default() -> Self {
        CanonicalWriter::new()
    }
}

/// Length-prefixed deterministic byte reader (mirror of [`CanonicalWriter`]).
pub struct CanonicalReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CanonicalReader<'a> {
    pub fn new(buf: &'a [u8]) -> CanonicalReader<'a> {
        CanonicalReader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ModelError> {
        if self.remaining() < n {
            return Err(ModelError::Parse(format!(
                "canonical stream truncated at offset {} (need {n} bytes)",
                self.pos
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn read_tag(&mut self) -> Result<u8, ModelError> {
        Ok(self.take(1)?[0])
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>, ModelError> {
        let n = self.read_u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }

    /// Raw bytes without a length prefix (length framed by the caller).
    pub fn read_raw(&mut self, n: usize) -> Result<Vec<u8>, ModelError> {
        Ok(self.take(n)?.to_vec())
    }

    pub fn read_str(&mut self) -> Result<String, ModelError> {
        let b = self.read_bytes()?;
        String::from_utf8(b).map_err(|e| ModelError::Parse(format!("invalid UTF-8: {e}")))
    }

    pub fn read_opt_str(&mut self) -> Result<Option<String>, ModelError> {
        match self.read_tag()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_str()?)),
            t => Err(ModelError::Parse(format!("bad optional tag {t}"))),
        }
    }

    pub fn read_opt_hash(&mut self) -> Result<Option<Hash>, ModelError> {
        match self.read_tag()? {
            0 => Ok(None),
            1 => Ok(Some(Hash(self.take(32)?.try_into().unwrap()))),
            t => Err(ModelError::Parse(format!("bad optional tag {t}"))),
        }
    }

    pub fn read_hash(&mut self) -> Result<Hash, ModelError> {
        Ok(Hash(self.take(32)?.try_into().unwrap()))
    }

    pub fn read_u16(&mut self) -> Result<u16, ModelError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, ModelError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, ModelError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_i64(&mut self) -> Result<i64, ModelError> {
        let b = self.take(8)?;
        Ok(i64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_bool(&mut self) -> Result<bool, ModelError> {
        match self.read_tag()? {
            0 => Ok(false),
            1 => Ok(true),
            t => Err(ModelError::Parse(format!("bad bool tag {t}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        // FIPS 180-4 / NIST vector for "abc"
        assert_eq!(
            sha256(&[b"abc"]).hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // empty input
        assert_eq!(
            sha256(&[]).hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_hex_round_trip() {
        let h = sha256(&[b"unidpp"]);
        assert_eq!(Hash::from_hex(&h.hex()).unwrap(), h);
        assert!(Hash::from_hex("zz").is_none());
        assert_eq!(h.to_string(), h.hex());
    }

    #[test]
    fn writer_reader_round_trip() {
        let mut w = CanonicalWriter::new();
        w.write_tag(7);
        w.write_str("héllo");
        w.write_u64(42);
        w.write_i64(-42);
        w.write_bool(true);
        w.write_opt_str(&None);
        w.write_opt_str(&Some("x".into()));
        let bytes = w.into_bytes();
        let mut r = CanonicalReader::new(&bytes);
        assert_eq!(r.read_tag().unwrap(), 7);
        assert_eq!(r.read_str().unwrap(), "héllo");
        assert_eq!(r.read_u64().unwrap(), 42);
        assert_eq!(r.read_i64().unwrap(), -42);
        assert!(r.read_bool().unwrap());
        assert_eq!(r.read_opt_str().unwrap(), None);
        assert_eq!(r.read_opt_str().unwrap().unwrap(), "x");
        assert_eq!(r.remaining(), 0);
    }
}
