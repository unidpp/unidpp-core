//! Deterministic PRNG for property tests (xorshift64*).
//!
//! Property tests must be reproducible: a failing seed re-runs the exact
//! failing chain. Not for production use.

/// xorshift64* generator.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in [lo, hi). Degenerate ranges (hi <= lo) yield `lo` —
    /// property generators must stay total, not panic on empty spans.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo)
    }

    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for chunk in b.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        b
    }

    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> Option<&'a T> {
        if xs.is_empty() {
            None
        } else {
            Some(&xs[self.range(0, xs.len() as u64 - 1) as usize])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_spread() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut r = Rng::new(7);
        let mut odd = 0;
        for _ in 0..1000 {
            if r.bool() {
                odd += 1;
            }
        }
        assert!((400..600).contains(&odd), "distribution skewed: {odd}");
    }
}
