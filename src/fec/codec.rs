//! Reed-Solomon encode / decode, wrapping `reed-solomon-erasure` v6.
//!
//! Each stripe of `data_shards` compressed chunks is encoded into
//! `parity_shards` parity shards using GF(2^8) arithmetic.  Because
//! Reed-Solomon requires equal-length shards the caller must supply
//! compressed chunks; this module pads each to the stripe maximum
//! internally and returns the original lengths so the receiver can trim
//! after reconstruction.

use anyhow::{bail, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

// ── Encoder ──────────────────────────────────────────────────────────────────

pub struct FecEncoder {
    rs: ReedSolomon,
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl FecEncoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| anyhow::anyhow!("FEC encoder init: {:?}", e))?;
        Ok(Self { rs, data_shards, parity_shards })
    }

    /// Encode a stripe of compressed data shards.
    ///
    /// Returns `(parity_shards, shard_lengths)`:
    /// - `parity_shards`: RS-computed parity shards, each `stripe_max` bytes long.
    /// - `shard_lengths[i]`: unpadded wire length of data shard `i` (before padding).
    ///
    /// The `data` input must contain exactly `self.data_shards` entries.
    /// Empty data is allowed (all lengths zero → parity is also all-zero).
    pub fn encode(&self, data: Vec<Vec<u8>>) -> Result<(Vec<Vec<u8>>, Vec<u32>)> {
        if data.len() != self.data_shards {
            bail!("FEC encode: expected {} data shards, got {}", self.data_shards, data.len());
        }

        let shard_lengths: Vec<u32> = data.iter().map(|s| s.len() as u32).collect();
        let stripe_max = data.iter().map(|s| s.len()).max().unwrap_or(0);

        if stripe_max == 0 {
            // All shards empty: parity is trivially empty.
            return Ok((vec![Vec::new(); self.parity_shards], shard_lengths));
        }

        // Pad all data shards to stripe_max with zeros, then append empty parity slots.
        let mut shards: Vec<Vec<u8>> = data
            .into_iter()
            .map(|mut s| {
                s.resize(stripe_max, 0);
                s
            })
            .collect();
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; stripe_max]);
        }

        self.rs.encode(&mut shards).map_err(|e| anyhow::anyhow!("FEC encode: {:?}", e))?;

        // Parity shards are the tail of the slice after encode.
        let parity: Vec<Vec<u8>> = shards.drain(self.data_shards..).collect();
        Ok((parity, shard_lengths))
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

pub struct FecDecoder {
    rs: ReedSolomon,
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl FecDecoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| anyhow::anyhow!("FEC decoder init: {:?}", e))?;
        Ok(Self { rs, data_shards, parity_shards })
    }

    /// Reconstruct missing shards and return trimmed data shards.
    ///
    /// `shards` must have length `data_shards + parity_shards`.  Each element
    /// is `Some(bytes)` if that shard was received, `None` if it is missing.
    ///
    /// **Caller responsibility**: present data shards must be padded to
    /// `stripe_max = max(shard_lengths)` before calling.  Synthetic zero shards
    /// (virtual padding in the last stripe) must be `Some(vec![0u8; stripe_max])`.
    /// Parity shards are already at stripe_max length.
    ///
    /// Returns the reconstructed data shards, each trimmed to `shard_lengths[i]`.
    pub fn reconstruct(
        &self,
        mut shards: Vec<Option<Vec<u8>>>,
        shard_lengths: &[u32],
    ) -> Result<Vec<Vec<u8>>> {
        if shards.len() != self.data_shards + self.parity_shards {
            bail!(
                "FEC reconstruct: expected {} shards, got {}",
                self.data_shards + self.parity_shards,
                shards.len()
            );
        }
        self.rs
            .reconstruct(&mut shards)
            .map_err(|e| anyhow::anyhow!("FEC reconstruct: {:?}", e))?;

        // Reconstruct fills all None slots.  Extract data shards and trim.
        let data: Vec<Vec<u8>> = shards
            .into_iter()
            .take(self.data_shards)
            .enumerate()
            .map(|(i, s)| {
                let mut v = s.expect("reconstruct filled all shards");
                if i < shard_lengths.len() {
                    v.truncate(shard_lengths[i] as usize);
                }
                v
            })
            .collect();
        Ok(data)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_no_loss() {
        let enc = FecEncoder::new(4, 2).unwrap();
        let data: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 100]).collect();
        let original = data.clone();
        let (parity, shard_lengths) = enc.encode(data).unwrap();
        assert_eq!(parity.len(), 2);
        assert_eq!(shard_lengths, vec![100u32; 4]);

        // No loss: reconstruct trivially by re-running with all shards present.
        let dec = FecDecoder::new(4, 2).unwrap();
        let shards: Vec<Option<Vec<u8>>> = original
            .iter()
            .map(|s| { let mut v = s.clone(); v.resize(100, 0); Some(v) })
            .chain(parity.iter().map(|p| Some(p.clone())))
            .collect();
        let got = dec.reconstruct(shards, &shard_lengths).unwrap();
        assert_eq!(got, original);
    }

    #[test]
    fn reconstruct_one_missing_data_shard() {
        let enc = FecEncoder::new(4, 2).unwrap();
        let data: Vec<Vec<u8>> = (1u8..=4).map(|i| vec![i; 80]).collect();
        let original = data.clone();
        let (parity, shard_lengths) = enc.encode(data).unwrap();

        let dec = FecDecoder::new(4, 2).unwrap();
        // Drop shard 2 (index 2).
        let stripe_max = *shard_lengths.iter().max().unwrap() as usize;
        let shards: Vec<Option<Vec<u8>>> = original
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i == 2 { None } else {
                    let mut v = s.clone();
                    v.resize(stripe_max, 0);
                    Some(v)
                }
            })
            .chain(parity.iter().map(|p| Some(p.clone())))
            .collect();
        let got = dec.reconstruct(shards, &shard_lengths).unwrap();
        assert_eq!(got, original);
    }

    #[test]
    fn reconstruct_variable_lengths() {
        // Shards of different compressed sizes — core of the pad-to-max design.
        let enc = FecEncoder::new(3, 1).unwrap();
        let data = vec![
            vec![0u8; 50],
            vec![1u8; 100],
            vec![2u8; 80],
        ];
        let original = data.clone();
        let (parity, shard_lengths) = enc.encode(data).unwrap();
        assert_eq!(shard_lengths, vec![50, 100, 80]);

        let dec = FecDecoder::new(3, 1).unwrap();
        // Drop shard 0.
        let stripe_max = 100usize;
        let shards: Vec<Option<Vec<u8>>> = original
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i == 0 { None } else {
                    let mut v = s.clone();
                    v.resize(stripe_max, 0);
                    Some(v)
                }
            })
            .chain(parity.iter().map(|p| Some(p.clone())))
            .collect();
        let got = dec.reconstruct(shards, &shard_lengths).unwrap();
        assert_eq!(got[0], original[0]);
        assert_eq!(got[1], original[1]);
        assert_eq!(got[2], original[2]);
    }

    #[test]
    fn two_parity_can_cover_two_lost_data() {
        let enc = FecEncoder::new(4, 2).unwrap();
        let data: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 64]).collect();
        let original = data.clone();
        let (parity, shard_lengths) = enc.encode(data).unwrap();
        let stripe_max = 64usize;

        let dec = FecDecoder::new(4, 2).unwrap();
        // Drop shards 1 and 3.
        let shards: Vec<Option<Vec<u8>>> = original
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i == 1 || i == 3 { None } else {
                    let mut v = s.clone();
                    v.resize(stripe_max, 0);
                    Some(v)
                }
            })
            .chain(parity.iter().map(|p| Some(p.clone())))
            .collect();
        let got = dec.reconstruct(shards, &shard_lengths).unwrap();
        assert_eq!(got, original);
    }
}
