//! Per-chunk hash collector for end-to-end file integrity.
//!
//! The file hash is computed as:
//!
//!   blake3(chunk_hash[0] || chunk_hash[1] || ... || chunk_hash[N-1])
//!
//! where each `chunk_hash[i]` is `blake3(raw_bytes_of_chunk_i)`.
//!
//! This lets both the sender and receiver compute a single BLAKE3 pass per
//! chunk (for wire integrity) and reuse that 32-byte result here — no second
//! streaming pass over the full file.  The final file hash is then a single
//! BLAKE3 call over N×32 bytes (≤20 KiB for a 5 GiB file at 4 MiB chunks).
//!
//! Chunks arrive out of order across N parallel streams, so the collector
//! buffers early arrivals and drains them once their turn comes.
//!
//! # Usage
//! ```ignore
//! let hasher = Arc::new(ChunkHasher::new(total_chunks));
//! // (in each stream worker, after computing chunk_hash = blake3::hash(&raw))
//! hasher.feed(chunk_index, chunk_hash)?;
//! // (after all workers finish)
//! let hash: [u8; 32] = Arc::try_unwrap(hasher).unwrap().finish()?;
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{bail, Result};

/// Maximum number of out-of-order chunk hashes held in the pending buffer.
///
/// With `MAX_IN_FLIGHT=4` per stream and `MAX_STREAMS=1024`, a legitimate
/// transfer can have at most 4096 chunks ahead of the in-order cursor at
/// once.  Exceeding this indicates a malicious sender deliberately withholding
/// early chunks to exhaust receiver memory.
const MAX_HASHER_PENDING: usize = 4096;

#[derive(Debug)]
pub struct ChunkHasher {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// In-order collected chunk hashes ready for the final digest.
    collected: Vec<[u8; 32]>,
    /// Index of the next chunk we are waiting to collect.
    next: u64,
    total: u64,
    /// Chunk hashes that arrived before their turn.
    pending: HashMap<u64, [u8; 32]>,
}

impl ChunkHasher {
    pub fn new(total_chunks: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                collected: Vec::with_capacity(total_chunks as usize),
                next: 0,
                total: total_chunks,
                pending: HashMap::new(),
            }),
        }
    }

    /// Record the BLAKE3 hash of one raw chunk.
    ///
    /// If `chunk_index` is the next expected chunk the hash is appended to the
    /// ordered list immediately, and any buffered successive chunks are drained.
    /// Otherwise the hash is stored until its turn comes.
    ///
    /// Returns an error if the pending buffer is full, indicating a malicious
    /// sender withholding early chunks to exhaust receiver memory.
    pub fn feed(&self, chunk_index: u64, hash: [u8; 32]) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if chunk_index == g.next {
            g.collected.push(hash);
            g.next += 1;
            loop {
                let key = g.next;
                match g.pending.remove(&key) {
                    Some(h) => { g.collected.push(h); g.next += 1; }
                    None => break,
                }
            }
        } else {
            if g.pending.len() >= MAX_HASHER_PENDING && !g.pending.contains_key(&chunk_index) {
                bail!(
                    "hasher pending buffer full ({MAX_HASHER_PENDING} out-of-order chunks) \
                     — possible malicious sender withholding early chunks"
                );
            }
            g.pending.insert(chunk_index, hash);
        }
        Ok(())
    }

    /// Finalise and return the file hash.
    ///
    /// Concatenates all per-chunk hashes in order and hashes that buffer with
    /// BLAKE3.  Must be called after all `feed` calls are complete.
    /// Returns an error if not all chunks were fed.
    pub fn finish(self) -> Result<[u8; 32]> {
        let g = self.inner.into_inner().unwrap();
        if g.next != g.total {
            bail!(
                "chunk hasher incomplete: collected {}/{} chunks ({} still buffered)",
                g.next,
                g.total,
                g.pending.len()
            );
        }
        // Concatenate N×32 bytes and hash once — trivial for any realistic file size.
        let buf: Vec<u8> = g.collected.iter().flat_map(|h| h.iter().copied()).collect();
        Ok(*blake3::hash(&buf).as_bytes())
    }
}

/// Compute the file hash using the same formula as the fresh-transfer path:
///   `blake3(blake3(chunk_0) || blake3(chunk_1) || ... || blake3(chunk_N-1))`
/// where chunks are `chunk_size` bytes (last chunk may be smaller).
/// Used on the resume path where some chunks are already at the receiver,
/// and by the sender when skipping already-received chunks.
pub(crate) fn hash_file_sync(path: &Path, chunk_size: usize) -> Result<[u8; 32]> {
    let file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();
    let total_chunks = file_size.div_ceil(chunk_size as u64);
    let mut chunk_hashes: Vec<u8> = Vec::with_capacity(total_chunks as usize * 32);
    let mut buf = vec![0u8; chunk_size];
    for idx in 0..total_chunks {
        let offset = idx * chunk_size as u64;
        let len = (chunk_size as u64).min(file_size - offset) as usize;
        crate::fs_ext::read_exact_at(&file, &mut buf[..len], offset)?;
        let h = blake3::hash(&buf[..len]);
        chunk_hashes.extend_from_slice(h.as_bytes());
    }
    Ok(*blake3::hash(&chunk_hashes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference: hash each chunk with blake3, then hash the concatenated results.
    fn reference_hash(chunks: &[&[u8]]) -> [u8; 32] {
        let buf: Vec<u8> = chunks
            .iter()
            .flat_map(|c| blake3::hash(c).as_bytes().to_vec())
            .collect();
        *blake3::hash(&buf).as_bytes()
    }

    #[test]
    fn in_order_matches_reference() {
        let data: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 1024]).collect();
        let hasher = ChunkHasher::new(4);
        for (i, d) in data.iter().enumerate() {
            hasher.feed(i as u64, *blake3::hash(d).as_bytes()).unwrap();
        }
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        assert_eq!(hasher.finish().unwrap(), reference_hash(&refs));
    }

    #[test]
    fn out_of_order_matches_reference() {
        let data: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 1024]).collect();
        let hasher = ChunkHasher::new(4);
        for (i, d) in data.iter().enumerate().rev() {
            hasher.feed(i as u64, *blake3::hash(d).as_bytes()).unwrap();
        }
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        assert_eq!(hasher.finish().unwrap(), reference_hash(&refs));
    }

    #[test]
    fn finish_errors_if_incomplete() {
        let hasher = ChunkHasher::new(4);
        hasher.feed(0, [1u8; 32]).unwrap();
        assert!(hasher.finish().is_err());
    }

    #[test]
    fn pending_cap_triggers_error() {
        let hasher = ChunkHasher::new(MAX_HASHER_PENDING as u64 + 2);
        for i in 1..=MAX_HASHER_PENDING as u64 {
            hasher.feed(i, [0u8; 32]).unwrap();
        }
        let result = hasher.feed(MAX_HASHER_PENDING as u64 + 1, [0u8; 32]);
        assert!(result.is_err());
    }
}
