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
    /// Maximum out-of-order hashes we hold before treating the situation as
    /// an error.  Derived from stream count so legitimate high-stream
    /// transfers never hit the cap.
    max_pending: usize,
}

impl ChunkHasher {
    /// Create a hasher for `total_chunks` chunks arriving across `stream_count`
    /// parallel streams.
    ///
    /// The pending buffer limit is `stream_count × 8`, which is 2× the
    /// theoretical maximum of `stream_count × MAX_IN_FLIGHT(4)` out-of-order
    /// chunks that can accumulate when one slow stream holds back the in-order
    /// cursor while all others run ahead.  The floor of 64 handles tiny files
    /// or single-stream transfers gracefully.
    pub fn new(total_chunks: u64, stream_count: usize) -> Self {
        let max_pending = (stream_count * 8).max(64);
        Self {
            inner: Mutex::new(Inner {
                collected: Vec::with_capacity(total_chunks as usize),
                next: 0,
                total: total_chunks,
                pending: HashMap::new(),
                max_pending,
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
                    Some(h) => {
                        g.collected.push(h);
                        g.next += 1;
                    }
                    None => break,
                }
            }
        } else {
            let limit = g.max_pending;
            if g.pending.len() >= limit && !g.pending.contains_key(&chunk_index) {
                bail!(
                    "hasher pending buffer full ({limit} out-of-order chunks buffered) — \
                     one stream is far behind the others; the transfer may be stalled"
                );
            }
            g.pending.insert(chunk_index, hash);
        }
        Ok(())
    }

    /// Increase the pending-buffer limit to accommodate a higher stream count.
    ///
    /// Called when dynamic stream scaling adds new streams mid-transfer.
    /// The limit only ever increases (decreasing would risk spurious errors
    /// while buffered hashes are still in flight).
    pub fn update_stream_count(&self, new_count: usize) {
        let new_limit = (new_count * 8).max(64);
        let mut g = self.inner.lock().unwrap();
        if new_limit > g.max_pending {
            g.max_pending = new_limit;
        }
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
        let hasher = ChunkHasher::new(4, 1);
        for (i, d) in data.iter().enumerate() {
            hasher.feed(i as u64, *blake3::hash(d).as_bytes()).unwrap();
        }
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        assert_eq!(hasher.finish().unwrap(), reference_hash(&refs));
    }

    #[test]
    fn out_of_order_matches_reference() {
        let data: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 1024]).collect();
        let hasher = ChunkHasher::new(4, 1);
        for (i, d) in data.iter().enumerate().rev() {
            hasher.feed(i as u64, *blake3::hash(d).as_bytes()).unwrap();
        }
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        assert_eq!(hasher.finish().unwrap(), reference_hash(&refs));
    }

    #[test]
    fn finish_errors_if_incomplete() {
        let hasher = ChunkHasher::new(4, 1);
        hasher.feed(0, [1u8; 32]).unwrap();
        assert!(hasher.finish().is_err());
    }

    #[test]
    fn pending_cap_triggers_error() {
        // stream_count=1 → max_pending = max(1*8, 64) = 64
        let limit: u64 = 64;
        let hasher = ChunkHasher::new(limit + 2, 1);
        // Feed chunks 1..=limit out of order (chunk 0 never arrives, so all go pending).
        for i in 1..=limit {
            hasher.feed(i, [0u8; 32]).unwrap();
        }
        // One more beyond the limit should error.
        let result = hasher.feed(limit + 1, [0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn high_stream_count_raises_pending_cap() {
        // 16 streams → max_pending = 16 * 8 = 128; should not error at 100 pending.
        let hasher = ChunkHasher::new(200, 16);
        for i in 1..=100u64 {
            hasher.feed(i, [0u8; 32]).unwrap();
        }
    }
}
