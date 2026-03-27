//! Streaming in-order file hasher for the receiver.
//!
//! Chunks arrive out of order across N parallel streams.  SHA-256 requires
//! sequential input, so we maintain a small buffer of ahead-of-time chunks
//! and drain it into the hasher whenever the next expected chunk arrives.
//!
//! With N streams, at most N-1 chunks are ever buffered simultaneously.
//! For the default of 8 streams with 4 MiB chunks that is ≤28 MiB.
//!
//! # Usage
//! ```ignore
//! let hasher = Arc::new(ChunkHasher::new(total_chunks));
//! // (in each stream worker, after pwrite)
//! hasher.feed(chunk_index, &decompressed_data);
//! // (after all workers finish)
//! let hash: [u8; 32] = Arc::try_unwrap(hasher).unwrap().finish()?;
//! ```

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct ChunkHasher {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    hasher: Sha256,
    /// Index of the next chunk we are waiting to feed into the hasher.
    next: u64,
    total: u64,
    /// Chunks that arrived before their turn.
    pending: BTreeMap<u64, Vec<u8>>,
}

impl ChunkHasher {
    pub fn new(total_chunks: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                hasher: Sha256::new(),
                next: 0,
                total: total_chunks,
                pending: BTreeMap::new(),
            }),
        }
    }

    /// Feed a chunk's decompressed bytes into the hasher.
    ///
    /// If `chunk_index` is the next expected chunk it is hashed immediately
    /// and any buffered successive chunks are drained.  Otherwise the data
    /// is stored until its turn comes.
    pub fn feed(&self, chunk_index: u64, data: &[u8]) {
        let mut g = self.inner.lock().unwrap();
        if chunk_index == g.next {
            g.hasher.update(data);
            g.next += 1;
            // Drain any consecutive chunks that arrived early.
            loop {
                let key = g.next;
                match g.pending.remove(&key) {
                    Some(buffered) => { g.hasher.update(&buffered); g.next += 1; }
                    None => break,
                }
            }
        } else {
            g.pending.insert(chunk_index, data.to_vec());
        }
    }

    /// Finalise and return the SHA-256 digest.
    ///
    /// Must be called after all `feed` calls are complete.
    /// Returns an error if not all chunks were fed.
    pub fn finish(self) -> Result<[u8; 32]> {
        let g = self.inner.into_inner().unwrap();
        if g.next != g.total {
            bail!(
                "chunk hasher incomplete: fed {}/{} chunks ({} still buffered)",
                g.next,
                g.total,
                g.pending.len()
            );
        }
        Ok(g.hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_sequential(chunks: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for c in chunks { h.update(c); }
        h.finalize().into()
    }

    #[test]
    fn in_order_matches_sequential() {
        let data: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 1024]).collect();
        let hasher = ChunkHasher::new(4);
        for (i, d) in data.iter().enumerate() { hasher.feed(i as u64, d); }
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        assert_eq!(hasher.finish().unwrap(), hash_sequential(&refs));
    }

    #[test]
    fn out_of_order_matches_sequential() {
        let data: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 1024]).collect();
        let hasher = ChunkHasher::new(4);
        // Feed in reverse order
        for (i, d) in data.iter().enumerate().rev() { hasher.feed(i as u64, d); }
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        assert_eq!(hasher.finish().unwrap(), hash_sequential(&refs));
    }

    #[test]
    fn finish_errors_if_incomplete() {
        let hasher = ChunkHasher::new(4);
        hasher.feed(0, &[1, 2, 3]);
        assert!(hasher.finish().is_err());
    }
}
