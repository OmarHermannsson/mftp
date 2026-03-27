//! File chunking and the work-stealing queue used by the sender.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Divides a file into fixed-size chunks and hands them out atomically
/// so multiple sender tasks can pull work without coordination overhead.
pub struct ChunkQueue {
    next: AtomicU64,
    total: u64,
    chunk_size: usize,
    file_size: u64,
}

impl ChunkQueue {
    pub fn new(file_size: u64, chunk_size: usize) -> Arc<Self> {
        let total = file_size.div_ceil(chunk_size as u64);
        Arc::new(Self {
            next: AtomicU64::new(0),
            total,
            chunk_size,
            file_size,
        })
    }

    /// Resume from a set of already-received chunk indices by skipping them.
    pub fn skip_received(self: &Arc<Self>, received: &[u64]) {
        // For now, we just restart from 0 and the sender skips known chunks.
        // A bitmap-based approach will replace this in the full implementation.
        let _ = received;
    }

    /// Returns the next chunk index to send, or `None` if all chunks are claimed.
    pub fn next_chunk(&self) -> Option<ChunkInfo> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed);
        if idx >= self.total {
            return None;
        }
        let offset = idx * self.chunk_size as u64;
        let len = ((self.file_size - offset) as usize).min(self.chunk_size);
        Some(ChunkInfo { index: idx, offset, len })
    }

    pub fn total_chunks(&self) -> u64 {
        self.total
    }
}

#[derive(Debug, Clone)]
pub struct ChunkInfo {
    pub index: u64,
    pub offset: u64,
    pub len: usize,
}
