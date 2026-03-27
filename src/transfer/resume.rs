//! Resumable transfer state.
//!
//! The resume file lives at `<output_dir>/<transfer_id>.mftp-resume` and
//! contains the manifest plus a bit-vector of received chunk indices.
//! On completion the resume file is deleted.

use std::path::{Path, PathBuf};

pub struct ResumeState {
    path: PathBuf,
    /// Bit-vector: bit i is set if chunk i has been received and verified.
    received: Vec<u64>,
    total_chunks: u64,
}

impl ResumeState {
    pub fn new(dir: &Path, transfer_id: &[u8; 16], total_chunks: u64) -> Self {
        let name = format!("{}.mftp-resume", hex::encode(transfer_id));
        Self {
            path: dir.join(name),
            received: vec![0u64; total_chunks.div_ceil(64) as usize],
            total_chunks,
        }
    }

    pub fn load_or_new(dir: &Path, transfer_id: &[u8; 16], total_chunks: u64) -> Self {
        // TODO: deserialize existing resume file if present.
        Self::new(dir, transfer_id, total_chunks)
    }

    pub fn mark_received(&mut self, chunk_index: u64) {
        let word = (chunk_index / 64) as usize;
        let bit = chunk_index % 64;
        self.received[word] |= 1 << bit;
    }

    pub fn is_received(&self, chunk_index: u64) -> bool {
        let word = (chunk_index / 64) as usize;
        let bit = chunk_index % 64;
        self.received[word] & (1 << bit) != 0
    }

    pub fn missing_chunks(&self) -> Vec<u64> {
        (0..self.total_chunks)
            .filter(|&i| !self.is_received(i))
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.missing_chunks().is_empty()
    }

    pub fn received_chunks(&self) -> Vec<u64> {
        (0..self.total_chunks)
            .filter(|&i| self.is_received(i))
            .collect()
    }

    /// Persist resume state to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        // TODO: serialize bit-vector to resume file.
        Ok(())
    }

    /// Delete resume file on successful completion.
    pub fn delete(&self) -> anyhow::Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}
