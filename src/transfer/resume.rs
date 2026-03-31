//! Resumable transfer state.
//!
//! The resume file lives at `<output_dir>/<transfer_id_hex>.mftp-resume` and
//! stores a bit-vector of received chunk indices so that a restarted transfer
//! can skip chunks that are already on disk.
//!
//! # File format
//! ```text
//! [8 bytes]  magic + version: b"mftpres\x01"
//! [N bytes]  bincode-serialised ResumeData { transfer_id, total_chunks, received }
//! ```
//!
//! The file is written atomically: data is written to `<path>.tmp` then
//! renamed to `<path>`, so a crash during save never produces a corrupt file.
//! On completion the resume file is deleted.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const RESUME_MAGIC: &[u8; 8] = b"mftpres\x01";

#[derive(Serialize, Deserialize)]
struct ResumeData {
    transfer_id: [u8; 16],
    total_chunks: u64,
    /// Bit-vector: bit i is set iff chunk i has been received and verified.
    received: Vec<u64>,
}

pub struct ResumeState {
    path: PathBuf,
    transfer_id: [u8; 16],
    /// Bit-vector: bit i is set iff chunk i has been received and verified.
    received: Vec<u64>,
    total_chunks: u64,
}

impl ResumeState {
    pub fn new(dir: &Path, transfer_id: &[u8; 16], total_chunks: u64) -> Self {
        let name = format!("{}.mftp-resume", hex::encode(transfer_id));
        Self {
            path: dir.join(name),
            transfer_id: *transfer_id,
            received: vec![0u64; total_chunks.div_ceil(64) as usize],
            total_chunks,
        }
    }

    /// Load an existing resume file for this transfer, or create fresh state.
    ///
    /// If the file exists but is corrupt/stale, it is silently discarded and a
    /// fresh state is returned (the transfer simply restarts from the beginning).
    pub fn load_or_new(dir: &Path, transfer_id: &[u8; 16], total_chunks: u64) -> Self {
        match Self::try_load(dir, transfer_id, total_chunks) {
            Ok(state) => {
                let n = state.received_chunks().len();
                if n > 0 {
                    tracing::info!(
                        "resuming transfer: {n}/{total_chunks} chunks already on disk"
                    );
                }
                state
            }
            Err(e) => {
                tracing::debug!("no usable resume file, starting fresh: {e:#}");
                Self::new(dir, transfer_id, total_chunks)
            }
        }
    }

    fn try_load(dir: &Path, transfer_id: &[u8; 16], total_chunks: u64) -> Result<Self> {
        let name = format!("{}.mftp-resume", hex::encode(transfer_id));
        let path = dir.join(&name);

        let mut f = std::fs::File::open(&path)
            .with_context(|| format!("open {}", path.display()))?;

        let mut magic = [0u8; 8];
        f.read_exact(&mut magic).context("read magic")?;
        if &magic != RESUME_MAGIC {
            anyhow::bail!("unrecognised magic bytes");
        }

        let mut payload = Vec::new();
        f.read_to_end(&mut payload).context("read payload")?;

        let data: ResumeData = bincode::deserialize(&payload).context("deserialise")?;

        if data.transfer_id != *transfer_id {
            anyhow::bail!("transfer_id mismatch in resume file");
        }
        if data.total_chunks != total_chunks {
            anyhow::bail!(
                "total_chunks mismatch: file has {}, expected {total_chunks}",
                data.total_chunks
            );
        }
        let expected_words = total_chunks.div_ceil(64) as usize;
        if data.received.len() != expected_words {
            anyhow::bail!(
                "bitvec length mismatch: got {}, expected {expected_words}",
                data.received.len()
            );
        }

        Ok(Self { path, transfer_id: *transfer_id, received: data.received, total_chunks })
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
        (0..self.total_chunks).filter(|&i| !self.is_received(i)).collect()
    }

    pub fn is_complete(&self) -> bool {
        // Check full words first (fast path), then handle the trailing partial word.
        let full_words = (self.total_chunks / 64) as usize;
        if !self.received[..full_words].iter().all(|&w| w == u64::MAX) {
            return false;
        }
        let remainder = self.total_chunks % 64;
        if remainder == 0 {
            return true;
        }
        let mask = (1u64 << remainder) - 1;
        self.received[full_words] & mask == mask
    }

    pub fn received_chunks(&self) -> Vec<u64> {
        (0..self.total_chunks).filter(|&i| self.is_received(i)).collect()
    }

    /// Return a clone of the raw packed bitvector for use in the wire protocol.
    pub fn received_bitvec(&self) -> Vec<u64> {
        self.received.clone()
    }

    /// Persist the current state to disk atomically (write-then-rename).
    ///
    /// Called after every `mark_received` so a crash loses at most the
    /// in-progress chunk.  Designed to be called from `spawn_blocking`.
    pub fn save(&self) -> Result<()> {
        let data = ResumeData {
            transfer_id: self.transfer_id,
            total_chunks: self.total_chunks,
            received: self.received.clone(),
        };
        let payload = bincode::serialize(&data).context("serialise resume state")?;

        let tmp = self.path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)
                .with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(RESUME_MAGIC).context("write magic")?;
            f.write_all(&payload).context("write payload")?;
            f.sync_data().context("fsync")?;
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename resume file to {}", self.path.display()))?;
        Ok(())
    }

    /// Delete the resume file on successful completion.
    pub fn delete(&self) -> Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)
                .with_context(|| format!("delete {}", self.path.display()))?;
        }
        Ok(())
    }
}
