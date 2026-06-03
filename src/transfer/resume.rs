//! Resumable transfer state.
//!
//! The resume file lives at `<output_dir>/<transfer_id_hex>.mftp-resume` and
//! stores a bit-vector of received chunk indices so that a restarted transfer
//! can skip chunks that are already on disk.
//!
//! # File format
//! ```text
//! [8 bytes]  magic + version: b"mftpres\x02"
//! [8 bytes]  integrity tag: first 8 bytes of BLAKE3(bincode payload)
//! [N bytes]  bincode-serialised ResumeData { transfer_id, total_chunks, received }
//! ```
//!
//! The file is written atomically: data is written to `<path>.tmp` then
//! renamed to `<path>`, so a crash during save never produces a corrupt file.
//! On completion the resume file is deleted.
//!
//! The atomic rename guards against torn writes, but not against on-disk bit-rot
//! or partial corruption from unrelated causes. The integrity tag catches those:
//! a mismatch on load is treated like any other unusable resume file — discarded,
//! with a fresh transfer started (see [`ResumeState::load_or_new`]).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Number of chunks to accumulate before flushing the resume file to disk.
///
/// Batching reduces fsync frequency (and mutex hold time under fsync) by this
/// factor.  On crash the receiver re-downloads at most this many extra chunks.
pub const RESUME_SAVE_BATCH: u64 = 64;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const RESUME_MAGIC: &[u8; 8] = b"mftpres\x02";

/// Length of the integrity tag (truncated BLAKE3 of the bincode payload).
const RESUME_TAG_LEN: usize = 8;

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
    /// Chunks marked since last save; used for batching.
    dirty: u64,
}

/// A point-in-time snapshot of the resume state ready for out-of-lock I/O.
///
/// Obtain via [`ResumeState::snapshot`], then call [`ResumeSnapshot::write_to_disk`]
/// *outside* any mutex so the slow fsync does not block other stream workers.
pub struct ResumeSnapshot {
    path: PathBuf,
    /// RESUME_MAGIC prepended, then bincode payload — ready to write verbatim.
    payload: Vec<u8>,
}

impl ResumeSnapshot {
    /// Atomically persist the snapshot: write to `<path>.tmp`, fsync, rename.
    pub fn write_to_disk(&self) -> Result<()> {
        let tmp = self.path.with_extension("tmp");
        {
            let mut f =
                std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(&self.payload)
                .context("write resume snapshot")?;
            f.sync_data().context("fsync resume snapshot")?;
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename resume file to {}", self.path.display()))?;
        Ok(())
    }
}

impl ResumeState {
    pub fn new(dir: &Path, transfer_id: &[u8; 16], total_chunks: u64) -> Self {
        let name = format!("{}.mftp-resume", hex::encode(transfer_id));
        Self {
            path: dir.join(name),
            transfer_id: *transfer_id,
            received: vec![0u64; total_chunks.div_ceil(64) as usize],
            total_chunks,
            dirty: 0,
        }
    }

    /// Load an existing resume file for this transfer, or create fresh state.
    ///
    /// If the file exists but is corrupt/stale, it is discarded and a fresh
    /// state is returned (the transfer restarts from the beginning).  Status is
    /// reported to stderr so the user can see a resume happen at the default log
    /// level.
    ///
    /// # Durability note
    /// A chunk's resume bit is set after its `pwrite` returns but the data file
    /// is not fsynced per chunk, so a crash can leave a chunk marked-received
    /// whose bytes never reached stable storage.  This is safe because the
    /// whole-file hash check at the end of the transfer will fail on any such
    /// gap and [`delete`](Self::delete) the resume file, forcing a clean
    /// re-transfer on the next run rather than silently accepting corruption.
    pub fn load_or_new(dir: &Path, transfer_id: &[u8; 16], total_chunks: u64) -> Self {
        let name = format!("{}.mftp-resume", hex::encode(transfer_id));
        let path = dir.join(&name);
        let existed = path.exists();
        match Self::try_load(dir, transfer_id, total_chunks) {
            Ok(state) => {
                let n = state.received_chunks().len();
                if n > 0 {
                    eprintln!(
                        "[mftp] resuming: {n}/{total_chunks} chunks already on disk \
                         (state: {})",
                        path.display()
                    );
                }
                state
            }
            Err(e) if existed => {
                // A file was present but unusable (corrupt, or from a different
                // file/size that happens to share this transfer_id) — tell the
                // user we're discarding it rather than failing silently.
                eprintln!(
                    "[mftp] ignoring unusable resume file {} ({e:#}); starting fresh",
                    path.display()
                );
                Self::new(dir, transfer_id, total_chunks)
            }
            Err(e) => {
                tracing::debug!("no resume file, starting fresh: {e:#}");
                Self::new(dir, transfer_id, total_chunks)
            }
        }
    }

    fn try_load(dir: &Path, transfer_id: &[u8; 16], total_chunks: u64) -> Result<Self> {
        let name = format!("{}.mftp-resume", hex::encode(transfer_id));
        let path = dir.join(&name);

        let mut f =
            std::fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;

        let mut magic = [0u8; 8];
        f.read_exact(&mut magic).context("read magic")?;
        if &magic != RESUME_MAGIC {
            anyhow::bail!("unrecognised magic bytes");
        }

        let mut tag = [0u8; RESUME_TAG_LEN];
        f.read_exact(&mut tag).context("read integrity tag")?;

        let mut payload = Vec::new();
        f.read_to_end(&mut payload).context("read payload")?;

        let computed = blake3::hash(&payload);
        if tag != computed.as_bytes()[..RESUME_TAG_LEN] {
            anyhow::bail!("integrity tag mismatch (resume file corrupt)");
        }

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

        Ok(Self {
            path,
            transfer_id: *transfer_id,
            received: data.received,
            total_chunks,
            dirty: 0,
        })
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
        (0..self.total_chunks)
            .filter(|&i| self.is_received(i))
            .collect()
    }

    /// Return a clone of the raw packed bitvector for use in the wire protocol.
    pub fn received_bitvec(&self) -> Vec<u64> {
        self.received.clone()
    }

    /// Increment the dirty counter and return the new value.
    ///
    /// Callers compare the return value against `RESUME_SAVE_BATCH` to decide
    /// whether to take a snapshot and persist.
    pub fn incr_dirty(&mut self) -> u64 {
        self.dirty += 1;
        self.dirty
    }

    /// Reset the dirty counter after a successful save.
    pub fn reset_dirty(&mut self) {
        self.dirty = 0;
    }

    /// Serialize the current state into a [`ResumeSnapshot`].
    ///
    /// The snapshot contains a point-in-time copy of the bitvector and can be
    /// written to disk outside the mutex — the slow fsync does not block other
    /// stream workers while they mark their own chunks.
    pub fn snapshot(&self) -> Result<ResumeSnapshot> {
        let data = ResumeData {
            transfer_id: self.transfer_id,
            total_chunks: self.total_chunks,
            received: self.received.clone(),
        };
        let bincode_payload = bincode::serialize(&data).context("serialise resume state")?;
        let tag = blake3::hash(&bincode_payload);
        let mut payload =
            Vec::with_capacity(RESUME_MAGIC.len() + RESUME_TAG_LEN + bincode_payload.len());
        payload.extend_from_slice(RESUME_MAGIC);
        payload.extend_from_slice(&tag.as_bytes()[..RESUME_TAG_LEN]);
        payload.extend_from_slice(&bincode_payload);
        Ok(ResumeSnapshot {
            path: self.path.clone(),
            payload,
        })
    }

    /// Persist the current state to disk atomically (write-then-rename).
    ///
    /// Prefer the `snapshot()` + `write_to_disk()` pattern in hot paths so
    /// the fsync runs outside the mutex.  `save()` is retained for call sites
    /// that already hold no lock or that are not performance-critical.
    pub fn save(&self) -> Result<()> {
        self.snapshot()?.write_to_disk()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_reloads_received_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let id = [7u8; 16];
        let mut s = ResumeState::new(dir.path(), &id, 200);
        s.mark_received(0);
        s.mark_received(63);
        s.mark_received(199);
        s.save().unwrap();

        let loaded = ResumeState::try_load(dir.path(), &id, 200).unwrap();
        assert!(loaded.is_received(0));
        assert!(loaded.is_received(63));
        assert!(loaded.is_received(199));
        assert!(!loaded.is_received(1));
    }

    #[test]
    fn corrupt_payload_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let id = [9u8; 16];
        let mut s = ResumeState::new(dir.path(), &id, 64);
        s.mark_received(5);
        s.save().unwrap();

        // Flip a byte in the bincode payload (past the 8-byte magic + 8-byte tag).
        let path = dir.path().join(format!("{}.mftp-resume", hex::encode(id)));
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        // load_or_new must discard the corrupt file and start fresh.
        let fresh = ResumeState::load_or_new(dir.path(), &id, 64);
        assert!(!fresh.is_received(5));
        assert_eq!(fresh.received_chunks().len(), 0);
    }
}
