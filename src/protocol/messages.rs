use serde::{Deserialize, Serialize};

// ── Parameter negotiation (first round-trip on the control stream) ────────────

/// Sent by the sender immediately after opening the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiateRequest {
    /// Logical CPU cores available on the sender.
    pub cpu_cores: u32,
    /// Total file size in bytes (helps receiver recommend chunk size).
    pub file_size: u64,
}

/// Receiver's reply to `NegotiateRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiateResponse {
    /// Logical CPU cores available on the receiver.
    pub cpu_cores: u32,
}

/// Sent by the sender on the control stream before data transfer begins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferManifest {
    /// Unique transfer ID (UUIDv4).
    pub transfer_id: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub chunk_size: usize,
    pub total_chunks: u64,
    /// How many parallel data streams the sender will open.
    pub num_streams: usize,
    pub compression: Compression,
    pub fec: Option<FecParams>,
    // Note: file_hash is NOT in the manifest. The sender computes it concurrently
    // with the transfer and delivers it via SenderMessage::Complete after all
    // data streams finish. This lets the sender start immediately without
    // blocking on a full-file hash before connecting.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Compression {
    None,
    Zstd { level: i32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecParams {
    /// Number of original shards per group.
    pub data_shards: usize,
    /// Number of parity shards per group.
    pub parity_shards: usize,
}

/// One chunk of file data, sent on a data stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkData {
    pub transfer_id: [u8; 16],
    pub chunk_index: u64,
    /// SHA-256 of the wire payload (post-compression).
    pub chunk_hash: [u8; 32],
    /// Whether the payload is zstd-compressed.
    /// Per-chunk flag because compression is skipped for incompressible chunks.
    pub compressed: bool,
    pub payload: Vec<u8>,
}

/// Sent by the sender on the control stream after all data streams finish.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SenderMessage {
    /// SHA-256 of the complete original file (pre-compression).
    /// Computed concurrently with the transfer; delivered here so it doesn't
    /// block connection setup.
    Complete { file_hash: [u8; 32] },
}

/// Sent by the receiver on the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReceiverMessage {
    /// Receiver is ready; lists chunk indices already on disk (resume).
    Ready { have_chunks: Vec<u64> },
    /// Periodic progress update: total bytes written to disk so far.
    /// Sent at most every 100 ms during the data-transfer phase so the
    /// sender can display an accurate progress bar.
    Progress { bytes_written: u64 },
    /// All chunks received and verified; echoes the file hash.
    Complete { file_hash: [u8; 32] },
    /// Some chunks are missing; sender should retransmit them.
    Retransmit { chunk_indices: Vec<u64> },
    /// Receiver encountered a fatal error.
    Error { message: String },
}
