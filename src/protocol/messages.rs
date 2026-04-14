use serde::{Deserialize, Serialize};

// ── Parameter negotiation (first round-trip on the control stream) ────────────

/// Current protocol version.  Both sides include this in NegotiateRequest /
/// NegotiateResponse so each peer knows whether the other supports newer
/// control messages (e.g. AdjustStreams / AdjustStreamsAck).
///
/// Version history:
///   1 — initial release (no version field; old binaries implicitly version 1)
///   2 — adds protocol_version field + AdjustStreams / AdjustStreamsAck messages
pub const PROTOCOL_VERSION: u32 = 2;

/// Sent by the sender immediately after opening the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiateRequest {
    /// Logical CPU cores available on the sender.
    pub cpu_cores: u32,
    /// Wire protocol version this sender supports.  See [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
}

/// Receiver's reply to `NegotiateRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiateResponse {
    /// Logical CPU cores available on the receiver.
    pub cpu_cores: u32,
    /// Wire protocol version this receiver supports.  See [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
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

/// One chunk of file data in a FEC-enabled transfer.
///
/// **Data shards** (`is_parity = false`):
///   - `chunk_index` is the actual file chunk index.
///   - `chunk_hash` is `blake3(raw_uncompressed_bytes)`, same as non-FEC `ChunkData`.
///   - `compressed` indicates whether the payload is zstd-compressed.
///   - `shard_lengths` and `shard_compressed` are empty (zero-length).
///   - `payload` contains the compressed (or raw) bytes, **not** RS-padded.
///
/// **Parity shards** (`is_parity = true`):
///   - `chunk_index` is a sentinel value (not used for file writes).
///   - `chunk_hash` is `blake3(payload)` for parity wire-integrity only.
///   - `compressed` is always `false`.
///   - `shard_lengths[i]` is the unpadded wire length of data shard `i` in this stripe.
///   - `shard_compressed[i]` is `1` if data shard `i` was zstd-compressed, `0` otherwise.
///   - `payload` is the RS-computed parity shard (length = stripe maximum).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecChunkData {
    pub transfer_id: [u8; 16],
    /// File chunk index (data shards only; sentinel for parity shards).
    pub chunk_index: u64,
    /// BLAKE3 hash: `blake3(raw_uncompressed)` for data; `blake3(payload)` for parity.
    pub chunk_hash: [u8; 32],
    /// True if the payload is zstd-compressed (always false for parity shards).
    pub compressed: bool,
    pub stripe_index: u32,
    /// 0-based index within the stripe (`0..data_shards` for data; `data_shards..` for parity).
    pub shard_index_in_stripe: u16,
    pub is_parity: bool,
    /// Non-empty only on parity shards: unpadded compressed length of each data shard.
    pub shard_lengths: Vec<u32>,
    /// Non-empty only on parity shards: `1` if the corresponding data shard was compressed.
    pub shard_compressed: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Sent by the sender on the control stream after all data streams finish.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SenderMessage {
    /// SHA-256 of the complete original file (pre-compression).
    /// Computed concurrently with the transfer; delivered here so it doesn't
    /// block connection setup.
    Complete { file_hash: [u8; 32] },
    /// Request the receiver to adjust the number of active data streams.
    ///
    /// Sent by the sender during the data-transfer phase when adaptive stream
    /// scaling is enabled (both peers protocol_version >= 2).
    /// - Scale-up: receiver should accept `target_count - current_count` new
    ///   streams and reply with `AdjustStreamsAck`.
    /// - Scale-down: sender closes excess streams (QUIC FIN / TLS shutdown);
    ///   receiver workers on those streams see EOF and exit normally.
    AdjustStreams { target_count: u8 },
}

/// Sent by the receiver on the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReceiverMessage {
    /// Receiver is ready; packed bitvector of already-received chunks (resume).
    ///
    /// `received_bits[i]` has bit `j` set iff chunk `i*64+j` was already written to
    /// disk.  This is 64× smaller than a list of chunk indices and stays well within
    /// the wire frame limit for any file that mftp can transfer.
    Ready {
        received_bits: Vec<u64>,
        total_chunks: u64,
    },
    /// Periodic progress update sent at most every 100 ms during the
    /// data-transfer phase.
    ///
    /// - `bytes_written`: cumulative bytes confirmed written to disk.
    /// - `in_flight_chunks`: number of chunk-processing tasks currently
    ///   active across all stream workers.  Max is `num_streams × 4`
    ///   (MAX_IN_FLIGHT per worker).  Consistently near the maximum signals
    ///   receiver-side CPU or disk saturation.
    /// - `disk_stall_ms`: peak chunk-write latency (ms) observed since the
    ///   last Progress message; reset to 0 after each report.  Values above
    ///   ~50 ms indicate the receiver disk is becoming a bottleneck.
    Progress {
        bytes_written: u64,
        in_flight_chunks: u32,
        disk_stall_ms: u32,
    },
    /// All chunks received and verified; echoes the file hash.
    Complete { file_hash: [u8; 32] },
    /// Receiver encountered a fatal error.
    Error { message: String },
    /// Acknowledgement of a `SenderMessage::AdjustStreams` request.
    ///
    /// `accepted_count` is the actual new total stream count after the
    /// adjustment.  It may differ from `target_count` if the receiver could
    /// not open/accept all requested streams.
    AdjustStreamsAck { accepted_count: u8 },
}
