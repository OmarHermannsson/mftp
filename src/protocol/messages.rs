use serde::{Deserialize, Serialize};

// ── Parameter negotiation (first round-trip on the control stream) ────────────

/// Current protocol version.  Both sides include this in NegotiateRequest /
/// NegotiateResponse so each peer knows whether the other supports newer
/// control messages (e.g. AdjustStreams / AdjustStreamsAck).
///
/// Version history:
///   1 — initial release (no version field; old binaries implicitly version 1)
///   2 — adds protocol_version field + AdjustStreams / AdjustStreamsAck messages
///   3 — adds recursive directory transfer: DirEntries message sent by sender
///       after TransferManifest when peer_version >= 3.
///   4 — adds `fatal` field to ReceiverMessage::Error so the sender can
///       distinguish fatal errors (hash mismatch, disk full) from transient
///       stream errors and decide whether to retry or abort.
///   5 — adds ReceiverMessage::Retransmit for in-band incremental repair: at
///       the completion checkpoint the receiver can request missing chunks
///       (failed hash, or an unreconstructable FEC stripe) over the control
///       stream instead of aborting, keeping the connection (and its warmed
///       congestion window) alive. Single-file transfers only.
///   6 — QUIC sender pipelines NegotiateRequest + TransferManifest + DirEntries
///       into a single opening flight instead of waiting for NegotiateResponse
///       between them, collapsing startup from two control round-trips to one.
///       This is wire-byte-identical to v5 for any v3+ receiver (framing is
///       ordered, self-delimiting frames, and the receiver reads them in the
///       same order regardless of sender await timing), so it requires no
///       receiver change; the bump is a marker and documents that the QUIC fast
///       path assumes a peer ≥ v3 (directory transfers already require it).
///   7 — each data stream begins with a `StreamHello { transfer_id, stream_seq }`
///       frame before any `ChunkData`. The receiver reads it first and rejects a
///       stream whose `transfer_id` doesn't match the negotiated manifest. This
///       lets data streams be attributed to a transfer regardless of which
///       connection or path they arrive on — the prerequisite for multipath
///       (M3) and relayed (M7) transfers, where streams no longer all share one
///       connection. Only sent/expected when BOTH peers are ≥ v7; against an
///       older peer the preamble is omitted and behaviour is identical to v6.
pub const PROTOCOL_VERSION: u32 = 7;

/// First version that sends/expects the [`StreamHello`] data-stream preamble.
pub const STREAM_HELLO_MIN_VERSION: u32 = 7;

/// Maximum number of completion→repair round-trips before the sender/receiver
/// give up and fall back to abort + resume.  A deterministic sender-side fault
/// would otherwise retransmit forever.
pub const MAX_REPAIR_ROUNDS: u32 = 5;

/// Maximum chunks the receiver will request in a single `Retransmit` (keeps the
/// message within the control-frame limit and bounds repair effort — a larger
/// gap is cheaper to recover with a fresh resumed transfer).
pub const MAX_REPAIR_CHUNKS_PER_ROUND: usize = 100_000;

/// First version that sends the `DirEntries` message (recursive directory
/// transfer). A sender to an older peer must refuse a directory transfer.
pub const MIN_DIRECTORY_VERSION: u32 = 3;

/// First version that supports in-band incremental repair
/// (`ReceiverMessage::Retransmit`). Against an older peer the receiver falls
/// back to abort + resume instead.
pub const MIN_REPAIR_VERSION: u32 = 5;

// ── Version-gated feature decisions ───────────────────────────────────────────
//
// Every protocol feature that is only safe when *both* peers understand it is
// gated through one of these helpers, so the cross-version rules live in one
// place (and are unit-testable without a live handshake).

/// Whether the `StreamHello` data-stream preamble (v7) is active on this
/// transfer. It is sent/expected only when **both** peers are ≥ v7 — otherwise
/// the wire stays byte-identical to v6 (see [`PROTOCOL_VERSION`] history).
pub fn stream_hello_active(local_version: u32, peer_version: u32) -> bool {
    local_version >= STREAM_HELLO_MIN_VERSION && peer_version >= STREAM_HELLO_MIN_VERSION
}

/// Whether `peer_version` understands the `DirEntries` message (directory transfers).
pub fn directory_supported(peer_version: u32) -> bool {
    peer_version >= MIN_DIRECTORY_VERSION
}

/// Whether `peer_version` supports in-band incremental repair.
pub fn repair_supported(peer_version: u32) -> bool {
    peer_version >= MIN_REPAIR_VERSION
}

/// Test-only override of the locally-advertised protocol version, letting an
/// in-process test negotiate down to an older version to exercise cross-version
/// interop. Hidden from docs; production never sets it (the only cost is one
/// relaxed atomic load per negotiation).
#[doc(hidden)]
pub mod test_hooks {
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 0 = no override (use [`super::PROTOCOL_VERSION`]).
    static FORCED_VERSION: AtomicU32 = AtomicU32::new(0);

    /// Force the version advertised in NegotiateRequest/Response, or clear it.
    pub fn force_local_version(version: Option<u32>) {
        FORCED_VERSION.store(version.unwrap_or(0), Ordering::Relaxed);
    }

    pub(crate) fn forced() -> u32 {
        FORCED_VERSION.load(Ordering::Relaxed)
    }
}

/// The protocol version this peer advertises during negotiation. Normally
/// [`PROTOCOL_VERSION`]; a test may cap it via
/// [`test_hooks::force_local_version`] to drive older-peer interop.
pub fn advertised_version() -> u32 {
    match test_hooks::forced() {
        0 => PROTOCOL_VERSION,
        v => v,
    }
}

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

// ── Directory transfer types (protocol version ≥ 3) ─────────────────────────

/// Kind of entry in a recursive directory transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileKind {
    /// A regular file with data bytes in the concat stream.
    File,
    /// An empty directory (no data bytes; materialised before data transfer).
    Directory,
    /// A symbolic link (no data bytes; target is preserved as-is).
    Symlink { target: String },
}

/// One entry in a recursive directory manifest.
///
/// `path` is a relative path using forward-slash separators and no leading `/`.
/// Only `FileKind::File` entries contribute bytes to the concat stream;
/// `Directory` and `Symlink` entries have `size == 0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path within the transfer root (e.g. `"docs/readme.txt"`).
    pub path: String,
    /// Size in bytes; 0 for `Directory` and `Symlink`.
    pub size: u64,
    pub kind: FileKind,
    /// Unix permission bits from the source.  0 if unavailable (e.g. Windows).
    pub mode: u32,
    /// Modification time as seconds since the Unix epoch.  0 if unavailable.
    pub mtime: i64,
}

/// Sent by a protocol-version-3+ sender immediately after `TransferManifest`.
///
/// `entries == None` → single-file transfer (same semantics as version 2,
/// just with the handshake extended to v3).
///
/// `entries == Some(vec)` → directory transfer; `vec` is ordered by path and
/// describes the layout of the virtual concatenated byte stream (all
/// `FileKind::File` sizes sum to `TransferManifest.file_size`).
///
/// Not sent by version-2 senders.  The receiver must check
/// `peer_protocol_version < 3` and skip this read when talking to an old peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntries {
    pub entries: Option<Vec<FileEntry>>,
}

/// Preamble frame sent by the sender at the very start of each data stream
/// (protocol version ≥ [`STREAM_HELLO_MIN_VERSION`]), before any `ChunkData`.
///
/// Lets the receiver attribute a data stream to a transfer independently of the
/// connection it arrived on — the foundation for multipath (M3) and relayed
/// (M7) transfers. For single-connection transfers it is a cheap correctness
/// check: the receiver rejects any stream whose `transfer_id` doesn't match the
/// manifest it negotiated on the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamHello {
    /// Must equal the `transfer_id` from the `TransferManifest`.
    pub transfer_id: [u8; 16],
    /// 0-based index of this stream within the transfer. Informational
    /// (logging / future per-path scheduling); not required for correctness
    /// because each `ChunkData` already carries its own `chunk_index`.
    pub stream_seq: u32,
}

/// One chunk of file data, sent on a data stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkData {
    pub transfer_id: [u8; 16],
    pub chunk_index: u64,
    /// BLAKE3 hash of the raw uncompressed chunk data.
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
    /// BLAKE3 hash of the complete original file.
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
    /// Receiver encountered an error.
    ///
    /// `fatal` is `true` for errors that make a retry pointless (hash mismatch,
    /// disk full, permission denied).  `false` or absent (v3 receivers) means
    /// the transfer may be resumed by reconnecting; the receiver's resume bitmap
    /// already reflects which chunks were successfully written.
    ///
    /// Added in protocol v4; older receivers never set `fatal`, so the sender
    /// MUST treat a missing field (serde default = false) as non-fatal.
    Error {
        message: String,
        #[serde(default)]
        fatal: bool,
    },
    /// Acknowledgement of a `SenderMessage::AdjustStreams` request.
    ///
    /// `accepted_count` is the actual new total stream count after the
    /// adjustment.  It may differ from `target_count` if the receiver could
    /// not open/accept all requested streams.
    AdjustStreamsAck { accepted_count: u8 },
    /// Sent in response to `SenderMessage::Complete` (protocol v5+) when chunks
    /// are still missing from disk — a failed hash check or an FEC stripe that
    /// could not be reconstructed.  The sender re-reads each listed chunk and
    /// re-sends it as a plain `ChunkData` frame on the control stream, then
    /// re-sends `Complete`; the receiver re-checks and either repeats or
    /// finalizes.  Bounded by `MAX_REPAIR_ROUNDS` / `MAX_REPAIR_CHUNKS_PER_ROUND`
    /// on both ends.  Single-file transfers only.
    Retransmit { chunks: Vec<u64> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_hello_active_only_when_both_v7() {
        // Active only if both peers are ≥ v7.
        assert!(stream_hello_active(7, 7));
        assert!(stream_hello_active(7, 8));
        assert!(stream_hello_active(8, 7));
        // Any older peer (either side) disables it → wire stays v6-identical.
        assert!(!stream_hello_active(7, 6));
        assert!(!stream_hello_active(6, 7));
        assert!(!stream_hello_active(6, 6));
    }

    #[test]
    fn directory_and_repair_version_floors() {
        assert!(!directory_supported(2));
        assert!(directory_supported(MIN_DIRECTORY_VERSION));
        assert!(directory_supported(7));

        assert!(!repair_supported(4));
        assert!(repair_supported(MIN_REPAIR_VERSION));
        assert!(repair_supported(7));
    }

    #[test]
    fn advertised_version_respects_override() {
        // Default: the compiled-in version.
        assert_eq!(advertised_version(), PROTOCOL_VERSION);
        // Override caps it; clearing restores the default.
        test_hooks::force_local_version(Some(6));
        assert_eq!(advertised_version(), 6);
        test_hooks::force_local_version(None);
        assert_eq!(advertised_version(), PROTOCOL_VERSION);
    }
}
