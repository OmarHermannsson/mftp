//! High-level transfer orchestration.
//!
//! # Send flow
//!   1. `Sender::new` opens a QUIC connection and control stream.
//!   2. Sends `TransferManifest`; receiver replies with `ReceiverMessage::Ready`
//!      (which may include chunks already received, enabling resume).
//!   3. Remaining chunks are dispatched across N parallel QUIC data streams via
//!      a work-stealing queue in `chunk::ChunkQueue`.
//!   4. After all chunks are sent, the sender sends `SenderMessage::Complete`
//!      and waits for the receiver's terminal `Complete`/`Error`.  A chunk that
//!      fails its hash check is dropped (left unmarked) rather than aborting the
//!      transfer.  At this checkpoint a v5 receiver may reply with
//!      `ReceiverMessage::Retransmit` listing still-missing chunks; the sender
//!      re-sends them as plain `ChunkData` on the control stream and re-sends
//!      `Complete` (in-band incremental repair, single-file only, bounded by
//!      `MAX_REPAIR_ROUNDS`).  If repair is unavailable or exhausted, the
//!      transfer fails and the missing chunks are re-fetched on the next run
//!      via the resume state.
//!
//! # Receive flow
//!   1. `Receiver` accepts a QUIC connection, reads `TransferManifest`.
//!   2. Checks resume state; sends `ReceiverMessage::Ready`.
//!   3. Spawns one task per incoming data stream; each task writes chunks to
//!      the resume store and the output file via `pwrite`-style random access.
//!   4. On the sender's `Complete`, if chunks are still missing (dropped corrupt
//!      chunk, or an unreconstructable FEC stripe) and repair is available, the
//!      receiver requests them via `ReceiverMessage::Retransmit` and writes the
//!      replies before finalizing.  Once every chunk is on disk and the
//!      whole-file hash verifies, it sends `ReceiverMessage::Complete`.

pub mod chunk;
pub mod hash;
pub mod negotiate;
pub mod receiver;
pub mod resume;
pub mod sender;
