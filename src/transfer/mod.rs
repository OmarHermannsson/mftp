//! High-level transfer orchestration.
//!
//! # Send flow
//!   1. `Sender::new` opens a QUIC connection and control stream.
//!   2. Sends `TransferManifest`; receiver replies with `ReceiverMessage::Ready`
//!      (which may include chunks already received, enabling resume).
//!   3. Remaining chunks are dispatched across N parallel QUIC data streams via
//!      a work-stealing queue in `chunk::ChunkQueue`.
//!   4. After all chunks are sent, sender waits for `ReceiverMessage::Complete`
//!      or handles `ReceiverMessage::Retransmit`.
//!
//! # Receive flow
//!   1. `Receiver` accepts a QUIC connection, reads `TransferManifest`.
//!   2. Checks resume state; sends `ReceiverMessage::Ready`.
//!   3. Spawns one task per incoming data stream; each task writes chunks to
//!      the resume store and the output file via `pwrite`-style random access.
//!   4. Once all chunks are received and verified, sends `ReceiverMessage::Complete`.

pub mod chunk;
pub mod hash;
pub mod negotiate;
pub mod receiver;
pub mod resume;
pub mod sender;
