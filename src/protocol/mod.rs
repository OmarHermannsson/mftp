//! Wire protocol definitions.
//!
//! All messages are serialized with `bincode` and framed over a QUIC stream.
//! The framing format is: [u32 length (LE)] [message bytes].
//!
//! Control stream (stream 0): handshake + TransferManifest + Ack messages.
//! Data streams (1..=N):      one ChunkData message per stream, pipelined.

pub mod framing;
pub mod messages;
