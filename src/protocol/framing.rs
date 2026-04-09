//! Length-prefixed message framing over any async byte stream.
//!
//! Frame format: [u32 little-endian length][bincode payload]
//!
//! All functions are generic over [`tokio::io::AsyncRead`] / [`tokio::io::AsyncWrite`]
//! so they work identically over QUIC streams (quinn) and plain TCP streams.
//!
//! For large chunk-data frames a dedicated pair of functions (`send_chunk_data` /
//! `recv_chunk_data`) serialises the fixed-size header fields manually and writes
//! the payload directly, avoiding the full 8 MiB bincode copy that the generic
//! `send_message` / `recv_data_message` pair would produce.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::messages::ChunkData;

/// Hard cap for chunk data frames (one compressed chunk payload).
const MAX_DATA_FRAME_SIZE: u32 = 128 * 1024 * 1024; // 128 MiB
/// Tight cap for control frames (NegotiateRequest/Response, TransferManifest,
/// SenderMessage, ReceiverMessage).  Prevents a malicious peer from forcing a
/// large heap allocation before deserialization even begins.
const MAX_CTRL_FRAME_SIZE: u32 = 1024 * 1024; // 1 MiB

/// Byte count of the fixed-size fields in a `ChunkData` frame body, matching
/// bincode's default (little-endian fixint) layout exactly:
///   [u8;16] transfer_id  +  u64 chunk_index  +  [u8;32] chunk_hash
///   +  u8 compressed  +  u64 payload_len  =  65 bytes
const CHUNK_HDR: usize = 16 + 8 + 32 + 1 + 8;

pub async fn send_message<W, T>(stream: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let payload = bincode::serialize(msg)?;
    let len = u32::try_from(payload.len())
        .context("serialized message exceeds 4 GiB — cannot frame")?;
    // Write length prefix + payload as a single buffer so the TLS layer sees one
    // contiguous write (no separate tiny record for the 4-byte length prefix).
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&payload);
    stream.write_all(&frame).await?;
    Ok(())
}

/// Send a `ChunkData` frame without copying the payload through bincode.
///
/// Wire format is identical to `bincode::serialize(ChunkData)` with the
/// standard 4-byte length prefix prepended, so the receiver can use either
/// `recv_data_message` or `recv_chunk_data` to decode it.
pub async fn send_chunk_data<W>(stream: &mut W, msg: &ChunkData) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload_len = msg.payload.len();
    let frame_body_len =
        u32::try_from(CHUNK_HDR + payload_len).context("chunk data frame too large")?;

    // Build the 4-byte length prefix + 65-byte header into one small stack buffer,
    // then write the raw payload in a second call.  Two writes of (69 B, up to 8 MiB)
    // rather than one write of 8 MiB+ avoids materialising a copy of the payload.
    let mut hdr = [0u8; 4 + CHUNK_HDR];
    hdr[0..4].copy_from_slice(&frame_body_len.to_le_bytes());
    hdr[4..20].copy_from_slice(&msg.transfer_id);
    hdr[20..28].copy_from_slice(&msg.chunk_index.to_le_bytes());
    hdr[28..60].copy_from_slice(&msg.chunk_hash);
    hdr[60] = msg.compressed as u8;
    hdr[61..69].copy_from_slice(&(payload_len as u64).to_le_bytes());

    stream.write_all(&hdr).await?;
    stream.write_all(&msg.payload).await?;
    Ok(())
}

/// Receive a `ChunkData` frame without the intermediate bincode copy.
///
/// Reads the 65-byte header directly, then reads the payload straight into its
/// final `Vec<u8>` — no second allocation needed.
///
/// Returns `Ok(None)` on clean EOF at a frame boundary.
pub async fn recv_chunk_data<R>(stream: &mut R) -> Result<Option<ChunkData>>
where
    R: AsyncRead + Unpin,
{
    let mut hdr = [0u8; 4 + CHUNK_HDR];

    // Single byte first so we can detect clean EOF without treating it as an error.
    if stream.read(&mut hdr[..1]).await.context("read chunk frame byte 0")? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut hdr[1..]).await.context("read chunk frame header")?;

    let frame_body_len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
    if frame_body_len > MAX_DATA_FRAME_SIZE as usize {
        bail!("chunk data frame too large: {frame_body_len} bytes (limit {})", MAX_DATA_FRAME_SIZE);
    }
    if frame_body_len < CHUNK_HDR {
        bail!("chunk data frame too small: {frame_body_len} bytes");
    }

    let transfer_id: [u8; 16] = hdr[4..20].try_into().unwrap();
    let chunk_index = u64::from_le_bytes(hdr[20..28].try_into().unwrap());
    let chunk_hash: [u8; 32] = hdr[28..60].try_into().unwrap();
    let compressed = hdr[60] != 0;
    let payload_len_hdr = u64::from_le_bytes(hdr[61..69].try_into().unwrap()) as usize;
    let payload_len = frame_body_len - CHUNK_HDR;
    if payload_len != payload_len_hdr {
        bail!(
            "chunk data frame: payload length mismatch \
             (frame says {payload_len}, bincode says {payload_len_hdr})"
        );
    }

    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .context("read chunk data payload")?;

    Ok(Some(ChunkData { transfer_id, chunk_index, chunk_hash, compressed, payload }))
}

/// Read one chunk-data frame (128 MiB cap).
///
/// Returns `Ok(None)` on clean EOF at a frame boundary.
pub async fn recv_data_message<R, T>(stream: &mut R) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    recv_message_inner(stream, MAX_DATA_FRAME_SIZE).await
}

/// Read one control frame (1 MiB cap).
///
/// Returns `Ok(None)` on clean EOF at a frame boundary.
pub async fn recv_message<R, T>(stream: &mut R) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    recv_message_inner(stream, MAX_CTRL_FRAME_SIZE).await
}

/// Like [`recv_message`] but treats EOF as an error.
/// Use on the control stream where unexpected close is always a peer error.
pub async fn recv_message_required<R, T>(stream: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    recv_message(stream)
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream closed unexpectedly"))
}

async fn recv_message_inner<R, T>(stream: &mut R, max_size: u32) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    // Read the first byte with read() so we can distinguish a clean EOF
    // (returns 0) from a mid-frame truncation.
    let mut len_buf = [0u8; 4];
    if stream.read(&mut len_buf[..1]).await.context("read frame header byte 0")? == 0 {
        return Ok(None); // clean EOF at a frame boundary
    }
    stream.read_exact(&mut len_buf[1..]).await.context("read frame header bytes 1-3")?;

    let len = u32::from_le_bytes(len_buf);
    if len > max_size {
        bail!("frame too large: {len} bytes (limit {max_size})");
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.with_context(|| format!("read frame body ({len} bytes)"))?;
    Ok(Some(bincode::deserialize(&buf)?))
}
