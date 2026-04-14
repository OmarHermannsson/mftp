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

use crate::protocol::messages::{ChunkData, FecChunkData};

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
    let len =
        u32::try_from(payload.len()).context("serialized message exceeds 4 GiB — cannot frame")?;
    // Write length prefix + payload as a single buffer so the TLS layer sees one
    // contiguous write (no separate tiny record for the 4-byte length prefix).
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&payload);
    stream.write_all(&frame).await?;
    stream.flush().await?;
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
    stream.flush().await?;
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
    if stream
        .read(&mut hdr[..1])
        .await
        .context("read chunk frame byte 0")?
        == 0
    {
        return Ok(None);
    }
    stream
        .read_exact(&mut hdr[1..])
        .await
        .context("read chunk frame header")?;

    let frame_body_len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
    if frame_body_len > MAX_DATA_FRAME_SIZE as usize {
        bail!("chunk data frame too large: {frame_body_len} bytes (limit {MAX_DATA_FRAME_SIZE})");
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

    Ok(Some(ChunkData {
        transfer_id,
        chunk_index,
        chunk_hash,
        compressed,
        payload,
    }))
}

// ── FEC chunk-data framing ────────────────────────────────────────────────────

/// Fixed-size fields before the variable shard-metadata block in a `FecChunkData` frame:
///   transfer_id [16]  +  chunk_index u64 [8]  +  chunk_hash [32]
///   +  compressed u8 [1]  +  stripe_index u32 [4]
///   +  shard_index_in_stripe u16 [2]  +  is_parity u8 [1]
///   +  shard_count u32 [4]
///      = 68 bytes
const FEC_FIXED_HDR: usize = 16 + 8 + 32 + 1 + 4 + 2 + 1 + 4;

/// Send a `FecChunkData` frame without copying the payload through bincode.
///
/// Wire format:
///   [u32 LE: frame_body_len]
///   [68 bytes: fixed fields (see FEC_FIXED_HDR)]
///   [shard_count × 4 bytes: shard_lengths as u32 LE]
///   [shard_count bytes: shard_compressed flags]
///   [8 bytes: payload_len u64 LE]
///   [payload_len bytes: payload]
pub async fn send_fec_chunk_data<W>(stream: &mut W, msg: &FecChunkData) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let shard_count = msg.shard_lengths.len() as u32;
    let payload_len = msg.payload.len();
    let frame_body_len =
        u32::try_from(FEC_FIXED_HDR + (shard_count as usize) * 5 + 8 + payload_len)
            .context("FEC chunk data frame too large")?;

    // Build frame prefix + fixed header + shard metadata into one contiguous buffer.
    let var_hdr_len = (shard_count as usize) * 5; // 4 bytes per length + 1 byte per flag
    let mut hdr = Vec::with_capacity(4 + FEC_FIXED_HDR + var_hdr_len + 8);
    hdr.extend_from_slice(&frame_body_len.to_le_bytes());
    hdr.extend_from_slice(&msg.transfer_id);
    hdr.extend_from_slice(&msg.chunk_index.to_le_bytes());
    hdr.extend_from_slice(&msg.chunk_hash);
    hdr.push(msg.compressed as u8);
    hdr.extend_from_slice(&msg.stripe_index.to_le_bytes());
    hdr.extend_from_slice(&msg.shard_index_in_stripe.to_le_bytes());
    hdr.push(msg.is_parity as u8);
    hdr.extend_from_slice(&shard_count.to_le_bytes());
    for &l in &msg.shard_lengths {
        hdr.extend_from_slice(&l.to_le_bytes());
    }
    hdr.extend_from_slice(&msg.shard_compressed);
    hdr.extend_from_slice(&(payload_len as u64).to_le_bytes());

    stream.write_all(&hdr).await?;
    stream.write_all(&msg.payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Receive a `FecChunkData` frame without the intermediate bincode copy.
///
/// Returns `Ok(None)` on clean EOF at a frame boundary.
pub async fn recv_fec_chunk_data<R>(stream: &mut R) -> Result<Option<FecChunkData>>
where
    R: AsyncRead + Unpin,
{
    // Read frame_body_len (4) + fixed header (68) in one call.
    const FIXED_TOTAL: usize = 4 + FEC_FIXED_HDR;
    let mut hdr = [0u8; FIXED_TOTAL];

    if stream
        .read(&mut hdr[..1])
        .await
        .context("read FEC chunk frame byte 0")?
        == 0
    {
        return Ok(None); // clean EOF at frame boundary
    }
    stream
        .read_exact(&mut hdr[1..])
        .await
        .context("read FEC chunk frame fixed header")?;

    let frame_body_len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
    if frame_body_len > MAX_DATA_FRAME_SIZE as usize {
        bail!(
            "FEC chunk data frame too large: {frame_body_len} bytes (limit {MAX_DATA_FRAME_SIZE})"
        );
    }

    let transfer_id: [u8; 16] = hdr[4..20].try_into().unwrap();
    let chunk_index = u64::from_le_bytes(hdr[20..28].try_into().unwrap());
    let chunk_hash: [u8; 32] = hdr[28..60].try_into().unwrap();
    let compressed = hdr[60] != 0;
    let stripe_index = u32::from_le_bytes(hdr[61..65].try_into().unwrap());
    let shard_index_in_stripe = u16::from_le_bytes(hdr[65..67].try_into().unwrap());
    let is_parity = hdr[67] != 0;
    let shard_count = u32::from_le_bytes(hdr[68..72].try_into().unwrap()) as usize;

    // Read shard_lengths (4 bytes each).
    let mut lengths_buf = vec![0u8; shard_count * 4];
    if !lengths_buf.is_empty() {
        stream
            .read_exact(&mut lengths_buf)
            .await
            .context("read FEC shard_lengths")?;
    }
    let shard_lengths: Vec<u32> = lengths_buf
        .chunks(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();

    // Read shard_compressed (1 byte each).
    let mut shard_compressed = vec![0u8; shard_count];
    if !shard_compressed.is_empty() {
        stream
            .read_exact(&mut shard_compressed)
            .await
            .context("read FEC shard_compressed")?;
    }

    // Read payload_len then payload.
    let mut payload_len_buf = [0u8; 8];
    stream
        .read_exact(&mut payload_len_buf)
        .await
        .context("read FEC payload_len")?;
    let payload_len = u64::from_le_bytes(payload_len_buf) as usize;

    let expected_frame_body = FEC_FIXED_HDR + shard_count * 5 + 8 + payload_len;
    if frame_body_len != expected_frame_body {
        bail!(
            "FEC chunk frame body length mismatch: \
             got {frame_body_len}, expected {expected_frame_body}"
        );
    }

    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .context("read FEC chunk payload")?;

    Ok(Some(FecChunkData {
        transfer_id,
        chunk_index,
        chunk_hash,
        compressed,
        stripe_index,
        shard_index_in_stripe,
        is_parity,
        shard_lengths,
        shard_compressed,
        payload,
    }))
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
    if stream
        .read(&mut len_buf[..1])
        .await
        .context("read frame header byte 0")?
        == 0
    {
        return Ok(None); // clean EOF at a frame boundary
    }
    stream
        .read_exact(&mut len_buf[1..])
        .await
        .context("read frame header bytes 1-3")?;

    let len = u32::from_le_bytes(len_buf);
    if len > max_size {
        bail!("frame too large: {len} bytes (limit {max_size})");
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .with_context(|| format!("read frame body ({len} bytes)"))?;
    Ok(Some(bincode::deserialize(&buf)?))
}
