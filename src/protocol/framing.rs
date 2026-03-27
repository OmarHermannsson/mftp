//! Length-prefixed message framing over any async byte stream.
//!
//! Frame format: [u32 little-endian length][bincode payload]
//!
//! All functions are generic over [`tokio::io::AsyncRead`] / [`tokio::io::AsyncWrite`]
//! so they work identically over QUIC streams (quinn) and plain TCP streams.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap for chunk data frames (one compressed chunk payload).
const MAX_DATA_FRAME_SIZE: u32 = 128 * 1024 * 1024; // 128 MiB
/// Tight cap for control frames (NegotiateRequest/Response, TransferManifest,
/// SenderMessage, ReceiverMessage).  Prevents a malicious peer from forcing a
/// large heap allocation before deserialization even begins.
const MAX_CTRL_FRAME_SIZE: u32 = 1024 * 1024; // 1 MiB

pub async fn send_message<W, T>(stream: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let payload = bincode::serialize(msg)?;
    let len = u32::try_from(payload.len())
        .context("serialized message exceeds 4 GiB — cannot frame")?;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&payload).await?;
    Ok(())
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
