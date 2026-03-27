//! Length-prefixed message framing over QUIC streams.
//!
//! Frame format: [u32 little-endian length][bincode payload]

use anyhow::{bail, Context, Result};
use quinn::{RecvStream, SendStream};

/// Hard cap for chunk data frames (the payload of a single compressed chunk).
const MAX_DATA_FRAME_SIZE: u32 = 128 * 1024 * 1024; // 128 MiB
/// Tight cap for control frames (NegotiateRequest/Response, TransferManifest,
/// SenderMessage, ReceiverMessage).  Prevents a malicious peer from forcing a
/// large heap allocation before deserialization even begins.
const MAX_CTRL_FRAME_SIZE: u32 = 1 * 1024 * 1024; // 1 MiB

pub async fn send_message<T: serde::Serialize>(stream: &mut SendStream, msg: &T) -> Result<()> {
    let payload = bincode::serialize(msg)?;
    let len = u32::try_from(payload.len())
        .context("serialized message exceeds 4 GiB — cannot frame")?;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

/// Variant for chunk data streams; allows frames up to 128 MiB.
pub async fn recv_data_message<T: serde::de::DeserializeOwned>(
    stream: &mut RecvStream,
) -> Result<Option<T>> {
    recv_message_inner(stream, MAX_DATA_FRAME_SIZE).await
}

/// Read one framed message from `stream` (control stream variant, 1 MiB cap).
///
/// Returns `Ok(None)` when the stream ends cleanly at a frame boundary
/// (i.e. the sender called `finish()` with no more frames pending).
/// Returns `Err` for any mid-frame truncation or deserialization failure.
pub async fn recv_message<T: serde::de::DeserializeOwned>(
    stream: &mut RecvStream,
) -> Result<Option<T>> {
    recv_message_inner(stream, MAX_CTRL_FRAME_SIZE).await
}

async fn recv_message_inner<T: serde::de::DeserializeOwned>(
    stream: &mut RecvStream,
    max_size: u32,
) -> Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(quinn::ReadExactError::FinishedEarly(n)) => {
            bail!("stream ended mid-frame after {n} bytes of length header");
        }
        Err(quinn::ReadExactError::ReadError(e)) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > max_size {
        bail!("frame too large: {len} bytes (limit {max_size})");
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(n) => {
            anyhow::anyhow!("stream ended mid-payload after {n}/{len} bytes")
        }
        quinn::ReadExactError::ReadError(e) => e.into(),
    })?;
    Ok(Some(bincode::deserialize(&buf)?))
}

/// Like `recv_message` but returns an error instead of `None` on EOF.
/// Convenient for the control stream where unexpected EOF is always an error.
pub async fn recv_message_required<T: serde::de::DeserializeOwned>(
    stream: &mut RecvStream,
) -> Result<T> {
    recv_message(stream)
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream closed unexpectedly"))
}
