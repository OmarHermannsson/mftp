//! Length-prefixed message framing over QUIC streams.
//!
//! Frame format: [u32 little-endian length][bincode payload]

use anyhow::{bail, Result};
use quinn::{RecvStream, SendStream};

const MAX_FRAME_SIZE: u32 = 64 * 1024 * 1024; // 64 MiB guard

pub async fn send_message<T: serde::Serialize>(stream: &mut SendStream, msg: &T) -> Result<()> {
    let payload = bincode::serialize(msg)?;
    let len = payload.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

/// Read one framed message from `stream`.
///
/// Returns `Ok(None)` when the stream ends cleanly at a frame boundary
/// (i.e. the sender called `finish()` with no more frames pending).
/// Returns `Err` for any mid-frame truncation or deserialization failure.
pub async fn recv_message<T: serde::de::DeserializeOwned>(
    stream: &mut RecvStream,
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
    if len > MAX_FRAME_SIZE {
        bail!("frame too large: {len} bytes");
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
