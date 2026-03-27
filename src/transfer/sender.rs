//! Sender-side transfer orchestration. See `transfer/mod.rs` for the full flow.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::compress;
use crate::net::connection::make_client_endpoint;
use crate::protocol::{
    framing,
    messages::{ChunkData, Compression, ReceiverMessage, SenderMessage, TransferManifest},
};
use crate::transfer::chunk::{ChunkInfo, ChunkQueue};

pub struct SendConfig {
    pub streams: usize,
    pub chunk_size: usize,
    pub compress: bool,
    pub compress_level: i32,
    /// Hex SHA-256 fingerprint to pin; None = TOFU (prints fingerprint, asks user).
    pub trusted_fingerprint: Option<String>,
}

pub async fn send(file: PathBuf, destination: SocketAddr, config: SendConfig) -> Result<()> {
    // ── Gather file metadata ──────────────────────────────────────────────────
    let meta = tokio::fs::metadata(&file)
        .await
        .with_context(|| format!("cannot stat {}", file.display()))?;
    let file_size = meta.len();
    let file_name = file
        .file_name()
        .context("file has no name")?
        .to_string_lossy()
        .into_owned();

    // ── Start hashing immediately — runs concurrently with everything below ───
    // For large files this can take tens of seconds. By running it in parallel
    // with the QUIC handshake and the data transfer we avoid blocking the start.
    let hash_task = {
        let path = file.clone();
        tokio::task::spawn_blocking(move || hash_file_sync(&path))
    };

    let chunk_size = config.chunk_size;
    let total_chunks = file_size.div_ceil(chunk_size as u64);
    let transfer_id: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();

    let compression = if config.compress {
        Compression::Zstd { level: config.compress_level }
    } else {
        Compression::None
    };

    // ── Connect ───────────────────────────────────────────────────────────────
    let endpoint = make_client_endpoint(config.trusted_fingerprint.as_deref())?;
    info!("connecting to {destination}");
    let conn = endpoint
        .connect(destination, "mftp")?
        .await
        .context("QUIC connect failed")?;
    info!("connected");

    // ── Control stream: handshake ─────────────────────────────────────────────
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;

    let num_streams = config.streams.min(total_chunks as usize).max(1);
    let manifest = TransferManifest {
        transfer_id,
        file_name: file_name.clone(),
        file_size,
        chunk_size,
        total_chunks,
        num_streams,
        compression: compression.clone(),
        fec: None,
    };
    framing::send_message(&mut ctrl_send, &manifest).await?;

    // Wait for Ready (receiver lists chunks it already has, for resume)
    let ready: ReceiverMessage =
        framing::recv_message_required(&mut ctrl_recv).await?;
    let have: HashSet<u64> = match ready {
        ReceiverMessage::Ready { have_chunks } => have_chunks.into_iter().collect(),
        ReceiverMessage::Error { message } => bail!("receiver error: {message}"),
        other => bail!("unexpected message from receiver: {other:?}"),
    };
    let skip_count = have.len() as u64;
    let remaining = total_chunks - skip_count;
    info!("{skip_count} chunks already at receiver, {remaining} to send");

    // ── Progress bar ──────────────────────────────────────────────────────────
    let bytes_to_send: u64 = (0..total_chunks)
        .filter(|i| !have.contains(i))
        .map(|i| chunk_byte_len(i, chunk_size, file_size))
        .sum();

    let pb = Arc::new({
        let pb = ProgressBar::new(bytes_to_send);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] {bar:50.cyan/blue} \
                 {bytes}/{total_bytes} {bytes_per_sec} eta {eta}",
            )
            .unwrap(),
        );
        pb
    });

    // ── Parallel data streams ─────────────────────────────────────────────────
    let actual_streams = num_streams.min(remaining.max(1) as usize);
    let queue = ChunkQueue::new(file_size, chunk_size);
    let have = Arc::new(have);

    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..actual_streams {
        let stream = conn.open_uni().await?;
        let queue = queue.clone();
        let have = have.clone();
        let file_path = file.clone();
        let compression = compression.clone();
        let pb = pb.clone();

        tasks.spawn(async move {
            stream_worker(stream, queue, have, file_path, chunk_size, transfer_id, compression, pb)
                .await
        });
    }

    while let Some(res) = tasks.join_next().await {
        res??;
    }
    pb.finish_with_message("all chunks sent");

    // ── Send file hash — await the background task (almost certainly done) ────
    let file_hash = hash_task.await.context("hash task panicked")??;
    framing::send_message(&mut ctrl_send, &SenderMessage::Complete { file_hash }).await?;

    // ── Wait for receiver's completion ack ────────────────────────────────────
    // The receiver now hashes its copy and sends Complete; keep_alive_interval
    // on our transport config keeps the connection alive during that time.
    let msg: ReceiverMessage = framing::recv_message_required(&mut ctrl_recv).await?;
    match msg {
        ReceiverMessage::Complete { file_hash: recv_hash } => {
            if recv_hash != file_hash {
                bail!("file hash mismatch: receiver computed a different hash");
            }
            println!("Transfer complete. Hash verified.");
        }
        ReceiverMessage::Retransmit { chunk_indices } => {
            bail!(
                "receiver missing {} chunks — retransmit not yet implemented",
                chunk_indices.len()
            );
        }
        ReceiverMessage::Error { message } => bail!("receiver error: {message}"),
        other => bail!("unexpected final message: {other:?}"),
    }

    let _ = ctrl_send.finish();
    conn.close(0u32.into(), b"done");
    Ok(())
}

async fn stream_worker(
    mut stream: quinn::SendStream,
    queue: Arc<ChunkQueue>,
    skip: Arc<HashSet<u64>>,
    file_path: PathBuf,
    _chunk_size: usize,
    transfer_id: [u8; 16],
    compression: Compression,
    pb: Arc<ProgressBar>,
) -> Result<()> {
    // Each worker opens its own file handle — avoids cross-task locking on seeks.
    let file = std::fs::File::open(&file_path)
        .with_context(|| format!("open {}", file_path.display()))?;

    while let Some(chunk) = queue.next_chunk() {
        if skip.contains(&chunk.index) {
            continue;
        }

        let raw = read_chunk(&file, &chunk)?;
        let (payload, compressed) = maybe_compress(&raw, &compression)?;
        let chunk_hash: [u8; 32] = Sha256::digest(&payload).into();

        framing::send_message(
            &mut stream,
            &ChunkData { transfer_id, chunk_index: chunk.index, chunk_hash, compressed, payload },
        )
        .await?;

        pb.inc(chunk.len as u64);
        debug!(chunk = chunk.index, "sent");
    }

    stream.finish()?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_chunk(file: &std::fs::File, chunk: &ChunkInfo) -> Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0u8; chunk.len];
    file.read_exact_at(&mut buf, chunk.offset)
        .context("pread chunk")?;
    Ok(buf)
}

fn maybe_compress(data: &[u8], compression: &Compression) -> Result<(Vec<u8>, bool)> {
    match compression {
        Compression::None => Ok((data.to_vec(), false)),
        Compression::Zstd { level } => match compress::compress_chunk(data, *level)? {
            Some(compressed) => Ok((compressed, true)),
            None => Ok((data.to_vec(), false)),
        },
    }
}

fn chunk_byte_len(index: u64, chunk_size: usize, file_size: u64) -> u64 {
    let offset = index * chunk_size as u64;
    ((file_size - offset) as usize).min(chunk_size) as u64
}

pub(crate) fn hash_file_sync(path: &Path) -> Result<[u8; 32]> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MiB read buffer
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}
