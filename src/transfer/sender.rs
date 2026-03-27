//! Sender-side transfer orchestration. See `transfer/mod.rs` for the full flow.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWrite;
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::compress;
use crate::net::connection::make_client_endpoint;
use crate::net::tcp::connect_tls;
use crate::protocol::{
    framing,
    messages::{
        ChunkData, Compression, NegotiateRequest, NegotiateResponse, ReceiverMessage,
        SenderMessage, TransferManifest,
    },
};
use crate::transfer::chunk::{ChunkInfo, ChunkQueue};
use crate::transfer::negotiate::compute_params;

pub struct SendConfig {
    /// Override parallel stream count. `None` = auto-negotiate from RTT + CPU.
    pub streams: Option<usize>,
    /// Override chunk size in bytes. `None` = auto-negotiate from RTT.
    pub chunk_size: Option<usize>,
    pub compress: bool,
    pub compress_level: i32,
    /// Hex SHA-256 fingerprint to pin; None = TOFU (prints fingerprint, asks user).
    pub trusted_fingerprint: Option<String>,
    /// Force TCP+TLS instead of QUIC. Normally not needed — the sender tries
    /// QUIC first and auto-falls-back to TCP+TLS if UDP is blocked.
    pub use_tcp: bool,
}

/// How long to wait for a QUIC connection before falling back to TCP+TLS.
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn send(file: PathBuf, destination: SocketAddr, config: SendConfig) -> Result<()> {
    if config.use_tcp {
        return send_tcp(file, destination, config).await;
    }

    // Try QUIC first; fall back to TCP+TLS if UDP is blocked or the connection
    // times out.  Only the connect phase triggers a fallback — errors during
    // the transfer itself are surfaced as real errors.
    let endpoint = make_client_endpoint(config.trusted_fingerprint.as_deref())?;
    info!("connecting to {destination} (QUIC, {QUIC_CONNECT_TIMEOUT:.1?} timeout)");
    let quic_result = tokio::time::timeout(QUIC_CONNECT_TIMEOUT, async {
        let connecting = endpoint
            .connect(destination, "mftp")
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        connecting.await.map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await;

    match quic_result {
        Ok(Ok(conn)) => {
            info!("connected via QUIC");
            send_quic_with_conn(file, destination, config, conn).await
        }
        Ok(Err(e)) => {
            eprintln!("[mftp] QUIC connect failed ({e:#}), retrying over TCP+TLS…");
            send_tcp(file, destination, config).await
        }
        Err(_timeout) => {
            eprintln!("[mftp] QUIC connect timed out (UDP may be blocked), retrying over TCP+TLS…");
            send_tcp(file, destination, config).await
        }
    }
}

// ── QUIC path ─────────────────────────────────────────────────────────────────

async fn send_quic_with_conn(
    file: PathBuf,
    _destination: SocketAddr,
    config: SendConfig,
    conn: quinn::Connection,
) -> Result<()> {
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
    let hash_task = {
        let path = file.clone();
        tokio::task::spawn_blocking(move || hash_file_sync(&path))
    };

    let transfer_id: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();

    let compression = if config.compress {
        Compression::Zstd { level: config.compress_level }
    } else {
        Compression::None
    };

    let sender_cores =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;

    // ── Control stream: negotiate parameters ──────────────────────────────────
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;

    framing::send_message(
        &mut ctrl_send,
        &NegotiateRequest { cpu_cores: sender_cores, file_size },
    )
    .await?;

    let neg_resp: NegotiateResponse =
        framing::recv_message_required(&mut ctrl_recv).await?;

    // RTT is available right after the handshake.
    let rtt = conn.stats().path.rtt;
    let params = compute_params(
        rtt,
        file_size,
        sender_cores,
        neg_resp.cpu_cores,
        config.streams,
        config.chunk_size,
    );
    println!(
        "Negotiated: {} streams, {} MiB chunks (RTT {:.1} ms, sender {} cores, receiver {} cores)",
        params.streams,
        params.chunk_size / (1024 * 1024),
        rtt.as_secs_f64() * 1000.0,
        sender_cores,
        neg_resp.cpu_cores,
    );

    let chunk_size = params.chunk_size;
    let total_chunks = file_size.div_ceil(chunk_size as u64);
    let num_streams = params.streams;

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

    let spinner = make_spinner(&file_name, remaining);
    let transfer_start = Instant::now();

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

        tasks.spawn(async move {
            quic_stream_worker(stream, queue, have, file_path, transfer_id, compression).await
        });
    }

    while let Some(res) = tasks.join_next().await {
        res??;
    }

    spinner.set_message("waiting for receiver to confirm delivery…");

    // ── Send file hash — await the background task (almost certainly done) ────
    let file_hash = hash_task.await.context("hash task panicked")??;
    framing::send_message(&mut ctrl_send, &SenderMessage::Complete { file_hash }).await?;

    // ── Wait for receiver's completion ack ────────────────────────────────────
    let msg: ReceiverMessage = framing::recv_message_required(&mut ctrl_recv).await?;
    spinner.finish_and_clear();
    print_completion(msg, &file_name, file_size, file_hash, transfer_start)?;

    let _ = ctrl_send.finish();
    conn.close(0u32.into(), b"done");
    Ok(())
}

async fn quic_stream_worker(
    mut stream: quinn::SendStream,
    queue: Arc<ChunkQueue>,
    skip: Arc<HashSet<u64>>,
    file_path: PathBuf,
    transfer_id: [u8; 16],
    compression: Compression,
) -> Result<()> {
    send_chunks(&mut stream, queue, skip, &file_path, transfer_id, &compression).await?;
    stream.finish()?;
    Ok(())
}

// ── TCP path ──────────────────────────────────────────────────────────────────

async fn send_tcp(file: PathBuf, destination: SocketAddr, config: SendConfig) -> Result<()> {
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

    let hash_task = {
        let path = file.clone();
        tokio::task::spawn_blocking(move || hash_file_sync(&path))
    };

    let transfer_id: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();

    let compression = if config.compress {
        Compression::Zstd { level: config.compress_level }
    } else {
        Compression::None
    };

    let sender_cores =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;

    // ── Connect control stream ────────────────────────────────────────────────
    info!("connecting to {destination} (TCP+TLS)");
    let ctrl = connect_tls(destination, config.trusted_fingerprint.as_deref()).await?;
    let (mut ctrl_recv, mut ctrl_send) = tokio::io::split(ctrl);
    info!("connected");

    // ── Negotiate + measure RTT ───────────────────────────────────────────────
    // Quinn gives us an RTT measurement from the QUIC handshake; for TCP we
    // time the NegotiateRequest/Response round trip instead.
    let rtt_start = Instant::now();
    framing::send_message(
        &mut ctrl_send,
        &NegotiateRequest { cpu_cores: sender_cores, file_size },
    )
    .await?;
    let neg_resp: NegotiateResponse =
        framing::recv_message_required(&mut ctrl_recv).await?;
    let rtt = rtt_start.elapsed();

    let params = compute_params(
        rtt,
        file_size,
        sender_cores,
        neg_resp.cpu_cores,
        config.streams,
        config.chunk_size,
    );
    println!(
        "Negotiated: {} streams, {} MiB chunks (RTT {:.1} ms, sender {} cores, receiver {} cores)",
        params.streams,
        params.chunk_size / (1024 * 1024),
        rtt.as_secs_f64() * 1000.0,
        sender_cores,
        neg_resp.cpu_cores,
    );

    let chunk_size = params.chunk_size;
    let total_chunks = file_size.div_ceil(chunk_size as u64);
    let num_streams = params.streams;

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

    let ready: ReceiverMessage = framing::recv_message_required(&mut ctrl_recv).await?;
    let have: HashSet<u64> = match ready {
        ReceiverMessage::Ready { have_chunks } => have_chunks.into_iter().collect(),
        ReceiverMessage::Error { message } => bail!("receiver error: {message}"),
        other => bail!("unexpected message from receiver: {other:?}"),
    };
    let skip_count = have.len() as u64;
    let remaining = total_chunks - skip_count;
    info!("{skip_count} chunks already at receiver, {remaining} to send");

    let spinner = make_spinner(&file_name, remaining);
    let transfer_start = Instant::now();

    // ── Parallel data connections ─────────────────────────────────────────────
    // Each data connection maps to one QUIC stream in the QUIC path.
    // The receiver accepts them in order after sending Ready.
    let actual_streams = num_streams.min(remaining.max(1) as usize);
    let queue = ChunkQueue::new(file_size, chunk_size);
    let have = Arc::new(have);

    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..actual_streams {
        let data_stream =
            connect_tls(destination, config.trusted_fingerprint.as_deref()).await?;
        let queue = queue.clone();
        let have = have.clone();
        let file_path = file.clone();
        let compression = compression.clone();

        tasks.spawn(async move {
            tcp_stream_worker(data_stream, queue, have, file_path, transfer_id, compression).await
        });
    }

    while let Some(res) = tasks.join_next().await {
        res??;
    }

    spinner.set_message("waiting for receiver to confirm delivery…");

    let file_hash = hash_task.await.context("hash task panicked")??;
    framing::send_message(&mut ctrl_send, &SenderMessage::Complete { file_hash }).await?;

    let msg: ReceiverMessage = framing::recv_message_required(&mut ctrl_recv).await?;
    spinner.finish_and_clear();
    print_completion(msg, &file_name, file_size, file_hash, transfer_start)?;

    // ctrl_send and ctrl_recv drop here, closing the TCP control connection.
    Ok(())
}

async fn tcp_stream_worker(
    mut stream: crate::net::tcp::ClientTlsStream<tokio::net::TcpStream>,
    queue: Arc<ChunkQueue>,
    skip: Arc<HashSet<u64>>,
    file_path: PathBuf,
    transfer_id: [u8; 16],
    compression: Compression,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    send_chunks(&mut stream, queue, skip, &file_path, transfer_id, &compression)
        .await
        .context("send_chunks")?;
    // Send TLS close_notify so the receiver sees a clean EOF.
    stream.shutdown().await.context("TLS shutdown on data stream")?;
    // Drain the server's close_notify before dropping.  Without this, the
    // kernel sends a RST when the socket is dropped with unread data in the
    // receive buffer, which arrives on the server side as ECONNRESET mid-read.
    let mut drain = [0u8; 1];
    let _ = stream.read(&mut drain).await;
    Ok(())
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Send all queued chunks (skipping already-received ones) to any [`AsyncWrite`].
///
/// Used by both the QUIC and TCP stream workers so the chunk-sending logic
/// lives in exactly one place.
async fn send_chunks<W>(
    writer: &mut W,
    queue: Arc<ChunkQueue>,
    skip: Arc<HashSet<u64>>,
    file_path: &Path,
    transfer_id: [u8; 16],
    compression: &Compression,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    // Each worker opens its own file handle — avoids cross-task locking on seeks.
    let file = std::fs::File::open(file_path)
        .with_context(|| format!("open {}", file_path.display()))?;

    while let Some(chunk) = queue.next_chunk() {
        if skip.contains(&chunk.index) {
            continue;
        }

        let raw = read_chunk(&file, &chunk)?;
        let (payload, compressed) = maybe_compress(&raw, compression)?;
        let chunk_hash: [u8; 32] = Sha256::digest(&payload).into();

        framing::send_message(
            writer,
            &ChunkData { transfer_id, chunk_index: chunk.index, chunk_hash, compressed, payload },
        )
        .await?;

        debug!(chunk = chunk.index, "sent");
    }

    Ok(())
}

fn make_spinner(file_name: &str, remaining: u64) -> Arc<ProgressBar> {
    Arc::new({
        let sp = ProgressBar::new_spinner();
        sp.set_style(
            ProgressStyle::with_template(
                "[send] {spinner:.green} [{elapsed_precise}] {msg}",
            )
            .unwrap(),
        );
        sp.enable_steady_tick(Duration::from_millis(100));
        sp.set_message(format!("sending {file_name} ({remaining} chunks remaining)"));
        sp
    })
}

fn print_completion(
    msg: ReceiverMessage,
    file_name: &str,
    file_size: u64,
    file_hash: [u8; 32],
    transfer_start: Instant,
) -> Result<()> {
    match msg {
        ReceiverMessage::Complete { file_hash: recv_hash } => {
            if recv_hash != file_hash {
                bail!("file hash mismatch: receiver computed a different hash");
            }
            let elapsed = transfer_start.elapsed();
            let mib = file_size as f64 / (1024.0 * 1024.0);
            let throughput = mib / elapsed.as_secs_f64();
            println!(
                "Transfer complete: {file_name} ({mib:.0} MiB) in {:.1}s \
                 ({throughput:.0} MiB/s end-to-end). Hash verified.",
                elapsed.as_secs_f64(),
            );
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
    Ok(())
}

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
