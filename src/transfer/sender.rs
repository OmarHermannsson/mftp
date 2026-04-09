//! Sender-side transfer orchestration. See `transfer/mod.rs` for the full flow.

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
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
use crate::transfer::hash::ChunkHasher;
use crate::transfer::negotiate::compute_params;

/// Which transport path to use for the transfer.
///
/// Used in [`SendConfig::forced_transport`]; `None` means auto (QUIC → TCP+TLS →
/// SFTP in SSH mode).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ForcedTransport {
    /// QUIC with BBR congestion control.  No TCP+TLS or SFTP fallback — the
    /// transfer fails immediately if QUIC is unreachable.
    Quic,
    /// TCP+TLS.  Skip the QUIC probe entirely.  No SFTP fallback.
    Tcp,
    /// Parallel SFTP through SSH port 22.  SSH mode only; not valid for
    /// direct `host:port` destinations.
    Sftp,
}

#[derive(Clone)]
pub struct SendConfig {
    /// Override parallel stream count. `None` = auto-negotiate from RTT + CPU.
    pub streams: Option<usize>,
    /// Override chunk size in bytes. `None` = auto-negotiate from RTT.
    pub chunk_size: Option<usize>,
    pub compress: bool,
    pub compress_level: i32,
    /// Hex SHA-256 fingerprint to pin; None = TOFU (prints fingerprint, asks user).
    pub trusted_fingerprint: Option<String>,
    /// Force a specific transport path; `None` = auto (QUIC → TCP+TLS → SFTP).
    pub forced_transport: Option<ForcedTransport>,
    /// In auto mode, switch to TCP+TLS when measured RTT is at or below this
    /// threshold.  Ignored when `forced_transport` is set.
    pub tcp_rtt_threshold: Duration,
}

/// How long to wait for a QUIC connection before falling back to TCP+TLS.
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// RTT at or below which the sender auto-switches to TCP+TLS even after a
/// successful QUIC handshake.  Zero = disabled (QUIC+BBR now wins at all RTTs
/// including LAN; the 5 ms default was set before the LAN regression was fixed).
pub const DEFAULT_TCP_RTT_THRESHOLD: Duration = Duration::ZERO;

pub async fn send(file: PathBuf, destination: SocketAddr, config: SendConfig) -> Result<()> {
    match &config.forced_transport {
        Some(ForcedTransport::Tcp) => return send_tcp(file, destination, config).await,
        Some(ForcedTransport::Sftp) => bail!(
            "--transport sftp is only available in SSH mode \
             ([user@]host:/path); it is not valid for a direct host:port destination"
        ),
        Some(ForcedTransport::Quic) | None => {}
    }

    let forced_quic = config.forced_transport == Some(ForcedTransport::Quic);

    // Try QUIC first (or QUIC only if forced); fall back to TCP+TLS in auto mode if:
    //   • UDP is blocked or the handshake times out, OR
    //   • the measured RTT is ≤ tcp_rtt_threshold (LAN / same-datacenter).
    let endpoint = make_client_endpoint(config.trusted_fingerprint.as_deref(), destination)?;
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
            let rtt = conn.stats().path.rtt;
            let threshold = config.tcp_rtt_threshold;
            // RTT-based TCP switch only applies in auto mode.
            if !forced_quic && threshold > Duration::ZERO && rtt <= threshold {
                eprintln!(
                    "[mftp] RTT {:.2} ms (≤ {:.2} ms threshold) — switching to TCP+TLS for LAN throughput…",
                    rtt.as_secs_f64() * 1000.0,
                    threshold.as_secs_f64() * 1000.0,
                );
                conn.close(0u32.into(), b"switching to tcp");
                send_tcp(file, destination, config).await
            } else {
                info!("connected via QUIC (RTT {:.1} ms)", rtt.as_secs_f64() * 1000.0);
                send_quic_with_conn(file, config, conn).await
            }
        }
        Ok(Err(e)) if forced_quic => Err(e.context(
            "QUIC connection failed (--transport quic; no TCP+TLS fallback)"
        )),
        Ok(Err(e)) => {
            eprintln!("[mftp] QUIC connect failed ({e:#}), retrying over TCP+TLS…");
            send_tcp(file, destination, config).await
        }
        Err(_) if forced_quic => bail!(
            "QUIC connect timed out after {QUIC_CONNECT_TIMEOUT:.1?} — \
             UDP may be blocked (--transport quic; no TCP+TLS fallback)"
        ),
        Err(_timeout) => {
            eprintln!("[mftp] QUIC connect timed out (UDP may be blocked), retrying over TCP+TLS…");
            send_tcp(file, destination, config).await
        }
    }
}

// ── QUIC path ─────────────────────────────────────────────────────────────────

async fn send_quic_with_conn(
    file: PathBuf,
    config: SendConfig,
    conn: quinn::Connection,
) -> Result<()> {
    let file_size = tokio::fs::metadata(&file)
        .await
        .with_context(|| format!("cannot stat {}", file.display()))?
        .len();

    let sender_cores =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;

    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;

    framing::send_message(
        &mut ctrl_send,
        &NegotiateRequest { cpu_cores: sender_cores },
    )
    .await?;
    let neg_resp: NegotiateResponse =
        framing::recv_message_required(&mut ctrl_recv).await?;
    let rtt = conn.stats().path.rtt;

    let conn_for_workers = conn.clone();
    let file_for_workers = file.clone();

    run_transfer(
        &file,
        file_size,
        &mut ctrl_send,
        ctrl_recv,
        rtt,
        sender_cores,
        neg_resp.cpu_cores,
        &config,
        move |queue, have, transfer_id, compression, hasher| {
            let conn = conn_for_workers.clone();
            let path = file_for_workers.clone();
            async move {
                let stream = conn
                    .open_uni()
                    .await
                    .context("open QUIC data stream")?;
                quic_stream_worker(stream, queue, have, path, transfer_id, compression, hasher).await
            }
        },
    )
    .await?;

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
    hasher: Option<Arc<ChunkHasher>>,
) -> Result<()> {
    send_chunks(&mut stream, queue, skip, &file_path, transfer_id, &compression, hasher).await?;
    stream.finish()?;
    Ok(())
}

// ── TCP path ──────────────────────────────────────────────────────────────────

async fn send_tcp(file: PathBuf, destination: SocketAddr, config: SendConfig) -> Result<()> {
    let file_size = tokio::fs::metadata(&file)
        .await
        .with_context(|| format!("cannot stat {}", file.display()))?
        .len();

    let sender_cores =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;

    info!("connecting to {destination} (TCP+TLS)");
    let ctrl = connect_tls(destination, config.trusted_fingerprint.as_deref()).await?;
    let (mut ctrl_recv, mut ctrl_send) = tokio::io::split(ctrl);
    info!("connected");

    // Measure RTT via the NegotiateRequest / NegotiateResponse round-trip —
    // the TCP equivalent of `conn.stats().path.rtt` for QUIC.
    let rtt_start = Instant::now();
    framing::send_message(
        &mut ctrl_send,
        &NegotiateRequest { cpu_cores: sender_cores },
    )
    .await?;
    let neg_resp: NegotiateResponse =
        framing::recv_message_required(&mut ctrl_recv).await?;
    let rtt = rtt_start.elapsed();

    let trusted_fp = config.trusted_fingerprint.clone();
    let file_for_workers = file.clone();

    run_transfer(
        &file,
        file_size,
        &mut ctrl_send,
        ctrl_recv,
        rtt,
        sender_cores,
        neg_resp.cpu_cores,
        &config,
        move |queue, have, transfer_id, compression, hasher| {
            let fp = trusted_fp.clone();
            let path = file_for_workers.clone();
            async move {
                let stream = connect_tls(destination, fp.as_deref())
                    .await
                    .context("open TCP data stream")?;
                tcp_stream_worker(stream, queue, have, path, transfer_id, compression, hasher).await
            }
        },
    )
    .await
    // ctrl_send and ctrl_recv drop here, closing the TCP control connection.
}

async fn tcp_stream_worker(
    mut stream: crate::net::tcp::ClientTlsStream<tokio::net::TcpStream>,
    queue: Arc<ChunkQueue>,
    skip: Arc<HashSet<u64>>,
    file_path: PathBuf,
    transfer_id: [u8; 16],
    compression: Compression,
    hasher: Option<Arc<ChunkHasher>>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    send_chunks(&mut stream, queue, skip, &file_path, transfer_id, &compression, hasher)
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

// ── Shared transfer body ──────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
/// Core transfer logic shared by both the QUIC and TCP paths.
///
/// Called after the control stream is established and the initial
/// `NegotiateRequest` / `NegotiateResponse` round-trip is complete.
///
/// `spawn_worker` is a factory called once per data stream; it must return a
/// future that opens one data stream, sends all assigned chunks, and closes
/// the stream cleanly.
async fn run_transfer<CW, CR, F, Fut>(
    file: &Path,
    file_size: u64,
    ctrl_send: &mut CW,
    mut ctrl_recv: CR,
    rtt: Duration,
    sender_cores: u32,
    receiver_cores: u32,
    config: &SendConfig,
    spawn_worker: F,
) -> Result<()>
where
    CW: AsyncWrite + Unpin,
    CR: AsyncRead + Unpin + Send + 'static,
    F: Fn(Arc<ChunkQueue>, Arc<HashSet<u64>>, [u8; 16], Compression, Option<Arc<ChunkHasher>>) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let file_name = file
        .file_name()
        .context("file has no name")?
        .to_string_lossy()
        .into_owned();

    let transfer_id: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();

    let compression = if config.compress {
        Compression::Zstd { level: config.compress_level }
    } else {
        Compression::None
    };

    let params = compute_params(
        rtt,
        file_size,
        sender_cores,
        receiver_cores,
        config.streams,
        config.chunk_size,
    );
    println!(
        "Negotiated: {} streams, {} MiB chunks (RTT {:.1} ms, sender {} cores, receiver {} cores)",
        params.streams,
        params.chunk_size / (1024 * 1024),
        rtt.as_secs_f64() * 1000.0,
        sender_cores,
        receiver_cores,
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
    framing::send_message(ctrl_send, &manifest).await?;

    // Receive Ready — receiver sends a packed bitvector of already-on-disk chunks.
    // Uses the data-frame limit (128 MiB) because the bitvector can be large for
    // big files even in its compact form (e.g. 16 TiB / 4 MiB = ~500 KB bitvec).
    let ready: ReceiverMessage = framing::recv_data_message(&mut ctrl_recv)
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream closed before Ready message"))?;
    let have: HashSet<u64> = match ready {
        ReceiverMessage::Ready { received_bits, total_chunks } => {
            bits_to_chunk_set(&received_bits, total_chunks)
        }
        ReceiverMessage::Error { message } => bail!("receiver error: {message}"),
        other => bail!("unexpected message from receiver: {other:?}"),
    };
    let skip_count = have.len() as u64;
    let remaining = total_chunks - skip_count;
    info!("{skip_count} chunks already at receiver, {remaining} to send");

    // For a fresh transfer (no resume), hash the file inline as chunks are read —
    // no second disk pass.  For a resume, we must hash skipped chunks too so we
    // fall back to a full sequential read running concurrently with the transfer.
    let file_hasher: Option<Arc<ChunkHasher>> = if have.is_empty() {
        Some(Arc::new(ChunkHasher::new(total_chunks)))
    } else {
        None
    };
    let hash_task = if have.is_empty() {
        None
    } else {
        let path = file.to_owned();
        Some(tokio::task::spawn_blocking(move || hash_file_sync(&path)))
    };

    let pb = make_progress_bar(&file_name, file_size);
    // Seed the bar with bytes the receiver already confirmed (resume).
    let resume_bytes: u64 = have.iter().map(|&i| {
        let offset = i * chunk_size as u64;
        (file_size - offset).min(chunk_size as u64)
    }).sum();
    pb.set_position(resume_bytes);
    let transfer_start = Instant::now();

    // Spawn a task that reads ReceiverMessage::Progress from the control
    // stream and advances the progress bar.  It captures the terminal message
    // (Complete / Retransmit / Error) via a oneshot channel.
    let pb_for_reader = pb.clone();
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel::<ReceiverMessage>();
    let reader = tokio::spawn(async move {
        loop {
            match framing::recv_message::<_, ReceiverMessage>(&mut ctrl_recv).await {
                Ok(Some(ReceiverMessage::Progress { bytes_written })) => {
                    pb_for_reader.set_position(bytes_written);
                }
                Ok(Some(other)) => {
                    let _ = completion_tx.send(other);
                    return;
                }
                _ => return, // EOF or error — completion_rx surfaces this
            }
        }
    });

    // ── Parallel data streams ─────────────────────────────────────────────────
    let actual_streams = num_streams.min(remaining.max(1) as usize);
    let queue = ChunkQueue::new(file_size, chunk_size);
    let have = Arc::new(have);

    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..actual_streams {
        let hasher = file_hasher.clone();
        tasks.spawn(spawn_worker(queue.clone(), have.clone(), transfer_id, compression.clone(), hasher));
    }
    while let Some(res) = tasks.join_next().await {
        res??;
    }

    pb.set_message("verifying…");

    let file_hash: [u8; 32] = match file_hasher {
        Some(h) => Arc::try_unwrap(h)
            .expect("all stream workers have completed; no other Arc<ChunkHasher> references remain")
            .finish()?,
        None => hash_task
            .expect("resume path always spawns hash_task")
            .await
            .context("hash task panicked")??,
    };
    framing::send_message(ctrl_send, &SenderMessage::Complete { file_hash }).await?;

    // The reader task keeps consuming Progress messages until Complete arrives.
    let msg = completion_rx.await.context("receiver closed without completing")?;
    reader.await.ok();
    pb.finish_and_clear();
    print_completion(msg, &file_name, file_size, file_hash, transfer_start)?;

    Ok(())
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// A chunk fully prepared for transmission: payload bytes, wire hash, and
/// compression flag.
struct PreparedChunk {
    index: u64,
    payload: Vec<u8>,
    chunk_hash: [u8; 32],
    compressed: bool,
}

/// Send all queued chunks (skipping already-received ones) to any [`AsyncWrite`].
///
/// Used by both the QUIC and TCP stream workers so the chunk-sending logic
/// lives in exactly one place.
///
/// The pipeline keeps `PIPELINE_DEPTH` chunks being prepared on blocking threads
/// while earlier chunks are being sent over the wire.  This overlaps CPU/disk work
/// (pread + compression probe + SHA-256) with network I/O so neither stalls the
/// other, and ensures the disk I/O queue stays full even if one read takes longer
/// than average (e.g. a slow NVMe slot on a busy system).
async fn send_chunks<W>(
    writer: &mut W,
    queue: Arc<ChunkQueue>,
    skip: Arc<HashSet<u64>>,
    file_path: &Path,
    transfer_id: [u8; 16],
    compression: &Compression,
    hasher: Option<Arc<ChunkHasher>>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    // Depth-2 pipeline: always have the next chunk being read from disk while
    // the current one is being sent.  A single slot (depth 1) means the stream
    // stalls briefly between chunks when disk latency > network time-per-chunk;
    // depth 2 covers that gap without buffering excessive data in memory.
    const PIPELINE_DEPTH: usize = 2;

    // Each stream worker opens its own file handle so there is no cross-task
    // locking.  Arc lets us move it into spawn_blocking without cloning the File.
    let file = Arc::new(
        std::fs::File::open(file_path)
            .with_context(|| format!("open {}", file_path.display()))?,
    );

    // Hint to the kernel that this file will be read sequentially so it
    // aggressively prefetches pages into the page cache.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
    }

    // Advance the queue, skipping already-received chunks, and return the
    // next chunk that actually needs to be sent.
    let next_sendable = |queue: &ChunkQueue, skip: &HashSet<u64>| -> Option<ChunkInfo> {
        loop {
            match queue.next_chunk() {
                Some(c) if skip.contains(&c.index) => continue,
                other => return other,
            }
        }
    };

    // Spawn a blocking prepare task for one chunk.
    let spawn_prepare = |chunk: ChunkInfo| {
        let file = Arc::clone(&file);
        let compression = compression.clone();
        let h = hasher.clone();
        tokio::task::spawn_blocking(move || prepare_chunk(chunk, file, &compression, h.as_deref()))
    };

    let mut pipeline: std::collections::VecDeque<
        tokio::task::JoinHandle<Result<PreparedChunk>>,
    > = std::collections::VecDeque::new();

    // Pre-fill the pipeline before the send loop begins.
    while pipeline.len() < PIPELINE_DEPTH {
        match next_sendable(&queue, &skip) {
            Some(chunk) => pipeline.push_back(spawn_prepare(chunk)),
            None => break,
        }
    }

    while let Some(prepare_task) = pipeline.pop_front() {
        // Await the oldest prepared chunk (.await yields control so the executor
        // can process QUIC ACKs while the disk read is in progress).
        let prepared = prepare_task.await.context("prepare task panicked")??;

        // Keep the pipeline full while we send this chunk over the wire.
        if let Some(chunk) = next_sendable(&queue, &skip) {
            pipeline.push_back(spawn_prepare(chunk));
        }

        framing::send_chunk_data(
            writer,
            &ChunkData {
                transfer_id,
                chunk_index: prepared.index,
                chunk_hash: prepared.chunk_hash,
                compressed: prepared.compressed,
                payload: prepared.payload,
            },
        )
        .await?;

        debug!(chunk = prepared.index, "sent");
    }

    Ok(())
}

/// Read one chunk from disk, compress if beneficial, and compute the wire hash.
/// Designed to run in [`tokio::task::spawn_blocking`].
fn prepare_chunk(
    chunk: ChunkInfo,
    file: Arc<std::fs::File>,
    compression: &Compression,
    hasher: Option<&ChunkHasher>,
) -> Result<PreparedChunk> {
    let raw = read_chunk(&file, &chunk)?;
    // Feed raw (pre-compression) bytes into the full-file hasher while they are
    // already in memory.  This eliminates the separate hash_file_sync disk pass
    // that would otherwise compete with the chunk workers for I/O bandwidth.
    if let Some(h) = hasher {
        h.feed(chunk.index, &raw)?;
    }
    let (payload, compressed) = maybe_compress(raw, compression)?;
    let chunk_hash: [u8; 32] = Sha256::digest(&payload).into();
    Ok(PreparedChunk { index: chunk.index, payload, chunk_hash, compressed })
}

fn make_progress_bar(file_name: &str, file_size: u64) -> Arc<ProgressBar> {
    Arc::new({
        let pb = ProgressBar::new(file_size);
        pb.set_style(
            ProgressStyle::with_template(
                "[send] {spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} \
                 {bytes}/{total_bytes} {bytes_per_sec} eta {eta}  {msg}",
            )
            .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_message(file_name.to_owned());
        pb
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
        ReceiverMessage::Error { message } => bail!("receiver error: {message}"),
        other => bail!("unexpected final message: {other:?}"),
    }
    Ok(())
}

/// Reconstruct a `HashSet` of chunk indices from a packed bitvector.
fn bits_to_chunk_set(bits: &[u64], total_chunks: u64) -> HashSet<u64> {
    bits.iter()
        .enumerate()
        .flat_map(|(wi, &word)| {
            (0u64..64).filter_map(move |bit| {
                if word & (1 << bit) != 0 {
                    let idx = wi as u64 * 64 + bit;
                    if idx < total_chunks { Some(idx) } else { None }
                } else {
                    None
                }
            })
        })
        .collect()
}

fn read_chunk(file: &std::fs::File, chunk: &ChunkInfo) -> Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0u8; chunk.len];
    file.read_exact_at(&mut buf, chunk.offset)
        .context("pread chunk")?;
    Ok(buf)
}

fn maybe_compress(data: Vec<u8>, compression: &Compression) -> Result<(Vec<u8>, bool)> {
    match compression {
        Compression::None => Ok((data, false)),
        Compression::Zstd { level } => match compress::compress_chunk(&data, *level)? {
            Some(compressed) => Ok((compressed, true)),
            None => Ok((data, false)),
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
