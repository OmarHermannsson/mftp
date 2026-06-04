//! Sender-side transfer orchestration. See `transfer/mod.rs` for the full flow.

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use indicatif::ProgressBar;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering as AtomicOrd};

use async_channel as ac;

use crate::compress;
use crate::fec::codec::FecEncoder;
use crate::net::connection::make_client_endpoint;
use crate::net::tcp::connect_tls;
use crate::protocol::{
    framing,
    messages::{
        ChunkData, Compression, DirEntries, FecChunkData, FecParams, FileEntry, FileKind,
        NegotiateRequest, NegotiateResponse, ReceiverMessage, SenderMessage, TransferManifest,
    },
};
use crate::transfer::hash::{hash_file_sync, ChunkHasher};
use crate::transfer::negotiate::{compute_params, compute_target_streams, ProgressSample};

/// Marker attached to errors from [`run_transfer`] / [`run_transfer_fec`] so
/// callers (e.g. the SSH wrapper in `ssh.rs`) can distinguish a mid-flight
/// failure — where the receiver already has a partial resume state — from a
/// failure that occurred before the transfer started.
///
/// When this marker is present the caller may retry the QUIC transfer and rely
/// on the receiver's resume bitmap to skip already-written chunks.
#[derive(Debug)]
pub(crate) struct MidTransferFailure;

impl std::fmt::Display for MidTransferFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "transfer failed mid-flight (resume state preserved on receiver)"
        )
    }
}

impl std::error::Error for MidTransferFailure {}

/// Marker: the sender finished transmitting all data and sent `SenderMessage::Complete`,
/// but the receiver did not respond within the ack timeout.
///
/// This is distinct from `MidTransferFailure`: the data is fully on the wire and
/// every chunk was individually verified.  Retrying or falling back to SFTP would
/// be harmful; the caller should warn and treat the transfer as succeeded.
#[derive(Debug)]
pub(crate) struct AckTimeoutAfterComplete;

impl std::fmt::Display for AckTimeoutAfterComplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "timed out waiting for receiver verification after all data was sent"
        )
    }
}

impl std::error::Error for AckTimeoutAfterComplete {}

/// Aggregate compression statistics shared across all worker tasks.
///
/// `.0` — total raw (uncompressed) bytes processed.
/// `.1` — total wire bytes sent (after compression; equals raw bytes when
///         a chunk is sent uncompressed).
type CompressionStats = (Arc<AtomicU64>, Arc<AtomicU64>);

fn new_compression_stats() -> CompressionStats {
    (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))
}

/// Returns `true` if any error in `e`'s source chain is a QUIC
/// `WriteError::Stopped`, meaning the receiver called `STOP_SENDING` on the
/// stream (usually because a receiver worker died and dropped its `RecvStream`).
///
/// This is distinct from a full connection failure and does not mean the whole
/// transfer is unrecoverable.
fn is_stream_stopped_by_peer(e: &anyhow::Error) -> bool {
    // quinn renders WriteError::Stopped(code) as "sending stopped by peer: error {code}"
    format!("{e:#}").contains("sending stopped by peer")
}

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
    /// direct `host@]host:/path` destinations.
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
    /// Reed-Solomon FEC parameters; `None` = FEC disabled.
    /// Automatically forced to `None` when the transport falls back to TCP+TLS
    /// (TCP already provides reliable delivery; FEC would only add overhead).
    pub fec: Option<FecParams>,
    /// Use multiple parallel file readers instead of a single sequential reader.
    /// Only measurable on local NVMe with queue-depth ≥ 32; no benefit on
    /// network-bound transfers or spinning disks.
    pub parallel_reads: bool,
    /// Transfer directories recursively.  When true and `file` is a directory,
    /// the sender scans the tree, builds a `DirEntries` manifest, and feeds the
    /// virtual concatenated byte stream.  Silently accepted (no-op) for regular
    /// files.
    pub recursive: bool,
    /// Preserve source file permissions and modification time on the receiver.
    /// Sent as metadata in `FileEntry`; the receiver applies them in a final
    /// pass after all data is written.
    pub preserve: bool,
}

/// How long to wait for a QUIC connection before falling back to TCP+TLS.
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// RTT at or below which the sender auto-switches to TCP+TLS even after a
/// successful QUIC handshake.  QUIC+BBR reaches full congestion window slowly
/// at low latency, consistently underperforming TCP+CUBIC at sub-15 ms RTT.
pub const DEFAULT_TCP_RTT_THRESHOLD: Duration = Duration::from_millis(15);

pub async fn send(file: PathBuf, destination: SocketAddr, config: SendConfig) -> Result<()> {
    // Scan directory before connecting so errors are surfaced early.
    let dir_entries = resolve_source(&file, &config)?;

    match &config.forced_transport {
        Some(ForcedTransport::Tcp) => {
            return send_tcp(file, destination, config, dir_entries).await
        }
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
                send_tcp(file, destination, config, dir_entries).await
            } else {
                info!(
                    "connected via QUIC (RTT {:.1} ms)",
                    rtt.as_secs_f64() * 1000.0
                );
                send_quic_with_conn(file, config, conn, dir_entries).await
            }
        }
        Ok(Err(e)) if forced_quic => {
            Err(e.context("QUIC connection failed (--transport quic; no TCP+TLS fallback)"))
        }
        Ok(Err(e)) => {
            eprintln!("[mftp] QUIC connect failed ({e:#}), retrying over TCP+TLS…");
            send_tcp(file, destination, config, dir_entries).await
        }
        Err(_) if forced_quic => bail!(
            "QUIC connect timed out after {QUIC_CONNECT_TIMEOUT:.1?} — \
             UDP may be blocked (--transport quic; no TCP+TLS fallback)"
        ),
        Err(_timeout) => {
            eprintln!("[mftp] QUIC connect timed out (UDP may be blocked), retrying over TCP+TLS…");
            send_tcp(file, destination, config, dir_entries).await
        }
    }
}

/// Resolve the source path: if it's a directory and `config.recursive` is set,
/// scan it and return the entry list.  Returns `None` for single-file sources.
fn resolve_source(file: &Path, config: &SendConfig) -> Result<Option<Vec<FileEntry>>> {
    if file.is_dir() {
        if !config.recursive {
            bail!(
                "{} is a directory — pass -r to transfer it recursively",
                file.display()
            );
        }
        if config.fec.is_some() {
            bail!(
                "directory transfer with FEC is not yet supported; \
                 omit --fec or send a single file"
            );
        }
        let entries = scan_directory(file, config.preserve)?;
        info!(
            "scanned {} ({} entries, {} files)",
            file.display(),
            entries.len(),
            entries
                .iter()
                .filter(|e| matches!(e.kind, FileKind::File))
                .count()
        );
        Ok(Some(entries))
    } else {
        Ok(None)
    }
}

// ── QUIC path ─────────────────────────────────────────────────────────────────

async fn send_quic_with_conn(
    file: PathBuf,
    config: SendConfig,
    conn: quinn::Connection,
    dir_entries: Option<Vec<FileEntry>>,
) -> Result<()> {
    let file_size = if let Some(ref entries) = dir_entries {
        total_file_bytes(entries)
    } else {
        tokio::fs::metadata(&file)
            .await
            .with_context(|| format!("cannot stat {}", file.display()))?
            .len()
    };

    let sender_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4) as u32;

    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;

    // RTT is available from the QUIC handshake immediately (no round-trip), so
    // we compute parameters and build the manifest up front and pipeline the
    // whole opening flight — NegotiateRequest + TransferManifest + DirEntries —
    // without blocking on NegotiateResponse in between.  This collapses startup
    // from two control round-trips to one (the receiver's NegotiateResponse +
    // Ready come back as a single reply flight).  Framing is ordered,
    // self-delimiting frames, so the wire bytes are identical to the old
    // two-await ordering and any v3+ receiver reads them unchanged.
    let rtt = conn.stats().path.rtt;
    let compression = if config.compress {
        Compression::Zstd {
            level: config.compress_level,
        }
    } else {
        Compression::None
    };
    let file_name = file
        .file_name()
        .context("file has no name")?
        .to_string_lossy()
        .into_owned();
    // Propose stream count from sender_cores alone; the receiver's real core
    // count (NegotiateResponse) only refines adaptive stream scaling later, and
    // the receiver accepts exactly manifest.num_streams data streams.
    let params = compute_params(
        rtt,
        file_size,
        sender_cores,
        sender_cores,
        config.streams,
        config.chunk_size,
    );
    let manifest = build_manifest(
        file_name,
        file_size,
        params.chunk_size,
        params.streams,
        compression,
        config.fec.clone(),
        dir_entries.as_deref(),
    );

    framing::send_message(
        &mut ctrl_send,
        &NegotiateRequest {
            cpu_cores: sender_cores,
            protocol_version: crate::protocol::messages::PROTOCOL_VERSION,
        },
    )
    .await?;
    framing::send_message(&mut ctrl_send, &manifest).await?;
    framing::send_message(
        &mut ctrl_send,
        &DirEntries {
            entries: dir_entries.clone(),
        },
    )
    .await?;

    // Await the receiver's reply flight; Ready follows on the same stream and is
    // read inside run_transfer/run_transfer_fec.
    let neg_resp: NegotiateResponse = framing::recv_message_required(&mut ctrl_recv).await?;

    // Expand the connection-level send window for high-BDP links (fast WAN /
    // satellite).  The static 512 MiB default is sufficient up to ~600 ms at
    // 1 Gbps, but on a 10 Gbps link at 600 ms the BDP is ~750 MiB — exceeding
    // the default and capping throughput.  The per-stream window (64 MiB) is
    // sized for the per-stream BDP and doesn't need adjustment.
    let bdp_window = crate::net::connection::compute_bdp_window(rtt);
    if bdp_window > crate::net::connection::SEND_WINDOW {
        conn.set_send_window(bdp_window);
        debug!(
            bdp_window,
            rtt_ms = rtt.as_secs_f64() * 1000.0,
            "enlarged send window for BDP"
        );
    }

    let conn_for_workers = conn.clone();
    let peer_version = neg_resp.protocol_version;

    if config.fec.is_some() {
        run_transfer_fec(
            &file,
            file_size,
            &mut ctrl_send,
            ctrl_recv,
            rtt,
            sender_cores,
            neg_resp.cpu_cores,
            &config,
            manifest,
            move |rx, transfer_id| {
                let conn = conn_for_workers.clone();
                async move {
                    let stream = conn.open_uni().await.context("open QUIC data stream")?;
                    quic_fec_stream_worker(stream, rx, transfer_id).await
                }
            },
        )
        // C1: tag mid-flight failures so ssh.rs can retry QUIC with resume
        // instead of falling back to SFTP.
        .await
        .map_err(|e| e.context(MidTransferFailure))?;
    } else {
        run_transfer(
            &file,
            file_size,
            dir_entries.as_deref(),
            &mut ctrl_send,
            ctrl_recv,
            rtt,
            sender_cores,
            neg_resp.cpu_cores,
            peer_version,
            &config,
            Some(conn.clone()),
            Some(manifest),
            move |rx, transfer_id, compression, file_hasher, excess_stop, stats| {
                let conn = conn_for_workers.clone();
                async move {
                    let stream = conn.open_uni().await.context("open QUIC data stream")?;
                    quic_stream_worker(
                        stream,
                        rx,
                        transfer_id,
                        compression,
                        file_hasher,
                        excess_stop,
                        stats,
                    )
                    .await
                }
            },
        )
        // C1: tag mid-flight failures so ssh.rs can retry QUIC with resume
        // instead of falling back to SFTP.
        .await
        .map_err(|e| e.context(MidTransferFailure))?;
    }

    let _ = ctrl_send.finish();
    conn.close(0u32.into(), b"done");
    Ok(())
}

async fn quic_stream_worker(
    mut stream: quinn::SendStream,
    rx: ac::Receiver<(u64, Vec<u8>)>,
    transfer_id: [u8; 16],
    compression: Compression,
    file_hasher: Option<Arc<ChunkHasher>>,
    excess_stop: Arc<AtomicUsize>,
    stats: CompressionStats,
) -> Result<()> {
    send_from_channel(
        &mut stream,
        rx,
        transfer_id,
        &compression,
        file_hasher,
        excess_stop,
        stats,
    )
    .await?;
    stream.finish()?;
    Ok(())
}

async fn quic_fec_stream_worker(
    mut stream: quinn::SendStream,
    rx: tokio::sync::mpsc::Receiver<FecChunkData>,
    _transfer_id: [u8; 16],
) -> Result<()> {
    send_fec_from_channel(&mut stream, rx).await?;
    stream.finish()?;
    Ok(())
}

// ── TCP path ──────────────────────────────────────────────────────────────────

async fn send_tcp(
    file: PathBuf,
    destination: SocketAddr,
    mut config: SendConfig,
    dir_entries: Option<Vec<FileEntry>>,
) -> Result<()> {
    if config.fec.is_some() {
        eprintln!(
            "[mftp] FEC is not used over TCP+TLS (reliable transport provides equivalent \
             protection without bandwidth overhead) — disabling FEC."
        );
        config.fec = None;
    }
    let file_size = if let Some(ref entries) = dir_entries {
        total_file_bytes(entries)
    } else {
        tokio::fs::metadata(&file)
            .await
            .with_context(|| format!("cannot stat {}", file.display()))?
            .len()
    };

    let sender_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4) as u32;

    info!("connecting to {destination} (TCP+TLS)");
    let ctrl = connect_tls(destination, config.trusted_fingerprint.as_deref()).await?;
    let (mut ctrl_recv, mut ctrl_send) = tokio::io::split(ctrl);
    info!("connected");

    // Measure RTT via the NegotiateRequest / NegotiateResponse round-trip —
    // the TCP equivalent of `conn.stats().path.rtt` for QUIC.
    let rtt_start = Instant::now();
    framing::send_message(
        &mut ctrl_send,
        &NegotiateRequest {
            cpu_cores: sender_cores,
            protocol_version: crate::protocol::messages::PROTOCOL_VERSION,
        },
    )
    .await?;
    let neg_resp: NegotiateResponse = framing::recv_message_required(&mut ctrl_recv).await?;
    let rtt = rtt_start.elapsed();

    let trusted_fp = config.trusted_fingerprint.clone();
    let peer_version = neg_resp.protocol_version;

    run_transfer(
        &file,
        file_size,
        dir_entries.as_deref(),
        &mut ctrl_send,
        ctrl_recv,
        rtt,
        sender_cores,
        neg_resp.cpu_cores,
        peer_version,
        &config,
        None, // no quinn connection on TCP path
        None, // TCP can't pipeline: it measures RTT via the negotiate round-trip
        move |rx, transfer_id, compression, file_hasher, excess_stop, stats| {
            let fp = trusted_fp.clone();
            async move {
                let stream = connect_tls(destination, fp.as_deref())
                    .await
                    .context("open TCP data stream")?;
                tcp_stream_worker(
                    stream,
                    rx,
                    transfer_id,
                    compression,
                    file_hasher,
                    excess_stop,
                    stats,
                )
                .await
            }
        },
    )
    .await
    // ctrl_send and ctrl_recv drop here, closing the TCP control connection.
}

async fn tcp_stream_worker(
    mut stream: crate::net::tcp::ClientTlsStream<tokio::net::TcpStream>,
    rx: ac::Receiver<(u64, Vec<u8>)>,
    transfer_id: [u8; 16],
    compression: Compression,
    file_hasher: Option<Arc<ChunkHasher>>,
    excess_stop: Arc<AtomicUsize>,
    stats: CompressionStats,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    send_from_channel(
        &mut stream,
        rx,
        transfer_id,
        &compression,
        file_hasher,
        excess_stop,
        stats,
    )
    .await
    .context("send_from_channel")?;
    // Send TLS close_notify so the receiver sees a clean EOF.
    stream
        .shutdown()
        .await
        .context("TLS shutdown on data stream")?;
    // Drain the server's close_notify before dropping.  Without this, the
    // kernel sends a RST when the socket is dropped with unread data in the
    // receive buffer, which arrives on the server side as ECONNRESET mid-read.
    let mut drain = [0u8; 1];
    let _ = stream.read(&mut drain).await;
    Ok(())
}

// ── Shared transfer body ──────────────────────────────────────────────────────

/// Build the `TransferManifest` from negotiated parameters and source info.
///
/// The `transfer_id` is derived deterministically from the source (name, size,
/// chunk_size, and — for directories — the tree shape) so re-sending the same
/// source resumes an interrupted transfer.  Including `chunk_size` ensures stale
/// resume state from a prior negotiation with different parameters is never reused.
fn build_manifest(
    file_name: String,
    file_size: u64,
    chunk_size: usize,
    num_streams: usize,
    compression: Compression,
    fec: Option<FecParams>,
    entries: Option<&[FileEntry]>,
) -> TransferManifest {
    let transfer_id: [u8; 16] = if let Some(ents) = entries {
        directory_transfer_id(&file_name, file_size, chunk_size, ents)
    } else {
        let mut h = blake3::Hasher::new();
        h.update(file_name.as_bytes());
        h.update(&file_size.to_le_bytes());
        h.update(&(chunk_size as u64).to_le_bytes());
        let mut id = [0u8; 16];
        id.copy_from_slice(&h.finalize().as_bytes()[..16]);
        id
    };
    TransferManifest {
        transfer_id,
        file_name,
        file_size,
        chunk_size,
        total_chunks: file_size.div_ceil(chunk_size as u64),
        num_streams,
        compression,
        fec,
    }
}

/// Message from the control-stream reader task to the dispatch loop.
enum ScaleMsg {
    /// Recommended stream target (scale-up or scale-down).
    Target(u8),
    /// Receiver confirmed new stream count.
    Ack(u8),
}

/// The dispatch/scaling coordination loop, extracted from `run_transfer` so its
/// termination logic is unit-testable.
///
/// Runs until every worker in `tasks` has exited — which happens once the work
/// channel is closed and drained (all chunks dispatched).  Services scale-up and
/// scale-down requests from `scale_rx`, and aborts on a fatal receiver error from
/// `early_abort_rx`.  `spawn_one(tasks)` spawns exactly one new stream worker,
/// used for scale-up; it is moved in and dropped on return.
///
/// The termination check runs after EVERY `select!` iteration, not only on a
/// worker join: a scale-up Ack (or any scale message) can arrive AFTER the final
/// worker already exited, and the loop must still terminate rather than block
/// forever on `scale_rx` with no workers left to join.  That gap was an
/// intermittent end-of-transfer deadlock when scaling fired late (RTT-dependent).
#[allow(clippy::too_many_arguments)]
async fn run_dispatch_loop<CW, F>(
    tasks: &mut JoinSet<Result<()>>,
    mut active_workers: usize,
    ctrl_send: &mut CW,
    early_abort_rx: &mut tokio::sync::mpsc::Receiver<String>,
    scale_rx: &mut tokio::sync::mpsc::Receiver<ScaleMsg>,
    current_streams: &AtomicUsize,
    excess_stop: &AtomicUsize,
    file_hasher: &Option<Arc<ChunkHasher>>,
    fec_enabled: bool,
    mut spawn_one: F,
) -> Result<()>
where
    CW: AsyncWrite + Unpin,
    F: FnMut(&mut JoinSet<Result<()>>),
{
    loop {
        tokio::select! {
            biased;

            // B2: receiver signalled a fatal error via the control stream.
            // Abort immediately — no point sending more chunks.
            Some(msg) = early_abort_rx.recv() => {
                bail!("receiver fatal error: {msg}");
            }

            // Drain completed workers first so active_workers stays accurate.
            Some(res) = tasks.join_next() => {
                match res? {
                    Ok(()) => {}
                    // B1: a single stream was stopped by the receiver (QUIC
                    // STOP_SENDING) when one receiver worker died (hash mismatch,
                    // disk error, …) and dropped its RecvStream.  The other
                    // streams are still healthy — tolerate it and let resume fill
                    // the gap rather than aborting the whole transfer.
                    Err(e) if is_stream_stopped_by_peer(&e) && active_workers > 1 => {
                        warn!(
                            error = format!("{e:#}"),
                            remaining = active_workers - 1,
                            "QUIC stream stopped by receiver; \
                             continuing on remaining streams (resume will fill gap)"
                        );
                    }
                    Err(e) => return Err(e),
                }
                active_workers -= 1;
            }

            // Scale signal from the reader task.
            msg = scale_rx.recv() => {
                match msg {
                    Some(ScaleMsg::Target(target)) if !fec_enabled => {
                        // Send scale request to receiver.
                        framing::send_message(
                            ctrl_send,
                            &SenderMessage::AdjustStreams { target_count: target },
                        )
                        .await?;
                        // Scale-up: open new streams NOW, before the receiver acks.
                        // The receiver calls accept_stream() as soon as it processes
                        // AdjustStreams; if we wait for the ack first, the two sides
                        // deadlock (receiver blocks on accept, sender blocks on ack).
                        let current = current_streams.load(AtomicOrd::Relaxed);
                        if target as usize > current {
                            let extra = target as usize - current;
                            for _ in 0..extra {
                                spawn_one(tasks);
                                active_workers += 1;
                            }
                            current_streams.store(target as usize, AtomicOrd::Relaxed);
                            if let Some(h) = file_hasher {
                                h.update_stream_count(target as usize);
                            }
                            tracing::info!(
                                previous = current,
                                now = target,
                                "scaling up: connecting {extra} new streams"
                            );
                        }
                    }
                    Some(ScaleMsg::Ack(accepted)) if !fec_enabled => {
                        let current = current_streams.load(AtomicOrd::Relaxed);
                        let new_count = accepted as usize;
                        if new_count < current {
                            // Receiver accepted fewer streams than we opened — either a
                            // scale-down ack or a partial scale-up (some accepts failed).
                            // Signal excess workers to stop after their current chunk.
                            // active_workers is NOT decremented here; it decrements via
                            // tasks.join_next() as each worker exits.
                            let excess = current - new_count;
                            excess_stop.store(excess, AtomicOrd::Release);
                            current_streams.store(new_count, AtomicOrd::Relaxed);
                            if let Some(h) = file_hasher {
                                h.update_stream_count(new_count);
                            }
                            tracing::info!(
                                previous = current,
                                now = new_count,
                                "scaling down: {excess} workers will exit after current chunk"
                            );
                        } else if new_count == current {
                            tracing::info!(now = new_count, "scaled up to {new_count} streams");
                        }
                    }
                    // FEC path, ignored variant, or channel closed — fall through.
                    _ => {}
                }
            }
        }
        // All stream workers have exited ⇒ every chunk was dispatched and the
        // work channel drained.  Re-checked after EVERY select! iteration (see
        // the doc comment) — this is the fix for the late-scaling deadlock.
        if active_workers == 0 {
            break;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Core transfer logic shared by both the QUIC and TCP paths.
///
/// Called after the control stream is established and the initial
/// `NegotiateRequest` / `NegotiateResponse` round-trip is complete.
///
/// `spawn_worker` is a factory called once per data stream.  It receives a
/// dedicated channel receiver from which to pull pre-read raw chunks, and must
/// return a future that opens one network stream, compresses and sends all
/// chunks from the receiver, and closes the stream cleanly.
async fn run_transfer<CW, CR, F, Fut>(
    file: &Path,
    file_size: u64,
    entries: Option<&[FileEntry]>,
    ctrl_send: &mut CW,
    mut ctrl_recv: CR,
    rtt: Duration,
    sender_cores: u32,
    receiver_cores: u32,
    peer_protocol_version: u32,
    config: &SendConfig,
    qconn: Option<quinn::Connection>,
    // `Some` when the caller already pipelined NegotiateRequest + manifest +
    // DirEntries into one flight (QUIC fast path); `None` to build and send the
    // manifest here (TCP path, which can't compute params before the RTT-probing
    // round-trip).
    prebuilt: Option<TransferManifest>,
    spawn_worker: F,
) -> Result<()>
where
    CW: AsyncWrite + Unpin,
    CR: AsyncRead + Unpin + Send + 'static,
    F: Fn(
        ac::Receiver<(u64, Vec<u8>)>,
        [u8; 16],
        Compression,
        Option<Arc<ChunkHasher>>,
        Arc<AtomicUsize>,
        CompressionStats,
    ) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    // For directory transfers, check that receiver supports v3.
    if entries.is_some() && peer_protocol_version < 3 {
        bail!(
            "the receiver is running an older version of mftp (protocol version {peer_protocol_version}) \
             that does not support directory transfers — please upgrade the receiver to v3+"
        );
    }

    let compression = if config.compress {
        Compression::Zstd {
            level: config.compress_level,
        }
    } else {
        Compression::None
    };

    let manifest = match prebuilt {
        // QUIC fast path: the manifest (and DirEntries) were already sent by the
        // caller in the same flight as NegotiateRequest — one fewer round-trip.
        Some(m) => m,
        // TCP path: now that the NegotiateResponse round-trip has measured RTT
        // and revealed receiver_cores, compute params, build, and send.
        None => {
            let file_name = file
                .file_name()
                .context("file has no name")?
                .to_string_lossy()
                .into_owned();
            let params = compute_params(
                rtt,
                file_size,
                sender_cores,
                receiver_cores,
                config.streams,
                config.chunk_size,
            );
            let m = build_manifest(
                file_name,
                file_size,
                params.chunk_size,
                params.streams,
                compression.clone(),
                None,
                entries,
            );
            framing::send_message(ctrl_send, &m).await?;
            // v3+: DirEntries immediately after the manifest (strict ordering).
            if peer_protocol_version >= 3 {
                let dir_entries_msg = DirEntries {
                    entries: entries.map(|e| e.to_vec()),
                };
                framing::send_message(ctrl_send, &dir_entries_msg).await?;
            }
            m
        }
    };

    let chunk_size = manifest.chunk_size;
    let transfer_id = manifest.transfer_id;
    let total_chunks = manifest.total_chunks;
    let num_streams = manifest.num_streams;
    let file_name = manifest.file_name.clone();
    tracing::info!(
        streams = num_streams,
        chunk_mib = chunk_size / (1024 * 1024),
        rtt_ms = rtt.as_secs_f64() * 1000.0,
        sender_cores,
        receiver_cores,
        "negotiated transfer parameters"
    );

    // Receive Ready — receiver sends a packed bitvector of already-on-disk chunks.
    // Uses the data-frame limit (128 MiB) because the bitvector can be large for
    // big files even in its compact form (e.g. 16 TiB / 4 MiB = ~500 KB bitvec).
    let ready: ReceiverMessage = framing::recv_data_message(&mut ctrl_recv)
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream closed before Ready message"))?;
    let have: HashSet<u64> = match ready {
        ReceiverMessage::Ready {
            received_bits,
            total_chunks,
        } => bits_to_chunk_set(&received_bits, total_chunks),
        ReceiverMessage::Error { message, .. } => bail!("receiver error: {message}"),
        other => bail!("unexpected message from receiver: {other:?}"),
    };
    let skip_count = have.len() as u64;
    let remaining = total_chunks - skip_count;
    info!("{skip_count} chunks already at receiver, {remaining} to send");

    // For a fresh transfer (no resume), hash inline as the feeder reads each
    // chunk — no second disk pass.  For a resume, we must also hash skipped
    // chunks, so fall back to a concurrent full-file read instead.
    let file_hasher: Option<Arc<ChunkHasher>> = if have.is_empty() {
        Some(Arc::new(ChunkHasher::new(total_chunks, num_streams)))
    } else {
        None
    };
    let hash_task = if have.is_empty() {
        None
    } else if let Some(ents) = entries {
        let path = file.to_owned();
        let ents_owned = ents.to_vec();
        Some(tokio::task::spawn_blocking(move || {
            crate::transfer::hash::hash_concat_sync(&ents_owned, &path, chunk_size)
        }))
    } else {
        let path = file.to_owned();
        Some(tokio::task::spawn_blocking(move || {
            hash_file_sync(&path, chunk_size)
        }))
    };

    let compress_stats = new_compression_stats();

    let chunk_mib = chunk_size / (1024 * 1024);
    let file_count = entries.map(|e| {
        e.iter()
            .filter(|en| matches!(en.kind, FileKind::File))
            .count()
    });
    let pb = make_progress_bar(&file_name, file_size, num_streams, chunk_mib, file_count);
    // Seed the bar with bytes the receiver already confirmed (resume).
    let resume_bytes: u64 = have
        .iter()
        .map(|&i| {
            let offset = i * chunk_size as u64;
            (file_size - offset).min(chunk_size as u64)
        })
        .sum();
    pb.set_position(resume_bytes);
    let transfer_start = Instant::now();

    // ── Control-stream reader task ────────────────────────────────────────────
    //
    // A dedicated task owns ctrl_recv and reads ReceiverMessage variants:
    //
    // • Progress  — advances the progress bar; drives saturation/stall warnings
    //               and, when --adaptive-streams is active, throughput measurement.
    //               When a target stream count is recommended the task forwards it
    //               to the main loop via `scale_tx` (ScaleMsg::Target).
    // • AdjustStreamsAck — forwarded as ScaleMsg::Ack so the main loop can spawn
    //               new workers.
    // • Complete / Error — forwarded via `completion_tx` (terminal message).

    let pb_for_reader = pb.clone();
    // mpsc (not oneshot): the reader forwards Retransmit requests non-terminally
    // and keeps reading until a terminal Complete/Error arrives.
    let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel::<ReceiverMessage>(4);
    // B2: channel for the reader task to signal a fatal receiver error to the
    // main loop without waiting for workers to drain first.
    let (early_abort_tx, mut early_abort_rx) = tokio::sync::mpsc::channel::<String>(1);
    let (scale_tx, mut scale_rx) = tokio::sync::mpsc::channel::<ScaleMsg>(8);
    // Shared current stream count: reader reads it for compute_target_streams;
    // main loop increments it when scale-up is accepted.
    let current_streams_arc = Arc::new(AtomicUsize::new(num_streams));
    let current_streams_for_reader = Arc::clone(&current_streams_arc);
    // MAX_IN_FLIGHT on the receiver is 4 per stream worker.
    let max_in_flight_base = num_streams as u32 * 4;
    // cpu_cap mirrors the same formula used in compute_params().
    let cpu_cap = (receiver_cores.min(sender_cores) as usize).max(1) * 2;
    // Adaptive scaling is on by default; disabled when streams are explicitly
    // pinned via -n N (explicit count implies user wants static behaviour).
    let adaptive_enabled = config.streams.is_none()
        && peer_protocol_version >= crate::protocol::messages::PROTOCOL_VERSION;

    // Observability: shared atomics sampled by a background stats task (QUIC
    // only) and by the reader task; make_diag() reads them for the {msg} slot.
    // disk_stall_ms comes from the receiver's Progress messages, so only the
    // reader owns that atomic (no stats-task clone needed).
    let rtt_ms_atom = Arc::new(AtomicU32::new(rtt.as_millis() as u32));
    let loss_atom = Arc::new(AtomicU64::new(0u64));
    let stall_ms_for_reader = Arc::new(AtomicU32::new(0u32));
    let rtt_ms_for_reader = Arc::clone(&rtt_ms_atom);
    let loss_for_reader = Arc::clone(&loss_atom);
    let _stats_task = qconn.map(|c| {
        let rtt_a = rtt_ms_atom;
        let loss_a = loss_atom;
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                iv.tick().await;
                let s = c.stats();
                rtt_a.store(s.path.rtt.as_millis() as u32, AtomicOrd::Relaxed);
                loss_a.store(s.path.lost_packets, AtomicOrd::Relaxed);
            }
        })
    });

    let scale_tx_for_reader = scale_tx.clone();
    let reader = tokio::spawn(async move {
        let mut flash_until: Option<std::time::Instant> = None;
        let mut saturated_run = 0u32;
        let mut last_disk_warn = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(30))
            .unwrap_or_else(std::time::Instant::now);

        // Sliding window of progress samples for throughput estimation.
        const SAMPLE_WINDOW: usize = 10;
        let mut samples: Vec<ProgressSample> = Vec::with_capacity(SAMPLE_WINDOW + 1);
        let mut last_scale_at: Option<std::time::Instant> = None;
        let mut last_scale_down_at: Option<std::time::Instant> = None;
        // Suppress sending another Target while a pending Ack is expected.
        let mut pending_scale = false;

        // Format persistent diagnostic for the {msg} slot of the progress bar.
        // Shows in wide-terminal mode (≥140 cols); no-op when {msg} is absent.
        let make_diag = || {
            let streams = current_streams_for_reader.load(AtomicOrd::Relaxed);
            let rtt_ms = rtt_ms_for_reader.load(AtomicOrd::Relaxed);
            let loss = loss_for_reader.load(AtomicOrd::Relaxed);
            let stall = stall_ms_for_reader.load(AtomicOrd::Relaxed);
            let mut s = format!("streams={streams}");
            if rtt_ms > 0 {
                s.push_str(&format!(" rtt={rtt_ms}ms"));
            }
            if loss > 0 {
                s.push_str(&format!(" loss={loss}"));
            }
            if stall > 0 {
                s.push_str(&format!(" stall={stall}ms"));
            }
            s
        };

        loop {
            match framing::recv_message::<_, ReceiverMessage>(&mut ctrl_recv).await {
                Ok(Some(ReceiverMessage::Progress {
                    bytes_written,
                    in_flight_chunks,
                    disk_stall_ms,
                })) => {
                    pb_for_reader.set_position(bytes_written);
                    stall_ms_for_reader.store(disk_stall_ms, AtomicOrd::Relaxed);

                    // Revert flash message if its display window has elapsed.
                    if flash_until.is_some_and(|d| std::time::Instant::now() >= d) {
                        pb_for_reader.set_message(make_diag());
                        flash_until = None;
                    }

                    let current = current_streams_for_reader.load(AtomicOrd::Relaxed);
                    let max_in_flight = current as u32 * 4;

                    // Saturation: ≥75% of max in-flight for 3+ consecutive samples.
                    if in_flight_chunks >= max_in_flight * 3 / 4 {
                        saturated_run += 1;
                        if saturated_run == 3 {
                            tracing::info!(
                                in_flight = in_flight_chunks,
                                max = max_in_flight,
                                "receiver saturated: chunk processing cannot keep up with network"
                            );
                            pb_for_reader.set_message("⚠ receiver saturated".to_string());
                            flash_until =
                                Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
                        }
                    } else {
                        if saturated_run >= 3 {
                            tracing::info!("receiver saturation cleared");
                            pb_for_reader.set_message("✓ saturation cleared".to_string());
                            flash_until =
                                Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
                        }
                        saturated_run = 0;
                    }

                    // Disk stall: log at info, throttle to once per 10 s.
                    // No progress-bar flash needed — stall=Nms is already shown
                    // persistently in the diagnostic line.
                    if disk_stall_ms > 50
                        && last_disk_warn.elapsed() >= std::time::Duration::from_secs(10)
                    {
                        tracing::info!(
                            disk_stall_ms,
                            "receiver disk stall: writes are taking longer than 50 ms"
                        );
                        last_disk_warn = std::time::Instant::now();
                    }

                    // Adaptive stream scaling.
                    if adaptive_enabled && !pending_scale {
                        samples.push(ProgressSample {
                            bytes_written,
                            in_flight_chunks,
                            disk_stall_ms,
                            timestamp: std::time::Instant::now(),
                        });
                        if samples.len() > SAMPLE_WINDOW {
                            samples.remove(0);
                        }
                        if let Some(target) = compute_target_streams(
                            &samples,
                            current,
                            cpu_cap,
                            file_size,
                            last_scale_at,
                            last_scale_down_at,
                        ) {
                            if (target as usize) != current {
                                let direction = if (target as usize) > current {
                                    "up"
                                } else {
                                    "down"
                                };
                                tracing::info!(
                                    current,
                                    target,
                                    "adaptive: scaling {direction} streams"
                                );
                                if tracing::enabled!(tracing::Level::INFO) {
                                    pb_for_reader
                                        .set_message(format!("scaling {current}→{target} streams"));
                                    flash_until = Some(
                                        std::time::Instant::now()
                                            + std::time::Duration::from_secs(5),
                                    );
                                }
                                if scale_tx_for_reader
                                    .send(ScaleMsg::Target(target))
                                    .await
                                    .is_err()
                                {
                                    return; // main loop dropped receiver
                                }
                                pending_scale = true;
                                let now = std::time::Instant::now();
                                last_scale_at = Some(now);
                                if (target as usize) < current {
                                    last_scale_down_at = Some(now);
                                }
                            }
                        }
                    }
                }
                Ok(Some(ReceiverMessage::AdjustStreamsAck { accepted_count })) => {
                    tracing::info!(accepted = accepted_count, "receiver acked stream scaling");
                    pending_scale = false;
                    pb_for_reader.set_message(make_diag());
                    flash_until = None;
                    let _ = scale_tx_for_reader
                        .send(ScaleMsg::Ack(accepted_count))
                        .await;
                }
                Ok(Some(other)) => {
                    // B2: if receiver sent a fatal Error, wake the main loop
                    // immediately — don't wait for all stream workers to drain.
                    if let ReceiverMessage::Error {
                        ref message,
                        fatal: true,
                    } = other
                    {
                        let _ = early_abort_tx.try_send(message.clone());
                    }
                    // Retransmit is non-terminal: forward it and keep reading so
                    // the next Complete/Error after the repair round is seen too.
                    let terminal = !matches!(other, ReceiverMessage::Retransmit { .. });
                    if completion_tx.send(other).await.is_err() {
                        return; // main loop dropped the receiver
                    }
                    if terminal {
                        return;
                    }
                }
                _ => return, // EOF or error — completion_rx surfaces this
            }
        }
    });
    let _ = max_in_flight_base; // used only for reference

    // ── Single-reader feeder + N parallel workers ─────────────────────────────
    //
    // The feeder reads the source file sequentially in one blocking thread,
    // matching scp's I/O pattern and achieving full sequential disk bandwidth.
    // It pushes raw chunks into a single bounded MPMC channel; all workers
    // pull from the same channel.
    //
    // Using MPMC (instead of N per-worker SPSC channels) means:
    //   - Workers that finish a chunk faster naturally pull more work (implicit
    //     load balancing, no head-of-line blocking behind a slow worker).
    //   - Dynamic stream count changes (Task 5 scaling) can add or remove
    //     workers without restructuring the feeder.
    //
    // Total channel capacity = WORKER_CHAN_DEPTH × stream_count so the feeder
    // can buffer the same amount as with per-worker channels, preserving the
    // backpressure characteristics.
    const WORKER_CHAN_DEPTH: usize = 4;

    let actual_streams = num_streams.min(remaining.max(1) as usize);

    // Single shared MPMC work channel.
    let (work_tx, work_rx) = ac::bounded::<(u64, Vec<u8>)>(WORKER_CHAN_DEPTH * actual_streams);
    // Scale-down: number of workers that should exit cleanly after their current chunk.
    // Set by the main loop on receiving a scale-down Ack; checked by each worker after
    // each chunk send.  Zero means no pending scale-down.
    let excess_stop = Arc::new(AtomicUsize::new(0));

    // Feeder(s): read file chunks and push to the shared MPMC channel.
    //
    // With --parallel-reads, spawn multiple blocking tasks covering disjoint
    // chunk ranges — useful on high-queue-depth NVMe where a single sequential
    // reader is the bottleneck.  Each task holds one work_tx clone; the channel
    // closes when all clones are dropped (i.e., all readers finish), signalling
    // workers to drain and exit.
    //
    // Without --parallel-reads, a single sequential reader is used, which is
    // optimal for spinning disks, network mounts, and all network-bound transfers.
    let total_chunks = file_size.div_ceil(chunk_size as u64);
    let feeders: Vec<tokio::task::JoinHandle<Result<()>>> = if let Some(ents) = entries {
        // Directory path: always use a single sequential feeder over the concat
        // stream.  The pre-reading optimisation in feed_chunks_concat already
        // handles NVMe efficiently; parallel-reads is not useful for the
        // scatter-gather read pattern needed here.
        let root = file.to_owned();
        let ents_owned = ents.to_vec();
        let skip = have.clone();
        vec![tokio::task::spawn_blocking(move || {
            feed_chunks_concat(&root, &ents_owned, file_size, chunk_size, &skip, work_tx)
        })]
    } else if config.parallel_reads && actual_streams > 1 {
        let p = actual_streams.min(8); // cap at 8 parallel readers
        let chunks_per_reader = total_chunks.div_ceil(p as u64);
        let mut handles = Vec::with_capacity(p);
        for reader_id in 0..p {
            let path = file.to_owned();
            let skip = have.clone();
            let tx = work_tx.clone();
            let range_start = reader_id as u64 * chunks_per_reader;
            let range_end = (range_start + chunks_per_reader).min(total_chunks);
            handles.push(tokio::task::spawn_blocking(move || {
                feed_chunks_range(
                    &path,
                    file_size,
                    chunk_size,
                    &skip,
                    tx,
                    range_start,
                    range_end,
                )
            }));
        }
        drop(work_tx); // close the sender side; channel empties when readers finish
        handles
    } else {
        let path = file.to_owned();
        let skip = have.clone();
        vec![tokio::task::spawn_blocking(move || {
            feed_chunks(&path, file_size, chunk_size, &skip, work_tx)
        })]
    };

    // Spawn N stream workers, and reuse the same spawner for scale-up.  Each
    // worker gets a clone of the shared MPMC receiver (all clones drain the same
    // queue) and an Arc of the file hasher.
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    let spawn_one = {
        let work_rx = work_rx.clone();
        let compression = compression.clone();
        let file_hasher = file_hasher.clone();
        let excess_stop = excess_stop.clone();
        let cs = (Arc::clone(&compress_stats.0), Arc::clone(&compress_stats.1));
        move |tasks: &mut JoinSet<Result<()>>| {
            tasks.spawn(spawn_worker(
                work_rx.clone(),
                transfer_id,
                compression.clone(),
                file_hasher.clone(),
                excess_stop.clone(),
                (Arc::clone(&cs.0), Arc::clone(&cs.1)),
            ));
        }
    };
    for _ in 0..actual_streams {
        spawn_one(&mut tasks);
    }

    // Dynamic scaling main loop (extracted to run_dispatch_loop for testability).
    // `spawn_one` is moved in and dropped on return, releasing the file-hasher
    // Arc clone it holds before the try_unwrap below.
    run_dispatch_loop(
        &mut tasks,
        actual_streams,
        ctrl_send,
        &mut early_abort_rx,
        &mut scale_rx,
        &current_streams_arc,
        &excess_stop,
        &file_hasher,
        config.fec.is_some(),
        spawn_one,
    )
    .await?;

    // Workers done; all feeders should have finished by now (channel closed).
    for feeder in feeders {
        feeder.await.context("feeder task panicked")??;
    }

    pb.set_message("verifying…");

    let file_hash: [u8; 32] = match file_hasher {
        Some(h) => Arc::try_unwrap(h)
            .expect(
                "all stream workers have completed; no other Arc<ChunkHasher> references remain",
            )
            .finish()?,
        None => hash_task
            .expect("resume path always spawns hash_task")
            .await
            .context("hash task panicked")??,
    };
    framing::send_message(ctrl_send, &SenderMessage::Complete { file_hash }).await?;

    // Completion handshake: service any v5 incremental-repair requests over the
    // control stream (single-file only), bounded by MAX_REPAIR_ROUNDS, until the
    // receiver returns a terminal Complete/Error.  B3: bounded by ack_timeout so
    // the sender never hangs if the receiver died without acknowledging.
    let msg = await_completion_with_repair(
        ctrl_send,
        &mut completion_rx,
        file,
        file_size,
        chunk_size,
        transfer_id,
        &compression,
        file_hash,
        rtt,
        entries.map(|e| e.to_vec()),
        &pb,
    )
    .await?;
    reader.await.ok();
    pb.finish_and_clear();
    print_completion(
        msg,
        &file_name,
        file_size,
        file_hash,
        transfer_start,
        &compress_stats,
    )?;

    Ok(())
}

// ── Incremental repair (protocol v5) ───────────────────────────────────────────

/// Drive the completion handshake after all data has been sent, servicing any
/// `Retransmit` repair requests over the control stream until the receiver
/// returns a terminal `Complete`/`Error` (or the repair bounds are exceeded).
///
/// The caller must have already sent the first `SenderMessage::Complete`.  On a
/// `Retransmit`, the listed chunks are re-read from the source, re-sent as plain
/// `ChunkData` on `ctrl_send`, and a fresh `Complete` is sent — all on the
/// existing connection, so the warmed congestion window survives.
///
/// `entries` selects the read strategy: `None` is a single-file transfer (the
/// global chunk index maps directly to a `file` offset); `Some(entries)` is a
/// directory transfer, where the global chunk index is reverse-mapped to the
/// byte range(s) it spans across the concatenated file set — the inverse of
/// [`feed_chunks_concat`] — so directory repair works in-band too.
#[allow(clippy::too_many_arguments)]
async fn await_completion_with_repair<CW>(
    ctrl_send: &mut CW,
    completion_rx: &mut tokio::sync::mpsc::Receiver<ReceiverMessage>,
    file: &Path,
    file_size: u64,
    chunk_size: usize,
    transfer_id: [u8; 16],
    compression: &Compression,
    file_hash: [u8; 32],
    rtt: Duration,
    entries: Option<Vec<FileEntry>>,
    pb: &ProgressBar,
) -> Result<ReceiverMessage>
where
    CW: AsyncWrite + Unpin,
{
    let mut round = 0u32;
    loop {
        let msg = tokio::time::timeout(ack_timeout(rtt, file_size), completion_rx.recv())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "timed out waiting for receiver acknowledgement after all data was sent"
                )
                .context(AckTimeoutAfterComplete)
            })?
            .context("receiver closed without completing")?;

        let chunks = match msg {
            ReceiverMessage::Retransmit { chunks } => chunks,
            terminal => return Ok(terminal),
        };

        round += 1;
        if round > crate::protocol::messages::MAX_REPAIR_ROUNDS {
            bail!(
                "exceeded {} repair rounds; receiver still missing {} chunk(s) — aborting (resume will recover)",
                crate::protocol::messages::MAX_REPAIR_ROUNDS,
                chunks.len()
            );
        }
        if chunks.len() > crate::protocol::messages::MAX_REPAIR_CHUNKS_PER_ROUND {
            bail!(
                "receiver requested {} chunks for repair, over the {} limit — aborting (resume will recover)",
                chunks.len(),
                crate::protocol::messages::MAX_REPAIR_CHUNKS_PER_ROUND
            );
        }

        tracing::info!(round, count = chunks.len(), "servicing repair request");
        pb.set_message(format!("repairing {} chunk(s)…", chunks.len()));

        // Re-read + recompress the requested chunks off the async runtime.
        let built = {
            let file = file.to_owned();
            let compression = compression.clone();
            let entries = entries.clone();
            tokio::task::spawn_blocking(move || -> Result<Vec<ChunkData>> {
                use std::io::{Read, Seek, SeekFrom};

                // Directory transfer: precompute the concat layout once so each
                // chunk re-read is a binary-search + scatter-read across files.
                let concat = entries.as_ref().map(|e| {
                    let fe: Vec<&FileEntry> = e
                        .iter()
                        .filter(|x| matches!(x.kind, FileKind::File) && x.size > 0)
                        .collect();
                    let mut ps = Vec::with_capacity(fe.len() + 1);
                    let mut acc = 0u64;
                    for x in &fe {
                        ps.push(acc);
                        acc += x.size;
                    }
                    ps.push(acc); // sentinel = total bytes
                    (fe, ps)
                });

                // Single-file transfer: one shared handle, seek per chunk.
                let mut single = match concat {
                    Some(_) => None,
                    None => Some(
                        std::fs::File::open(&file)
                            .with_context(|| format!("open {} for repair", file.display()))?,
                    ),
                };

                let mut out = Vec::with_capacity(chunks.len());
                for idx in chunks {
                    let offset = idx * chunk_size as u64;
                    if offset >= file_size {
                        bail!("repair: chunk {idx} is out of range for this transfer");
                    }
                    let len = ((file_size - offset) as usize).min(chunk_size);
                    let mut raw = vec![0u8; len];
                    match &concat {
                        Some((fe, ps)) => read_concat_chunk_into(&file, fe, ps, offset, &mut raw)?,
                        None => {
                            let f = single.as_mut().expect("single-file handle present");
                            f.seek(SeekFrom::Start(offset))
                                .with_context(|| format!("seek to repair chunk {idx}"))?;
                            f.read_exact(&mut raw)
                                .with_context(|| format!("read repair chunk {idx}"))?;
                        }
                    }
                    let chunk_hash = *blake3::hash(&raw).as_bytes();
                    let (payload, compressed) = maybe_compress(raw, &compression)?;
                    out.push(ChunkData {
                        transfer_id,
                        chunk_index: idx,
                        chunk_hash,
                        compressed,
                        payload,
                    });
                }
                Ok(out)
            })
            .await
            .context("repair read task panicked")??
        };

        for cd in &built {
            framing::send_chunk_data(ctrl_send, cd).await?;
        }
        framing::send_message(ctrl_send, &SenderMessage::Complete { file_hash }).await?;
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Compute the timeout for waiting on the receiver's final `Complete` message.
///
/// After the sender transmits all data, the receiver must hash-verify the full
/// file before responding.  On the resume path it re-reads the file from disk,
/// so the budget must scale with `file_size`.
///
/// Formula: max(4×RTT + 30 s,  file_size / 500 MB/s + 30 s)
///
/// The 500 MB/s floor is a conservative estimate for sequential disk read +
/// BLAKE3 on spinning media.  The 30-second addend covers small files and any
/// network / scheduling jitter.
fn ack_timeout(rtt: Duration, file_size: u64) -> Duration {
    const HASH_FLOOR_BPS: u64 = 500_000_000; // 500 MB/s
    let hash_estimate = Duration::from_secs(file_size / HASH_FLOOR_BPS + 1);
    (rtt * 4 + Duration::from_secs(30)).max(hash_estimate + Duration::from_secs(30))
}

/// Read the source file sequentially and distribute non-skipped chunks
/// round-robin to the per-worker channels.
///
/// Designed to run in [`tokio::task::spawn_blocking`].  Uses a single file
/// handle with `POSIX_FADV_SEQUENTIAL` so the kernel maintains one large
/// read-ahead window and delivers data at full sequential disk bandwidth —
/// the same I/O pattern as `scp`.
///
/// Sending directly to per-worker channels (rather than through an async
/// dispatcher) means the channels are pre-filled from an OS thread that runs
/// truly in parallel with the async executor.  Workers can therefore call
/// `try_recv` immediately and find a chunk waiting, enabling the
/// compress/hash pipeline to overlap with network sends.
fn feed_chunks(
    path: &Path,
    file_size: u64,
    chunk_size: usize,
    skip: &HashSet<u64>,
    tx: ac::Sender<(u64, Vec<u8>)>,
) -> Result<()> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
    }

    let total_chunks = file_size.div_ceil(chunk_size as u64);

    for idx in 0..total_chunks {
        if skip.contains(&idx) {
            continue;
        }
        let offset = idx * chunk_size as u64;
        let len = (chunk_size as u64).min(file_size - offset) as usize;

        let mut raw = vec![0u8; len];
        crate::fs_ext::read_exact_at(&file, &mut raw, offset)
            .with_context(|| format!("read chunk {idx}"))?;

        // send_blocking provides backpressure: if the channel is full the
        // feeder waits here, naturally throttling disk reads to the network
        // send rate.  An Err means all receivers (workers) have closed.
        if tx.send_blocking((idx, raw)).is_err() {
            break;
        }
    }

    Ok(())
}

/// Receive pre-read raw chunks from the feeder, compress and hash each one,
/// and send over the given network stream.
///
/// Compress+BLAKE3 runs in a blocking thread so it never stalls the async
/// executor (which would delay QUIC ACK processing and hurt BBR at high RTT).
///
/// Pipeline: after spawning the compress+hash task for chunk N we immediately
/// try to pre-fetch chunk N+1 from the channel and spawn its task too.  Both
/// blocking threads run concurrently.  When we then call `send(N).await`, the
/// blocking thread for N+1 has already been running for the full send duration,
/// so `task(N+1).await` usually returns immediately after the send completes.
///
/// `file_hasher` is `Some` on fresh transfers; each worker feeds its chunks
/// into the shared hasher from inside `spawn_blocking`, distributing the
/// hashing work across N threads instead of serialising it on the feeder.
async fn send_from_channel<W>(
    writer: &mut W,
    rx: ac::Receiver<(u64, Vec<u8>)>,
    transfer_id: [u8; 16],
    compression: &Compression,
    file_hasher: Option<Arc<ChunkHasher>>,
    excess_stop: Arc<AtomicUsize>,
    stats: CompressionStats,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    // (chunk_index, payload, wire_hash, compressed, raw_len)
    // raw_len is fed back to the adaptive level tracker after each chunk.
    type Ready = (u64, Vec<u8>, [u8; 32], bool, usize);

    // Per-worker adaptive compression level.  Starts at the negotiated level
    // and adjusts based on observed compression ratios across recent chunks.
    // None when compression is disabled entirely.
    let mut adaptive = if let Compression::Zstd { level } = compression {
        Some(compress::AdaptiveLevel::new(*level))
    } else {
        None
    };

    // Return the Compression variant to use for the next chunk, reflecting the
    // current adaptive level.
    let current_compression = |adaptive: &Option<compress::AdaptiveLevel>| -> Compression {
        match (compression, adaptive) {
            (Compression::None, _) => Compression::None,
            (Compression::Zstd { .. }, Some(al)) => Compression::Zstd { level: al.level },
            (Compression::Zstd { level }, None) => Compression::Zstd { level: *level },
        }
    };

    let spawn_prepare = |chunk_index: u64, raw: Vec<u8>, comp: Compression| {
        // Cheap Arc clone — one per chunk, just increments a reference count.
        let hasher = file_hasher.clone();
        tokio::task::spawn_blocking(move || -> Result<Ready> {
            // Hash raw bytes once — this single hash serves two purposes:
            //   1. Wire integrity (chunk_hash field in ChunkData)
            //   2. File integrity (fed into ChunkHasher for end-to-end verification)
            // Previously we hashed raw for file integrity AND payload for wire, doing
            // BLAKE3 twice on the same data for incompressible inputs (~40% CPU waste).
            let raw_len = raw.len();
            let chunk_hash: [u8; 32] = *blake3::hash(&raw).as_bytes();
            if let Some(h) = hasher {
                h.feed(chunk_index, chunk_hash)?;
            }
            let (payload, compressed) = maybe_compress(raw, &comp)?;
            Ok((chunk_index, payload, chunk_hash, compressed, raw_len))
        })
    };

    while let Ok((idx, raw)) = rx.recv().await {
        let mut task = spawn_prepare(idx, raw, current_compression(&adaptive));

        loop {
            // Try to prefetch the next raw chunk and start its prepare task
            // before awaiting the current one.  Because spawn_blocking runs on
            // a separate thread pool, this prepare runs concurrently with both
            // the current task.await and the subsequent send_chunk_data.await.
            let next_task = rx
                .try_recv()
                .ok()
                .map(|(ni, nr)| spawn_prepare(ni, nr, current_compression(&adaptive)));

            let (chunk_index, payload, chunk_hash, compressed, raw_len) =
                task.await.context("prepare task panicked")??;

            // Update the adaptive level with the ratio just observed.
            // The next prefetch task (next_task above) already captured the
            // current level, so the adaptation takes effect one chunk later —
            // a one-chunk latency that is acceptable.
            if let Some(ref mut al) = adaptive {
                al.update(raw_len, payload.len());
            }
            stats.0.fetch_add(raw_len as u64, AtomicOrd::Relaxed);
            stats.1.fetch_add(payload.len() as u64, AtomicOrd::Relaxed);

            framing::send_chunk_data(
                writer,
                &ChunkData {
                    transfer_id,
                    chunk_index,
                    chunk_hash,
                    compressed,
                    payload,
                },
            )
            .await?;
            debug!(chunk = chunk_index, "sent");

            // Scale-down: after each chunk, check if this worker should exit.
            // Use compare_exchange loop to safely claim one exit slot without
            // risking fetch_sub underflow if multiple workers race.
            if excess_stop.load(AtomicOrd::Relaxed) > 0 {
                let mut val = excess_stop.load(AtomicOrd::Acquire);
                loop {
                    if val == 0 {
                        break;
                    }
                    match excess_stop.compare_exchange(
                        val,
                        val - 1,
                        AtomicOrd::AcqRel,
                        AtomicOrd::Relaxed,
                    ) {
                        Ok(_) => {
                            // This worker claimed an exit slot.  If there is a
                            // prefetched chunk already pulled from the channel,
                            // send it too — dropping it would lose data.
                            if let Some(nt) = next_task {
                                let (ci, pl, ch, compr, rl) =
                                    nt.await.context("prepare task panicked")??;
                                if let Some(ref mut al) = adaptive {
                                    al.update(rl, pl.len());
                                }
                                framing::send_chunk_data(
                                    writer,
                                    &ChunkData {
                                        transfer_id,
                                        chunk_index: ci,
                                        chunk_hash: ch,
                                        compressed: compr,
                                        payload: pl,
                                    },
                                )
                                .await?;
                                debug!(chunk = ci, "sent (final before scale-down exit)");
                            }
                            return Ok(()); // caller will finish/shutdown the stream
                        }
                        Err(actual) => {
                            val = actual; // retry with fresh value
                        }
                    }
                }
            }

            match next_task {
                // next_task's blocking thread was running during task.await +
                // send_chunk_data; it is likely done already.
                Some(nt) => task = nt,
                // Channel was empty at try_recv; break to the outer recv loop
                // so we wait for the next chunk without spinning.
                None => break,
            }
        }
    }

    Ok(())
}

fn make_progress_bar(
    file_name: &str,
    file_size: u64,
    streams: usize,
    chunk_mib: usize,
    file_count: Option<usize>,
) -> Arc<ProgressBar> {
    let meta = if let Some(n) = file_count {
        format!("  {streams} streams · {chunk_mib} MiB chunks · {n} files")
    } else {
        format!("  {streams} streams · {chunk_mib} MiB chunks")
    };
    eprintln!("{meta}");
    let term_width = console::Term::stdout().size().1 as usize;
    let wide = term_width >= 140;
    Arc::new({
        let pb = ProgressBar::new(file_size);
        pb.set_style(crate::progress::transfer_style("↑", wide));
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_prefix(file_name.to_owned());
        pb
    })
}

fn print_completion(
    msg: ReceiverMessage,
    file_name: &str,
    file_size: u64,
    file_hash: [u8; 32],
    transfer_start: Instant,
    stats: &CompressionStats,
) -> Result<()> {
    match msg {
        ReceiverMessage::Complete {
            file_hash: recv_hash,
        } => {
            if recv_hash != file_hash {
                bail!("file hash mismatch: receiver computed a different hash");
            }
            let elapsed = transfer_start.elapsed();
            let mib = file_size as f64 / (1024.0 * 1024.0);
            let throughput = mib / elapsed.as_secs_f64();
            let raw = stats.0.load(AtomicOrd::Relaxed);
            let wire = stats.1.load(AtomicOrd::Relaxed);
            if raw > 0 && wire < raw {
                let saved_pct = (1.0 - wire as f64 / raw as f64) * 100.0;
                let wire_mib = wire as f64 / (1024.0 * 1024.0);
                println!(
                    "Transfer complete: {file_name} ({mib:.0} MiB) in {:.1}s \
                     ({throughput:.0} MiB/s end-to-end). Hash verified. \
                     Wire: {wire_mib:.0} MiB ({saved_pct:.0}% saved by compression).",
                    elapsed.as_secs_f64(),
                );
            } else {
                println!(
                    "Transfer complete: {file_name} ({mib:.0} MiB) in {:.1}s \
                     ({throughput:.0} MiB/s end-to-end). Hash verified.",
                    elapsed.as_secs_f64(),
                );
            }
        }
        ReceiverMessage::Error { message, .. } => bail!("receiver error: {message}"),
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
                    if idx < total_chunks {
                        Some(idx)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        })
        .collect()
}

/// Return the set of FEC stripe indices where every real data chunk is already
/// present at the receiver.  Only complete stripes can safely be skipped —
/// partial stripes must be resent because the receiver may have discarded
/// incomplete stripe buffers on restart.
fn complete_fec_stripes(bits: &[u64], total_chunks: u64, data_shards: usize) -> HashSet<u32> {
    let total_stripes = total_chunks.div_ceil(data_shards as u64) as u32;
    let mut skip = HashSet::new();
    for s in 0..total_stripes {
        let start = s as u64 * data_shards as u64;
        let end = (start + data_shards as u64).min(total_chunks);
        let complete = (start..end).all(|idx| {
            let word = (idx / 64) as usize;
            let bit = idx % 64;
            word < bits.len() && (bits[word] >> bit) & 1 != 0
        });
        if complete {
            skip.insert(s);
        }
    }
    skip
}

/// Read a contiguous range of chunks [range_start, range_end) from disk and
/// push them to the shared MPMC work channel.
///
/// Designed to run in `spawn_blocking`.  Multiple instances cover disjoint
/// ranges in parallel — useful on high-queue-depth NVMe where a single
/// sequential reader cannot saturate the drive.  Uses `POSIX_FADV_SEQUENTIAL`
/// scoped to each reader's byte range so the kernel pre-fetches only the
/// relevant region.
fn feed_chunks_range(
    path: &Path,
    file_size: u64,
    chunk_size: usize,
    skip: &HashSet<u64>,
    tx: ac::Sender<(u64, Vec<u8>)>,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let byte_start = range_start * chunk_size as u64;
        let byte_len = (range_end * chunk_size as u64).min(file_size) - byte_start;
        unsafe {
            libc::posix_fadvise(
                file.as_raw_fd(),
                byte_start as i64,
                byte_len as i64,
                libc::POSIX_FADV_SEQUENTIAL,
            );
        }
    }

    for idx in range_start..range_end {
        if skip.contains(&idx) {
            continue;
        }
        let offset = idx * chunk_size as u64;
        let len = (chunk_size as u64).min(file_size - offset) as usize;
        let mut raw = vec![0u8; len];
        crate::fs_ext::read_exact_at(&file, &mut raw, offset)
            .with_context(|| format!("read chunk {idx}"))?;
        if tx.send_blocking((idx, raw)).is_err() {
            break;
        }
    }
    Ok(())
}

// ── Recursive directory support ───────────────────────────────────────────────

/// Threshold below which a file's contents are pre-read into memory during
/// directory scan.  Pre-reading small files avoids `open()`/`close()` overhead
/// for every chunk that spans many tiny files.
const PREREAD_THRESHOLD: u64 = 256 * 1024; // 256 KiB

/// Walk `root` and return a sorted list of `FileEntry` items representing the
/// complete directory tree.  Symlinks are preserved (not followed).
/// Files ≥ 1 entry and ≤ PREREAD_THRESHOLD are flagged for pre-reading by the
/// caller.
pub(crate) fn scan_directory(root: &Path, preserve: bool) -> Result<Vec<FileEntry>> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use walkdir::WalkDir;

    let mut entries: Vec<FileEntry> = Vec::new();

    for dent in WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
    {
        let dent = dent.with_context(|| format!("walk {}", root.display()))?;
        let rel = dent
            .path()
            .strip_prefix(root)
            .context("walkdir path prefix strip")?;

        if rel.as_os_str().is_empty() {
            // skip the root itself
            continue;
        }

        // Build relative path with forward slashes (relative to the transfer root,
        // no root-name prefix — the receiver joins output_dir/file_name/path).
        let path = rel.to_string_lossy().replace('\\', "/");

        let ft = dent.file_type();
        let meta = dent
            .metadata()
            .with_context(|| format!("stat {}", dent.path().display()))?;

        let (mode, mtime) = if preserve {
            #[cfg(unix)]
            let m = (meta.mode(), meta.mtime());
            #[cfg(not(unix))]
            let m = (0u32, 0i64);
            m
        } else {
            (0u32, 0i64)
        };

        if ft.is_symlink() {
            let target = std::fs::read_link(dent.path())
                .with_context(|| format!("readlink {}", dent.path().display()))?
                .to_string_lossy()
                .replace('\\', "/");
            entries.push(FileEntry {
                path,
                size: 0,
                kind: FileKind::Symlink { target },
                mode,
                mtime,
            });
        } else if ft.is_dir() {
            entries.push(FileEntry {
                path,
                size: 0,
                kind: FileKind::Directory,
                mode,
                mtime,
            });
        } else if ft.is_file() {
            entries.push(FileEntry {
                path,
                size: meta.len(),
                kind: FileKind::File,
                mode,
                mtime,
            });
        } else {
            warn!("skipping {}: unsupported file type {:?}", path, ft);
        }
    }

    // Stable sort: walkdir already sorts within each directory level, but a
    // re-sort at the top level ensures fully deterministic ordering across
    // platforms regardless of walkdir version behaviour.
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(entries)
}

/// Compute the total bytes contributed by `FileKind::File` entries.
pub(crate) fn total_file_bytes(entries: &[FileEntry]) -> u64 {
    entries
        .iter()
        .filter(|e| matches!(e.kind, FileKind::File))
        .map(|e| e.size)
        .sum()
}

/// Derive a deterministic `transfer_id` for a directory transfer.
///
/// Hashes the root name, total bytes, chunk_size, and the full path+size list
/// of all `FileKind::File` entries so that resume keys off the exact tree shape.
fn directory_transfer_id(
    root_name: &str,
    total_bytes: u64,
    chunk_size: usize,
    entries: &[FileEntry],
) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(root_name.as_bytes());
    h.update(&total_bytes.to_le_bytes());
    h.update(&(chunk_size as u64).to_le_bytes());
    for e in entries {
        if matches!(e.kind, FileKind::File) {
            h.update(e.path.as_bytes());
            h.update(&e.size.to_le_bytes());
        }
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.finalize().as_bytes()[..16]);
    id
}

/// Read file entries into the per-chunk feeder channel, treating all File
/// entries as a single virtual concatenated byte stream.
///
/// Small files (≤ PREREAD_THRESHOLD) are pre-read into memory up front so the
/// inner loop only does memory copies for them, avoiding repeated `open()`
/// overhead when a single chunk spans many tiny files.
///
/// Designed to run in `tokio::task::spawn_blocking`.
fn feed_chunks_concat(
    root: &Path,
    entries: &[FileEntry],
    total_bytes: u64,
    chunk_size: usize,
    skip: &HashSet<u64>,
    tx: ac::Sender<(u64, Vec<u8>)>,
) -> Result<()> {
    // Collect only File entries that have size > 0.
    let file_entries: Vec<&FileEntry> = entries
        .iter()
        .filter(|e| matches!(e.kind, FileKind::File) && e.size > 0)
        .collect();

    // Pre-read small files into memory.
    let preread: Vec<Option<Vec<u8>>> = file_entries
        .iter()
        .map(|e| {
            if e.size <= PREREAD_THRESHOLD {
                let path = root.join(&e.path);
                std::fs::read(&path)
                    .with_context(|| format!("pre-read {}", path.display()))
                    .ok()
            } else {
                None
            }
        })
        .collect();

    // Build prefix sums over file sizes.
    let mut prefix_sums: Vec<u64> = Vec::with_capacity(file_entries.len() + 1);
    let mut acc = 0u64;
    for e in &file_entries {
        prefix_sums.push(acc);
        acc += e.size;
    }
    prefix_sums.push(acc); // sentinel = total_bytes

    let total_chunks = total_bytes.div_ceil(chunk_size as u64);

    // Keep one open large-file handle to avoid repeated open/close when
    // many consecutive chunks land in the same large file.
    let mut cur_large: Option<(usize, std::fs::File)> = None;

    for idx in 0..total_chunks {
        if skip.contains(&idx) {
            continue;
        }

        let global_start = idx * chunk_size as u64;
        let global_end = (global_start + chunk_size as u64).min(total_bytes);
        let chunk_len = (global_end - global_start) as usize;
        let mut buf = vec![0u8; chunk_len];

        let mut written = 0usize;
        // Find the first file index whose range overlaps [global_start, global_end).
        let mut fi = prefix_sums
            .partition_point(|&ps| ps <= global_start)
            .saturating_sub(1);
        let mut pos = global_start;

        while written < chunk_len && fi < file_entries.len() {
            let file_start = prefix_sums[fi];
            let file_end = prefix_sums[fi + 1];
            let offset_in_file = pos - file_start;
            let remaining_in_file = (file_end - pos) as usize;
            let take = remaining_in_file.min(chunk_len - written);

            if let Some(ref data) = preread[fi] {
                // Small file: copy from pre-read buffer.
                let src_start = offset_in_file as usize;
                buf[written..written + take].copy_from_slice(&data[src_start..src_start + take]);
            } else {
                // Large file: use cached handle or open new one.
                let file = match &cur_large {
                    Some((open_fi, _)) if *open_fi == fi => {
                        cur_large.as_ref().map(|(_, f)| f).unwrap()
                    }
                    _ => {
                        let path = root.join(&file_entries[fi].path);
                        let f = std::fs::File::open(&path)
                            .with_context(|| format!("open {}", path.display()))?;

                        #[cfg(target_os = "linux")]
                        {
                            use std::os::unix::io::AsRawFd;
                            unsafe {
                                libc::posix_fadvise(
                                    f.as_raw_fd(),
                                    0,
                                    0,
                                    libc::POSIX_FADV_SEQUENTIAL,
                                );
                            }
                        }

                        cur_large = Some((fi, f));
                        cur_large.as_ref().map(|(_, f)| f).unwrap()
                    }
                };
                crate::fs_ext::read_exact_at(
                    file,
                    &mut buf[written..written + take],
                    offset_in_file,
                )
                .with_context(|| format!("read file[{fi}] at {offset_in_file}"))?;
            }

            written += take;
            pos += take as u64;
            fi += 1;
        }

        if tx.send_blocking((idx, buf)).is_err() {
            break; // workers closed — abort cleanly
        }
    }

    Ok(())
}

/// Fill `buf` with one global chunk from a concatenated directory source.
///
/// The inverse of the inner loop in [`feed_chunks_concat`]: given the global
/// byte offset where the chunk starts, walk the prefix-sum table to find the
/// file(s) the chunk spans and read each overlapping slice in turn.  Used by
/// the in-band repair path to re-read a chunk by its global index without the
/// feeder's pre-read cache (repair handles only a bounded handful of chunks).
fn read_concat_chunk_into(
    root: &Path,
    file_entries: &[&FileEntry],
    prefix_sums: &[u64],
    global_start: u64,
    buf: &mut [u8],
) -> Result<()> {
    let chunk_len = buf.len();
    let mut written = 0usize;
    let mut fi = prefix_sums
        .partition_point(|&ps| ps <= global_start)
        .saturating_sub(1);
    let mut pos = global_start;

    while written < chunk_len && fi < file_entries.len() {
        let file_start = prefix_sums[fi];
        let file_end = prefix_sums[fi + 1];
        let offset_in_file = pos - file_start;
        let remaining_in_file = (file_end - pos) as usize;
        let take = remaining_in_file.min(chunk_len - written);
        let path = root.join(&file_entries[fi].path);
        let f = std::fs::File::open(&path)
            .with_context(|| format!("open {} for repair", path.display()))?;
        crate::fs_ext::read_exact_at(&f, &mut buf[written..written + take], offset_in_file)
            .with_context(|| format!("repair read {} at {offset_in_file}", path.display()))?;
        written += take;
        pos += take as u64;
        fi += 1;
    }

    if written != chunk_len {
        bail!("repair: short read filling chunk at offset {global_start}: {written}/{chunk_len} bytes");
    }
    Ok(())
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

// ── FEC sender path ───────────────────────────────────────────────────────────

/// Simple FEC worker: drain pre-encoded `FecChunkData` from the channel and
/// write each frame to the stream.  All CPU work (compress + RS encode) is
/// already done by the `stripe_encode_chunks` blocking task.
async fn send_fec_from_channel<W>(
    writer: &mut W,
    mut rx: tokio::sync::mpsc::Receiver<FecChunkData>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    while let Some(fcd) = rx.recv().await {
        framing::send_fec_chunk_data(writer, &fcd).await?;
        debug!(
            chunk = fcd.chunk_index,
            parity = fcd.is_parity,
            "sent FEC shard"
        );
    }
    Ok(())
}

/// Sequential file reader for the FEC pipeline.
///
/// Sends all chunks (no resume skipping) to a single channel that feeds the
/// `stripe_encode_chunks` blocking task.  Designed to run in `spawn_blocking`.
///
/// `skip_stripes` is the set of stripe indices whose real data chunks are
/// fully present at the receiver — those chunks are skipped here and the
/// stripe encoder derives the correct stripe index from the first chunk index
/// in each batch rather than relying on a local counter.
fn feed_chunks_single(
    path: &Path,
    file_size: u64,
    chunk_size: usize,
    data_shards: usize,
    skip_stripes: &HashSet<u32>,
    tx: tokio::sync::mpsc::Sender<(u64, Vec<u8>)>,
) -> Result<()> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
    }

    let total_chunks = file_size.div_ceil(chunk_size as u64);
    for idx in 0..total_chunks {
        if !skip_stripes.is_empty() {
            let stripe = (idx / data_shards as u64) as u32;
            if skip_stripes.contains(&stripe) {
                continue;
            }
        }
        let offset = idx * chunk_size as u64;
        let len = (chunk_size as u64).min(file_size - offset) as usize;
        let mut raw = vec![0u8; len];
        crate::fs_ext::read_exact_at(&file, &mut raw, offset)
            .with_context(|| format!("read chunk {idx}"))?;
        if tx.blocking_send((idx, raw)).is_err() {
            break; // encoder side dropped (failed) — feeder exits cleanly
        }
    }
    Ok(())
}

/// Compress + hash + RS-encode a full stripe, then dispatch data and parity
/// `FecChunkData` items round-robin to the per-worker channels.
///
/// `buf` must have exactly `encoder.data_shards` entries.  Entries at indices
/// `[real_count..data_shards)` are synthetic zeros (last-stripe padding) and
/// are used for RS parity computation but **not** dispatched as data shards.
#[allow(clippy::too_many_arguments)]
fn encode_and_dispatch(
    buf: Vec<(u64, Vec<u8>)>,
    real_count: usize,
    encoder: &FecEncoder,
    compression: &Compression,
    transfer_id: [u8; 16],
    stripe_index: u32,
    worker_txs: &[tokio::sync::mpsc::Sender<FecChunkData>],
    worker_i: &mut usize,
    n: usize,
    file_hasher: Option<&Arc<ChunkHasher>>,
    stats: &CompressionStats,
) -> Result<()> {
    let data_shards = encoder.data_shards;
    let parity_shards = encoder.parity_shards;

    // Step 1: compress each shard and hash real ones.  `buf` is consumed so each
    // raw chunk moves straight into the compressor (no 8 MiB clone per shard).
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(data_shards);
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(data_shards);
    let mut comp_flags: Vec<bool> = Vec::with_capacity(data_shards);
    let mut real_chunk_indices: Vec<u64> = Vec::with_capacity(real_count);

    for (i, (chunk_idx, raw)) in buf.into_iter().enumerate() {
        let hash = *blake3::hash(&raw).as_bytes();
        let raw_len = raw.len();
        // Feed real chunk hashes into the file hasher inline (fresh transfers only;
        // on resume the full-file hash is computed by a separate concurrent task).
        if i < real_count {
            if let Some(h) = file_hasher {
                h.feed(chunk_idx, hash)?;
            }
            real_chunk_indices.push(chunk_idx);
        }
        let (payload, comp) = maybe_compress(raw, compression)?;
        // Accumulate compression stats for real shards only (padding shards are
        // synthetic zeros and would distort the ratio).
        if i < real_count {
            stats.0.fetch_add(raw_len as u64, AtomicOrd::Relaxed);
            stats.1.fetch_add(payload.len() as u64, AtomicOrd::Relaxed);
        }
        hashes.push(hash);
        payloads.push(payload);
        comp_flags.push(comp);
    }

    // Step 2: RS encode.  This clone is unavoidable: the encoder pads its inputs
    // to stripe_max in place and returns only the parity shards, but we still
    // need the originals (at their unpadded length) to dispatch as data shards.
    let (parity, shard_lengths) = encoder.encode(payloads.clone())?;
    let shard_compressed: Vec<u8> = comp_flags.iter().map(|&c| c as u8).collect();

    // Step 3: dispatch real data shards, moving each payload out of `payloads`
    // (the padding shards at the tail are dropped here).
    for (i, payload) in payloads.into_iter().enumerate().take(real_count) {
        let fcd = FecChunkData {
            transfer_id,
            chunk_index: real_chunk_indices[i],
            chunk_hash: hashes[i],
            compressed: comp_flags[i],
            stripe_index,
            shard_index_in_stripe: i as u16,
            is_parity: false,
            shard_lengths: Vec::new(),
            shard_compressed: Vec::new(),
            payload,
        };
        if worker_txs[*worker_i].blocking_send(fcd).is_err() {
            bail!("FEC worker channel closed prematurely");
        }
        *worker_i = (*worker_i + 1) % n;
    }

    // Step 4: dispatch parity shards (all, even for partial last stripe).
    for (j, parity_shard) in parity.iter().enumerate().take(parity_shards) {
        let parity_hash = *blake3::hash(parity_shard).as_bytes();
        let fcd = FecChunkData {
            transfer_id,
            chunk_index: stripe_index as u64 * (data_shards + parity_shards) as u64
                + data_shards as u64
                + j as u64,
            chunk_hash: parity_hash,
            compressed: false,
            stripe_index,
            shard_index_in_stripe: data_shards as u16 + j as u16,
            is_parity: true,
            shard_lengths: shard_lengths.clone(),
            shard_compressed: shard_compressed.clone(),
            payload: parity_shard.clone(),
        };
        if worker_txs[*worker_i].blocking_send(fcd).is_err() {
            bail!("FEC worker channel closed prematurely");
        }
        *worker_i = (*worker_i + 1) % n;
    }

    Ok(())
}

/// Blocking task: reads raw chunks from the feeder channel, groups them into
/// stripes of `data_shards`, RS-encodes parity, and dispatches `FecChunkData`
/// to the per-worker channels.
///
/// Runs on Tokio's blocking thread pool so RS computation never stalls the
/// async executor (which would delay QUIC ACK processing at high RTT).
fn stripe_encode_chunks(
    mut chunk_rx: tokio::sync::mpsc::Receiver<(u64, Vec<u8>)>,
    fec_params: FecParams,
    compression: Compression,
    transfer_id: [u8; 16],
    file_hasher: Option<Arc<ChunkHasher>>,
    worker_txs: Vec<tokio::sync::mpsc::Sender<FecChunkData>>,
    stats: CompressionStats,
) -> Result<()> {
    let encoder = FecEncoder::new(fec_params.data_shards, fec_params.parity_shards)?;
    let data_shards = fec_params.data_shards;
    let n = worker_txs.len();
    let mut worker_i = 0usize;

    // Accumulate `data_shards` chunks per stripe before encoding.
    let mut buf: Vec<(u64, Vec<u8>)> = Vec::with_capacity(data_shards);

    while let Some(item) = chunk_rx.blocking_recv() {
        buf.push(item);
        if buf.len() == data_shards {
            // Derive the stripe index from the first chunk index in the batch.
            // This is correct even when preceding stripes were skipped on resume —
            // a sequential counter would give wrong indices in that case.
            let stripe_index = (buf[0].0 / data_shards as u64) as u32;
            // Hand ownership of the full stripe to the encoder and start a fresh
            // buffer for the next one (so raw chunks need not be cloned downstream).
            let stripe = std::mem::replace(&mut buf, Vec::with_capacity(data_shards));
            encode_and_dispatch(
                stripe,
                data_shards, // all real
                &encoder,
                &compression,
                transfer_id,
                stripe_index,
                &worker_txs,
                &mut worker_i,
                n,
                file_hasher.as_ref(),
                &stats,
            )?;
        }
    }

    // Flush the last partial stripe (file size not a multiple of data_shards * chunk_size).
    if !buf.is_empty() {
        let real_count = buf.len();
        let stripe_index = (buf[0].0 / data_shards as u64) as u32;
        // Pad with synthetic zero-length entries so RS sees `data_shards` shards.
        // The encoder pads empty payloads to stripe_max with zeros — identical to
        // what the receiver will pre-fill for these virtual shard positions.
        while buf.len() < data_shards {
            buf.push((u64::MAX, Vec::new())); // sentinel chunk_index; empty payload
        }
        encode_and_dispatch(
            buf,
            real_count,
            &encoder,
            &compression,
            transfer_id,
            stripe_index,
            &worker_txs,
            &mut worker_i,
            n,
            file_hasher.as_ref(),
            &stats,
        )?;
    }

    Ok(())
}

/// Core FEC transfer logic, analogous to `run_transfer` for the non-FEC path.
///
/// Key differences from `run_transfer`:
/// - Sends all chunks regardless of receiver resume state (FEC v1 does not
///   resume mid-stripe; the receiver's file hash check will catch any gap).
/// - Uses a two-stage pipeline: feeder → stripe_encoder → workers.
///   All compression and RS encoding happens in the stripe_encoder blocking task;
///   workers only frame and send pre-built `FecChunkData` items.
/// - File hash is collected inline by the stripe encoder (no second disk pass).
#[allow(clippy::too_many_arguments)]
async fn run_transfer_fec<CW, CR, F, Fut>(
    file: &Path,
    file_size: u64,
    ctrl_send: &mut CW,
    mut ctrl_recv: CR,
    rtt: Duration,
    sender_cores: u32,
    receiver_cores: u32,
    config: &SendConfig,
    // Already pipelined by the QUIC caller (FEC is QUIC-only) in the same flight
    // as NegotiateRequest + DirEntries — saving a control round-trip.
    manifest: TransferManifest,
    spawn_worker: F,
) -> Result<()>
where
    CW: AsyncWrite + Unpin,
    CR: AsyncRead + Unpin + Send + 'static,
    F: Fn(tokio::sync::mpsc::Receiver<FecChunkData>, [u8; 16]) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let fec_params = manifest
        .fec
        .clone()
        .expect("run_transfer_fec requires FEC params in the manifest");
    let compression = if config.compress {
        Compression::Zstd {
            level: config.compress_level,
        }
    } else {
        Compression::None
    };

    let chunk_size = manifest.chunk_size;
    let transfer_id = manifest.transfer_id;
    let total_chunks = manifest.total_chunks;
    let num_streams = manifest.num_streams;
    let file_name = manifest.file_name.clone();
    tracing::info!(
        streams = num_streams,
        chunk_mib = chunk_size / (1024 * 1024),
        fec_data = fec_params.data_shards,
        fec_parity = fec_params.parity_shards,
        rtt_ms = rtt.as_secs_f64() * 1000.0,
        sender_cores,
        receiver_cores,
        "negotiated transfer parameters"
    );

    let compress_stats = new_compression_stats();

    // Receive Ready — check which stripes the receiver already has complete.
    let ready: ReceiverMessage = framing::recv_data_message(&mut ctrl_recv)
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream closed before Ready message"))?;
    let skip_stripes: HashSet<u32> = match ready {
        ReceiverMessage::Ready {
            received_bits,
            total_chunks: tc,
        } => {
            let s = complete_fec_stripes(&received_bits, tc, fec_params.data_shards);
            let skipped_chunks = s.len() as u64 * fec_params.data_shards as u64;
            let remaining_chunks = total_chunks.saturating_sub(skipped_chunks);
            info!(
                "{} complete stripes ({skipped_chunks} chunks) already at receiver, \
                 {} chunks to send",
                s.len(),
                remaining_chunks
            );
            s
        }
        ReceiverMessage::Error { message, .. } => bail!("receiver error: {message}"),
        other => bail!("unexpected message from receiver: {other:?}"),
    };

    // For a fresh transfer hash inline via the stripe encoder — no extra disk pass.
    // On resume we must also hash skipped chunks, so fall back to a concurrent
    // full-file read (same strategy as the non-FEC path).
    let file_hasher: Option<Arc<ChunkHasher>> = if skip_stripes.is_empty() {
        Some(Arc::new(ChunkHasher::new(total_chunks, num_streams)))
    } else {
        None
    };
    let hash_task = if skip_stripes.is_empty() {
        None
    } else {
        let path = file.to_owned();
        Some(tokio::task::spawn_blocking(move || {
            hash_file_sync(&path, chunk_size)
        }))
    };

    let chunk_mib = chunk_size / (1024 * 1024);
    let pb = make_progress_bar(&file_name, file_size, num_streams, chunk_mib, None);
    let transfer_start = Instant::now();
    let pb_for_reader = pb.clone();
    // mpsc (not oneshot): the reader forwards Retransmit requests non-terminally
    // and keeps reading until a terminal Complete/Error arrives.
    let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel::<ReceiverMessage>(4);
    let max_in_flight = num_streams as u32 * 4;
    let reader = tokio::spawn(async move {
        let mut flash_until: Option<std::time::Instant> = None;
        let mut saturated_run = 0u32;
        let mut last_disk_warn = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(30))
            .unwrap_or_else(std::time::Instant::now);
        loop {
            match framing::recv_message::<_, ReceiverMessage>(&mut ctrl_recv).await {
                Ok(Some(ReceiverMessage::Progress {
                    bytes_written,
                    in_flight_chunks,
                    disk_stall_ms,
                })) => {
                    pb_for_reader.set_position(bytes_written);

                    // Revert flash message if its display window has elapsed.
                    if flash_until.is_some_and(|d| std::time::Instant::now() >= d) {
                        pb_for_reader.set_message("");
                        flash_until = None;
                    }

                    if in_flight_chunks >= max_in_flight * 3 / 4 {
                        saturated_run += 1;
                        if saturated_run == 3 {
                            tracing::info!(
                                in_flight = in_flight_chunks,
                                max = max_in_flight,
                                "receiver saturated: chunk processing cannot keep up with network"
                            );
                            pb_for_reader.set_message("⚠ receiver saturated".to_string());
                            flash_until =
                                Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
                        }
                    } else {
                        if saturated_run >= 3 {
                            tracing::info!("receiver saturation cleared");
                            pb_for_reader.set_message("✓ saturation cleared".to_string());
                            flash_until =
                                Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
                        }
                        saturated_run = 0;
                    }

                    if disk_stall_ms > 50
                        && last_disk_warn.elapsed() >= std::time::Duration::from_secs(10)
                    {
                        tracing::info!(
                            disk_stall_ms,
                            "receiver disk stall: writes are taking longer than 50 ms"
                        );
                        last_disk_warn = std::time::Instant::now();
                    }
                }
                Ok(Some(other)) => {
                    // Retransmit is non-terminal: forward it and keep reading so
                    // the next Complete/Error after the repair round is seen too.
                    let terminal = !matches!(other, ReceiverMessage::Retransmit { .. });
                    if completion_tx.send(other).await.is_err() {
                        return;
                    }
                    if terminal {
                        return;
                    }
                }
                _ => return,
            }
        }
    });

    // Feeder → stripe encoder channel; depth allows a stripe ahead.
    const FEEDER_CHAN_DEPTH: usize = 16;
    const WORKER_CHAN_DEPTH: usize = 4;
    let actual_streams = num_streams.min(total_chunks.max(1) as usize);

    let (feeder_tx, feeder_rx) = tokio::sync::mpsc::channel::<(u64, Vec<u8>)>(FEEDER_CHAN_DEPTH);

    let mut worker_txs: Vec<tokio::sync::mpsc::Sender<FecChunkData>> = Vec::new();
    let mut worker_rxs: Vec<tokio::sync::mpsc::Receiver<FecChunkData>> = Vec::new();
    for _ in 0..actual_streams {
        let (tx, rx) = tokio::sync::mpsc::channel(WORKER_CHAN_DEPTH);
        worker_txs.push(tx);
        worker_rxs.push(rx);
    }

    // Feeder: sequential file read → feeder channel.
    let feeder = {
        let path = file.to_owned();
        let data_shards = fec_params.data_shards;
        let skip = skip_stripes.clone();
        tokio::task::spawn_blocking(move || {
            feed_chunks_single(&path, file_size, chunk_size, data_shards, &skip, feeder_tx)
        })
    };

    // Stripe encoder: read from feeder, RS encode, dispatch FecChunkData to workers.
    let fec_params_clone = fec_params.clone();
    let compression_clone = compression.clone();
    let hasher_for_encoder = file_hasher.clone();
    let stats_for_encoder = (Arc::clone(&compress_stats.0), Arc::clone(&compress_stats.1));
    let encoder_task = tokio::task::spawn_blocking(move || {
        stripe_encode_chunks(
            feeder_rx,
            fec_params_clone,
            compression_clone,
            transfer_id,
            hasher_for_encoder,
            worker_txs,
            stats_for_encoder,
        )
    });

    // Spawn N QUIC stream workers.
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for rx in worker_rxs {
        tasks.spawn(spawn_worker(rx, transfer_id));
    }
    while let Some(res) = tasks.join_next().await {
        match res? {
            Ok(()) => {}
            // B1 (FEC): a single stream stopped — receiver will use FEC parity
            // to reconstruct any affected stripes.  Let remaining streams finish.
            Err(e) if is_stream_stopped_by_peer(&e) => {
                warn!(
                    error = format!("{e:#}"),
                    "FEC stream stopped by receiver; receiver will attempt FEC recovery"
                );
            }
            Err(e) => return Err(e),
        }
    }

    // Ensure encoder and feeder finished cleanly.
    encoder_task
        .await
        .context("stripe encoder task panicked")??;
    feeder.await.context("feeder task panicked")??;

    pb.set_message("verifying…");

    let file_hash: [u8; 32] = match file_hasher {
        Some(h) => Arc::try_unwrap(h)
            .expect("all encoder tasks finished; no other Arc<ChunkHasher> references remain")
            .finish()?,
        None => hash_task
            .expect("resume path always spawns hash_task")
            .await
            .context("hash task panicked")??,
    };
    framing::send_message(ctrl_send, &SenderMessage::Complete { file_hash }).await?;

    // Completion handshake with v5 incremental repair.  FEC transfers are always
    // single-file, so `entries` is None here; a stripe the receiver could not
    // reconstruct comes back as a Retransmit and is repaired in-band.
    let msg = await_completion_with_repair(
        ctrl_send,
        &mut completion_rx,
        file,
        file_size,
        chunk_size,
        transfer_id,
        &compression,
        file_hash,
        rtt,
        None,
        &pb,
    )
    .await?;
    reader.await.ok();
    pb.finish_and_clear();
    print_completion(
        msg,
        &file_name,
        file_size,
        file_hash,
        transfer_start,
        &compress_stats,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio::sync::{mpsc, Semaphore};

    /// Regression test for the late-scaling end-of-transfer deadlock.
    ///
    /// Reproduces the ordering where the final worker exits while a scale-up is
    /// still in flight.  The fixed loop terminates on `active_workers == 0`; the
    /// buggy version (termination checked only in the worker-join arm, gated on a
    /// since-removed `pending_scale`) blocked forever on `scale_rx` with no
    /// workers left to join.
    #[tokio::test]
    async fn dispatch_loop_terminates_when_worker_drains_during_scale_up() {
        // Workers are gated on this semaphore so they cannot finish until we
        // release them — guaranteeing the scale-up Target is processed first.
        let sem = Arc::new(Semaphore::new(0));
        let mut tasks: JoinSet<Result<()>> = JoinSet::new();
        {
            let sem = sem.clone();
            tasks.spawn(async move {
                let _p = sem.acquire().await.unwrap();
                Ok(())
            });
        }

        // Keep the tx ends alive for the whole test so the channels stay open
        // (a closed scale_rx would let even the buggy loop fall through).
        let (_ea_tx, mut ea_rx) = mpsc::channel::<String>(1);
        let (scale_tx, mut scale_rx) = mpsc::channel::<ScaleMsg>(8);
        let current = AtomicUsize::new(1);
        let excess = AtomicUsize::new(0);
        let hasher: Option<Arc<ChunkHasher>> = None;
        let mut sink = tokio::io::sink();

        // Queue a scale-up Target (1 → 2); deliberately send NO Ack.  After the
        // workers drain, a correct loop breaks on active_workers == 0.
        scale_tx.send(ScaleMsg::Target(2)).await.unwrap();

        // Scale-up spawner: adds another gated worker.
        let spawn_one = {
            let sem = sem.clone();
            move |ts: &mut JoinSet<Result<()>>| {
                let sem = sem.clone();
                ts.spawn(async move {
                    let _p = sem.acquire().await.unwrap();
                    Ok(())
                });
            }
        };

        let loop_fut = run_dispatch_loop(
            &mut tasks,
            1,
            &mut sink,
            &mut ea_rx,
            &mut scale_rx,
            &current,
            &excess,
            &hasher,
            false,
            spawn_one,
        );

        // Let the loop process the Target (spawning worker #2), then release both
        // workers.  The fixed loop returns; the buggy one hangs on scale_rx.
        let driver = async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            sem.add_permits(2);
            std::future::pending::<()>().await
        };

        let outcome = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                r = loop_fut => r,
                _ = driver => unreachable!("driver future never resolves"),
            }
        })
        .await;

        // scale_tx stays alive until here so scale_rx never closes.
        let _keep_tx = &scale_tx;

        outcome
            .expect("run_dispatch_loop deadlocked after a late scale-up (regression)")
            .expect("run_dispatch_loop returned an error");
    }
}
