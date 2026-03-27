//! Receiver-side transfer orchestration. See `transfer/mod.rs` for the full flow.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::io::AsyncRead;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::compress;
use crate::net::connection::make_server_endpoint;
use crate::protocol::{
    framing,
    messages::{
        ChunkData, NegotiateRequest, NegotiateResponse, ReceiverMessage, SenderMessage,
        TransferManifest,
    },
};
use crate::transfer::hash::ChunkHasher;
use crate::transfer::resume::ResumeState;

pub struct ReceiveConfig {
    pub output_dir: PathBuf,
}

// ── QUIC server ───────────────────────────────────────────────────────────────

/// A bound QUIC server endpoint, ready to accept incoming transfers.
///
/// Separating bind from serve lets callers (and tests) inspect `local_addr`
/// and `fingerprint` before starting the accept loop.
pub struct Server {
    endpoint: quinn::Endpoint,
    /// The actual bound address — useful when binding on port 0.
    pub local_addr: SocketAddr,
    /// Hex SHA-256 fingerprint of the server's self-signed certificate.
    /// Pass this to the sender's `--trust` flag for non-interactive use.
    pub fingerprint: String,
    output_dir: PathBuf,
}

impl Server {
    pub fn bind(addr: SocketAddr, output_dir: PathBuf) -> Result<Self> {
        let (endpoint, fingerprint) = make_server_endpoint(addr)?;
        let local_addr = endpoint.local_addr()?;
        Ok(Self { endpoint, local_addr, fingerprint, output_dir })
    }

    /// Accept and handle exactly one incoming connection, then return.
    /// Intended for integration tests; production code should use `serve`.
    pub async fn accept_one(&self) -> Result<()> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("endpoint closed before any connection arrived"))?;
        let conn = incoming.await.context("connection setup failed")?;
        info!("connection from {}", conn.remote_address());
        handle_quic_connection(conn, self.output_dir.clone()).await
    }

    /// Accept and handle connections indefinitely.
    pub async fn serve(self) -> Result<()> {
        println!("Listening on {}", self.local_addr);
        println!(
            "Certificate fingerprint (share with sender --trust):\n  {}",
            self.fingerprint
        );
        while let Some(incoming) = self.endpoint.accept().await {
            let out = self.output_dir.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        info!("connection from {}", conn.remote_address());
                        if let Err(e) = handle_quic_connection(conn, out).await {
                            tracing::error!("transfer error: {e:#}");
                        }
                    }
                    Err(e) => warn!("incoming connection failed: {e}"),
                }
            });
        }
        Ok(())
    }
}

/// Convenience wrapper for the CLI; binds and serves indefinitely.
pub async fn listen(bind: SocketAddr, config: ReceiveConfig) -> Result<()> {
    Server::bind(bind, config.output_dir)?.serve().await
}

// ── TCP server ────────────────────────────────────────────────────────────────

/// A bound TCP server, ready to accept incoming transfers.
///
/// TCP mode is intended for trusted LAN / same-datacenter transfers where the
/// lower per-packet overhead of kernel TCP outweighs QUIC's features.
/// There is no TLS — do not use over untrusted networks.
///
/// Transfers are served sequentially (one at a time) because the protocol
/// uses connection ordering to assign data streams to the active transfer.
pub struct TcpServer {
    listener: Arc<TcpListener>,
    /// The actual bound address — useful when binding on port 0.
    pub local_addr: SocketAddr,
    output_dir: PathBuf,
}

impl TcpServer {
    pub async fn bind(addr: SocketAddr, output_dir: PathBuf) -> Result<Self> {
        let (listener, local_addr) = crate::net::tcp::bind_tcp(addr).await?;
        Ok(Self { listener: Arc::new(listener), local_addr, output_dir })
    }

    /// Accept and handle exactly one incoming transfer (control + data streams), then return.
    /// Intended for integration tests.
    pub async fn accept_one(&self) -> Result<()> {
        let (ctrl_stream, peer_addr) = self.listener.accept().await?;
        ctrl_stream.set_nodelay(true)?;
        info!("TCP connection from {peer_addr}");
        // Clone the Arc so handle_tcp_connection owns it — avoids a self-referential
        // future that would make this async fn non-Send.
        handle_tcp_connection(ctrl_stream, Arc::clone(&self.listener), self.output_dir.clone())
            .await
    }

    /// Accept and handle transfers sequentially, indefinitely.
    pub async fn serve(self) -> Result<()> {
        println!("Listening on {} (TCP mode, no TLS)", self.local_addr);
        loop {
            let (ctrl_stream, peer_addr) = self.listener.accept().await?;
            ctrl_stream.set_nodelay(true)?;
            info!("TCP connection from {peer_addr}");
            if let Err(e) = handle_tcp_connection(
                ctrl_stream,
                Arc::clone(&self.listener),
                self.output_dir.clone(),
            )
            .await
            {
                tracing::error!("transfer error: {e:#}");
            }
        }
    }
}

/// Convenience wrapper for the CLI; binds and serves indefinitely.
pub async fn listen_tcp(bind: SocketAddr, config: ReceiveConfig) -> Result<()> {
    TcpServer::bind(bind, config.output_dir).await?.serve().await
}

// ── Per-connection logic: QUIC ────────────────────────────────────────────────

async fn handle_quic_connection(conn: quinn::Connection, output_dir: PathBuf) -> Result<()> {
    // Keep conn alive until the end so we can call conn.closed() before dropping it.
    // ── Negotiation ───────────────────────────────────────────────────────────
    let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;

    let neg_req: NegotiateRequest =
        framing::recv_message_required(&mut ctrl_recv).await?;
    let receiver_cores =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;
    framing::send_message(
        &mut ctrl_send,
        &NegotiateResponse { cpu_cores: receiver_cores },
    )
    .await?;
    debug!(
        sender_cores = neg_req.cpu_cores,
        receiver_cores,
        file_size = neg_req.file_size,
        "negotiation complete"
    );

    // ── Manifest ──────────────────────────────────────────────────────────────
    let manifest: TransferManifest =
        framing::recv_message_required(&mut ctrl_recv).await?;

    validate_manifest(&manifest)?;

    info!(
        file = %manifest.file_name,
        size = manifest.file_size,
        chunks = manifest.total_chunks,
        streams = manifest.num_streams,
        "transfer started"
    );

    let (out_file, resume, pb, hasher, bytes_already_received) =
        prepare_transfer(&manifest, &output_dir)?;

    let have_chunks = resume.lock().unwrap().received_chunks();
    framing::send_message(&mut ctrl_send, &ReceiverMessage::Ready { have_chunks }).await?;
    pb.set_position(bytes_already_received);

    // ── Accept exactly num_streams unidirectional data streams ────────────────
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..manifest.num_streams {
        let stream = conn.accept_uni().await.context("accept data stream")?;
        let out_file = out_file.clone();
        let resume = resume.clone();
        let manifest = manifest.clone();
        let pb = pb.clone();
        let hasher = hasher.clone();
        tasks.spawn(async move {
            recv_stream_worker(stream, out_file, resume, manifest, pb, hasher).await
        });
    }

    let task_err = drain_tasks(&mut tasks, &mut ctrl_send).await;
    pb.finish();
    if let Some(e) = task_err {
        bail!("{e}");
    }

    finish_transfer(
        &mut ctrl_send,
        &mut ctrl_recv,
        resume,
        hasher,
        &output_dir,
        &manifest,
    )
    .await?;

    let _ = ctrl_send.finish();
    // Wait for the sender to close the connection before we drop `conn`.
    let _ = conn.closed().await;
    Ok(())
}

// ── Per-connection logic: TCP ─────────────────────────────────────────────────

async fn handle_tcp_connection(
    ctrl_stream: tokio::net::TcpStream,
    listener: Arc<TcpListener>,
    output_dir: PathBuf,
) -> Result<()> {
    let (mut ctrl_recv, mut ctrl_send) = ctrl_stream.into_split();

    // ── Negotiation ───────────────────────────────────────────────────────────
    let neg_req: NegotiateRequest =
        framing::recv_message_required(&mut ctrl_recv).await?;
    let receiver_cores =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;
    framing::send_message(
        &mut ctrl_send,
        &NegotiateResponse { cpu_cores: receiver_cores },
    )
    .await?;
    debug!(
        sender_cores = neg_req.cpu_cores,
        receiver_cores,
        file_size = neg_req.file_size,
        "negotiation complete"
    );

    // ── Manifest ──────────────────────────────────────────────────────────────
    let manifest: TransferManifest =
        framing::recv_message_required(&mut ctrl_recv).await?;

    validate_manifest(&manifest)?;

    info!(
        file = %manifest.file_name,
        size = manifest.file_size,
        chunks = manifest.total_chunks,
        streams = manifest.num_streams,
        "transfer started"
    );

    let (out_file, resume, pb, hasher, bytes_already_received) =
        prepare_transfer(&manifest, &output_dir)?;

    let have_chunks = { resume.lock().unwrap().received_chunks() };
    framing::send_message(&mut ctrl_send, &ReceiverMessage::Ready { have_chunks }).await?;
    pb.set_position(bytes_already_received);

    // ── Accept exactly num_streams data connections ───────────────────────────
    // The sender connects in order after receiving Ready; we accept them here.
    // Sequential serve guarantees no other transfers compete for connections.
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..manifest.num_streams {
        let (data_stream, _peer) = listener.accept().await.context("accept data stream")?;
        data_stream.set_nodelay(true)?;
        let (read_half, _write_half) = data_stream.into_split();
        let out_file = out_file.clone();
        let resume = resume.clone();
        let manifest = manifest.clone();
        let pb = pb.clone();
        let hasher = hasher.clone();
        tasks.spawn(async move {
            recv_stream_worker(read_half, out_file, resume, manifest, pb, hasher).await
        });
    }

    let task_err = drain_tasks(&mut tasks, &mut ctrl_send).await;
    pb.finish();
    if let Some(e) = task_err {
        bail!("{e}");
    }

    finish_transfer(
        &mut ctrl_send,
        &mut ctrl_recv,
        resume,
        hasher,
        &output_dir,
        &manifest,
    )
    .await?;

    Ok(())
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Set up the output file, resume state, progress bar, and chunk hasher.
/// Returns them along with the number of bytes already on disk (for progress).
#[allow(clippy::type_complexity)]
fn prepare_transfer(
    manifest: &TransferManifest,
    output_dir: &std::path::Path,
) -> Result<(Arc<std::fs::File>, Arc<Mutex<ResumeState>>, Arc<ProgressBar>, Arc<ChunkHasher>, u64)>
{
    let resume = Arc::new(Mutex::new(ResumeState::load_or_new(
        output_dir,
        &manifest.transfer_id,
        manifest.total_chunks,
    )));
    let have_chunks = resume.lock().unwrap().received_chunks();
    let bytes_already_received: u64 = have_chunks
        .iter()
        .map(|&i| {
            let offset = i * manifest.chunk_size as u64;
            ((manifest.file_size - offset) as usize).min(manifest.chunk_size) as u64
        })
        .sum();

    let out_path = output_dir.join(&manifest.file_name);
    let out_file = Arc::new({
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false) // we size the file explicitly via fallocate/set_len below
            .open(&out_path)
            .with_context(|| format!("open output {}", out_path.display()))?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe {
                libc::fallocate(f.as_raw_fd(), 0, 0, manifest.file_size as libc::off_t)
            };
            if rc != 0 {
                f.set_len(manifest.file_size)?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        f.set_len(manifest.file_size)?;
        f
    });

    let pb = Arc::new({
        let pb = ProgressBar::new(manifest.file_size);
        pb.set_style(
            ProgressStyle::with_template(
                "[recv] {spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} \
                 {bytes}/{total_bytes} {bytes_per_sec} eta {eta}",
            )
            .unwrap(),
        );
        pb
    });

    let hasher = Arc::new(ChunkHasher::new(manifest.total_chunks));

    Ok((out_file, resume, pb, hasher, bytes_already_received))
}

/// Drain all stream-worker tasks; on first error notify the sender.
/// Returns the first error encountered, if any.
async fn drain_tasks<S>(
    tasks: &mut JoinSet<Result<()>>,
    ctrl_send: &mut S,
) -> Option<anyhow::Error>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let mut task_err: Option<anyhow::Error> = None;
    while let Some(join_res) = tasks.join_next().await {
        let task_result = match join_res {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!("stream worker panicked: {e}")),
        };
        if let Err(e) = task_result {
            if task_err.is_none() {
                let _ = framing::send_message(
                    ctrl_send,
                    &ReceiverMessage::Error { message: e.to_string() },
                )
                .await;
                task_err = Some(e);
            }
        }
    }
    task_err
}

/// Check completeness, verify file hash, send Complete to sender.
async fn finish_transfer<S, R>(
    ctrl_send: &mut S,
    ctrl_recv: &mut R,
    resume: Arc<Mutex<ResumeState>>,
    hasher: Arc<ChunkHasher>,
    output_dir: &std::path::Path,
    manifest: &TransferManifest,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    let missing = resume.lock().unwrap().missing_chunks();
    if !missing.is_empty() {
        warn!("{} chunks missing, requesting retransmit", missing.len());
        framing::send_message(
            ctrl_send,
            &ReceiverMessage::Retransmit { chunk_indices: missing },
        )
        .await?;
        bail!("transfer incomplete; retransmit requested");
    }

    let file_hash = Arc::try_unwrap(hasher)
        .expect("all stream tasks finished so no other Arc references exist")
        .finish()?;

    let expected_hash = match framing::recv_message_required(ctrl_recv).await? {
        SenderMessage::Complete { file_hash } => file_hash,
    };

    if file_hash != expected_hash {
        framing::send_message(
            ctrl_send,
            &ReceiverMessage::Error { message: "file hash mismatch".into() },
        )
        .await?;
        bail!("file hash mismatch — file is corrupted");
    }

    framing::send_message(ctrl_send, &ReceiverMessage::Complete { file_hash }).await?;

    resume.lock().unwrap().delete()?;
    println!("Received: {}", output_dir.join(&manifest.file_name).display());
    Ok(())
}

// ── Stream worker (generic over any AsyncRead) ────────────────────────────────

async fn recv_stream_worker<R>(
    mut stream: R,
    out_file: Arc<std::fs::File>,
    resume: Arc<Mutex<ResumeState>>,
    manifest: TransferManifest,
    pb: Arc<ProgressBar>,
    hasher: Arc<ChunkHasher>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    // Pipelined processing: keep up to MAX_IN_FLIGHT blocking tasks running
    // concurrently per stream.  While one chunk is being SHA-256 verified and
    // written to disk, the next chunk arrives over the network — overlapping
    // CPU/disk with network receive.  On a fast LAN this is the difference
    // between network being idle half the time and being fully utilised.
    const MAX_IN_FLIGHT: usize = 4;
    let mut processing: JoinSet<Result<()>> = JoinSet::new();

    loop {
        // Before receiving the next chunk, drain any completed tasks and
        // propagate errors early.  When at the pipeline limit, wait for a
        // slot to free up.
        if processing.len() >= MAX_IN_FLIGHT {
            match processing.join_next().await {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(e))) => return Err(e),
                Some(Err(e)) => bail!("chunk processing task panicked: {e}"),
                None => {}
            }
        }

        let chunk: ChunkData = match framing::recv_data_message(&mut stream).await? {
            Some(c) => c,
            None => break, // sender closed the stream — normal end
        };

        // Reject out-of-range chunk indices before doing any work with them.
        if chunk.chunk_index >= manifest.total_chunks {
            bail!(
                "chunk index {} out of range (total_chunks {})",
                chunk.chunk_index,
                manifest.total_chunks
            );
        }

        let chunk_index = chunk.chunk_index;
        let chunk_size = manifest.chunk_size;
        let out_file = Arc::clone(&out_file);
        let hasher = Arc::clone(&hasher);
        let resume = Arc::clone(&resume);
        let pb = Arc::clone(&pb);

        processing.spawn_blocking(move || -> Result<()> {
            let computed: [u8; 32] = Sha256::digest(&chunk.payload).into();
            if computed != chunk.chunk_hash {
                bail!("chunk {chunk_index} hash mismatch");
            }

            let data = if chunk.compressed {
                compress::decompress_chunk(&chunk.payload, chunk_size)?
            } else {
                chunk.payload
            };

            let offset = chunk_index * chunk_size as u64;
            {
                use std::os::unix::fs::FileExt;
                out_file
                    .write_all_at(&data, offset)
                    .with_context(|| format!("write chunk {chunk_index} at offset {offset}"))?;
            }

            hasher.feed(chunk_index, &data);
            pb.inc(data.len() as u64);
            resume.lock().unwrap().mark_received(chunk_index);
            debug!(chunk = chunk_index, "received");
            Ok(())
        });
    }

    // Drain all remaining in-flight tasks.
    while let Some(res) = processing.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => bail!("chunk processing task panicked: {e}"),
        }
    }

    Ok(())
}

// ── Manifest validation ───────────────────────────────────────────────────────

/// Maximum file size we are willing to accept (16 TiB).
const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024;
/// Chunk size must be between 4 KiB and 128 MiB.
const MIN_CHUNK_SIZE: usize = 4 * 1024;
const MAX_CHUNK_SIZE: usize = 128 * 1024 * 1024;
/// Sanity cap on stream count to prevent an accept loop that never ends.
const MAX_STREAMS: usize = 1024;

fn validate_manifest(m: &crate::protocol::messages::TransferManifest) -> Result<()> {
    if m.file_name.is_empty() {
        bail!("manifest: file_name is empty");
    }
    if m.file_name.contains('/') || m.file_name.contains('\\') {
        bail!("manifest: file_name contains path separator: {:?}", m.file_name);
    }
    if m.file_name == ".." || m.file_name == "." {
        bail!("manifest: file_name is a relative-path component: {:?}", m.file_name);
    }

    if m.file_size > MAX_FILE_SIZE {
        bail!(
            "manifest: file_size {} exceeds limit of {} bytes",
            m.file_size,
            MAX_FILE_SIZE
        );
    }

    if m.chunk_size < MIN_CHUNK_SIZE || m.chunk_size > MAX_CHUNK_SIZE {
        bail!(
            "manifest: chunk_size {} out of allowed range [{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}]",
            m.chunk_size
        );
    }

    let expected = m.file_size.div_ceil(m.chunk_size as u64);
    if m.total_chunks != expected {
        bail!(
            "manifest: total_chunks {} inconsistent with file_size {}/chunk_size {} (expected {})",
            m.total_chunks,
            m.file_size,
            m.chunk_size,
            expected
        );
    }

    if m.num_streams == 0 || m.num_streams > MAX_STREAMS {
        bail!(
            "manifest: num_streams {} out of allowed range [1, {MAX_STREAMS}]",
            m.num_streams
        );
    }

    Ok(())
}
