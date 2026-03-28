//! Receiver-side transfer orchestration. See `transfer/mod.rs` for the full flow.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::io::AsyncRead;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::compress;
use crate::net::connection::{
    cert_fingerprint, generate_self_signed_cert, make_private_key, make_server_endpoint,
};
use crate::net::tcp::{ServerTlsStream, make_tls_acceptor};
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
pub struct Server {
    endpoint: quinn::Endpoint,
    pub local_addr: SocketAddr,
    pub fingerprint: String,
    output_dir: PathBuf,
}

impl Server {
    pub fn bind(addr: SocketAddr, output_dir: PathBuf) -> Result<Self> {
        let (endpoint, fingerprint) = make_server_endpoint(addr)?;
        let local_addr = endpoint.local_addr()?;
        Ok(Self { endpoint, local_addr, fingerprint, output_dir })
    }

    /// Build from a pre-generated certificate so QUIC and TCP can share one cert.
    pub fn bind_with_cert(
        addr: SocketAddr,
        output_dir: PathBuf,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        fingerprint: String,
    ) -> Result<Self> {
        use crate::net::connection::{make_server_endpoint_with_cert};
        let endpoint = make_server_endpoint_with_cert(addr, cert, key)?;
        let local_addr = endpoint.local_addr()?;
        Ok(Self { endpoint, local_addr, fingerprint, output_dir })
    }

    /// Accept and handle exactly one incoming connection, then return.
    /// Intended for integration tests.
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

    /// Accept and handle connections indefinitely (QUIC only; use `listen` for auto mode).
    pub async fn serve(self) -> Result<()> {
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

// ── TCP+TLS server ────────────────────────────────────────────────────────────

/// A bound TCP+TLS server, ready to accept incoming transfers.
///
/// Uses the same self-signed-certificate / TOFU model as QUIC so the
/// fingerprint can be shared across both transports.  Transfers are served
/// sequentially (one at a time) — connection ordering is used to assign data
/// streams without an extra protocol header.
pub struct TcpServer {
    listener: Arc<TcpListener>,
    acceptor: Arc<TlsAcceptor>,
    pub local_addr: SocketAddr,
    pub fingerprint: String,
    output_dir: PathBuf,
}

impl TcpServer {
    /// Bind and generate a fresh self-signed certificate.
    pub async fn bind(addr: SocketAddr, output_dir: PathBuf) -> Result<Self> {
        let (cert, key_bytes) = generate_self_signed_cert()?;
        let fingerprint = cert_fingerprint(&cert);
        let key = make_private_key(key_bytes)?;
        Self::bind_with_cert(addr, output_dir, cert, key, fingerprint).await
    }

    /// Bind using a pre-generated certificate (for sharing with the QUIC server).
    pub async fn bind_with_cert(
        addr: SocketAddr,
        output_dir: PathBuf,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        fingerprint: String,
    ) -> Result<Self> {
        let (listener, local_addr) = crate::net::tcp::bind_tcp(addr).await?;
        let acceptor = Arc::new(make_tls_acceptor(cert, key)?);
        Ok(Self { listener: Arc::new(listener), acceptor, local_addr, fingerprint, output_dir })
    }

    /// Accept and handle exactly one complete transfer (control + data streams), then return.
    /// Intended for integration tests.
    pub async fn accept_one(&self) -> Result<()> {
        let (raw, peer_addr) = self.listener.accept().await?;
        raw.set_nodelay(true)?;
        info!("TCP connection from {peer_addr}");
        let tls = Arc::clone(&self.acceptor)
            .accept(raw)
            .await
            .context("TLS handshake on control stream")?;
        handle_tcp_connection(tls, Arc::clone(&self.listener), Arc::clone(&self.acceptor), self.output_dir.clone()).await
    }

    /// Accept and handle transfers sequentially, indefinitely.
    pub async fn serve(self) -> Result<()> {
        loop {
            let (raw, peer_addr) = self.listener.accept().await?;
            raw.set_nodelay(true)?;
            info!("TCP connection from {peer_addr}");
            let tls = match Arc::clone(&self.acceptor).accept(raw).await {
                Ok(s) => s,
                Err(e) => { warn!("TLS handshake failed from {peer_addr}: {e}"); continue; }
            };
            if let Err(e) = handle_tcp_connection(
                tls,
                Arc::clone(&self.listener),
                Arc::clone(&self.acceptor),
                self.output_dir.clone(),
            ).await {
                tracing::error!("transfer error: {e:#}");
            }
        }
    }
}

// ── Public listen functions ───────────────────────────────────────────────────

/// Bind and serve both QUIC and TCP+TLS on the same port using one shared certificate.
///
/// The sender auto-detects which transport is available: it tries QUIC first
/// (with a short timeout) and falls back to TCP+TLS if UDP is blocked.
pub async fn listen(bind: SocketAddr, config: ReceiveConfig) -> Result<()> {
    // Generate one cert — used by both QUIC and TCP so the fingerprint is the same.
    let (cert, key_bytes) = generate_self_signed_cert()?;
    let fingerprint = cert_fingerprint(&cert);

    let quic_key = make_private_key(key_bytes.clone())?;
    let tcp_key = make_private_key(key_bytes)?;

    let quic_server =
        Server::bind_with_cert(bind, config.output_dir.clone(), cert.clone(), quic_key, fingerprint.clone())?;
    let tcp_server =
        TcpServer::bind_with_cert(bind, config.output_dir, cert, tcp_key, fingerprint.clone()).await?;

    println!("Listening on {} (QUIC + TCP+TLS, auto-fallback)", quic_server.local_addr);
    println!("Certificate fingerprint (share with sender --trust):\n  {fingerprint}");

    tokio::try_join!(quic_server.serve(), tcp_server.serve())?;
    Ok(())
}

/// Bind and serve TCP+TLS only (explicit `--tcp` mode).
pub async fn listen_tcp(bind: SocketAddr, config: ReceiveConfig) -> Result<()> {
    let server = TcpServer::bind(bind, config.output_dir).await?;
    println!("Listening on {} (TCP+TLS)", server.local_addr);
    println!("Certificate fingerprint (share with sender --trust):\n  {}", server.fingerprint);
    server.serve().await
}

/// Bind on a random port, write a JSON handshake to stdout for the SSH
/// launcher to read, accept exactly one transfer (QUIC or TCP+TLS), then exit.
///
/// Both transports are offered on the same port number so the sender's
/// auto-fallback (QUIC → TCP+TLS) works without any extra configuration.
pub async fn serve_one_stdio(output_dir: PathBuf) -> Result<()> {
    use std::net::SocketAddr;

    let (cert, key_bytes) = generate_self_signed_cert()?;
    let fingerprint = cert_fingerprint(&cert);

    let quic_key = make_private_key(key_bytes.clone())?;
    let tcp_key = make_private_key(key_bytes)?;

    // Bind QUIC on a random UDP port, then reuse that port number for TCP.
    // UDP and TCP port spaces are independent, so this always works.
    let quic_server = Server::bind_with_cert(
        "0.0.0.0:0".parse::<SocketAddr>()?,
        output_dir.clone(),
        cert.clone(),
        quic_key,
        fingerprint.clone(),
    )?;
    let port = quic_server.local_addr.port();
    let tcp_server = TcpServer::bind_with_cert(
        format!("0.0.0.0:{port}").parse::<SocketAddr>()?,
        output_dir,
        cert,
        tcp_key,
        fingerprint.clone(),
    )
    .await?;

    // Machine-readable handshake — the SSH launcher reads exactly this line.
    println!("{{\"port\":{port},\"fingerprint\":\"{fingerprint}\"}}");

    // Race QUIC and TCP.  If the QUIC connection is immediately closed by the
    // sender with the "switching to tcp" sentinel (RTT-based LAN detection),
    // fall through to accept the follow-up TCP+TLS connection instead of
    // exiting — the TCP listener is still bound and waiting.
    tokio::select! {
        res = quic_server.accept_one() => {
            match res {
                Ok(()) => Ok(()),
                Err(e) if e.is::<SwitchToTcp>() => tcp_server.accept_one().await,
                Err(e) => Err(e),
            }
        }
        res = tcp_server.accept_one() => res,
    }
}

// ── Per-connection logic: QUIC ────────────────────────────────────────────────

/// Returned when the sender probed RTT over QUIC and then closed the connection
/// to switch to TCP+TLS.  `serve_one_stdio` catches this and falls through to
/// the TCP server instead of treating it as a real error.
#[derive(Debug)]
struct SwitchToTcp;
impl std::fmt::Display for SwitchToTcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sender is switching to TCP+TLS")
    }
}
impl std::error::Error for SwitchToTcp {}

async fn handle_quic_connection(conn: quinn::Connection, output_dir: PathBuf) -> Result<()> {
    let (mut ctrl_send, mut ctrl_recv) = match conn.accept_bi().await {
        Ok(s) => s,
        // Sender connected only to measure RTT, found it was within the LAN
        // threshold, and closed the connection to retry over TCP+TLS.
        Err(quinn::ConnectionError::ApplicationClosed(close))
            if close.error_code.into_inner() == 0
                && close.reason.as_ref() == b"switching to tcp" =>
        {
            return Err(anyhow::Error::new(SwitchToTcp));
        }
        Err(e) => return Err(e.into()),
    };

    let neg_req: NegotiateRequest = framing::recv_message_required(&mut ctrl_recv).await?;
    let receiver_cores =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;
    framing::send_message(&mut ctrl_send, &NegotiateResponse { cpu_cores: receiver_cores }).await?;
    debug!(sender_cores = neg_req.cpu_cores, receiver_cores, "negotiation complete");

    let manifest: TransferManifest = framing::recv_message_required(&mut ctrl_recv).await?;
    validate_manifest(&manifest)?;
    info!(file = %manifest.file_name, size = manifest.file_size, chunks = manifest.total_chunks, streams = manifest.num_streams, "transfer started");

    let (out_file, resume, pb, hasher, bytes_already_received) =
        prepare_transfer(&manifest, &output_dir)?;

    let have_chunks = { resume.lock().unwrap().received_chunks() };
    framing::send_message(&mut ctrl_send, &ReceiverMessage::Ready { have_chunks }).await?;
    pb.set_position(bytes_already_received);

    // Progress channel: data workers → reporter → ctrl_send (throttled to 100 ms).
    let (progress_tx, progress_rx) = tokio::sync::mpsc::channel::<u64>(256);

    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..manifest.num_streams {
        let stream = conn.accept_uni().await.context("accept data stream")?;
        let out_file = out_file.clone();
        let resume = resume.clone();
        let manifest = manifest.clone();
        let pb = pb.clone();
        let hasher = hasher.clone();
        let progress_tx = progress_tx.clone();
        tasks.spawn(async move {
            recv_stream_worker(stream, out_file, resume, manifest, pb, hasher, progress_tx).await
        });
    }
    // Drop the original sender so the channel closes when all workers finish.
    drop(progress_tx);

    // Reporter owns ctrl_send and sends throttled Progress messages to the sender.
    // It runs concurrently with the data workers and returns ctrl_send when done.
    let reporter = tokio::spawn(progress_reporter(ctrl_send, progress_rx, bytes_already_received));

    let task_err = drain_tasks(&mut tasks).await;
    pb.finish();

    let mut ctrl_send = reporter.await.context("progress reporter panicked")??;

    if let Some(e) = task_err {
        let _ = framing::send_message(
            &mut ctrl_send,
            &ReceiverMessage::Error { message: e.to_string() },
        ).await;
        bail!("{e}");
    }

    finish_transfer(&mut ctrl_send, &mut ctrl_recv, resume, hasher, &output_dir, &manifest).await?;

    let _ = ctrl_send.finish();
    let _ = conn.closed().await;
    Ok(())
}

// ── Per-connection logic: TCP+TLS ─────────────────────────────────────────────

async fn handle_tcp_connection(
    ctrl_stream: ServerTlsStream<tokio::net::TcpStream>,
    listener: Arc<TcpListener>,
    acceptor: Arc<TlsAcceptor>,
    output_dir: PathBuf,
) -> Result<()> {
    let (mut ctrl_recv, mut ctrl_send) = tokio::io::split(ctrl_stream);

    let neg_req: NegotiateRequest = framing::recv_message_required(&mut ctrl_recv).await?;
    let receiver_cores =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;
    framing::send_message(&mut ctrl_send, &NegotiateResponse { cpu_cores: receiver_cores }).await?;
    debug!(sender_cores = neg_req.cpu_cores, receiver_cores, "negotiation complete");

    let manifest: TransferManifest = framing::recv_message_required(&mut ctrl_recv).await?;
    validate_manifest(&manifest)?;
    info!(file = %manifest.file_name, size = manifest.file_size, chunks = manifest.total_chunks, streams = manifest.num_streams, "transfer started");

    let (out_file, resume, pb, hasher, bytes_already_received) =
        prepare_transfer(&manifest, &output_dir)?;

    let have_chunks = { resume.lock().unwrap().received_chunks() };
    framing::send_message(&mut ctrl_send, &ReceiverMessage::Ready { have_chunks }).await?;
    pb.set_position(bytes_already_received);

    let (progress_tx, progress_rx) = tokio::sync::mpsc::channel::<u64>(256);

    // Accept exactly num_streams TLS-wrapped data connections.
    // The sender opens them in order after receiving Ready; sequential serve
    // guarantees no other transfer competes for these connections.
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..manifest.num_streams {
        let (raw, _peer) = listener.accept().await.context("accept data stream")?;
        raw.set_nodelay(true)?;
        // Pass the full TLS stream (no split): data streams are read-only, and
        // keeping the stream whole avoids split-half interactions in the TLS
        // state machine.
        let data_tls = acceptor.accept(raw).await.context("TLS handshake on data stream")?;
        let out_file = out_file.clone();
        let resume = resume.clone();
        let manifest = manifest.clone();
        let pb = pb.clone();
        let hasher = hasher.clone();
        let progress_tx = progress_tx.clone();
        tasks.spawn(async move {
            recv_stream_worker(data_tls, out_file, resume, manifest, pb, hasher, progress_tx).await
        });
    }
    drop(progress_tx);

    let reporter = tokio::spawn(progress_reporter(ctrl_send, progress_rx, bytes_already_received));

    let task_err = drain_tasks(&mut tasks).await;
    pb.finish();

    let mut ctrl_send = reporter.await.context("progress reporter panicked")??;

    if let Some(e) = task_err {
        let _ = framing::send_message(
            &mut ctrl_send,
            &ReceiverMessage::Error { message: e.to_string() },
        ).await;
        bail!("{e}");
    }

    finish_transfer(&mut ctrl_send, &mut ctrl_recv, resume, hasher, &output_dir, &manifest).await?;
    Ok(())
}

// ── Shared helpers ────────────────────────────────────────────────────────────

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
            .truncate(false) // sized explicitly via fallocate/set_len below
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

async fn drain_tasks(tasks: &mut JoinSet<Result<()>>) -> Option<anyhow::Error> {
    let mut task_err: Option<anyhow::Error> = None;
    while let Some(join_res) = tasks.join_next().await {
        let task_result = match join_res {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!("stream worker panicked: {e}")),
        };
        if let Err(e) = task_result {
            if task_err.is_none() {
                task_err = Some(e);
            }
        }
    }
    task_err
}

/// Receives confirmed-written byte counts from data workers and sends
/// throttled `ReceiverMessage::Progress` updates on the control stream.
///
/// Takes ownership of `ctrl_send` and returns it when the channel closes
/// (i.e. when all data workers have finished), so the caller can use it
/// for the final `ReceiverMessage::Complete` / `Error` exchange.
async fn progress_reporter<W>(
    mut ctrl_send: W,
    mut rx: tokio::sync::mpsc::Receiver<u64>,
    initial_bytes: u64,
) -> Result<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut bytes_written = initial_bytes;
    let mut last_reported = initial_bytes;
    let report_interval = Duration::from_millis(100);
    let mut next_report = tokio::time::Instant::now() + report_interval;

    loop {
        tokio::select! {
            n = rx.recv() => {
                match n {
                    Some(n) => bytes_written += n,
                    None => break, // all workers finished, channel closed
                }
            }
            _ = tokio::time::sleep_until(next_report) => {
                if bytes_written != last_reported {
                    framing::send_message(
                        &mut ctrl_send,
                        &ReceiverMessage::Progress { bytes_written },
                    ).await?;
                    last_reported = bytes_written;
                }
                next_report = tokio::time::Instant::now() + report_interval;
            }
        }
    }

    // Final update to make sure the sender sees 100%.
    if bytes_written != last_reported {
        framing::send_message(
            &mut ctrl_send,
            &ReceiverMessage::Progress { bytes_written },
        ).await?;
    }

    Ok(ctrl_send)
}

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
    progress_tx: tokio::sync::mpsc::Sender<u64>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    const MAX_IN_FLIGHT: usize = 4;
    let mut processing: JoinSet<Result<()>> = JoinSet::new();
    let mut chunk_count = 0u64;

    loop {
        if processing.len() >= MAX_IN_FLIGHT {
            match processing.join_next().await {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(e))) => return Err(e),
                Some(Err(e)) => bail!("chunk processing task panicked: {e}"),
                None => {}
            }
        }

        let chunk: ChunkData = match framing::recv_data_message(&mut stream).await
            .with_context(|| format!("recv chunk#{chunk_count}"))? {
            Some(c) => c,
            None => break,
        };

        if chunk.chunk_index >= manifest.total_chunks {
            bail!(
                "chunk index {} out of range (total_chunks {})",
                chunk.chunk_index,
                manifest.total_chunks
            );
        }
        if chunk.transfer_id != manifest.transfer_id {
            bail!(
                "chunk {}: transfer_id mismatch (got {}, expected {})",
                chunk.chunk_index,
                hex::encode(chunk.transfer_id),
                hex::encode(manifest.transfer_id),
            );
        }

        let chunk_index = chunk.chunk_index;
        let chunk_size = manifest.chunk_size;
        let out_file = Arc::clone(&out_file);
        let hasher = Arc::clone(&hasher);
        let resume = Arc::clone(&resume);
        let pb = Arc::clone(&pb);
        let progress_tx = progress_tx.clone();

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
            let n = data.len() as u64;
            pb.inc(n);
            // Non-blocking: progress updates are best-effort; never slow the data path.
            let _ = progress_tx.try_send(n);
            {
                let mut r = resume.lock().unwrap();
                r.mark_received(chunk_index);
                r.save()?;
            }
            debug!(chunk = chunk_index, "received");
            Ok(())
        });
        chunk_count += 1;
    }

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

const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024;
const MIN_CHUNK_SIZE: usize = 4 * 1024;
const MAX_CHUNK_SIZE: usize = 128 * 1024 * 1024;
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
        bail!("manifest: file_size {} exceeds limit of {} bytes", m.file_size, MAX_FILE_SIZE);
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
            m.total_chunks, m.file_size, m.chunk_size, expected
        );
    }
    if m.num_streams == 0 || m.num_streams > MAX_STREAMS {
        bail!("manifest: num_streams {} out of allowed range [1, {MAX_STREAMS}]", m.num_streams);
    }
    Ok(())
}
