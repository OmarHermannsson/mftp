//! Receiver-side transfer orchestration. See `transfer/mod.rs` for the full flow.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncRead;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::compress;
use crate::fec::codec::FecDecoder;
use crate::net::connection::{
    cert_fingerprint, generate_self_signed_cert, make_private_key, make_server_endpoint,
};
use crate::net::tcp::{make_tls_acceptor, ServerTlsStream};
use crate::protocol::{
    framing,
    messages::{
        ChunkData, DirEntries, FecChunkData, FileEntry, FileKind, NegotiateRequest,
        NegotiateResponse, ReceiverMessage, SenderMessage, TransferManifest, PROTOCOL_VERSION,
    },
};
use crate::transfer::hash::ChunkHasher;
use crate::transfer::resume::{ResumeState, RESUME_SAVE_BATCH};

/// Shared receiver-side metrics updated by data workers and read by the
/// progress reporter every 100 ms.
struct ReceiverStats {
    /// Total chunk-processing tasks currently active across all stream workers.
    /// Each worker holds at most MAX_IN_FLIGHT (4) tasks, so the maximum value
    /// is `num_streams × 4`.  Consistently near the maximum indicates CPU or
    /// disk saturation on the receiver.
    in_flight_chunks: AtomicU32,
    /// Peak chunk-write latency (µs) observed since the last progress report.
    /// Reset to 0 after each read.  Values above ~50 000 µs (50 ms) indicate
    /// disk back-pressure on the receiver.
    last_disk_us: AtomicU32,
}

impl ReceiverStats {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            in_flight_chunks: AtomicU32::new(0),
            last_disk_us: AtomicU32::new(0),
        })
    }
}

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
        Ok(Self {
            endpoint,
            local_addr,
            fingerprint,
            output_dir,
        })
    }

    /// Build from a pre-generated certificate so QUIC and TCP can share one cert.
    pub fn bind_with_cert(
        addr: SocketAddr,
        output_dir: PathBuf,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        fingerprint: String,
    ) -> Result<Self> {
        use crate::net::connection::make_server_endpoint_with_cert;
        let endpoint = make_server_endpoint_with_cert(addr, cert, key)?;
        let local_addr = endpoint.local_addr()?;
        Ok(Self {
            endpoint,
            local_addr,
            fingerprint,
            output_dir,
        })
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
        Ok(Self {
            listener: Arc::new(listener),
            acceptor,
            local_addr,
            fingerprint,
            output_dir,
        })
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
        handle_tcp_connection(
            tls,
            Arc::clone(&self.listener),
            Arc::clone(&self.acceptor),
            self.output_dir.clone(),
        )
        .await
    }

    /// Accept and handle transfers sequentially, indefinitely.
    pub async fn serve(self) -> Result<()> {
        loop {
            let (raw, peer_addr) = self.listener.accept().await?;
            raw.set_nodelay(true)?;
            info!("TCP connection from {peer_addr}");
            let tls = match Arc::clone(&self.acceptor).accept(raw).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("TLS handshake failed from {peer_addr}: {e}");
                    continue;
                }
            };
            if let Err(e) = handle_tcp_connection(
                tls,
                Arc::clone(&self.listener),
                Arc::clone(&self.acceptor),
                self.output_dir.clone(),
            )
            .await
            {
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

    let quic_server = Server::bind_with_cert(
        bind,
        config.output_dir.clone(),
        cert.clone(),
        quic_key,
        fingerprint.clone(),
    )?;
    let tcp_server =
        TcpServer::bind_with_cert(bind, config.output_dir, cert, tcp_key, fingerprint.clone())
            .await?;

    println!(
        "Listening on {} (QUIC + TCP+TLS, auto-fallback)",
        quic_server.local_addr
    );
    println!("Certificate fingerprint (share with sender --trust):\n  {fingerprint}");

    tokio::try_join!(quic_server.serve(), tcp_server.serve())?;
    Ok(())
}

/// Bind and serve TCP+TLS only (explicit `--tcp` mode).
pub async fn listen_tcp(bind: SocketAddr, config: ReceiveConfig) -> Result<()> {
    let server = TcpServer::bind(bind, config.output_dir).await?;
    println!("Listening on {} (TCP+TLS)", server.local_addr);
    println!(
        "Certificate fingerprint (share with sender --trust):\n  {}",
        server.fingerprint
    );
    server.serve().await
}

/// Bind on a given port (or a random one when `port` is `None`), write a JSON
/// handshake to stdout for the SSH launcher to read, accept exactly one
/// transfer (QUIC or TCP+TLS), then exit.
///
/// Both transports are offered on the same port number so the sender's
/// auto-fallback (QUIC → TCP+TLS) works without any extra configuration.
pub async fn serve_one_stdio(output_dir: PathBuf, port: Option<u16>) -> Result<()> {
    use std::net::SocketAddr;

    let (cert, key_bytes) = generate_self_signed_cert()?;
    let fingerprint = cert_fingerprint(&cert);

    let quic_key = make_private_key(key_bytes.clone())?;
    let tcp_key = make_private_key(key_bytes)?;

    let bind_port = port.unwrap_or(0);

    // Bind QUIC on the requested port (0 = random), then reuse that port for TCP.
    // UDP and TCP port spaces are independent, so this always works.
    let quic_server = Server::bind_with_cert(
        format!("0.0.0.0:{bind_port}").parse::<SocketAddr>()?,
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
    //
    // No overall timeout here: in SSH mode the server is launched by the
    // sender and inherits the SSH session.  If the sender is killed, the SSH
    // connection closes and the remote sshd sends SIGHUP to this process,
    // causing it to exit.  The DATA_STREAM_ACCEPT_TIMEOUT inside run_receive
    // handles the case where the sender dies after connecting the control
    // stream but before all data streams are established.
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
    let (ctrl_send, ctrl_recv) = match conn.accept_bi().await {
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

    let conn_for_accept = conn.clone();
    let mut ctrl_send = run_receive(ctrl_send, ctrl_recv, output_dir, move || {
        let conn = conn_for_accept.clone();
        async move {
            let stream = conn.accept_uni().await.context("accept QUIC data stream")?;
            Ok(Box::new(stream) as Box<dyn AsyncRead + Unpin + Send + 'static>)
        }
    })
    .await?;

    // Gracefully close the control stream so the sender sees a clean FIN.
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
    let (ctrl_recv, ctrl_send) = tokio::io::split(ctrl_stream);

    run_receive(ctrl_send, ctrl_recv, output_dir, move || {
        let listener = Arc::clone(&listener);
        let acceptor = Arc::clone(&acceptor);
        async move {
            let (raw, _peer) = listener.accept().await.context("accept TCP data stream")?;
            raw.set_nodelay(true)?;
            let tls = acceptor
                .accept(raw)
                .await
                .context("TLS handshake on data stream")?;
            Ok(Box::new(tls) as Box<dyn AsyncRead + Unpin + Send + 'static>)
        }
    })
    .await?;
    Ok(())
}

// ── FEC stripe accumulator ────────────────────────────────────────────────────

/// Per-stripe shard accumulator used by FEC-enabled transfers.
///
/// Created when the first shard for a stripe arrives; removed from the shared
/// map and processed (written to disk) as soon as `is_ready()` returns true.
struct StripeBuffer {
    stripe_index: u32,
    data_shards: usize,
    parity_shards: usize,
    /// Number of real file chunks in this stripe (`≤ data_shards`; `< data_shards`
    /// only for the last stripe when `total_chunks % data_shards != 0`).
    real_data_count: usize,
    /// Received data shard slots: `(compressed_payload, chunk_hash, compressed_flag)`.
    #[allow(clippy::type_complexity)]
    data: Vec<Option<(Vec<u8>, [u8; 32], bool)>>,
    /// Received parity shard slots (RS-encoded payload at stripe-max length).
    parity: Vec<Option<Vec<u8>>>,
    /// Unpadded compressed length of each data shard; non-empty once any parity
    /// shard arrives.  Needed to trim RS-reconstructed data shards after padding.
    shard_lengths: Option<Vec<u32>>,
    /// Compression flag for each data shard (0=raw, 1=compressed); same source.
    shard_compressed_flags: Option<Vec<u8>>,
    received_data: usize,
    received_parity: usize,
}

impl StripeBuffer {
    fn new(
        stripe_index: u32,
        data_shards: usize,
        parity_shards: usize,
        real_data_count: usize,
    ) -> Self {
        Self {
            stripe_index,
            data_shards,
            parity_shards,
            real_data_count,
            data: vec![None; data_shards],
            parity: vec![None; parity_shards],
            shard_lengths: None,
            shard_compressed_flags: None,
            received_data: 0,
            received_parity: 0,
        }
    }

    fn insert(&mut self, fcd: FecChunkData) -> Result<()> {
        if fcd.is_parity {
            let j = (fcd.shard_index_in_stripe as usize)
                .checked_sub(self.data_shards)
                .with_context(|| {
                    format!(
                        "FEC stripe {}: parity shard_index_in_stripe {} < data_shards {}",
                        self.stripe_index, fcd.shard_index_in_stripe, self.data_shards
                    )
                })?;
            if j >= self.parity_shards {
                bail!(
                    "FEC stripe {}: parity shard index {} out of range",
                    self.stripe_index,
                    j
                );
            }
            if self.parity[j].is_none() {
                self.parity[j] = Some(fcd.payload);
                self.received_parity += 1;
            }
            // All parity shards for the same stripe carry identical metadata;
            // store it once from whichever arrives first.
            if self.shard_lengths.is_none() && !fcd.shard_lengths.is_empty() {
                self.shard_lengths = Some(fcd.shard_lengths);
                self.shard_compressed_flags = Some(fcd.shard_compressed);
            }
        } else {
            let i = fcd.shard_index_in_stripe as usize;
            if i >= self.data_shards {
                bail!(
                    "FEC stripe {}: data shard index {} out of range",
                    self.stripe_index,
                    i
                );
            }
            if self.data[i].is_none() {
                self.data[i] = Some((fcd.payload, fcd.chunk_hash, fcd.compressed));
                self.received_data += 1;
            }
        }
        Ok(())
    }

    /// True when we have enough shards (real data + parity + synthetic zeros) to
    /// reconstruct all real file chunks in this stripe.
    fn is_ready(&self) -> bool {
        self.received_data + self.received_parity >= self.real_data_count
    }
}

/// Decompress, verify, write, and account for one data chunk from a FEC stripe.
///
/// Called from `process_stripe` for both directly received and RS-reconstructed
/// data shards.  `payload` is the possibly-compressed chunk data after any RS
/// trimming.  `expected_hash` is `Some(h)` for directly received shards (verify
/// against `blake3(raw)`), `None` for reconstructed shards (trust RS; file hash
/// catches errors end-to-end).
#[allow(clippy::too_many_arguments)]
fn write_fec_chunk(
    chunk_index: u64,
    payload: &[u8],
    compressed: bool,
    expected_hash: Option<[u8; 32]>,
    chunk_size: usize,
    out_file: &std::fs::File,
    resume: &Mutex<ResumeState>,
    hasher: &Option<Arc<ChunkHasher>>,
    pb: &ProgressBar,
    progress_tx: &tokio::sync::mpsc::Sender<u64>,
) -> Result<()> {
    let data = if compressed {
        compress::decompress_chunk(payload, chunk_size)
            .with_context(|| format!("decompress FEC chunk {chunk_index}"))?
    } else {
        payload.to_vec()
    };

    let computed: [u8; 32] = *blake3::hash(&data).as_bytes();
    if let Some(expected) = expected_hash {
        if computed != expected {
            bail!("FEC chunk {chunk_index}: hash mismatch");
        }
    }

    let offset = chunk_index * chunk_size as u64;
    crate::fs_ext::write_all_at_advise(out_file, &data, offset)
        .with_context(|| format!("write FEC chunk {chunk_index} at offset {offset}"))?;

    if let Some(h) = hasher {
        h.feed(chunk_index, computed)?;
    }
    let n = data.len() as u64;
    pb.inc(n);
    let _ = progress_tx.try_send(n);

    let snap = {
        let mut r = resume.lock().unwrap();
        r.mark_received(chunk_index);
        if r.incr_dirty() >= RESUME_SAVE_BATCH {
            r.reset_dirty();
            Some(r.snapshot()?)
        } else {
            None
        }
    };
    if let Some(snap) = snap {
        snap.write_to_disk()?;
    }

    debug!(chunk = chunk_index, "FEC chunk written");
    Ok(())
}

/// Process a completed stripe: write directly received data shards and use
/// RS reconstruction for any missing ones.
///
/// Designed to run in `spawn_blocking`; all I/O is synchronous.
fn process_stripe(
    stripe: StripeBuffer,
    chunk_size: usize,
    out_file: Arc<std::fs::File>,
    resume: Arc<Mutex<ResumeState>>,
    hasher: Option<Arc<ChunkHasher>>,
    pb: Arc<ProgressBar>,
    progress_tx: tokio::sync::mpsc::Sender<u64>,
) -> Result<()> {
    let data_shards = stripe.data_shards;
    let parity_shards = stripe.parity_shards;
    let real_data_count = stripe.real_data_count;
    let first_chunk = stripe.stripe_index as u64 * data_shards as u64;

    if stripe.received_data == real_data_count && stripe.shard_lengths.is_none() {
        // Happy path: all real data shards arrived; no RS needed.
        for i in 0..real_data_count {
            let (payload, hash, compressed) = stripe.data[i].as_ref().unwrap();
            write_fec_chunk(
                first_chunk + i as u64,
                payload,
                *compressed,
                Some(*hash),
                chunk_size,
                &out_file,
                &resume,
                &hasher,
                &pb,
                &progress_tx,
            )?;
        }
        return Ok(());
    }

    // RS reconstruction path.
    let shard_lengths = stripe.shard_lengths.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "FEC stripe {}: RS reconstruction needed but no parity metadata received",
            stripe.stripe_index
        )
    })?;
    let shard_compressed_flags = stripe.shard_compressed_flags.as_ref().unwrap();
    let stripe_max = shard_lengths.iter().copied().max().unwrap_or(0) as usize;

    // Build the shard array for FecDecoder.
    //   data shards:   Some(padded_to_stripe_max) if received; None if missing.
    //   virtual shards (last stripe only): Some(zeros at stripe_max).
    //   parity shards: Some(payload) or None if missing.
    let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(data_shards + parity_shards);
    for i in 0..data_shards {
        if i >= real_data_count {
            // Synthetic zero shard — known, counted as "present" by FecDecoder.
            shards.push(Some(vec![0u8; stripe_max]));
        } else if let Some((payload, _, _)) = &stripe.data[i] {
            let mut padded = payload.clone();
            padded.resize(stripe_max, 0);
            shards.push(Some(padded));
        } else {
            shards.push(None); // missing; RS will reconstruct
        }
    }
    for j in 0..parity_shards {
        shards.push(stripe.parity[j].clone());
    }

    let decoder = FecDecoder::new(data_shards, parity_shards)?;
    let reconstructed = decoder.reconstruct(shards, shard_lengths)?;

    for i in 0..real_data_count {
        let was_reconstructed = stripe.data[i].is_none();
        let payload = &reconstructed[i]; // already trimmed to shard_lengths[i]
        let compressed = shard_compressed_flags[i] != 0;
        // expected_hash: Some for directly received (verify), None for reconstructed (trust RS).
        let expected_hash = if was_reconstructed {
            None
        } else {
            stripe.data[i].as_ref().map(|(_, h, _)| *h)
        };
        write_fec_chunk(
            first_chunk + i as u64,
            payload,
            compressed,
            expected_hash,
            chunk_size,
            &out_file,
            &resume,
            &hasher,
            &pb,
            &progress_tx,
        )?;
    }

    Ok(())
}

// ── Shared transfer body ──────────────────────────────────────────────────────

/// Core receive logic shared by both the QUIC and TCP paths.
///
/// Handles the full negotiation → manifest → data transfer → verification flow.
/// `accept_stream` is a factory called once per data stream; it must return a
/// future that yields a readable stream (QUIC `RecvStream` or TCP+TLS stream).
///
/// Returns the write half of the control stream so the QUIC caller can send
/// a graceful FIN; TCP callers may discard it.
async fn run_receive<CW, CR, F, Fut>(
    mut ctrl_send: CW,
    mut ctrl_recv: CR,
    output_dir: PathBuf,
    mut accept_stream: F,
) -> Result<CW>
where
    CW: tokio::io::AsyncWrite + Unpin + Send + 'static,
    CR: tokio::io::AsyncRead + Unpin + Send + 'static,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Box<dyn AsyncRead + Unpin + Send + 'static>>> + Send + 'static,
{
    let neg_req: NegotiateRequest = framing::recv_message_required(&mut ctrl_recv).await?;
    let receiver_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4) as u32;
    framing::send_message(
        &mut ctrl_send,
        &NegotiateResponse {
            cpu_cores: receiver_cores,
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await?;
    debug!(
        sender_cores = neg_req.cpu_cores,
        receiver_cores, "negotiation complete"
    );

    // Use the data-frame limit (128 MiB) for the manifest so that large
    // directories (many entries serialized) don't hit the 1 MiB control cap.
    let manifest: TransferManifest = framing::recv_data_message(&mut ctrl_recv)
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream closed before TransferManifest"))?;
    validate_manifest(&manifest)?;

    // Protocol version 3+: read DirEntries immediately after the manifest.
    // v2 senders don't send this message; skip the read for them.
    let dir_entries: Option<Vec<FileEntry>> = if neg_req.protocol_version >= 3 {
        let de: DirEntries = framing::recv_data_message(&mut ctrl_recv)
            .await?
            .ok_or_else(|| anyhow::anyhow!("stream closed before DirEntries"))?;
        validate_dir_entries(&manifest, &de)?;
        de.entries
    } else {
        None
    };

    let entry_count = dir_entries.as_deref().map(|e| {
        e.iter()
            .filter(|en| matches!(en.kind, FileKind::File))
            .count()
    });
    info!(
        file = %manifest.file_name,
        size = manifest.file_size,
        chunks = manifest.total_chunks,
        streams = manifest.num_streams,
        files = ?entry_count,
        "transfer started"
    );

    let pt = match prepare_transfer(&manifest, dir_entries.as_deref(), &output_dir) {
        Ok(pt) => pt,
        Err(e) => {
            // Send the error to the sender before closing so the sender shows
            // the actual filesystem error instead of "connection lost".
            let _ = framing::send_message(
                &mut ctrl_send,
                &ReceiverMessage::Error {
                    message: format!("{e:#}"),
                },
            )
            .await;
            return Err(e);
        }
    };
    framing::send_message(
        &mut ctrl_send,
        &ReceiverMessage::Ready {
            received_bits: pt.received_bits,
            total_chunks: manifest.total_chunks,
        },
    )
    .await?;
    pt.pb.set_position(pt.bytes_already_received);

    // Progress channel: data workers → reporter → ctrl_send (throttled to 100 ms).
    let (progress_tx, progress_rx) = tokio::sync::mpsc::channel::<u64>(256);
    // Keep one extra clone for scale-up workers added during transfer.
    // Dropped after the main loop to let the reporter exit once all workers finish.
    let scale_progress_tx = progress_tx.clone();

    // Ack channel: main loop → reporter → ctrl_send (AdjustStreamsAck messages).
    let (ack_req_tx, ack_req_rx) = tokio::sync::mpsc::channel::<u8>(8);

    // Ctrl-reader channels: ctrl_reader_task forwards SenderMessage variants
    // received during the data phase to the main loop and finish_transfer.
    let (scale_req_tx, mut scale_req_rx) = tokio::sync::mpsc::channel::<u8>(8);
    let (complete_tx, complete_rx) = tokio::sync::oneshot::channel::<[u8; 32]>();

    // Shared metrics: in-flight task count and peak disk latency.
    let stats = ReceiverStats::new();

    // Global semaphore that caps concurrent pwrite operations across all stream
    // workers.  Without this, N streams × MAX_IN_FLIGHT tasks each writing an
    // 8 MiB chunk can generate 256+ MiB of dirty pages simultaneously, causing
    // the kernel to stall pwrite callers while it flushes.  Limiting to 8
    // concurrent writers keeps peak dirty pages at ~64 MiB, well below the
    // kernel's dirty_ratio threshold on typical systems.
    let write_sem = Arc::new(tokio::sync::Semaphore::new(8));

    // Accept all N data streams concurrently.
    //
    // For QUIC this is a no-op difference (QUIC stream opens are instantaneous
    // on an existing connection).  For TCP+TLS it is critical: each stream
    // requires an independent TCP 3-way handshake + TLS 1.3 exchange, which
    // takes roughly 1-2 RTTs.  Accepting them sequentially would serialize all
    // N TLS handshakes; accepting them concurrently lets all N proceed in
    // parallel, cutting setup time from N×RTT down to ~1×RTT regardless of N.
    let mut accept_tasks: JoinSet<Result<Box<dyn AsyncRead + Unpin + Send + 'static>>> =
        JoinSet::new();
    for _ in 0..manifest.num_streams {
        let fut = accept_stream();
        accept_tasks.spawn(async move {
            tokio::time::timeout(DATA_STREAM_ACCEPT_TIMEOUT, fut)
                .await
                .unwrap_or_else(|_| {
                    Err(anyhow!(
                        "timed out waiting for data stream — sender disconnected"
                    ))
                })
        });
    }

    // For FEC transfers, workers share a stripe accumulator map.
    let fec_stripe_bufs: Option<Arc<Mutex<HashMap<u32, StripeBuffer>>>> = if manifest.fec.is_some()
    {
        Some(Arc::new(Mutex::new(HashMap::new())))
    } else {
        None
    };

    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    while let Some(accept_res) = accept_tasks.join_next().await {
        let stream = accept_res.context("accept task panicked")??;
        let out_file = pt.out_file.clone();
        let layout = pt.layout.clone();
        let resume = pt.resume.clone();
        let manifest_c = manifest.clone();
        let pb = pt.pb.clone();
        let hasher = pt.hasher.clone();
        let ptx = progress_tx.clone();
        let st = Arc::clone(&stats);
        let wsem = Arc::clone(&write_sem);
        if let Some(ref bufs_arc) = fec_stripe_bufs {
            // FEC path: always single-file (directory+FEC rejected at sender).
            let fec_file = out_file.expect("FEC requires single-file output");
            let stripe_bufs = Arc::clone(bufs_arc);
            tasks.spawn(async move {
                recv_fec_stream_worker(
                    stream,
                    fec_file,
                    resume,
                    manifest_c,
                    pb,
                    hasher,
                    ptx,
                    stripe_bufs,
                    st,
                    wsem,
                )
                .await
            });
        } else {
            tasks.spawn(async move {
                recv_stream_worker(
                    stream, out_file, layout, resume, manifest_c, pb, hasher, ptx, st, wsem,
                )
                .await
            });
        }
    }
    // Drop the original sender so the reporter exits once all workers (including
    // any dynamically added ones) finish and drop their own senders.
    // `scale_progress_tx` keeps the channel open for scale-up workers.
    drop(progress_tx);

    // Reporter owns ctrl_send and sends throttled Progress messages to the sender.
    // It also forwards AdjustStreamsAck messages from the main loop (ack_req_rx).
    // It runs concurrently with the data workers and returns ctrl_send when done.
    let reporter = tokio::spawn(progress_reporter(
        ctrl_send,
        progress_rx,
        pt.bytes_already_received,
        Arc::clone(&stats),
        ack_req_rx,
    ));

    // Ctrl-reader task: reads SenderMessage from the control stream during the
    // data phase, forwarding AdjustStreams requests and the final Complete.
    // Owns ctrl_recv so framing reads are never cancelled mid-frame.
    tokio::spawn(ctrl_reader_task(ctrl_recv, scale_req_tx, complete_tx));

    // Main transfer loop: drain worker tasks and handle dynamic stream scaling.
    let mut task_err: Option<anyhow::Error> = None;
    let mut active_workers = manifest.num_streams;
    let mut current_workers = manifest.num_streams;

    loop {
        tokio::select! {
            Some(join_res) = tasks.join_next() => {
                let r = join_res.unwrap_or_else(|e| Err(anyhow!("stream worker panicked: {e}")));
                if let Err(e) = r {
                    if task_err.is_none() { task_err = Some(e); }
                }
                active_workers = active_workers.saturating_sub(1);
                if active_workers == 0 { break; }
            }
            Some(target_count) = scale_req_rx.recv(), if fec_stripe_bufs.is_none() => {
                let target = target_count as usize;
                if target > current_workers {
                    // Scale-up: accept new streams and spawn workers.
                    let new_count = target - current_workers;
                    info!(current = current_workers, target, "scaling up: accepting {new_count} new streams");
                    if let Some(ref h) = pt.hasher {
                        h.update_stream_count(target);
                    }
                    let mut accepted = current_workers;
                    for _ in 0..new_count {
                        let fut = accept_stream();
                        match tokio::time::timeout(DATA_STREAM_ACCEPT_TIMEOUT, fut).await {
                            Ok(Ok(stream)) => {
                                let out_file = pt.out_file.clone();
                                let layout = pt.layout.clone();
                                let resume = pt.resume.clone();
                                let manifest_c = manifest.clone();
                                let pb = pt.pb.clone();
                                let hasher = pt.hasher.clone();
                                let ptx = scale_progress_tx.clone();
                                let st = Arc::clone(&stats);
                                let wsem = Arc::clone(&write_sem);
                                tasks.spawn(async move {
                                    recv_stream_worker(
                                        stream, out_file, layout, resume, manifest_c, pb, hasher,
                                        ptx, st, wsem,
                                    )
                                    .await
                                });
                                accepted += 1;
                                active_workers += 1;
                            }
                            Ok(Err(e)) => warn!("failed to accept new data stream: {e:#}"),
                            Err(_) => warn!("timed out accepting new data stream"),
                        }
                    }
                    current_workers = accepted;
                    let _ = ack_req_tx.send(accepted as u8).await;
                } else if target < current_workers {
                    // Scale-down: no stream management needed on the receiver side.
                    // The sender will close excess streams (QUIC FIN / TLS shutdown);
                    // those workers exit when they see EOF, decrementing active_workers
                    // via the tasks.join_next() arm above.
                    info!(
                        current = current_workers,
                        target,
                        "scaling down: sender will close {} streams",
                        current_workers - target
                    );
                    current_workers = target;
                    let _ = ack_req_tx.send(target as u8).await;
                }
            }
        }
    }
    // Let the reporter know no more workers will be added (closes channel).
    drop(scale_progress_tx);
    pt.pb.finish();

    // FEC: after all stream workers finish, any remaining stripes in the map
    // did not receive enough shards for reconstruction — warn and let the
    // file-hash check in finish_transfer surface the error.
    if let Some(ref bufs_arc) = fec_stripe_bufs {
        let remaining = bufs_arc.lock().unwrap();
        if !remaining.is_empty() {
            warn!(
                "{} FEC stripe(s) incomplete after transfer: received too few shards \
                 to reconstruct — those chunks will fail the file hash check",
                remaining.len()
            );
        }
    }

    // Reporter closes when all workers finish (progress_tx fully dropped).
    // Wait for it to return ctrl_send.
    let mut ctrl_send = reporter.await.context("progress reporter panicked")??;

    if let Some(e) = task_err {
        let _ = framing::send_message(
            &mut ctrl_send,
            &ReceiverMessage::Error {
                message: e.to_string(),
            },
        )
        .await;
        bail!("{e}");
    }

    // Wait for the sender's Complete message (forwarded by ctrl_reader_task).
    let expected_hash = complete_rx
        .await
        .context("sender closed without sending Complete")?;

    finish_transfer(
        &mut ctrl_send,
        pt.resume,
        pt.hasher,
        pt.layout,
        &output_dir,
        &manifest,
        expected_hash,
    )
    .await?;

    Ok(ctrl_send)
}

// ── Directory layout helper ───────────────────────────────────────────────────

/// Maps chunks of the virtual concatenated byte stream back to individual files.
///
/// Only `FileKind::File` entries with `size > 0` appear here; directories and
/// symlinks are materialised during `prepare_transfer` and have no chunks.
#[derive(Debug)]
pub(crate) struct ConcatLayout {
    /// File entries in concat-stream order (same order as sent in `DirEntries`).
    file_entries: Vec<FileEntry>,
    /// `prefix_sums[i]` = global byte offset where `file_entries[i]` starts.
    /// `prefix_sums[n]` = total_bytes (sentinel).
    prefix_sums: Vec<u64>,
    /// Base directory for resolving relative paths.
    base_dir: PathBuf,
}

impl ConcatLayout {
    fn new(entries: &[FileEntry], base_dir: PathBuf) -> Self {
        let file_entries: Vec<FileEntry> = entries
            .iter()
            .filter(|e| matches!(e.kind, FileKind::File) && e.size > 0)
            .cloned()
            .collect();

        let mut prefix_sums = Vec::with_capacity(file_entries.len() + 1);
        let mut acc = 0u64;
        for e in &file_entries {
            prefix_sums.push(acc);
            acc += e.size;
        }
        prefix_sums.push(acc); // sentinel

        Self {
            file_entries,
            prefix_sums,
            base_dir,
        }
    }

    /// Write `data` for `chunk_index` into the correct file(s).
    ///
    /// A chunk may span multiple files when many small files are packed into
    /// one chunk.  Each portion is pwrite-d to its respective file.
    fn scatter_write(&self, chunk_index: u64, chunk_size: usize, data: &[u8]) -> Result<()> {
        let global_start = chunk_index * chunk_size as u64;

        // Find first file whose range overlaps this chunk.
        let mut fi = self
            .prefix_sums
            .partition_point(|&ps| ps <= global_start)
            .saturating_sub(1);
        let mut written = 0usize;

        while written < data.len() && fi < self.file_entries.len() {
            let file_start = self.prefix_sums[fi];
            let file_end = self.prefix_sums[fi + 1];
            let pos_in_stream = global_start + written as u64;
            let offset_in_file = pos_in_stream - file_start;
            let available_in_file = (file_end - pos_in_stream) as usize;
            let take = available_in_file.min(data.len() - written);

            let path = self.base_dir.join(&self.file_entries[fi].path);

            #[cfg(unix)]
            let file = {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)
                    .with_context(|| format!("open {}", path.display()))?
            };
            #[cfg(not(unix))]
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .with_context(|| format!("open {}", path.display()))?;

            crate::fs_ext::write_all_at_advise(
                &file,
                &data[written..written + take],
                offset_in_file,
            )
            .with_context(|| format!("pwrite {} at offset {offset_in_file}", path.display()))?;

            written += take;
            fi += 1;
        }

        Ok(())
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Prepared state for a transfer: output target, resume state, progress bar,
/// and the resume bitvector to include in the Ready message.
struct PreparedTransfer {
    /// Single-file transfers: the pre-allocated output file handle.
    out_file: Option<Arc<std::fs::File>>,
    /// Directory transfers: the concat layout for scatter-pwrite.
    layout: Option<Arc<ConcatLayout>>,
    resume: Arc<Mutex<ResumeState>>,
    pb: Arc<ProgressBar>,
    /// `Some` on a fresh transfer (hashes collected inline); `None` on resume
    /// (the full stream is re-hashed from disk in `finish_transfer` instead).
    hasher: Option<Arc<ChunkHasher>>,
    bytes_already_received: u64,
    /// Packed bitvector of already-received chunks; sent in ReceiverMessage::Ready.
    received_bits: Vec<u64>,
}

fn prepare_transfer(
    manifest: &TransferManifest,
    dir_entries: Option<&[FileEntry]>,
    output_dir: &std::path::Path,
) -> Result<PreparedTransfer> {
    let resume = Arc::new(Mutex::new(ResumeState::load_or_new(
        output_dir,
        &manifest.transfer_id,
        manifest.total_chunks,
    )));
    let (received_bits, bytes_already_received) = {
        let state = resume.lock().unwrap();
        let bits = state.received_bitvec();
        let bytes: u64 = state
            .received_chunks()
            .iter()
            .map(|&i| {
                let offset = i * manifest.chunk_size as u64;
                ((manifest.file_size - offset) as usize).min(manifest.chunk_size) as u64
            })
            .sum();
        (bits, bytes)
    };

    // ── Output target: single file vs directory ───────────────────────────────

    let (out_file, layout) = if let Some(entries) = dir_entries {
        // Directory mode: create the directory tree, allocate all files, and
        // materialise symlinks before data arrives.
        let base_dir = output_dir.join(&manifest.file_name);
        prepare_directory(entries, &base_dir)?;
        let layout = Arc::new(ConcatLayout::new(entries, base_dir));
        (None, Some(layout))
    } else {
        // Single-file mode: open and pre-allocate the output file.
        let out_path = output_dir.join(&manifest.file_name);
        let f = open_and_preallocate(&out_path, manifest.file_size)?;
        (Some(Arc::new(f)), None)
    };

    // ── Progress bar ─────────────────────────────────────────────────────────

    let pb = Arc::new({
        let term_width = console::Term::stdout().size().1 as usize;
        let template = if term_width >= 140 {
            "[recv] {spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} \
             {bytes}/{total_bytes} {bytes_per_sec} eta {eta}  {prefix}  {msg}"
        } else {
            "[recv] {spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} \
             {bytes}/{total_bytes} {bytes_per_sec} eta {eta}  {prefix}"
        };
        let pb = ProgressBar::new(manifest.file_size);
        pb.set_style(ProgressStyle::with_template(template).unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        let chunk_mib = manifest.chunk_size / (1024 * 1024);
        let file_count = dir_entries.map(|e| {
            e.iter()
                .filter(|en| matches!(en.kind, FileKind::File))
                .count()
        });
        let prefix = if let Some(n) = file_count {
            format!(
                "{} · {} streams · {} MiB · {n} files",
                manifest.file_name, manifest.num_streams, chunk_mib
            )
        } else {
            format!(
                "{} · {} streams · {} MiB",
                manifest.file_name, manifest.num_streams, chunk_mib
            )
        };
        pb.set_prefix(prefix);
        pb
    });

    // On a fresh transfer, collect per-chunk hashes inline (no extra disk pass).
    // On resume, some chunks are already on disk and will never be fed to the
    // hasher, so we skip inline collection and do a full-stream hash at the end.
    let hasher = if bytes_already_received == 0 {
        Some(Arc::new(ChunkHasher::new(
            manifest.total_chunks,
            manifest.num_streams,
        )))
    } else {
        None
    };

    Ok(PreparedTransfer {
        out_file,
        layout,
        resume,
        pb,
        hasher,
        bytes_already_received,
        received_bits,
    })
}

/// Open `path` for write, pre-allocate it to `size` bytes, and disable the
/// page cache on macOS.
fn open_and_preallocate(path: &std::path::Path, size: u64) -> Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false) // sized explicitly via fallocate/set_len below
        .open(path)
        .with_context(|| format!("open output {}", path.display()))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let isize = i64::try_from(size).context("file too large for this platform")?;
        let rc = unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, isize) };
        if rc != 0 {
            f.set_len(size)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    f.set_len(size)?;
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_NOCACHE, 1) };
    }
    Ok(f)
}

/// Create the directory tree, pre-allocate all files, and materialise symlinks
/// described by `entries` under `base_dir`.
fn prepare_directory(entries: &[FileEntry], base_dir: &std::path::Path) -> Result<()> {
    // Create the root directory.
    std::fs::create_dir_all(base_dir).with_context(|| format!("create {}", base_dir.display()))?;

    for entry in entries {
        let dest = base_dir.join(&entry.path);
        match &entry.kind {
            FileKind::Directory => {
                std::fs::create_dir_all(&dest)
                    .with_context(|| format!("create dir {}", dest.display()))?;
            }
            FileKind::Symlink { target } => {
                // Create parent if needed.
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create parent {}", parent.display()))?;
                }
                // Remove existing symlink if present (resume-safe idempotency).
                let _ = std::fs::remove_file(&dest);
                #[cfg(unix)]
                std::os::unix::fs::symlink(target, &dest)
                    .with_context(|| format!("symlink {} → {target}", dest.display()))?;
                #[cfg(not(unix))]
                warn!(
                    "symlinks not supported on this platform; skipping {}",
                    dest.display()
                );
            }
            FileKind::File => {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create parent {}", parent.display()))?;
                }
                // Pre-allocate the file (0-byte files just create the file).
                open_and_preallocate(&dest, entry.size)
                    .with_context(|| format!("preallocate {}", dest.display()))?;
            }
        }
    }
    Ok(())
}

/// Apply preserved mode and mtime to a single file.
#[cfg(unix)]
fn apply_metadata(path: &std::path::Path, mode: u32, mtime: i64) {
    use std::os::unix::fs::PermissionsExt;
    if mode != 0 {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    if mtime != 0 {
        let t = libc::timespec {
            tv_sec: mtime,
            tv_nsec: libc::UTIME_OMIT,
        };
        let times = [
            t,
            libc::timespec {
                tv_sec: mtime,
                tv_nsec: 0,
            },
        ];
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap_or_default();
        if !c_path.as_bytes().is_empty() {
            unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
        }
    }
}

/// Receives confirmed-written byte counts from data workers and sends
/// throttled `ReceiverMessage::Progress` updates on the control stream.
///
/// Takes ownership of `ctrl_send` and returns it when the channel closes
/// (i.e. when all data workers have finished), so the caller can use it
/// for the final `ReceiverMessage::Complete` / `Error` exchange.
///
/// When dynamic stream scaling is active, the caller may send accepted stream
/// counts through `ack_rx`.  The reporter forwards them as
/// `ReceiverMessage::AdjustStreamsAck` messages immediately (not rate-limited,
/// since the sender is waiting for the ack to proceed with scaling).
async fn progress_reporter<W>(
    mut ctrl_send: W,
    mut rx: tokio::sync::mpsc::Receiver<u64>,
    initial_bytes: u64,
    stats: Arc<ReceiverStats>,
    mut ack_rx: tokio::sync::mpsc::Receiver<u8>,
) -> Result<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut bytes_written = initial_bytes;
    let mut last_reported = initial_bytes;
    let report_interval = Duration::from_millis(100);

    // interval_at avoids timer drift: each tick fires at a fixed cadence
    // relative to the start time rather than relative to the previous tick.
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + report_interval,
        report_interval,
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            n = rx.recv() => {
                match n {
                    Some(n) => bytes_written += n,
                    None => break, // all workers finished, channel closed
                }
            }
            _ = interval.tick() => {
                if bytes_written != last_reported {
                    let in_flight_chunks = stats.in_flight_chunks.load(Ordering::Relaxed);
                    // Swap resets the peak so we report per-interval maximum.
                    let disk_us = stats.last_disk_us.swap(0, Ordering::Relaxed);
                    let disk_stall_ms = disk_us / 1000;
                    framing::send_message(
                        &mut ctrl_send,
                        &ReceiverMessage::Progress {
                            bytes_written,
                            in_flight_chunks,
                            disk_stall_ms,
                        },
                    )
                    .await?;
                    last_reported = bytes_written;
                }
                // Drain any pending acks (scale-up acknowledgements).
                while let Ok(accepted) = ack_rx.try_recv() {
                    framing::send_message(
                        &mut ctrl_send,
                        &ReceiverMessage::AdjustStreamsAck {
                            accepted_count: accepted,
                        },
                    )
                    .await?;
                }
            }
        }
    }

    // Final update to make sure the sender sees 100%.
    if bytes_written != last_reported {
        let in_flight_chunks = stats.in_flight_chunks.load(Ordering::Relaxed);
        let disk_stall_ms = stats.last_disk_us.swap(0, Ordering::Relaxed) / 1000;
        framing::send_message(
            &mut ctrl_send,
            &ReceiverMessage::Progress {
                bytes_written,
                in_flight_chunks,
                disk_stall_ms,
            },
        )
        .await?;
    }

    Ok(ctrl_send)
}

/// Reads `SenderMessage` variants from the control stream during the data
/// transfer phase (concurrently with data workers).
///
/// Forwards `AdjustStreams` requests to the main loop via `scale_tx` and the
/// final `Complete` file hash via `complete_tx`.  Exits when the control
/// stream is closed or `complete_tx` is sent.
async fn ctrl_reader_task<R>(
    mut ctrl_recv: R,
    scale_tx: tokio::sync::mpsc::Sender<u8>,
    complete_tx: tokio::sync::oneshot::Sender<[u8; 32]>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let mut complete_tx = Some(complete_tx);
    loop {
        match framing::recv_message::<_, SenderMessage>(&mut ctrl_recv).await {
            Ok(Some(SenderMessage::AdjustStreams { target_count })) => {
                if scale_tx.send(target_count).await.is_err() {
                    break; // main loop dropped receiver — transfer ending
                }
            }
            Ok(Some(SenderMessage::Complete { file_hash })) => {
                if let Some(tx) = complete_tx.take() {
                    let _ = tx.send(file_hash);
                }
                break;
            }
            _ => break, // EOF or error — main loop will surface via complete_rx timeout
        }
    }
}

async fn finish_transfer<S>(
    ctrl_send: &mut S,
    resume: Arc<Mutex<ResumeState>>,
    hasher: Option<Arc<ChunkHasher>>,
    layout: Option<Arc<ConcatLayout>>,
    output_dir: &std::path::Path,
    manifest: &TransferManifest,
    expected_hash: [u8; 32],
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let file_hash: [u8; 32] = match hasher {
        Some(h) => Arc::try_unwrap(h)
            .expect("all stream tasks finished so no other Arc references exist")
            .finish()?,
        None => {
            // Resume path: some chunks were already on disk and never fed to a
            // ChunkHasher, so hash the complete stream from disk instead.
            let chunk_size = manifest.chunk_size;
            if let Some(ref cl) = layout {
                // Directory: hash the concat stream across all files in order.
                let entries = cl.file_entries.clone();
                let base_dir = cl.base_dir.clone();
                tokio::task::spawn_blocking(move || {
                    crate::transfer::hash::hash_concat_sync(&entries, &base_dir, chunk_size)
                })
                .await
                .context("hash task panicked")??
            } else {
                // Single file.
                let path = output_dir.join(&manifest.file_name);
                tokio::task::spawn_blocking(move || {
                    crate::transfer::hash::hash_file_sync(&path, chunk_size)
                })
                .await
                .context("hash task panicked")??
            }
        }
    };

    if file_hash != expected_hash {
        // Delete the stale resume file so the next attempt starts fresh
        // rather than re-using chunk data that may have come from a changed file.
        let _ = resume.lock().unwrap().delete();
        framing::send_message(
            ctrl_send,
            &ReceiverMessage::Error {
                message: "transfer hash mismatch".into(),
            },
        )
        .await?;
        bail!("transfer hash mismatch — received data is corrupted");
    }

    // Apply preserved permissions/mtime if any entries carry non-zero metadata.
    // (The sender sets mode=0 and mtime=0 when --preserve is not requested.)
    #[cfg(unix)]
    if let Some(ref cl) = layout {
        let root = output_dir.join(&manifest.file_name);
        for entry in &cl.file_entries {
            if entry.mode != 0 || entry.mtime != 0 {
                apply_metadata(&root.join(&entry.path), entry.mode, entry.mtime);
            }
        }
    }

    framing::send_message(ctrl_send, &ReceiverMessage::Complete { file_hash }).await?;

    resume.lock().unwrap().delete()?;
    println!(
        "Received: {}",
        output_dir.join(&manifest.file_name).display()
    );
    Ok(())
}

// ── Stream worker (generic over any AsyncRead) ────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn recv_stream_worker<R>(
    mut stream: R,
    out_file: Option<Arc<std::fs::File>>,
    layout: Option<Arc<ConcatLayout>>,
    resume: Arc<Mutex<ResumeState>>,
    manifest: TransferManifest,
    pb: Arc<ProgressBar>,
    hasher: Option<Arc<ChunkHasher>>,
    progress_tx: tokio::sync::mpsc::Sender<u64>,
    stats: Arc<ReceiverStats>,
    write_sem: Arc<tokio::sync::Semaphore>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    // Keep at most this many chunk-processing tasks in flight per stream worker.
    // Processing (SHA-256 + optional decompress + pwrite) is typically 10-30×
    // faster than receiving at the network rate per stream, so a pipeline depth
    // of 4 is more than sufficient to overlap compute with the next network read
    // without buffering excessive chunk data in memory.  A larger value creates
    // memory pressure (N streams × depth × chunk_size) and disk-I/O contention
    // with no throughput benefit.
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

        let chunk: ChunkData = match framing::recv_chunk_data(&mut stream)
            .await
            .with_context(|| format!("recv chunk#{chunk_count}"))?
        {
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
        let out_file = out_file.as_ref().map(Arc::clone);
        let layout = layout.as_ref().map(Arc::clone);
        let hasher = hasher.as_ref().map(Arc::clone);
        let resume = Arc::clone(&resume);
        let pb = Arc::clone(&pb);
        let progress_tx = progress_tx.clone();
        let stats = Arc::clone(&stats);

        // Acquire the global write semaphore before spawning.  This limits peak
        // concurrent pwrite calls across all streams to 8, capping dirty-page
        // pressure at ~64 MiB instead of the per-stream-MAX_IN_FLIGHT * N_streams
        // ceiling (~256 MiB for 8 streams).  The permit is moved into the blocking
        // task and dropped immediately after the write completes.
        let write_permit = write_sem
            .clone()
            .acquire_owned()
            .await
            .expect("write semaphore closed");

        stats.in_flight_chunks.fetch_add(1, Ordering::Relaxed);
        processing.spawn_blocking(move || -> Result<()> {
            // Decompress first: chunk_hash is blake3(raw_bytes) on the sender,
            // so we must verify against the decompressed data, not the wire payload.
            let data = if chunk.compressed {
                compress::decompress_chunk(&chunk.payload, chunk_size)?
            } else {
                chunk.payload
            };

            let computed: [u8; 32] = *blake3::hash(&data).as_bytes();
            if computed != chunk.chunk_hash {
                stats.in_flight_chunks.fetch_sub(1, Ordering::Relaxed);
                bail!("chunk {chunk_index} hash mismatch");
            }

            let write_start = std::time::Instant::now();
            if let Some(ref cl) = layout {
                // Directory mode: scatter-pwrite across the files that overlap
                // this chunk's byte range in the concat stream.
                cl.scatter_write(chunk_index, chunk_size, &data)
                    .with_context(|| format!("scatter write chunk {chunk_index}"))?;
            } else {
                // Single-file mode: direct pwrite to the pre-allocated file.
                let offset = chunk_index * chunk_size as u64;
                let f = out_file
                    .as_ref()
                    .expect("single-file mode must have out_file");
                crate::fs_ext::write_all_at_advise(f, &data, offset)
                    .with_context(|| format!("write chunk {chunk_index} at offset {offset}"))?;
            }
            // Release the write semaphore now that all pwrite calls for this chunk
            // are done; the remaining work below is cheap.
            drop(write_permit);

            // Feed the already-verified hash (not the raw bytes) — ChunkHasher
            // collects per-chunk hashes and combines them, no second BLAKE3 pass.
            // On resume, hasher is None and the full-file hash is done at the end.
            if let Some(ref h) = hasher {
                h.feed(chunk_index, chunk.chunk_hash)?;
            }
            let n = data.len() as u64;
            pb.inc(n);
            // Non-blocking: progress updates are best-effort; never slow the data path.
            let _ = progress_tx.try_send(n);

            // Mark under the lock (fast), then snapshot if the batch threshold
            // is reached, releasing the lock *before* the slow fsync so other
            // stream workers are not serialised waiting on disk I/O.
            let snap = {
                let mut r = resume.lock().unwrap();
                r.mark_received(chunk_index);
                if r.incr_dirty() >= RESUME_SAVE_BATCH {
                    r.reset_dirty();
                    Some(r.snapshot()?)
                } else {
                    None
                }
            };
            if let Some(snap) = snap {
                snap.write_to_disk()?;
            }

            let write_us = write_start.elapsed().as_micros() as u32;
            stats.last_disk_us.fetch_max(write_us, Ordering::Relaxed);
            stats.in_flight_chunks.fetch_sub(1, Ordering::Relaxed);

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

// ── FEC stream worker ─────────────────────────────────────────────────────────

/// Stream worker for FEC-enabled transfers.
///
/// Reads `FecChunkData` frames from one data stream.  Each received shard is
/// inserted into the shared `stripe_bufs` map.  When a stripe has received
/// enough shards (`is_ready()`), the stripe is extracted from the map and
/// processed (RS reconstruct if needed, then decompress → verify → pwrite)
/// in a `spawn_blocking` task so it does not stall the async executor.
///
/// At most `MAX_IN_FLIGHT` stripe-processing tasks run concurrently per stream
/// worker.  The shared `stripe_bufs` map bounds total in-flight stripes across
/// all workers.
#[allow(clippy::too_many_arguments)]
async fn recv_fec_stream_worker<R>(
    mut stream: R,
    out_file: Arc<std::fs::File>,
    resume: Arc<Mutex<ResumeState>>,
    manifest: TransferManifest,
    pb: Arc<ProgressBar>,
    hasher: Option<Arc<ChunkHasher>>,
    progress_tx: tokio::sync::mpsc::Sender<u64>,
    stripe_bufs: Arc<Mutex<HashMap<u32, StripeBuffer>>>,
    stats: Arc<ReceiverStats>,
    write_sem: Arc<tokio::sync::Semaphore>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    const MAX_IN_FLIGHT: usize = 4;
    let mut processing: JoinSet<Result<()>> = JoinSet::new();
    let fec_params = manifest
        .fec
        .as_ref()
        .expect("recv_fec_stream_worker called without FEC params");
    let data_shards = fec_params.data_shards;
    let parity_shards = fec_params.parity_shards;
    let total_chunks = manifest.total_chunks;
    let chunk_size = manifest.chunk_size;
    let transfer_id = manifest.transfer_id;
    let mut shard_count = 0u64;

    loop {
        // Drain any completed processing tasks before accepting more shards
        // so in-flight memory stays bounded.
        if processing.len() >= MAX_IN_FLIGHT {
            match processing.join_next().await {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(e))) => return Err(e),
                Some(Err(e)) => bail!("FEC stripe processing task panicked: {e}"),
                None => {}
            }
        }

        let fcd = match framing::recv_fec_chunk_data(&mut stream)
            .await
            .with_context(|| format!("recv FEC shard #{shard_count}"))?
        {
            Some(c) => c,
            None => break, // clean EOF — all shards for this stream delivered
        };

        if fcd.transfer_id != transfer_id {
            bail!(
                "FEC shard: transfer_id mismatch (shard {}, chunk {})",
                shard_count,
                fcd.chunk_index
            );
        }

        // Wire integrity check for parity shards only (data shards are verified
        // against chunk_hash after RS reconstruction / decompression).
        if fcd.is_parity {
            let computed: [u8; 32] = *blake3::hash(&fcd.payload).as_bytes();
            if computed != fcd.chunk_hash {
                bail!(
                    "FEC parity shard stripe={} shard={}: wire hash mismatch",
                    fcd.stripe_index,
                    fcd.shard_index_in_stripe
                );
            }
        }

        let stripe_index = fcd.stripe_index;

        // Insert shard into the shared buffer; extract the stripe if it is now ready.
        let ready_stripe = {
            let mut bufs = stripe_bufs.lock().unwrap();
            let real_count = {
                let first = stripe_index as u64 * data_shards as u64;
                (total_chunks - first).min(data_shards as u64) as usize
            };
            let buf = bufs.entry(stripe_index).or_insert_with(|| {
                StripeBuffer::new(stripe_index, data_shards, parity_shards, real_count)
            });
            buf.insert(fcd)?;
            let ready = buf.is_ready();
            if ready {
                bufs.remove(&stripe_index)
            } else {
                None
            }
        };

        if let Some(stripe) = ready_stripe {
            let out_file = Arc::clone(&out_file);
            let resume = Arc::clone(&resume);
            let hasher = hasher.as_ref().map(Arc::clone);
            let pb = Arc::clone(&pb);
            let ptx = progress_tx.clone();
            let stats = Arc::clone(&stats);
            let write_permit = write_sem
                .clone()
                .acquire_owned()
                .await
                .expect("write semaphore closed");
            stats.in_flight_chunks.fetch_add(1, Ordering::Relaxed);
            processing.spawn_blocking(move || {
                let write_start = std::time::Instant::now();
                let result = process_stripe(stripe, chunk_size, out_file, resume, hasher, pb, ptx);
                drop(write_permit);
                let write_us = write_start.elapsed().as_micros() as u32;
                stats.last_disk_us.fetch_max(write_us, Ordering::Relaxed);
                stats.in_flight_chunks.fetch_sub(1, Ordering::Relaxed);
                result
            });
        }

        shard_count += 1;
    }

    // Await all remaining stripe processing tasks.
    while let Some(res) = processing.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => bail!("FEC stripe processing task panicked: {e}"),
        }
    }

    Ok(())
}

// ── Timeouts ──────────────────────────────────────────────────────────────────

/// How long `run_receive` waits for each individual data stream to be
/// accepted.  The sender opens all data streams right after the receiver
/// replies with `ReceiverMessage::Ready`, so 30 s is very generous; it
/// only fires when the sender has already died mid-setup.
const DATA_STREAM_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

// ── Manifest validation ───────────────────────────────────────────────────────

const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024;
const MIN_CHUNK_SIZE: usize = 4 * 1024;
const MAX_CHUNK_SIZE: usize = 128 * 1024 * 1024;
const MAX_STREAMS: usize = 1024;

/// Maximum number of file entries in a `DirEntries` message.
/// Limits memory usage and prevents degenerate manifests.
const MAX_DIR_ENTRIES: usize = 500_000;

fn validate_manifest(m: &crate::protocol::messages::TransferManifest) -> Result<()> {
    if m.file_name.is_empty() {
        bail!("manifest: file_name is empty");
    }
    if m.file_name.contains('\0') {
        bail!("manifest: file_name contains null byte");
    }
    if m.file_name.contains('/') || m.file_name.contains('\\') {
        bail!(
            "manifest: file_name contains path separator: {:?}",
            m.file_name
        );
    }
    if m.file_name == ".." || m.file_name == "." {
        bail!(
            "manifest: file_name is a relative-path component: {:?}",
            m.file_name
        );
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

/// Validate a `DirEntries` payload received over the wire.
///
/// Security checks — path traversal, symlink escape, size consistency.
fn validate_dir_entries(manifest: &TransferManifest, de: &DirEntries) -> Result<()> {
    let entries = match &de.entries {
        None => return Ok(()), // single-file v3 transfer; nothing to validate
        Some(e) => e,
    };

    if entries.len() > MAX_DIR_ENTRIES {
        bail!(
            "DirEntries: too many entries ({}, limit {MAX_DIR_ENTRIES})",
            entries.len()
        );
    }

    let mut seen_paths = std::collections::HashSet::new();
    let mut total_file_bytes: u64 = 0;

    for (i, entry) in entries.iter().enumerate() {
        // Path must not be empty.
        if entry.path.is_empty() {
            bail!("DirEntries[{i}]: empty path");
        }
        // No null bytes.
        if entry.path.contains('\0') {
            bail!("DirEntries[{i}]: path contains null byte");
        }
        // Must not start with a path separator.
        if entry.path.starts_with('/') || entry.path.starts_with('\\') {
            bail!("DirEntries[{i}]: path is absolute: {:?}", entry.path);
        }
        // Validate every component.
        for component in entry.path.split('/') {
            if component.is_empty() {
                bail!(
                    "DirEntries[{i}]: path has empty component: {:?}",
                    entry.path
                );
            }
            if component == ".." || component == "." {
                bail!(
                    "DirEntries[{i}]: path contains traversal component: {:?}",
                    entry.path
                );
            }
            if component.contains('\0') {
                bail!(
                    "DirEntries[{i}]: path component contains null: {:?}",
                    entry.path
                );
            }
            // Reject Windows drive letters (e.g. "C:").
            if component.len() >= 2
                && component.as_bytes()[1] == b':'
                && component.as_bytes()[0].is_ascii_alphabetic()
            {
                bail!(
                    "DirEntries[{i}]: path contains drive letter: {:?}",
                    entry.path
                );
            }
        }

        // No duplicate paths.
        if !seen_paths.insert(&entry.path) {
            bail!("DirEntries[{i}]: duplicate path {:?}", entry.path);
        }

        // Symlink targets must not be absolute and must not escape the root.
        if let FileKind::Symlink { target } = &entry.kind {
            if target.starts_with('/') || target.starts_with('\\') {
                bail!(
                    "DirEntries[{i}]: symlink {:?} has absolute target {:?}",
                    entry.path,
                    target
                );
            }
            // Resolve the target lexically relative to the symlink's parent directory
            // and ensure it doesn't escape via "..".
            let parent = entry.path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let resolved = resolve_relative_path(parent, target);
            if resolved.starts_with("../") || resolved == ".." {
                bail!(
                    "DirEntries[{i}]: symlink {:?} target {:?} escapes transfer root",
                    entry.path,
                    target
                );
            }
        }

        // Accumulate File sizes for cross-check against manifest.file_size.
        if matches!(entry.kind, FileKind::File) {
            total_file_bytes = total_file_bytes.saturating_add(entry.size);
        } else if entry.size != 0 {
            bail!(
                "DirEntries[{i}]: non-File entry {:?} has non-zero size {}",
                entry.path,
                entry.size
            );
        }
    }

    // Verify that the sum of File sizes matches the manifest's file_size.
    if total_file_bytes != manifest.file_size {
        bail!(
            "DirEntries: sum of file sizes ({total_file_bytes}) \
             does not match manifest.file_size ({})",
            manifest.file_size
        );
    }

    Ok(())
}

/// Lexically resolve `target` relative to `base_dir` (e.g. a symlink's parent
/// directory within the transfer root).  Returns a normalised relative path
/// that can be checked for `..` escape.
fn resolve_relative_path(base_dir: &str, target: &str) -> String {
    // Start with the base directory components.
    let mut parts: Vec<&str> = if base_dir.is_empty() {
        vec![]
    } else {
        base_dir.split('/').collect()
    };

    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }

    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}
