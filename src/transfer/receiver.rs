//! Receiver-side transfer orchestration. See `transfer/mod.rs` for the full flow.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use indicatif::ProgressBar;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncRead;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

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
        NegotiateResponse, ReceiverMessage, SenderMessage, TransferManifest,
    },
};
use crate::transfer::hash::ChunkHasher;
use crate::transfer::resume::{ResumeState, RESUME_SAVE_BATCH};

/// Test-only fault injection for exercising the incremental-repair path.
///
/// Lets a test mark chunk indices to be dropped exactly once on first receipt,
/// simulating corruption so the completion-checkpoint repair flow runs against
/// real sender/receiver machinery.  Hidden from docs; prod cost is a single
/// relaxed atomic load per chunk (the set is never enabled outside tests).
#[doc(hidden)]
pub mod test_hooks {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static DROP_ONCE: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();

    /// Number of chunks to mark before aborting; 0 disables the abort hook.
    static ABORT_AFTER: AtomicU64 = AtomicU64::new(0);
    /// Count of chunks marked-received since the abort hook was armed.
    static MARKED: AtomicU64 = AtomicU64::new(0);
    /// Latches true once the abort threshold is crossed; read by every stream
    /// worker at the top of its loop so they all tear down promptly.
    static ABORT_FIRED: AtomicBool = AtomicBool::new(false);

    fn set() -> &'static Mutex<HashSet<u64>> {
        DROP_ONCE.get_or_init(|| Mutex::new(HashSet::new()))
    }

    /// Mark chunk indices to drop once each on next receipt (test only).
    pub fn drop_chunks_once(indices: &[u64]) {
        set()
            .lock()
            .expect("test-hook drop set mutex poisoned")
            .extend(indices.iter().copied());
        ENABLED.store(true, Ordering::Relaxed);
    }

    /// Arm a simulated crash: once `n` chunks have been marked-received across all
    /// stream workers, the receiver flushes its resume state and aborts the
    /// transfer (leaving a partial resume file for a follow-up run). Test only.
    pub fn abort_after_chunks(n: u64) {
        MARKED.store(0, Ordering::Relaxed);
        ABORT_FIRED.store(false, Ordering::Relaxed);
        ABORT_AFTER.store(n, Ordering::Relaxed);
    }

    /// Clear all pending drops/aborts and disable the hooks.
    pub fn clear() {
        set()
            .lock()
            .expect("test-hook drop set mutex poisoned")
            .clear();
        ENABLED.store(false, Ordering::Relaxed);
        ABORT_AFTER.store(0, Ordering::Relaxed);
        MARKED.store(0, Ordering::Relaxed);
        ABORT_FIRED.store(false, Ordering::Relaxed);
    }

    /// Returns true (and consumes the mark) if `idx` should be dropped.
    pub(crate) fn should_drop(idx: u64) -> bool {
        if !ENABLED.load(Ordering::Relaxed) {
            return false;
        }
        set()
            .lock()
            .expect("test-hook drop set mutex poisoned")
            .remove(&idx)
    }

    /// Record one marked chunk; returns true the moment the armed abort threshold
    /// is crossed (so the caller can force a resume flush before tearing down).
    /// A single relaxed load in the common (disarmed) path.
    pub(crate) fn note_marked_and_check_abort() -> bool {
        if ABORT_AFTER.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let n = MARKED.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= ABORT_AFTER.load(Ordering::Relaxed) {
            ABORT_FIRED.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// True once the simulated crash has fired; stream workers poll this at the
    /// top of their receive loop and bail.
    pub(crate) fn abort_requested() -> bool {
        ABORT_FIRED.load(Ordering::Relaxed)
    }
}

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
    /// Optional counter incremented once per successfully completed transfer in
    /// [`Server::serve`]/[`Server::serve_with_router`]. Attached via
    /// [`Server::count_completions_into`] (the daemon shares its Status counter
    /// here); `None` for the test/one-shot accept helpers.
    completed: Option<Arc<AtomicU64>>,
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
            completed: None,
        })
    }

    /// Attach a counter incremented once per successfully completed transfer
    /// (used by the daemon to back its `Status.transfers_completed`).
    pub fn count_completions_into(mut self, counter: Arc<AtomicU64>) -> Self {
        self.completed = Some(counter);
        self
    }

    /// Build from a pre-generated certificate so QUIC and TCP can share one cert.
    pub fn bind_with_cert(
        addr: SocketAddr,
        output_dir: PathBuf,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        fingerprint: String,
    ) -> Result<Self> {
        Self::bind_with_cert_auth(addr, output_dir, cert, key, fingerprint, None)
    }

    /// Like [`Server::bind_with_cert`], but when `authorized` is `Some(list)` the
    /// server requires mutual-TLS DeviceId auth and only accepts senders whose
    /// Ed25519 DeviceId is allowlisted (M4 daemon identity auth).
    pub fn bind_with_cert_auth(
        addr: SocketAddr,
        output_dir: PathBuf,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        fingerprint: String,
        authorized: Option<Vec<String>>,
    ) -> Result<Self> {
        use crate::net::connection::make_server_endpoint_with_cert_auth;
        let endpoint = make_server_endpoint_with_cert_auth(addr, cert, key, authorized)?;
        let local_addr = endpoint.local_addr()?;
        Ok(Self {
            endpoint,
            local_addr,
            fingerprint,
            output_dir,
            completed: None,
        })
    }

    /// Like [`Server::bind_with_cert_auth`], but the DeviceId allowlist is a live
    /// [`ReloadableAllowlist`] the caller (the daemon) can update in place to
    /// reload trust on SIGHUP. The verifier is always installed; an empty
    /// allowlist means open (client auth not mandatory).
    pub fn bind_with_reloadable_auth(
        addr: SocketAddr,
        output_dir: PathBuf,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        fingerprint: String,
        allowlist: crate::net::connection::ReloadableAllowlist,
    ) -> Result<Self> {
        use crate::net::connection::make_server_endpoint_with_reloadable_auth;
        let endpoint = make_server_endpoint_with_reloadable_auth(addr, cert, key, allowlist)?;
        let local_addr = endpoint.local_addr()?;
        Ok(Self {
            endpoint,
            local_addr,
            fingerprint,
            output_dir,
            completed: None,
        })
    }

    /// Accept and handle exactly one incoming connection (single-path), then
    /// return. Intended for integration tests.
    pub async fn accept_one(&self) -> Result<()> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("endpoint closed before any connection arrived"))?;
        let conn = incoming.await.context("connection setup failed")?;
        info!("connection from {}", conn.remote_address());
        handle_quic_connection(conn, None, self.output_dir.clone().into()).await
    }

    /// Accept one transfer, treating any additional connections that arrive
    /// during it as bonded multipath paths (M3). Intended for integration tests.
    pub async fn accept_one_multipath(&self) -> Result<()> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("endpoint closed before any connection arrived"))?;
        let conn = incoming.await.context("connection setup failed")?;
        info!("connection from {} (multipath)", conn.remote_address());
        handle_quic_connection(
            conn,
            Some(self.endpoint.clone()),
            self.output_dir.clone().into(),
        )
        .await
    }

    /// Accept and handle transfers indefinitely (QUIC only; use `listen` for
    /// auto mode). Each connection is handled on its own task, so independent
    /// senders get concurrent, isolated transfers.
    pub async fn serve(self) -> Result<()> {
        let out = self.output_dir.clone();
        self.serve_with_router(move |_peer| Ok(out.clone())).await
    }

    /// Like [`Server::serve`], but `router` maps each connection's peer DeviceId
    /// to a [`Route`] (or plain output directory)
    /// (extracted from its client certificate under mutual-TLS auth): the
    /// output directory its files should land in — the basis for per-peer tenant
    /// isolation (M8 ACLs). `router` receives `None` when the peer presented no
    /// usable identity.
    ///
    /// Connections are served **concurrently and independently** (one task each).
    /// Each transfer uses a single connection here — connection bonding
    /// (multipath) is offered only via [`Server::accept_one_multipath`], where a
    /// dedicated receiver owns the endpoint; bonding multiple connections into
    /// one of many *concurrent* transfers needs a transfer_id→path registry and
    /// is deliberately out of scope for the shared accept loop (mixing the two
    /// is what let an unrelated connection corrupt an in-flight transfer).
    pub async fn serve_with_router<F, R>(self, router: F) -> Result<()>
    where
        F: Fn(Option<&str>) -> Result<R> + Send + Sync + 'static,
        R: Into<Route>,
    {
        let router = std::sync::Arc::new(router);
        let completed = self.completed.clone();
        while let Some(incoming) = self.endpoint.accept().await {
            let router = std::sync::Arc::clone(&router);
            let completed = completed.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        info!("connection from {}", conn.remote_address());
                        let peer = peer_device_id(&conn);
                        let route: Route = match router(peer.as_deref()) {
                            Ok(r) => r.into(),
                            Err(e) => {
                                tracing::error!("rejecting connection: {e:#}");
                                conn.close(1u32.into(), b"not authorized");
                                return;
                            }
                        };
                        // Single connection per transfer (endpoint = None): no
                        // cross-connection feeder, so a second sender can never
                        // be absorbed into this transfer.
                        match handle_quic_connection(conn, None, route).await {
                            Ok(()) => {
                                // Count only genuine completions (handle_quic_connection
                                // returns Ok after the whole-file hash verifies and the
                                // Complete ack is sent).
                                if let Some(c) = &completed {
                                    c.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(e) => {
                                if e.downcast_ref::<SwitchToTcp>().is_some() {
                                    debug!("sender switched to TCP+TLS");
                                } else {
                                    tracing::error!("transfer error: {e:#}");
                                }
                            }
                        }
                    }
                    Err(e) => warn!("incoming connection failed: {e}"),
                }
            });
        }
        Ok(())
    }
}

/// Extract the peer's Ed25519 DeviceId from its client certificate (mutual TLS).
/// Returns `None` if the peer presented no certificate or no Ed25519 key.
pub fn peer_device_id(conn: &quinn::Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let leaf = certs.first()?;
    crate::identity::device_id_from_cert(leaf)
}

/// The DeviceId of a TCP+TLS peer's client certificate, if it presented one.
fn tls_peer_device_id(tls: &ServerTlsStream<tokio::net::TcpStream>) -> Option<String> {
    let leaf = tls.get_ref().1.peer_certificates()?.first()?;
    crate::identity::device_id_from_cert(leaf)
}

// ── TCP+TLS server ────────────────────────────────────────────────────────────

/// A bound TCP+TLS server, ready to accept incoming transfers.
///
/// Uses the same self-signed-certificate / TOFU model as QUIC so the
/// fingerprint can be shared across both transports.
///
/// [`TcpServer::serve`] handles transfers **concurrently**: every connection is
/// TLS-handshaken on its own task and classified by its first frame — a
/// `NegotiateRequest` opens a transfer (control connection), a v7
/// `StreamHello` names the transfer a data connection belongs to, and the
/// [`TcpStreamRouter`] hands it to that transfer. Pre-v7 senders send no
/// `StreamHello`, so their data connections can only be matched by arrival:
/// at most one such legacy transfer runs at a time. Data connections must come
/// from the same IP as their control connection. Handshakes and the first
/// frame are bounded by [`TLS_HANDSHAKE_TIMEOUT`] / [`HANDSHAKE_READ_TIMEOUT`],
/// so idle peers can't wedge the server.
///
/// [`TcpServer::accept_one`] serves a single transfer that owns the listener
/// (data connections are taken in arrival order), as the SSH one-shot server
/// and tests use it.
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
        Self::bind_with_cert_auth(addr, output_dir, cert, key, fingerprint, None).await
    }

    /// Like [`TcpServer::bind_with_cert`], but when `authorized` is `Some(list)`
    /// every TLS connection (control and data) must present a client
    /// certificate whose DeviceId is in `list`.
    pub async fn bind_with_cert_auth(
        addr: SocketAddr,
        output_dir: PathBuf,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        fingerprint: String,
        authorized: Option<Vec<String>>,
    ) -> Result<Self> {
        let (listener, local_addr) = crate::net::tcp::bind_tcp(addr).await?;
        let acceptor = Arc::new(make_tls_acceptor(cert, key, authorized)?);
        Ok(Self {
            listener: Arc::new(listener),
            acceptor,
            local_addr,
            fingerprint,
            output_dir,
        })
    }

    /// Accept the next control connection whose TLS handshake completes within
    /// [`TLS_HANDSHAKE_TIMEOUT`], skipping (and logging) any that fail or stall.
    async fn accept_control(&self) -> Result<ServerTlsStream<tokio::net::TcpStream>> {
        loop {
            let (raw, peer_addr) = match self.listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    // Transient (e.g. EMFILE, ECONNABORTED): don't kill the server.
                    warn!("TCP accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            if let Err(e) = raw.set_nodelay(true) {
                warn!("set_nodelay failed for {peer_addr}: {e}");
                continue;
            }
            info!("TCP connection from {peer_addr}");
            let handshake = Arc::clone(&self.acceptor).accept(raw);
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, handshake).await {
                Ok(Ok(tls)) => return Ok(tls),
                Ok(Err(e)) => warn!("TLS handshake failed from {peer_addr}: {e}"),
                Err(_) => warn!(
                    "TLS handshake from {peer_addr} timed out after {}s; dropping",
                    TLS_HANDSHAKE_TIMEOUT.as_secs()
                ),
            }
        }
    }

    /// Accept and handle exactly one complete transfer (control + data streams), then return.
    /// Intended for integration tests.
    pub async fn accept_one(&self) -> Result<()> {
        let tls = self.accept_control().await?;
        handle_tcp_connection(
            tls,
            Arc::clone(&self.listener),
            Arc::clone(&self.acceptor),
            self.output_dir.clone(),
        )
        .await
    }

    /// Accept and handle transfers concurrently, indefinitely (see the type docs
    /// for how data connections are routed to their transfer).
    pub async fn serve(self) -> Result<()> {
        let router = Arc::new(TcpStreamRouter::default());
        loop {
            let (raw, peer_addr) = match self.listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    warn!("TCP accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let acceptor = Arc::clone(&self.acceptor);
            let router = Arc::clone(&router);
            let output_dir = self.output_dir.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    serve_routed_tcp_connection(raw, peer_addr, acceptor, router, output_dir).await
                {
                    tracing::error!("TCP connection from {peer_addr}: {e:#}");
                }
            });
        }
    }
}

// ── Public listen functions ───────────────────────────────────────────────────

/// Bind and serve both QUIC and TCP+TLS on the same port using one shared certificate.
///
/// The sender auto-detects which transport is available: it tries QUIC first
/// (with a short timeout) and falls back to TCP+TLS if UDP is blocked.
pub async fn listen(bind: SocketAddr, config: ReceiveConfig) -> Result<()> {
    // Persistent device identity: one cert shared by QUIC and TCP, stable across
    // restarts so a pinned/TOFU fingerprint keeps matching (see crate::identity).
    let id = crate::identity::load_or_create()?;
    let fingerprint = id.fingerprint.clone();
    let device_id = id.device_id.clone();

    let quic_key = make_private_key(id.key_bytes.clone())?;
    let tcp_key = make_private_key(id.key_bytes)?;

    let quic_server = Server::bind_with_cert(
        bind,
        config.output_dir.clone(),
        id.cert.clone(),
        quic_key,
        fingerprint.clone(),
    )?;
    let tcp_server = TcpServer::bind_with_cert(
        bind,
        config.output_dir,
        id.cert,
        tcp_key,
        fingerprint.clone(),
    )
    .await?;

    println!(
        "Listening on {} (QUIC + TCP+TLS, auto-fallback)",
        quic_server.local_addr
    );
    println!("Certificate fingerprint (share with sender --trust):\n  {fingerprint}");
    println!("Device ID: {device_id}");

    tokio::try_join!(quic_server.serve(), tcp_server.serve())?;
    Ok(())
}

/// Bind and serve TCP+TLS only (explicit `--tcp` mode).
pub async fn listen_tcp(bind: SocketAddr, config: ReceiveConfig) -> Result<()> {
    // Use the persistent device identity so the fingerprint is stable across
    // restarts, matching the QUIC+TCP `listen` path.
    let id = crate::identity::load_or_create()?;
    let tcp_key = make_private_key(id.key_bytes)?;
    let server = TcpServer::bind_with_cert(
        bind,
        config.output_dir,
        id.cert,
        tcp_key,
        id.fingerprint.clone(),
    )
    .await?;
    println!("Listening on {} (TCP+TLS)", server.local_addr);
    println!(
        "Certificate fingerprint (share with sender --trust):\n  {}",
        server.fingerprint
    );
    println!("Device ID: {}", id.device_id);
    server.serve().await
}

/// Bind on a given port (or a random one when `port` is `None`), write a JSON
/// handshake to stdout for the SSH launcher to read, accept exactly one
/// transfer (QUIC or TCP+TLS), then exit.
///
/// Both transports are offered on the same port number so the sender's
/// auto-fallback (QUIC → TCP+TLS) works without any extra configuration.
///
/// `require_peer`: the launching sender's DeviceId. When set, both listeners
/// demand a matching client certificate, so another host that reaches the
/// printed port first can't claim the one-shot slot and write into the
/// remote directory.
pub async fn serve_one_stdio(
    output_dir: PathBuf,
    port: Option<u16>,
    require_peer: Option<String>,
) -> Result<()> {
    use std::net::SocketAddr;

    // Persistent device identity (stable across SSH-launched runs too).
    let id = crate::identity::load_or_create()?;
    let cert = id.cert;
    let fingerprint = id.fingerprint;

    let quic_key = make_private_key(id.key_bytes.clone())?;
    let tcp_key = make_private_key(id.key_bytes)?;

    let bind_port = port.unwrap_or(0);

    // Bind QUIC on the requested port (0 = random), then reuse that port for TCP.
    // UDP and TCP port spaces are independent, so this always works.
    let authorized = require_peer.map(|id| vec![id]);
    let quic_server = Server::bind_with_cert_auth(
        format!("0.0.0.0:{bind_port}").parse::<SocketAddr>()?,
        output_dir.clone(),
        cert.clone(),
        quic_key,
        fingerprint.clone(),
        authorized.clone(),
    )?;
    let port = quic_server.local_addr.port();
    let tcp_server = TcpServer::bind_with_cert_auth(
        format!("0.0.0.0:{port}").parse::<SocketAddr>()?,
        output_dir,
        cert,
        tcp_key,
        fingerprint.clone(),
        authorized,
    )
    .await?;

    // Machine-readable handshake — the SSH launcher reads exactly this line.
    println!("{{\"port\":{port},\"fingerprint\":\"{fingerprint}\"}}");

    // Accept up to 2 connections: the initial transfer and one resume retry.
    //
    // The sender's retry logic (ssh.rs) keeps the SSH session alive after a
    // mid-flight failure and immediately reconnects to the same port.  By
    // looping here instead of exiting we keep both endpoints bound so the
    // retry can succeed without relaunching the receiver.
    //
    // A timeout is applied to each *accept* (not the transfer that follows) as
    // a safety net: 5 minutes for the initial connection, 60 seconds for the
    // retry.  This prevents the
    // receiver from hanging indefinitely when SIGHUP is not delivered (e.g.
    // the user has SSH ControlMaster enabled and the muxed session outlives
    // our SSH child, or a network partition where TCP keepalives haven't
    // fired yet).
    for attempt in 0_u8..=1 {
        let timeout = if attempt == 0 {
            STDIO_ACCEPT_TIMEOUT
        } else {
            STDIO_RETRY_TIMEOUT
        };
        let result = accept_one_quic_or_tcp(&quic_server, &tcp_server, timeout).await;
        match result {
            Ok(()) => return Ok(()),
            Err(e) if e.is::<AcceptTimedOut>() => bail!(
                "no {} received within {}s — exiting",
                if attempt == 0 {
                    "connection"
                } else {
                    "reconnection"
                },
                timeout.as_secs(),
            ),
            Err(e) if attempt == 0 => {
                // First transfer failed; stay alive so the sender's automatic
                // resume retry can reconnect to the same port.
                warn!("transfer failed (attempt 1), waiting for resume retry: {e:#}");
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Race QUIC and TCP for one complete transfer.  If the QUIC connection is
/// immediately closed by the sender with the "switching to tcp" sentinel
/// (RTT-based LAN detection), fall through to accept the follow-up TCP+TLS
/// connection instead.
///
/// `accept_timeout` bounds only the wait for each connection; the transfer
/// itself may take as long as it needs. A timed-out wait returns
/// [`AcceptTimedOut`].
async fn accept_one_quic_or_tcp(
    quic: &Server,
    tcp: &TcpServer,
    accept_timeout: Duration,
) -> Result<()> {
    enum Accepted {
        Quic(quinn::Connection),
        Tcp(Box<ServerTlsStream<tokio::net::TcpStream>>),
    }
    let accept_quic = async {
        let incoming = quic
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("endpoint closed before any connection arrived"))?;
        incoming.await.context("connection setup failed")
    };
    let accepted = tokio::time::timeout(accept_timeout, async {
        tokio::select! {
            c = accept_quic => c.map(Accepted::Quic),
            t = tcp.accept_control() => t.map(|t| Accepted::Tcp(Box::new(t))),
        }
    })
    .await
    .map_err(|_| anyhow::Error::new(AcceptTimedOut))??;

    let handle_tcp = |tls| {
        handle_tcp_connection(
            tls,
            Arc::clone(&tcp.listener),
            Arc::clone(&tcp.acceptor),
            tcp.output_dir.clone(),
        )
    };
    match accepted {
        Accepted::Quic(conn) => {
            info!("connection from {}", conn.remote_address());
            match handle_quic_connection(conn, None, quic.output_dir.clone().into()).await {
                Err(e) if e.is::<SwitchToTcp>() => {
                    let tls = tokio::time::timeout(accept_timeout, tcp.accept_control())
                        .await
                        .map_err(|_| anyhow::Error::new(AcceptTimedOut))??;
                    handle_tcp(tls).await
                }
                other => other,
            }
        }
        Accepted::Tcp(tls) => handle_tcp(*tls).await,
    }
}

/// No connection arrived within `serve_one_stdio`'s accept window.
#[derive(Debug)]
struct AcceptTimedOut;
impl std::fmt::Display for AcceptTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "timed out waiting for a connection")
    }
}
impl std::error::Error for AcceptTimedOut {}

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

/// Continuously accept unidirectional data streams from `conn`, boxing each and
/// forwarding it to `tx`. Exits when the connection closes or `tx` is dropped.
/// Used by the multipath feeder to merge data streams across bonded connections.
async fn drain_uni_streams(
    conn: quinn::Connection,
    tx: async_channel::Sender<Box<dyn AsyncRead + Unpin + Send + 'static>>,
) {
    // Exits when the connection errors/closes (accept_uni returns Err) or the
    // receiver has finished with all streams (send returns Err on a closed rx).
    while let Ok(s) = conn.accept_uni().await {
        if tx
            .send(Box::new(s) as Box<dyn AsyncRead + Unpin + Send + 'static>)
            .await
            .is_err()
        {
            break;
        }
    }
}

/// Handle one QUIC transfer.
///
/// `endpoint` enables **multipath** (M3): when `Some`, additional connections
/// arriving at the endpoint during this transfer are treated as extra bonded
/// paths — their data streams are merged with the primary connection's, so a
/// transfer can be striped across several connections. When `None`, only the
/// primary connection's data streams are used (classic single-path).
///
/// Multipath here is sequential: while this transfer runs, the feeder owns the
/// endpoint's incoming-connection accept. Concurrent multi-tenant transfers
/// (which need a transfer_id→path registry) arrive with the M4 daemon.
async fn handle_quic_connection(
    conn: quinn::Connection,
    endpoint: Option<quinn::Endpoint>,
    route: Route,
) -> Result<()> {
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

    // Expand the connection-level receive window for high-BDP links, mirroring
    // the sender's set_send_window adjustment.  RTT from the just-completed
    // QUIC handshake is close enough for window sizing before data starts.
    let rtt = conn.stats().path.rtt;
    let bdp_window = crate::net::connection::compute_bdp_window(rtt);
    let apply_window = |c: &quinn::Connection| {
        if bdp_window > crate::net::connection::CONNECTION_RECEIVE_WINDOW as u64 {
            if let Ok(w) = quinn::VarInt::from_u64(bdp_window) {
                c.set_receive_window(w);
            }
        }
    };
    apply_window(&conn);

    // Feeder: a channel of accepted data streams, fed by the primary connection
    // and (for multipath) any additional connections that arrive at the endpoint.
    let (tx, rx) = async_channel::unbounded::<Box<dyn AsyncRead + Unpin + Send + 'static>>();
    let mut feeders: JoinSet<()> = JoinSet::new();
    feeders.spawn(drain_uni_streams(conn.clone(), tx.clone()));
    if let Some(ep) = endpoint {
        // Accept extra bonded connections and drain their data streams too.
        let tx_extra = tx.clone();
        feeders.spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let tx = tx_extra.clone();
                tokio::spawn(async move {
                    if let Ok(c) = incoming.await {
                        apply_extra_path_window(&c);
                        drain_uni_streams(c, tx).await;
                    }
                });
            }
        });
    }
    drop(tx); // feeders hold their own clones; rx closes when they all exit

    let peer = peer_device_id(&conn);
    let result = run_receive(ctrl_send, ctrl_recv, route, peer, move |_transfer_id| {
        let rx = rx.clone();
        async move {
            rx.recv()
                .await
                .map_err(|_| anyhow!("data stream source closed before all streams arrived"))
        }
    })
    .await;
    feeders.abort_all();
    let mut ctrl_send = result?;

    // Gracefully close the control stream so the sender sees a clean FIN.
    let _ = ctrl_send.finish();
    let _ = conn.closed().await;
    Ok(())
}

/// Enlarge the receive window on an extra bonded path for high-BDP links.
fn apply_extra_path_window(c: &quinn::Connection) {
    let rtt = c.stats().path.rtt;
    let bdp_window = crate::net::connection::compute_bdp_window(rtt);
    if bdp_window > crate::net::connection::CONNECTION_RECEIVE_WINDOW as u64 {
        if let Ok(w) = quinn::VarInt::from_u64(bdp_window) {
            c.set_receive_window(w);
        }
    }
}

// ── Per-connection logic: TCP+TLS ─────────────────────────────────────────────

async fn handle_tcp_connection(
    ctrl_stream: ServerTlsStream<tokio::net::TcpStream>,
    listener: Arc<TcpListener>,
    acceptor: Arc<TlsAcceptor>,
    output_dir: PathBuf,
) -> Result<()> {
    let peer = tls_peer_device_id(&ctrl_stream);
    let (ctrl_recv, ctrl_send) = tokio::io::split(ctrl_stream);

    run_receive(
        ctrl_send,
        ctrl_recv,
        output_dir.into(),
        peer,
        move |_transfer_id| {
            let listener = Arc::clone(&listener);
            let acceptor = Arc::clone(&acceptor);
            async move {
                let (raw, _peer) = listener.accept().await.context("accept TCP data stream")?;
                raw.set_nodelay(true)?;
                let tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(raw))
                    .await
                    .map_err(|_| anyhow!("TLS handshake on data stream timed out"))?
                    .context("TLS handshake on data stream")?;
                Ok(Box::new(tls) as Box<dyn AsyncRead + Unpin + Send + 'static>)
            }
        },
    )
    .await?;
    Ok(())
}

// ── Concurrent TCP: routing data connections to transfers ─────────────────────

type DataStream = Box<dyn AsyncRead + Unpin + Send + 'static>;

/// How long a classified data connection waits for its transfer to start
/// accepting streams (the sender opens them right after `Ready`, a moment
/// before the receiver registers).
const TCP_ROUTE_WAIT: Duration = Duration::from_secs(10);

/// How long a connection may stay silent before it is taken to be an idle
/// pre-v7 data stream (when a legacy transfer from its IP is accepting streams).
const LEGACY_IDLE_PROBE: Duration = Duration::from_secs(2);

/// Which transfer a TCP data connection belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TcpRouteKey {
    /// v7+: named by the connection's `StreamHello`.
    Transfer([u8; 16]),
    /// Pre-v7 sender (no `StreamHello`): the single legacy transfer.
    Legacy,
}

/// Registry of in-progress TCP transfers on a shared listener, mapping each
/// to the channel its data connections are delivered on.
#[derive(Default)]
struct TcpStreamRouter {
    routes: Mutex<HashMap<TcpRouteKey, (std::net::IpAddr, async_channel::Sender<DataStream>)>>,
    changed: tokio::sync::Notify,
}

/// Unregisters a [`TcpStreamRouter`] route on drop.
struct TcpRouteGuard {
    router: Arc<TcpStreamRouter>,
    key: TcpRouteKey,
}

impl Drop for TcpRouteGuard {
    fn drop(&mut self) {
        self.router
            .routes
            .lock()
            .expect("tcp router mutex poisoned")
            .remove(&self.key);
        self.router.changed.notify_waiters();
    }
}

impl TcpStreamRouter {
    /// Start accepting data connections for `key` from `peer_ip`.
    fn register(
        self: &Arc<Self>,
        key: TcpRouteKey,
        peer_ip: std::net::IpAddr,
    ) -> Result<(async_channel::Receiver<DataStream>, TcpRouteGuard)> {
        let mut routes = self.routes.lock().expect("tcp router mutex poisoned");
        if routes.contains_key(&key) {
            bail!(match key {
                TcpRouteKey::Legacy => {
                    "another pre-v7 TCP transfer is already in progress on this receiver; \
                     retry once it finishes (or upgrade the sender)"
                }
                TcpRouteKey::Transfer(_) => {
                    "the same transfer is already in progress on this receiver"
                }
            });
        }
        let (tx, rx) = async_channel::unbounded();
        routes.insert(key, (peer_ip, tx));
        drop(routes);
        self.changed.notify_waiters();
        Ok((
            rx,
            TcpRouteGuard {
                router: Arc::clone(self),
                key,
            },
        ))
    }

    /// Whether `key` is registered for connections from `peer_ip`.
    fn has_route(&self, key: TcpRouteKey, peer_ip: std::net::IpAddr) -> bool {
        self.routes
            .lock()
            .expect("tcp router mutex poisoned")
            .get(&key)
            .is_some_and(|(ip, _)| *ip == peer_ip)
    }

    /// Hand a data connection to its transfer, waiting up to [`TCP_ROUTE_WAIT`]
    /// for the transfer to register.
    async fn deliver(
        &self,
        key: TcpRouteKey,
        peer_ip: std::net::IpAddr,
        stream: DataStream,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + TCP_ROUTE_WAIT;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let route = self
                .routes
                .lock()
                .expect("tcp router mutex poisoned")
                .get(&key)
                .cloned();
            if let Some((ip, tx)) = route {
                if ip != peer_ip {
                    bail!("data connection from {peer_ip} for a transfer controlled from {ip}");
                }
                return tx
                    .send(stream)
                    .await
                    .map_err(|_| anyhow!("transfer ended before this data connection arrived"));
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                bail!("no transfer in progress for this data connection");
            }
        }
    }
}

/// What a TCP connection on a shared listener turned out to be.
enum TcpConnKind {
    Control { legacy: bool },
    Data(TcpRouteKey),
}

/// TLS-handshake one connection from the shared listener, classify it by its
/// first frame and either run its transfer (control) or hand it to its
/// transfer (data).
async fn serve_routed_tcp_connection(
    raw: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    acceptor: Arc<TlsAcceptor>,
    router: Arc<TcpStreamRouter>,
    output_dir: PathBuf,
) -> Result<()> {
    use tokio::io::AsyncReadExt;

    raw.set_nodelay(true)?;
    let mut tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(raw))
        .await
        .map_err(|_| anyhow!("TLS handshake timed out"))?
        .context("TLS handshake")?;

    // Classify by the first frame's length: a NegotiateRequest and a
    // StreamHello have fixed bincode sizes that no ChunkData frame can match.
    let neg_len = bincode::serialized_size(&NegotiateRequest {
        cpu_cores: 0,
        protocol_version: 0,
    })? as u32;
    let hello_len = bincode::serialized_size(&crate::protocol::messages::StreamHello {
        transfer_id: [0; 16],
        stream_seq: 0,
    })? as u32;
    let peer_ip = peer_addr.ip();
    let mut prefix = vec![0u8; 4];
    let mut filled = 0;
    let deadline = tokio::time::Instant::now() + HANDSHAKE_READ_TIMEOUT;
    while filled < 4 {
        // A pre-v7 sender's data connection has no StreamHello and may have
        // nothing to send yet (e.g. a resume with fewer missing chunks than
        // streams) — or close straight away. If its legacy transfer from this
        // IP is waiting for streams, hand the connection over as-is instead of
        // dropping it. v7 senders always speak first, right after the handshake.
        let read = tokio::time::timeout(LEGACY_IDLE_PROBE, tls.read(&mut prefix[filled..])).await;
        // A peer that closes without a TLS close_notify reads as UnexpectedEof.
        let eof = match &read {
            Ok(Ok(0)) => true,
            Ok(Err(e)) => e.kind() == std::io::ErrorKind::UnexpectedEof,
            _ => false,
        };
        match read {
            Ok(Ok(n)) if n > 0 => {
                filled += n;
                continue;
            }
            Ok(Err(e)) if !eof => return Err(e).context("read first frame"),
            _ => {}
        }
        if router.has_route(TcpRouteKey::Legacy, peer_ip) {
            prefix.truncate(filled);
            let stream = std::io::Cursor::new(prefix).chain(tls);
            return router
                .deliver(TcpRouteKey::Legacy, peer_ip, Box::new(stream))
                .await;
        }
        if eof {
            bail!("connection closed before its first frame");
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "timed out after {}s waiting for first frame",
                HANDSHAKE_READ_TIMEOUT.as_secs()
            );
        }
    }
    let len = u32::from_le_bytes(prefix[..4].try_into().expect("4 bytes"));
    let kind = if len == neg_len || len == hello_len {
        prefix.resize(4 + len as usize, 0);
        handshake_read("first frame", async {
            tls.read_exact(&mut prefix[4..])
                .await
                .context("read first frame")
        })
        .await?;
        if len == neg_len {
            let req: NegotiateRequest = bincode::deserialize(&prefix[4..])?;
            TcpConnKind::Control {
                legacy: !crate::protocol::messages::stream_hello_active(
                    crate::protocol::messages::advertised_version(),
                    req.protocol_version,
                ),
            }
        } else {
            let hello: crate::protocol::messages::StreamHello = bincode::deserialize(&prefix[4..])?;
            TcpConnKind::Data(TcpRouteKey::Transfer(hello.transfer_id))
        }
    } else {
        // Pre-v7 data connection: starts straight with a chunk frame.
        TcpConnKind::Data(TcpRouteKey::Legacy)
    };

    match kind {
        TcpConnKind::Data(key) => {
            // Re-prepend what we consumed: run_receive re-reads (and validates)
            // the StreamHello itself.
            let stream = std::io::Cursor::new(prefix).chain(tls);
            router.deliver(key, peer_ip, Box::new(stream)).await
        }
        TcpConnKind::Control { legacy } => {
            info!("TCP transfer from {peer_addr}");
            let peer = tls_peer_device_id(&tls);
            let (ctrl_recv, ctrl_send) = tokio::io::split(tls);
            let ctrl_recv = std::io::Cursor::new(prefix).chain(ctrl_recv);
            let mut route: Option<(async_channel::Receiver<DataStream>, TcpRouteGuard)> = None;
            run_receive(
                ctrl_send,
                ctrl_recv,
                output_dir.into(),
                peer,
                move |transfer_id| {
                    let rx = match &route {
                        Some((rx, _)) => Ok(rx.clone()),
                        None => {
                            let key = if legacy {
                                TcpRouteKey::Legacy
                            } else {
                                TcpRouteKey::Transfer(transfer_id)
                            };
                            router.register(key, peer_ip).map(|(rx, guard)| {
                                route = Some((rx.clone(), guard));
                                rx
                            })
                        }
                    };
                    async move {
                        rx?.recv()
                            .await
                            .map_err(|_| anyhow!("TCP data stream router closed"))
                    }
                },
            )
            .await?;
            Ok(())
        }
    }
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

/// Shared FEC stripe state across all stream workers.
#[derive(Default)]
struct FecStripes {
    /// Stripes still accumulating shards.
    bufs: HashMap<u32, StripeBuffer>,
    /// Stripes already extracted for processing.  Shards arriving after their
    /// stripe completed (typically surplus parity) are dropped instead of
    /// starting a fresh `StripeBuffer` that would either leak (never becoming
    /// ready) or reconstruct and rewrite the stripe a second time.
    done: std::collections::HashSet<u32>,
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
            // Parity metadata describes every data shard of the stripe; a
            // mismatched count would index out of bounds in process_stripe.
            if fcd.shard_lengths.len() != self.data_shards
                || fcd.shard_compressed.len() != self.data_shards
            {
                bail!(
                    "FEC stripe {}: parity metadata has {}/{} entries, expected {}",
                    self.stripe_index,
                    fcd.shard_lengths.len(),
                    fcd.shard_compressed.len(),
                    self.data_shards
                );
            }
            if self.parity[j].is_none() {
                self.parity[j] = Some(fcd.payload);
                self.received_parity += 1;
            }
            // All parity shards for the same stripe carry identical metadata;
            // store it once from whichever arrives first.
            if self.shard_lengths.is_none() {
                self.shard_lengths = Some(fcd.shard_lengths);
                self.shard_compressed_flags = Some(fcd.shard_compressed);
            }
        } else {
            let i = fcd.shard_index_in_stripe as usize;
            // Only the first `real_data_count` positions carry real chunks; the
            // rest of a short last stripe is synthetic padding that is never
            // sent.  Accepting a shard there would count towards `is_ready`
            // while a real slot is still empty (and panic in process_stripe).
            if i >= self.real_data_count {
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

    /// True when we have enough shards to reconstruct all real file chunks.
    ///
    /// Reed-Solomon needs `data_shards` shards *present* to reconstruct.  For the
    /// last (partial) stripe `process_stripe` injects the `data_shards −
    /// real_data_count` trailing positions as synthetic zero shards (they are
    /// known, not transmitted), so the number that still has to arrive over the
    /// wire is `data_shards − (data_shards − real_data_count) = real_data_count`.
    /// Hence the threshold below is `real_data_count`, not `data_shards` — the
    /// two are equal for full stripes, so this is *correct*, not a premature
    /// trigger.  Keep it in sync with the synthetic-shard fill in `process_stripe`.
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
/// Returns the pwrite duration in µs so callers can report disk latency without
/// including the resume-state fsync that follows.
fn write_fec_chunk(
    chunk_index: u64,
    payload: &[u8],
    compressed: bool,
    expected_hash: Option<[u8; 32]>,
    chunk_size: usize,
    file_size: u64,
    out_file: &std::fs::File,
    resume: &Mutex<ResumeState>,
    hasher: &Option<Arc<ChunkHasher>>,
    pb: &ProgressBar,
    progress_tx: &tokio::sync::mpsc::Sender<u64>,
    deferred: &crate::fs_ext::DeferredDontneed,
) -> Result<u32> {
    let data = if compressed {
        compress::decompress_chunk(payload, chunk_size)
            .with_context(|| format!("decompress FEC chunk {chunk_index}"))?
    } else {
        payload.to_vec()
    };
    let want = expected_chunk_len(chunk_index, chunk_size, file_size);
    if data.len() != want {
        bail!(
            "FEC chunk {chunk_index}: {} bytes, expected {want}",
            data.len()
        );
    }

    let computed: [u8; 32] = *blake3::hash(&data).as_bytes();
    if let Some(expected) = expected_hash {
        if computed != expected {
            // Drop the corrupt shard rather than aborting the transfer; the
            // chunk stays unmarked in resume and is recovered at the completion
            // checkpoint (in-band repair on v5, or a resumed rerun otherwise).
            warn!(
                chunk = chunk_index,
                "FEC data shard hash mismatch; dropping (will be repaired or re-fetched)"
            );
            if let Some(h) = hasher {
                h.abandon();
            }
            return Ok(0);
        }
    }

    let offset = chunk_index * chunk_size as u64;
    let write_start = std::time::Instant::now();
    crate::fs_ext::write_all_at_deferred(out_file, &data, offset, deferred)
        .with_context(|| format!("write FEC chunk {chunk_index} at offset {offset}"))?;
    let write_us = write_start.elapsed().as_micros() as u32;

    if let Some(h) = hasher {
        h.feed(chunk_index, computed)?;
    }
    let n = data.len() as u64;
    pb.inc(n);
    let _ = progress_tx.try_send(n);

    let snap = {
        let mut r = resume.lock().expect("resume-state mutex poisoned");
        r.mark_received(chunk_index);
        if r.incr_dirty() >= RESUME_SAVE_BATCH {
            r.reset_dirty();
            Some(r.snapshot()?)
        } else {
            None
        }
    };
    if let Some(snap) = snap {
        snap.write_to_disk_best_effort();
    }

    debug!(chunk = chunk_index, "FEC chunk written");
    Ok(write_us)
}

/// Process a completed stripe: write directly received data shards and use
/// RS reconstruction for any missing ones.
///
/// Designed to run in `spawn_blocking`; all I/O is synchronous.
#[allow(clippy::too_many_arguments)]
/// Returns the peak pwrite duration (µs) across all chunks in the stripe so
/// callers can update disk-latency stats without including the resume-state
/// fsync that follows each write.
fn process_stripe(
    stripe: StripeBuffer,
    chunk_size: usize,
    file_size: u64,
    out_file: Arc<std::fs::File>,
    resume: Arc<Mutex<ResumeState>>,
    hasher: Option<Arc<ChunkHasher>>,
    pb: Arc<ProgressBar>,
    progress_tx: tokio::sync::mpsc::Sender<u64>,
    deferred: crate::fs_ext::DeferredDontneed,
) -> Result<u32> {
    let data_shards = stripe.data_shards;
    let parity_shards = stripe.parity_shards;
    let real_data_count = stripe.real_data_count;
    let first_chunk = stripe.stripe_index as u64 * data_shards as u64;

    if stripe.received_data == real_data_count && stripe.shard_lengths.is_none() {
        // Happy path: all real data shards arrived; no RS needed.
        let mut peak_write_us = 0u32;
        for i in 0..real_data_count {
            let (payload, hash, compressed) = stripe.data[i].as_ref().unwrap();
            let write_us = write_fec_chunk(
                first_chunk + i as u64,
                payload,
                *compressed,
                Some(*hash),
                chunk_size,
                file_size,
                &out_file,
                &resume,
                &hasher,
                &pb,
                &progress_tx,
                &deferred,
            )?;
            peak_write_us = peak_write_us.max(write_us);
        }
        return Ok(peak_write_us);
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

    let mut peak_write_us = 0u32;
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
        let write_us = write_fec_chunk(
            first_chunk + i as u64,
            payload,
            compressed,
            expected_hash,
            chunk_size,
            file_size,
            &out_file,
            &resume,
            &hasher,
            &pb,
            &progress_tx,
            &deferred,
        )?;
        peak_write_us = peak_write_us.max(write_us);
    }

    Ok(peak_write_us)
}

// ── Shared transfer body ──────────────────────────────────────────────────────

/// Core receive logic shared by both the QUIC and TCP paths.
///
/// Handles the full negotiation → manifest → data transfer → verification flow.
/// `accept_stream` is a factory called once per data stream (with the
/// manifest's `transfer_id`, for transports that route streams by it); it must return a
/// future that yields a readable stream (QUIC `RecvStream` or TCP+TLS stream).
///
/// Returns the write half of the control stream so the QUIC caller can send
/// a graceful FIN; TCP callers may discard it.
async fn run_receive<CW, CR, F, Fut>(
    mut ctrl_send: CW,
    mut ctrl_recv: CR,
    route: Route,
    peer: Option<String>,
    mut accept_stream: F,
) -> Result<CW>
where
    CW: tokio::io::AsyncWrite + Unpin + Send + 'static,
    CR: tokio::io::AsyncRead + Unpin + Send + 'static,
    F: FnMut([u8; 16]) -> Fut,
    Fut: Future<Output = Result<Box<dyn AsyncRead + Unpin + Send + 'static>>> + Send + 'static,
{
    let Route {
        output_dir,
        budget,
        observer,
    } = route;
    // The opening flight (NegotiateRequest, manifest, DirEntries) is sent by the
    // sender immediately after connecting; bound each read so a peer that
    // connects and goes silent (or stalls mid-frame after claiming a large
    // length) cannot pin this task and its buffer forever.
    let neg_req: NegotiateRequest = handshake_read(
        "NegotiateRequest",
        framing::recv_message_required(&mut ctrl_recv),
    )
    .await?;
    // v7+ senders prefix each data stream with a StreamHello frame; only read it
    // when both peers negotiated ≥ v7 (older senders never send it).
    let expect_hello = crate::protocol::messages::stream_hello_active(
        crate::protocol::messages::advertised_version(),
        neg_req.protocol_version,
    );
    let receiver_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4) as u32;
    framing::send_message(
        &mut ctrl_send,
        &NegotiateResponse {
            cpu_cores: receiver_cores,
            protocol_version: crate::protocol::messages::advertised_version(),
        },
    )
    .await?;
    debug!(
        sender_cores = neg_req.cpu_cores,
        receiver_cores, "negotiation complete"
    );

    // The manifest is small and fixed-shape (directory entries travel
    // separately in DirEntries), so the 1 MiB control cap is ample.
    let manifest: TransferManifest =
        handshake_read("TransferManifest", framing::recv_message(&mut ctrl_recv))
            .await?
            .ok_or_else(|| anyhow::anyhow!("stream closed before TransferManifest"))?;
    validate_manifest(&manifest)?;

    // Protocol version 3+: read DirEntries immediately after the manifest.
    // v2 senders don't send this message; skip the read for them.
    let dir_entries: Option<Vec<FileEntry>> =
        if crate::protocol::messages::directory_supported(neg_req.protocol_version) {
            let de: DirEntries = handshake_read(
                "DirEntries",
                framing::recv_message_limited(&mut ctrl_recv, MAX_DIR_ENTRIES_FRAME),
            )
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

    // Track the transfer from here on, so refusals below are recorded too.
    let mut job = observer.as_deref().map(|o| JobGuard::start(o, &manifest));

    // Tell the sender (and the job) why the transfer is refused, then fail.
    macro_rules! refuse {
        ($e:expr) => {{
            let e: anyhow::Error = $e;
            let message = format!("{e:#}");
            let _ = framing::send_message(
                &mut ctrl_send,
                &ReceiverMessage::Error {
                    message: message.clone(),
                    fatal: true,
                },
            )
            .await;
            if let Some(j) = job.take() {
                j.fail(&message);
            }
            return Err(e);
        }};
    }

    // Admission: reserve the bytes this transfer adds against the peer's quota
    // (atomically with concurrent transfers from the same peer). Held until the
    // output is preallocated, after which the files count as used on disk.
    let reservation = match budget {
        Some(budget) => {
            let incoming = new_bytes_needed(&output_dir, &manifest, dir_entries.as_deref());
            match tokio::task::spawn_blocking(move || budget.reserve(incoming))
                .await
                .context("quota task panicked")
                .and_then(|r| r)
            {
                Ok(r) => Some(r),
                Err(e) => refuse!(e),
            }
        }
        None => None,
    };

    // Refuse a second concurrent transfer into the same destination: two
    // writers (each with its own resume state) would interleave chunks
    // undetected.  Held until this function returns.
    let dest_guard =
        match claim_destination(&output_dir, &manifest.file_name, manifest.transfer_id, peer).await
        {
            Ok(g) => g,
            Err(e) => refuse!(e),
        };

    // On failure, send the error to the sender before closing so the sender
    // shows the actual filesystem error instead of "connection lost".
    let pt = match prepare_transfer(&manifest, dir_entries.as_deref(), &output_dir) {
        Ok(pt) => pt,
        Err(e) => refuse!(e),
    };
    drop(reservation);
    dest_guard.track_writes(&pt);
    let cancelled = dest_guard.cancelled();
    framing::send_message(
        &mut ctrl_send,
        &ReceiverMessage::Ready {
            received_bits: pt.received_bits,
            total_chunks: manifest.total_chunks,
        },
    )
    .await?;
    pt.pb.set_position(pt.bytes_already_received);
    if let Some(j) = &mut job {
        j.track_progress(Arc::clone(&pt.pb));
    }

    // The rest of the transfer runs cancellably: a reconnect of the same
    // sender (see `claim_destination`) drops it, closing its streams. Its
    // blocking writes finish on their own; the next claim waits for them.
    let body = async move {
        // Progress channel: data workers → reporter → ctrl_send (throttled to 100 ms).
        let (progress_tx, progress_rx) = tokio::sync::mpsc::channel::<u64>(256);
        // Keep one extra clone for scale-up workers added during transfer.
        // Dropped after the main loop to let the reporter exit once all workers finish.
        let scale_progress_tx = progress_tx.clone();

        // Ack channel: main loop → reporter → ctrl_send (AdjustStreamsAck messages).
        let (ack_req_tx, ack_req_rx) = tokio::sync::mpsc::channel::<u8>(8);

        // Ctrl-reader channels: ctrl_reader_task forwards SenderMessage variants
        // received during the data phase to the main loop.  It returns the control
        // recv half + Complete hash via its JoinHandle so the repair handshake can
        // read further frames after the data phase.
        let (scale_req_tx, mut scale_req_rx) = tokio::sync::mpsc::channel::<u8>(8);

        // Shared metrics: in-flight task count and peak disk latency.
        let stats = ReceiverStats::new();

        // Global semaphore that caps concurrent pwrite operations across all stream
        // workers.  Without this, N streams × MAX_IN_FLIGHT tasks each writing an
        // 8 MiB chunk can generate 256+ MiB of dirty pages simultaneously, causing
        // the kernel to stall pwrite callers while it flushes.  Limiting to 8
        // concurrent writers keeps peak dirty pages at ~64 MiB, well below the
        // kernel's dirty_ratio threshold on typical systems.
        let write_sem = Arc::new(tokio::sync::Semaphore::new(8));

        // Deferred FADV_DONTNEED tracker: shared by all stream workers writing to
        // the same output file.  Issuing DONTNEED immediately after sync_file_range
        // can stall if the block layer hasn't dispatched the submitted I/O yet;
        // the deferred tracker waits for a lookahead of later writes before evicting
        // each range from the page cache.
        let deferred_dontneed = match &pt.out_file {
            Some(f) => crate::fs_ext::DeferredDontneed::new(f),
            None => crate::fs_ext::DeferredDontneed::noop(), // directory mode: no single fd
        };

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
            let fut = accept_stream(manifest.transfer_id);
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
        let fec_stripe_bufs: Option<Arc<Mutex<FecStripes>>> = if manifest.fec.is_some() {
            Some(Arc::new(Mutex::new(FecStripes::default())))
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
            let dd = deferred_dontneed.clone();
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
                        dd,
                        expect_hello,
                    )
                    .await
                });
            } else {
                tasks.spawn(async move {
                    recv_stream_worker(
                        stream,
                        out_file,
                        layout,
                        resume,
                        manifest_c,
                        pb,
                        hasher,
                        ptx,
                        st,
                        wsem,
                        dd,
                        expect_hello,
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
        let ctrl_reader = tokio::spawn(ctrl_reader_task(ctrl_recv, scale_req_tx));

        // Main transfer loop: drain worker tasks and handle dynamic stream scaling.
        let mut task_err: Option<anyhow::Error> = None;
        let mut active_workers = manifest.num_streams;
        let mut current_workers = manifest.num_streams;

        loop {
            tokio::select! {
                Some(join_res) = tasks.join_next() => {
                    let r = join_res.unwrap_or_else(|e| Err(anyhow!("stream worker panicked: {e}")));
                    if let Err(e) = r {
                        // Log immediately so the operator sees which stream/chunk
                        // failed even if the error is later superseded by the
                        // cascade (e.g. "receiver closed without completing").
                        error!(error = format!("{e:#}"), "receive worker failed");
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
                            let fut = accept_stream(manifest.transfer_id);
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
                                    let dd = deferred_dontneed.clone();
                                    tasks.spawn(async move {
                                        recv_stream_worker(
                                            stream, out_file, layout, resume, manifest_c, pb, hasher,
                                            ptx, st, wsem, dd, expect_hello,
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
                        let _ = ack_req_tx
                            .send(crate::transfer::negotiate::stream_count_u8(accepted))
                            .await;
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
                        let _ = ack_req_tx
                            .send(crate::transfer::negotiate::stream_count_u8(target))
                            .await;
                    }
                }
            }
        }
        // Let the reporter know no more workers will be added (closes channel).
        drop(scale_progress_tx);
        pt.pb.finish();

        // Flush any ranges still in the deferred DONTNEED queue now that all
        // writes have completed and the block device has had time to drain them.
        deferred_dontneed.flush();
        if let Some(ref cl) = pt.layout {
            cl.close_files();
        }

        // Reporter closes when all workers finish (progress_tx fully dropped).
        // Wait for it to return ctrl_send.
        let mut ctrl_send = reporter.await.context("progress reporter panicked")??;

        // A hard worker failure (panic, disk error, malformed frame) is fatal and
        // not repairable — surface it immediately.
        if let Some(e) = task_err {
            let _ = framing::send_message(
                &mut ctrl_send,
                &ReceiverMessage::Error {
                    message: e.to_string(),
                    fatal: true,
                },
            )
            .await;
            bail!("{e}");
        }

        // Reclaim the control recv half + the sender's first Complete hash.
        let (mut ctrl_recv, hash_opt) = ctrl_reader.await.context("ctrl reader task panicked")?;
        let mut expected_hash =
            hash_opt.ok_or_else(|| anyhow!("sender closed without sending Complete"))?;

        // ── Incremental repair (protocol v5) ──────────────────────────────────────
        //
        // Some chunks may be missing from disk: a dropped corrupt chunk, or an FEC
        // stripe that could not be reconstructed.  Rather than fail outright, ask
        // the sender (over the still-open control stream) to re-send exactly those
        // chunks as plain ChunkData, keeping the connection and its warmed
        // congestion window alive.  Works for single-file (pwrite to the output fd)
        // and directory transfers (scatter-write across the concat layout); bounded
        // by MAX_REPAIR_ROUNDS.
        let repairable = crate::protocol::messages::repair_supported(neg_req.protocol_version)
            && (pt.out_file.is_some() || pt.layout.is_some());
        let mut repaired = false;
        let mut round = 0u32;
        // `repairable` is fixed, but each iteration either breaks or writes repaired
        // chunks into resume state and is bounded by MAX_REPAIR_ROUNDS — not infinite.
        #[allow(clippy::while_immutable_condition)]
        while repairable {
            let missing = pt
                .resume
                .lock()
                .expect("resume-state mutex poisoned")
                .missing_chunks();
            if missing.is_empty() {
                break;
            }
            round += 1;
            if round > crate::protocol::messages::MAX_REPAIR_ROUNDS
                || missing.len() > crate::protocol::messages::MAX_REPAIR_CHUNKS_PER_ROUND
            {
                // Too much missing or too many rounds — stop and let the explicit
                // missing-chunk error below fire (resume recovers on rerun).
                break;
            }
            info!(round, count = missing.len(), "requesting in-band repair");
            pt.pb
                .set_message(format!("repairing {} chunk(s)…", missing.len()));
            let want = missing.len();
            framing::send_message(
                &mut ctrl_send,
                &ReceiverMessage::Retransmit { chunks: missing },
            )
            .await?;

            // Read exactly that many ChunkData repair frames, then the sender's
            // follow-up Complete (which re-syncs us for the next round).
            for _ in 0..want {
                let cd = framing::recv_chunk_data(&mut ctrl_recv)
                    .await?
                    .ok_or_else(|| anyhow!("sender closed control stream mid-repair"))?;
                write_repair_chunk(
                    &cd,
                    pt.out_file.as_ref(),
                    pt.layout.as_ref(),
                    &pt.resume,
                    &manifest,
                    &pt.pb,
                )
                .await?;
            }
            repaired = true;
            match framing::recv_message::<_, SenderMessage>(&mut ctrl_recv).await? {
                Some(SenderMessage::Complete { file_hash }) => expected_hash = file_hash,
                _ => bail!("sender closed control stream without re-Complete after repair"),
            }
        }

        // If chunks are still missing (repair unavailable, exhausted, or too large),
        // report an attributable error before the generic whole-file hash check.
        let still_missing = pt
            .resume
            .lock()
            .expect("resume-state mutex poisoned")
            .missing_chunks();
        if !still_missing.is_empty() {
            let e = missing_chunks_error(&still_missing, &manifest);
            let _ = framing::send_message(
                &mut ctrl_send,
                &ReceiverMessage::Error {
                    message: e.to_string(),
                    fatal: true,
                },
            )
            .await;
            bail!("{e}");
        }

        // After any repair, per-chunk hashes fed to the ChunkHasher are incomplete
        // (repaired chunks bypassed it), so force a from-disk rehash by passing None.
        let hasher = if repaired { None } else { pt.hasher };

        // Directory mode: close the cached output handles (flushing their deferred
        // DONTNEED) before the from-disk hash and metadata pass.
        if let Some(ref cl) = pt.layout {
            cl.close_files();
        }

        finish_transfer(
            &mut ctrl_send,
            pt.resume,
            hasher,
            pt.layout,
            &output_dir,
            &manifest,
            expected_hash,
        )
        .await?;

        if let Some(job) = job {
            let files = transfer_files(&output_dir, &manifest, dir_entries.as_deref());
            job.completed(manifest.file_size, files).await;
        }

        Ok(ctrl_send)
    };
    let result = tokio::select! {
        r = body => r,
        _ = cancelled.notified() => Err(anyhow!(
            "transfer superseded: the same sender reconnected to resume it"
        )),
    };
    drop(dest_guard);
    result
}

/// Exact byte length of chunk `idx` (`< total_chunks`): `chunk_size`, except a
/// shorter final chunk.
fn expected_chunk_len(idx: u64, chunk_size: usize, file_size: u64) -> usize {
    let offset = idx.saturating_mul(chunk_size as u64);
    file_size.saturating_sub(offset).min(chunk_size as u64) as usize
}

/// Build an attributable error naming the chunks (and, for FEC, stripes) that
/// never landed on disk after the transfer and any repair attempts.
fn missing_chunks_error(missing: &[u64], manifest: &TransferManifest) -> anyhow::Error {
    if let Some(fec) = &manifest.fec {
        let data_shards = fec.data_shards.max(1) as u64;
        let mut stripes: Vec<u64> = missing.iter().map(|c| c / data_shards).collect();
        stripes.dedup();
        let shown: Vec<String> = stripes
            .iter()
            .take(8)
            .map(|s| {
                let first = s * data_shards;
                format!("#{s} (chunks {}..{})", first, first + data_shards)
            })
            .collect();
        let more = stripes.len().saturating_sub(shown.len());
        let suffix = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        anyhow!(
            "FEC reconstruction failed: {} chunk(s) across {} stripe(s) could not \
             be recovered even after repair: {}{}. The link likely dropped more \
             shards than the parity level tolerates — retry, or raise --fec parity.",
            missing.len(),
            stripes.len(),
            shown.join(", "),
            suffix
        )
    } else {
        let shown: Vec<String> = missing.iter().take(8).map(|c| format!("#{c}")).collect();
        let more = missing.len().saturating_sub(shown.len());
        let suffix = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        anyhow!(
            "{} chunk(s) missing after transfer: {}{} — retry; a resumed rerun \
             will re-fetch only the missing chunks.",
            missing.len(),
            shown.join(", "),
            suffix
        )
    }
}

/// Verify, write, and mark a single chunk received during the v5 repair phase.
///
/// Handles both single-file transfers (pwrite the chunk to `out_file` at its
/// global offset) and directory transfers (scatter-write across the concat
/// `layout`, which a chunk may span when it packs several small files).
async fn write_repair_chunk(
    cd: &ChunkData,
    out_file: Option<&Arc<std::fs::File>>,
    layout: Option<&Arc<ConcatLayout>>,
    resume: &Arc<Mutex<ResumeState>>,
    manifest: &TransferManifest,
    pb: &ProgressBar,
) -> Result<()> {
    let chunk_size = manifest.chunk_size;
    // The repair frame is peer-supplied: it must name a chunk of this transfer
    // and carry exactly that chunk's length, or it could write past the file
    // (or another file of a directory) and index the resume bitvector OOB.
    if cd.chunk_index >= manifest.total_chunks {
        bail!(
            "repair chunk index {} out of range (total_chunks {})",
            cd.chunk_index,
            manifest.total_chunks
        );
    }
    if cd.transfer_id != manifest.transfer_id {
        bail!("repair chunk {}: transfer_id mismatch", cd.chunk_index);
    }
    let data = if cd.compressed {
        compress::decompress_chunk(&cd.payload, chunk_size)
            .with_context(|| format!("decompress repair chunk {}", cd.chunk_index))?
    } else {
        cd.payload.clone()
    };
    let want = expected_chunk_len(cd.chunk_index, chunk_size, manifest.file_size);
    if data.len() != want {
        bail!(
            "repair chunk {}: {} bytes, expected {want}",
            cd.chunk_index,
            data.len()
        );
    }
    let computed: [u8; 32] = *blake3::hash(&data).as_bytes();
    if computed != cd.chunk_hash {
        bail!("repair chunk {} failed hash verification", cd.chunk_index);
    }
    let n = data.len() as u64;
    let chunk_index = cd.chunk_index;
    match (layout, out_file) {
        // Directory transfer: scatter the chunk across the file(s) it spans.
        (Some(layout), _) => {
            let layout = Arc::clone(layout);
            tokio::task::spawn_blocking(move || {
                layout.scatter_write(chunk_index, chunk_size, &data)
            })
            .await
            .context("repair scatter-write task panicked")?
            .with_context(|| format!("scatter-write repair chunk {chunk_index}"))?;
        }
        // Single-file transfer: pwrite at the chunk's global offset.
        (None, Some(out_file)) => {
            let offset = chunk_index * chunk_size as u64;
            let f = Arc::clone(out_file);
            tokio::task::spawn_blocking(move || crate::fs_ext::write_all_at(&f, &data, offset))
                .await
                .context("repair write task panicked")?
                .with_context(|| format!("write repair chunk {chunk_index} at offset {offset}"))?;
        }
        (None, None) => bail!("repair chunk {chunk_index}: no output target available"),
    }
    // Persist the resume bit immediately — repair sets are small, so the
    // per-chunk fsync cost is negligible and it keeps the bitvector accurate.
    let snap = {
        let mut r = resume.lock().expect("resume-state mutex poisoned");
        r.mark_received(chunk_index);
        r.snapshot()?
    };
    snap.write_to_disk_best_effort();
    pb.inc(n);
    Ok(())
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
    /// Small MRU cache of open output files, keyed by `file_entries` index.
    /// Consecutive chunks usually land in the same file (or neighbouring small
    /// ones), so this avoids an open/close per file segment per chunk.
    open_files: Mutex<std::collections::VecDeque<(usize, Arc<CachedFile>)>>,
}

/// How many directory-mode output files [`ConcatLayout`] keeps open at once.
const OPEN_FILE_CACHE: usize = 16;

/// An open output file plus its own deferred-DONTNEED tracker (the same
/// lookahead mechanism the single-file path uses, instead of an immediate
/// DONTNEED per write).  The tracker holds the raw fd, so it is flushed in
/// `Drop` *before* the `File` field closes it — and is never cloned out.
struct CachedFile {
    deferred: crate::fs_ext::DeferredDontneed,
    file: std::fs::File,
}

impl Drop for CachedFile {
    fn drop(&mut self) {
        self.deferred.flush();
    }
}

impl std::fmt::Debug for CachedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedFile")
            .field("file", &self.file)
            .finish()
    }
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
            open_files: Mutex::new(std::collections::VecDeque::with_capacity(OPEN_FILE_CACHE)),
        }
    }

    /// Return an open handle for `file_entries[fi]`, from the cache or freshly
    /// opened (evicting the least recently used entry when full).
    fn open_file(&self, fi: usize) -> Result<Arc<CachedFile>> {
        {
            let mut cache = self.open_files.lock().expect("open-file cache poisoned");
            if let Some(pos) = cache.iter().position(|(i, _)| *i == fi) {
                let entry = cache.remove(pos).expect("position is in range");
                let f = Arc::clone(&entry.1);
                cache.push_front(entry);
                return Ok(f);
            }
        }
        // Open outside the lock so a slow open doesn't serialise other writers.
        let path = self.base_dir.join(&self.file_entries[fi].path);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let cached = Arc::new(CachedFile {
            deferred: crate::fs_ext::DeferredDontneed::new(&file),
            file,
        });
        let evicted = {
            let mut cache = self.open_files.lock().expect("open-file cache poisoned");
            // Another writer may have opened the same file meanwhile; either
            // handle works, keep the one already cached.
            if let Some((_, f)) = cache.iter().find(|(i, _)| *i == fi) {
                return Ok(Arc::clone(f));
            }
            cache.push_front((fi, Arc::clone(&cached)));
            if cache.len() > OPEN_FILE_CACHE {
                cache.pop_back()
            } else {
                None
            }
        };
        // Dropped (flushing its DONTNEED queue and closing) outside the lock,
        // or later by whichever writer still holds it.
        drop(evicted);
        Ok(cached)
    }

    /// Close all cached handles (flushing their deferred DONTNEED ranges).
    /// Called once writes are done, before metadata is applied.
    fn close_files(&self) {
        let drained: Vec<_> = self
            .open_files
            .lock()
            .expect("open-file cache poisoned")
            .drain(..)
            .collect();
        drop(drained);
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

            let cf = self.open_file(fi)?;
            crate::fs_ext::write_all_at_deferred(
                &cf.file,
                &data[written..written + take],
                offset_in_file,
                &cf.deferred,
            )
            .with_context(|| {
                format!(
                    "pwrite {} at offset {offset_in_file}",
                    self.file_entries[fi].path
                )
            })?;

            written += take;
            fi += 1;
        }

        Ok(())
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Where a routed connection's files land, how many new bytes it may add, and
/// who to tell about its progress.
#[derive(Clone)]
pub struct Route {
    pub output_dir: PathBuf,
    /// Byte quota the transfer's new on-disk bytes are reserved against once
    /// its manifest is read (refused if they don't fit). `None` = unlimited.
    pub budget: Option<Arc<dyn ByteBudget>>,
    /// Lifecycle hooks for the transfer on this connection (the daemon's queue
    /// and at-rest encryption).
    pub observer: Option<Arc<dyn TransferObserver>>,
}

impl From<PathBuf> for Route {
    fn from(output_dir: PathBuf) -> Self {
        Route {
            output_dir,
            budget: None,
            observer: None,
        }
    }
}

/// A byte quota transfers reserve against (see [`Route::budget`]).
pub trait ByteBudget: Send + Sync {
    /// Atomically check that `bytes` more fit — counting other reservations
    /// still outstanding — and hold them until the returned guard is dropped.
    /// May block (e.g. to measure current usage).
    fn reserve(&self, bytes: u64) -> Result<Box<dyn Send>>;
}

/// Per-transfer lifecycle hooks a server's owner can attach through [`Route`].
pub trait TransferObserver: Send + Sync {
    /// A transfer was admitted and is about to receive data. `total_bytes` is
    /// the payload size (all files, for a directory).
    fn started(&self, file_name: &str, total_bytes: u64) -> Arc<dyn TransferJob>;
}

/// One observed transfer (see [`TransferObserver`]).
pub trait TransferJob: Send + Sync {
    /// Bytes received so far (called about once a second).
    fn progress(&self, bytes_done: u64);
    /// The transfer verified and was acknowledged; `files` are the regular
    /// files it wrote. Awaited while the destination is still claimed, so
    /// post-processing (e.g. encrypting them) can't race a new transfer to the
    /// same target.
    fn completed(&self, files: Vec<PathBuf>) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;
    /// The transfer failed or was aborted.
    fn failed(&self, error: &str);
}

/// Reports `failed` for a job that never reached `completed` (any early return
/// or error out of `run_receive`), and stops its progress ticker.
struct JobGuard {
    job: Arc<dyn TransferJob>,
    ticker: Option<tokio::task::JoinHandle<()>>,
    done: bool,
}

impl JobGuard {
    fn start(observer: &dyn TransferObserver, manifest: &TransferManifest) -> Self {
        JobGuard {
            job: observer.started(&manifest.file_name, manifest.file_size),
            ticker: None,
            done: false,
        }
    }

    /// Report `pb`'s position about once a second until the job ends.
    fn track_progress(&mut self, pb: Arc<ProgressBar>) {
        let job = Arc::clone(&self.job);
        self.ticker = Some(tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(1));
            loop {
                every.tick().await;
                job.progress(pb.position());
            }
        }));
    }

    /// The transfer was refused or failed for a known reason.
    fn fail(mut self, error: &str) {
        self.done = true;
        self.job.failed(error);
    }

    async fn completed(mut self, bytes: u64, files: Vec<PathBuf>) {
        if let Some(t) = self.ticker.take() {
            t.abort();
        }
        self.job.progress(bytes);
        self.done = true;
        self.job.completed(files).await;
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        if let Some(t) = self.ticker.take() {
            t.abort();
        }
        if !self.done {
            self.job
                .failed("transfer failed or was aborted (see receiver log)");
        }
    }
}

/// The regular files a transfer writes, for [`TransferJob::completed`].
fn transfer_files(
    output_dir: &std::path::Path,
    manifest: &TransferManifest,
    dir_entries: Option<&[FileEntry]>,
) -> Vec<PathBuf> {
    let root = output_dir.join(&manifest.file_name);
    match dir_entries {
        Some(entries) => entries
            .iter()
            .filter(|e| matches!(e.kind, FileKind::File))
            .map(|e| root.join(&e.path))
            .collect(),
        None => vec![root],
    }
}

/// Bytes a transfer will add on disk beyond what its destination already holds
/// (a resumed transfer's preallocated file is already counted as used).
fn new_bytes_needed(
    output_dir: &std::path::Path,
    manifest: &TransferManifest,
    dir_entries: Option<&[FileEntry]>,
) -> u64 {
    let existing = |p: std::path::PathBuf| {
        std::fs::symlink_metadata(p)
            .ok()
            .filter(|m| m.is_file())
            .map_or(0, |m| m.len())
    };
    let root = output_dir.join(&manifest.file_name);
    match dir_entries {
        Some(entries) => entries
            .iter()
            .filter(|e| matches!(e.kind, FileKind::File))
            .map(|e| e.size.saturating_sub(existing(root.join(&e.path))))
            .fold(0u64, u64::saturating_add),
        None => manifest.file_size.saturating_sub(existing(root)),
    }
}

/// Keeps alive the shared state an in-flight transfer's blocking write tasks
/// hold (output file, layout, resume state); all dead once every such task has
/// finished.
type WriteLife = std::sync::Weak<dyn std::any::Any + Send + Sync>;

/// A transfer's hold on its destination.
struct DestinationClaim {
    /// Distinguishes this claim from a later one for the same path.
    id: u64,
    transfer_id: [u8; 16],
    /// The sender's authenticated DeviceId (client certificate), if any.
    peer: Option<String>,
    /// Fired to cancel this transfer when its sender reconnects.
    cancel: Arc<tokio::sync::Notify>,
    /// Shared state of this transfer's write tasks (see [`WriteLife`]).
    writes: Vec<WriteLife>,
    /// The transfer has ended but some of its blocking writes may still be
    /// running; the next claim waits for them to drain.
    released: bool,
}

impl DestinationClaim {
    fn writes_drained(&self) -> bool {
        self.writes.iter().all(|w| w.strong_count() == 0)
    }
}

/// Destinations (`output_dir/file_name`) with a transfer in progress (or still
/// draining its writes) in this process.
static ACTIVE_DESTINATIONS: std::sync::OnceLock<Mutex<HashMap<PathBuf, DestinationClaim>>> =
    std::sync::OnceLock::new();
static NEXT_CLAIM_ID: AtomicU64 = AtomicU64::new(0);

/// How long a claim waits for a superseded or just-ended transfer on the same
/// destination to stop (including its in-flight blocking writes).
const SUPERSEDE_WAIT: Duration = Duration::from_secs(15);

fn destinations() -> &'static Mutex<HashMap<PathBuf, DestinationClaim>> {
    ACTIVE_DESTINATIONS.get_or_init(Default::default)
}

/// Releases a [`claim_destination`] registration on drop.
struct DestinationGuard {
    key: PathBuf,
    id: u64,
    cancel: Arc<tokio::sync::Notify>,
}

impl DestinationGuard {
    /// Resolves when a reconnect of the same sender supersedes this transfer.
    fn cancelled(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.cancel)
    }

    /// Record the shared state this transfer's blocking writes hold, so a later
    /// claim on the destination waits until they have all finished.
    fn track_writes(&self, pt: &PreparedTransfer) {
        let mut lives: Vec<WriteLife> = Vec::new();
        let resume: Arc<dyn std::any::Any + Send + Sync> = pt.resume.clone();
        lives.push(Arc::downgrade(&resume));
        if let Some(f) = &pt.out_file {
            let f: Arc<dyn std::any::Any + Send + Sync> = f.clone();
            lives.push(Arc::downgrade(&f));
        }
        if let Some(l) = &pt.layout {
            let l: Arc<dyn std::any::Any + Send + Sync> = l.clone();
            lives.push(Arc::downgrade(&l));
        }
        self.track_lives(lives);
    }

    fn track_lives(&self, lives: Vec<WriteLife>) {
        let mut g = destinations()
            .lock()
            .expect("destination registry mutex poisoned");
        if let Some(c) = g.get_mut(&self.key).filter(|c| c.id == self.id) {
            c.writes = lives;
        }
    }
}

impl Drop for DestinationGuard {
    fn drop(&mut self) {
        let mut g = destinations()
            .lock()
            .expect("destination registry mutex poisoned");
        if let Some(c) = g.get_mut(&self.key).filter(|c| c.id == self.id) {
            if c.writes_drained() {
                g.remove(&self.key);
            } else {
                c.released = true;
            }
        }
    }
}

/// Register `output_dir/file_name` as the target of an in-progress transfer.
///
/// A different transfer already writing there is refused. The *same* transfer
/// (matching `transfer_id`) from the *same authenticated sender* (matching
/// client-certificate DeviceId — the transfer_id alone is predictable, so an
/// anonymous or different peer can never take over) is a sender that
/// reconnected, e.g. after a crash while the old connection lingers: the stale
/// transfer is cancelled and this claim waits for it to stop. Either way a new
/// claim also waits for the previous transfer's in-flight blocking writes to
/// drain, so they can't land on top of the new transfer's file or resume state.
///
/// The key uses the canonicalised output directory so different spellings of
/// the same directory (relative path, trailing `.`, symlinked parent) collide.
async fn claim_destination(
    output_dir: &std::path::Path,
    file_name: &str,
    transfer_id: [u8; 16],
    peer: Option<String>,
) -> Result<DestinationGuard> {
    let dir = std::fs::canonicalize(output_dir).unwrap_or_else(|_| output_dir.to_path_buf());
    let key = dir.join(file_name);
    let id = NEXT_CLAIM_ID.fetch_add(1, Ordering::Relaxed);
    let deadline = tokio::time::Instant::now() + SUPERSEDE_WAIT;
    let mut signalled = false;
    loop {
        {
            let mut g = destinations()
                .lock()
                .expect("destination registry mutex poisoned");
            let free = match g.get(&key) {
                None => true,
                Some(c) if c.released => c.writes_drained(),
                Some(c) if c.transfer_id == transfer_id && peer.is_some() && c.peer == peer => {
                    if !signalled {
                        warn!(dest = %key.display(), "sender reconnected; cancelling its stale transfer");
                        c.cancel.notify_one();
                        signalled = true;
                    }
                    false
                }
                Some(_) => bail!(
                    "another transfer to {} is already in progress on this receiver; \
                     retry once it finishes",
                    key.display()
                ),
            };
            if free {
                let cancel = Arc::new(tokio::sync::Notify::new());
                g.insert(
                    key.clone(),
                    DestinationClaim {
                        id,
                        transfer_id,
                        peer,
                        cancel: Arc::clone(&cancel),
                        writes: Vec::new(),
                        released: false,
                    },
                );
                return Ok(DestinationGuard { key, id, cancel });
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "a previous transfer to {} has not finished shutting down; retry shortly",
                key.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

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
    // ── Free-space precondition (checked first, before allocating anything) ─────
    // Refuse if the destination filesystem can't hold the file. Otherwise
    // open_and_preallocate's fallocate would reserve (and, on ENOSPC, strand) the
    // remaining free space — filling the disk and killing the transfer mid-flight
    // with an opaque "connection reset" on the sender. `already` lets a resume of
    // an already-preallocated file pass (its space is reserved).
    {
        let target = output_dir.join(&manifest.file_name);
        let already: u64 = if dir_entries.is_some() {
            walkdir::WalkDir::new(&target)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .map(|e| crate::fs_ext::allocated_size(e.path()))
                .sum()
        } else {
            crate::fs_ext::allocated_size(&target)
        };
        let needed = manifest.file_size.saturating_sub(already);
        let avail = crate::fs_ext::available_space(output_dir);
        if avail < needed {
            anyhow::bail!(
                "destination is out of space: {} free at {}, but \"{}\" needs {} more \
                 (total {}). Free space or choose another destination.",
                indicatif::HumanBytes(avail),
                output_dir.display(),
                manifest.file_name,
                indicatif::HumanBytes(needed),
                indicatif::HumanBytes(manifest.file_size),
            );
        }
    }

    let resume = Arc::new(Mutex::new(ResumeState::load_or_new(
        output_dir,
        &manifest.transfer_id,
        manifest.total_chunks,
    )));
    let (received_bits, bytes_already_received) = {
        let state = resume.lock().expect("resume-state mutex poisoned");
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
        let f = open_and_preallocate(&out_path, manifest.file_size, false)?;
        (Some(Arc::new(f)), None)
    };

    // ── Progress bar ─────────────────────────────────────────────────────────

    let term_width = console::Term::stdout().size().1 as usize;
    let wide = term_width >= 140;
    let pb = Arc::new({
        let pb = ProgressBar::new(manifest.file_size);
        pb.set_style(crate::progress::transfer_style("↓", wide));
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_prefix(manifest.file_name.clone());
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

/// Open `path` for write, pre-allocate it to exactly `size` bytes, and disable
/// the page cache on macOS.
///
/// `nofollow` refuses to open `path` if it is a symlink (directory transfers:
/// a file entry must never be written through a link left in the destination).
///
/// An existing file keeps its contents up to `size` (resume) but never keeps a
/// stale tail beyond it.
fn open_and_preallocate(
    path: &std::path::Path,
    size: u64,
    nofollow: bool,
) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(false); // sized explicitly below
    #[cfg(unix)]
    if nofollow {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = nofollow;
    let f = opts
        .open(path)
        .with_context(|| format!("open output {}", path.display()))?;
    let existing_len = f
        .metadata()
        .with_context(|| format!("stat output {}", path.display()))?
        .len();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let isize = i64::try_from(size).context("file too large for this platform")?;
        let rc = unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, isize) };
        if rc != 0 {
            // fallocate can leave a partial reservation behind on ENOSPC.  For a
            // file we just created (or that was empty) release it by truncating
            // to 0 before falling back to a sparse file, so a failed allocation
            // doesn't strand blocks and fill the disk.  Never truncate an
            // existing file to 0: it may hold resumed chunks.
            if existing_len == 0 {
                let _ = f.set_len(0);
            }
            f.set_len(size)?;
        } else if existing_len > size {
            // fallocate never shrinks; drop any stale tail from a larger file.
            f.set_len(size)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = existing_len;
        f.set_len(size)?;
    }
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
        // Never create anything through a symlink already on disk (validation
        // has already rejected paths through symlinks from this transfer).
        ensure_no_symlink_prefix(base_dir, &entry.path)?;
        let dest = base_dir.join(&entry.path);
        match &entry.kind {
            FileKind::Directory => {
                std::fs::create_dir_all(&dest)
                    .with_context(|| format!("create dir {}", dest.display()))?;
            }
            #[allow(unused_variables)]
            FileKind::Symlink { target } => {
                // Create parent if needed.
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create parent {}", parent.display()))?;
                }
                // The target must not pass through a symlink on disk either: the
                // lexical escape check assumes real directories.
                let parent = entry.path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                let walk = resolve_relative_path(parent, target)
                    .with_context(|| format!("symlink {} escapes transfer root", dest.display()))?;
                for p in &walk.traversed {
                    let full = base_dir.join(p);
                    if std::fs::symlink_metadata(&full).is_ok_and(|m| m.file_type().is_symlink()) {
                        bail!(
                            "symlink {} target {target:?} traverses existing symlink {}",
                            dest.display(),
                            full.display()
                        );
                    }
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
                open_and_preallocate(&dest, entry.size, true)
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
/// Forwards `AdjustStreams` requests to the main loop via `scale_tx`.  Returns
/// the recv half of the control stream together with the `Complete` file hash
/// (or `None` if the stream closed first) so the caller can drive the v5
/// incremental-repair handshake — which reads `ChunkData` repair frames and
/// further `Complete` messages on the same stream — after the data phase.
async fn ctrl_reader_task<R>(
    mut ctrl_recv: R,
    scale_tx: tokio::sync::mpsc::Sender<u8>,
) -> (R, Option<[u8; 32]>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    loop {
        match framing::recv_message::<_, SenderMessage>(&mut ctrl_recv).await {
            Ok(Some(SenderMessage::AdjustStreams { target_count })) => {
                if scale_tx.send(target_count).await.is_err() {
                    break; // main loop dropped receiver — transfer ending
                }
            }
            Ok(Some(SenderMessage::Complete { file_hash })) => {
                return (ctrl_recv, Some(file_hash));
            }
            _ => break, // EOF or error
        }
    }
    (ctrl_recv, None)
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
    // An abandoned hasher (dropped chunk, pending overflow) is incomplete; treat
    // it like the resume path and hash from disk.
    let hasher = hasher
        .map(|h| {
            Arc::try_unwrap(h).expect("all stream tasks finished so no other Arc references exist")
        })
        .filter(|h| !h.is_abandoned());
    let file_hash: [u8; 32] = match hasher {
        Some(h) => h.finish()?,
        None => {
            // Resume path (or abandoned inline hasher): some chunks were never
            // fed to a ChunkHasher, so hash the complete stream from disk instead.
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
        let _ = resume.lock().expect("resume-state mutex poisoned").delete();
        framing::send_message(
            ctrl_send,
            &ReceiverMessage::Error {
                message: "transfer hash mismatch".into(),
                fatal: true,
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

    resume
        .lock()
        .expect("resume-state mutex poisoned")
        .delete()?;
    println!(
        "Received: {}",
        output_dir.join(&manifest.file_name).display()
    );
    Ok(())
}

// ── Stream worker (generic over any AsyncRead) ────────────────────────────────

#[allow(clippy::too_many_arguments)]
/// Read and validate the v7 [`StreamHello`] preamble at the start of a data
/// stream, when the sender negotiated protocol ≥ 7. Rejects a stream whose
/// `transfer_id` doesn't match the manifest (the cross-transfer guard that
/// makes multi-connection transfers safe). No-op against a < v7 sender.
async fn maybe_recv_stream_hello<R>(
    stream: &mut R,
    expected_transfer_id: [u8; 16],
    expect_hello: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    if !expect_hello {
        return Ok(());
    }
    let hello: crate::protocol::messages::StreamHello = framing::recv_message_required(stream)
        .await
        .context("read StreamHello preamble")?;
    if hello.transfer_id != expected_transfer_id {
        bail!(
            "StreamHello transfer_id mismatch (got {}, expected {}) — \
             stream belongs to a different transfer",
            hex::encode(hello.transfer_id),
            hex::encode(expected_transfer_id),
        );
    }
    Ok(())
}

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
    deferred: crate::fs_ext::DeferredDontneed,
    expect_hello: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    maybe_recv_stream_hello(&mut stream, manifest.transfer_id, expect_hello).await?;
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
        // Test-only: simulate a crash mid-transfer once the armed chunk count is
        // reached.  Every worker polls this so the whole connection tears down
        // promptly, leaving a partial (flushed) resume file behind.
        if test_hooks::abort_requested() {
            bail!("test hook: simulated crash mid-transfer");
        }

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

        // Test-only fault injection: simulate a corrupt/lost chunk by dropping it
        // (leaving it unmarked) exactly once, exercising the repair path.
        if test_hooks::should_drop(chunk_index) {
            warn!(chunk = chunk_index, "test hook: dropping chunk");
            if let Some(ref h) = hasher {
                h.abandon();
            }
            continue;
        }

        let chunk_size = manifest.chunk_size;
        let want_len = expected_chunk_len(chunk_index, chunk_size, manifest.file_size);
        let out_file = out_file.as_ref().map(Arc::clone);
        let layout = layout.as_ref().map(Arc::clone);
        let hasher = hasher.as_ref().map(Arc::clone);
        let resume = Arc::clone(&resume);
        let pb = Arc::clone(&pb);
        let progress_tx = progress_tx.clone();
        let stats = Arc::clone(&stats);
        let deferred_c = deferred.clone();

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
                compress::decompress_chunk(&chunk.payload, chunk_size)
                    .with_context(|| format!("decompress chunk {chunk_index}"))?
            } else {
                chunk.payload
            };
            let computed: [u8; 32] = *blake3::hash(&data).as_bytes();
            if computed != chunk.chunk_hash {
                // Drop the corrupt chunk and keep the worker (and its stream)
                // alive instead of aborting the whole transfer.  The chunk stays
                // unmarked in the resume bitvector, so the completion checkpoint
                // either repairs it in-band (protocol v5) or fails the whole-file
                // hash and lets a resumed rerun re-fetch it.
                stats.in_flight_chunks.fetch_sub(1, Ordering::Relaxed);
                drop(write_permit);
                // The chunk can now only arrive via repair (which bypasses the
                // inline hasher), so stop collecting inline — otherwise every
                // later chunk piles up behind it until the pending cap trips.
                if let Some(ref h) = hasher {
                    h.abandon();
                }
                warn!(
                    chunk = chunk_index,
                    got = %hex::encode(computed),
                    expected = %hex::encode(chunk.chunk_hash),
                    "chunk hash mismatch; dropping (will be repaired or re-fetched)"
                );
                return Ok(());
            }
            // A self-consistent but wrongly sized chunk (hash matches its own
            // bytes) would write past this chunk's range: into the next chunk,
            // past EOF, or across file boundaries in a directory transfer.
            if data.len() != want_len {
                bail!(
                    "chunk {chunk_index}: {} bytes, expected {want_len}",
                    data.len()
                );
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
                crate::fs_ext::write_all_at_deferred(f, &data, offset, &deferred_c)
                    .with_context(|| format!("write chunk {chunk_index} at offset {offset}"))?;
            }
            // Measure only the actual data write; resume fsync below must not
            // inflate this value and cause spurious disk-stall reports.
            let write_us = write_start.elapsed().as_micros() as u32;
            stats.last_disk_us.fetch_max(write_us, Ordering::Relaxed);

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
                let mut r = resume.lock().expect("resume-state mutex poisoned");
                r.mark_received(chunk_index);
                // Test-only: force a flush the moment the simulated-crash threshold
                // is crossed so the partial resume file is guaranteed on disk
                // regardless of where it falls relative to RESUME_SAVE_BATCH.
                let force = test_hooks::note_marked_and_check_abort();
                if r.incr_dirty() >= RESUME_SAVE_BATCH || force {
                    r.reset_dirty();
                    Some(r.snapshot()?)
                } else {
                    None
                }
            };
            if let Some(snap) = snap {
                snap.write_to_disk_best_effort();
            }
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
    stripe_bufs: Arc<Mutex<FecStripes>>,
    stats: Arc<ReceiverStats>,
    write_sem: Arc<tokio::sync::Semaphore>,
    deferred: crate::fs_ext::DeferredDontneed,
    expect_hello: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    maybe_recv_stream_hello(&mut stream, manifest.transfer_id, expect_hello).await?;
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
    let file_size = manifest.file_size;
    let transfer_id = manifest.transfer_id;
    let total_stripes = total_chunks.div_ceil(data_shards as u64);
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

        // Test-only fault injection: drop a marked data shard, simulating loss.
        // Dropping more than `parity_shards` per stripe makes it unreconstructable,
        // exercising the FEC repair path.
        if !fcd.is_parity && test_hooks::should_drop(fcd.chunk_index) {
            warn!(
                chunk = fcd.chunk_index,
                "test hook: dropping FEC data shard"
            );
            // The stripe may now be unreconstructable and the chunk recovered
            // only via repair, which bypasses the inline hasher.
            if let Some(ref h) = hasher {
                h.abandon();
            }
            shard_count += 1;
            continue;
        }

        let stripe_index = fcd.stripe_index;
        if stripe_index as u64 >= total_stripes {
            bail!("FEC shard: stripe_index {stripe_index} out of range (total stripes {total_stripes})");
        }

        // Insert shard into the shared buffer; extract the stripe if it is now ready.
        let ready_stripe = {
            let mut st = stripe_bufs
                .lock()
                .expect("FEC stripe buffer mutex poisoned");
            if st.done.contains(&stripe_index) {
                // Late shard (usually surplus parity) for a stripe that was
                // already processed — nothing left to do with it.
                shard_count += 1;
                continue;
            }
            let real_count = {
                let first = stripe_index as u64 * data_shards as u64;
                (total_chunks - first).min(data_shards as u64) as usize
            };
            let buf = st.bufs.entry(stripe_index).or_insert_with(|| {
                StripeBuffer::new(stripe_index, data_shards, parity_shards, real_count)
            });
            buf.insert(fcd)?;
            let ready = buf.is_ready();
            if ready {
                st.done.insert(stripe_index);
                st.bufs.remove(&stripe_index)
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
            let deferred_c = deferred.clone();
            let write_permit = write_sem
                .clone()
                .acquire_owned()
                .await
                .expect("write semaphore closed");
            stats.in_flight_chunks.fetch_add(1, Ordering::Relaxed);
            processing.spawn_blocking(move || {
                let peak_write_us = process_stripe(
                    stripe, chunk_size, file_size, out_file, resume, hasher, pb, ptx, deferred_c,
                );
                drop(write_permit);
                // Use the pwrite time returned by process_stripe (excludes resume
                // fsync) so disk_stall_ms reflects only actual data write latency.
                let write_us = peak_write_us.as_ref().ok().copied().unwrap_or(0);
                stats.last_disk_us.fetch_max(write_us, Ordering::Relaxed);
                stats.in_flight_chunks.fetch_sub(1, Ordering::Relaxed);
                peak_write_us.map(|_| ())
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

/// Bound on a TCP+TLS handshake (control or data connection).  A real sender
/// completes it in a couple of RTTs; this only fires for idle/stalled peers,
/// which would otherwise block the sequential TCP server indefinitely.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-message bound on reading the sender's opening flight (NegotiateRequest,
/// TransferManifest, DirEntries).  The sender writes these right after
/// connecting (at most one RTT apart on TCP), so this only fires for a stalled
/// or idle peer.
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Apply [`HANDSHAKE_READ_TIMEOUT`] to one opening-flight read.
async fn handshake_read<T>(what: &str, fut: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, fut)
        .await
        .map_err(|_| {
            anyhow!(
                "timed out after {}s waiting for {what} from sender",
                HANDSHAKE_READ_TIMEOUT.as_secs()
            )
        })?
}

/// How long `run_receive` waits for each individual data stream to be
/// accepted.  The sender opens all data streams right after the receiver
/// replies with `ReceiverMessage::Ready`, so 30 s is very generous; it
/// only fires when the sender has already died mid-setup.
const DATA_STREAM_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long `serve_one_stdio` waits for the initial connection.  The sender
/// connects almost immediately after receiving the handshake line, so this
/// only fires when something has gone badly wrong (sender crashed, firewall,
/// etc.).  Acts as a safety net for cases where SIGHUP is not delivered (e.g.
/// SSH ControlMaster, network partition before TCP keepalives fire).
const STDIO_ACCEPT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long `serve_one_stdio` waits for the sender to reconnect after a
/// mid-flight failure.  The sender retries immediately on the same SSH
/// session, so 60 s is very generous.
const STDIO_RETRY_TIMEOUT: Duration = Duration::from_secs(60);

// ── Manifest validation ───────────────────────────────────────────────────────

const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024;
const MIN_CHUNK_SIZE: usize = 4 * 1024;
const MAX_CHUNK_SIZE: usize = 128 * 1024 * 1024;
const MAX_STREAMS: usize = 1024;

/// Maximum number of file entries in a `DirEntries` message.
/// Limits memory usage and prevents degenerate manifests.
const MAX_DIR_ENTRIES: usize = 500_000;

/// Frame-size cap for the `DirEntries` message. Kept at the 128 MiB data cap
/// so large real trees (long paths) still fit; the frame body is allocated as
/// it arrives, so the cap doesn't let a peer reserve memory it never sends.
const MAX_DIR_ENTRIES_FRAME: u32 = 128 * 1024 * 1024;

/// Maximum total Reed-Solomon shards (data + parity) in a stripe.  The galois_8
/// field caps this at 256; the manifest validator rejects anything larger.
const MAX_FEC_TOTAL_SHARDS: usize = 256;

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
    if let Some(ref fec) = m.fec {
        // Reed-Solomon (galois_8) requires data_shards ≥ 1, parity_shards ≥ 1,
        // and data + parity ≤ 256.  Reject out-of-range values from a malicious
        // manifest up front with a clear error instead of letting them surface
        // deep inside stripe-buffer allocation or RS init.
        if fec.data_shards == 0 || fec.parity_shards == 0 {
            bail!(
                "manifest: FEC data_shards/parity_shards must be ≥ 1 \
                 (got {}:{})",
                fec.data_shards,
                fec.parity_shards
            );
        }
        if fec.data_shards + fec.parity_shards > MAX_FEC_TOTAL_SHARDS {
            bail!(
                "manifest: FEC data_shards + parity_shards = {} exceeds limit {MAX_FEC_TOTAL_SHARDS}",
                fec.data_shards + fec.parity_shards
            );
        }
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
            // Resolve the target lexically relative to the symlink's parent
            // directory; a ".." that would climb above the root is an escape.
            let parent = entry.path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            if resolve_relative_path(parent, target).is_none() {
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

    // Second pass, once every symlink is known: nothing may be created *through*
    // a symlink from this transfer, and no symlink target may traverse one.
    // Lexical resolution assumes every intermediate component is a real
    // directory; a symlink in the middle (e.g. `q/s -> ../x`, then `t ->
    // q/s/../..`) physically lands somewhere else and can escape the root.
    let symlinks: std::collections::HashSet<&str> = entries
        .iter()
        .filter(|e| matches!(e.kind, FileKind::Symlink { .. }))
        .map(|e| e.path.as_str())
        .collect();
    if !symlinks.is_empty() {
        for (i, entry) in entries.iter().enumerate() {
            if let Some(p) = path_prefixes(&entry.path).find(|p| symlinks.contains(p)) {
                bail!(
                    "DirEntries[{i}]: path {:?} traverses symlink {p:?} from this transfer",
                    entry.path
                );
            }
            if let FileKind::Symlink { target } = &entry.kind {
                let parent = entry.path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                let walk = resolve_relative_path(parent, target).unwrap_or_default();
                if let Some(p) = walk
                    .traversed
                    .iter()
                    .find(|p| symlinks.contains(p.as_str()))
                {
                    bail!(
                        "DirEntries[{i}]: symlink {:?} target {:?} traverses symlink {p:?}",
                        entry.path,
                        target
                    );
                }
            }
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

/// Every proper prefix of a `/`-separated relative path, shortest first
/// (`"a/b/c"` -> `"a"`, `"a/b"`).
fn path_prefixes(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(move |(i, _)| &path[..i])
}

/// Result of [`resolve_relative_path`].
#[derive(Debug, Default)]
struct ResolvedTarget {
    /// Root-relative paths the walk passes *through* (descends into and then
    /// applies a further component to).  These must be real directories: a
    /// symlink here makes the lexical result differ from the physical one.
    traversed: Vec<String>,
}

/// Lexically resolve `target` relative to `base_dir` (e.g. a symlink's parent
/// directory within the transfer root).
///
/// Returns `None` if the target escapes the root, i.e. a `..` would pop past
/// the root.  (Silently ignoring such a `..` would let `x -> ../../etc`
/// resolve to the harmless-looking `etc`.)
fn resolve_relative_path(base_dir: &str, target: &str) -> Option<ResolvedTarget> {
    // Start with the base directory components.
    let mut parts: Vec<&str> = if base_dir.is_empty() {
        vec![]
    } else {
        base_dir.split('/').collect()
    };
    let mut traversed = Vec::new();
    // True when `parts` was last extended by a target component, so applying
    // another component passes through it.
    let mut descended = false;

    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if descended {
                    traversed.push(parts.join("/"));
                }
                parts.pop()?;
                descended = false;
            }
            c => {
                if descended {
                    traversed.push(parts.join("/"));
                }
                parts.push(c);
                descended = true;
            }
        }
    }

    Some(ResolvedTarget { traversed })
}

/// Fail if any proper prefix of the relative path `rel` under `base_dir` is a
/// symlink on disk.  Guards writes against symlinks that already exist in the
/// destination (e.g. left by an earlier transfer into the same directory).
fn ensure_no_symlink_prefix(base_dir: &std::path::Path, rel: &str) -> Result<()> {
    for p in path_prefixes(rel) {
        let full = base_dir.join(p);
        if std::fs::symlink_metadata(&full).is_ok_and(|m| m.file_type().is_symlink()) {
            bail!("refusing to write {rel:?}: {} is a symlink", full.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::messages::{Compression, FecParams, StreamHello};

    /// serve_one_stdio's accept timeout must bound only the wait for a
    /// connection, never the transfer that follows (a long SSH transfer used
    /// to be cancelled after 5 minutes).
    #[tokio::test]
    async fn stdio_accept_timeout_does_not_cut_off_accepted_connection() {
        let dir = tempfile::tempdir().unwrap();
        let quic = Server::bind("127.0.0.1:0".parse().unwrap(), dir.path().to_owned()).unwrap();
        let tcp = TcpServer::bind("127.0.0.1:0".parse().unwrap(), dir.path().to_owned())
            .await
            .unwrap();
        let addr = tcp.local_addr;
        let fp = tcp.fingerprint.clone();

        // Nothing connects: the short accept window expires.
        let err = accept_one_quic_or_tcp(&quic, &tcp, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(err.is::<AcceptTimedOut>(), "{err:#}");

        // A connection that arrives in time keeps the call alive well past the
        // accept window (here it just goes quiet; a real transfer would run).
        let task = tokio::spawn(async move {
            accept_one_quic_or_tcp(&quic, &tcp, Duration::from_millis(300)).await
        });
        let client = crate::net::tcp::connect_tls(addr, Some(&fp), None, None)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(
            !task.is_finished(),
            "accepted connection was cut off by the accept timeout"
        );
        drop(client);
        let res = task.await.unwrap();
        assert!(
            !res.as_ref().is_err_and(|e| e.is::<AcceptTimedOut>()),
            "{res:?}"
        );
    }

    #[tokio::test]
    async fn stream_hello_skipped_when_not_expected() {
        // expect_hello = false: nothing is read, even if bytes are waiting.
        let (mut a, mut b) = tokio::io::duplex(1024);
        framing::send_message(
            &mut a,
            &StreamHello {
                transfer_id: [9u8; 16],
                stream_seq: 0,
            },
        )
        .await
        .unwrap();
        // Should return Ok without consuming, since expect_hello is false.
        maybe_recv_stream_hello(&mut b, [1u8; 16], false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stream_hello_accepts_matching_transfer_id() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let id = [7u8; 16];
        framing::send_message(
            &mut a,
            &StreamHello {
                transfer_id: id,
                stream_seq: 3,
            },
        )
        .await
        .unwrap();
        maybe_recv_stream_hello(&mut b, id, true).await.unwrap();
    }

    #[tokio::test]
    async fn stream_hello_rejects_mismatched_transfer_id() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        framing::send_message(
            &mut a,
            &StreamHello {
                transfer_id: [2u8; 16],
                stream_seq: 0,
            },
        )
        .await
        .unwrap();
        let err = maybe_recv_stream_hello(&mut b, [1u8; 16], true)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("transfer_id mismatch"),
            "expected transfer_id mismatch error, got: {err:#}"
        );
    }

    fn base_manifest() -> TransferManifest {
        TransferManifest {
            transfer_id: [0u8; 16],
            file_name: "file.bin".to_string(),
            file_size: 10,
            chunk_size: MIN_CHUNK_SIZE,
            total_chunks: 10u64.div_ceil(MIN_CHUNK_SIZE as u64),
            num_streams: 1,
            compression: Compression::None,
            fec: None,
        }
    }

    // The free-space precondition relies on statvfs, so it only enforces on unix;
    // on other targets `available_space` returns u64::MAX (check disabled).
    #[cfg(unix)]
    #[test]
    fn prepare_transfer_refuses_when_destination_too_small() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = base_manifest();
        m.file_name = "huge.bin".to_string();
        m.chunk_size = 8 * 1024 * 1024;
        // 100 TiB — larger than any real test disk, so the free-space check must
        // reject before allocating, with a clear out-of-space error.
        m.file_size = 100 * 1024 * 1024 * 1024 * 1024;
        m.total_chunks = m.file_size.div_ceil(m.chunk_size as u64);
        match prepare_transfer(&m, None, dir.path()) {
            Ok(_) => panic!("expected an out-of-space rejection"),
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(msg.contains("out of space"), "unexpected error: {msg}");
            }
        }
    }

    #[test]
    fn manifest_accepts_valid_fec() {
        let mut m = base_manifest();
        m.fec = Some(FecParams {
            data_shards: 8,
            parity_shards: 2,
        });
        assert!(validate_manifest(&m).is_ok());
    }

    #[test]
    fn manifest_rejects_zero_fec_shards() {
        let mut m = base_manifest();
        m.fec = Some(FecParams {
            data_shards: 0,
            parity_shards: 2,
        });
        assert!(validate_manifest(&m).is_err());
        m.fec = Some(FecParams {
            data_shards: 4,
            parity_shards: 0,
        });
        assert!(validate_manifest(&m).is_err());
    }

    #[test]
    fn manifest_rejects_oversized_fec_stripe() {
        let mut m = base_manifest();
        m.fec = Some(FecParams {
            data_shards: 200,
            parity_shards: 100,
        });
        assert!(validate_manifest(&m).is_err());
    }

    #[test]
    fn preallocate_truncates_stale_tail_but_keeps_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("out.bin");
        std::fs::write(&p, vec![0xAB; 10_000]).unwrap();
        let f = open_and_preallocate(&p, 4096, false).unwrap();
        drop(f);
        let got = std::fs::read(&p).unwrap();
        assert_eq!(got.len(), 4096, "stale tail beyond size must be dropped");
        assert!(got.iter().all(|&b| b == 0xAB), "existing prefix preserved");

        // Growing keeps existing data too.
        let f = open_and_preallocate(&p, 8192, false).unwrap();
        drop(f);
        let got = std::fs::read(&p).unwrap();
        assert_eq!(got.len(), 8192);
        assert!(got[..4096].iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn concurrent_claims_on_same_destination_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Some("a".repeat(64));
        let g = claim_destination(dir.path(), "same.bin", [1; 16], alice.clone())
            .await
            .unwrap();
        // Same target, different spelling of the directory, other transfer.
        let alias = dir.path().join(".");
        assert!(
            claim_destination(&alias, "same.bin", [2; 16], alice.clone())
                .await
                .is_err()
        );
        // Same (predictable) transfer_id but anonymous or a different peer:
        // never allowed to take over.
        assert!(claim_destination(dir.path(), "same.bin", [1; 16], None)
            .await
            .is_err());
        assert!(
            claim_destination(dir.path(), "same.bin", [1; 16], Some("b".repeat(64)))
                .await
                .is_err()
        );
        // A different file in the same directory is fine.
        let other = claim_destination(dir.path(), "other.bin", [3; 16], None)
            .await
            .unwrap();
        drop(g);
        // Released on drop.
        let _again = claim_destination(dir.path(), "same.bin", [4; 16], None)
            .await
            .unwrap();
        drop(other);
    }

    #[tokio::test]
    async fn reconnect_of_same_sender_supersedes_stale_claim() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Some("a".repeat(64));
        let old = claim_destination(dir.path(), "r.bin", [9; 16], alice.clone())
            .await
            .unwrap();
        // The stale transfer exits (dropping its guard) once cancelled.
        let cancelled = old.cancelled();
        let stale = tokio::spawn(async move {
            cancelled.notified().await;
            drop(old);
        });
        let new = claim_destination(dir.path(), "r.bin", [9; 16], alice.clone())
            .await
            .unwrap();
        stale.await.unwrap();
        // The new claim is in force (a third claimant without the same
        // identity is refused).
        assert!(claim_destination(dir.path(), "r.bin", [9; 16], None)
            .await
            .is_err());
        drop(new);
    }

    /// A pre-v7 sender's data connection that sends nothing (or closes right
    /// away) is still handed to its legacy transfer instead of being dropped.
    #[tokio::test]
    async fn idle_legacy_tcp_data_connection_is_delivered() {
        use crate::net::connection::{cert_fingerprint, generate_self_signed_cert};
        let (cert, key) = generate_self_signed_cert().unwrap();
        let fp = cert_fingerprint(&cert);
        let acceptor =
            Arc::new(make_tls_acceptor(cert, make_private_key(key).unwrap(), None).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Arc::new(TcpStreamRouter::default());
        let (rx, _route) = router
            .register(TcpRouteKey::Legacy, "127.0.0.1".parse().unwrap())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().to_owned();
        let srv_router = Arc::clone(&router);
        tokio::spawn(async move {
            loop {
                let (raw, peer) = listener.accept().await.unwrap();
                let (a, r, o) = (Arc::clone(&acceptor), Arc::clone(&srv_router), out.clone());
                tokio::spawn(async move {
                    let _ = serve_routed_tcp_connection(raw, peer, a, r, o).await;
                });
            }
        });

        // Idle: stays open, sends nothing.
        let _idle = crate::net::tcp::connect_tls(addr, Some(&fp), None, None)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("idle legacy connection delivered")
            .unwrap();
        // Closes right after the handshake.
        let mut closing = crate::net::tcp::connect_tls(addr, Some(&fp), None, None)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut closing)
            .await
            .unwrap();
        drop(closing);
        tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("closed legacy connection delivered")
            .unwrap();
    }

    #[tokio::test]
    async fn next_claim_waits_for_previous_writes_to_drain() {
        let dir = tempfile::tempdir().unwrap();
        let g = claim_destination(dir.path(), "w.bin", [5; 16], None)
            .await
            .unwrap();
        // A blocking write task still holds the transfer's shared state.
        let held: Arc<dyn std::any::Any + Send + Sync> = Arc::new(());
        g.track_lives(vec![Arc::downgrade(&held)]);
        drop(g);
        let start = std::time::Instant::now();
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(held);
        });
        let _next = claim_destination(dir.path(), "w.bin", [6; 16], None)
            .await
            .unwrap();
        assert!(
            start.elapsed() >= Duration::from_millis(250),
            "claim granted while the previous transfer's writes were in flight"
        );
        release.await.unwrap();
    }

    #[test]
    fn scatter_write_with_handle_cache_eviction() {
        // More files than OPEN_FILE_CACHE, several per chunk, written out of
        // order so cached handles are evicted and reopened.
        let root = tempfile::tempdir().unwrap();
        let entries: Vec<FileEntry> = (0..40)
            .map(|i| entry(&format!("f{i:02}"), FileKind::File, 1000 + i))
            .collect();
        prepare_directory(&entries, root.path()).unwrap();
        let layout = ConcatLayout::new(&entries, root.path().to_owned());
        let total: u64 = entries.iter().map(|e| e.size).sum();
        let stream: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let cs = MIN_CHUNK_SIZE;
        let n = total.div_ceil(cs as u64);
        for idx in (0..n).rev() {
            let start = idx as usize * cs;
            let end = (start + cs).min(stream.len());
            layout.scatter_write(idx, cs, &stream[start..end]).unwrap();
        }
        layout.close_files();
        let mut got = Vec::new();
        for e in &entries {
            got.extend(std::fs::read(root.path().join(&e.path)).unwrap());
        }
        assert_eq!(got, stream);
    }

    // ── Peer-supplied repair chunks ───────────────────────────────────────────

    #[tokio::test]
    async fn repair_chunk_index_and_length_validated() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = base_manifest();
        m.file_size = (MIN_CHUNK_SIZE * 2) as u64;
        m.total_chunks = 2;
        let f = Arc::new(open_and_preallocate(&dir.path().join("o"), m.file_size, false).unwrap());
        let resume = Arc::new(Mutex::new(ResumeState::new(dir.path(), &m.transfer_id, 2)));
        let pb = ProgressBar::hidden();
        let cd = |idx: u64, len: usize| {
            let payload = vec![5u8; len];
            ChunkData {
                transfer_id: m.transfer_id,
                chunk_index: idx,
                chunk_hash: *blake3::hash(&payload).as_bytes(),
                compressed: false,
                payload,
            }
        };
        // Out-of-range index used to index the resume bitvector out of bounds.
        let c = cd(9, MIN_CHUNK_SIZE);
        let r = write_repair_chunk(&c, Some(&f), None, &resume, &m, &pb);
        assert!(r.await.is_err());
        // Oversized (but hash-consistent) payload would write past its chunk.
        let c = cd(1, MIN_CHUNK_SIZE * 3);
        let r = write_repair_chunk(&c, Some(&f), None, &resume, &m, &pb);
        assert!(r.await.is_err());
        assert_eq!(
            std::fs::metadata(dir.path().join("o")).unwrap().len(),
            m.file_size
        );
        // A well-formed repair chunk is accepted and marked.
        let c = cd(1, MIN_CHUNK_SIZE);
        let r = write_repair_chunk(&c, Some(&f), None, &resume, &m, &pb);
        r.await.unwrap();
        assert!(resume.lock().unwrap().is_received(1));
    }

    // ── FEC stripe accounting ─────────────────────────────────────────────────

    fn fec_shard(
        stripe: u32,
        idx: u16,
        parity: bool,
        payload: Vec<u8>,
        lens: Vec<u32>,
    ) -> FecChunkData {
        let hash = *blake3::hash(&payload).as_bytes();
        FecChunkData {
            transfer_id: [0u8; 16],
            chunk_index: if parity { u64::MAX } else { idx as u64 },
            chunk_hash: hash,
            compressed: false,
            stripe_index: stripe,
            shard_index_in_stripe: idx,
            is_parity: parity,
            shard_compressed: vec![0; lens.len()],
            shard_lengths: lens,
            payload,
        }
    }

    /// Feed `shards` through one FEC stream worker for a 1:2 single-chunk
    /// transfer and return (worker result, bytes credited to the progress bar).
    async fn run_fec_worker(shards: Vec<FecChunkData>) -> (Result<()>, u64) {
        let dir = tempfile::tempdir().unwrap();
        let mut m = base_manifest();
        m.file_size = MIN_CHUNK_SIZE as u64;
        m.total_chunks = 1;
        m.fec = Some(FecParams {
            data_shards: 1,
            parity_shards: 2,
        });
        let f = Arc::new(open_and_preallocate(&dir.path().join("o"), m.file_size, false).unwrap());
        let resume = Arc::new(Mutex::new(ResumeState::new(dir.path(), &m.transfer_id, 1)));
        let pb = Arc::new(ProgressBar::hidden());
        let (ptx, _prx) = tokio::sync::mpsc::channel(64);
        let (mut w, r) = tokio::io::duplex(1 << 20);
        for s in &shards {
            framing::send_fec_chunk_data(&mut w, s).await.unwrap();
        }
        drop(w);
        let res = recv_fec_stream_worker(
            r,
            f,
            resume,
            m,
            Arc::clone(&pb),
            None,
            ptx,
            Arc::new(Mutex::new(FecStripes::default())),
            ReceiverStats::new(),
            Arc::new(tokio::sync::Semaphore::new(8)),
            crate::fs_ext::DeferredDontneed::noop(),
            false,
        )
        .await;
        (res, pb.position())
    }

    #[tokio::test]
    async fn fec_late_parity_after_stripe_complete_is_dropped() {
        let data = vec![7u8; MIN_CHUNK_SIZE];
        let (parity, lens) = crate::fec::codec::FecEncoder::new(1, 2)
            .unwrap()
            .encode(vec![data.clone()])
            .unwrap();
        // Data shard completes the stripe; both parity shards arrive late.  With
        // p >= d the second late parity used to make a fresh buffer "ready" and
        // reconstruct + rewrite the stripe (double-counting progress).
        let shards = vec![
            fec_shard(0, 0, false, data, vec![]),
            fec_shard(0, 1, true, parity[0].clone(), lens.clone()),
            fec_shard(0, 2, true, parity[1].clone(), lens),
        ];
        let (res, written) = run_fec_worker(shards).await;
        res.unwrap();
        assert_eq!(
            written, MIN_CHUNK_SIZE as u64,
            "stripe processed exactly once"
        );
    }

    #[tokio::test]
    async fn fec_bogus_stripe_and_shard_indices_error_not_panic() {
        let data = vec![1u8; MIN_CHUNK_SIZE];
        // stripe_index past the end used to underflow `total_chunks - first`.
        let (res, _) = run_fec_worker(vec![fec_shard(5, 0, false, data.clone(), vec![])]).await;
        assert!(res.is_err());
        // Parity metadata with the wrong number of entries.
        let (res, _) = run_fec_worker(vec![fec_shard(0, 1, true, data, vec![1, 2, 3])]).await;
        assert!(res.is_err());
    }

    #[test]
    fn stripe_rejects_data_shard_in_padding_slot() {
        // Last stripe with 1 real chunk out of 4 data shards: slot 2 is padding.
        let mut sb = StripeBuffer::new(0, 4, 1, 1);
        let r = sb.insert(fec_shard(0, 2, false, vec![0u8; 8], vec![]));
        assert!(r.is_err());
        assert!(!sb.is_ready());
    }

    // ── Symlink escape (adversarial DirEntries) ───────────────────────────────

    fn entry(path: &str, kind: FileKind, size: u64) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            size,
            kind,
            mode: 0,
            mtime: 0,
        }
    }

    fn link(path: &str, target: &str) -> FileEntry {
        entry(
            path,
            FileKind::Symlink {
                target: target.to_string(),
            },
            0,
        )
    }

    fn dir_manifest(entries: &[FileEntry]) -> TransferManifest {
        let mut m = base_manifest();
        m.file_size = entries.iter().map(|e| e.size).sum();
        m.total_chunks = m.file_size.div_ceil(m.chunk_size as u64);
        m
    }

    fn check(entries: Vec<FileEntry>) -> Result<()> {
        let m = dir_manifest(&entries);
        validate_dir_entries(
            &m,
            &DirEntries {
                entries: Some(entries),
            },
        )
    }

    #[test]
    fn symlink_leading_dotdot_escape_rejected() {
        // `..` past an empty stack used to be silently dropped, so this resolved
        // to "etc" and passed.
        assert!(check(vec![link("x", "../../../../etc")]).is_err());
        assert!(check(vec![link("x", "..")]).is_err());
        assert!(check(vec![
            entry("d", FileKind::Directory, 0),
            link("d/x", "../../etc")
        ])
        .is_err());
    }

    #[test]
    fn symlink_within_root_accepted() {
        assert!(check(vec![
            entry("d", FileKind::Directory, 0),
            entry("d/f", FileKind::File, 3),
            link("d/x", "../d/f"),
            link("y", "d"),
            link("z", "."),
        ])
        .is_ok());
    }

    #[test]
    fn entry_through_transfer_symlink_rejected() {
        // `a -> d` is in-root, but writing `a/f` would go through the link.
        assert!(check(vec![
            entry("d", FileKind::Directory, 0),
            link("a", "d"),
            entry("a/f", FileKind::File, 3),
        ])
        .is_err());
        // Order-independent: the entry under the link is listed first.
        assert!(check(vec![entry("a/f", FileKind::File, 3), link("a", ".")]).is_err());
    }

    #[test]
    fn symlink_target_through_symlink_rejected() {
        // `q/s` physically points at `x` (depth 1) but is lexically depth 2, so
        // `q/s/../..` passes the lexical check yet lands outside the root.
        assert!(check(vec![
            entry("q", FileKind::Directory, 0),
            link("q/s", "../x"),
            link("t", "q/s/../.."),
        ])
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_directory_refuses_existing_symlink_in_path() {
        let outside = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        // A symlink already present in the destination (e.g. from an earlier
        // transfer, or planted locally) pointing outside the root.
        std::os::unix::fs::symlink(outside.path(), root.path().join("a")).unwrap();
        let entries = vec![entry("a/f", FileKind::File, 3)];
        assert!(prepare_directory(&entries, root.path()).is_err());
        assert!(!outside.path().join("f").exists(), "wrote through symlink");

        // A file entry whose own path is an existing symlink must not follow it.
        std::os::unix::fs::symlink(outside.path().join("g"), root.path().join("g")).unwrap();
        let entries = vec![entry("g", FileKind::File, 3)];
        assert!(prepare_directory(&entries, root.path()).is_err());
        assert!(!outside.path().join("g").exists(), "followed final symlink");
    }
}
