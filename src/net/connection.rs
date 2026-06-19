//! QUIC endpoint construction for sender and receiver.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use tracing::debug;

/// How long a connection may be idle before it is closed.
/// 10 minutes accommodates hashing very large files on slow disks.
const MAX_IDLE_TIMEOUT_MS: u32 = 10 * 60 * 1000;

/// Sender-side keep-alive interval. The sender sends QUIC PING frames at this
/// rate while waiting for the receiver to finish verifying the file, preventing
/// the connection from hitting the idle timeout on either side.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

// ── Crypto provider ───────────────────────────────────────────────────────────

/// Install the `ring` crypto provider exactly once for the process lifetime.
///
/// Both `ring` and `aws-lc-rs` feature flags can be active simultaneously
/// (e.g. quinn pulls in aws-lc-rs while we request ring). Rustls panics if
/// neither or both are available and no provider has been installed explicitly.
/// Calling this before any TLS object is constructed avoids the ambiguity.
fn install_crypto_provider() {
    use std::sync::OnceLock;
    static DONE: OnceLock<()> = OnceLock::new();
    DONE.get_or_init(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("failed to install ring crypto provider");
    });
}

// ── Transport config ──────────────────────────────────────────────────────────

// QUIC flow-control windows are sized independently of the OS socket buffers.
//
// Quinn's defaults target 100 ms RTT @ 100 Mbps (≈ 1.25 MiB per stream),
// which throttles throughput on any fast or high-latency link:
//
//   150 ms: 1.25 MiB / 0.15 s =  8 MiB/s per stream
//   400 ms: 1.25 MiB / 0.40 s =  3 MiB/s per stream  ← satellite ceiling
//
// Window formula:  window ≥ bandwidth × RTT  (bandwidth-delay product).
// Target: 1 Gbps at up to 500 ms RTT → 64 MiB per stream.
//
//   500 ms: 64 MiB / 0.50 s = 128 MiB/s per stream  (no longer the bottleneck)
//   150 ms: 64 MiB / 0.15 s = 427 MiB/s per stream  (well above wire speed)
//
// Connection-level window covers 8 streams at full speed simultaneously.
// These are decoupled from SO_RCVBUF (still 32 MiB) because the OS socket
// buffer and the QUIC application window serve different purposes: the kernel
// buffer absorbs burst UDP datagrams; the QUIC window controls how much the
// *sender* is allowed to have in flight before the receiver must grant credit.
const STREAM_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024; // 64 MiB per stream
pub(crate) const CONNECTION_RECEIVE_WINDOW: u32 = 8 * 64 * 1024 * 1024; // 512 MiB total
pub(crate) const SEND_WINDOW: u64 = 8 * 64 * 1024 * 1024; // 512 MiB

/// Compute a BDP-aware connection-level window for a measured RTT.
///
/// Uses a 10 Gbps reference bandwidth (generous upper bound) and 1.5× headroom
/// to accommodate BBR's probe phase and ACK delay.  The result is clamped to
/// the static `SEND_WINDOW` floor so that low-latency connections are unchanged.
///
/// At 600 ms RTT → 1.125 GiB (exceeds the 512 MiB static window).
/// At  15 ms RTT → ~28 MiB  → clamped to 512 MiB (no change).
pub fn compute_bdp_window(rtt: std::time::Duration) -> u64 {
    const REFERENCE_BW_BYTES_PER_SEC: f64 = 10_000_000_000.0 / 8.0; // 10 Gbps
    let bdp = (REFERENCE_BW_BYTES_PER_SEC * rtt.as_secs_f64() * 1.5) as u64;
    bdp.max(SEND_WINDOW)
}

/// BBR initial congestion window (bytes).  quinn's BBR default is
/// `200 * 1200 ≈ 234 KiB`; we raise it modestly so the exponential STARTUP phase
/// reaches a high-BDP line rate in a few fewer RTTs (each doubling costs a full
/// RTT — ~600 ms on a satellite link).  Override with `MFTP_INITIAL_CWND=<bytes>`
/// (clamped to [64 KiB, 64 MiB]); lower it on thin/constrained links where a
/// large first-flight burst would cause startup loss.
const DEFAULT_INITIAL_WINDOW: u64 = 1024 * 1024; // 1 MiB

fn bbr_config() -> quinn::congestion::BbrConfig {
    let iw = std::env::var("MFTP_INITIAL_CWND")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|v| v.clamp(64 * 1024, 64 * 1024 * 1024))
        .unwrap_or(DEFAULT_INITIAL_WINDOW);
    let mut cfg = quinn::congestion::BbrConfig::default();
    cfg.initial_window(iw);
    cfg
}

/// Congestion-controller selection.
///
/// Ideally we would pick the controller from the *measured* RTT (improvement
/// #6: BBR for high-RTT/high-BDP paths, a loss-based controller for short,
/// lossy LAN paths).  RTT, however, is only available *after* the QUIC
/// handshake — `negotiate.rs` reads it from `conn.stats().path.rtt`, and the
/// stream-count / chunk-size negotiation already runs at that point.  quinn's
/// `TransportConfig` (where the CC factory must be installed) is, by contrast,
/// fixed *before* the connection is opened, so no RTT estimate exists yet at
/// the moment we build it.  Rebuilding the controller mid-connection is not
/// something quinn 0.11 exposes without tearing down and re-establishing the
/// connection — a risky lifecycle change we deliberately avoid here.
///
/// So instead of an RTT-driven choice we make a deliberate, well-justified
/// *static* choice:
///
/// - **Default: BBR.**  mftp's entire reason for existing is high-BDP links
///   (satellite, intercontinental).  BBR measures bandwidth and RTT directly
///   instead of inferring congestion from packet loss, avoiding the throughput
///   sawtooth CUBIC/Reno exhibit at high latency.  On low-RTT LAN paths mftp
///   already switches to TCP+TLS (see `--tcp-below-rtt`), so the QUIC path is
///   essentially *always* the high-BDP case BBR is best at — making BBR the
///   correct default regardless of RTT.
///
/// - **Override: `MFTP_CC`.**  For paths where the operator knows better
///   (e.g. a measurably lossy link where a loss-based controller behaves more
///   conservatively), `MFTP_CC=cubic` / `=reno` / `=bbr` selects the
///   controller explicitly.  This matches the existing `MFTP_*` env-var
///   convention (`MFTP_INITIAL_CWND`, `MFTP_SOCKET_BUFFER`,
///   `MFTP_ACK_ELICITING_THRESHOLD`) and needs no new CLI flag, per the
///   improvement's "internal/auto only" scope.  Unknown/empty values fall
///   back to the BBR default.
fn set_congestion_controller(t: &mut quinn::TransportConfig) {
    match std::env::var("MFTP_CC")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "cubic" => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        "reno" | "newreno" => {
            t.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default()));
        }
        // "bbr", "", or anything unrecognized → BBR (the high-BDP default).
        _ => {
            t.congestion_controller_factory(Arc::new(bbr_config()));
        }
    }
}

fn transport_base() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(quinn::VarInt::from_u32(MAX_IDLE_TIMEOUT_MS).into()));
    // Congestion control: BBR by default (overridable via MFTP_CC).  BBR
    // measures bandwidth and RTT directly rather than inferring congestion from
    // packet loss, avoiding the sawtooth throughput pattern that loss-based
    // controllers exhibit at high latency and making better use of the pipe on
    // satellite / intercontinental links.  Its initial window is raised above
    // quinn's ~234 KiB default to shorten STARTUP on high-BDP links (see
    // DEFAULT_INITIAL_WINDOW).  See `set_congestion_controller` for why this is
    // a static choice rather than an RTT-driven one.
    set_congestion_controller(&mut t);
    // Start at 1350 B instead of the quinn default of 1200 B.  MTU discovery
    // is already enabled by default and will probe higher; raising the floor
    // skips the lowest portion of the probe range on most real-world paths
    // (Ethernet MTU 1500, QUIC overhead ~40 B → useful payload ≈ 1460 B).
    // Black-hole detection will fall back if the path cannot sustain 1350 B.
    t.initial_mtu(1350);
    // Per-stream and connection-level flow control windows.
    t.stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW));
    t.receive_window(quinn::VarInt::from_u32(CONNECTION_RECEIVE_WINDOW));
    t.send_window(SEND_WINDOW);
    t
}

fn receiver_transport() -> Arc<quinn::TransportConfig> {
    Arc::new(transport_base())
}

fn sender_transport() -> Arc<quinn::TransportConfig> {
    let mut t = transport_base();
    // Send PING frames so the receiver's idle timer doesn't expire while it is
    // hashing the received file.
    t.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    // Optional ACK-frequency tuning: request the peer (the data receiver) to
    // coalesce ACKs, cutting reverse-path ACK traffic on asymmetric/high-RTT
    // links. Off by default — over-batching can blunt BBR's bandwidth/RTT
    // sampling — so enable and tune only with measurement, via
    // MFTP_ACK_ELICITING_THRESHOLD=<n> (ACK after n ack-eliciting packets).
    if let Some(n) = std::env::var("MFTP_ACK_ELICITING_THRESHOLD")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        if let Ok(threshold) = quinn::VarInt::from_u64(n.clamp(1, 1000)) {
            let mut af = quinn::AckFrequencyConfig::default();
            af.ack_eliciting_threshold(threshold);
            t.ack_frequency_config(Some(af));
        }
    }
    Arc::new(t)
}

// ── Server ────────────────────────────────────────────────────────────────────

/// Bind a QUIC server endpoint with a freshly generated self-signed certificate.
///
/// Returns the endpoint and the hex-encoded SHA-256 fingerprint of the
/// certificate, which should be printed for the user to share with the sender.
pub fn make_server_endpoint(bind_addr: SocketAddr) -> Result<(Endpoint, String)> {
    let (cert_der, key_bytes) = generate_self_signed_cert()?;
    let key_der = make_private_key(key_bytes)?;
    let fingerprint = cert_fingerprint(&cert_der);
    let endpoint = make_server_endpoint_with_cert(bind_addr, cert_der, key_der)?;
    debug!(%fingerprint, "server endpoint bound");
    Ok((endpoint, fingerprint))
}

/// A live, reloadable set of authorized peer DeviceIds shared between the daemon
/// and the running TLS verifier.
///
/// The verifier reads the *current* contents on every handshake, so the daemon
/// can swap the set in place (on SIGHUP) and have it take effect for subsequent
/// connections without rebuilding the endpoint. Cheap to clone (an `Arc`).
#[derive(Clone, Debug, Default)]
pub struct ReloadableAllowlist {
    set: Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
}

impl ReloadableAllowlist {
    pub fn new(ids: Vec<String>) -> Self {
        ReloadableAllowlist {
            set: Arc::new(std::sync::RwLock::new(Self::normalize(ids))),
        }
    }

    fn normalize(ids: Vec<String>) -> std::collections::HashSet<String> {
        ids.into_iter().map(|s| s.trim().to_lowercase()).collect()
    }

    /// Replace the entire authorized set (the SIGHUP-reload operation).
    pub fn replace(&self, ids: Vec<String>) {
        *self.set.write().expect("allowlist lock poisoned") = Self::normalize(ids);
    }

    /// True when no peer is authorized — auth is *open* (any/no client cert).
    pub fn is_empty(&self) -> bool {
        self.set.read().expect("allowlist lock poisoned").is_empty()
    }

    /// Number of currently authorized peers.
    pub fn len(&self) -> usize {
        self.set.read().expect("allowlist lock poisoned").len()
    }

    fn contains(&self, id: &str) -> bool {
        self.set
            .read()
            .expect("allowlist lock poisoned")
            .contains(id)
    }
}

/// Verifies an incoming client certificate by its Ed25519 DeviceId against a
/// [`ReloadableAllowlist`] (M4 daemon identity auth).
///
/// When the allowlist is non-empty, mutual TLS is mandatory and a client whose
/// DeviceId is not listed — or that presents no Ed25519 key — is rejected at the
/// handshake. When the allowlist is empty the daemon is *open*: client auth is
/// not mandatory, so a sender without an identity still connects (and any cert
/// that is presented is accepted). This lets SIGHUP flip a daemon between open
/// and enforced without a restart.
#[derive(Debug)]
pub struct DeviceAllowlistVerifier {
    authorized: ReloadableAllowlist,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl DeviceAllowlistVerifier {
    pub fn new(authorized: Vec<String>) -> Self {
        Self::from_allowlist(ReloadableAllowlist::new(authorized))
    }

    pub fn from_allowlist(authorized: ReloadableAllowlist) -> Self {
        DeviceAllowlistVerifier {
            authorized,
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl rustls::server::danger::ClientCertVerifier for DeviceAllowlistVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    /// When the allowlist is empty the daemon is open: don't require a client
    /// certificate (senders without an identity must still connect).
    fn client_auth_mandatory(&self) -> bool {
        !self.authorized.is_empty()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Open mode (empty allowlist): accept whatever cert was presented.
        if self.authorized.is_empty() {
            return Ok(rustls::server::danger::ClientCertVerified::assertion());
        }
        let id = crate::identity::device_id_from_cert(end_entity).ok_or_else(|| {
            rustls::Error::General("client certificate has no Ed25519 device key".into())
        })?;
        if self.authorized.contains(&id) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "client device {id} is not authorized"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

// ── Server (shared cert) ──────────────────────────────────────────────────────

/// Bind a QUIC server endpoint using a pre-generated certificate.
///
/// Use this when you want QUIC and TCP to share the same self-signed certificate
/// (and therefore the same fingerprint).
pub fn make_server_endpoint_with_cert(
    bind_addr: SocketAddr,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<Endpoint> {
    make_server_endpoint_with_cert_auth(bind_addr, cert, key, None)
}

/// Like [`make_server_endpoint_with_cert`], but when `authorized` is
/// `Some(list)` the server requires mutual TLS and only accepts senders whose
/// Ed25519 DeviceId is in `list` (M4 daemon identity auth). `None` keeps the
/// open, server-auth-only behaviour.
pub fn make_server_endpoint_with_cert_auth(
    bind_addr: SocketAddr,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    authorized: Option<Vec<String>>,
) -> Result<Endpoint> {
    install_crypto_provider();

    let builder = rustls::ServerConfig::builder();
    let server_crypto = match authorized {
        Some(list) => builder
            .with_client_cert_verifier(Arc::new(DeviceAllowlistVerifier::new(list)))
            .with_single_cert(vec![cert], key)
            .context("failed to build rustls server config (client auth)")?,
        None => builder
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .context("failed to build rustls server config")?,
    };
    finalize_server_endpoint(bind_addr, server_crypto)
}

/// Like [`make_server_endpoint_with_cert_auth`], but the DeviceId allowlist is a
/// live [`ReloadableAllowlist`] the daemon can update in place (SIGHUP reload).
/// The verifier is always installed: an empty allowlist is *open* (client auth
/// not mandatory), a non-empty one enforces — see [`DeviceAllowlistVerifier`].
pub fn make_server_endpoint_with_reloadable_auth(
    bind_addr: SocketAddr,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    allowlist: ReloadableAllowlist,
) -> Result<Endpoint> {
    install_crypto_provider();
    let server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(DeviceAllowlistVerifier::from_allowlist(allowlist)))
        .with_single_cert(vec![cert], key)
        .context("failed to build rustls server config (reloadable client auth)")?;
    finalize_server_endpoint(bind_addr, server_crypto)
}

/// Wrap a finished rustls server config into a bound QUIC endpoint with the
/// shared receiver transport settings.
fn finalize_server_endpoint(
    bind_addr: SocketAddr,
    server_crypto: rustls::ServerConfig,
) -> Result<Endpoint> {
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    server_config.transport_config(receiver_transport());

    let socket = make_udp_socket(bind_addr)?;
    let runtime = quinn::default_runtime().context("no async runtime")?;
    let abstract_socket = test_support::maybe_wrap(runtime.wrap_udp_socket(socket)?);
    let endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        abstract_socket,
        runtime,
    )?;

    Ok(endpoint)
}

/// Build a QUIC client endpoint.
///
/// `trusted_fingerprint`: if `Some`, the peer certificate must match this
/// hex SHA-256 fingerprint (scripted / non-interactive use).  If `None`,
/// TOFU: the fingerprint is checked against `~/.config/mftp/known_hosts` and
/// the user is prompted on the first connection to a new server.
pub fn make_client_endpoint(
    trusted_fingerprint: Option<&str>,
    trusted_device: Option<&str>,
    client_identity: Option<&crate::identity::Identity>,
    server_addr: SocketAddr,
) -> Result<Endpoint> {
    install_crypto_provider();
    let verifier = build_client_verifier(trusted_fingerprint, trusted_device, server_addr)?;

    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    // Present our device identity as a client certificate so daemons enforcing
    // DeviceId auth can verify us. A server that doesn't request client auth
    // never asks for it, so this is invisible to non-auth receivers.
    let client_crypto = match client_identity {
        Some(id) => builder
            .with_client_auth_cert(
                vec![id.cert.clone()],
                make_private_key(id.key_bytes.clone())?,
            )
            .context("attach client identity certificate")?,
        None => builder.with_no_client_auth(),
    };

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    client_config.transport_config(sender_transport());

    let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let socket = make_udp_socket(bind)?;
    let runtime = quinn::default_runtime().context("no async runtime")?;
    let abstract_socket = test_support::maybe_wrap(runtime.wrap_udp_socket(socket)?);
    let mut endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        abstract_socket,
        runtime,
    )?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

// ── Socket helpers ────────────────────────────────────────────────────────────

fn make_udp_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("UDP socket creation failed")?;

    // Best-effort: some kernels cap at /proc/sys/net/core/rmem_max.
    let buf = super::socket_buffer_size();
    if let Err(e) = socket.set_recv_buffer_size(buf) {
        tracing::warn!("could not set SO_RCVBUF to {buf}: {e}");
    }
    if let Err(e) = socket.set_send_buffer_size(buf) {
        tracing::warn!("could not set SO_SNDBUF to {buf}: {e}");
    }

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

// ── Test-only network-loss injection ──────────────────────────────────────────

/// Process-global packet-loss injection for testing transfer correctness under
/// a lossy link without a remote host + `tc netem`.
///
/// When armed via [`set_send_loss`], every QUIC endpoint built afterwards wraps
/// its UDP socket in a [`LossySocket`] that deterministically drops 1 of every
/// `denom` outbound datagrams (after a short warm-up so the handshake starts
/// cleanly).  Dropping is on the send path — quinn believes the datagram was
/// sent, so its normal loss recovery retransmits it, exactly as for a datagram
/// lost in the network.  Production never arms the knob, so the only cost on the
/// hot path is nil (the wrapper is bypassed) and at endpoint-construction time a
/// single relaxed atomic load.  Hidden from docs; mirrors the receiver's
/// `test_hooks` pattern.
#[doc(hidden)]
pub mod test_support {
    use super::*;
    use quinn::udp::{RecvMeta, Transmit};
    use quinn::{AsyncUdpSocket, UdpPoller};
    use std::io::{self, IoSliceMut};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};

    /// Drop 1 of every `DENOM` datagrams; 0 disables injection.
    static SEND_LOSS_DENOM: AtomicU64 = AtomicU64::new(0);
    /// First few datagrams per socket are never dropped, so the QUIC handshake
    /// reliably gets underway before loss begins.
    const WARMUP: u64 = 16;

    /// Arm loss injection: every subsequently-built endpoint drops 1 of every
    /// `denom` outbound datagrams.  `denom == 0` disables it.
    pub fn set_send_loss(denom: u64) {
        SEND_LOSS_DENOM.store(denom, Ordering::Relaxed);
    }

    /// Disarm loss injection.
    pub fn clear() {
        SEND_LOSS_DENOM.store(0, Ordering::Relaxed);
    }

    /// Wrap `socket` in a [`LossySocket`] iff loss injection is currently armed;
    /// otherwise return it unchanged.  Called by the endpoint constructors.
    pub(crate) fn maybe_wrap(socket: Arc<dyn AsyncUdpSocket>) -> Arc<dyn AsyncUdpSocket> {
        let denom = SEND_LOSS_DENOM.load(Ordering::Relaxed);
        if denom == 0 {
            socket
        } else {
            Arc::new(LossySocket {
                inner: socket,
                denom,
                sent: AtomicU64::new(0),
            })
        }
    }

    /// An [`AsyncUdpSocket`] that forwards to an inner socket but silently drops
    /// a deterministic fraction of outbound datagrams.
    #[derive(Debug)]
    struct LossySocket {
        inner: Arc<dyn AsyncUdpSocket>,
        denom: u64,
        sent: AtomicU64,
    }

    impl LossySocket {
        fn should_drop(&self) -> bool {
            let n = self.sent.fetch_add(1, Ordering::Relaxed);
            n >= WARMUP && (n - WARMUP).is_multiple_of(self.denom)
        }
    }

    impl AsyncUdpSocket for LossySocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            self.inner.clone().create_io_poller()
        }

        fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
            if self.should_drop() {
                // Report success without transmitting: the datagram is "lost"
                // and quinn's loss recovery will retransmit it.
                return Ok(());
            }
            self.inner.try_send(transmit)
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            self.inner.poll_recv(cx, bufs, meta)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        // Force one datagram per send so the drop fraction is per-datagram
        // (disables GSO batching — irrelevant for tests).
        fn max_transmit_segments(&self) -> usize {
            1
        }

        fn max_receive_segments(&self) -> usize {
            self.inner.max_receive_segments()
        }

        fn may_fragment(&self) -> bool {
            self.inner.may_fragment()
        }
    }
}

// ── TLS certificate helpers ───────────────────────────────────────────────────

/// Generate a fresh self-signed certificate for this endpoint.
///
/// Returns the DER-encoded certificate and the raw private-key bytes.
/// The raw key bytes can be cloned freely; call [`make_private_key`] to
/// reconstruct a [`PrivateKeyDer`] from them.
pub fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["mftp".into()])
        .context("cert generation failed")?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_bytes = cert.key_pair.serialize_der();
    Ok((cert_der, key_bytes))
}

/// Wrap raw key bytes in a [`PrivateKeyDer`].
pub fn make_private_key(key_bytes: Vec<u8>) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::try_from(key_bytes).map_err(|e| anyhow::anyhow!("bad private key: {e}"))
}

/// SHA-256 fingerprint of a DER certificate, hex-encoded.
pub fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(cert.as_ref()))
}

/// Build a rustls `ServerConfig` for the TCP+TLS path (no QUIC-specific settings).
pub fn make_server_tls_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    install_crypto_provider();
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("failed to build rustls server config")
}

/// Build a rustls `ClientConfig` for the TCP+TLS path (no QUIC-specific settings).
pub fn make_client_tls_config(
    trusted_fingerprint: Option<&str>,
    trusted_device: Option<&str>,
    server_addr: SocketAddr,
) -> Result<rustls::ClientConfig> {
    install_crypto_provider();
    let verifier = build_client_verifier(trusted_fingerprint, trusted_device, server_addr)?;
    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

// ── Certificate verifiers ─────────────────────────────────────────────────────

/// TOFU (trust-on-first-use) verifier.
///
/// On the first connection to a given `server_addr`, the certificate fingerprint
/// is stored in `~/.config/mftp/known_hosts` after the user confirms it.
/// On subsequent connections, the stored fingerprint is compared and any
/// mismatch is treated as a potential MITM attack.
#[derive(Debug)]
struct TofuVerifier {
    server_addr: SocketAddr,
}

impl TofuVerifier {
    fn new(server_addr: SocketAddr) -> Self {
        Self { server_addr }
    }
}

impl rustls::client::danger::ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = cert_fingerprint(end_entity);
        match load_known_host(self.server_addr) {
            Some(known_fp) => {
                if fp != known_fp {
                    return Err(rustls::Error::General(format!(
                        "certificate fingerprint mismatch for {} — possible MITM attack!\n  \
                         stored:  {known_fp}\n  got:     {fp}\n  \
                         If the server cert changed intentionally, remove the entry for {} \
                         from ~/.config/mftp/known_hosts",
                        self.server_addr, self.server_addr,
                    )));
                }
                // Fingerprint matches stored value — accept silently.
            }
            None => {
                // First connection to this server — prompt the user.
                eprintln!("Server certificate fingerprint (SHA-256):\n  {fp}");
                if !prompt_trust() {
                    return Err(rustls::Error::General(format!(
                        "certificate not trusted\n  \
                         To pin this fingerprint for non-interactive use, add --trust {fp}\n  \
                         To accept interactively, run from a terminal without stdin redirected"
                    )));
                }
                store_known_host(self.server_addr, &fp);
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accepts only a certificate whose SHA-256 fingerprint matches a pre-shared value.
#[derive(Debug)]
struct PinnedFingerprintVerifier {
    expected: String,
}

impl PinnedFingerprintVerifier {
    fn new(fp: &str) -> Result<Self> {
        let normalized = normalize_fingerprint(fp);
        if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!(
                "invalid --trust fingerprint (expected 64 hex chars, got {} usable): {fp:?}",
                normalized.len()
            );
        }
        Ok(Self {
            expected: normalized,
        })
    }
}

/// Normalize a user-supplied fingerprint for comparison.
///
/// Tolerates the shapes people actually paste: surrounding whitespace, a
/// `sha256:` prefix, and `AA:BB:..`/spaced grouping, and case.  Produces a bare
/// lowercase hex string.
fn normalize_fingerprint(fp: &str) -> String {
    fp.trim()
        .trim_start_matches("sha256:")
        .trim_start_matches("SHA256:")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

impl rustls::client::danger::ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = cert_fingerprint(end_entity);
        if fp != self.expected {
            return Err(rustls::Error::General(format!(
                "certificate fingerprint mismatch\n  got:      {fp}\n  expected: {}",
                self.expected
            )));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accepts only a certificate whose Ed25519 DeviceId matches a pre-shared value.
///
/// Unlike [`PinnedFingerprintVerifier`] (which pins the whole certificate),
/// this pins the device's public key, so it keeps matching even if the device
/// re-issues its certificate. The DeviceId is the hex SHA-256 of the cert's
/// Ed25519 SubjectPublicKeyInfo (see [`crate::identity::device_id_from_cert`]).
#[derive(Debug)]
struct PinnedDeviceVerifier {
    expected: String,
}

impl PinnedDeviceVerifier {
    fn new(device_id: &str) -> Result<Self> {
        let normalized = normalize_fingerprint(device_id);
        if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!(
                "invalid --trust-device id (expected 64 hex chars, got {} usable): {device_id:?}",
                normalized.len()
            );
        }
        Ok(Self {
            expected: normalized,
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedDeviceVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let got = crate::identity::device_id_from_cert(end_entity).ok_or_else(|| {
            rustls::Error::General(
                "peer certificate has no Ed25519 device key — cannot match --trust-device".into(),
            )
        })?;
        if got != self.expected {
            return Err(rustls::Error::General(format!(
                "device id mismatch\n  got:      {got}\n  expected: {}",
                self.expected
            )));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build the client-side certificate verifier from the trust options.
///
/// Precedence: a pinned DeviceId (`--trust-device`) wins over a pinned cert
/// fingerprint (`--trust`), which wins over interactive TOFU.
fn build_client_verifier(
    trusted_fingerprint: Option<&str>,
    trusted_device: Option<&str>,
    server_addr: SocketAddr,
) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>> {
    Ok(match (trusted_device, trusted_fingerprint) {
        (Some(dev), _) => Arc::new(PinnedDeviceVerifier::new(dev)?),
        (None, Some(fp)) => Arc::new(PinnedFingerprintVerifier::new(fp)?),
        (None, None) => Arc::new(TofuVerifier::new(server_addr)),
    })
}

// ── TOFU known-hosts helpers ──────────────────────────────────────────────────

fn known_hosts_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/mftp/known_hosts"))
}

/// Look up the stored fingerprint for `addr` in `~/.config/mftp/known_hosts`.
fn load_known_host(addr: SocketAddr) -> Option<String> {
    let path = known_hosts_path()?;
    let content = std::fs::read_to_string(path).ok()?;
    let key = addr.to_string();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        if parts.next()? == key {
            return Some(parts.next()?.trim().to_owned());
        }
    }
    None
}

/// Append an `addr fingerprint` entry to `~/.config/mftp/known_hosts`.
fn store_known_host(addr: SocketAddr, fp: &str) {
    let Some(path) = known_hosts_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
    };
    #[cfg(not(unix))]
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path);
    if let Ok(mut f) = file {
        let _ = writeln!(f, "{addr} {fp}");
    }
}

/// Prompt the user to accept a new certificate fingerprint.
///
/// Opens `/dev/tty` directly so the prompt works even when stdin is redirected.
/// Returns `true` if the user types "yes" (case-insensitive).  Returns `false`
/// in non-interactive contexts where `/dev/tty` is not available — callers
/// must refuse the connection and tell the user to pass `--trust <fingerprint>`.
fn prompt_trust() -> bool {
    use std::io::{BufRead, BufReader, Write};
    let Ok(mut tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        // No controlling terminal — cannot prompt.  Caller emits error with --trust hint.
        return false;
    };
    let _ = write!(tty, "Trust this certificate? [yes/N]: ");
    let _ = tty.flush();
    // Re-open for reading so we don't hold a conflicting borrow.
    let Ok(tty_r) = std::fs::File::open("/dev/tty") else {
        return false;
    };
    let mut answer = String::new();
    BufReader::new(tty_r).read_line(&mut answer).ok();
    answer.trim().eq_ignore_ascii_case("yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fingerprint_normalization_tolerates_common_shapes() {
        let canonical = "a".repeat(64);
        // Already canonical.
        assert!(PinnedFingerprintVerifier::new(&canonical).is_ok());
        // Uppercase, surrounding whitespace, sha256: prefix, and colon grouping.
        let messy = format!("  SHA256:{}  ", "AA:".repeat(32));
        let v = PinnedFingerprintVerifier::new(&messy).expect("should normalize");
        assert_eq!(v.expected, canonical);
        // Still rejects genuinely wrong input.
        assert!(PinnedFingerprintVerifier::new("deadbeef").is_err());
        assert!(PinnedFingerprintVerifier::new(&"z".repeat(64)).is_err());
    }

    #[test]
    fn congestion_controller_selection_does_not_panic() {
        // Exercises all MFTP_CC branches: each must construct a valid
        // TransportConfig without panicking.  (Env var is process-global, so we
        // keep this to one test to avoid cross-test interference.)
        for v in ["bbr", "cubic", "reno", "newreno", "BBR", "", "garbage"] {
            std::env::set_var("MFTP_CC", v);
            let mut t = quinn::TransportConfig::default();
            set_congestion_controller(&mut t);
        }
        std::env::remove_var("MFTP_CC");
        // Default path (var unset) must also work.
        let mut t = quinn::TransportConfig::default();
        set_congestion_controller(&mut t);
    }

    #[test]
    fn bdp_window_clamps_at_floor_for_low_rtt() {
        // At 15 ms RTT: BDP = 1.25 GB/s * 0.015 * 1.5 = ~28 MiB → clamped to 512 MiB.
        let w = compute_bdp_window(Duration::from_millis(15));
        assert_eq!(
            w, SEND_WINDOW,
            "low-RTT window should equal the static floor"
        );
    }

    #[test]
    fn bdp_window_scales_for_high_rtt() {
        // At 600 ms RTT: BDP = 1.25 GB/s * 0.6 * 1.5 = 1.125 GiB > 512 MiB.
        let w = compute_bdp_window(Duration::from_millis(600));
        let floor = SEND_WINDOW;
        assert!(w > floor, "high-RTT window should exceed the static floor");
        // Sanity-check the magnitude: expect roughly 1.1 GiB ± 10%.
        let expected = (10_000_000_000u64 / 8) * 6 / 10 * 15 / 10; // ≈ 1.125 GiB
        assert!(
            (w as i64 - expected as i64).unsigned_abs() < expected / 10,
            "window {w} should be close to {expected}"
        );
    }

    // ── Hole-punching feasibility spike (M6) ───────────────────────────────────
    //
    // De-risks the make-or-break question before building NAT traversal: can we
    // (1) send raw "punch" datagrams on a UDP socket and then run a quinn
    // connection over that *same* socket, and (2) does quinn's server tolerate a
    // non-QUIC datagram (the peer's punch probe) arriving on its socket before
    // the handshake? Both are required because hole-punching must open the NAT
    // mapping on the exact socket/port quinn will use, and probes from the peer
    // will land on quinn's socket during the punch.

    /// Build a quinn **server** endpoint on an already-created (possibly
    /// pre-probed) socket — the seam the real feature needs to run QUIC over a
    /// punched mapping.
    fn server_endpoint_on(
        socket: std::net::UdpSocket,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Endpoint {
        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let mut sc = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));
        sc.transport_config(receiver_transport());
        let runtime = quinn::default_runtime().unwrap();
        Endpoint::new(quinn::EndpointConfig::default(), Some(sc), socket, runtime).unwrap()
    }

    /// Build a quinn **client** endpoint on an already-created (pre-probed) socket,
    /// pinning the server's cert fingerprint.
    fn client_endpoint_on(socket: std::net::UdpSocket, fingerprint: &str) -> Endpoint {
        let runtime = quinn::default_runtime().unwrap();
        let abstract_socket = runtime.wrap_udp_socket(socket).unwrap();
        client_endpoint_on_abstract(abstract_socket, fingerprint)
    }

    /// Like [`client_endpoint_on`], but over an arbitrary abstract socket — e.g. a
    /// `natsim::NatSocket` so the client runs behind a simulated NAT.
    fn client_endpoint_on_abstract(
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        fingerprint: &str,
    ) -> Endpoint {
        let verifier = Arc::new(PinnedFingerprintVerifier::new(fingerprint).unwrap());
        let client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let mut cc = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        ));
        cc.transport_config(sender_transport());
        let runtime = quinn::default_runtime().unwrap();
        let mut ep = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .unwrap();
        ep.set_default_client_config(cc);
        ep
    }

    #[tokio::test]
    async fn holepunch_spike_quinn_runs_over_pre_probed_socket() {
        install_crypto_provider();
        let (cert, key_bytes) = generate_self_signed_cert().unwrap();
        let fingerprint = cert_fingerprint(&cert);

        // ── Receiver: quinn server on its own socket, accepting one connection. ──
        let recv_sock = make_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let server = server_endpoint_on(recv_sock, cert, make_private_key(key_bytes).unwrap());
        let accept = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut buf = [0u8; 5];
            recv.read_exact(&mut buf).await.unwrap();
            send.write_all(b"pong").await.unwrap();
            send.finish().unwrap();
            // Wait for the client to close (after it has read the reply) so the
            // finished stream is flushed before this task — and the endpoint —
            // drop.
            conn.closed().await;
            buf
        });

        // ── Sender: pre-probe on its socket, then run quinn over that same one. ──
        let send_sock = make_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        // (1) Raw "punch" probe from the exact socket quinn will use. In a real
        // NAT this opens the mapping; here it also (2) exercises the receiver's
        // quinn server tolerating a non-QUIC datagram before the handshake.
        send_sock
            .send_to(b"\x00\x01mftp-punch-probe", recv_addr)
            .expect("raw probe send");

        let client = client_endpoint_on(send_sock, &fingerprint);
        let conn = client.connect(recv_addr, "mftp").unwrap().await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"hello").await.unwrap();
        send.finish().unwrap();
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong", "handshake + data survived punch-then-QUIC");

        // Reply received → close the client connection, which releases the
        // server's `closed().await` above (avoids a teardown deadlock).
        conn.close(0u32.into(), b"done");

        let got = tokio::time::timeout(std::time::Duration::from_secs(5), accept)
            .await
            .expect("server task finishes promptly after client close")
            .unwrap();
        assert_eq!(
            &got, b"hello",
            "server received the payload despite a pre-handshake junk datagram"
        );
    }

    /// Phase 0b: a real QUIC connection survives running over the NAT simulator —
    /// the client endpoint sits behind a full-cone `NatSocket`, so its traffic is
    /// re-sourced through the NAT's mapped external address and the receiver's
    /// replies come back through it.
    #[tokio::test]
    async fn natsim_carries_quic_through_a_cone_nat() {
        use crate::net::natsim::{NatPolicy, NatSocket};

        install_crypto_provider();
        let (cert, key_bytes) = generate_self_signed_cert().unwrap();
        let fingerprint = cert_fingerprint(&cert);

        // Receiver on a plain socket.
        let recv_sock = make_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let server = server_endpoint_on(recv_sock, cert, make_private_key(key_bytes).unwrap());
        let accept = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut buf = [0u8; 5];
            recv.read_exact(&mut buf).await.unwrap();
            send.write_all(b"pong").await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
            // The receiver sees the connection coming from the NAT's external
            // (mapped) address, not the client's synthetic internal one.
            (buf, conn.remote_address())
        });

        // Client behind a full-cone NAT.
        let nat = Arc::new(NatSocket::new(NatPolicy::full_cone()));
        let client = client_endpoint_on_abstract(nat, &fingerprint);
        let conn = client.connect(recv_addr, "mftp").unwrap().await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"hello").await.unwrap();
        send.finish().unwrap();
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong", "QUIC data round-trips through the cone NAT");
        conn.close(0u32.into(), b"done");

        let (got, remote) = tokio::time::timeout(std::time::Duration::from_secs(5), accept)
            .await
            .expect("server task finishes promptly")
            .unwrap();
        assert_eq!(&got, b"hello");
        // The remote address the receiver observed is a NAT external port, not the
        // client's 127.0.0.2:4xxxx synthetic internal address.
        assert_ne!(
            remote.ip().to_string(),
            "127.0.0.2",
            "receiver should see the NAT's mapped address, not the internal one"
        );
    }
}
