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

// Set QUIC flow control windows to match the OS socket buffer size.
// Quinn's defaults are sized for 100 ms RTT @ 100 Mbps (≈ 1.25 MiB per stream),
// which throttles throughput at high latency:
//
//   150 ms: 1.25 MiB / 0.15 s = 8.3 MiB/s per stream × 8 = 67 MiB/s max
//   400 ms: 1.25 MiB / 0.40 s = 3.1 MiB/s per stream × 8 = 25 MiB/s max
//
// Per-stream window is 32 MiB (matching SO_RCVBUF) so each stream is never
// flow-control limited.  The connection-level window must be larger: it caps
// the *total* in-flight bytes across all streams.  Setting it equal to the
// per-stream window (the prior bug) meant at most one stream could have a
// full window at a time, capping aggregate throughput to ~320 MiB/s at 100ms
// even with 16 streams.  256 MiB covers 8 streams × 32 MiB each.
const STREAM_RECEIVE_WINDOW: u32 = super::SOCKET_BUFFER_SIZE as u32; // 32 MiB per stream
const CONNECTION_RECEIVE_WINDOW: u32 = 8 * super::SOCKET_BUFFER_SIZE as u32; // 256 MiB total
const SEND_WINDOW: u64 = 8 * super::SOCKET_BUFFER_SIZE as u64; // 256 MiB

fn transport_base() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(quinn::VarInt::from_u32(MAX_IDLE_TIMEOUT_MS).into()));
    // BBR congestion control: measures bandwidth and RTT directly rather than
    // inferring congestion from packet loss (CUBIC default).  This avoids the
    // sawtooth throughput pattern that CUBIC exhibits at high latency and makes
    // better use of the pipe on satellite / intercontinental links.
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
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
    install_crypto_provider();

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("failed to build rustls server config")?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    server_config.transport_config(receiver_transport());

    let socket = make_udp_socket(bind_addr)?;
    let runtime = quinn::default_runtime().context("no async runtime")?;
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
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
    server_addr: SocketAddr,
) -> Result<Endpoint> {
    install_crypto_provider();
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match trusted_fingerprint {
        Some(fp) => Arc::new(PinnedFingerprintVerifier::new(fp)?),
        None => Arc::new(TofuVerifier::new(server_addr)),
    };

    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    client_config.transport_config(sender_transport());

    let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let socket = make_udp_socket(bind)?;
    let runtime = quinn::default_runtime().context("no async runtime")?;
    let mut endpoint = Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;
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
    if let Err(e) = socket.set_recv_buffer_size(super::SOCKET_BUFFER_SIZE) {
        tracing::warn!(
            "could not set SO_RCVBUF to {}: {e}",
            super::SOCKET_BUFFER_SIZE
        );
    }
    if let Err(e) = socket.set_send_buffer_size(super::SOCKET_BUFFER_SIZE) {
        tracing::warn!(
            "could not set SO_SNDBUF to {}: {e}",
            super::SOCKET_BUFFER_SIZE
        );
    }

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
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
    server_addr: SocketAddr,
) -> Result<rustls::ClientConfig> {
    install_crypto_provider();
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match trusted_fingerprint {
        Some(fp) => Arc::new(PinnedFingerprintVerifier::new(fp)?),
        None => Arc::new(TofuVerifier::new(server_addr)),
    };
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
        if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("invalid fingerprint (expected 64 hex chars): {fp}");
        }
        Ok(Self {
            expected: fp.to_ascii_lowercase(),
        })
    }
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
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
    {
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
