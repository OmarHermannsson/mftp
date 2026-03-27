//! QUIC endpoint construction for sender and receiver.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use tracing::debug;

/// UDP socket buffer size: 32 MiB covers ~250 ms RTT at 1 Gbps BDP.
const SOCKET_BUFFER_SIZE: usize = 32 * 1024 * 1024;

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

fn receiver_transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(quinn::VarInt::from_u32(MAX_IDLE_TIMEOUT_MS).into()));
    Arc::new(t)
}

fn sender_transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(quinn::VarInt::from_u32(MAX_IDLE_TIMEOUT_MS).into()));
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
    install_crypto_provider();
    let (cert_der, key_der) = generate_self_signed_cert()?;
    let fingerprint = cert_fingerprint(&cert_der);

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
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

    debug!(%fingerprint, "server endpoint bound");
    Ok((endpoint, fingerprint))
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Build a QUIC client endpoint.
///
/// `trusted_fingerprint`: if `Some`, the peer certificate must match this
/// hex SHA-256 fingerprint (scripted / non-interactive use).  If `None`,
/// the first connection is accepted and the fingerprint is printed; the
/// caller is responsible for prompting the user.
pub fn make_client_endpoint(trusted_fingerprint: Option<&str>) -> Result<Endpoint> {
    install_crypto_provider();
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        match trusted_fingerprint {
            Some(fp) => Arc::new(PinnedFingerprintVerifier::new(fp)?),
            None => Arc::new(TofuVerifier),
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
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

// ── Socket helpers ────────────────────────────────────────────────────────────

fn make_udp_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("UDP socket creation failed")?;

    // Best-effort: some kernels cap at /proc/sys/net/core/rmem_max.
    if let Err(e) = socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
        tracing::warn!("could not set SO_RCVBUF to {SOCKET_BUFFER_SIZE}: {e}");
    }
    if let Err(e) = socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
        tracing::warn!("could not set SO_SNDBUF to {SOCKET_BUFFER_SIZE}: {e}");
    }

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

// ── TLS certificate helpers ───────────────────────────────────────────────────

fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["mftp".into()])
        .context("cert generation failed")?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("bad private key: {e}"))?;
    Ok((cert_der, key_der))
}

fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(cert.as_ref()))
}

// ── Certificate verifiers ─────────────────────────────────────────────────────

/// Accepts any certificate and prints its fingerprint. Used for the very first
/// connection when no fingerprint has been pinned yet (interactive TOFU).
#[derive(Debug)]
struct TofuVerifier;

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
        eprintln!("Server certificate fingerprint (SHA-256):\n  {fp}");
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
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
        Ok(Self { expected: fp.to_ascii_lowercase() })
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
        &self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
