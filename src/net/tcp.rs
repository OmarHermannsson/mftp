//! TCP+TLS socket helpers for the TCP fallback transport.
//!
//! Encryption uses the same TLS 1.3 / self-signed-certificate / TOFU model as
//! the QUIC path, so the receiver prints one fingerprint and the sender's
//! `--trust` flag works for both transports.
//!
//! Buffer sizes match the QUIC path: 32 MiB SO_SNDBUF/SO_RCVBUF.
//! TCP_NODELAY is set on every stream to eliminate Nagle delay on control
//! messages (NegotiateRequest, Ready, …).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// How long to wait for a TCP handshake before giving up.
///
/// Matches the QUIC connect timeout so that a firewall silently dropping UDP
/// *and* TCP packets fails fast enough for the SSH tunnel fallback to kick in
/// within a few seconds rather than waiting for the OS TCP retransmit timeout
/// (~2 minutes on Linux).
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub use tokio_rustls::client::TlsStream as ClientTlsStream;
pub use tokio_rustls::server::TlsStream as ServerTlsStream;

// ── Listener helpers ──────────────────────────────────────────────────────────

/// Bind a TCP listener with large send/recv buffers.
///
/// Returns the tokio [`TcpListener`] and the actual bound address.
pub async fn bind_tcp(addr: SocketAddr) -> Result<(TcpListener, SocketAddr)> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("TCP socket creation failed")?;
    socket.set_reuse_address(true).context("SO_REUSEADDR")?;
    if let Err(e) = socket.set_recv_buffer_size(super::SOCKET_BUFFER_SIZE) {
        tracing::warn!("could not set SO_RCVBUF to {}: {e}", super::SOCKET_BUFFER_SIZE);
    }
    if let Err(e) = socket.set_send_buffer_size(super::SOCKET_BUFFER_SIZE) {
        tracing::warn!("could not set SO_SNDBUF to {}: {e}", super::SOCKET_BUFFER_SIZE);
    }
    socket.set_nonblocking(true).context("set_nonblocking")?;
    socket.bind(&addr.into()).context("TCP bind")?;
    socket.listen(128).context("TCP listen")?;
    let std_listener: std::net::TcpListener = socket.into();
    let local_addr = std_listener.local_addr()?;
    let listener = TcpListener::from_std(std_listener).context("tokio TcpListener")?;
    Ok((listener, local_addr))
}

/// Build a [`TlsAcceptor`] from a pre-generated certificate and private key.
pub fn make_tls_acceptor(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor> {
    use crate::net::connection::make_server_tls_config;
    let config = make_server_tls_config(cert, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

// ── Connection helpers ────────────────────────────────────────────────────────

/// Connect and TLS-handshake a stream to `addr`.
///
/// `trusted_fingerprint`: if `Some`, the peer certificate must match this
/// hex SHA-256 fingerprint.  If `None`, TOFU: accept any cert and print the
/// fingerprint (same behaviour as the QUIC path).
pub async fn connect_tls(
    addr: SocketAddr,
    trusted_fingerprint: Option<&str>,
) -> Result<ClientTlsStream<TcpStream>> {
    use crate::net::connection::make_client_tls_config;

    let tcp = connect_raw(addr).await?;
    let config = make_client_tls_config(trusted_fingerprint, addr)?;
    let connector = TlsConnector::from(Arc::new(config));
    // Use the server's IP address as the TLS SNI — our custom verifiers don't
    // validate the name, but TLS requires one.
    let server_name = ServerName::IpAddress(addr.ip().into());
    connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")
}

// ── Internal ──────────────────────────────────────────────────────────────────

async fn connect_raw(addr: SocketAddr) -> Result<TcpStream> {
    let socket = if addr.is_ipv6() {
        TcpSocket::new_v6()
    } else {
        TcpSocket::new_v4()
    }
    .context("TCP socket creation failed")?;

    // Mirror the buffer sizing from the server side (bind_tcp) and the QUIC path.
    if let Err(e) = socket.set_recv_buffer_size(super::SOCKET_BUFFER_SIZE as u32) {
        tracing::warn!("could not set SO_RCVBUF to {}: {e}", super::SOCKET_BUFFER_SIZE);
    }
    if let Err(e) = socket.set_send_buffer_size(super::SOCKET_BUFFER_SIZE as u32) {
        tracing::warn!("could not set SO_SNDBUF to {}: {e}", super::SOCKET_BUFFER_SIZE);
    }

    let stream = tokio::time::timeout(TCP_CONNECT_TIMEOUT, socket.connect(addr))
        .await
        .with_context(|| format!("TCP connect to {addr} timed out after {TCP_CONNECT_TIMEOUT:.1?}"))?
        .with_context(|| format!("TCP connect to {addr}"))?;
    stream.set_nodelay(true).context("TCP_NODELAY")?;
    Ok(stream)
}
