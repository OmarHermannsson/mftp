//! TCP socket helpers for the TCP fallback transport.
//!
//! Buffer sizes match the QUIC path: 32 MiB SO_SNDBUF/SO_RCVBUF so a LAN
//! burst can fill the kernel buffers without stalling.  TCP_NODELAY is set
//! on every stream so small control messages (NegotiateRequest, Ready, …)
//! are not delayed by Nagle's algorithm.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

/// TCP socket buffer size — same target as QUIC path.
const SOCKET_BUFFER_SIZE: usize = 32 * 1024 * 1024; // 32 MiB

/// Bind a TCP listener with large send/recv buffers.
///
/// Returns the tokio [`TcpListener`] and the actual bound address.
/// The actual address differs from `addr` when `addr` uses port 0.
pub async fn bind_tcp(addr: SocketAddr) -> Result<(TcpListener, SocketAddr)> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("TCP socket creation failed")?;
    socket.set_reuse_address(true).context("SO_REUSEADDR")?;
    if let Err(e) = socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
        tracing::warn!("could not set SO_RCVBUF to {SOCKET_BUFFER_SIZE}: {e}");
    }
    if let Err(e) = socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
        tracing::warn!("could not set SO_SNDBUF to {SOCKET_BUFFER_SIZE}: {e}");
    }
    socket.set_nonblocking(true).context("set_nonblocking")?;
    socket.bind(&addr.into()).context("TCP bind")?;
    socket.listen(128).context("TCP listen")?;
    let std_listener: std::net::TcpListener = socket.into();
    let local_addr = std_listener.local_addr()?;
    let listener = TcpListener::from_std(std_listener).context("tokio TcpListener")?;
    Ok((listener, local_addr))
}

/// Connect a TCP stream. Sets `TCP_NODELAY` to minimise control-message latency.
pub async fn connect_tcp(addr: SocketAddr) -> Result<TcpStream> {
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("TCP connect to {addr}"))?;
    stream.set_nodelay(true).context("TCP_NODELAY")?;
    Ok(stream)
}
