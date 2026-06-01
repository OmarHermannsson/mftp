//! QUIC connection setup and socket tuning.
//!
//! Both sender and receiver use self-signed TLS certificates for transport
//! security. In the initial implementation trust is TOFU (trust-on-first-use)
//! with the peer's certificate fingerprint printed to stdout; a `--trust`
//! flag accepting a known fingerprint will allow scripted use.
//!
//! Socket buffer sizes are requested before binding (the kernel clamps to
//! `net.core.rmem_max`/`wmem_max`; both endpoints log a warning if the full
//! amount isn't granted). The QUIC application windows scale to 512 MiB–1 GiB,
//! so the kernel UDP buffer must be large enough to absorb bursts without
//! dropping datagrams; we default to 64 MiB and allow `MFTP_SOCKET_BUFFER=<bytes>`
//! to raise it further on very-high-BDP links (after raising the sysctl caps).

pub mod connection;
pub mod tcp;

/// Default UDP/TCP socket buffer target: 64 MiB (~500 ms RTT at 1 Gbps BDP).
/// Raised from 32 MiB so the kernel buffer doesn't bottleneck QUIC's much larger
/// application windows on high-BDP paths.
pub const DEFAULT_SOCKET_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Requested socket send/receive buffer size, overridable via `MFTP_SOCKET_BUFFER`
/// (bytes, clamped to [1 MiB, 1 GiB]). The kernel still clamps to its sysctl max.
pub fn socket_buffer_size() -> usize {
    std::env::var("MFTP_SOCKET_BUFFER")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|v| v.clamp(1024 * 1024, 1024 * 1024 * 1024))
        .unwrap_or(DEFAULT_SOCKET_BUFFER_SIZE)
}
