//! QUIC connection setup and socket tuning.
//!
//! Both sender and receiver use self-signed TLS certificates for transport
//! security. In the initial implementation trust is TOFU (trust-on-first-use)
//! with the peer's certificate fingerprint printed to stdout; a `--trust`
//! flag accepting a known fingerprint will allow scripted use.
//!
//! Socket buffer sizes are set to max(2 × BDP, OS default) before binding.
//! BDP is estimated as `bandwidth_bytes_per_sec × rtt_seconds`; without a
//! prior measurement we default to 32 MiB which covers a ~250ms RTT at 1 Gbps.

pub mod connection;
pub mod tcp;

/// UDP/TCP socket buffer size target: 32 MiB covers ~250 ms RTT at 1 Gbps BDP.
pub const SOCKET_BUFFER_SIZE: usize = 32 * 1024 * 1024;
