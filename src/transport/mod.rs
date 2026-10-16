//! Pluggable transport abstraction (mftp v2, milestone M1).
//!
//! The data-plane engine ([`crate::transfer::run_transfer`] /
//! `run_receive`) is already generic over `AsyncRead`/`AsyncWrite` plus
//! stream-factory closures, so a "transport" only needs to expose two things
//! the engine itself depends on:
//!
//!   * **path metrics** — live RTT / loss / congestion window, used to size the
//!     send window and drive adaptive stream scaling, and
//!   * **capabilities** — whether the link is already reliable (so FEC is
//!     redundant), whether it supports many concurrent streams, and whether the
//!     connection-level send window can be enlarged for high-BDP links.
//!
//! Stream *lifecycle* (open / accept) stays as the engine's existing factory
//! closures — they were the de-facto transport seam already. This trait
//! formalises the remaining, capability surface so the engine no longer
//! references `quinn` directly, and so future transports (multipath/link
//! bonding in M3, relay in M7) can be selected behind one interface.
//!
//! SFTP is deliberately **not** a `Transport`: it is a whole-file protocol, not
//! a chunk/stream transport, and remains the terminal fallback in the cascade.

use std::time::Duration;

/// Live metrics for a transport path, sampled during a transfer.
///
/// For QUIC these come straight from `quinn`'s connection stats; for TCP+TLS
/// (where the kernel owns congestion control) only the negotiated round-trip
/// estimate is available and the rest default to zero / `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStats {
    /// Smoothed round-trip time for the path.
    pub rtt: Duration,
    /// Cumulative packets the congestion controller has declared lost.
    pub lost_packets: u64,
    /// Current congestion window in bytes, if the transport exposes it.
    pub cwnd: Option<u64>,
}

impl Default for PathStats {
    fn default() -> Self {
        PathStats {
            rtt: Duration::ZERO,
            lost_packets: 0,
            cwnd: None,
        }
    }
}

/// Static capabilities of a transport, used by the engine to decide behaviour
/// without knowing the concrete transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportCaps {
    /// The transport already guarantees in-order reliable delivery (TCP, or a
    /// QUIC reliable stream). When `true` the engine disables FEC — parity
    /// shards would only add overhead over a transport that already retransmits.
    pub reliable: bool,
    /// The transport supports many cheap concurrent streams (QUIC opens streams
    /// instantly on one connection; TCP needs a fresh handshake per stream but
    /// still supports many).
    pub multistream: bool,
    /// The connection-level send window can be enlarged for high-BDP links via
    /// [`Transport::set_send_window`]. Only QUIC honours this; the kernel owns
    /// the TCP window.
    pub supports_window_tuning: bool,
    /// Hint for the largest datagram the transport can carry efficiently, if
    /// known (QUIC after MTU probing); `None` when not applicable.
    pub mtu_hint: Option<u16>,
}

/// A selected transport path the engine can query for metrics and tune.
///
/// Object-safe and synchronous: stream open/accept stays in the engine's
/// factory closures (see module docs), so this trait only carries the
/// capability + metrics surface. `Send + Sync` because the sampler task in
/// `run_transfer` reads it from a background task.
pub trait Transport: Send + Sync {
    /// Short human-readable name for logs/diagnostics (e.g. `"quic"`, `"tcp"`).
    fn name(&self) -> &'static str;

    /// Static capabilities of this transport.
    fn caps(&self) -> TransportCaps;

    /// Current live path metrics. Cheap to call (sampled ~1×/s).
    fn path_stats(&self) -> PathStats;

    /// Request a larger connection-level send window (bytes) for high-BDP links.
    /// No-op for transports where `caps().supports_window_tuning` is `false`.
    fn set_send_window(&self, _bytes: u64) {}
}

/// QUIC transport: thin wrapper over a live `quinn::Connection`.
pub struct QuicTransport {
    conn: quinn::Connection,
}

impl QuicTransport {
    pub fn new(conn: quinn::Connection) -> Self {
        QuicTransport { conn }
    }
}

impl Transport for QuicTransport {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn caps(&self) -> TransportCaps {
        TransportCaps {
            reliable: true,
            multistream: true,
            supports_window_tuning: true,
            mtu_hint: None,
        }
    }

    fn path_stats(&self) -> PathStats {
        let s = self.conn.stats();
        PathStats {
            rtt: s.path.rtt,
            lost_packets: s.path.lost_packets,
            cwnd: Some(s.path.cwnd),
        }
    }

    fn set_send_window(&self, bytes: u64) {
        self.conn.set_send_window(bytes);
    }
}

/// TCP+TLS transport. The kernel owns congestion control, so the only metric
/// available is the round-trip time measured during negotiation; the send
/// window cannot be tuned from user space.
pub struct TcpTransport {
    rtt: Duration,
}

impl TcpTransport {
    pub fn new(rtt: Duration) -> Self {
        TcpTransport { rtt }
    }
}

impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn caps(&self) -> TransportCaps {
        TransportCaps {
            reliable: true,
            multistream: true,
            supports_window_tuning: false,
            mtu_hint: None,
        }
    }

    fn path_stats(&self) -> PathStats {
        PathStats {
            rtt: self.rtt,
            lost_packets: 0,
            cwnd: None,
        }
    }
    // set_send_window: default no-op (kernel owns the TCP window).
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_caps_and_stats() {
        let t = TcpTransport::new(Duration::from_millis(40));
        let caps = t.caps();
        assert!(caps.reliable, "TCP is reliable");
        assert!(!caps.supports_window_tuning, "kernel owns the TCP window");
        assert_eq!(t.path_stats().rtt, Duration::from_millis(40));
        assert_eq!(t.path_stats().cwnd, None);
        assert_eq!(t.name(), "tcp");
        // set_send_window is a no-op and must not panic.
        t.set_send_window(1 << 30);
    }

    #[test]
    fn path_stats_default_is_zeroed() {
        let p = PathStats::default();
        assert_eq!(p.rtt, Duration::ZERO);
        assert_eq!(p.lost_packets, 0);
        assert_eq!(p.cwnd, None);
    }

    #[test]
    fn transport_is_object_safe() {
        // Compile-time assertion that the trait can be used as a trait object,
        // which the engine relies on (Option<Arc<dyn Transport>>).
        fn takes(_: &dyn Transport) {}
        let t = TcpTransport::new(Duration::from_millis(1));
        takes(&t);
    }
}
