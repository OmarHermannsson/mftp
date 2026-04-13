//! Auto-negotiation of transfer parameters.
//!
//! After the QUIC handshake the sender and receiver exchange CPU core counts.
//! Combined with the measured RTT (from quinn connection stats) the sender
//! derives stream count and chunk size that maximise throughput for the
//! observed connection characteristics.
//!
//! # Heuristics
//!
//! **Stream count** — more streams fill the bandwidth-delay product on
//! high-latency links.  We use roughly one stream per 5 ms of RTT, capped by
//! `2 × min(sender_cores, receiver_cores)` so we never overwhelm either CPU
//! with per-stream work.  Minimum is 2.
//!
//! **Chunk size** — larger chunks amortise per-chunk overhead (hash, framing,
//! compression decision) but cost more memory and make resume coarser.  We
//! choose smaller chunks for low-latency (LAN) connections and larger ones
//! for high-latency (WAN/satellite) links.
//!
//! CLI flags (`-n`/`--chunk-size`) always override the computed values.

use std::time::Duration;

/// Negotiated transfer parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferParams {
    pub streams: usize,
    pub chunk_size: usize,
}

/// Compute the optimal [`TransferParams`] from connection and system info.
///
/// # Arguments
/// - `rtt`: measured round-trip time (from `conn.stats().path.rtt`)
/// - `file_size`: total bytes to transfer
/// - `sender_cores`: logical CPUs on the sender
/// - `receiver_cores`: logical CPUs on the receiver
/// - `override_streams`: `Some(n)` to force stream count (CLI flag)
/// - `override_chunk_size`: `Some(n)` to force chunk size (CLI flag)
pub fn compute_params(
    rtt: Duration,
    file_size: u64,
    sender_cores: u32,
    receiver_cores: u32,
    override_streams: Option<usize>,
    override_chunk_size: Option<usize>,
) -> TransferParams {
    let rtt_ms = rtt.as_millis() as u64;

    // ── Chunk size ────────────────────────────────────────────────────────────
    // Chunk size is tuned to the observed RTT.  With BBR congestion control and
    // 32 MiB stream receive windows, flow control no longer stalls large writes,
    // so larger chunks amortise per-chunk overhead (framing, SHA-256, bincode)
    // across more payload bytes.
    //
    // Benchmarks (BBR, 32 MiB windows, 1 GiB random file):
    //   50 ms RTT : 4 MiB = 94 MiB/s,  2 MiB (old) = 55 MiB/s  → +70 %
    //   150 ms RTT: 4 MiB = 75 MiB/s,  all sizes roughly equal  (~80 MiB/s)
    //   400 ms RTT: 4 MiB = 47 MiB/s,  1 MiB (old) = 42 MiB/s  → +12 %
    let chunk_size = override_chunk_size.unwrap_or({
        if rtt_ms < 10 {
            8 * 1024 * 1024 // 8 MiB — LAN / loopback
        } else if rtt_ms < 200 {
            4 * 1024 * 1024 // 4 MiB — regional cloud through intercontinental
        } else {
            2 * 1024 * 1024 // 2 MiB — satellite / very high latency (was 1 MiB)
        }
    });

    // ── Stream count ──────────────────────────────────────────────────────────
    let streams = override_streams.unwrap_or({
        // One stream per 5 ms of RTT to fill the bandwidth-delay product on
        // high-latency links.
        let rtt_streams = ((rtt_ms / 5) as usize).max(2);
        // Cap at 2× the weaker side's CPU count.
        let cpu_cap = (receiver_cores.min(sender_cores) as usize).max(1) * 2;
        // On low-latency links rtt_streams is tiny (2 for <10 ms), but streams
        // also serve a second purpose: pipelining CPU work (SHA-256, disk write)
        // with network receives across streams.  Use the weaker side's core
        // count as a floor so we always have enough streams to keep CPUs busy
        // even on LAN/loopback where the bottleneck is compute, not BDP.
        let cpu_floor = receiver_cores.min(sender_cores) as usize;
        rtt_streams.max(cpu_floor).min(cpu_cap).max(2)
    });

    // Never open more streams than chunks.
    let total_chunks = file_size.div_ceil(chunk_size as u64) as usize;
    let streams = streams.min(total_chunks.max(1));

    TransferParams {
        streams,
        chunk_size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_uses_cpu_floor_not_rtt() {
        // RTT=1ms → rtt_streams=2, but cpu_floor=8 cores → streams=8.
        // On LAN the bottleneck is CPU/disk, not BDP, so we use cpu_floor.
        let p = compute_params(
            Duration::from_millis(1),
            100 * 1024 * 1024,
            8,
            8,
            None,
            None,
        );
        assert_eq!(p.chunk_size, 8 * 1024 * 1024);
        assert_eq!(p.streams, 8); // cpu_floor=8 > rtt_streams=2
    }

    #[test]
    fn satellite_high_streams_small_chunks() {
        let p = compute_params(
            Duration::from_millis(600),
            1024 * 1024 * 1024,
            8,
            8,
            None,
            None,
        );
        assert_eq!(p.chunk_size, 2 * 1024 * 1024); // ≥ 200 ms → 2 MiB
                                                   // rtt_streams = 120, cpu_cap = 16 → clamped to 16
        assert_eq!(p.streams, 16);
    }

    #[test]
    fn intercontinental_medium() {
        let p = compute_params(
            Duration::from_millis(100),
            1024 * 1024 * 1024,
            8,
            8,
            None,
            None,
        );
        assert_eq!(p.chunk_size, 4 * 1024 * 1024); // < 200 ms → 4 MiB
                                                   // rtt_streams = 20, cpu_cap = 16 → 16
        assert_eq!(p.streams, 16);
    }

    #[test]
    fn cli_overrides_take_precedence() {
        let p = compute_params(
            Duration::from_millis(600),
            1024 * 1024 * 1024,
            8,
            8,
            Some(4),
            Some(2 * 1024 * 1024),
        );
        assert_eq!(p.streams, 4);
        assert_eq!(p.chunk_size, 2 * 1024 * 1024);
    }

    #[test]
    fn streams_capped_by_chunks() {
        // Tiny file: only 2 chunks at 4MiB, so even a high-stream suggestion
        // is limited to the number of chunks.
        let p = compute_params(
            Duration::from_millis(100),
            5 * 1024 * 1024, // 5 MiB → 2 chunks at 4MiB chunk_size (RTT=100ms)
            8,
            8,
            None,
            Some(4 * 1024 * 1024),
        );
        assert!(p.streams <= 2);
    }

    #[test]
    fn weak_receiver_limits_streams() {
        let p = compute_params(
            Duration::from_millis(200),
            1024 * 1024 * 1024,
            16,
            2, // receiver only has 2 cores
            None,
            None,
        );
        // cpu_cap = min(16,2)*2 = 4
        assert!(p.streams <= 4);
    }
}
