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

/// Input snapshot for one progress sample, used by [`compute_target_streams`].
#[derive(Debug, Clone)]
pub struct ProgressSample {
    pub bytes_written: u64,
    pub in_flight_chunks: u32,
    pub disk_stall_ms: u32,
    /// Wall-clock instant when this sample was received.
    pub timestamp: std::time::Instant,
}

/// Decide whether to scale the number of active streams up or down.
///
/// Returns `Some(target)` when a stream count change is recommended,
/// `None` when no change is needed or the cooldown period is still active.
///
/// # Parameters
/// - `samples`: sliding window of the last ≤10 progress samples (newest last).
/// - `current_streams`: current active stream count.
/// - `cpu_cap`: maximum stream count (`2 × min(sender_cores, receiver_cores)`).
/// - `bytes_total`: total file size in bytes (used to gate the 5%-sent check).
/// - `last_scale_at`: when the last scaling action occurred (`None` = never).
///
/// # Heuristics
/// **Scale-up** (all of the following must hold):
///   - At least 5% of the file has been transferred.
///   - Actual throughput < 70% of estimated per-stream capacity for ≥3 consecutive samples.
///   - Receiver is NOT saturated (`in_flight_chunks < 75%` of max) across those samples.
///   - `disk_stall_ms < 50` — receiver disk is not the bottleneck.
///   - `current_streams < cpu_cap`.
///   - 2-second cooldown since last scale action has elapsed.
///
/// **Scale-down** (one of the following):
///   - Receiver saturated for ≥5 consecutive samples.
///   - `disk_stall_ms > 100` for ≥3 consecutive samples.
///   - `current_streams > 2` and cooldown elapsed.
pub fn compute_target_streams(
    samples: &[ProgressSample],
    current_streams: usize,
    cpu_cap: usize,
    bytes_total: u64,
    last_scale_at: Option<std::time::Instant>,
) -> Option<u8> {
    const COOLDOWN: std::time::Duration = std::time::Duration::from_secs(2);
    const MAX_IN_FLIGHT_PER_STREAM: u32 = 4;

    if samples.len() < 3 {
        return None;
    }

    // Enforce cooldown.
    if let Some(last) = last_scale_at {
        if last.elapsed() < COOLDOWN {
            return None;
        }
    }

    // Gate on 5% of file transferred.
    let latest_bytes = samples.last().unwrap().bytes_written;
    if bytes_total > 0 && latest_bytes < bytes_total / 20 {
        return None;
    }

    let max_in_flight = current_streams as u32 * MAX_IN_FLIGHT_PER_STREAM;

    // ── Scale-down check ──────────────────────────────────────────────────
    // Receiver saturated for ≥5 consecutive trailing samples.
    let saturated_tail = samples
        .iter()
        .rev()
        .take(5)
        .filter(|s| s.in_flight_chunks >= max_in_flight * 3 / 4)
        .count();
    if saturated_tail >= 5 && current_streams > 2 {
        let target = ((current_streams as u8).saturating_sub(2)).max(2);
        return Some(target);
    }

    // Disk stall for ≥3 consecutive trailing samples.
    let stall_tail = samples
        .iter()
        .rev()
        .take(3)
        .filter(|s| s.disk_stall_ms > 100)
        .count();
    if stall_tail >= 3 && current_streams > 2 {
        let target = ((current_streams as u8).saturating_sub(2)).max(2);
        return Some(target);
    }

    // ── Scale-up check ────────────────────────────────────────────────────
    if current_streams >= cpu_cap {
        return None;
    }

    // All trailing 3 samples must be non-saturated and disk-stall-free.
    // This is the key gate: only scale up when the receiver has headroom.
    let not_saturated = samples
        .iter()
        .rev()
        .take(3)
        .all(|s| s.in_flight_chunks < max_in_flight * 3 / 4 && s.disk_stall_ms < 50);
    if !not_saturated {
        return None;
    }

    // Compute throughput over the last 3 samples.  If per-stream throughput is
    // already ≥ 50 MiB/s the link is well-utilized; let QUIC congestion control
    // handle it rather than adding more streams.
    if samples.len() >= 4 {
        let window = &samples[samples.len() - 4..]; // 4 samples → 3 intervals
        let duration = window
            .last()
            .unwrap()
            .timestamp
            .duration_since(window.first().unwrap().timestamp);
        if duration.as_secs_f64() >= 0.1 {
            let bytes_delta = window
                .last()
                .unwrap()
                .bytes_written
                .saturating_sub(window.first().unwrap().bytes_written);
            let throughput_bps = bytes_delta as f64 / duration.as_secs_f64();
            let per_stream_bps = throughput_bps / current_streams as f64;
            if per_stream_bps >= 50.0 * 1024.0 * 1024.0 {
                return None;
            }
        }
    }

    // Recommend scaling up by 2 streams (capped at cpu_cap).
    let target = ((current_streams + 2) as u8).min(cpu_cap as u8);
    Some(target)
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

    // ── compute_target_streams tests ──────────────────────────────────────────

    fn make_sample(bytes_written: u64, in_flight: u32, stall_ms: u32) -> ProgressSample {
        ProgressSample {
            bytes_written,
            in_flight_chunks: in_flight,
            disk_stall_ms: stall_ms,
            timestamp: std::time::Instant::now(),
        }
    }

    #[test]
    fn no_change_below_5pct() {
        // Only 2% of file written — gate should block.
        let samples: Vec<_> = (0..5).map(|i| make_sample(i * 1024, 0, 0)).collect();
        let result = compute_target_streams(
            &samples,
            4,                      // current_streams
            16,                     // cpu_cap
            5 * 1024 * 1024 * 1024, // 5 GiB total — 5*1024 bytes is way under 5%
            None,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn no_change_during_cooldown() {
        let samples: Vec<_> = (0..6).map(|i| make_sample(i * 10_000_000, 0, 0)).collect();
        let last_scale = Some(std::time::Instant::now()); // just happened
        let result = compute_target_streams(&samples, 4, 16, 100_000_000, last_scale);
        assert_eq!(result, None, "cooldown should suppress scaling");
    }

    #[test]
    fn scale_down_on_receiver_saturation() {
        let max_in_flight = 4 * 4; // current_streams * 4 = 16
                                   // All 5 trailing samples saturated at ≥75% of 16 = 12+
        let samples: Vec<_> = (0..7).map(|i| make_sample(i * 10_000_000, 13, 0)).collect();
        let result = compute_target_streams(&samples, 4, 16, 100_000_000, None);
        assert_eq!(result, Some(2), "should scale down by 2");
        let _ = max_in_flight;
    }

    #[test]
    fn scale_down_on_disk_stall() {
        let samples: Vec<_> = (0..5)
            .map(|i| make_sample(i * 10_000_000, 0, 150)) // stall > 100ms
            .collect();
        let result = compute_target_streams(&samples, 6, 16, 100_000_000, None);
        assert_eq!(result, Some(4), "should scale down by 2");
    }

    #[test]
    fn no_scale_down_at_minimum() {
        // At 2 streams, scale-down is suppressed.
        let samples: Vec<_> = (0..7)
            .map(|i| make_sample(i * 10_000_000, 7, 0)) // 7 of 8 in-flight = 87.5% saturated
            .collect();
        let result = compute_target_streams(&samples, 2, 16, 100_000_000, None);
        assert_eq!(result, None, "cannot go below 2 streams");
    }

    #[test]
    fn scale_up_when_receiver_has_headroom() {
        // Low in-flight, no disk stall, below cpu_cap, past 5%.
        // Throughput low enough (bytes_written barely increasing) to not trigger
        // the 50 MiB/s per-stream gate.
        let mut samples = Vec::new();
        for i in 0..5u64 {
            let mut s = make_sample(
                5_000_000 + i * 1_000, // ~1 KiB/sample = very slow
                1,                     // in-flight low
                0,
            );
            // Stagger timestamps so duration is meaningful.
            s.timestamp = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_millis((400 - i * 100) as u64))
                .unwrap_or_else(std::time::Instant::now);
            samples.push(s);
        }
        let result = compute_target_streams(&samples, 2, 16, 100_000_000, None);
        assert_eq!(result, Some(4), "should scale up by 2 (2+2)");
    }

    #[test]
    fn no_scale_up_at_cpu_cap() {
        let samples: Vec<_> = (0..5)
            .map(|i| make_sample(5_000_000 + i * 100, 0, 0))
            .collect();
        // current_streams == cpu_cap
        let result = compute_target_streams(&samples, 8, 8, 100_000_000, None);
        assert_eq!(result, None, "already at cpu_cap");
    }
}
