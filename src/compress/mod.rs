//! Adaptive per-chunk compression.
//!
//! Compression is applied per chunk before FEC encoding (so FEC protects
//! compressed data). Whether to compress is decided by sampling the first
//! 64 KiB of each chunk: if zstd achieves < 5% reduction on the sample,
//! compression is skipped for that chunk (and flagged in the chunk header).
//! Only when the sample looks promising is the full chunk compressed.
//!
//! Known uncompressible magic bytes (first 4 bytes) are fast-pathed to skip
//! sampling entirely: gzip (1f 8b), zstd (28 b5 2f fd), zip (50 4b), etc.

pub mod detect;

use anyhow::Result;

/// Bytes to probe before deciding whether to compress the full chunk.
/// 64 KiB is representative enough for most data patterns while being
/// ~128× cheaper to encode than an 8 MiB LAN chunk.
const SAMPLE_SIZE: usize = 64 * 1024;

/// Per-worker adaptive compression level tracker.
///
/// Maintains an exponential moving average (α = 0.15) of the compression
/// ratio seen across recent chunks and adjusts the zstd level accordingly:
///
/// - ratio < 8 %  → level 1 (near-incompressible data; spend minimal CPU)
/// - ratio > 35 % → level 6 (highly compressible; worth the extra CPU)
/// - otherwise    → level 3 (default mid-range)
///
/// The level is held constant for the first 4 chunks so the EMA has time to
/// warm up before any adjustment.  Each worker owns its own instance, so
/// there is no shared state or locking.
pub struct AdaptiveLevel {
    /// Current zstd compression level (updated after every chunk).
    pub level: i32,
    /// EMA of compression ratio: 0.0 = no gain, 1.0 = perfect compression.
    ema_ratio: f32,
    chunks_seen: u32,
}

impl AdaptiveLevel {
    pub fn new(initial: i32) -> Self {
        Self {
            level: initial,
            // Initialise the EMA to a neutral mid-range value so the first
            // few chunks don't trigger a premature level change.
            ema_ratio: 0.20,
            chunks_seen: 0,
        }
    }

    /// Update the EMA with the outcome of one chunk and possibly adjust the
    /// level.  `raw_len` is the uncompressed size; `wire_len` is the size
    /// actually sent (compressed or raw if compression was skipped).
    pub fn update(&mut self, raw_len: usize, wire_len: usize) {
        if raw_len == 0 {
            return;
        }
        let ratio = 1.0 - (wire_len as f32 / raw_len as f32);
        self.ema_ratio = self.ema_ratio * 0.85 + ratio * 0.15;
        self.chunks_seen += 1;
        if self.chunks_seen >= 4 {
            self.level = if self.ema_ratio < 0.08 {
                1 // Near-incompressible — use the fastest level to save CPU.
            } else if self.ema_ratio > 0.35 {
                6 // Highly compressible — invest more CPU for better ratio.
            } else {
                3 // Default mid-range.
            };
        }
    }
}

pub fn compress_chunk(data: &[u8], level: i32) -> Result<Option<Vec<u8>>> {
    if detect::is_already_compressed(data) {
        return Ok(None);
    }
    // Probe a leading sample to avoid paying full compression cost on every
    // chunk only to discard the result.  Previously this compressed the entire
    // chunk before checking the gain threshold, wasting CPU on LAN transfers.
    let sample = &data[..data.len().min(SAMPLE_SIZE)];
    let sample_compressed = zstd::encode_all(sample, level)?;
    if sample_compressed.len() >= sample.len() * 95 / 100 {
        return Ok(None);
    }
    // Sample compresses well — compress the full chunk.
    let compressed = zstd::encode_all(data, level)?;
    // Final check: full chunk might still miss the threshold if only the
    // leading portion was compressible.
    if compressed.len() >= data.len() * 95 / 100 {
        return Ok(None);
    }
    Ok(Some(compressed))
}

/// Decompress a chunk, refusing to produce more than `max_output` bytes.
///
/// Without this limit a malicious sender can craft a tiny zstd frame that
/// expands to gigabytes ("decompression bomb"), exhausting memory before
/// the receiver even verifies the file hash.
pub fn decompress_chunk(data: &[u8], max_output: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let decoder = zstd::Decoder::new(data)?;
    let mut out = Vec::new();
    // Read at most max_output+1 bytes; if we reach that limit the data is
    // maliciously large and we reject it.
    decoder.take(max_output as u64 + 1).read_to_end(&mut out)?;
    if out.len() > max_output {
        anyhow::bail!("decompressed chunk exceeds maximum size of {max_output} bytes");
    }
    Ok(out)
}
