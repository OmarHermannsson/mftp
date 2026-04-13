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
