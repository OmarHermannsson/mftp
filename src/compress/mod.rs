//! Adaptive per-chunk compression.
//!
//! Compression is applied per chunk before FEC encoding (so FEC protects
//! compressed data). Whether to compress is decided by sampling the first
//! 4 KiB of each chunk: if zstd achieves < 5% reduction, compression is
//! skipped for that chunk (and flagged in the chunk header).
//!
//! Known uncompressible magic bytes (first 4 bytes) are fast-pathed to skip
//! sampling entirely: gzip (1f 8b), zstd (28 b5 2f fd), zip (50 4b), etc.

pub mod detect;

use anyhow::Result;

pub fn compress_chunk(data: &[u8], level: i32) -> Result<Option<Vec<u8>>> {
    if detect::is_already_compressed(data) {
        return Ok(None);
    }
    let compressed = zstd::encode_all(data, level)?;
    // Only use compression if it saves at least 5%.
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
        anyhow::bail!(
            "decompressed chunk exceeds maximum size of {max_output} bytes"
        );
    }
    Ok(out)
}
