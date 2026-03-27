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

pub fn decompress_chunk(data: &[u8]) -> Result<Vec<u8>> {
    Ok(zstd::decode_all(data)?)
}
