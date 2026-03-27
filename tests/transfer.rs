//! End-to-end transfer tests.
//!
//! Each test binds the receiver on 127.0.0.1:0 (ephemeral port) so tests
//! can run in parallel without port conflicts.  The sender uses the
//! certificate fingerprint from Server::bind, so TLS verification is
//! exercised without manual prompting.

use std::path::Path;

use mftp::transfer::{
    receiver::Server,
    sender::{self, SendConfig},
};
use tempfile::TempDir;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Generate a deterministic pseudo-random file of the given size.
fn make_test_file(dir: &Path, name: &str, size: usize) -> std::path::PathBuf {
    let path = dir.join(name);
    // LCG-derived bytes: incompressible, deterministic, cheap to verify.
    let data: Vec<u8> = (0..size)
        .map(|i| {
            let x = (i as u64)
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (x >> 56) as u8
        })
        .collect();
    std::fs::write(&path, &data).expect("write test file");
    path
}

/// Core helper: send `src` over loopback and assert the received file is
/// byte-for-byte identical.
async fn roundtrip(
    src: std::path::PathBuf,
    recv_dir: &TempDir,
    streams: usize,
    chunk_size: usize,
    compress: bool,
) -> anyhow::Result<()> {
    let server = Server::bind("127.0.0.1:0".parse()?, recv_dir.path().to_owned())?;
    let addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();

    // Receiver runs in the background; completes after one connection.
    let recv_task = tokio::spawn(async move { server.accept_one().await });

    sender::send(
        src.clone(),
        addr,
        SendConfig {
            streams,
            chunk_size,
            compress,
            compress_level: 3,
            trusted_fingerprint: Some(fingerprint),
        },
    )
    .await?;

    recv_task.await??;

    // Byte-for-byte comparison
    let file_name = src.file_name().unwrap();
    let received = recv_dir.path().join(file_name);
    let original = std::fs::read(&src)?;
    let got = std::fs::read(&received)?;
    assert_eq!(original.len(), got.len(), "size mismatch");
    assert_eq!(original, got, "content mismatch");

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// File smaller than one chunk (partial-chunk path).
#[tokio::test]
async fn test_file_smaller_than_chunk() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let src = make_test_file(send_dir.path(), "small.bin", 1_234);
    roundtrip(src, &recv_dir, 1, 4 * 1024 * 1024, false).await
}

/// File that is exactly one chunk in size.
#[tokio::test]
async fn test_exact_single_chunk() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let src = make_test_file(send_dir.path(), "one_chunk.bin", 1024 * 1024);
    roundtrip(src, &recv_dir, 1, 1024 * 1024, false).await
}

/// Multi-chunk file with multiple streams; also exercises the work-stealing queue.
#[tokio::test]
async fn test_multi_chunk_multi_stream() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    // 12 MiB + some bytes → 13 chunks of 1 MiB
    let src = make_test_file(send_dir.path(), "big.bin", 12 * 1024 * 1024 + 7_777);
    roundtrip(src, &recv_dir, 4, 1024 * 1024, false).await
}

/// Chunk count is an exact multiple of chunk size (no trailing partial chunk).
#[tokio::test]
async fn test_exact_chunk_boundary() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let src = make_test_file(send_dir.path(), "boundary.bin", 4 * 1024 * 1024);
    roundtrip(src, &recv_dir, 4, 1024 * 1024, false).await
}

/// Requesting more streams than chunks — sender clamps to chunk count.
#[tokio::test]
async fn test_more_streams_than_chunks() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    // 3 chunks, 8 streams requested
    let src = make_test_file(send_dir.path(), "few_chunks.bin", 3 * 1024 * 1024);
    roundtrip(src, &recv_dir, 8, 1024 * 1024, false).await
}

/// Highly compressible data (all zeros) with compression enabled.
/// Verifies the compressed/decompressed flag round-trips correctly.
#[tokio::test]
async fn test_compressible_data() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let path = send_dir.path().join("zeros.bin");
    std::fs::write(&path, vec![0u8; 4 * 1024 * 1024])?;

    let server = Server::bind("127.0.0.1:0".parse()?, recv_dir.path().to_owned())?;
    let addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();
    let recv_task = tokio::spawn(async move { server.accept_one().await });

    sender::send(
        path,
        addr,
        SendConfig {
            streams: 2,
            chunk_size: 1024 * 1024,
            compress: true,
            compress_level: 3,
            trusted_fingerprint: Some(fingerprint),
        },
    )
    .await?;
    recv_task.await??;

    let got = std::fs::read(recv_dir.path().join("zeros.bin"))?;
    assert_eq!(got, vec![0u8; 4 * 1024 * 1024]);
    Ok(())
}

/// Incompressible data with compression enabled — sender must fall back to
/// raw payload (< 5% gain threshold) and the compressed flag stays false.
#[tokio::test]
async fn test_incompressible_data_with_compress_flag() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    // LCG bytes are incompressible — zstd will not gain 5%
    let src = make_test_file(send_dir.path(), "random.bin", 2 * 1024 * 1024);
    roundtrip(src, &recv_dir, 2, 1024 * 1024, true).await
}

/// Single-byte file — tests the minimum-size edge case.
#[tokio::test]
async fn test_single_byte_file() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let path = send_dir.path().join("one.bin");
    std::fs::write(&path, [42u8])?;
    roundtrip(path, &recv_dir, 1, 4 * 1024 * 1024, false).await
}
