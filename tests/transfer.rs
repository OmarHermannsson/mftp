//! End-to-end transfer tests.
//!
//! Each test binds the receiver on 127.0.0.1:0 (ephemeral port) so tests
//! can run in parallel without port conflicts.  The sender uses the
//! certificate fingerprint from Server::bind, so TLS verification is
//! exercised without manual prompting.

use std::path::Path;

use mftp::protocol::messages::FecParams;
use mftp::transfer::{
    receiver::{Server, TcpServer},
    sender::{self, ForcedTransport, SendConfig},
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
            streams: Some(streams),
            chunk_size: Some(chunk_size),
            compress,
            compress_level: 3,
            trusted_fingerprint: Some(fingerprint),
            forced_transport: None,
            tcp_rtt_threshold: std::time::Duration::ZERO,
            fec: None,
            adaptive_streams: false,
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
            streams: Some(2),
            chunk_size: Some(1024 * 1024),
            compress: true,
            compress_level: 3,
            trusted_fingerprint: Some(fingerprint),
            forced_transport: None,
            tcp_rtt_threshold: std::time::Duration::ZERO,
            fec: None,
            adaptive_streams: false,
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

// ── TCP path tests ────────────────────────────────────────────────────────────

/// Core TCP helper: send `src` over loopback using plain TCP.
///
/// Uses `tokio::join!` instead of `tokio::spawn` because `handle_tcp_connection`
/// is not `Send` (it uses `std::sync::MutexGuard` internally). Sequential TCP
/// serve never spawns, so this is not a production concern.
async fn roundtrip_tcp(
    src: std::path::PathBuf,
    recv_dir: &TempDir,
    streams: usize,
    chunk_size: usize,
    compress: bool,
) -> anyhow::Result<()> {
    let server = TcpServer::bind("127.0.0.1:0".parse()?, recv_dir.path().to_owned()).await?;
    let addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();

    // Spawn the server so sender and receiver run on separate tasks.
    let recv_task = tokio::spawn(async move { server.accept_one().await });

    let send_res = sender::send(
        src.clone(),
        addr,
        SendConfig {
            streams: Some(streams),
            chunk_size: Some(chunk_size),
            compress,
            compress_level: 3,
            trusted_fingerprint: Some(fingerprint),
            forced_transport: Some(ForcedTransport::Tcp),
            tcp_rtt_threshold: std::time::Duration::ZERO,
            fec: None,
            adaptive_streams: false,
        },
    )
    .await;
    let recv_res = recv_task.await?;
    if let Err(ref e) = send_res {
        eprintln!("SENDER ERROR: {e:#}");
    }
    if let Err(ref e) = recv_res {
        eprintln!("RECEIVER ERROR: {e:#}");
    }
    recv_res?;
    send_res?;

    let file_name = src.file_name().unwrap().to_string_lossy();
    let received = std::fs::read(recv_dir.path().join(file_name.as_ref()))?;
    let original = std::fs::read(&src)?;
    assert_eq!(
        received, original,
        "TCP: received file differs from original"
    );
    Ok(())
}

/// Minimal TLS two-stream test (no mftp logic).
#[tokio::test]
async fn test_tls_two_streams_raw() -> anyhow::Result<()> {
    use mftp::net::{
        connection::{
            generate_self_signed_cert, make_client_tls_config, make_private_key,
            make_server_tls_config,
        },
        tcp::bind_tcp,
    };
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    let (cert, key_bytes) = generate_self_signed_cert()?;
    let fingerprint = mftp::net::connection::cert_fingerprint(&cert);
    let server_config = make_server_tls_config(cert, make_private_key(key_bytes)?)?;
    let acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_config)));
    let (listener, addr) = bind_tcp("127.0.0.1:0".parse()?).await?;

    const DATA_SIZE: usize = 512 * 1024;

    // Spawn server that accepts 2 TLS connections and reads all data
    let acceptor2 = Arc::clone(&acceptor);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (raw, _) = listener.accept().await.unwrap();
            let tls = acceptor2.accept(raw).await.unwrap();
            let (mut read, _write) = tokio::io::split(tls);
            let mut buf = vec![0u8; DATA_SIZE];
            read.read_exact(&mut buf).await.unwrap();
            // Drain to consume TLS close_notify so the socket closes cleanly.
            let mut drain = [0u8; 1];
            let _ = read.read(&mut drain).await;
        }
    });

    // Client: open 2 TLS connections and write DATA_SIZE bytes each
    for i in 0..2 {
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let config = make_client_tls_config(Some(&fingerprint), addr)?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::IpAddress(addr.ip().into());
        let mut tls = connector.connect(server_name, tcp).await?;
        let data = vec![i as u8; DATA_SIZE];
        tls.write_all(&data).await?;
        tls.shutdown().await?;
        // Drain server's close_notify so the kernel doesn't send RST when
        // we drop the socket with unread data in the receive buffer.
        let mut drain = [0u8; 1];
        let _ = tls.read(&mut drain).await;
    }

    server.await?;
    Ok(())
}

/// Basic TCP round-trip with multiple streams and chunks.
#[tokio::test]
async fn test_tcp_multi_chunk_multi_stream() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let src = make_test_file(send_dir.path(), "tcp_random.bin", 1024 * 1024);
    roundtrip_tcp(src, &recv_dir, 2, 512 * 1024, false).await
}

/// TCP path with compression enabled.
#[tokio::test]
async fn test_tcp_compressible_data() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let src = send_dir.path().join("tcp_zeros.bin");
    std::fs::write(&src, vec![0u8; 2 * 1024 * 1024])?;
    roundtrip_tcp(src, &recv_dir, 1, 1024 * 1024, true).await
}

// ── FEC tests ─────────────────────────────────────────────────────────────────

/// Core FEC helper: send `src` over loopback with FEC enabled and assert
/// the received file is byte-for-byte identical.
async fn roundtrip_fec(
    src: std::path::PathBuf,
    recv_dir: &TempDir,
    streams: usize,
    chunk_size: usize,
    compress: bool,
    data_shards: usize,
    parity_shards: usize,
) -> anyhow::Result<()> {
    let server = Server::bind("127.0.0.1:0".parse()?, recv_dir.path().to_owned())?;
    let addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();

    let recv_task = tokio::spawn(async move { server.accept_one().await });

    sender::send(
        src.clone(),
        addr,
        SendConfig {
            streams: Some(streams),
            chunk_size: Some(chunk_size),
            compress,
            compress_level: 3,
            trusted_fingerprint: Some(fingerprint),
            forced_transport: None,
            tcp_rtt_threshold: std::time::Duration::ZERO,
            fec: Some(FecParams {
                data_shards,
                parity_shards,
            }),
            adaptive_streams: false,
        },
    )
    .await?;

    recv_task.await??;

    let file_name = src.file_name().unwrap();
    let received = recv_dir.path().join(file_name);
    let original = std::fs::read(&src)?;
    let got = std::fs::read(&received)?;
    assert_eq!(original.len(), got.len(), "FEC: size mismatch");
    assert_eq!(original, got, "FEC: content mismatch");

    Ok(())
}

/// FEC roundtrip where total_chunks is an exact multiple of data_shards
/// (no partial last stripe).
#[tokio::test]
async fn test_fec_exact_stripe_boundary() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    // 8 chunks × 512 KiB = 4 MiB; data_shards=4 → 2 complete stripes
    let src = make_test_file(send_dir.path(), "fec_exact.bin", 4 * 512 * 1024 * 2);
    roundtrip_fec(src, &recv_dir, 2, 512 * 1024, false, 4, 1).await
}

/// FEC roundtrip where total_chunks % data_shards != 0 — last stripe is partial.
#[tokio::test]
async fn test_fec_partial_last_stripe() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    // 10 chunks × 512 KiB = 5 MiB; data_shards=4 → 2 full stripes + 1 stripe with 2 real shards
    let src = make_test_file(send_dir.path(), "fec_partial.bin", 10 * 512 * 1024);
    roundtrip_fec(src, &recv_dir, 2, 512 * 1024, false, 4, 1).await
}

/// FEC roundtrip with highly compressible data — compression should still
/// apply per shard, and the compressed/decompressed flags must survive.
#[tokio::test]
async fn test_fec_with_compression() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let path = send_dir.path().join("fec_zeros.bin");
    // 6 chunks × 512 KiB; data_shards=3 → 2 complete stripes
    std::fs::write(&path, vec![0u8; 6 * 512 * 1024])?;
    roundtrip_fec(path, &recv_dir, 2, 512 * 1024, true, 3, 1).await
}

/// FEC roundtrip with 8:2 config — classic satellite setting.
#[tokio::test]
async fn test_fec_eight_two_config() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    // 17 chunks → 2 full 8-shard stripes + 1 stripe with 1 real shard
    let src = make_test_file(send_dir.path(), "fec_82.bin", 17 * 256 * 1024);
    roundtrip_fec(src, &recv_dir, 4, 256 * 1024, false, 8, 2).await
}

/// FEC with a file smaller than one chunk (single shard in first stripe).
#[tokio::test]
async fn test_fec_smaller_than_chunk() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let src = make_test_file(send_dir.path(), "fec_small.bin", 12_345);
    roundtrip_fec(src, &recv_dir, 1, 512 * 1024, false, 4, 1).await
}

/// TCP path with --fec set should warn and disable FEC, completing successfully.
#[tokio::test]
async fn test_fec_disabled_on_tcp() -> anyhow::Result<()> {
    let send_dir = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let src = make_test_file(send_dir.path(), "fec_tcp.bin", 2 * 512 * 1024);

    let server = TcpServer::bind("127.0.0.1:0".parse()?, recv_dir.path().to_owned()).await?;
    let addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();
    let recv_task = tokio::spawn(async move { server.accept_one().await });

    let send_res = sender::send(
        src.clone(),
        addr,
        SendConfig {
            streams: Some(1),
            chunk_size: Some(512 * 1024),
            compress: false,
            compress_level: 3,
            trusted_fingerprint: Some(fingerprint),
            forced_transport: Some(ForcedTransport::Tcp),
            tcp_rtt_threshold: std::time::Duration::ZERO,
            // FEC requested but should be silently discarded for TCP
            fec: Some(FecParams {
                data_shards: 4,
                parity_shards: 1,
            }),
            adaptive_streams: false,
        },
    )
    .await;
    let recv_res = recv_task.await?;
    if let Err(ref e) = send_res {
        eprintln!("SENDER ERROR: {e:#}");
    }
    if let Err(ref e) = recv_res {
        eprintln!("RECEIVER ERROR: {e:#}");
    }
    recv_res?;
    send_res?;

    let file_name = src.file_name().unwrap();
    let received = std::fs::read(recv_dir.path().join(file_name))?;
    let original = std::fs::read(&src)?;
    assert_eq!(received, original, "TCP+FEC-disabled: file mismatch");
    Ok(())
}
