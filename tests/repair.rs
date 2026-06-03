//! End-to-end tests for in-band incremental repair (protocol v5).
//!
//! These use the receiver's test-only fault-injection hook
//! (`mftp::transfer::receiver::test_hooks`) to drop specific chunks on first
//! receipt, leaving them missing at the completion checkpoint.  A correct
//! repair flow then re-requests exactly those chunks over the control stream
//! and the transfer still completes byte-for-byte.
//!
//! The hook is a process-global, so both scenarios live in one test function
//! (run sequentially in this process) to avoid cross-test interference.

use mftp::protocol::messages::FecParams;
use mftp::transfer::receiver::{test_hooks, Server};
use mftp::transfer::sender::{self, SendConfig};
use tempfile::TempDir;

fn make_file(dir: &std::path::Path, name: &str, size: usize) -> std::path::PathBuf {
    let path = dir.join(name);
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

/// Transfer `src` to a fresh receiver over loopback QUIC, asserting the transfer
/// succeeds (including any repair rounds) and the received file is identical.
/// The drop hook must already be armed by the caller.
async fn transfer_ok(
    src: &std::path::Path,
    recv_dir: &TempDir,
    streams: usize,
    chunk_size: usize,
    fec: Option<FecParams>,
) {
    let server = Server::bind("127.0.0.1:0".parse().unwrap(), recv_dir.path().to_owned()).unwrap();
    let addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();
    let recv_task = tokio::spawn(async move { server.accept_one().await });

    let config = SendConfig {
        streams: Some(streams),
        chunk_size: Some(chunk_size),
        compress: false,
        compress_level: 3,
        trusted_fingerprint: Some(fingerprint),
        forced_transport: None,
        tcp_rtt_threshold: std::time::Duration::ZERO,
        fec,
        parallel_reads: false,
        recursive: false,
        preserve: false,
    };
    sender::send(src.to_owned(), addr, config)
        .await
        .expect("send completes after repair");
    recv_task
        .await
        .unwrap()
        .expect("receive completes after repair");

    let received = recv_dir.path().join(src.file_name().unwrap());
    let original = std::fs::read(src).unwrap();
    let got = std::fs::read(&received).unwrap();
    assert_eq!(original.len(), got.len(), "size mismatch");
    assert_eq!(original, got, "content mismatch");
}

#[tokio::test]
async fn incremental_repair_end_to_end() {
    const CHUNK: usize = 64 * 1024;

    // ── Scenario 1: non-FEC, several dropped chunks are repaired ──────────────
    {
        test_hooks::clear();
        let dir = TempDir::new().unwrap();
        let recv = TempDir::new().unwrap();
        let src = make_file(dir.path(), "plain.bin", CHUNK * 10); // chunks 0..9
        test_hooks::drop_chunks_once(&[2, 5, 8]);
        transfer_ok(&src, &recv, 4, CHUNK, None).await;
        test_hooks::clear();
    }

    // ── Scenario 2: an unreconstructable FEC stripe is repaired ───────────────
    {
        test_hooks::clear();
        let dir = TempDir::new().unwrap();
        let recv = TempDir::new().unwrap();
        let src = make_file(dir.path(), "fec.bin", CHUNK * 12); // 3 stripes of 4
                                                                // fec 4:1 tolerates 1 lost shard per stripe; dropping 2 data shards of
                                                                // stripe 0 (chunks 0 and 1) makes the stripe unreconstructable → repair.
        test_hooks::drop_chunks_once(&[0, 1]);
        transfer_ok(
            &src,
            &recv,
            2,
            CHUNK,
            Some(FecParams {
                data_shards: 4,
                parity_shards: 1,
            }),
        )
        .await;
        test_hooks::clear();
    }

    // ── Scenario 3: directory transfer with dropped chunks repaired in-band ────
    // Directory repair was previously unsupported (the sender rejected the
    // Retransmit). This exercises the concat reverse-mapping on the sender and
    // scatter-write on the receiver across a multi-file tree.
    {
        test_hooks::clear();
        let dir = TempDir::new().unwrap();
        let recv = TempDir::new().unwrap();
        let src_dir = dir.path().join("payload");
        std::fs::create_dir(&src_dir).unwrap();
        // Concatenated in path-sorted order (a, b, c); interior dropped chunks
        // straddle file boundaries to test multi-file scatter on repair.
        let fa = make_file(&src_dir, "a.bin", CHUNK * 3 + 1234);
        let fb = make_file(&src_dir, "b.bin", CHUNK * 2);
        let fc = make_file(&src_dir, "c.bin", CHUNK * 4);
        test_hooks::drop_chunks_once(&[1, 4, 6]);

        let server = Server::bind("127.0.0.1:0".parse().unwrap(), recv.path().to_owned()).unwrap();
        let addr = server.local_addr;
        let fingerprint = server.fingerprint.clone();
        let recv_task = tokio::spawn(async move { server.accept_one().await });

        let config = SendConfig {
            streams: Some(4),
            chunk_size: Some(CHUNK),
            compress: false,
            compress_level: 3,
            trusted_fingerprint: Some(fingerprint),
            forced_transport: None,
            tcp_rtt_threshold: std::time::Duration::ZERO,
            fec: None,
            parallel_reads: false,
            recursive: true,
            preserve: false,
        };
        sender::send(src_dir.clone(), addr, config)
            .await
            .expect("directory send completes after repair");
        recv_task
            .await
            .unwrap()
            .expect("directory receive completes after repair");

        for f in [&fa, &fb, &fc] {
            let rel = f.file_name().unwrap();
            let received = recv.path().join("payload").join(rel);
            let original = std::fs::read(f).unwrap();
            let got = std::fs::read(&received)
                .unwrap_or_else(|e| panic!("read {}: {e}", received.display()));
            assert_eq!(
                original, got,
                "content mismatch for {rel:?} after directory repair"
            );
        }
        test_hooks::clear();
    }
}
