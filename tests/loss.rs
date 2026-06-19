//! Transfer-correctness tests under simulated packet loss.
//!
//! `mftp::net::connection::test_support::set_send_loss(denom)` arms a
//! process-global hook that wraps every subsequently-built QUIC endpoint's UDP
//! socket so it deterministically drops 1 of every `denom` outbound datagrams
//! (after a short handshake warm-up).  Because both the in-process sender and
//! receiver endpoints are built while armed, loss applies in both directions —
//! data datagrams and ACKs alike.
//!
//! QUIC's reliable streams must retransmit every dropped datagram, so the file
//! still arrives byte-for-byte.  This exercises the whole pipeline (handshake,
//! loss recovery, per-chunk BLAKE3, FEC reconstruction) under realistic loss
//! locally, without a remote host + `tc netem`.  The knob is process-global, so
//! these run sequentially in one test function.

use mftp::net::connection::test_support;
use mftp::protocol::messages::FecParams;
use mftp::transfer::receiver::Server;
use mftp::transfer::sender::{self, ForcedTransport, SendConfig};
use std::path::Path;
use tempfile::TempDir;

fn make_file(dir: &Path, name: &str, size: usize) -> std::path::PathBuf {
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

/// Send `src` to a fresh receiver over loopback QUIC and assert the received
/// file is byte-for-byte identical.  Loss must already be armed by the caller.
async fn transfer_ok(src: &Path, recv_dir: &TempDir, fec: Option<FecParams>) {
    let server = Server::bind("127.0.0.1:0".parse().unwrap(), recv_dir.path().to_owned()).unwrap();
    let addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();
    let recv_task = tokio::spawn(async move { server.accept_one().await });

    let config = SendConfig {
        streams: Some(4),
        chunk_size: Some(64 * 1024),
        compress: false,
        compress_level: 3,
        trusted_fingerprint: Some(fingerprint),
        trusted_device: None,
        client_identity: None,
        // Pin QUIC: the whole point is to exercise QUIC loss recovery, and we
        // must not silently fall back to (lossless-in-this-harness) TCP.
        forced_transport: Some(ForcedTransport::Quic),
        tcp_rtt_threshold: std::time::Duration::ZERO,
        fec,
        parallel_reads: false,
        paths: 1,
        recursive: false,
        preserve: false,
    };
    sender::send(src.to_owned(), addr, config)
        .await
        .expect("send completes despite packet loss");
    recv_task
        .await
        .unwrap()
        .expect("receive completes despite packet loss");

    let received = recv_dir.path().join(src.file_name().unwrap());
    let original = std::fs::read(src).unwrap();
    let got = std::fs::read(&received).unwrap();
    assert_eq!(original.len(), got.len(), "size mismatch under loss");
    assert_eq!(original, got, "content mismatch under loss");
}

#[tokio::test]
async fn transfers_complete_under_packet_loss() {
    // Drop ~10% of datagrams in both directions.
    test_support::set_send_loss(10);

    // ── Plain QUIC: loss recovery alone must carry the transfer. ──────────────
    {
        let src_dir = TempDir::new().unwrap();
        let recv_dir = TempDir::new().unwrap();
        let src = make_file(src_dir.path(), "lossy.bin", 4 * 1024 * 1024);
        transfer_ok(&src, &recv_dir, None).await;
    }

    // ── With FEC (8:2): the reconstruction path runs under real loss too. ─────
    {
        let src_dir = TempDir::new().unwrap();
        let recv_dir = TempDir::new().unwrap();
        let src = make_file(src_dir.path(), "lossy_fec.bin", 4 * 1024 * 1024);
        transfer_ok(
            &src,
            &recv_dir,
            Some(FecParams {
                data_shards: 8,
                parity_shards: 2,
            }),
        )
        .await;
    }

    test_support::clear();
}
