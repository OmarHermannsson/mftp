//! End-to-end hardening tests for the receiver's server loops and transfer
//! setup: misbehaving peers and concurrent transfers must be rejected or
//! skipped cleanly instead of wedging the server or corrupting output.

use std::path::Path;
use std::time::Duration;

use mftp::transfer::{
    receiver::TcpServer,
    sender::{self, ForcedTransport, SendConfig},
};
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

fn tcp_config(fingerprint: String) -> SendConfig {
    SendConfig {
        streams: Some(2),
        chunk_size: Some(256 * 1024),
        compress: false,
        compress_level: 3,
        trusted_fingerprint: Some(fingerprint),
        trusted_device: None,
        client_identity: None,
        paths: 1,
        forced_transport: Some(ForcedTransport::Tcp),
        tcp_rtt_threshold: Duration::ZERO,
        fec: None,
        parallel_reads: false,
        recursive: false,
        preserve: false,
    }
}

/// An idle TCP connection that never starts its TLS handshake used to block
/// the sequential TCP server forever.  It must be dropped after the handshake
/// timeout so the next (real) transfer is served.
#[tokio::test]
async fn idle_tcp_connection_does_not_wedge_server() {
    let src_dir = TempDir::new().unwrap();
    let recv_dir = TempDir::new().unwrap();
    let src = make_file(src_dir.path(), "after_idle.bin", 1024 * 1024);

    let server = TcpServer::bind("127.0.0.1:0".parse().unwrap(), recv_dir.path().to_owned())
        .await
        .unwrap();
    let addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();

    // Connect first and say nothing; this is the connection accept_one sees.
    let idle = tokio::net::TcpStream::connect(addr).await.unwrap();
    let recv_task = tokio::spawn(async move { server.accept_one().await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let send = sender::send(src.clone(), addr, tcp_config(fingerprint));
    tokio::time::timeout(Duration::from_secs(60), send)
        .await
        .expect("send must not hang behind an idle connection")
        .expect("send ok");
    recv_task.await.unwrap().expect("receive ok");
    drop(idle);

    let got = std::fs::read(recv_dir.path().join("after_idle.bin")).unwrap();
    assert_eq!(got, std::fs::read(&src).unwrap());
}
