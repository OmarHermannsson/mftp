//! Cross-version protocol interop.
//!
//! `mftp::protocol::messages::test_hooks::force_local_version(Some(v))` caps the
//! version this process advertises in negotiation. Because the in-process sender
//! and receiver share it, this exercises a transfer where *both* peers negotiate
//! an older version `v` — the realistic case of the current binary talking to
//! what an older one would negotiate.
//!
//! The point of interest is v7's `StreamHello` data-stream preamble: at v6 it
//! must be neither sent nor expected (the wire stays v6-identical), so a transfer
//! capped to v6 must still complete byte-for-byte. The per-combination gating
//! decision itself is unit-tested in `protocol::messages` (the asymmetric
//! 7↔6 matrix, which a single in-process pair can't reproduce).
//!
//! The override is a process-global, so all scenarios live in one test function.

use mftp::protocol::messages::test_hooks;
use mftp::transfer::receiver::Server;
use mftp::transfer::sender::{self, SendConfig};
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

fn send_config(fingerprint: String, recursive: bool) -> SendConfig {
    SendConfig {
        streams: Some(4),
        chunk_size: Some(64 * 1024),
        compress: false,
        compress_level: 3,
        trusted_fingerprint: Some(fingerprint),
        trusted_device: None,
        client_identity: None,
        forced_transport: None,
        tcp_rtt_threshold: std::time::Duration::ZERO,
        fec: None,
        parallel_reads: false,
        paths: 1,
        recursive,
        preserve: false,
    }
}

async fn transfer(src: &Path, recv_dir: &TempDir, recursive: bool) -> anyhow::Result<()> {
    let server = Server::bind("127.0.0.1:0".parse()?, recv_dir.path().to_owned())?;
    let addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();
    let recv_task = tokio::spawn(async move { server.accept_one().await });
    sender::send(src.to_owned(), addr, send_config(fingerprint, recursive)).await?;
    recv_task.await??;
    Ok(())
}

#[tokio::test]
async fn transfers_complete_when_negotiated_down_to_v6() -> anyhow::Result<()> {
    // Both peers advertise v6 → no StreamHello preamble; the wire is v6-shaped.
    test_hooks::force_local_version(Some(6));

    // ── Single file. ──────────────────────────────────────────────────────────
    {
        let send_dir = TempDir::new()?;
        let recv_dir = TempDir::new()?;
        let src = make_file(send_dir.path(), "v6.bin", 64 * 1024 * 5 + 123);
        transfer(&src, &recv_dir, false).await?;
        assert_eq!(
            std::fs::read(&src)?,
            std::fs::read(recv_dir.path().join("v6.bin"))?,
            "single-file transfer completes at v6"
        );
    }

    // ── Directory (exercises the DirEntries path, which v6 still carries). ─────
    {
        let send_dir = TempDir::new()?;
        let recv_dir = TempDir::new()?;
        let tree = send_dir.path().join("tree");
        std::fs::create_dir_all(&tree)?;
        let a = make_file(&tree, "a.bin", 64 * 1024 + 7);
        let b = make_file(&tree, "b.bin", 64 * 1024 * 3);
        transfer(&tree, &recv_dir, true).await?;
        let got = recv_dir.path().join("tree");
        assert_eq!(std::fs::read(&a)?, std::fs::read(got.join("a.bin"))?);
        assert_eq!(std::fs::read(&b)?, std::fs::read(got.join("b.bin"))?);
    }

    test_hooks::force_local_version(None);
    Ok(())
}
