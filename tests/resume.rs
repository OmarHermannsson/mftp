//! End-to-end test for interrupt-and-resume.
//!
//! The receiver's test-only abort hook (`mftp::transfer::receiver::test_hooks`)
//! simulates a crash mid-transfer: once N chunks have been marked-received it
//! flushes the resume bit-vector and tears the connection down, leaving a
//! partial resume file on disk.  A second transfer of the *same* file to the
//! *same* output directory must pick up that state, fetch only the remaining
//! chunks, and reconstruct the file byte-for-byte.
//!
//! Resume keys on `transfer_id`, which the sender derives deterministically from
//! (file_name, file_size, chunk_size) — so re-running the same send resumes
//! rather than starting fresh.  The abort hook is a process-global, so this lives
//! in a single test function to avoid cross-test interference.

use mftp::transfer::receiver::{test_hooks, Server};
use mftp::transfer::resume::ResumeState;
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

/// Recompute the single-file transfer_id the sender assigns in `build_manifest`,
/// so the test can open the resume file and inspect how much was persisted.
fn single_file_transfer_id(file_name: &str, file_size: u64, chunk_size: usize) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(file_name.as_bytes());
    h.update(&file_size.to_le_bytes());
    h.update(&(chunk_size as u64).to_le_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.finalize().as_bytes()[..16]);
    id
}

fn send_config(streams: usize, chunk_size: usize, fingerprint: String) -> SendConfig {
    SendConfig {
        streams: Some(streams),
        chunk_size: Some(chunk_size),
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
        recursive: false,
        preserve: false,
    }
}

#[tokio::test]
async fn interrupted_transfer_resumes_to_completion() {
    const CHUNK: usize = 64 * 1024;
    const TOTAL_CHUNKS: u64 = 512; // 32 MiB
    const ABORT_AFTER: u64 = 200; // crash partway through
    const STREAMS: usize = 4;

    test_hooks::clear();

    let src_dir = TempDir::new().unwrap();
    let recv_dir = TempDir::new().unwrap();
    let src = make_file(src_dir.path(), "big.bin", CHUNK * TOTAL_CHUNKS as usize);
    let file_size = std::fs::metadata(&src).unwrap().len();
    let transfer_id = single_file_transfer_id("big.bin", file_size, CHUNK);

    // ── Phase 1: start a transfer that aborts mid-flight ──────────────────────
    test_hooks::abort_after_chunks(ABORT_AFTER);
    {
        let server =
            Server::bind("127.0.0.1:0".parse().unwrap(), recv_dir.path().to_owned()).unwrap();
        let addr = server.local_addr;
        let fingerprint = server.fingerprint.clone();
        let recv_task = tokio::spawn(async move { server.accept_one().await });

        let config = send_config(STREAMS, CHUNK, fingerprint);
        // The send may fail (connection torn down) or, on a slow runner, race to
        // completion before the abort fires — either is fine; the resume file is
        // what matters.  We assert progress, not a specific error.
        let _ = sender::send(src.clone(), addr, config).await;
        let _ = recv_task.await;
    }
    test_hooks::clear();

    // The aborted transfer must have left a partial resume file: more than zero
    // chunks persisted, but not the whole file.
    let resume_path = recv_dir
        .path()
        .join(format!("{}.mftp-resume", hex::encode(transfer_id)));
    assert!(
        resume_path.exists(),
        "expected a partial resume file at {} after the simulated crash",
        resume_path.display()
    );
    let partial = ResumeState::load_or_new(recv_dir.path(), &transfer_id, TOTAL_CHUNKS);
    let received_after_crash = partial.received_chunks().len() as u64;
    assert!(
        received_after_crash > 0 && received_after_crash < TOTAL_CHUNKS,
        "expected partial progress, got {received_after_crash}/{TOTAL_CHUNKS} chunks persisted"
    );

    // ── Phase 2: re-run the same transfer; it must resume and complete ────────
    {
        let server =
            Server::bind("127.0.0.1:0".parse().unwrap(), recv_dir.path().to_owned()).unwrap();
        let addr = server.local_addr;
        let fingerprint = server.fingerprint.clone();
        let recv_task = tokio::spawn(async move { server.accept_one().await });

        let config = send_config(STREAMS, CHUNK, fingerprint);
        sender::send(src.clone(), addr, config)
            .await
            .expect("resumed send completes");
        recv_task.await.unwrap().expect("resumed receive completes");
    }

    // The completed transfer reconstructs the file byte-for-byte...
    let received = recv_dir.path().join("big.bin");
    let original = std::fs::read(&src).unwrap();
    let got = std::fs::read(&received).unwrap();
    assert_eq!(original.len(), got.len(), "size mismatch after resume");
    assert_eq!(original, got, "content mismatch after resume");

    // ...and deletes the resume file on success.
    assert!(
        !resume_path.exists(),
        "resume file should be deleted after a clean completion"
    );

    test_hooks::clear();
}
