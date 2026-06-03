//! Adversarial / negative tests for defensive code paths.
//!
//! These exercise the guards that protect a receiver against a malicious or
//! buggy peer: decompression bombs, unreconstructable FEC stripes, and
//! oversized wire frames.  Each test asserts the guard returns `Err` (or the
//! documented bound) *without panicking or exhausting memory*, and pairs the
//! failure case with a control case proving the happy path still works.

use mftp::compress::{compress_chunk, decompress_chunk};
use mftp::fec::codec::{FecDecoder, FecEncoder};

// ── 1. Decompression-bomb rejection ─────────────────────────────────────────────

/// A small zstd frame that expands far beyond `max_output` must be rejected by
/// `decompress_chunk` rather than allocating the full decompressed size.
#[test]
fn decompress_bomb_rejected() {
    // 16 MiB of zeros compresses to a tiny frame but expands hugely.
    let raw = vec![0u8; 16 * 1024 * 1024];
    let compressed = compress_chunk(&raw, 3)
        .expect("compress_chunk ok")
        .expect("zeros are highly compressible — expected Some");
    assert!(
        compressed.len() < raw.len(),
        "expected the bomb frame to be smaller than its payload"
    );

    // Decompressing with a 1 MiB cap must error: the real output is 16 MiB.
    let result = decompress_chunk(&compressed, 1024 * 1024);
    assert!(
        result.is_err(),
        "decompress_chunk should reject output exceeding max_output"
    );
}

/// Control case: a within-limit decompression round-trips byte-for-byte.
#[test]
fn decompress_within_limit_roundtrips() {
    let raw = vec![0u8; 16 * 1024 * 1024];
    let compressed = compress_chunk(&raw, 3)
        .expect("compress_chunk ok")
        .expect("zeros are highly compressible — expected Some");

    // Cap generously above the real output size.
    let out = decompress_chunk(&compressed, 32 * 1024 * 1024).expect("within-limit decompress ok");
    assert_eq!(out.len(), raw.len(), "round-trip size mismatch");
    assert_eq!(out, raw, "round-trip content mismatch");
}

// ── 2. Unreconstructable FEC stripe ─────────────────────────────────────────────

/// Build an 8:2 stripe and present its (data + parity) shards with `missing`
/// of them set to `None`, all others padded to `stripe_max`.
fn build_82_shards(missing: &[usize]) -> (Vec<Option<Vec<u8>>>, Vec<u32>, Vec<Vec<u8>>) {
    let enc = FecEncoder::new(8, 2).unwrap();
    // Distinct, equal-length data shards.
    let data: Vec<Vec<u8>> = (0u8..8).map(|i| vec![i.wrapping_add(1); 128]).collect();
    let original = data.clone();
    let (parity, shard_lengths) = enc.encode(data).unwrap();
    let stripe_max = *shard_lengths.iter().max().unwrap() as usize;

    let shards: Vec<Option<Vec<u8>>> = original
        .iter()
        .map(|s| {
            let mut v = s.clone();
            v.resize(stripe_max, 0);
            v
        })
        .chain(parity.iter().cloned())
        .enumerate()
        .map(|(i, v)| if missing.contains(&i) { None } else { Some(v) })
        .collect();

    (shards, shard_lengths, original)
}

/// With only 2 parity shards, losing 5 of the 10 shards is unrecoverable.
/// `reconstruct` must return `Err` and must not panic.
#[test]
fn fec_too_many_missing_errors() {
    // Drop 5 shards (indices 0..=4): more than the 2 parity shards can cover.
    let (shards, shard_lengths, _original) = build_82_shards(&[0, 1, 2, 3, 4]);
    let present = shards.iter().filter(|s| s.is_some()).count();
    assert_eq!(present, 5, "expected 5 present / 5 missing");

    let dec = FecDecoder::new(8, 2).unwrap();
    let result = dec.reconstruct(shards, &shard_lengths);
    assert!(
        result.is_err(),
        "reconstruct should fail when more shards are missing than parity can cover"
    );
}

/// Control case: losing exactly 2 shards (== parity count) reconstructs cleanly
/// and the recovered data shards match the originals.
#[test]
fn fec_exactly_parity_missing_reconstructs() {
    // Drop one data shard and one parity shard — 2 missing total.
    let (shards, shard_lengths, original) = build_82_shards(&[3, 9]);
    let present = shards.iter().filter(|s| s.is_some()).count();
    assert_eq!(present, 8, "expected 8 present / 2 missing");

    let dec = FecDecoder::new(8, 2).unwrap();
    let got = dec
        .reconstruct(shards, &shard_lengths)
        .expect("losing exactly parity-count shards must reconstruct");
    assert_eq!(got, original, "reconstructed data must match originals");
}

// ── 3. Malformed frame: oversized length prefix ─────────────────────────────────

/// A frame whose length prefix exceeds the control-frame cap
/// (`MAX_CTRL_FRAME_SIZE` = 1 MiB) must be rejected by `recv_message` before any
/// large allocation, rather than panicking or attempting to allocate the bogus
/// size.  Driven over an in-memory `tokio::io::duplex` through the public API.
#[tokio::test]
async fn oversized_ctrl_frame_rejected() {
    use mftp::protocol::framing::recv_message;
    use mftp::protocol::messages::ReceiverMessage;
    use tokio::io::AsyncWriteExt;

    let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);

    // Length prefix far above the 1 MiB control-frame cap.  We never write the
    // body — a correct guard rejects on the prefix alone, so no allocation of
    // this size is attempted.
    let bogus_len: u32 = 64 * 1024 * 1024; // 64 MiB
    writer.write_all(&bogus_len.to_le_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    let result: anyhow::Result<Option<ReceiverMessage>> = recv_message(&mut reader).await;
    assert!(
        result.is_err(),
        "recv_message should reject a frame whose length prefix exceeds the cap"
    );
}

/// A frame whose length prefix exceeds the data-frame cap
/// (`MAX_DATA_FRAME_SIZE` = 128 MiB) must likewise be rejected by
/// `recv_data_message`.
#[tokio::test]
async fn oversized_data_frame_rejected() {
    use mftp::protocol::framing::recv_data_message;
    use mftp::protocol::messages::TransferManifest;
    use tokio::io::AsyncWriteExt;

    let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);

    // Just above the 128 MiB data-frame cap.
    let bogus_len: u32 = 128 * 1024 * 1024 + 1;
    writer.write_all(&bogus_len.to_le_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    let result: anyhow::Result<Option<TransferManifest>> = recv_data_message(&mut reader).await;
    assert!(
        result.is_err(),
        "recv_data_message should reject a frame whose length prefix exceeds the cap"
    );
}
