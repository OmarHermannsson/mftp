# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

`mftp` is a CLI tool for transferring large files over the internet with maximum throughput, especially over high-latency links (satellite, intercontinental). It uses QUIC with parallel streams, adaptive zstd compression, per-chunk SHA-256 integrity, resumable transfers, and optional Reed-Solomon FEC.

## Commands

```bash
# Check for compile errors (fast, no linking)
cargo check

# Build debug binary
cargo build

# Build optimized release binary
cargo build --release

# Run all tests
cargo test

# Run a single test by name
cargo test <test_name>

# Run integration tests only
cargo test --test '*'

# Check formatting
cargo fmt --check

# Lint
cargo clippy -- -D warnings

# Run the binary (debug)
cargo run -- send <file> <host:port>
cargo run -- receive --output-dir /tmp
```

## Architecture

### Module Map

```
src/
  main.rs           CLI entry point — clap arg parsing, logging init, dispatches to sender/receiver
  lib.rs            Re-exports all modules

  protocol/
    messages.rs     Wire types: TransferManifest, ChunkData, ReceiverMessage (serde + bincode)
    framing.rs      Length-prefixed framing ([u32 LE len][bincode payload]) over QUIC streams

  transfer/
    mod.rs          Full send/receive flow documented here — read this first
    chunk.rs        ChunkQueue: atomic work-stealing queue used by parallel sender tasks
    sender.rs       Opens QUIC connection, sends manifest, dispatches chunks across N streams
    receiver.rs     Accepts connection, reads manifest, writes chunks, sends completion ack
    resume.rs       Bit-vector resume state persisted to <output_dir>/<transfer_id>.mftp-resume

  net/
    mod.rs          QUIC setup notes: TOFU TLS, socket buffer sizing rationale
    connection.rs   make_server_endpoint() / make_client_endpoint() using quinn

  fec/
    mod.rs          Reed-Solomon stripe layout documented here
    codec.rs        FecEncoder / FecDecoder wrapping reed-solomon-erasure

  compress/
    mod.rs          compress_chunk() / decompress_chunk() — skips if < 5% gain
    detect.rs       Magic-byte table for already-compressed formats (gzip, zstd, zip, jpeg, …)
```

### Data Flow (Send)

```
File on disk
  → ChunkQueue (atomic index dispenser)
  → N parallel tokio tasks, each owning one QUIC stream:
      read chunk (mmap/pread)
      → detect compression → zstd encode (if beneficial)
      → FEC encode (if --fec): adds parity shards to stripe
      → SHA-256 hash payload
      → framing::send_message(ChunkData) on stream
  → Control stream: wait for ReceiverMessage::Complete or ::Retransmit
```

### Data Flow (Receive)

```
QUIC connection accepted
  → Control stream: read TransferManifest
  → ResumeState::load_or_new → reply ReceiverMessage::Ready(have_chunks)
  → N tasks each reading one data stream:
      framing::recv_message(ChunkData)
      → verify SHA-256
      → FEC decode (accumulate stripe; reconstruct on shard threshold)
      → decompress if flagged
      → pwrite chunk to output file at correct offset
      → ResumeState::mark_received + save()
  → all chunks received → verify whole-file SHA-256
  → send ReceiverMessage::Complete
  → ResumeState::delete()
```

### Key Design Decisions

- **QUIC streams, not connections**: all chunks share one QUIC connection; each of the N parallel sender tasks holds one long-lived bidirectional stream. This avoids per-connection handshake overhead while providing independent flow control per stream (no TCP head-of-line blocking).
- **Compression before FEC**: FEC operates on compressed bytes, so parity shards are smaller.
- **Per-chunk hashing**: SHA-256 is computed over the wire payload (post-compression, post-FEC-encoding for data shards), enabling chunk-level retry without re-hashing the whole file.
- **Socket buffers**: both endpoints set `SO_SNDBUF`/`SO_RCVBUF` to at least 32 MiB (covers ~250 ms RTT at 1 Gbps BDP) via socket2 before binding.
- **Resume granularity**: the bit-vector in `ResumeState` is flushed to disk after each chunk, so a crash loses at most one in-progress chunk.

### TLS / Authentication

Self-signed certificates with TOFU. The receiver prints its certificate fingerprint on startup; the sender prints the peer fingerprint and prompts for confirmation (or accepts `--trust <fingerprint>` to skip the prompt for scripted use).
