# Changelog

All notable changes to mftp are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Config file** at `~/.config/mftp/config.toml` for persistent per-link
  defaults: `streams`, `chunk_size`, `no_compress`, `transport`,
  `tcp_below_rtt`, `fec`, `port`. Precedence is explicit CLI flag > config file
  > built-in default; an absent file is not an error.
- **`MFTP_CC` environment variable** to override the QUIC congestion controller
  (`bbr` / `cubic` / `reno`); the default remains BBR, which suits mftp's
  high-BDP target.

### Performance
- **Adaptive compression now caps at zstd level 3** instead of escalating to
  level 6 on highly-compressible data. Level 6 cost roughly 2× the CPU for only
  ~7% better ratio, so whenever compression rather than the network was the
  bottleneck it *reduced* throughput. On a 50 ms-RTT transfer of compressible
  (JSON-log) data, throughput roughly doubled (~67 → ~135 MiB/s) after the
  change. Incompressible data is unaffected (still drops to level 1 / skips).
- **Sender skips zero-filling chunk buffers.** The file feeders read into
  uninitialised buffers (immediately and fully overwritten by the read) instead
  of allocating `vec![0u8; chunk_size]` per chunk. Profiling the LAN/TCP path
  showed the redundant zero-fill was ~10% of sender CPU; removed with no
  behaviour change.

### Reliability
- **In-band incremental repair now covers directory transfers** (previously
  single-file only). A missing/corrupt chunk or unreconstructable FEC stripe in
  a directory transfer is repaired over the existing connection — the sender
  reverse-maps the global chunk index across the concatenated file set and the
  receiver scatter-writes it — instead of aborting and resuming. No wire-format
  change.
- **Resume files now carry an integrity tag** (format v2): a corrupt or
  bit-rotted resume file is detected on load and discarded (clean restart)
  rather than trusted.

### Fixed
- **Stream-scaling deadlock near end-of-transfer.** When adaptive stream scaling
  added streams just as the transfer was finishing, the sender could hang
  indefinitely: if the final worker exited before the scale-up acknowledgement
  arrived, the completion check (which only ran on a worker-join) was never
  re-evaluated, so the loop waited forever on the scale channel and the receiver
  waited forever for a `Complete` that never came. This hit roughly 1 in 3
  transfers at ~50 ms RTT under the default (adaptive-streams) configuration;
  pinning `-n N` was a workaround. The dispatch loop now re-checks completion
  after every event, and the case has a regression test.

## [0.1.130] — 2026-06-02

First release since 0.1.102. Adds a new in-band repair protocol, a supply-chain
security fix, high-latency performance wins, and macOS/Windows support.

### Protocol
- Wire protocol bumped to **v6**. Sender and receiver must both be on 0.1.130+
  for the QUIC/TCP direct path (SFTP fallback is unaffected).

### Added
- **In-band incremental repair (protocol v5+):** missing/corrupt chunks and
  unreconstructable FEC stripes are re-requested over the control stream at the
  completion checkpoint (`ReceiverMessage::Retransmit`, single-file) instead of
  aborting and resuming.
- **macOS** (x86_64 + aarch64) and **Windows** (x86_64) builds, now tested in CI.

### Security
- Cross-platform binaries downloaded from GitHub releases are checksum-verified
  (against `--remote-binary-sha256` or the published `<asset>.sha256`) before
  being executed on the remote host.

### Performance
- **1-RTT QUIC startup** (was 2 control round-trips): the sender pipelines
  NegotiateRequest + manifest + DirEntries into a single flight. Measured
  ~850 ms faster per connection at 400 ms RTT.
- Larger, tunable **BBR initial congestion window** (`MFTP_INITIAL_CWND`).
- **Socket-buffer default raised to 64 MiB** (`MFTP_SOCKET_BUFFER`); opt-in
  ACK-frequency (`MFTP_ACK_ELICITING_THRESHOLD`).
- Dropped redundant chunk copies in the FEC sender path.

### Reliability
- Hardened FEC wire/manifest validation; overflow checks enabled.
- Attributable errors for unreconstructable FEC stripes.
- Resume surfaces resume/discard status; durability model documented.

### Changed
- Tolerate common `--trust` fingerprint formats (colons, whitespace, case).
- Hard-fail invalid `--fec` specs; clearer CLI examples and download prompt.

## [0.1.102] and earlier — baseline

Per-version history was not tracked before 0.1.130; these are the major
capabilities present as of the 0.1.102 baseline:

- Recursive directory transfer (`-r`) with optional metadata preservation (`--preserve`)
- Adaptive stream scaling on by default; pin with `-n N` (dynamic scale-up/down, protocol v2)
- SFTP fallback when the remote host cannot reach the mftp receive port
- FEC resume support: resumes skip already-received parity stripes
- NVMe parallel multi-reader (`--parallel-reads`, advanced/hidden flag)
- BDP-aware QUIC connection window sizing from measured RTT
- Adaptive zstd compression level (per-worker EMA of ratio/CPU)
- QUIC initial MTU raised to 1350 B (skips the lowest probe segment on Ethernet paths)
- TCP+TLS BBR: `setsockopt(TCP_CONGESTION, "bbr")` on Linux for parity with the QUIC path
- Live progress diagnostics: `streams=N rtt=Xms loss=N stall=Nms` in wide-terminal mode

[Unreleased]: https://github.com/OmarHermannsson/mftp/compare/v0.1.130...HEAD
[0.1.130]: https://github.com/OmarHermannsson/mftp/releases/tag/v0.1.130
