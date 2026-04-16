# mftp

**High-throughput file transfer over high-latency links.**

mftp is built for the scenarios where `scp` crawls: satellite uplinks, intercontinental hops, anything where bandwidth × delay product is large. It multiplexes a single file across parallel QUIC streams, adapts chunk size and stream count to measured RTT, and compresses on the fly — while keeping the UX as simple as `scp`.

```
mftp send dataset.tar.gz user@remote-host:/data/
```

In SSH mode, mftp launches the receiver automatically over your existing SSH session. The primary transfer uses QUIC or TCP+TLS (both require an open port on the receiver); if those ports are blocked, mftp falls back to parallel SFTP through port 22 with no extra configuration.

---

## Features

| | |
|---|---|
| **QUIC transport** | Parallel streams over a single connection; no TCP head-of-line blocking |
| **BBR congestion control** | Measures bandwidth and RTT directly; avoids CUBIC's sawtooth pattern on lossy/high-latency links |
| **Auto TCP+TLS fallback** | If UDP is blocked, retries transparently over TCP+TLS; also auto-switches on LAN/datacenter links (RTT ≤ 15 ms) where kernel TCP beats QUIC |
| **SSH-assisted launch** | Spawns the receiver on the remote via SSH — no manual setup |
| **SFTP fallback** | If both QUIC and TCP+TLS are blocked, falls back to N parallel SFTP connections through port 22 — only this path requires no open port beyond SSH. **Significantly slower** (~22–32 MiB/s cap) due to SSH SFTP protocol overhead |
| **Adaptive compression** | Per-chunk zstd; skips chunks that don't compress (already-compressed formats auto-detected) |
| **Reed-Solomon FEC** | Optional parity shards (`--fec DATA:PARITY`) for lossy links; tolerates burst loss without retransmission |
| **End-to-end integrity** | BLAKE3 per chunk (raw bytes) + full-file BLAKE3 verified on arrival |
| **RTT-aware negotiation** | Stream count and chunk size auto-tuned from measured round-trip time |
| **Resumable transfers** | Crash-safe bit-vector tracks received chunks; transfers continue where they left off |
| **TOFU authentication** | Self-signed certs; fingerprint confirmed once per session; `--trust` pins it for scripted use |

---

## Quick start

### Install

```sh
cargo install mftp
```

Or from git:

```sh
cargo install --git https://github.com/OmarHermannsson/mftp
```

Or build from source:

```sh
git clone https://github.com/OmarHermannsson/mftp
cd mftp
cargo build --release
# binary is at target/release/mftp
```

### Send a file (SSH mode)

```sh
# mftp SSHes to the remote, starts the receiver, transfers, and cleans up
mftp send bigfile.tar.gz user@remote-host:/data/landing/
```

mftp connects via your existing SSH credentials. The receiver is started automatically and exits when the transfer completes. It tries QUIC first, then TCP+TLS, then SFTP — falling back automatically if the direct transfer ports are blocked.

### Send a file (manual receiver)

On the receiver:
```sh
mftp receive --output-dir /data/landing
# Prints: Listening on 0.0.0.0:7777 (QUIC + TCP+TLS, auto-fallback)
# Prints: Certificate fingerprint: a3f9...
```

On the sender:
```sh
mftp send bigfile.tar.gz remote-host:7777 --trust a3f9...
```

The receiver port (7777 by default) must be reachable: UDP for QUIC, TCP for TCP+TLS, or both. There is no SFTP fallback in direct `host:port` mode.

---

## Usage

### `mftp send`

```
mftp send [OPTIONS] <FILE> <DESTINATION>
```

`DESTINATION` is either:
- `host:port` — connect to an already-running `mftp receive`. The port must be reachable (UDP for QUIC, TCP for TCP+TLS).
- `[user@]host:/remote/path` — launch the receiver via SSH (recommended). Falls back through QUIC → TCP+TLS → SFTP automatically.

```
Options:
  --trust <FINGERPRINT>    Pin the receiver's SHA-256 certificate fingerprint.
                           Omit to use TOFU (fingerprint is printed and you are
                           prompted to accept it once per session; it is not
                           automatically stored between sessions).
                           Ignored in SSH mode — fingerprint is read from the server.
  --remote-mftp <PATH>     Path to a pre-installed mftp on the remote host.
                           By default mftp pipes itself over SSH stdin on first use
                           and caches it at ~/.cache/mftp-<hash> on the remote.
  --port <PORT>            Port the remote mftp server should bind on (SSH mode only).
                           Defaults to a randomly assigned port. Use this when the
                           transfer port must be in a firewall allow-list.
  -n, --streams <N>        Parallel streams.
                           Direct mode: default auto-negotiated from RTT + CPU cores.
                           SFTP: default 8 (each stream = one SSH connection;
                           raise to 12 if the remote sshd allows it).
      --chunk-size <BYTES> Chunk size in bytes (default: auto from RTT).
      --no-compress        Disable adaptive zstd compression.
  -r, --recursive          Transfer directories recursively. Required when the
                           source is a directory; silently accepted (no-op) when
                           the source is a regular file.
      --preserve           Preserve source file permissions and modification time
                           on the receiver. No effect on Windows receivers.
      --fec <DATA:PARITY>  Enable Reed-Solomon forward error correction.
                           e.g. --fec 8:2 adds 25% overhead but tolerates up to 2
                           lost chunks per stripe without retransmission.
                           Automatically disabled when the transport falls back to
                           TCP (reliable delivery).
      --transport <TRANSPORT>
                           Force a specific transport path:
                           quic — QUIC only; fails immediately if UDP is blocked
                                  (no TCP+TLS or SFTP fallback).
                           tcp  — TCP+TLS only; skip the QUIC probe (no SFTP fallback).
                           sftp — parallel SFTP through port 22 (SSH mode only;
                                  significantly slower, ~22 MiB/s cap; skips remote
                                  server launch).
                           Omit for auto: QUIC → TCP+TLS → SFTP (SSH mode only).
      --tcp-below-rtt <MS> In auto mode, switch to TCP+TLS when measured RTT ≤ this
                           value. Ignored when --transport is set [default: 15].
      --adaptive-streams   Enabled by default. The sender measures throughput and
                           receiver congestion every 100 ms and adjusts stream
                           count to maximise utilisation. Bounded by
                           [2, 2 × min(cores)]. Pass -n N to pin streams and
                           disable adaptive scaling. Requires both endpoints
                           to be protocol version ≥ 2.
      --parallel-reads     Use multiple parallel file readers instead of one
                           sequential reader. Only beneficial on local NVMe with
                           queue depth ≥ 32; no measurable effect on spinning
                           disks or network-bound transfers.
      --download           When the remote platform differs from local, automatically
                           download the correct mftp binary from GitHub releases
                           without prompting. Mutually exclusive with --no-download.
      --no-download        When the remote platform differs from local, skip the
                           download attempt and fall back to SFTP immediately.
                           Mutually exclusive with --download.
  -v, --verbose            Increase log verbosity (-v / -vv / -vvv).
```

### `mftp receive`

```
mftp receive [OPTIONS] [BIND]
```

`BIND` defaults to `0.0.0.0:7777`. Both QUIC (UDP) and TCP+TLS listen on the same port, so the sender's auto-fallback works with no extra configuration on the receiver side. **The bind port must be reachable from the sender.**

```
Options:
  -o, --output-dir <DIR>   Directory to write received files into (default: .).
```

FEC parameters are negotiated automatically via the `TransferManifest` — no `--fec` flag needed on the receiver.

### `mftp --version`

```
mftp 0.1.93
```

---

## How it works

### Transport

mftp defaults to QUIC (via [quinn](https://github.com/quinn-rs/quinn)) with BBR congestion control. In SSH mode it tries three transports in order, falling back automatically:

```
Sender                                    Receiver
  │                                           │
  ├─── QUIC connect (5 s timeout) ──────────►│  mftp receiver (launched via SSH)
  │    (if UDP blocked or times out)          │  requires: data port open (UDP)
  ├─── TCP+TLS connect ──────────────────────►│  mftp receiver (same process)
  │    (if TCP port also unreachable)         │  requires: data port open (TCP)
  └─── SFTP (N parallel SSH connections) ───►│  sshd sftp-server (port 22 only)
                                             │  requires: SSH port 22 only
```

The QUIC and TCP+TLS paths use TLS 1.3 with a freshly generated self-signed certificate shared between both transports (same fingerprint). The SFTP path bypasses the mftp receiver entirely and writes directly to the remote filesystem via the sshd built-in sftp-server subsystem.

### SSH-assisted launch

When you write `mftp send file.bin user@host:/path`, the sender:

1. SSHes to `user@host` and runs `mftp server --output-dir /path`
   - If mftp is not installed on the remote, the local binary is piped over SSH stdin and cached at `~/.cache/mftp-<hash>` — subsequent transfers with the same binary version skip the copy.
   - The remote OS and architecture are probed first so the correct binary is delivered (Linux/macOS/Windows, x86_64/arm64).
   - Use `--port <N>` to have the remote server bind on a specific port instead of a random one (required when the transfer port must be in a firewall allow-list; without `--port`, the random port will almost certainly be blocked).
2. The remote server binds on the chosen (or random) port and prints one JSON line to stdout:
   ```json
   {"port":54321,"fingerprint":"a3f9..."}
   ```
3. The sender reads the handshake, then attempts a direct connection to `host:54321`
4. If the direct connection fails (firewall blocks the port), the sender falls back to **parallel SFTP** — N independent SSH/SFTP connections each writing a non-overlapping segment of the file directly to the remote. No mftp process is needed on the remote for this leg; it talks to the sshd sftp-server subsystem.

The remote `mftp server` exits as soon as the transfer completes (or is killed when SFTP takes over).

### Firewall configuration

The QUIC and TCP+TLS paths both require a port to be open on the receiver — UDP for QUIC, TCP for TCP+TLS (or both, since the auto-fallback tries both). In SSH mode a random port is picked by default, which will almost certainly be blocked by a firewall; use `--port <N>` to pick a specific port you control.

**Opening a port temporarily (Linux)**

```sh
# iptables (most distributions)
sudo iptables -A INPUT -p udp --dport 7777 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7777 -j ACCEPT

# firewalld (RHEL/Fedora/Rocky/AlmaLinux)
sudo firewall-cmd --add-port=7777/udp --add-port=7777/tcp

# ufw (Ubuntu/Debian)
sudo ufw allow 7777/udp
sudo ufw allow 7777/tcp
```

These rules are not persistent across reboots. To persist them, add `--permanent` to `firewall-cmd` (then `sudo firewall-cmd --reload`), use `iptables-save`, or add a `ufw` allow rule before enabling ufw persistence.

**Cloud providers**: security group or VPC firewall rules (AWS, GCP, Azure, etc.) must also permit the port — kernel-level rules alone are not enough on cloud instances. The rule must allow inbound traffic from the sender's public IP on the chosen port (UDP and TCP).

**If you cannot open a port**: the automatic SFTP fallback (port 22 only) requires no additional firewall changes. It is slower — typically 22–32 MiB/s versus the full QUIC/TCP throughput — but works through any firewall that allows SSH.

### SFTP fallback

The SFTP fallback uses libssh2 to open N independent SSH connections to port 22, each with its own SFTP channel. The file is divided into N equal segments; each connection writes its segment with positional I/O (`seek` + `write`) in parallel.

Throughput scales linearly with stream count because each connection is fully independent (separate congestion window, separate SSH channel):

| Streams | Throughput (LAN, 500 MiB) |
|---------|--------------------------|
| 4       | ~12 MiB/s |
| 8       | ~22 MiB/s (default) |
| 12      | ~32 MiB/s |

The ceiling per stream (~3 MiB/s) comes from libssh2's synchronous SFTP write acknowledgment — it is a fundamental limitation of the SSH SFTP protocol. Raising `--streams` to 12 is safe on most servers; beyond that, OpenSSH's `MaxStartups` setting (default `10:30:100`) may start rate-limiting concurrent auth attempts.

The SFTP path uses a single encryption layer (SSH), whereas the tunnel approach used SSH + TLS. Authentication uses the SSH agent if running, otherwise the default key files (`~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa`). The remote host key is verified against `~/.ssh/known_hosts`.

### Parallel streams and RTT negotiation

After the QUIC handshake, sender and receiver exchange CPU core counts. The sender then reads the measured RTT from the QUIC connection stats and computes:

| RTT | Default chunk size |
|-----|-------------------|
| < 10 ms (LAN) | 8 MiB |
| 10 – 200 ms (regional/intercontinental) | 4 MiB |
| ≥ 200 ms (satellite) | 2 MiB |

Stream count is `max(⌈RTT_ms / 5⌉, min_cores)`, capped at `2 × min(sender_cores, receiver_cores)`. On a satellite link with 600 ms RTT and an 8-core machine on each end, mftp opens 16 streams of 2 MiB chunks — keeping the pipe full while staying within CPU budget.

Both values can be overridden with `--streams` and `--chunk-size`.

### Data flow

```
File on disk
  └─► ChunkQueue (atomic work-stealing index)
        └─► N parallel tasks, one per QUIC/TCP stream:
              ├─ read chunk from file (pread)
              ├─ detect already-compressed format (magic bytes)
              ├─ BLAKE3 hash of raw chunk bytes
              ├─ zstd compress full chunk; discard if < 5% gain
              ├─ [FEC] accumulate DATA shards into stripe; RS-encode PARITY shards
              └─ send ChunkData / FecChunkData frame (hash + payload)

Control stream (after all data streams finish):
  Sender ──► SenderMessage::Complete { file_hash }
  Receiver ──► ReceiverMessage::Complete { file_hash }  (after full-file verify)
```

The receiver writes each chunk directly to its final offset with `pwrite`, so no reassembly pass is needed after the transfer.

### Wire protocol

All messages are length-prefixed bincode frames (`[u32 LE length][payload]`):

```
Control stream (1 per connection):
  Sender → NegotiateRequest   { cpu_cores }
  Receiver → NegotiateResponse { cpu_cores }
  Sender → TransferManifest   { transfer_id, file_name, file_size, chunk_size,
                                 total_chunks, num_streams, compression, fec }
  Receiver → ReceiverMessage::Ready { received_bits, total_chunks }  ← resume bitvector
  ...data streams transfer...
  Sender → SenderMessage::Complete  { file_hash }
  Receiver → ReceiverMessage::Complete { file_hash }

Data streams (N per connection):
  Without FEC — one ChunkData per chunk:
    Sender → ChunkData { transfer_id, chunk_index, chunk_hash, compressed, payload }

  With FEC — one FecChunkData per shard (data + parity):
    Sender → FecChunkData { transfer_id, chunk_index, chunk_hash, compressed,
                            stripe_index, shard_index_in_stripe, is_parity,
                            shard_lengths, payload }
```

### Reed-Solomon FEC

Enable with `--fec DATA:PARITY` on the sender (e.g. `--fec 8:2`). The receiver accepts both FEC and non-FEC transfers on the same port — the `TransferManifest` advertises whether FEC is active.

**Stripe layout**: chunks are grouped into stripes of `DATA` shards. Each stripe is RS-encoded to produce `PARITY` additional shards. All `DATA + PARITY` shards are sent independently across the parallel streams. The receiver can reconstruct any stripe as long as it receives at least `DATA` out of the `DATA + PARITY` shards — tolerating up to `PARITY` lost shards per stripe without retransmission.

**Ordering**: compression happens before FEC encoding, so parity shards are computed over (and are the same size as) compressed data shards. FEC is automatically disabled when the transport falls back to TCP, since TCP guarantees delivery.

**Overhead**: `--fec 8:2` adds 25% to the wire size (`2/8`). Use it when packet loss is high enough that retransmission round-trips would dominate transfer time (satellite, intercontinental, congested links).

### Compression

mftp compresses each chunk independently with zstd:

1. **Magic-byte check** — if the first 4 bytes match a known compressed format (gzip, zstd, bzip2, zip, 7-zip, xz, jpeg, png, mp4, mkv/webm…), compression is skipped entirely.
2. **Full-chunk compression** — the chunk is compressed and the result compared to the original size.
3. **Threshold** — if compression does not achieve at least a 5% reduction, the compressed bytes are discarded and the chunk is sent raw.
4. **Per-chunk flag** — `ChunkData.compressed` tells the receiver whether to decompress.

Note that this always pays the compression CPU cost before deciding whether to use the result. For files that are already compressed (not caught by the magic-byte table), this is wasted work. `--no-compress` avoids it entirely.

### Integrity

- **Per-chunk**: BLAKE3 of the raw (pre-compression) chunk bytes. The sender computes the hash before compressing, embeds it in the frame, and the receiver decompresses then re-computes and compares before writing to disk.
- **Full-file**: BLAKE3 of the concatenated per-chunk hashes — `blake3(hash[0] || hash[1] || … || hash[N-1])`. The sender sends this in `SenderMessage::Complete`; the receiver verifies it after all chunks land. A mismatch fails the transfer.
- **SFTP fallback**: integrity is provided by SSH's channel MAC (HMAC-SHA2-256). Per-chunk and full-file hashing are not available on this path since there is no mftp receiver process.

### Resume

Each transfer has a deterministic 16-byte ID derived from the file name, file size, and negotiated chunk size (`BLAKE3(name || size || chunk_size)[..16]`). This means re-sending the same file automatically resumes an interrupted transfer — no flags needed. If the negotiation produces different parameters (e.g. different RTT), the ID changes and a fresh transfer starts. The ID is embedded in every `ChunkData` frame.

On the receiver side, a bit-vector tracking which chunks have been received is flushed to `<output_dir>/<transfer_id_hex>.mftp-resume` in batches (every 64 chunks) to limit fsync overhead. If the transfer is interrupted, at most 64 chunks may need re-downloading on resume.

If the transfer is interrupted:

1. Restart `mftp receive` (or re-run the same `mftp send` command in SSH mode)
2. The receiver finds the resume file, reads which chunks it already has
3. In the `ReceiverMessage::Ready` response it sends the received-chunk bitvector
4. The sender skips already-received chunks and only retransmits what's missing

The resume file is deleted on successful completion. Resume is not available on the SFTP fallback path.

### Security

mftp uses self-signed TLS certificates with a TOFU (Trust On First Use) model, similar to SSH:

- The receiver generates a fresh key pair on every start
- It prints the SHA-256 fingerprint of its certificate
- On first connect to a new server the sender prompts for confirmation (requires a TTY; non-interactive invocations without `--trust` are rejected)
- Pass `--trust <fingerprint>` to pin a fingerprint for scripted or non-interactive use; the fingerprint is not stored between sessions automatically

For SSH-assisted transfers the fingerprint is obtained automatically over the existing SSH channel — no manual verification step required.

The SFTP fallback path relies on SSH host key verification against `~/.ssh/known_hosts` (the same file used by the `ssh` command). Run `ssh <host>` once if the host is not yet in your known_hosts.

Socket buffers are set to 32 MiB (`SO_SNDBUF` / `SO_RCVBUF`) on both ends. QUIC flow control windows are 32 MiB per stream and 256 MiB at the connection level.

---

## Performance

Benchmarked against `scp` on a 10 GbE link, 1 GiB random (incompressible) file:

| Link | scp | mftp (auto) | speedup |
|------|-----|-------------|---------|
| LAN (< 5 ms) | ~440 MiB/s | ~440 MiB/s | 1× |
| 50 ms RTT | 36 MiB/s | **71 MiB/s** | **2× faster** |
| 150 ms RTT | 12 MiB/s | **82 MiB/s** | **7× faster** |
| 400 ms RTT | 4.6 MiB/s | **43 MiB/s** | **9× faster** |
| 600 ms + 1% loss | 2.6 MiB/s | **29 MiB/s** | **11× faster** |

LAN performance uses the auto TCP+TLS path (same speed as scp). At 50 ms and beyond, QUIC BBR with parallel streams dominates.

---

## Known limitations

- **Firewall**: the QUIC and TCP+TLS paths both require an open port on the receiver. In SSH mode a random port is used by default — likely to be blocked. Use `--port <N>` with a known-open port, or rely on the automatic SFTP fallback (port 22 only, but capped at ~22–32 MiB/s). See [Firewall configuration](#firewall-configuration) above.
- **SFTP fallback is significantly slower**: the SFTP path is capped at ~3 MiB/s per stream (a fundamental SSH SFTP protocol limitation — synchronous write acknowledgments). At the default of 8 streams that is ~22 MiB/s; 12 streams gives ~32 MiB/s. This is several times slower than the QUIC or TCP+TLS paths, which saturate the link. If transfers are consistently falling back to SFTP, open a port and use `--port <N>`.
- **macOS: not tested**: mftp is developed and tested on Linux. It may compile and work on macOS, but this is not verified. Issues specific to macOS are welcome but may not be promptly fixed.
- **TOFU fingerprint persistence**: `--trust` fingerprints are not stored between sessions. You must pass `--trust` on every non-interactive invocation, or accept the prompt each time.
- **Directory transfer**: `-r` transfers the directory tree recursively. `--preserve` copies mode bits and mtime; without it, files land with default umask permissions and current mtime.

---

## Performance tips

- **Satellite / high-latency links**: mftp is designed for these. Let RTT negotiation pick the parameters; don't override unless you have a reason.
- **Lossy links**: add `--fec 8:2` (or `--fec 4:1` for lighter overhead) to tolerate burst loss without retransmission. FEC shines on links where 1–5% packet loss is common.
- **LAN / datacenter transfers**: mftp auto-switches to TCP+TLS when it measures RTT ≤ 15 ms. No flags needed — just run the same command.
- **Pre-compressed data** (videos, archives, already-zstd files): mftp auto-detects these and skips compression. No `--no-compress` needed.
- **Open port required**: in SSH mode, use `--port <N>` with a firewall-allowed port to avoid the automatic fallback to SFTP. The SFTP path is reliable but slower.
- **SFTP fallback throughput**: if the direct transfer ports are always blocked, raise `--streams` from the default of 8 to 12 for ~32 MiB/s. Check that the remote sshd's `MaxStartups` is set to at least `12:30:100`.
- **OS socket buffer limit**: on Linux, the kernel may cap socket buffers below 32 MiB. Set `net.core.rmem_max` and `net.core.wmem_max` to `33554432` on both hosts for maximum throughput.

  ```sh
  sudo sysctl -w net.core.rmem_max=33554432 net.core.wmem_max=33554432
  ```

---

## Building

```sh
cargo build --release
```

Requires Rust 1.75+ (for `div_ceil` stabilization) and libssh2 (for the SFTP fallback). On most Linux distributions libssh2 is already installed; on others install `libssh2-devel` (RPM) or `libssh2-dev` (Debian/Ubuntu). On Windows, OpenSSL is vendored automatically — no extra setup needed.

> **Platform support**: Linux (x86_64, arm64) is the primary supported platform. macOS may compile and work, but is not tested — proceed with caution and report issues. Windows builds are supported for the receiver-less SFTP path; the full QUIC/TCP stack is untested on Windows.

```sh
# Check only (fast)
cargo check

# Tests
cargo test

# Lint
cargo clippy -- -D warnings
```

---

## Roadmap

- **Fingerprint persistence** — store `--trust` fingerprints across sessions (keyed by host)

### Shipped (not yet extracted to changelog)

- Recursive directory transfer (`-r`) with optional metadata preservation (`--preserve`)
- Adaptive stream scaling on by default (dynamic scale-up/scale-down, protocol v2)
- SFTP fallback when the remote host cannot reach the mftp receive port
- FEC resume support: resumes skip already-received parity stripes
- NVMe parallel multi-reader (`--parallel-reads`)
- BDP-aware QUIC window sizing from measured RTT
- Adaptive zstd compression level (per-worker EMA of ratio/CPU)

---

## License

MIT
