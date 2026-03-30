# mftp

**High-throughput file transfer over high-latency links.**

mftp is built for the scenarios where `scp` crawls: satellite uplinks, intercontinental hops, anything where bandwidth × delay product is large. It multiplexes a single file across parallel QUIC streams, adapts chunk size and stream count to measured RTT, and compresses on the fly — while keeping the UX as simple as `scp`.

```
mftp send dataset.tar.gz user@remote-host:/data/
```

That's it. No receiver daemon to start first, no firewall rules to configure — not even an open port beyond SSH.

---

## Features

| | |
|---|---|
| **QUIC transport** | Parallel streams over a single connection; no TCP head-of-line blocking |
| **BBR congestion control** | Measures bandwidth and RTT directly; avoids CUBIC's sawtooth pattern on lossy/high-latency links |
| **Auto TCP+TLS fallback** | If UDP is blocked, retries transparently over TCP+TLS; also auto-switches on LAN/datacenter links (RTT ≤ 5 ms) where kernel TCP beats QUIC |
| **SSH-assisted launch** | Spawns the receiver on the remote via SSH — no manual setup |
| **SFTP fallback** | If the transfer port is firewalled, falls back to N parallel SFTP connections through SSH port 22 — no open ports required beyond SSH |
| **Adaptive compression** | Per-chunk zstd; skips chunks that don't compress (already-compressed formats auto-detected) |
| **End-to-end integrity** | SHA-256 per chunk (wire payload) + full-file hash verified on arrival |
| **RTT-aware negotiation** | Stream count and chunk size auto-tuned from measured round-trip time |
| **Resumable transfers** | Crash-safe bit-vector tracks received chunks; transfers continue where they left off |
| **TOFU authentication** | Self-signed certs; fingerprints stored in `~/.config/mftp/known_hosts`; `--trust` for scripted use |

---

## Quick start

### Install

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

### Send a file (SSH mode — no receiver setup needed)

```sh
# mftp SSHes to the remote, starts the receiver, transfers, and cleans up
mftp send bigfile.tar.gz user@remote-host:/data/landing/
```

mftp connects via your existing SSH credentials. The receiver is started automatically and exits when the transfer completes. If the transfer port is blocked by a firewall, mftp falls back to SFTP through port 22 without any intervention.

### Send a file (manual receiver)

On the receiver:
```sh
mftp receive --output-dir /data/landing
# Prints: Listening on 0.0.0.0:7777
# Prints: Certificate fingerprint: a3f9...
```

On the sender:
```sh
mftp send bigfile.tar.gz remote-host:7777 --trust a3f9...
```

---

## Usage

### `mftp send`

```
mftp send [OPTIONS] <FILE> <DESTINATION>
```

`DESTINATION` is either:
- `host:port` — connect to an already-running `mftp receive`
- `[user@]host:/remote/path` — launch the receiver via SSH (recommended)

```
Options:
  --trust <FINGERPRINT>    Pin the receiver's SHA-256 certificate fingerprint.
                           Omit to use TOFU (prompted once; stored in
                           ~/.config/mftp/known_hosts for subsequent transfers).
                           Ignored in SSH mode — fingerprint is read from the server.
  --remote-mftp <PATH>     Path to a pre-installed mftp on the remote host.
                           By default mftp pipes itself over SSH stdin on first use
                           and caches it at ~/.cache/mftp-<hash> on the remote.
  --port <PORT>            Port the remote mftp server should bind on (SSH mode only).
                           Defaults to a randomly assigned port. Use this when the
                           transfer port must be in a firewall allow-list.
  -n, --streams <N>        Parallel streams.
                           Direct mode: default auto-negotiated from RTT + CPU cores.
                           SFTP fallback: default 8 (each stream = one SSH connection;
                           raise to 12 if the remote sshd allows it).
      --chunk-size <BYTES> Chunk size in bytes (default: auto from RTT).
      --no-compress        Disable adaptive zstd compression.
      --tcp                Force TCP+TLS; skip the QUIC attempt.
      --tcp-below-rtt <MS> Switch to TCP+TLS when measured RTT ≤ this value (ms).
                           Auto-switches on LAN/datacenter where kernel TCP beats
                           QUIC BBR [default: 5.0]. Set to 0 to always use QUIC.
  -v, --verbose            Increase log verbosity (-v / -vv / -vvv).
```

### `mftp receive`

```
mftp receive [OPTIONS] [BIND]
```

`BIND` defaults to `0.0.0.0:7777`. Both QUIC (UDP) and TCP+TLS listen on the same port, so the sender's auto-fallback works with no extra configuration on the receiver side.

```
Options:
  -o, --output-dir <DIR>   Directory to write received files into (default: .).
      --tcp                TCP+TLS only; don't open a QUIC endpoint.
      --tcp-below-rtt <MS> See send --tcp-below-rtt above [default: 5.0].
```

### `mftp --version`

```
mftp 0.1.22
```

---

## How it works

### Transport

mftp defaults to QUIC (via [quinn](https://github.com/quinn-rs/quinn)) with BBR congestion control. In SSH mode it tries three transports in order, falling back automatically:

```
Sender                                    Receiver
  │                                           │
  ├─── QUIC connect (5 s timeout) ──────────►│  mftp receiver (launched via SSH)
  │    (if UDP is blocked or times out)       │
  ├─── TCP+TLS connect (5 s timeout) ───────►│  mftp receiver (same process)
  │    (if TCP port also unreachable)         │
  └─── SFTP (N parallel SSH connections) ───►│  sshd sftp-server (port 22 only)
```

The QUIC and TCP+TLS paths use TLS 1.3 with a freshly generated self-signed certificate shared between both transports (same fingerprint). The SFTP path bypasses the mftp receiver entirely and writes directly to the remote filesystem via the sshd built-in sftp-server subsystem.

### SSH-assisted launch

When you write `mftp send file.bin user@host:/path`, the sender:

1. SSHes to `user@host` and runs `mftp server --output-dir /path`
   - If mftp is not installed on the remote, the local binary is piped over SSH stdin and cached at `~/.cache/mftp-<hash>` — subsequent transfers with the same binary version skip the copy.
   - Use `--port <N>` to have the remote server bind on a specific port instead of a random one (useful when the transfer port must be in a firewall allow-list).
2. The remote server binds on the chosen (or random) port and prints one JSON line to stdout:
   ```json
   {"port":54321,"fingerprint":"a3f9..."}
   ```
3. The sender reads the handshake, then attempts a direct connection to `host:54321`
4. If the direct connection fails (firewall blocks the port), the sender falls back to **parallel SFTP** — N independent SSH/SFTP connections each writing a non-overlapping segment of the file directly to the remote. No mftp process is needed on the remote for this leg; it talks to the sshd sftp-server subsystem.

The remote `mftp server` exits as soon as the transfer completes (or is killed when SFTP takes over).

### SFTP fallback

The SFTP fallback uses libssh2 to open N independent SSH connections to port 22, each with its own SFTP channel. The file is divided into N equal segments; each connection writes its segment with positional I/O (`seek` + `write`) in parallel.

Throughput scales linearly with stream count because each connection is fully independent (separate congestion window, separate SSH channel):

| Streams | Throughput (LAN, 500 MiB) |
|---------|--------------------------|
| 4       | ~12 MiB/s |
| 8       | ~22 MiB/s (default) |
| 12      | ~32 MiB/s |

The ceiling per stream (~3 MiB/s) comes from libssh2's synchronous SFTP write acknowledgment. Raising `--streams` to 12 is safe on most servers; beyond that, OpenSSH's `MaxStartups` setting (default `10:30:100`) may start rate-limiting concurrent auth attempts.

The SFTP path uses a single encryption layer (SSH), whereas the tunnel approach used SSH + TLS. Authentication uses the SSH agent if running, otherwise the default key files (`~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa`). The remote host key is verified against `~/.ssh/known_hosts`.

### Parallel streams and RTT negotiation

After the QUIC handshake, sender and receiver exchange CPU core counts. The sender then reads the measured RTT from the QUIC connection stats and computes:

| RTT | Default chunk size |
|-----|-------------------|
| < 10 ms (LAN) | 8 MiB |
| 10 – 200 ms (regional/intercontinental) | 4 MiB |
| ≥ 200 ms (satellite) | 2 MiB |

Stream count is `max(⌈RTT_ms / 5⌉, min_cores)`, capped at `2 × min(sender_cores, receiver_cores)`. On a satellite link with 600 ms RTT and an 8-core machine on each end, mftp opens 8 streams of 2 MiB chunks — keeping the pipe full while staying within CPU budget.

Both values can be overridden with `--streams` and `--chunk-size`.

### Data flow

```
File on disk
  └─► ChunkQueue (atomic work-stealing index)
        └─► N parallel tasks, one per QUIC/TCP stream:
              ├─ read chunk from file (pread)
              ├─ detect already-compressed format (magic bytes)
              ├─ zstd compress if ≥5% gain
              ├─ SHA-256 hash of wire payload
              └─ send ChunkData frame

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
  Receiver → ReceiverMessage::Ready { have_chunks }   ← resume list
  ...data streams transfer...
  Sender → SenderMessage::Complete  { file_hash }
  Receiver → ReceiverMessage::Complete { file_hash }

Data streams (N per connection, one ChunkData per chunk):
  Sender → ChunkData { transfer_id, chunk_index, chunk_hash, compressed, payload }
```

### Compression

mftp compresses each chunk independently, so the decision can be made chunk-by-chunk:

1. **Magic-byte check** — if the first 4 bytes match a known compressed format (gzip, zstd, bzip2, zip, 7-zip, xz, jpeg, png, mp4, mkv/webm…), compression is skipped entirely.
2. **Sample probe** — the first 4 KiB of the chunk is compressed with zstd to estimate the ratio.
3. **Threshold** — if the estimated compressed size is not at least 5% smaller, the chunk is sent raw.
4. **Per-chunk flag** — `ChunkData.compressed` tells the receiver whether to decompress.

This means a tarball of mixed content (source code + pre-built binaries) will compress the text files and pass the binaries through unmodified, all in one transfer.

### Integrity

- **Per-chunk**: SHA-256 of the wire payload (post-compression). The receiver rejects any chunk whose hash doesn't match before writing it to disk.
- **Full-file**: SHA-256 of the original file bytes, computed by the sender. After all chunks are written and decompressed, the receiver computes the same hash from its received data and compares. A mismatch fails the transfer.
- **SFTP fallback**: integrity is provided by SSH's channel MAC (HMAC-SHA2-256). Per-chunk and full-file hashing are not available on this path since there is no mftp receiver.

### Resume

Each transfer has a UUID that the sender embeds in every `ChunkData` frame. On the receiver side, a bit-vector tracking which chunks have been received is flushed to `<output_dir>/<transfer_id>.mftp-resume` after each chunk. If the transfer is interrupted:

1. Restart `mftp receive` (or re-run the same `mftp send` command in SSH mode)
2. The receiver finds the resume file, reads which chunks it already has
3. In the `ReceiverMessage::Ready` response it lists those chunks
4. The sender skips them and only retransmits what's missing

The resume file is deleted on successful completion. Resume is not available on the SFTP fallback path.

### Security

mftp uses self-signed TLS certificates with a TOFU (Trust On First Use) model, similar to SSH:

- The receiver generates a fresh key pair on every start
- It prints the SHA-256 fingerprint of its certificate
- On first connect to a new server the sender prompts for confirmation and stores the fingerprint in `~/.config/mftp/known_hosts`, keyed by `ip:port`
- On subsequent transfers to the same server the stored fingerprint is verified silently; a mismatch is rejected as a potential MITM
- Pass `--trust <fingerprint>` to skip the interactive prompt in scripts or CI

For SSH-assisted transfers the fingerprint is obtained automatically over the existing SSH channel — no manual verification step required.

The SFTP fallback path relies on SSH host key verification against `~/.ssh/known_hosts` (the same file used by the `ssh` command).

Socket buffers are set to 32 MiB (`SO_SNDBUF` / `SO_RCVBUF`) on both ends. This covers the bandwidth-delay product at 1 Gbps × 250 ms RTT.

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

LAN performance uses the auto TCP+TLS path (same-speed as scp). At 50 ms and beyond, QUIC BBR with parallel streams dominates.

---

## Performance tips

- **Satellite / high-latency links**: mftp is designed for these. Let RTT negotiation pick the parameters; don't override unless you have a reason.
- **LAN / datacenter transfers**: mftp auto-switches to TCP+TLS when it measures RTT ≤ 5 ms (QUIC's BBR start-up is costly at near-zero latency; kernel TCP wins there). No flags needed — just run the same command.
- **Pre-compressed data** (videos, archives, already-zstd files): mftp auto-detects these and skips the compression probe. No `--no-compress` needed.
- **SFTP fallback throughput**: if the direct transfer ports are always blocked and you rely on the SFTP path, raise `--streams` from the default of 8 to 12 for ~32 MiB/s. Check that the remote sshd's `MaxStartups` is set to at least `12:30:100`.
- **OS socket buffer limit**: On Linux, the kernel may cap socket buffers below 32 MiB. Set `net.core.rmem_max` and `net.core.wmem_max` to `33554432` on both hosts for maximum throughput.

  ```sh
  sudo sysctl -w net.core.rmem_max=33554432 net.core.wmem_max=33554432
  ```

---

## Building

```sh
cargo build --release
```

Requires Rust 1.75+ (for `div_ceil` stabilization) and libssh2 (for the SFTP fallback). On most Linux distributions libssh2 is already installed (it is pulled in by git and curl); on others install `libssh2-devel` (RPM) or `libssh2-dev` (Debian/Ubuntu).

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

- **Reed-Solomon FEC** — parity shards for lossy links (e.g. satellite with burst loss); framework is in place
- **Directory transfer** — recursive send with a single command
- **Progress over SSH** — rich progress reporting in SSH mode (currently handled by the sender side only)
- **Windows support** — currently Linux/macOS only

---

## License

MIT
