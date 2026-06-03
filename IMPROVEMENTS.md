# Improvement backlog

Tracked improvements to mftp, ordered roughly by impact. Status: ☐ todo · ◐ in progress · ☑ done.

All items below were implemented in the v0.1.138–0.1.143 range.

## 1. Extend in-band incremental repair to directory transfers ☑
**Re-scoped after reading the code.** Directories *already* stream over one QUIC
connection as a single concatenated virtual stream (`ConcatLayout`, global chunk
indices) — there was no per-file handshake to remove. The real remaining
single-file limitation was **in-band repair**: the sender rejected a `Retransmit`
for directory transfers because its repair read seeked `chunk_index * chunk_size`
into a single source file. So a hash mismatch / unreconstructable FEC stripe in a
directory transfer aborted and fell back to resume, losing the warmed CWND.

**Done.** The sender reverse-maps each requested global chunk index to the byte
range(s) it spans across the file set (`read_concat_chunk_into`, mirroring
`feed_chunks_concat`); the receiver scatter-writes repaired chunks via
`ConcatLayout`. No wire-format change, so no `PROTOCOL_VERSION` bump. Covered by a
directory-repair end-to-end test.

## 2. Local microbenchmarks (criterion) ☑
`benches/` with criterion microbenchmarks for BLAKE3 hashing, zstd encode at the
adaptive levels (1/3/6, on compressible and incompressible input), and
Reed-Solomon FEC encode/decode (8:2). CPU-path changes can now be measured
without the lab host.

## 3. Remove unused `thiserror` dependency ☑
Dropped from Cargo.toml (was never used).

## 4. Adversarial / negative tests ☑
`tests/adversarial.rs`: decompression-bomb rejection, unreconstructable FEC stripe
(more shards lost than parity), and oversized length-prefix frames on the control
and data framing paths — each with a passing control case.

## 5. `lock().unwrap()` → `lock().expect("...")` ☑
Every mutex `lock().unwrap()` (receiver, hash tree, FEC stripe buffer,
deferred-flush, test-hook set) now names the guarded resource.

## 6. RTT-aware congestion controller selection ☑
**Finding:** mftp already used BBR explicitly with a raised initial window —
correct for its high-BDP target (low-RTT LAN already diverts to TCP+TLS). RTT is
only known post-handshake and quinn can't swap CC mid-connection, so the choice is
necessarily static per process. Delivered as an `MFTP_CC={bbr,cubic,reno}` env
override (BBR default), consistent with the other `MFTP_*` env vars.

## 7. Resume-file integrity tag ☑
Resume file format v2 prepends an 8-byte truncated BLAKE3 of the payload; a
mismatch on load (bit-rot, partial corruption) is treated like any other unusable
resume file — discarded, transfer restarts clean. Round-trip + corruption tests.

## 8. Config file ☑
`~/.config/mftp/config.toml` providing persistent defaults for the sender tuning
knobs (streams, chunk_size, no_compress, transport, tcp_below_rtt, fec, port).
Precedence: explicit CLI flag > config file > built-in default. Absent file is not
an error.

## 9. README usage examples ☑
Examples by link type — satellite (FEC), intercontinental (streams), LAN
(TCP/no-compress), and directory transfers.
