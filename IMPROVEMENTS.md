# Improvement backlog

Tracked improvements to mftp, ordered roughly by impact. Status: ☐ todo · ◐ in progress · ☑ done.

## 1. Multi-file / directory transfer over a single connection ☐
**Problem.** The transfer protocol is single-file-centric and in-band repair
(`ReceiverMessage::Retransmit`) is explicitly single-file only. Sending a
directory of many files re-handshakes per file; on a high-RTT link the
per-file handshake cost dominates — the exact case mftp exists to win.

**Plan.** A manifest-of-files (paths, sizes, per-file chunk ranges) streamed
over one QUIC connection, with chunks addressed by `(file_index, chunk_index)`.
Extend repair to span files. Bumps `PROTOCOL_VERSION`.

**Highest impact; done last, carefully, sequentially — touches the protocol core.**

## 2. Local microbenchmarks (criterion) ☐
**Problem.** Only `tests/bench.sh` exists, which needs the lab host and can't
isolate CPU-bound stages (a shared rate ceiling masks startup/window changes).

**Plan.** `benches/` with criterion microbenchmarks for BLAKE3 hashing, zstd
encode at each adaptive level, and Reed-Solomon FEC encode/decode. Lets CPU-path
changes be verified without the lab and guards against regressions.

## 3. Remove unused `thiserror` dependency ☐
Imported in Cargo.toml but never used anywhere in `src/`. Trivial cleanup.

## 4. Adversarial / negative tests ☐
**Problem.** The code defends against decompression bombs (`compress/mod.rs`),
malformed frames, and corrupt resume files, but nothing tests those paths.
**Plan.** Tests for: decompression bomb rejection, unreconstructable FEC stripes
(more shards lost than parity), corrupt/truncated resume file → clean restart,
and TLS fingerprint mismatch (wrong cert presented) → rejection.

## 5. `lock().unwrap()` → `lock().expect("...")` ☐
~16 `lock().unwrap()` sites (receiver.rs, hash.rs, fs_ext.rs). A panic inside a
critical section poisons the lock and turns one bug into a cascade of opaque
`PoisonError` unwraps. Give each an `expect` that names what it guards.

## 6. RTT-aware congestion controller selection ☐
**Problem.** Congestion control is fixed. Optimal CC differs by path: BBR for
high-RTT/high-BDP, something loss-tolerant for lossy links.
**Plan.** Select quinn's CC factory from the measured RTT (`negotiate.rs`) at
connection setup. Internal/auto only for now — no new CLI flag.

## 7. Resume-file integrity tag ☐
**Problem.** The resume bit-vector is trusted on reload. Atomic write-then-rename
prevents torn writes, but not bit-rot or partial corruption from other causes.
**Plan.** Store a truncated BLAKE3 (already a dep) of the payload in the header;
verify on load and fall back to a clean restart on mismatch (path already handled).

## 8. Config file ☐
**Problem.** A growing set of tuning knobs (`--streams`, `--chunk-size`,
`--tcp-below-rtt`, `MFTP_*` env vars) must be passed every invocation.
**Plan.** `~/.config/mftp/config.toml` providing defaults, overridden by CLI flags.

## 9. README usage examples ☐
Concrete commands for the three headline scenarios — satellite uplink, LAN,
intercontinental — each with the flags that matter for that link.
