# mftp v2 — Vision & Roadmap

> Strategic vision/roadmap, not an executable plan. Structured as milestones
> (M0–M8) with acceptance criteria so it can drive incremental, trackable
> execution. Each milestone is sized to ship standalone value; a follow-up turns
> one milestone into an implementation plan.

## Implementation status

All milestones M0–M8 are implemented, tested, and committed (one commit per
milestone). Every change keeps `cargo test`, `cargo clippy -- -D warnings`, and
`cargo fmt --check` green; the suite grew from ~70 to ~140 tests.

| Milestone | Status | Verification |
|---|---|---|
| M0 Document | ✅ | this doc, linked from README |
| M1 Transport trait + v7 StreamHello | ✅ | unit + full integration suite |
| M2 Persistent identity + `--trust-device` | ✅ | unit + e2e accept/reject |
| M3 Multipath / link bonding | ✅ | e2e 2-path transfer on loopback¹ |
| M4 Daemon + mutual-TLS DeviceId auth | ✅ | control RPCs + e2e auth + CLI smoke |
| M5 LAN discovery | ✅ | protocol + resolve e2e (unicast)² |
| M6 Rendezvous + hole punching | ✅ | broker e2e + rendezvous→QUIC transfer¹ |
| M7 Zero-knowledge relay | ✅ | full QUIC transfer *through* the relay¹ |
| M8 Service (ACL/quota/queue/Web UI/at-rest enc) | ✅ | unit + e2e ACL routing + live Web UI |

**Deployment-gated checks** (the data-plane code is implemented and verified for
correctness on loopback; these specific numbers/conditions require infrastructure
not present in a single-host sandbox):
- ¹ **Throughput / real paths** — M3's "aggregate beats one connection" needs the
  multi-NIC lab harness; loopback proves multi-connection correctness.
- ² **Multicast / NAT** — M5 multicast delivery and M6 cross-NAT hole-punch
  *success* depend on the network (blocked in containers); the protocols are
  verified over unicast/loopback, and M7's relay is the symmetric-NAT fallback.

Post-review hardening (code-review pass): fixed concurrent-transfer isolation
(the daemon/`serve` path now handles each connection on its own task — a second
sender can no longer be absorbed into an in-flight transfer); replaced the
DeviceId byte-scan with structural X.509 SubjectPublicKeyInfo extraction (closes
an auth-bypass where a planted SPKI could forge an id); bound each relay session
to its first sender (no third-party hijack); generation-checked broker
de-registration; broker reports `Found` only when the receiver's presence is
live; discovery no longer lets a nameless responder wildcard-match a real query;
ACL byte-quotas are now enforced at connect time; and the sender surfaces a
device-identity load failure instead of silently dropping its client cert.

Carried-forward refinements (noted in commits): TCP-path client-cert auth (QUIC
done), connection-bonding *multipath into one of many concurrent* daemon
transfers (needs a transfer_id→path registry; bonding is available via the
dedicated multipath receiver, and concurrent single-connection transfers work),
per-transfer (vs connect-time) quota precision, and the browser-rendered
dashboard (the JSON/HTML API it consumes is served and tested).

## Context

mftp today (v0.2.2) is a mature, clean **point-to-point pipe**: one sender, one
receiver, one transfer per invocation. The protocol backlog is exhausted —
PROTOCOL_VERSION is at 6; adaptive compression, BDP windows, dynamic streams,
in-band repair, and the QUIC→TCP→SFTP fallback cascade all shipped and
benchmarked. There is no obvious *incremental* protocol win left, which is the
signal that the next step is a **change in product shape**, not more tuning.

Three constraints define what mftp can't do today, mapping onto the three v2
themes in this vision:

1. **It can only reach what's already reachable.** The sender needs a routable
   `host:port` or an SSH login — no daemon, discovery, NAT traversal, or relay
   (`net/connection.rs` connects to a raw `SocketAddr`; `receive` loops but has
   no identity/auth/queue).
2. **It is single-tenant and stateless.** No persistent identity, auth beyond a
   session-only TOFU fingerprint, quotas, queue, API, or at-rest encryption.
3. **It rides one connection over one path.** All streams share a single QUIC
   connection on a single interface; directory transfers flatten to one logical
   concat stream.

### The keystone insight (validated against the code)

The data plane is **already transport-agnostic**. `run_transfer`
(`transfer/sender.rs:786`) and `run_receive` (`transfer/receiver.rs:810`) are
generic over `AsyncWrite`/`AsyncRead` plus `spawn_worker` / `accept_stream`
closures. The chunk feed (`ChunkQueue`, `feed_chunks*`), per-chunk BLAKE3
(`ChunkHasher`), resume (`ResumeState`), compression, and in-band repair
(`Retransmit`) never touch `quinn` or `TcpStream` directly — only closures and
`Box<dyn AsyncRead + Unpin + Send>`. The only QUIC leak into the engine is the
optional `qconn` used for `set_send_window` and the stats sampler
(`sender.rs:996-1008`).

That seam is what every v2 theme hangs off, so v2's invariant — *reuse the
existing data plane under any new transport* — is achievable **without
rewriting the hot path.** The unifying architectural move is promoting mftp from
a *CLI invocation* to a **persistent daemon (`mftpd`) with a pluggable transport
layer and a control plane**; the existing transfer engine is preserved
underneath as the data plane. Classic point-to-point mode keeps working with no
daemon required.

---

## Architecture overview

```
            ┌────────────── control plane (new in v2) ──────────────┐
  mftp CLI ─┤  UDS + bincode  ├─► mftpd ◄─┤ rendezvous / relay (opt) │
   (client) └─────────────────┘    │       └──────────────────────────┘
   or embedded (classic)           │  auth + ACL gate
                                    ▼
            ┌──── data plane (today's engine, reused under a trait) ──┐
            │ Transport trait → {QUIC | TCP+TLS | multipath | relay}  │
            │ ChunkQueue · zstd · BLAKE3 · resume · in-band repair    │
            │ (SFTP stays a terminal whole-file fallback, not a impl) │
            └──────────────────────────────────────────────────────────┘
```

### Core abstractions introduced

- **`Transport` trait** (`src/transport/mod.rs`, new). Abstracts: `connect` /
  `accept_control` (a bidirectional control channel), `open_stream` /
  `accept_stream` (one unidirectional data stream), `path_stats()` (RTT / loss /
  cwnd for window sizing + adaptive scaling), and `caps()` (`reliable`,
  `multistream`, `supports_window_tuning`, `mtu_hint`). QUIC and TCP+TLS become
  thin impls wrapping existing code; multipath and relay are future impls. FEC
  enable/disable is driven by `caps.reliable` (matching today's `send_tcp`
  behaviour). **SFTP is deliberately *not* a `Transport`** — it's a whole-file
  protocol, kept as the terminal cascade fallback.

- **Stream-id preamble** (small wire change, lands in **protocol v7**). Today
  the receiver attributes data streams to chunks by *accept order* on one
  connection. A 1-frame `StreamHello { transfer_id, stream_seq }` per data
  stream lets the receiver attribute streams regardless of arrival order or
  which connection/path they came in on. Required before any multi-connection
  feature (multipath, relay).

- **`mftpd` daemon** (`src/daemon/`, new). A long-lived per-user process owning
  persistent identity, the listener endpoints (reusing `receiver::Server` /
  `TcpServer`), an auth+ACL gate inserted between `accept` and `run_receive`
  (which is **reused verbatim**), and a local control socket. The CLI becomes a
  client; if no daemon socket is present, `mftp send` falls back to today's
  in-process path automatically.

- **Local control IPC: Unix domain socket + length-prefixed bincode, reusing
  `protocol/framing.rs`.** No gRPC, no JSON-RPC — `framing.rs` is already
  generic over any byte stream, the types already derive serde, and UDS gives
  filesystem-perm + `SO_PEERCRED` auth for free. A new `DaemonRequest` /
  `DaemonResponse` enum pair carries: `SubmitTransfer`, `QueryStatus`, `Cancel`,
  `Subscribe` (streamed progress), trust mgmt, ACL mgmt, `Identity`. The
  REST/Web-UI is a separate adapter (behind a cargo feature) that translates
  HTTP → the same enum; HTTP stays out of the core protocol.

- **Persistent device identity** (`src/identity.rs`, new). An Ed25519 device key
  at `~/.config/mftp/device_key` (mode 0600). Its public key is the stable
  **DeviceId** used for rendezvous and ACLs. The TLS cert is bound to / signed
  by this key, so the receiver fingerprint becomes **stable across restarts**
  (today it changes every session — a real TOFU wart). The trust store evolves
  from `addr → fingerprint` to `DeviceId → …` so peers that roam IPs stay
  trusted; old `known_hosts` entries are migrated.

---

## Theme 1 — Reach / connectivity

**Goal:** a transfer succeeds between any two machines that can each reach the
internet, with zero firewall/port-forward setup. Biggest leap toward
"open-source Aspera."

Mechanics (all layered onto the existing self-managed UDP socket in
`connection.rs:291`, reused for STUN/probe before the QUIC handshake — no second
socket):

- **mDNS LAN discovery** (cheap, no infra) — `mftp send file alice/laptop`
  resolves on the local network. Highest value-per-effort; ship first.
- **Rendezvous + ICE-lite hole punching** — `mftpd` registers
  `{DeviceId, signed_token, observed_external_addr}` with a self-hostable
  rendezvous broker (signaling only, never sees bytes). Sides exchange
  `Offer`/`Answer` candidates (host / server-reflexive / relay) and fire
  simultaneous UDP probes from the QUIC socket to punch NAT mappings; first
  round-tripping pair wins.
- **Relay fallback** (symmetric NAT both sides) — a TURN-like relay blindly
  forwards encrypted QUIC datagrams. **Zero-knowledge**: TLS terminates at the
  two `mftpd` endpoints authenticated by DeviceId, so the relay sees ciphertext
  only and cannot impersonate or decrypt.

New cascade: **direct → mDNS → hole-punched → relayed → SSH legacy**. New
signaling protocol lives in `src/reach/signal.rs`, distinct from the data-plane
`protocol/messages.rs`; once a path is established the data wire format is
unchanged. Rendezvous/relay are **opt-in** (a config URL) — the no-infra TOFU
story is preserved.

---

## Theme 2 — Service / platform

**Goal:** turn the one-shot receiver into a real multi-tenant service.

- **Daemon receiver** — many transfers over time; each routed through the
  auth+ACL gate, then today's `run_receive`.
- **Identity-based auth & ACLs** — peers authenticate with their DeviceId; ACLs
  govern who may push/pull, to which path prefixes, with what quota. Per-user
  output roots replace the single global `--output-dir`. Client cert (mutual
  auth) is optional, gated by ACLs — classic mode stays server-auth-only.
- **Transfer queue & quotas** — persistent queue with priorities/retries
  (cancel is safe & resumable since resume state persists); per-peer disk/bw
  quotas.
- **Web UI + REST/gRPC API** — a thin HTTP adapter over the daemon control
  plane; CLI and Web UI are two clients of one API.
- **Encryption-at-rest (optional)** — envelope encryption keyed per-account so a
  compromised receiver disk doesn't leak payloads.

**Trade-off:** this is where mftp stops being "scp but faster" and becomes
infrastructure — a real security surface (auth, ACLs, network API, at-rest
crypto) and operational burden. Gate it behind explicit server mode so the
simple CLI stays simple. Do it **last**.

---

## Theme 3 — Protocol / perf frontier

**Goal:** push throughput/robustness past a single QUIC connection on one path.
(Measure these with the tmpfs + small-file + multi-NIC lab harness — bulk 5 GiB
timing masks them behind a shared rate ceiling.)

- **Multipath / link bonding — the headline.** Decision settled: **bond N
  independent `Transport` connections above the chunk layer; do NOT use
  multipath-QUIC.** The existing model — N stream workers pulling from one shared
  MPMC work channel (`sender.rs:1211`) — already *is* link bonding: a fast path
  naturally drains more chunks, chunks are self-describing (carry offset +
  BLAKE3) so they land via `pwrite` regardless of path/order, and each path runs
  its own independent BBR (correct for heterogeneous links like satellite +
  cellular). The change: `spawn_worker` distributes streams across a
  `PathSet: Vec<Box<dyn Transport>>` instead of always `conn.open_uni()`; the
  adaptive-scaling loop (`sender.rs:706-764`) becomes "add/remove a stream *on
  path P*." Requires the stream-id preamble (receiver attributes streams across
  connections). Resume is unaffected — one bit-vector per transfer regardless of
  paths.
- **Pluggable transports** — the `Transport` trait itself (M1); formalizes
  today's `--transport` cascade into impls so new data planes drop in without
  touching chunk/repair logic.
- **Parallel BLAKE3 hashing** — BLAKE3 is ~35% of sender CPU; on fast links it's
  the bottleneck. `ChunkHasher` already accepts out-of-order feeds, so
  parallelizing per-chunk hashes across threads is local to `transfer/hash.rs`
  and low-risk.
- **Per-file stream scheduling for directories** — today a directory flattens to
  one concat stream; allocate streams per-file/size-class so many-small-files
  isn't serialized behind the concat layout.
- **Bandwidth shaping / QoS** — a `--limit-rate` + fair-share scheduling in the
  daemon so background transfers yield to interactive traffic (no rate control
  beyond BBR today).
- **Retire FEC as a headline feature** — benchmarks show `--fec` is
  wash-to-worse over reliable QUIC streams. Keep it only as the
  reset-stream/hash-failure repair primitive it earns; drop it from v2 throughput
  marketing.

---

## Milestone roadmap (trackable units)

Dependency order: the `Transport` trait + stream preamble is the linchpin
(unblocks multipath & multi-connection reach); identity is independent and the
best first *user-visible* ship; the daemon reuses `run_receive` and hosts the
service + rendezvous features.

### M0 — Document & commit the vision
- **Do:** land this doc as `docs/V2_VISION.md`; link from README; open tracking
  issues per milestone.
- **Done when:** doc committed; milestones enumerated as issues/goals.

### M1 — `Transport` trait + stream-id preamble (protocol v7) *(foundation)*
- **Do:** define `Transport` in `src/transport/mod.rs`; wrap QUIC & TCP+TLS as
  impls; replace the hand-rolled cascade in `sender::send` with "decide →
  `Box<dyn Transport>` → same engine"; generalize `run_transfer`'s `qconn` to
  `path_stats()` + `caps()`; add the `StreamHello` preamble per data stream;
  bump PROTOCOL_VERSION to 7. SFTP documented as terminal fallback (not a impl).
- **Touches:** `transfer/sender.rs` (`send`, `run_transfer`, `spawn_worker`),
  `transfer/receiver.rs` (`run_receive`, `accept_stream`), `protocol/messages.rs`
  + `framing.rs`, new `src/transport/`.
- **Done when:** QUIC & TCP paths run entirely through the trait; per-transport
  unit tests pass; full integration + adversarial suites green; no engine code
  references `quinn` directly.

### M2 — Persistent Ed25519 identity + stable fingerprint *(first user-visible ship)*
- **Do:** generate/load device key in new `src/identity.rs`; bind TLS cert to
  it; DeviceId-keyed trust store with migration from old `known_hosts`; add
  `--trust-device <pubkey>`. Independent of M1.
- **Touches:** `net/connection.rs` (cert gen, `TofuVerifier`,
  `PinnedFingerprintVerifier`, known-hosts helpers), new `src/identity.rs`,
  `config.rs`.
- **Done when:** receiver fingerprint is stable across restarts; v1↔v2 trust
  matrix tested; `--trust` scripted path unchanged.

### M3 — Multipath / link bonding *(headline perf)*
- **Do:** `PathSet`; distribute `spawn_worker` streams across paths; per-path
  `set_send_window`; extend adaptive scaling to per-path; receiver attributes
  streams via M1 preamble. No daemon needed.
- **Touches:** `transfer/sender.rs` (worker distribution, scaling loop),
  `transfer/receiver.rs` (multi-connection `accept_stream`).
- **Done when:** two-NIC (or two `tc`-shaped paths) aggregate throughput beats a
  single tuned connection on the lab harness; single-path unaffected.

### M4 — `mftpd` daemon (accept-many + identity auth only)
- **Do:** daemon process + lifecycle; UDS+bincode control socket
  (`DaemonRequest`/`Response`); auth+ACL gate before `run_receive` (reused
  verbatim); CLI becomes a client with classic-mode fallback. Excludes
  queue/quota/Web-UI.
- **Touches:** new `src/daemon/{mod,proto,server}.rs`, `main.rs` (client vs
  embedded dispatch), reuses `receiver::serve`.
- **Done when:** daemon accepts sequential transfers with DeviceId auth; CLI
  submits to it; `mftp send host:port` with no daemon still works in-process.

### M5 — Reach: mDNS LAN discovery
- **Done when:** `mftp send file <name>` resolves & transfers on the LAN with no
  IP specified.

### M6 — Reach: rendezvous + hole punching
- **Do:** `mftp-rendezvous` broker; registration/heartbeat; `Offer`/`Answer`
  candidate exchange; simultaneous-open punch on the QUIC socket
  (`src/reach/signal.rs`).
- **Done when:** transfer succeeds between two consumer-NAT hosts via punched
  path (measure success rate by NAT type — see Validation).

### M7 — Reach: relay fallback
- **Done when:** transfer succeeds across symmetric NAT via zero-knowledge
  relay; relay verified to see ciphertext only.

### M8 — Service layer
- **Do:** ACLs, quotas, transfer queue, REST/Web-UI adapter (cargo-gated),
  at-rest encryption. Gated behind explicit server mode.
- **Done when:** multi-tenant receiver with per-peer ACLs/quotas; Web UI submits
  & monitors transfers.

**Parallelizable / opportunistic:** M1 and M2 can run concurrently. Parallel
BLAKE3 (`transfer/hash.rs`) and bandwidth shaping are small, self-contained
items that slot in any time after M1.

---

## What stays the same (invariants / non-goals)

- The **chunk + BLAKE3 + resume + in-band-repair data plane** is reused, not
  rewritten — v2 wraps it behind the `Transport` trait.
- **Classic point-to-point mode** (`mftp send host:port`, SSH mode) keeps
  working with no daemon required; v2 is additive.
- **TOFU simplicity** survives for the no-infra case; rendezvous/relay/accounts
  are opt-in.
- **SFTP** stays the terminal whole-file fallback, not forced into the trait.
- The **mission** is unchanged — maximum throughput for large files over
  high-latency links. Every theme is judged against it (FEC demoted, multipath
  promoted).

---

## Key risks & trade-offs

- **Scope explosion.** Three themes is multi-quarter. The milestone split exists
  so each ships standalone; resist building Service (M8) before the daemon (M4)
  proves out, and split Reach's cheap LAN win (M5) from the expensive WAN tail
  (M6–M7).
- **Receiver stream attribution** is the real engineering in multipath/relay —
  the M1 stream-id preamble must land first.
- **Security surface.** Service mode adds auth, ACLs, a network API, at-rest
  crypto — gate it; don't let the simple CLI inherit it.
- **Operational dependency.** Rendezvous + relay are servers someone must run —
  ship self-hostable references and keep direct/SSH fallbacks so mftp never
  *requires* hosted infra.
- **Identity backward-compat.** The cert↔key binding must keep a v1 sender
  accepting a v2 receiver via TOFU; test the v1↔v2 matrix; don't break `--trust`.
- **Benchmark blindness.** Multipath/hole-punch wins must be measured with the
  tmpfs + small-file + multi-NIC lab harness, or they'll read as noise.

---

## Validation (de-risk before committing to a phase)

1. **Hole-punching spike (gates M6 scope).** Prototype STUN-style candidate
   exchange + simultaneous QUIC open between two machines behind real consumer
   NATs; measure success rate by NAT type. Poor rate → Reach leans on relay.
2. **Multipath spike (gates M3).** On the bench server, bond two NICs (or two
   `tc`-shaped paths) and stripe streams; confirm aggregate beats a single tuned
   connection on the tmpfs + small-file harness. If not, M3 isn't worth it.
3. **Daemon API shape (gates M4).** Sketch `DaemonRequest`/`Response` and
   re-skin today's CLI as a UDS client in classic mode — proves the daemon
   abstraction holds before Reach/Service build on it.

Per-milestone acceptance criteria above double as the functional verification;
all milestones must keep the existing `cargo test` (integration + adversarial)
and `cargo clippy -- -D warnings` / `cargo fmt --check` green, and commit after
each meaningful change.
