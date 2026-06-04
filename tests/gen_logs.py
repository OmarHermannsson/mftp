#!/usr/bin/env python3
"""Generate a realistic, compressible JSON-log fixture for the transfer benchmark.

Emits structured log lines (stable keys, varied values) to stdout until the target
byte count is reached. Compresses ~5x with zstd-3 — representative of real logs/JSON,
unlike a trivially-repeated fixture (which compresses thousands of x and tells you
nothing). Deterministic (fixed seed; no clock/urandom) so runs are reproducible.

Usage:
    python3 tests/gen_logs.py <bytes> > test_logs.bin
    python3 tests/gen_logs.py $((1024*1024*1024)) > /tmp/test_1g_logs.bin
"""
import random
import sys

random.seed(1234)  # deterministic — no clock/urandom

words = (
    "user session token request response cache miss hit timeout retry queue "
    "worker thread pool connection socket buffer flush commit rollback index "
    "shard replica leader follower heartbeat election quorum payload header "
    "latency throughput backlog dropped accepted refused parsed encoded gzip"
).split()
levels = ["INFO", "INFO", "INFO", "DEBUG", "WARN", "ERROR"]
paths = ["/api/v1/users", "/api/v1/orders", "/healthz", "/metrics", "/api/v1/items", "/login"]

target = int(sys.argv[1])
out = sys.stdout.buffer
written = 0
buf = []
i = 0
try:
    while written < target:
        i += 1
        lvl = random.choice(levels)
        path = random.choice(paths)
        rid = random.getrandbits(48)
        msg = " ".join(random.choices(words, k=random.randint(4, 9)))
        line = (
            f'{{"ts":"2026-06-04T12:{(i // 60) % 60:02d}:{i % 60:02d}.{i % 1000:03d}Z",'
            f'"level":"{lvl}","rid":"{rid:012x}","path":"{path}",'
            f'"status":{random.choice([200, 200, 200, 404, 500])},'
            f'"latency_ms":{random.randint(1, 900)},"msg":"{msg}"}}\n'
        )
        b = line.encode()
        buf.append(b)
        written += len(b)
        if len(buf) >= 20000:
            out.write(b"".join(buf))
            buf.clear()
    if buf:
        out.write(b"".join(buf))
except BrokenPipeError:
    sys.exit(0)  # downstream consumer (e.g. `head`) closed the pipe — fine
