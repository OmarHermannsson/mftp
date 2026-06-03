//! BLAKE3 hashing throughput over a representative 4 MiB chunk.
//!
//! Per-chunk BLAKE3 is on the hot path of both send and receive (the receiver
//! verifies every chunk before writing). This bench measures raw hashing
//! throughput so CPU-path changes can be tracked without the lab host.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Deterministic pseudo-random fill via a simple LCG (no rand / no Date).
fn lcg_fill(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

fn bench_blake3(c: &mut Criterion) {
    let data = lcg_fill(CHUNK_SIZE);
    let mut group = c.benchmark_group("blake3_hash");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(CHUNK_SIZE as u64));
    group.bench_function("4MiB", |b| {
        b.iter(|| blake3::hash(black_box(&data)));
    });
    group.finish();
}

criterion_group!(benches, bench_blake3);
criterion_main!(benches);
