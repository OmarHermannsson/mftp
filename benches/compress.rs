//! zstd compression throughput at the three adaptive levels (1, 3, 6).
//!
//! `mftp::compress::compress_chunk` samples a 64 KiB prefix and only compresses
//! the full chunk if the sample shows >5% gain (see `src/compress/mod.rs`).
//! These are the levels picked by `AdaptiveLevel`: 1 for near-incompressible,
//! 3 mid-range, 6 for highly compressible data. We bench both highly
//! compressible (repeated text) and near-incompressible (LCG bytes) inputs.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use mftp::compress::compress_chunk;
use std::hint::black_box;

const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const LEVELS: [i32; 3] = [1, 3, 6];

/// Highly compressible: a short phrase repeated to fill the chunk.
fn compressible(len: usize) -> Vec<u8> {
    let phrase = b"the quick brown fox jumps over the lazy dog. ";
    phrase.iter().copied().cycle().take(len).collect()
}

/// Near-incompressible: deterministic LCG-generated pseudo-random bytes
/// (no rand / no Date dependency).
fn incompressible(len: usize) -> Vec<u8> {
    let mut state: u64 = 0xDEADBEEFCAFEBABE;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

fn bench_compress(c: &mut Criterion) {
    let inputs: [(&str, Vec<u8>); 2] = [
        ("compressible", compressible(CHUNK_SIZE)),
        ("incompressible", incompressible(CHUNK_SIZE)),
    ];

    let mut group = c.benchmark_group("compress_chunk");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(CHUNK_SIZE as u64));
    for (kind, data) in &inputs {
        for level in LEVELS {
            group.bench_with_input(
                BenchmarkId::new(*kind, format!("level{level}")),
                &level,
                |b, &lvl| {
                    b.iter(|| compress_chunk(black_box(data), lvl).unwrap());
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_compress);
criterion_main!(benches);
