//! Reed-Solomon FEC encode/decode for an 8:2 stripe at a representative shard
//! size, via `mftp::fec::codec::{FecEncoder, FecDecoder}`.
//!
//! Encode: full stripe of 8 equal-length data shards → 2 parity shards.
//! Reconstruct: drop exactly 2 shards and rebuild them from the remainder.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use mftp::fec::codec::{FecDecoder, FecEncoder};
use std::hint::black_box;

const DATA_SHARDS: usize = 8;
const PARITY_SHARDS: usize = 2;
/// Representative compressed-chunk shard size.
const SHARD_SIZE: usize = 256 * 1024;

/// Deterministic LCG fill (no rand / no Date).
fn lcg_fill(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

fn make_data() -> Vec<Vec<u8>> {
    (0..DATA_SHARDS)
        .map(|i| lcg_fill(SHARD_SIZE, 0x1000 + i as u64))
        .collect()
}

fn bench_fec(c: &mut Criterion) {
    let enc = FecEncoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap();
    let dec = FecDecoder::new(DATA_SHARDS, PARITY_SHARDS).unwrap();
    let stripe_bytes = (DATA_SHARDS * SHARD_SIZE) as u64;

    let data = make_data();
    let (parity, shard_lengths) = enc.encode(data.clone()).unwrap();

    let mut group = c.benchmark_group("fec_8_2");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(stripe_bytes));

    group.bench_function("encode", |b| {
        b.iter(|| enc.encode(black_box(data.clone())).unwrap());
    });

    // Reconstruct after dropping exactly 2 shards (data shards 1 and 4).
    group.bench_function("reconstruct_2_lost", |b| {
        b.iter_batched(
            || {
                let mut shards: Vec<Option<Vec<u8>>> = data
                    .iter()
                    .map(|s| Some(s.clone()))
                    .chain(parity.iter().map(|p| Some(p.clone())))
                    .collect();
                shards[1] = None;
                shards[4] = None;
                shards
            },
            |shards| {
                dec.reconstruct(black_box(shards), &shard_lengths).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_fec);
criterion_main!(benches);
