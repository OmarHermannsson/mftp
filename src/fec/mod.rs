//! Reed-Solomon forward error correction.
//!
//! File chunks are grouped into stripes of `data_shards` chunks each.
//! `parity_shards` additional parity chunks are appended per stripe.
//! The receiver can reconstruct any `data_shards` chunks from any
//! `data_shards` received shards in the stripe (data or parity).
//!
//! Shard grouping:
//!   stripe 0: chunks [0 .. data_shards)        + parity [P0 .. P(parity_shards))
//!   stripe 1: chunks [data_shards .. 2*ds)     + parity ...
//!   ...
//!
//! Chunk indices on the wire include a `is_parity` flag and `stripe_index`
//! so the receiver can reconstruct without knowing the original order.

pub mod codec;
