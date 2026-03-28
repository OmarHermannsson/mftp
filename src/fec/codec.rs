//! Thin wrapper around `reed-solomon-erasure` for encode/decode.
//!
//! `FecEncoder` and `FecDecoder` are not yet implemented.
//! The protocol messages (`FecParams`, `TransferManifest::fec`) and the
//! stripe layout described in `fec/mod.rs` are already defined; this module
//! will provide the codec once the feature is built out.
