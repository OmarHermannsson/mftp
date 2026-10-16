//! Multi-tenant service layer (mftp v2, milestone M8).
//!
//! Turns the receiver daemon into a small service:
//!   * [`acl`]    — per-peer access control + byte quotas (tenant isolation)
//!   * [`queue`]  — a persistent, crash-safe record of transfer jobs
//!   * [`tracker`]— feeds received transfers into the queue and applies at-rest
//!     encryption (the receiver's [`crate::transfer::receiver::TransferObserver`])
//!   * [`encrypt`]— at-rest file encryption (`mftpd --encrypt-at-rest`)
//!   * [`http`]   — a read-only HTTP status API + Web UI dashboard
//!
//! These compose with the M4 daemon (control socket + mutual-TLS identity auth):
//! the ACL supplies the authorized DeviceIds and per-peer output dirs/quotas,
//! and the HTTP surface exposes status and the queue.

pub mod acl;
pub mod encrypt;
pub mod http;
pub mod queue;
pub mod tracker;
