//! Multi-tenant service layer (mftp v2, milestone M8).
//!
//! Turns the receiver daemon into a small service:
//!   * [`acl`]    — per-peer access control + byte quotas (tenant isolation)
//!   * [`queue`]  — a persistent, crash-safe transfer queue with retry
//!   * [`encrypt`]— optional at-rest encryption of received files
//!   * [`http`]   — a read-only HTTP status API + Web UI dashboard
//!
//! These compose with the M4 daemon (control socket + mutual-TLS identity auth):
//! the ACL supplies the authorized DeviceIds and per-peer output dirs/quotas,
//! the queue records transfers, and the HTTP surface exposes them.

pub mod acl;
pub mod encrypt;
pub mod http;
pub mod queue;
