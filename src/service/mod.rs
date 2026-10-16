//! Multi-tenant service layer (mftp v2, milestone M8).
//!
//! Turns the receiver daemon into a small service:
//!   * [`acl`]    — per-peer access control + byte quotas (tenant isolation)
//!   * [`queue`]  — a persistent, crash-safe transfer queue with retry (library
//!     only: the daemon does not enqueue transfers yet)
//!   * [`encrypt`]— at-rest file encryption (library only: not yet applied to
//!     received files)
//!   * [`http`]   — a read-only HTTP status API + Web UI dashboard
//!
//! These compose with the M4 daemon (control socket + mutual-TLS identity auth):
//! the ACL supplies the authorized DeviceIds and per-peer output dirs/quotas,
//! and the HTTP surface exposes status (plus the queue, once it is populated).

pub mod acl;
pub mod encrypt;
pub mod http;
pub mod queue;
