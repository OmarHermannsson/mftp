//! `mftpd` daemon control plane (mftp v2, milestone M4).
//!
//! The daemon is a long-running per-user process that (a) serves the network
//! receiver (accept-many, reusing [`crate::transfer::receiver`]) and (b) exposes
//! a **local control socket** the CLI talks to. Per the v2 design the control
//! transport is a Unix domain socket carrying length-prefixed bincode frames —
//! reusing [`crate::protocol::framing`] rather than pulling in gRPC/JSON-RPC, and
//! getting filesystem-permission auth for free.
//!
//! This module is Unix-only (the control socket is a UDS); the daemon network
//! receiver itself is cross-platform.

#![cfg(unix)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};

use crate::protocol::framing;

/// A request from a CLI client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonRequest {
    /// Liveness check.
    Ping,
    /// Ask for this device's identity (DeviceId + cert fingerprint).
    Identity,
    /// List the authorized peer DeviceIds (the mutual-TLS allowlist).
    ListTrust,
    /// Authorize a peer DeviceId to send to this daemon.
    AddTrust { device_id: String },
    /// Revoke a peer DeviceId.
    RemoveTrust { device_id: String },
    /// Daemon status snapshot.
    Status,
}

/// The daemon's reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonResponse {
    Pong,
    Identity {
        device_id: String,
        fingerprint: String,
    },
    Trust {
        devices: Vec<String>,
    },
    /// Result of an Add/Remove: whether the set actually changed.
    TrustChanged {
        changed: bool,
    },
    Status {
        listening_on: String,
        /// Whether mutual-TLS DeviceId auth is enforced (allowlist non-empty).
        auth_enforced: bool,
        authorized_count: usize,
        transfers_completed: u64,
    },
    Error {
        message: String,
    },
}

/// Shared daemon state behind the control socket.
pub struct DaemonState {
    /// Config directory holding identity + authorized_devices.
    pub config_dir: PathBuf,
    /// Human-readable address the network receiver is bound to.
    pub listening_on: String,
    /// Count of completed transfers (for Status).
    pub transfers_completed: AtomicU64,
}

impl DaemonState {
    pub fn new(config_dir: PathBuf, listening_on: String) -> Self {
        DaemonState {
            config_dir,
            listening_on,
            transfers_completed: AtomicU64::new(0),
        }
    }
}

/// Default control-socket path (`$XDG_RUNTIME_DIR/mftpd.sock`, else
/// `~/.config/mftp/mftpd.sock`).
pub fn default_socket_path() -> Option<PathBuf> {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Some(PathBuf::from(rt).join("mftpd.sock"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/mftp/mftpd.sock"))
}

/// Handle one control request against the daemon state.
fn handle_request(state: &DaemonState, req: DaemonRequest) -> DaemonResponse {
    match req {
        DaemonRequest::Ping => DaemonResponse::Pong,
        DaemonRequest::Identity => match crate::identity::load_or_create_in(&state.config_dir) {
            Ok(id) => DaemonResponse::Identity {
                device_id: id.device_id,
                fingerprint: id.fingerprint,
            },
            Err(e) => DaemonResponse::Error {
                message: format!("identity: {e:#}"),
            },
        },
        DaemonRequest::ListTrust => DaemonResponse::Trust {
            devices: crate::identity::load_authorized_in(&state.config_dir),
        },
        DaemonRequest::AddTrust { device_id } => {
            match crate::identity::add_authorized_in(&state.config_dir, &device_id) {
                Ok(changed) => DaemonResponse::TrustChanged { changed },
                Err(e) => DaemonResponse::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        DaemonRequest::RemoveTrust { device_id } => {
            match crate::identity::remove_authorized_in(&state.config_dir, &device_id) {
                Ok(changed) => DaemonResponse::TrustChanged { changed },
                Err(e) => DaemonResponse::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        DaemonRequest::Status => {
            let authorized = crate::identity::load_authorized_in(&state.config_dir);
            DaemonResponse::Status {
                listening_on: state.listening_on.clone(),
                auth_enforced: !authorized.is_empty(),
                authorized_count: authorized.len(),
                transfers_completed: state.transfers_completed.load(Ordering::Relaxed),
            }
        }
    }
}

/// Serve the control socket: one request/response per connection, forever.
pub async fn serve_control(listener: UnixListener, state: Arc<DaemonState>) -> Result<()> {
    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .context("accept control connection")?;
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_control_conn(stream, st).await {
                tracing::debug!("control connection error: {e:#}");
            }
        });
    }
}

async fn handle_control_conn(stream: UnixStream, state: Arc<DaemonState>) -> Result<()> {
    let (mut rd, mut wr) = stream.into_split();
    // One request per connection keeps the protocol trivial and stateless.
    let req: DaemonRequest = match framing::recv_message(&mut rd).await? {
        Some(r) => r,
        None => return Ok(()), // client closed without a request
    };
    let resp = handle_request(&state, req);
    framing::send_message(&mut wr, &resp).await?;
    Ok(())
}

/// Bind the control socket, removing any stale socket file first.
pub fn bind_control_socket(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // A leftover socket file from a previous run would make bind() fail with
    // EADDRINUSE even though nothing is listening; clear it.
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    Ok(listener)
}

/// Run the daemon: serve the QUIC network receiver (accept-many, multipath) and
/// the local control socket concurrently, using the persistent device identity.
///
/// When `~/.config/mftp/authorized_devices` is non-empty, mutual-TLS DeviceId
/// auth is enforced and only QUIC is served (the TCP path does not yet present
/// client certs, so serving it under auth would be a bypass).
pub async fn run(
    bind: std::net::SocketAddr,
    output_dir: PathBuf,
    socket_path: PathBuf,
    announce_name: String,
) -> Result<()> {
    let config_dir =
        crate::identity::config_dir().context("cannot locate config dir ($HOME unset)")?;
    let id = crate::identity::load_or_create_in(&config_dir)?;
    let authorized = crate::identity::load_authorized_in(&config_dir);
    let auth_enforced = !authorized.is_empty();

    let key = crate::net::connection::make_private_key(id.key_bytes.clone())?;
    let server = crate::transfer::receiver::Server::bind_with_cert_auth(
        bind,
        output_dir,
        id.cert.clone(),
        key,
        id.fingerprint.clone(),
        if auth_enforced {
            Some(authorized.clone())
        } else {
            None
        },
    )?;
    let listening_on = server.local_addr.to_string();

    println!("mftpd listening on {listening_on} (QUIC)");
    println!("Device ID: {}", id.device_id);
    println!("Fingerprint: {}", id.fingerprint);
    if auth_enforced {
        println!(
            "Identity auth: ENFORCED ({} authorized device(s))",
            authorized.len()
        );
    } else {
        println!("Identity auth: open (add devices with `mftp daemon-trust add <id>`)");
    }
    println!("Control socket: {}", socket_path.display());

    // LAN discovery responder (M5): announce ourselves so senders can reach us
    // by name. Best-effort — if the host can't join the multicast group (e.g.
    // no multicast-capable interface) the daemon still serves normally.
    let announce_port = server.local_addr.port();
    let announce_device = id.device_id.clone();
    match crate::discovery::bind_responder() {
        Ok(sock) => {
            println!("Discovery: announcing as {announce_name:?} on the LAN");
            tokio::spawn(crate::discovery::respond_loop(
                sock,
                announce_name,
                announce_port,
                announce_device,
            ));
        }
        Err(e) => tracing::warn!("LAN discovery disabled (could not bind responder): {e:#}"),
    }

    let listener = bind_control_socket(&socket_path)?;
    let state = Arc::new(DaemonState::new(config_dir, listening_on));

    // Serve both forever; if either exits (error), propagate.
    tokio::try_join!(server.serve(), serve_control(listener, state))?;
    Ok(())
}

/// Send a single request to the daemon at `socket_path` and return its reply.
pub async fn client_request(socket_path: &Path, req: DaemonRequest) -> Result<DaemonResponse> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect to daemon at {}", socket_path.display()))?;
    let (mut rd, mut wr) = stream.into_split();
    framing::send_message(&mut wr, &req).await?;
    let resp: DaemonResponse = framing::recv_message_required(&mut rd).await?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn_test_daemon(dir: &Path) -> (PathBuf, Arc<DaemonState>) {
        let sock = dir.join("test.sock");
        let listener = bind_control_socket(&sock).unwrap();
        let state = Arc::new(DaemonState::new(
            dir.to_owned(),
            "127.0.0.1:7777".to_string(),
        ));
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = serve_control(listener, st).await;
        });
        (sock, state)
    }

    #[tokio::test]
    async fn control_ping_identity_status() {
        let dir = tempfile::tempdir().unwrap();
        let (sock, _state) = spawn_test_daemon(dir.path()).await;

        assert!(matches!(
            client_request(&sock, DaemonRequest::Ping).await.unwrap(),
            DaemonResponse::Pong
        ));

        match client_request(&sock, DaemonRequest::Identity)
            .await
            .unwrap()
        {
            DaemonResponse::Identity {
                device_id,
                fingerprint,
            } => {
                assert_eq!(device_id.len(), 64);
                assert_eq!(fingerprint.len(), 64);
            }
            other => panic!("expected Identity, got {other:?}"),
        }

        match client_request(&sock, DaemonRequest::Status).await.unwrap() {
            DaemonResponse::Status {
                auth_enforced,
                authorized_count,
                ..
            } => {
                assert!(!auth_enforced);
                assert_eq!(authorized_count, 0);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn control_trust_management() {
        let dir = tempfile::tempdir().unwrap();
        let (sock, _state) = spawn_test_daemon(dir.path()).await;
        let id = "b".repeat(64);

        // Initially empty.
        match client_request(&sock, DaemonRequest::ListTrust)
            .await
            .unwrap()
        {
            DaemonResponse::Trust { devices } => assert!(devices.is_empty()),
            other => panic!("expected Trust, got {other:?}"),
        }

        // Add → changed=true; add again → changed=false.
        for expect in [true, false] {
            match client_request(
                &sock,
                DaemonRequest::AddTrust {
                    device_id: id.clone(),
                },
            )
            .await
            .unwrap()
            {
                DaemonResponse::TrustChanged { changed } => assert_eq!(changed, expect),
                other => panic!("expected TrustChanged, got {other:?}"),
            }
        }

        // Now listed and auth is enforced.
        match client_request(&sock, DaemonRequest::Status).await.unwrap() {
            DaemonResponse::Status {
                auth_enforced,
                authorized_count,
                ..
            } => {
                assert!(auth_enforced);
                assert_eq!(authorized_count, 1);
            }
            other => panic!("expected Status, got {other:?}"),
        }

        // Remove → changed=true.
        match client_request(&sock, DaemonRequest::RemoveTrust { device_id: id })
            .await
            .unwrap()
        {
            DaemonResponse::TrustChanged { changed } => assert!(changed),
            other => panic!("expected TrustChanged, got {other:?}"),
        }
    }
}
