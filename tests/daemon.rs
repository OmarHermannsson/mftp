//! Daemon lifecycle integration tests (Unix-only — the control socket is a UDS).
//!
//! These exercise the real `Daemon::bind` / `Daemon::serve` wiring end-to-end:
//! the network receiver and control socket come up together on ephemeral
//! addresses with an isolated (temp) config dir, a real authorized transfer is
//! served, an unauthorized peer is rejected without taking the daemon down, and
//! a shutdown signal makes `serve` return gracefully and clean up its socket.
//!
//! Unlike the control-socket unit tests in `src/daemon/mod.rs`, this drives the
//! full daemon serve loop (router + auth + control) the production `run` uses.

#![cfg(unix)]

use std::time::Duration;

use mftp::daemon::{client_request, Daemon, DaemonOptions, DaemonRequest, DaemonResponse};
use mftp::transfer::receiver::Server;
use mftp::transfer::sender::{self, ForcedTransport, SendConfig};
use tempfile::TempDir;
use tokio::sync::oneshot;

fn make_file(dir: &std::path::Path, name: &str, size: usize) -> std::path::PathBuf {
    let path = dir.join(name);
    let data: Vec<u8> = (0..size)
        .map(|i| {
            let x = (i as u64)
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (x >> 56) as u8
        })
        .collect();
    std::fs::write(&path, &data).expect("write test file");
    path
}

/// Send config for a sender presenting `identity`, pinned to the daemon's
/// `fingerprint`, over QUIC (no TCP fallback — auth only applies on QUIC).
fn auth_send_config(fingerprint: String, identity: mftp::identity::Identity) -> SendConfig {
    SendConfig {
        streams: Some(2),
        chunk_size: Some(256 * 1024),
        compress: false,
        compress_level: 3,
        trusted_fingerprint: Some(fingerprint),
        trusted_device: None,
        client_identity: Some(identity),
        forced_transport: Some(ForcedTransport::Quic),
        tcp_rtt_threshold: Duration::ZERO,
        fec: None,
        parallel_reads: false,
        paths: 1,
        recursive: false,
        preserve: false,
    }
}

/// Bring up a daemon on ephemeral addresses with an isolated config dir, no LAN
/// discovery and no HTTP.
async fn bind_test_daemon(config_dir: &TempDir, output_dir: &TempDir) -> Daemon {
    Daemon::bind(DaemonOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        output_dir: output_dir.path().to_owned(),
        socket_path: config_dir.path().join("mftpd.sock"),
        config_dir: config_dir.path().to_owned(),
        announce_name: None,
        http: None,
    })
    .await
    .expect("daemon binds")
}

/// Spawn `daemon.serve(..)` and return the join handle plus a trigger that makes
/// it shut down gracefully.
fn spawn_serve(
    daemon: Daemon,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (tx, rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        daemon
            .serve(async move {
                let _ = rx.await;
            })
            .await
    });
    (tx, handle)
}

#[tokio::test]
async fn daemon_starts_serves_transfer_and_shuts_down_gracefully() -> anyhow::Result<()> {
    let dcfg = TempDir::new()?;
    let out = TempDir::new()?;
    let scfg = TempDir::new()?;
    let send_dir = TempDir::new()?;

    // Authorize the sender's DeviceId in the daemon's config dir *before* bind,
    // so auth is enforced against it.
    let sender_id = mftp::identity::load_or_create_in(scfg.path())?;
    mftp::identity::add_authorized_in(dcfg.path(), &sender_id.device_id)?;

    let daemon = bind_test_daemon(&dcfg, &out).await;
    let addr = daemon.local_addr();
    let fingerprint = daemon.fingerprint().to_owned();
    let daemon_device = daemon.device_id().to_owned();
    let socket = daemon.control_socket().to_owned();

    let (shutdown_tx, serve) = spawn_serve(daemon);

    // ── Control plane is up and reports the expected state. ───────────────────
    assert!(matches!(
        client_request(&socket, DaemonRequest::Ping).await?,
        DaemonResponse::Pong
    ));
    match client_request(&socket, DaemonRequest::Identity).await? {
        DaemonResponse::Identity { device_id, .. } => {
            assert_eq!(device_id, daemon_device, "control identity matches daemon")
        }
        other => panic!("expected Identity, got {other:?}"),
    }
    match client_request(&socket, DaemonRequest::Status).await? {
        DaemonResponse::Status {
            auth_enforced,
            authorized_count,
            ..
        } => {
            assert!(auth_enforced, "auth should be enforced");
            assert_eq!(authorized_count, 1);
        }
        other => panic!("expected Status, got {other:?}"),
    }

    // ── An authorized sender transfers a file through the daemon. ─────────────
    let src = make_file(send_dir.path(), "payload.bin", 512 * 1024);
    sender::send(src.clone(), addr, auth_send_config(fingerprint, sender_id)).await?;
    let received = out.path().join("payload.bin");
    assert_eq!(
        std::fs::read(&src)?,
        std::fs::read(&received)?,
        "received file matches"
    );

    // ── Graceful shutdown: serve returns Ok and removes the control socket. ───
    shutdown_tx.send(()).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), serve)
        .await
        .expect("serve returns promptly after shutdown")
        .expect("serve task did not panic")
        .expect("serve returns Ok on graceful shutdown");
    assert!(
        !socket.exists(),
        "control socket file should be removed on shutdown"
    );
    Ok(())
}

#[tokio::test]
async fn daemon_rejects_unauthorized_sender_and_keeps_serving() -> anyhow::Result<()> {
    let dcfg = TempDir::new()?;
    let out = TempDir::new()?;
    let scfg = TempDir::new()?;
    let send_dir = TempDir::new()?;

    // Authorize *some other* device, not our sender.
    mftp::identity::add_authorized_in(dcfg.path(), &"c".repeat(64))?;
    let unauthorized = mftp::identity::load_or_create_in(scfg.path())?;

    let daemon = bind_test_daemon(&dcfg, &out).await;
    let addr = daemon.local_addr();
    let fingerprint = daemon.fingerprint().to_owned();
    let socket = daemon.control_socket().to_owned();

    let (shutdown_tx, serve) = spawn_serve(daemon);

    // The unauthorized sender is rejected at the TLS handshake.
    let src = make_file(send_dir.path(), "nope.bin", 256 * 1024);
    let result = sender::send(src, addr, auth_send_config(fingerprint, unauthorized)).await;
    assert!(result.is_err(), "unauthorized sender must be rejected");

    // The daemon survived the rejection: the control socket still answers.
    assert!(matches!(
        client_request(&socket, DaemonRequest::Ping).await?,
        DaemonResponse::Pong
    ));

    shutdown_tx.send(()).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), serve)
        .await
        .expect("serve returns after shutdown")
        .expect("serve task did not panic")
        .expect("serve returns Ok");
    Ok(())
}

/// `bind` should fail (rather than silently rebinding) when the network address
/// is already taken — a basic startup-error path.
#[tokio::test]
async fn daemon_bind_fails_on_busy_address() -> anyhow::Result<()> {
    let out = TempDir::new()?;
    let cfg = TempDir::new()?;

    // Occupy a port with a plain QUIC server, then try to bind a daemon to it.
    // `occupier` stays in scope (endpoint bound) through the assertion.
    let occupier = Server::bind("127.0.0.1:0".parse()?, out.path().to_owned())?;
    let busy = occupier.local_addr;

    let result = Daemon::bind(DaemonOptions {
        bind: busy,
        output_dir: out.path().to_owned(),
        socket_path: cfg.path().join("mftpd.sock"),
        config_dir: cfg.path().to_owned(),
        announce_name: None,
        http: None,
    })
    .await;
    assert!(
        result.is_err(),
        "binding to an occupied address should fail"
    );
    drop(occupier);
    Ok(())
}
