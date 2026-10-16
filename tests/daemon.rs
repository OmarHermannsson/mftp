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
        encrypt_key: None,
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

    // ── Status reflects the completed transfer. ───────────────────────────────
    // The receiver increments the counter in its per-connection task just after
    // sending Complete, which may land a hair after the sender's send() returns,
    // so poll briefly rather than asserting immediately.
    let mut completed = 0;
    for _ in 0..40 {
        if let DaemonResponse::Status {
            transfers_completed,
            ..
        } = client_request(&socket, DaemonRequest::Status).await?
        {
            completed = transfers_completed;
            if completed >= 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(completed, 1, "Status should report one completed transfer");

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

/// SIGHUP-style reload: a device authorized *after* the daemon is already
/// serving can connect once the live allowlist is reloaded — no restart, no
/// rebinding of the endpoint.
#[tokio::test]
async fn daemon_reload_admits_newly_authorized_device() -> anyhow::Result<()> {
    let dcfg = TempDir::new()?;
    let out = TempDir::new()?;
    let scfg = TempDir::new()?;
    let send_dir = TempDir::new()?;

    // Start enforced against some unrelated device so auth is mandatory but our
    // sender is not yet allowed.
    mftp::identity::add_authorized_in(dcfg.path(), &"a".repeat(64))?;

    let daemon = bind_test_daemon(&dcfg, &out).await;
    let addr = daemon.local_addr();
    let fingerprint = daemon.fingerprint().to_owned();
    // Capture the reload handle *before* serve consumes the daemon.
    let reloader = daemon.reloader();
    let (shutdown_tx, serve) = spawn_serve(daemon);

    // Our sender's DeviceId is not authorized yet → rejected at the handshake.
    let sender_id = mftp::identity::load_or_create_in(scfg.path())?;
    let device = sender_id.device_id.clone();
    let src = make_file(send_dir.path(), "before.bin", 256 * 1024);
    let before = sender::send(src, addr, auth_send_config(fingerprint.clone(), sender_id)).await;
    assert!(before.is_err(), "sender is not authorized before reload");

    // Authorize the device on disk and reload (what SIGHUP does).
    mftp::identity::add_authorized_in(dcfg.path(), &device)?;
    assert_eq!(reloader.reload()?, 2, "reload sees both authorized devices");

    // The same device now completes a transfer through the running daemon.
    let sender_id2 = mftp::identity::load_or_create_in(scfg.path())?;
    let src2 = make_file(send_dir.path(), "after.bin", 256 * 1024);
    sender::send(
        src2.clone(),
        addr,
        auth_send_config(fingerprint, sender_id2),
    )
    .await?;
    assert_eq!(
        std::fs::read(&src2)?,
        std::fs::read(out.path().join("after.bin"))?,
        "received file matches after reload"
    );

    shutdown_tx.send(()).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), serve)
        .await
        .expect("serve returns after shutdown")
        .expect("serve task did not panic")
        .expect("serve returns Ok");
    Ok(())
}

/// SIGHUP-style reload also re-applies ACL routing: a per-peer output-subdir
/// change on disk takes effect for the next transfer without a restart.
#[tokio::test]
async fn daemon_reload_applies_acl_routing_change() -> anyhow::Result<()> {
    use mftp::service::acl::{Acl, PeerPolicy};

    let dcfg = TempDir::new()?;
    let out = TempDir::new()?;
    let scfg = TempDir::new()?;
    let send_dir = TempDir::new()?;

    // Initial ACL: the sender's files route into "first".
    let sender_id = mftp::identity::load_or_create_in(scfg.path())?;
    let device = sender_id.device_id.clone();
    let mut acl = Acl::default();
    acl.set_peer(
        &device,
        PeerPolicy {
            output_subdir: "first".into(),
            quota_bytes: None,
        },
    );
    acl.save(dcfg.path())?;

    let daemon = bind_test_daemon(&dcfg, &out).await;
    let addr = daemon.local_addr();
    let fingerprint = daemon.fingerprint().to_owned();
    let reloader = daemon.reloader();
    let (shutdown_tx, serve) = spawn_serve(daemon);

    // First transfer lands under the "first" tenant subdir.
    let src1 = make_file(send_dir.path(), "one.bin", 256 * 1024);
    sender::send(
        src1.clone(),
        addr,
        auth_send_config(fingerprint.clone(), sender_id),
    )
    .await?;
    assert_eq!(
        std::fs::read(&src1)?,
        std::fs::read(out.path().join("first").join("one.bin"))?,
        "first transfer routes to the original subdir"
    );

    // Re-point the same peer at "second" on disk and reload.
    let mut acl2 = Acl::default();
    acl2.set_peer(
        &device,
        PeerPolicy {
            output_subdir: "second".into(),
            quota_bytes: None,
        },
    );
    acl2.save(dcfg.path())?;
    reloader.reload()?;

    // The next transfer routes to the new subdir — no restart.
    let sender_id2 = mftp::identity::load_or_create_in(scfg.path())?;
    let src2 = make_file(send_dir.path(), "two.bin", 256 * 1024);
    sender::send(
        src2.clone(),
        addr,
        auth_send_config(fingerprint, sender_id2),
    )
    .await?;
    assert_eq!(
        std::fs::read(&src2)?,
        std::fs::read(out.path().join("second").join("two.bin"))?,
        "after reload the transfer routes to the updated subdir"
    );

    shutdown_tx.send(()).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), serve)
        .await
        .expect("serve returns after shutdown")
        .expect("serve task did not panic")
        .expect("serve returns Ok");
    Ok(())
}

/// Open mode (no authorized devices): a sender presenting no client identity
/// must still connect — the always-installed verifier must not make client auth
/// mandatory when the allowlist is empty.
#[tokio::test]
async fn daemon_open_mode_accepts_sender_without_identity() -> anyhow::Result<()> {
    let dcfg = TempDir::new()?; // empty: no authorized_devices → open
    let out = TempDir::new()?;
    let send_dir = TempDir::new()?;

    let daemon = bind_test_daemon(&dcfg, &out).await;
    let addr = daemon.local_addr();
    let fingerprint = daemon.fingerprint().to_owned();
    let socket = daemon.control_socket().to_owned();
    let (shutdown_tx, serve) = spawn_serve(daemon);

    match client_request(&socket, DaemonRequest::Status).await? {
        DaemonResponse::Status { auth_enforced, .. } => {
            assert!(!auth_enforced, "open daemon should not enforce auth")
        }
        other => panic!("expected Status, got {other:?}"),
    }

    // Sender with no client identity (the common case) over QUIC.
    let src = make_file(send_dir.path(), "open.bin", 256 * 1024);
    let cfg = SendConfig {
        streams: Some(2),
        chunk_size: Some(256 * 1024),
        compress: false,
        compress_level: 3,
        trusted_fingerprint: Some(fingerprint),
        trusted_device: None,
        client_identity: None,
        forced_transport: Some(ForcedTransport::Quic),
        tcp_rtt_threshold: Duration::ZERO,
        fec: None,
        parallel_reads: false,
        paths: 1,
        recursive: false,
        preserve: false,
    };
    sender::send(src.clone(), addr, cfg).await?;
    assert_eq!(
        std::fs::read(&src)?,
        std::fs::read(out.path().join("open.bin"))?,
        "open-mode transfer without client identity succeeds"
    );

    shutdown_tx.send(()).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), serve)
        .await
        .expect("serve returns after shutdown")
        .expect("serve task did not panic")
        .expect("serve returns Ok");
    Ok(())
}

/// A peer already at/over its ACL byte quota is rejected at connect time, a
/// transfer bigger than the remaining quota is refused after its manifest, and
/// a peer under quota is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_enforces_acl_quota_at_connect() -> anyhow::Result<()> {
    use mftp::service::acl::{Acl, PeerPolicy};

    let dcfg = TempDir::new()?;
    let out = TempDir::new()?;
    let scfg = TempDir::new()?;
    let send_dir = TempDir::new()?;

    let sender_id = mftp::identity::load_or_create_in(scfg.path())?;
    let mut acl = Acl::default();
    acl.set_peer(
        &sender_id.device_id,
        PeerPolicy {
            output_subdir: "tenant".into(),
            quota_bytes: Some(1024 * 1024),
        },
    );
    acl.save(dcfg.path())?;

    let daemon = bind_test_daemon(&dcfg, &out).await;
    let addr = daemon.local_addr();
    let fingerprint = daemon.fingerprint().to_owned();
    let (shutdown_tx, serve) = spawn_serve(daemon);

    // Under quota: served.
    let src = make_file(send_dir.path(), "ok.bin", 256 * 1024);
    sender::send(
        src,
        addr,
        auth_send_config(fingerprint.clone(), sender_id.clone()),
    )
    .await?;
    assert!(out.path().join("tenant/ok.bin").exists());

    // Under quota now, but this transfer alone would overshoot it → refused
    // once the manifest reveals its size.
    let big = make_file(send_dir.path(), "big.bin", 2 * 1024 * 1024);
    let too_big = sender::send(
        big,
        addr,
        auth_send_config(fingerprint.clone(), sender_id.clone()),
    )
    .await;
    assert!(
        too_big.is_err(),
        "transfer larger than remaining quota must be refused"
    );
    assert!(!out.path().join("tenant/big.bin").exists());

    // Fill the tenant dir past the quota → the next connection is refused.
    std::fs::write(out.path().join("tenant/filler.bin"), vec![0u8; 1024 * 1024])?;
    let src2 = make_file(send_dir.path(), "over.bin", 64 * 1024);
    let over = sender::send(src2, addr, auth_send_config(fingerprint, sender_id)).await;
    assert!(over.is_err(), "over-quota peer must be rejected");
    assert!(!out.path().join("tenant/over.bin").exists());

    shutdown_tx.send(()).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), serve)
        .await
        .expect("serve returns after shutdown")
        .expect("serve task did not panic")
        .expect("serve returns Ok");
    Ok(())
}

/// A malformed `acl.toml` must make startup fail (fail closed) instead of being
/// read as an empty ACL — which would leave the daemon open to any sender.
#[tokio::test]
async fn daemon_bind_fails_on_malformed_acl() -> anyhow::Result<()> {
    let dcfg = TempDir::new()?;
    let out = TempDir::new()?;
    std::fs::write(dcfg.path().join("acl.toml"), "peers = [this is not toml")?;
    let result = Daemon::bind(DaemonOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        output_dir: out.path().to_owned(),
        socket_path: dcfg.path().join("mftpd.sock"),
        config_dir: dcfg.path().to_owned(),
        announce_name: None,
        http: None,
        encrypt_key: None,
    })
    .await;
    assert!(
        result.is_err(),
        "malformed acl.toml must be a startup error"
    );
    Ok(())
}

/// A reload that hits a malformed policy keeps the previous one in force, and
/// revoking the last authorized device keeps the daemon enforcing (deny-all)
/// rather than flipping it to open mode.
#[tokio::test]
async fn daemon_reload_fails_closed() -> anyhow::Result<()> {
    let dcfg = TempDir::new()?;
    let out = TempDir::new()?;
    let id = "a".repeat(64);
    mftp::identity::add_authorized_in(dcfg.path(), &id)?;

    let daemon = bind_test_daemon(&dcfg, &out).await;
    let addr = daemon.local_addr();
    let fingerprint = daemon.fingerprint().to_owned();
    let socket = daemon.control_socket().to_owned();
    let reloader = daemon.reloader();
    let (shutdown_tx, serve) = spawn_serve(daemon);

    let status = |socket: std::path::PathBuf| async move {
        match client_request(&socket, DaemonRequest::Status).await? {
            DaemonResponse::Status {
                auth_enforced,
                authorized_count,
                ..
            } => anyhow::Ok((auth_enforced, authorized_count)),
            other => panic!("expected Status, got {other:?}"),
        }
    };
    assert_eq!(status(socket.clone()).await?, (true, 1));

    // Broken ACL on disk → reload errors, previous policy is kept.
    std::fs::write(dcfg.path().join("acl.toml"), "garbage = = =")?;
    assert!(reloader.reload().is_err(), "malformed acl must fail reload");
    assert_eq!(status(socket.clone()).await?, (true, 1), "previous kept");
    std::fs::remove_file(dcfg.path().join("acl.toml"))?;

    // Remove the last device → still enforced, with nobody authorized.
    match client_request(
        &socket,
        DaemonRequest::RemoveTrust {
            device_id: id.clone(),
        },
    )
    .await?
    {
        DaemonResponse::TrustChanged { changed } => assert!(changed),
        other => panic!("expected TrustChanged, got {other:?}"),
    }
    reloader.reload()?;
    assert_eq!(
        status(socket.clone()).await?,
        (true, 0),
        "deny-all, not open"
    );

    // A sender with no identity is now rejected (not admitted as "open").
    let send_dir = TempDir::new()?;
    let src = make_file(send_dir.path(), "denied.bin", 64 * 1024);
    let mut cfg = auth_send_config(
        fingerprint,
        mftp::identity::load_or_create_in(TempDir::new()?.path())?,
    );
    cfg.client_identity = None;
    assert!(
        sender::send(src, addr, cfg).await.is_err(),
        "deny-all daemon must reject"
    );

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
        encrypt_key: None,
    })
    .await;
    assert!(
        result.is_err(),
        "binding to an occupied address should fail"
    );
    drop(occupier);
    Ok(())
}

/// Every received transfer is recorded in the persistent queue, and with
/// `encrypt_key` each received file is stored encrypted (`<name>.enc`, no
/// plaintext left) and decrypts back to the original.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_records_jobs_and_encrypts_at_rest() -> anyhow::Result<()> {
    use mftp::service::queue::{JobState, Queue};

    let dcfg = TempDir::new()?;
    let out = TempDir::new()?;
    let scfg = TempDir::new()?;
    let send_dir = TempDir::new()?;
    let sender_id = mftp::identity::load_or_create_in(scfg.path())?;
    mftp::identity::add_authorized_in(dcfg.path(), &sender_id.device_id)?;

    let key = [0x5au8; 32];
    let daemon = Daemon::bind(DaemonOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        output_dir: out.path().to_owned(),
        socket_path: dcfg.path().join("mftpd.sock"),
        config_dir: dcfg.path().to_owned(),
        announce_name: None,
        http: None,
        encrypt_key: Some(key),
    })
    .await?;
    assert!(daemon.encrypts_at_rest());
    let addr = daemon.local_addr();
    let fingerprint = daemon.fingerprint().to_owned();
    let (shutdown_tx, serve) = spawn_serve(daemon);

    let src = make_file(send_dir.path(), "secret.bin", 700 * 1024);
    sender::send(
        src.clone(),
        addr,
        auth_send_config(fingerprint, sender_id.clone()),
    )
    .await?;

    // Encryption finishes just after the sender's Complete ack; wait for the job.
    let job = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(j) = Queue::load(dcfg.path())
                .ok()
                .and_then(|q| q.jobs().first().cloned())
                .filter(|j| j.state != JobState::Active)
            {
                return j;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("job finishes");
    assert_eq!(job.state, JobState::Completed, "{job:?}");
    assert_eq!(job.peer, sender_id.device_id);
    assert_eq!(job.what, "secret.bin");
    assert_eq!(job.total_bytes, 700 * 1024);
    assert_eq!(job.bytes_done, 700 * 1024);

    assert!(
        !out.path().join("secret.bin").exists(),
        "no plaintext at rest"
    );
    let enc = out.path().join("secret.bin.enc");
    let plain = send_dir.path().join("roundtrip.bin");
    mftp::service::encrypt::decrypt_file(&key, &enc, &plain)?;
    assert_eq!(std::fs::read(&plain)?, std::fs::read(&src)?);

    shutdown_tx.send(()).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), serve)
        .await
        .expect("serve returns after shutdown")
        .expect("serve task did not panic")
        .expect("serve returns Ok");
    Ok(())
}
