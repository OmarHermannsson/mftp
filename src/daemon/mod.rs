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
use crate::transfer::receiver::Route;

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
    /// The *effective* authorized set currently applied by the daemon (from
    /// `acl.toml` or `authorized_devices`), whether it is enforced, and where it
    /// comes from.
    Trust {
        devices: Vec<String>,
        enforced: bool,
        source: AuthSource,
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

/// Where the daemon's effective authorized-device set comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthSource {
    /// Neither `acl.toml` nor `authorized_devices` exists: any sender may
    /// connect (classic receiver behaviour).
    Open,
    /// The plain `authorized_devices` allowlist (M4).
    Allowlist,
    /// The per-peer `acl.toml` policy (M8).
    Acl,
}

/// The effective authorization policy, loaded from the config dir in one pass.
///
/// **Fail-closed rules**: a malformed or unreadable `acl.toml` /
/// `authorized_devices` is an error (never "empty → open"), and an
/// authorization file that *exists* keeps the daemon enforcing even when it
/// lists no devices — removing the last device denies everyone instead of
/// silently re-opening the receiver. Open mode requires that neither file
/// exists.
#[derive(Debug, Clone)]
pub struct AuthPolicy {
    pub acl: crate::service::acl::Acl,
    /// Effective authorized DeviceIds (normalized, sorted).
    pub authorized: Vec<String>,
    pub source: AuthSource,
}

impl AuthPolicy {
    /// Load the policy from `config_dir`: the ACL's peers if `acl.toml` has any,
    /// else the `authorized_devices` allowlist, else open mode.
    pub fn load(config_dir: &Path) -> Result<AuthPolicy> {
        let acl = crate::service::acl::Acl::load(config_dir)?;
        if !acl.is_empty() {
            let authorized = acl.authorized_ids();
            return Ok(AuthPolicy {
                acl,
                authorized,
                source: AuthSource::Acl,
            });
        }
        let acl_file_exists = config_dir.join("acl.toml").symlink_metadata().is_ok();
        let (mut authorized, source) = match crate::identity::load_authorized_opt_in(config_dir)? {
            Some(ids) => (ids, AuthSource::Allowlist),
            None if acl_file_exists => (Vec::new(), AuthSource::Acl),
            None => (Vec::new(), AuthSource::Open),
        };
        authorized.sort();
        authorized.dedup();
        Ok(AuthPolicy {
            acl,
            authorized,
            source,
        })
    }

    /// Whether mutual-TLS DeviceId auth is enforced.
    pub fn enforced(&self) -> bool {
        self.source != AuthSource::Open
    }

    /// The id set handed to the TLS verifier. The verifier treats an empty set
    /// as *open*, so an enforcing policy with no devices is expressed as a
    /// sentinel that no real (hex) DeviceId can ever match — deny-all.
    fn verifier_ids(&self) -> Vec<String> {
        if self.enforced() && self.authorized.is_empty() {
            vec![DENY_ALL_SENTINEL.to_string()]
        } else {
            self.authorized.clone()
        }
    }
}

/// Allowlist entry that matches no DeviceId (DeviceIds are 64 hex chars), used
/// to keep the verifier enforcing when the authorized set is empty.
const DENY_ALL_SENTINEL: &str = "!deny-all";

/// Shared daemon state behind the control socket.
pub struct DaemonState {
    /// Config directory holding identity + authorized_devices.
    pub config_dir: PathBuf,
    /// Human-readable address the network receiver is bound to.
    pub listening_on: String,
    /// Count of completed transfers (for Status). Shared with the network
    /// receiver (see [`crate::transfer::receiver::Server::count_completions_into`]),
    /// which increments it as transfers complete.
    pub transfers_completed: Arc<AtomicU64>,
    /// Live authorized-device set the TLS verifier consults.
    allowlist: crate::net::connection::ReloadableAllowlist,
    /// Live per-peer routing/quota policy the connection router consults.
    acl: crate::service::acl::ReloadableAcl,
    /// The currently applied policy's source + effective device set.
    applied: std::sync::RwLock<(AuthSource, Vec<String>)>,
    /// Serializes daemon-trust edits (read-modify-write of authorized_devices +
    /// reload) so concurrent control requests cannot lose an update.
    trust_edit: std::sync::Mutex<()>,
}

impl DaemonState {
    /// Load the authorization policy from `config_dir` (a malformed/unreadable
    /// policy is an error) and build the live allowlist + ACL handles from it.
    pub fn load(config_dir: PathBuf, listening_on: String) -> Result<Self> {
        Self::load_with_counter(config_dir, listening_on, Arc::new(AtomicU64::new(0)))
    }

    /// Like [`load`](Self::load), but shares an existing completed-transfer
    /// counter (so the network receiver and the Status reply observe the same
    /// value).
    pub fn load_with_counter(
        config_dir: PathBuf,
        listening_on: String,
        transfers_completed: Arc<AtomicU64>,
    ) -> Result<Self> {
        let policy = AuthPolicy::load(&config_dir)?;
        Ok(DaemonState {
            config_dir,
            listening_on,
            transfers_completed,
            allowlist: crate::net::connection::ReloadableAllowlist::new(policy.verifier_ids()),
            acl: crate::service::acl::ReloadableAcl::new(policy.acl.clone()),
            applied: std::sync::RwLock::new((policy.source, policy.authorized)),
            trust_edit: std::sync::Mutex::new(()),
        })
    }

    /// Re-read the policy from disk and swap it into the live verifier + router.
    /// On a load error the previous policy stays in force and the error is
    /// returned. Returns the new authorized count.
    pub fn reload(&self) -> Result<usize> {
        let policy = AuthPolicy::load(&self.config_dir)?;
        let n = policy.authorized.len();
        self.allowlist.replace(policy.verifier_ids());
        self.acl.replace(policy.acl);
        *self.applied.write().expect("auth state lock poisoned") =
            (policy.source, policy.authorized);
        Ok(n)
    }

    /// Source of the currently applied authorization policy.
    pub fn auth_source(&self) -> AuthSource {
        self.applied.read().expect("auth state lock poisoned").0
    }

    /// The currently applied effective authorized DeviceIds.
    pub fn authorized_devices(&self) -> Vec<String> {
        self.applied
            .read()
            .expect("auth state lock poisoned")
            .1
            .clone()
    }

    /// Whether the live TLS verifier is enforcing DeviceId auth.
    pub fn auth_enforced(&self) -> bool {
        !self.allowlist.is_empty()
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
            devices: state.authorized_devices(),
            enforced: state.auth_enforced(),
            source: state.auth_source(),
        },
        DaemonRequest::AddTrust { device_id } => edit_trust(state, |dir| {
            crate::identity::add_authorized_in(dir, &device_id)
        }),
        DaemonRequest::RemoveTrust { device_id } => edit_trust(state, |dir| {
            crate::identity::remove_authorized_in(dir, &device_id)
        }),
        DaemonRequest::Status => DaemonResponse::Status {
            listening_on: state.listening_on.clone(),
            auth_enforced: state.auth_enforced(),
            authorized_count: state.authorized_devices().len(),
            transfers_completed: state.transfers_completed.load(Ordering::Relaxed),
        },
    }
}

/// Apply a daemon-trust edit to `authorized_devices` and immediately reload it
/// into the live verifier (the same operation as SIGHUP), so the change takes
/// effect for the next connection without a restart.
///
/// When `acl.toml` governs authorization, editing `authorized_devices` would
/// have no effect, so the request is refused with an explanatory error instead
/// of silently succeeding.
fn edit_trust(state: &DaemonState, edit: impl FnOnce(&Path) -> Result<bool>) -> DaemonResponse {
    let _guard = state.trust_edit.lock().expect("trust edit lock poisoned");
    let result = (|| -> Result<bool> {
        // Re-check against disk, not only the applied state: an ACL added since
        // the last reload also governs.
        if state.auth_source() == AuthSource::Acl
            || AuthPolicy::load(&state.config_dir)?.source == AuthSource::Acl
        {
            anyhow::bail!(
                "authorization is governed by {} — edit its [peers] and reload the daemon \
                 (SIGHUP) instead of using daemon-trust",
                state.config_dir.join("acl.toml").display()
            );
        }
        let changed = edit(&state.config_dir)?;
        state
            .reload()
            .context("trust file updated but reloading it into the daemon failed")?;
        Ok(changed)
    })();
    match result {
        Ok(changed) => DaemonResponse::TrustChanged { changed },
        Err(e) => DaemonResponse::Error {
            message: format!("{e:#}"),
        },
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

/// Bind the control socket.
///
/// * Missing parent directories are created with mode 0700.
/// * An existing path is only replaced if it is a *stale* socket: if a live
///   daemon answers on it, this fails with "already running" instead of
///   stealing its socket; a non-socket file there is never deleted.
/// * The socket is chmod'ed to 0600 after bind — the control plane can add
///   trusted devices, so only the owning user may connect.
pub fn bind_control_socket(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_socket() => {
            // A leftover socket from a crashed run makes bind() fail with
            // EADDRINUSE even though nothing listens; but a *live* daemon must
            // not have its socket pulled out from under it.
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                anyhow::bail!(
                    "a daemon is already running on control socket {} \
                     (stop it first, or pass a different --socket)",
                    path.display()
                );
            }
            std::fs::remove_file(path)
                .with_context(|| format!("remove stale socket {}", path.display()))?;
        }
        Ok(_) => anyhow::bail!(
            "{} exists and is not a socket; refusing to replace it",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    }
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(listener)
}

/// Construction options for a [`Daemon`].
///
/// Unlike [`run`], the config directory is injected rather than resolved from
/// `$HOME`, and LAN discovery is opt-in — so the daemon can be brought up
/// in-process on an ephemeral port (`127.0.0.1:0`) with isolated state for
/// tests.
pub struct DaemonOptions {
    pub bind: std::net::SocketAddr,
    pub output_dir: PathBuf,
    pub socket_path: PathBuf,
    /// Directory holding identity + authorized_devices/acl.toml.
    pub config_dir: PathBuf,
    /// `Some(name)` announces on the LAN via multicast discovery (best-effort);
    /// `None` disables it (the default for tests, which want no multicast).
    pub announce_name: Option<String>,
    pub http: Option<std::net::SocketAddr>,
}

/// A fully-bound daemon: the network receiver and control socket (plus optional
/// HTTP dashboard and LAN discovery) are listening, but no accept loop is
/// running yet.  Inspect [`local_addr`](Daemon::local_addr) etc., then call
/// [`serve`](Daemon::serve) to run until a shutdown signal fires.
pub struct Daemon {
    server: crate::transfer::receiver::Server,
    control: UnixListener,
    /// Shared state, including the live allowlist + ACL that SIGHUP reloads.
    state: Arc<DaemonState>,
    output_dir: PathBuf,
    socket_path: PathBuf,
    device_id: String,
    fingerprint: String,
    local_addr: std::net::SocketAddr,
    /// Real address the HTTP dashboard bound to, if enabled.
    http_addr: Option<std::net::SocketAddr>,
    /// Whether the LAN discovery responder came up.
    announced: bool,
    /// Background tasks (discovery, HTTP) aborted on shutdown.
    background: Vec<tokio::task::JoinHandle<()>>,
}

impl Daemon {
    /// Bind the network receiver, control socket, and optional HTTP/discovery,
    /// using the persistent device identity in `opts.config_dir`.
    ///
    /// When an authorization file exists (acl.toml or authorized_devices — see
    /// [`AuthPolicy`]), mutual-TLS DeviceId auth is enforced and only QUIC is
    /// served (the TCP path does not present client certs, so serving it under
    /// auth would be a bypass). A malformed or unreadable authorization file is
    /// a hard error: the daemon refuses to start rather than fail open.
    pub async fn bind(opts: DaemonOptions) -> Result<Daemon> {
        let id = crate::identity::load_or_create_in(&opts.config_dir)?;

        // M8: an ACL (acl.toml), if present, supplies the authorized peers and
        // their per-tenant output dirs/quotas. Otherwise fall back to the M4
        // plain allowlist (authorized_devices).
        //
        // The verifier reads the allowlist and the router reads the ACL on every
        // connection, so a SIGHUP reload (see `serve`) swaps both in place and
        // takes effect for subsequent connections — new trust *and* new per-peer
        // routing/quotas — without rebinding. One counter is shared by the
        // network receiver (which increments it per completed transfer) and
        // DaemonState (which reports it in Status); `listening_on` is filled in
        // once the endpoint is bound.
        let completed = Arc::new(AtomicU64::new(0));
        let mut state = DaemonState::load_with_counter(
            opts.config_dir.clone(),
            String::new(),
            Arc::clone(&completed),
        )
        .context("load daemon authorization policy")?;

        let key = crate::net::connection::make_private_key(id.key_bytes.clone())?;
        let server = crate::transfer::receiver::Server::bind_with_reloadable_auth(
            opts.bind,
            opts.output_dir.clone(),
            id.cert.clone(),
            key,
            id.fingerprint.clone(),
            state.allowlist.clone(),
        )?
        .count_completions_into(completed);
        let local_addr = server.local_addr;
        let listening_on = local_addr.to_string();
        state.listening_on = listening_on.clone();

        let mut background = Vec::new();

        // LAN discovery responder (M5): best-effort — if the host can't join the
        // multicast group the daemon still serves normally.
        let mut announced = false;
        if let Some(name) = opts.announce_name {
            match crate::discovery::bind_responder() {
                Ok(sock) => {
                    announced = true;
                    let device = id.device_id.clone();
                    background.push(tokio::spawn(async move {
                        let _ =
                            crate::discovery::respond_loop(sock, name, local_addr.port(), device)
                                .await;
                    }));
                }
                Err(e) => {
                    tracing::warn!("LAN discovery disabled (could not bind responder): {e:#}")
                }
            }
        }

        let control = bind_control_socket(&opts.socket_path)?;
        let state = Arc::new(state);

        // M8: optional HTTP status API + Web UI dashboard.
        let mut http_addr = None;
        if let Some(addr) = opts.http {
            let http_listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("bind HTTP dashboard on {addr}"))?;
            let bound = http_listener.local_addr()?;
            crate::service::http::warn_if_exposed(bound);
            http_addr = Some(bound);
            let auth_state = Arc::clone(&state);
            let http_state = Arc::new(crate::service::http::HttpState {
                config_dir: opts.config_dir.clone(),
                listening_on: listening_on.clone(),
                auth: Arc::new(move || crate::service::http::AuthView {
                    enforced: auth_state.auth_enforced(),
                    authorized_count: auth_state.authorized_devices().len(),
                }),
            });
            background.push(tokio::spawn(async move {
                let _ = crate::service::http::serve(http_listener, http_state).await;
            }));
        }

        Ok(Daemon {
            server,
            control,
            state,
            output_dir: opts.output_dir,
            socket_path: opts.socket_path,
            device_id: id.device_id,
            fingerprint: id.fingerprint,
            local_addr,
            http_addr,
            announced,
            background,
        })
    }

    /// Address the QUIC network receiver is bound to.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }
    /// This daemon's device certificate fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    /// This daemon's Ed25519 DeviceId.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    /// Path of the local control socket.
    pub fn control_socket(&self) -> &Path {
        &self.socket_path
    }
    /// Shared state behind the control socket (e.g. the completed-transfer count).
    pub fn state(&self) -> &Arc<DaemonState> {
        &self.state
    }

    /// A handle that reloads the authorized-device set *and* ACL from disk into
    /// the running receiver — the same operation SIGHUP performs.  Capture it
    /// before [`serve`](Daemon::serve) consumes the daemon to drive reloads
    /// programmatically (the production daemon drives it from SIGHUP instead).
    pub fn reloader(&self) -> Reloader {
        Reloader {
            state: Arc::clone(&self.state),
        }
    }

    /// Serve the network receiver and control socket until `shutdown` resolves
    /// (graceful) or a fatal serve error occurs.  On SIGHUP, reload the
    /// authorized-device set and ACL from disk into the running receiver and
    /// keep going.
    ///
    /// On return the control socket file is removed and background tasks
    /// (discovery, HTTP) are aborted.  Shutdown stops *accepting* immediately;
    /// in-flight transfers running in their own tasks are dropped (and are
    /// resumable on reconnect).
    pub async fn serve(self, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
        let Daemon {
            server,
            control,
            state,
            output_dir,
            socket_path,
            background,
            ..
        } = self;

        // Per-peer output routing (M8): with an ACL, each authorized peer's files
        // land in its own subdir (tenant isolation); without one, the shared root.
        // The router reads the *live* ACL on every connection, so a SIGHUP reload
        // changes routing/quotas for subsequent transfers.
        let acl_for_router = state.acl.clone();
        let output_root = output_dir.clone();
        let serve_fut = server.serve_with_router(move |peer| {
            // Snapshot what we need from the live ACL and drop the read lock
            // before touching the filesystem, so a slow directory walk never
            // blocks a SIGHUP reload (or other connections) on the lock.
            let routed = acl_for_router.with(|acl| -> Result<Option<_>> {
                if acl.is_empty() {
                    return Ok(None);
                }
                let device = peer.context("ACL enforced but peer presented no DeviceId")?;
                let dir = acl.output_dir_for(&output_root, device)?;
                let quota = acl.policy(device).and_then(|p| p.quota_bytes);
                Ok(Some((device.to_owned(), dir, quota)))
            })?;
            let Some((device, dir, quota)) = routed else {
                return Ok(Route::from(output_root.clone()));
            };
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("create tenant dir {}", dir.display()))?;
            // Enforce the peer's byte quota: reject a peer already at/over it
            // here, and hand the receiver the remaining budget so a transfer
            // larger than that is refused once its manifest (size) is known.
            // Concurrent transfers from one peer each see the same budget.
            let mut max_new_bytes = None;
            if let Some(limit) = quota {
                let used = run_blocking(|| dir_size_bytes(&dir));
                if used >= limit {
                    anyhow::bail!("{device} is at/over its quota ({used} of {limit} bytes used)");
                }
                max_new_bytes = Some(limit - used);
            }
            Ok(Route {
                output_dir: dir,
                max_new_bytes,
            })
        });

        let control_fut = serve_control(control, Arc::clone(&state));
        tokio::pin!(serve_fut);
        tokio::pin!(control_fut);
        tokio::pin!(shutdown);

        // SIGHUP triggers a reload of both the allowlist and the ACL; best-effort
        // to register the handler.
        let mut sighup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

        // Serve until one of the loops errors or shutdown fires; SIGHUP reloads
        // the live allowlist + ACL in place and continues.
        let result = loop {
            tokio::select! {
                r = &mut serve_fut => break r,
                r = &mut control_fut => break r,
                _ = &mut shutdown => break Ok(()),
                _ = wait_for_sighup(&mut sighup) => match state.reload() {
                    Ok(n) => tracing::info!("SIGHUP: reloaded {n} authorized device(s) + ACL"),
                    // Fail closed: a broken edit must not drop (or open) the
                    // authorization currently in force.
                    Err(e) => tracing::error!(
                        "SIGHUP: reload failed, keeping the previous authorization config: {e:#}"
                    ),
                },
            }
        };

        // Cleanup: abort background tasks and remove the control socket file so a
        // restart does not trip over a stale socket.
        for h in background {
            h.abort();
        }
        let _ = std::fs::remove_file(&socket_path);
        result
    }
}

/// A handle for reloading the daemon's authorized-device set and ACL from disk
/// into the running receiver (what SIGHUP does).  Obtain via [`Daemon::reloader`].
pub struct Reloader {
    state: Arc<DaemonState>,
}

impl Reloader {
    /// Re-read the authorized set + ACL from disk and apply both to the running
    /// receiver; returns the new authorized count. On error (malformed or
    /// unreadable policy) the previous policy stays in force.
    pub fn reload(&self) -> Result<usize> {
        self.state.reload()
    }
}

/// Await the next SIGHUP, or never (if the handler could not be registered).
async fn wait_for_sighup(sig: &mut Option<tokio::signal::unix::Signal>) {
    match sig {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Resolve when the process receives SIGINT (Ctrl-C) or SIGTERM, so the daemon
/// can shut down gracefully instead of being hard-killed.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("register SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

/// Run the daemon to completion: bind the receiver + control socket using the
/// persistent identity under the resolved config dir, print the startup banner,
/// and serve until SIGINT/SIGTERM.
pub async fn run(
    bind: std::net::SocketAddr,
    output_dir: PathBuf,
    socket_path: PathBuf,
    announce_name: String,
    http: Option<std::net::SocketAddr>,
) -> Result<()> {
    let config_dir =
        crate::identity::config_dir().context("cannot locate config dir ($HOME unset)")?;

    let daemon = Daemon::bind(DaemonOptions {
        bind,
        output_dir,
        socket_path: socket_path.clone(),
        config_dir,
        announce_name: Some(announce_name),
        http,
    })
    .await?;

    println!("mftpd listening on {} (QUIC)", daemon.local_addr());
    println!("Device ID: {}", daemon.device_id());
    println!("Fingerprint: {}", daemon.fingerprint());
    let state = daemon.state();
    if state.auth_enforced() {
        let mode = match state.auth_source() {
            AuthSource::Acl => "ACL",
            _ => "allowlist",
        };
        let n = state.authorized_devices().len();
        println!("Identity auth: ENFORCED via {mode} ({n} authorized device(s))");
        if n == 0 {
            println!(
                "  (no devices authorized — all senders are denied; delete the empty \
                 authorization file to run open)"
            );
        }
    } else {
        println!("Identity auth: open (add devices with `mftp daemon-trust add <id>`)");
    }
    if daemon.announced {
        println!("Discovery: announcing on the LAN");
    }
    println!("Control socket: {}", socket_path.display());
    if let Some(real) = daemon.http_addr {
        println!("Web UI / HTTP API: http://{real}/");
    }

    daemon.serve(shutdown_signal()).await
}

/// Run blocking filesystem work from inside the (synchronous) connection router
/// without stalling an async worker: on a multi-threaded runtime the current
/// worker is handed off via `block_in_place`; elsewhere (current-thread
/// runtimes, no runtime) the closure simply runs inline.
fn run_blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// Total size in bytes of all regular files under `dir` (0 if absent). Used for
/// per-peer quota enforcement.
fn dir_size_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            if let Ok(md) = entry.metadata() {
                total = total.saturating_add(md.len());
            }
        }
    }
    total
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
        let state =
            Arc::new(DaemonState::load(dir.to_owned(), "127.0.0.1:7777".to_string()).unwrap());
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = serve_control(listener, st).await;
        });
        (sock, state)
    }

    #[tokio::test]
    async fn control_socket_is_private_and_not_stolen() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("run/sub/mftpd.sock");
        let listener = bind_control_socket(&sock).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&sock), 0o600);
        assert_eq!(mode(sock.parent().unwrap()), 0o700);

        // A live listener → a second bind refuses instead of stealing.
        let err = bind_control_socket(&sock).unwrap_err();
        assert!(format!("{err:#}").contains("already running"), "{err:#}");

        // Once the listener is gone the stale socket is replaced.
        drop(listener);
        let _again = bind_control_socket(&sock).unwrap();

        // A regular file at the path is never deleted.
        let file = dir.path().join("not-a-socket");
        std::fs::write(&file, b"keep").unwrap();
        assert!(bind_control_socket(&file).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"keep");
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
            DaemonResponse::Trust { devices, .. } => assert!(devices.is_empty()),
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

        // Applied live (no reload needed): listed and auth is enforced.
        match client_request(&sock, DaemonRequest::ListTrust)
            .await
            .unwrap()
        {
            DaemonResponse::Trust {
                devices, enforced, ..
            } => {
                assert_eq!(devices, vec![id.clone()]);
                assert!(enforced);
            }
            other => panic!("expected Trust, got {other:?}"),
        }
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

        // Removing the last device keeps the daemon enforcing (deny-all).
        match client_request(&sock, DaemonRequest::Status).await.unwrap() {
            DaemonResponse::Status {
                auth_enforced,
                authorized_count,
                ..
            } => {
                assert!(auth_enforced, "removing the last device must not open");
                assert_eq!(authorized_count, 0);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn control_trust_refused_when_acl_governs() {
        use crate::service::acl::{Acl, PeerPolicy};
        let dir = tempfile::tempdir().unwrap();
        let peer = "c".repeat(64);
        let mut acl = Acl::default();
        acl.set_peer(
            &peer,
            PeerPolicy {
                output_subdir: "c".into(),
                quota_bytes: None,
            },
        );
        acl.save(dir.path()).unwrap();
        let (sock, _state) = spawn_test_daemon(dir.path()).await;

        // List reflects the effective (ACL) set.
        match client_request(&sock, DaemonRequest::ListTrust)
            .await
            .unwrap()
        {
            DaemonResponse::Trust {
                devices, source, ..
            } => {
                assert_eq!(devices, vec![peer]);
                assert_eq!(source, AuthSource::Acl);
            }
            other => panic!("expected Trust, got {other:?}"),
        }
        // Editing the allowlist is refused with a clear error.
        match client_request(
            &sock,
            DaemonRequest::AddTrust {
                device_id: "d".repeat(64),
            },
        )
        .await
        .unwrap()
        {
            DaemonResponse::Error { message } => assert!(message.contains("acl.toml")),
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
