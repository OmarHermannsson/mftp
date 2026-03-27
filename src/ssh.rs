//! SSH-assisted transfer: launch `mftp server` on the remote via SSH,
//! read the port/fingerprint handshake, then connect directly.
//!
//! If the direct connection fails (e.g. a firewall blocks the transfer port),
//! the sender falls back to routing data through an SSH port-forward tunnel,
//! which is available whenever SSH itself is available.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::transfer::sender::SendConfig;

// ── Destination parsing ───────────────────────────────────────────────────────

/// An SSH-style destination parsed from `[user@]host:/remote/path`.
pub struct SshDest {
    /// Passed directly to `ssh(1)`: `"user@host"` or `"host"`.
    pub user_host: String,
    /// Hostname component, used for DNS resolution of the direct connection.
    pub host: String,
    /// Remote filesystem path for the output directory.
    pub remote_path: String,
}

/// Try to parse `dest` as an SSH destination.
///
/// Returns `None` when `dest` looks like a direct `host:port` address —
/// specifically, when it contains no `@` and the portion after `:` is a
/// valid port number.
pub fn parse_ssh_dest(dest: &str) -> Option<SshDest> {
    let colon = dest.rfind(':')?;
    let before = &dest[..colon];
    let after = &dest[colon + 1..];

    // No '@' and the part after ':' is a port number → plain host:port address.
    if !before.contains('@') && after.parse::<u16>().is_ok() {
        return None;
    }

    let (user_host, host) = if let Some(at) = before.find('@') {
        (before.to_owned(), before[at + 1..].to_owned())
    } else {
        (before.to_owned(), before.to_owned())
    };

    Some(SshDest { user_host, host, remote_path: after.to_owned() })
}

// ── SSH launch + transfer ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ServerHandshake {
    port: u16,
    fingerprint: String,
}

/// RAII guard that kills a child process when dropped.
///
/// Used to ensure the remote `mftp server` (and the SSH multiplexer) are
/// always reaped, even when the transfer fails and the function returns early
/// via `?`.
struct KillOnDrop(tokio::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        // start_kill is non-blocking (sends SIGKILL) and ignores errors (e.g.
        // if the process already exited).
        let _ = self.0.start_kill();
    }
}

/// Launch `mftp server` on the remote via SSH and transfer `file`.
///
/// Steps:
/// 1. Spawns `ssh [user@]host mftp server --output-dir /path`
/// 2. Reads `{"port":N,"fingerprint":"…"}` from the child's stdout.
/// 3. Attempts a direct connection (QUIC first, auto-falls-back to TCP+TLS).
/// 4. On failure, retries via an SSH port-forward tunnel.
pub async fn send_via_ssh(
    file: PathBuf,
    dest: SshDest,
    config: SendConfig,
    remote_mftp: Option<String>,
) -> Result<()> {
    let mftp_bin = remote_mftp.as_deref().unwrap_or("mftp");

    let child = tokio::process::Command::new("ssh")
        .arg(&dest.user_host)
        .arg(mftp_bin)
        .arg("server")
        .arg("--output-dir")
        .arg(&dest.remote_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn ssh(1) — is it installed and in PATH?")?;

    // Wrap immediately so the process is killed on any early return.
    let mut ssh = KillOnDrop(child);

    // Read the one-line JSON handshake printed by the remote server.
    let stdout = ssh.0.stdout.take().expect("stdout is piped");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await.context("reading server handshake from ssh")?;
    let line = line.trim();
    if line.is_empty() {
        bail!(
            "remote mftp server exited without printing a handshake\n  \
             Is `{mftp_bin}` installed and in PATH on the remote host?"
        );
    }
    let hs: ServerHandshake = serde_json::from_str(line)
        .with_context(|| format!("invalid server handshake line: {line:?}"))?;

    eprintln!(
        "Remote server ready  port={}  fp={}…",
        hs.port,
        hs.fingerprint.get(..16).unwrap_or(&hs.fingerprint),
    );

    let direct_addr = resolve_host(&dest.host, hs.port).await?;
    let direct_cfg = SendConfig { trusted_fingerprint: Some(hs.fingerprint.clone()), ..config.clone() };
    let direct_result = crate::transfer::sender::send(file.clone(), direct_addr, direct_cfg).await;

    if let Err(e) = direct_result {
        eprintln!("[mftp] direct connection to {direct_addr} failed ({e:#})");
        eprintln!("[mftp] retrying via SSH port-forward tunnel…");
        // ? propagation here is safe: KillOnDrop ensures ssh is killed on exit.
        send_via_tunnel(file, &dest, hs.port, &hs.fingerprint, config).await?;
    }

    // Transfer complete — give the remote server a moment to exit cleanly.
    // KillOnDrop fires on drop regardless, so this is best-effort.
    let _ = ssh.0.wait().await;
    Ok(())
}

// ── SSH tunnel fallback ───────────────────────────────────────────────────────

/// Open an SSH `-L` port-forward tunnel and retry the transfer through loopback.
///
/// The tunnel routes `127.0.0.1:local_port → remote:remote_port` over the
/// existing SSH connection.  This always works when the direct transfer port
/// is blocked by a firewall.
async fn send_via_tunnel(
    file: PathBuf,
    dest: &SshDest,
    remote_port: u16,
    fingerprint: &str,
    config: SendConfig,
) -> Result<()> {
    // Grab a free local port, then release it immediately for SSH to bind.
    // The brief race on loopback is acceptable in practice.
    let local_port = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        l.local_addr()?.port()
    };

    let fwd = format!("{local_port}:localhost:{remote_port}");
    let mut tunnel = tokio::process::Command::new("ssh")
        .args(["-N", "-L"])
        .arg(&fwd)
        .args(["-o", "ExitOnForwardFailure=yes"])
        .arg(&dest.user_host)
        .spawn()
        .context("failed to spawn SSH tunnel")?;

    // Poll until the tunnel is accepting connections (up to 5 s).
    let tunnel_addr: SocketAddr = format!("127.0.0.1:{local_port}").parse().unwrap();
    wait_for_port(tunnel_addr, Duration::from_secs(5))
        .await
        .context("SSH tunnel did not become ready")?;

    let tunnel_cfg = SendConfig {
        trusted_fingerprint: Some(fingerprint.to_owned()),
        use_tcp: true, // tunnel is always TCP
        ..config
    };
    let result = crate::transfer::sender::send(file, tunnel_addr, tunnel_cfg).await;

    tunnel.kill().await.ok();
    result
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn resolve_host(host: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("DNS lookup failed for {host}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses found for {host}"))
}

/// Repeatedly attempt a TCP connect until it succeeds or `timeout` elapses.
async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting for port {} to become available", addr.port());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
