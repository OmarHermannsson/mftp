//! SSH-assisted transfer: launch `mftp server` on the remote via SSH,
//! read the port/fingerprint handshake, then connect directly.
//!
//! If the direct connection fails (e.g. a firewall blocks the transfer port),
//! the sender falls back to routing data through an SSH port-forward tunnel,
//! which is available whenever SSH itself is available.
//!
//! # Binary delivery
//!
//! When `--remote-mftp` is not given the local binary is piped to the remote
//! over SSH stdin.  The remote shell writes it to a content-addressed cache
//! path (`~/.cache/mftp-<hash16>`), making subsequent transfers with the same
//! binary version instant (the remote already has it; stdin is drained to
//! `/dev/null`).  Only the first transfer — or after a version upgrade — pays
//! the copy cost.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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
/// When `remote_mftp` is `None` (the default), the local binary is piped to
/// the remote over SSH stdin so mftp does not need to be pre-installed there.
/// When `remote_mftp` is `Some(path)`, that pre-installed binary is used
/// instead and nothing is copied.
///
/// In both cases:
/// 1. A JSON handshake `{"port":N,"fingerprint":"…"}` is read from stdout.
/// 2. A direct connection is attempted (QUIC first, auto-falls-back to TCP+TLS).
/// 3. On failure, the transfer is retried via an SSH port-forward tunnel.
pub async fn send_via_ssh(
    file: PathBuf,
    dest: SshDest,
    config: SendConfig,
    remote_mftp: Option<String>,
    remote_port: Option<u16>,
) -> Result<()> {
    // A ControlMaster socket lets the tunnel reuse this SSH connection instead
    // of establishing a second one.  Keyed on PID so parallel transfers don't
    // collide.
    let ctrl_socket = std::env::temp_dir()
        .join(format!("mftp-ssh-{}.sock", std::process::id()));

    let child = match remote_mftp {
        Some(ref bin) => spawn_remote_binary(&dest, bin, remote_port, &ctrl_socket)?,
        None => pipe_self_to_remote(&dest, remote_port, &ctrl_socket).await?,
    };

    // Wrap immediately so the process is killed on any early return.
    let mut ssh = KillOnDrop(child);

    // Read lines from ssh stdout until we find the JSON handshake.
    // Shell startup files (.bashrc, /etc/profile, etc.) often print to stdout
    // before our script runs — we skip those lines and look for the first one
    // that begins with '{'.
    let stdout = ssh.0.stdout.take().expect("stdout is piped");
    let mut reader = BufReader::new(stdout);
    let hs: ServerHandshake = loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .await
            .context("reading server handshake from ssh")?;
        if n == 0 {
            bail!(
                "remote mftp server exited without printing a handshake \
                 (check that the remote shell startup files don't produce errors)"
            );
        }
        let line = line.trim();
        if line.starts_with('{') {
            break serde_json::from_str(line)
                .with_context(|| format!("invalid server handshake: {line:?}"))?;
        }
        // Shell preamble noise — log at debug and skip.
        tracing::debug!("ssh preamble: {line}");
    };

    eprintln!(
        "Remote server ready  port={}  fp={}…",
        hs.port,
        hs.fingerprint.get(..16).unwrap_or(&hs.fingerprint),
    );

    let direct_addr = resolve_host(&dest.host, hs.port).await?;
    let direct_cfg = SendConfig {
        trusted_fingerprint: Some(hs.fingerprint.clone()),
        ..config.clone()
    };
    let direct_result = crate::transfer::sender::send(file.clone(), direct_addr, direct_cfg).await;

    if let Err(e) = direct_result {
        eprintln!("[mftp] direct connection to {direct_addr} failed ({e:#})");
        eprintln!("[mftp] retrying via SSH port-forward tunnel…");
        // ? propagation here is safe: KillOnDrop ensures ssh is killed on exit.
        send_via_tunnel(file, &dest, hs.port, &hs.fingerprint, config, &ctrl_socket).await?;
    }

    // Transfer complete — give the remote server a moment to exit cleanly.
    // KillOnDrop fires on drop regardless, so this is best-effort.
    let _ = ssh.0.wait().await;
    Ok(())
}

// ── Binary delivery ───────────────────────────────────────────────────────────

/// Spawn SSH to run a pre-installed binary on the remote.
fn spawn_remote_binary(
    dest: &SshDest,
    bin: &str,
    remote_port: Option<u16>,
    ctrl_socket: &Path,
) -> Result<tokio::process::Child> {
    let mut cmd = tokio::process::Command::new("ssh");
    cmd.args(["-o", "ControlMaster=yes"])
        .args(["-o", &format!("ControlPath={}", ctrl_socket.display())])
        .arg(&dest.user_host)
        .arg(bin)
        .arg("server")
        .arg("--output-dir")
        .arg(&dest.remote_path);
    if let Some(p) = remote_port {
        cmd.arg("--port").arg(p.to_string());
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn ssh(1) — is it installed and in PATH?")
}

/// Pipe the local binary to the remote over SSH stdin and run it as a server.
///
/// The remote shell script caches the binary at `~/.cache/mftp-<hash16>` so
/// that a second call with an identical binary skips the copy and just runs
/// the cached file.
async fn pipe_self_to_remote(dest: &SshDest, remote_port: Option<u16>, ctrl_socket: &Path) -> Result<tokio::process::Child> {
    let exe = std::env::current_exe().context("cannot locate current executable")?;
    let binary = tokio::fs::read(&exe)
        .await
        .with_context(|| format!("cannot read {}", exe.display()))?;

    // 16 hex chars of SHA-256 — enough to identify a binary version uniquely.
    let hash: String = {
        let digest: [u8; 32] = Sha256::digest(&binary).into();
        hex::encode(&digest[..8])
    };

    let quoted_dir = shell_quote(&dest.remote_path);
    let port_arg = match remote_port {
        Some(p) => format!(" --port {p}"),
        None => String::new(),
    };

    // Remote script:
    //   • Derive a stable cache path from the binary's content hash.
    //   • If the cached file does not exist: write stdin to it and chmod +x.
    //   • Otherwise: drain stdin (cat > /dev/null) so the pipe is clean.
    //   • Exec the cached binary as a one-shot server.
    let remote_cmd = format!(
        r#"set -e
f="${{HOME:-/tmp}}/.cache/mftp-{hash}"
if [ ! -x "$f" ]; then
  mkdir -p "$(dirname "$f")"
  cat > "$f"
  chmod +x "$f"
  printf '[mftp] binary installed (%s)\n' "$(du -sh "$f" 2>/dev/null | cut -f1 || echo '?')" >&2
else
  cat > /dev/null
  printf '[mftp] using cached binary\n' >&2
fi
exec "$f" server --output-dir {quoted_dir}{port_arg}"#
    );

    let mut child = tokio::process::Command::new("ssh")
        .args(["-o", "ControlMaster=yes"])
        .args(["-o", &format!("ControlPath={}", ctrl_socket.display())])
        .arg(&dest.user_host)
        .arg("sh")
        .arg("-c")
        .arg(&remote_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn ssh(1) — is it installed and in PATH?")?;

    // Write the binary to ssh's stdin, then close it so the remote `cat`
    // sees EOF and the script continues to the exec.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(&binary).await.context("writing binary to ssh stdin")?;
    drop(stdin);

    Ok(child)
}

/// Single-quote a string for safe embedding in a POSIX shell command.
///
/// Wraps `s` in single quotes and escapes any literal `'` by ending the
/// quoted section, inserting `'\''`, and reopening.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
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
    ctrl_socket: &Path,
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
        // Reuse the ControlMaster socket opened by the initial SSH connection —
        // no second TCP+SSH handshake needed.
        .args(["-o", "ControlMaster=auto"])
        .args(["-o", &format!("ControlPath={}", ctrl_socket.display())])
        .arg(&dest.user_host)
        .spawn()
        .context("failed to spawn SSH tunnel")?;

    // Wait until SSH has bound the local port (up to 5 s), without connecting
    // through the tunnel — connecting would reach the receiver and consume its
    // single control-stream accept slot before the real transfer connects.
    wait_for_ssh_listener(local_port, Duration::from_secs(5))
        .await
        .context("SSH tunnel did not become ready")?;
    let tunnel_addr: SocketAddr = format!("127.0.0.1:{local_port}").parse().unwrap();

    let tunnel_cfg = SendConfig {
        trusted_fingerprint: Some(fingerprint.to_owned()),
        use_tcp: true, // tunnel is always TCP
        // SSH multiplexes all data over one TCP connection; parallel streams
        // add overhead without gain.  One stream with a large chunk keeps the
        // pipe full without fragmenting into many SSH channels.
        streams: Some(1),
        chunk_size: Some(8 * 1024 * 1024), // 8 MiB — optimal for single-stream
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

/// Wait until SSH has bound the local tunnel port, without connecting through it.
///
/// Connecting through the tunnel would go all the way to the receiver, which
/// would accept it as the real control stream, start TLS, and then crash when
/// the test connection drops — consuming the receiver's single accept slot.
///
/// Instead we try to *bind* the port: if binding fails (EADDRINUSE), SSH owns
/// it and the tunnel is ready.  This never touches the receiver.
async fn wait_for_ssh_listener(port: u16, timeout: Duration) -> Result<()> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::net::TcpListener::bind(addr).await {
            Err(_) => return Ok(()), // port in use → SSH has bound it
            Ok(_) => {}              // port still free → SSH not ready yet
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("SSH tunnel listener on port {port} not ready within {timeout:.1?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn shell_quote_plain() {
        assert_eq!(shell_quote("/tmp/out"), "'/tmp/out'");
    }

    #[test]
    fn shell_quote_spaces() {
        assert_eq!(shell_quote("/my files/out dir"), "'/my files/out dir'");
    }

    #[test]
    fn shell_quote_single_quote() {
        assert_eq!(shell_quote("it's here"), "'it'\\''s here'");
    }
}
