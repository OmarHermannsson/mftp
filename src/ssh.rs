//! SSH-assisted transfer: launch `mftp server` on the remote via SSH,
//! read the port/fingerprint handshake, then connect directly.
//!
//! If the direct connection fails (e.g. a firewall blocks the transfer port),
//! the sender falls back to parallel SFTP — N independent SSH/SFTP connections
//! writing non-overlapping file segments directly via the remote sshd, with
//! no mftp receiver process and a single SSH encryption layer.
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
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::transfer::sender::SendConfig;

// ── Destination parsing ───────────────────────────────────────────────────────

/// An SSH-style destination parsed from `[user@]host:/remote/path`.
#[derive(Clone)]
pub struct SshDest {
    /// Passed directly to `ssh(1)`: `"user@host"` or `"host"`.
    pub user_host: String,
    /// Username for ssh2 authentication (split from `user_host`).
    pub user: String,
    /// Hostname component, used for DNS resolution and ssh2 TCP connect.
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

    let (user_host, user, host) = if let Some(at) = before.find('@') {
        (before.to_owned(), before[..at].to_owned(), before[at + 1..].to_owned())
    } else {
        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_owned());
        (before.to_owned(), user, before.to_owned())
    };

    Some(SshDest { user_host, user, host, remote_path: after.to_owned() })
}

// ── SSH launch + transfer ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ServerHandshake {
    port: u16,
    fingerprint: String,
}

/// RAII guard that kills a child process when dropped.
///
/// Used to ensure the remote `mftp server` is always reaped, even when the
/// transfer fails and the function returns early via `?`.
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
/// 3. On failure, the transfer is retried via parallel SFTP (N independent
///    SSH/SFTP connections writing directly to the remote file).
pub async fn send_via_ssh(
    file: PathBuf,
    dest: SshDest,
    config: SendConfig,
    remote_mftp: Option<String>,
    remote_port: Option<u16>,
) -> Result<()> {
    let child = match remote_mftp {
        Some(ref bin) => spawn_remote_binary(&dest, bin, remote_port)?,
        None => pipe_self_to_remote(&dest, remote_port).await?,
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
        eprintln!("[mftp] retrying via SFTP (parallel SSH streams, single encryption layer)…");
        // Kill the mftp server — SFTP bypasses it entirely and talks to sshd
        // directly.  KillOnDrop also fires on drop, but being explicit here
        // lets the remote process exit before SFTP opens its connections.
        drop(ssh);
        // 8 parallel SFTP streams ≈ 22 MiB/s; scales linearly up to ~12
        // before sshd MaxStartups (default 10:30:100) starts rejecting
        // concurrent auth attempts.  User can override with --streams.
        let n = config.streams.unwrap_or(8);
        crate::sftp::send_via_sftp(file, dest, n).await?;
        return Ok(());
    }

    // Transfer complete — give the remote server a moment to exit cleanly.
    // KillOnDrop fires on drop regardless, so this is best-effort.
    let _ = ssh.0.wait().await;
    Ok(())
}

// ── Binary delivery ───────────────────────────────────────────────────────────

/// Spawn SSH to run a pre-installed binary on the remote.
///
/// OpenSSH joins all non-hostname arguments with spaces into a single shell
/// command on the remote, so we must shell-quote `bin` and `remote_path` to
/// handle spaces and other metacharacters correctly.
fn spawn_remote_binary(
    dest: &SshDest,
    bin: &str,
    remote_port: Option<u16>,
) -> Result<tokio::process::Child> {
    let port_arg = match remote_port {
        Some(p) => format!(" --port {p}"),
        None => String::new(),
    };
    let remote_cmd = format!(
        "{} server --output-dir {}{}",
        shell_quote(bin),
        shell_quote(&dest.remote_path),
        port_arg,
    );
    tokio::process::Command::new("ssh")
        .arg(&dest.user_host)
        .arg("sh")
        .arg("-c")
        .arg(&remote_cmd)
        .stdin(Stdio::null())
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
async fn pipe_self_to_remote(
    dest: &SshDest,
    remote_port: Option<u16>,
) -> Result<tokio::process::Child> {
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

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn resolve_host(host: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("DNS lookup failed for {host}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses found for {host}"))
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
