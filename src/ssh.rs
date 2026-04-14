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
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Controls whether mftp may download a cross-platform binary from GitHub
/// releases when the remote OS/arch differs from the local machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadPolicy {
    /// Always download without prompting.
    Always,
    /// Never attempt a download; fall back to SFTP immediately.
    Never,
    /// Prompt the user interactively (default). Falls back to SFTP if no TTY.
    Ask,
}

use crate::transfer::sender::{ForcedTransport, SendConfig};

// ── Platform detection ────────────────────────────────────────────────────────

/// OS + CPU architecture of a host.
#[derive(Debug, PartialEq, Eq)]
struct RemotePlatform {
    os: String,   // "linux" | "macos" | "windows" | …
    arch: String, // "x86_64" | "aarch64" | …
}

/// Platform of the currently-running binary (from `std::env::consts`).
fn local_platform() -> RemotePlatform {
    RemotePlatform {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
    }
}

/// Returns `true` when `remote` can run a binary built for `local`.
///
/// On Windows, arch-level compat is assumed (WoW64 / emulation) so only the
/// OS is checked.  On Linux/macOS, both OS and arch must match.
fn platform_matches(local: &RemotePlatform, remote: &RemotePlatform) -> bool {
    if local.os == "windows" || remote.os == "windows" {
        local.os == remote.os
    } else {
        local.os == remote.os && local.arch == remote.arch
    }
}

/// Parse `uname -sm` / `ver` output into a `RemotePlatform`.
///
/// Scans `output` line by line, returning the first recognisable match.
/// Returns `None` if no line matches a known pattern.
fn parse_remote_platform_output(output: &str) -> Option<RemotePlatform> {
    for line in output.lines() {
        let line = line.trim();

        // Windows `ver`: "Microsoft Windows [Version 10.0.19041.1706]"
        if line.to_ascii_lowercase().contains("microsoft windows")
            || line.to_ascii_lowercase().starts_with("windows")
        {
            return Some(RemotePlatform {
                os: "windows".to_owned(),
                // Can't determine remote arch from `ver` alone; caller treats
                // windows→windows as arch-compatible (WoW64).
                arch: "x86_64".to_owned(),
            });
        }

        // Unix `uname -sm`: "Linux x86_64", "Darwin arm64", etc.
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() == 2 {
            let os = match parts[0] {
                "Linux" => "linux",
                "Darwin" => "macos",
                "FreeBSD" | "OpenBSD" | "NetBSD" => parts[0],
                _ => continue,
            };
            // macOS reports "arm64"; Rust's ARCH constant uses "aarch64".
            let arch = match parts[1] {
                "arm64" => "aarch64",
                other => other,
            };
            return Some(RemotePlatform {
                os: os.to_owned(),
                arch: arch.to_owned(),
            });
        }
    }
    None
}

/// Probe the remote host's OS and CPU architecture over SSH.
///
/// Runs `uname -sm` (Unix) and `ver` (Windows cmd.exe) in a single command;
/// one of them will produce recognisable output.  The whole probe is bounded
/// by a 10-second timeout so a slow or custom shell cannot block the transfer.
///
/// Returns `Ok(None)` when the remote output cannot be parsed (caller treats
/// this conservatively as a mismatch).
async fn probe_remote_platform(dest: &SshDest) -> Result<Option<RemotePlatform>> {
    // `uname -sm` on Unix; `ver` on Windows cmd.exe.  Both are run; one will
    // produce noise, the other the expected string — the parser skips noise.
    let mut child = tokio::process::Command::new("ssh")
        .arg(&dest.user_host)
        .arg("uname -sm 2>/dev/null; ver 2>NUL")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn ssh(1) for platform probe")?;

    let stdout = child.stdout.take().expect("stdout is piped");
    let read_output = async {
        let mut reader = BufReader::new(stdout);
        let mut out = String::new();
        reader
            .read_to_string(&mut out)
            .await
            .context("reading platform probe output")?;
        Ok::<String, anyhow::Error>(out)
    };

    let output = match tokio::time::timeout(std::time::Duration::from_secs(10), read_output).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            let _ = child.kill().await;
            tracing::debug!("platform probe timed out — treating remote as unknown");
            return Ok(None);
        }
    };

    let _ = child.wait().await;
    Ok(parse_remote_platform_output(&output))
}

// ── Cross-platform binary download ───────────────────────────────────────────

/// Construct the GitHub release download URL for a given remote platform.
///
/// Artifact naming follows `std::env::consts` values so the URL matches the
/// release filenames: `mftp-{os}-{arch}[.exe]`.
fn download_url(platform: &RemotePlatform) -> String {
    let suffix = if platform.os == "windows" { ".exe" } else { "" };
    format!(
        "https://github.com/OmarHermannsson/mftp/releases/latest/download/mftp-{}-{}{}",
        platform.os, platform.arch, suffix,
    )
}

/// Download the mftp binary for `platform` from GitHub releases.
///
/// `reqwest` follows GitHub's 302 redirect to the CDN automatically.
/// Returns the raw binary bytes.
async fn download_remote_binary(platform: &RemotePlatform) -> Result<Vec<u8>> {
    let url = download_url(platform);
    tracing::debug!("downloading remote binary from {url}");
    eprintln!(
        "[mftp] downloading mftp for {}/{} from GitHub…",
        platform.os, platform.arch
    );

    let resp = reqwest::get(&url)
        .await
        .context("HTTP request to GitHub releases failed")?;

    if !resp.status().is_success() {
        bail!(
            "GitHub release download returned HTTP {} — \
             no pre-built binary for {}/{} ({})",
            resp.status(),
            platform.os,
            platform.arch,
            url,
        );
    }

    let bytes = resp.bytes().await.context("reading download body")?;
    eprintln!("[mftp] downloaded {} KiB", bytes.len() / 1024);
    Ok(bytes.to_vec())
}

/// Pipe `binary` to the remote over SSH stdin and run it as a server.
///
/// Behaves like `pipe_self_to_remote` but accepts arbitrary bytes and uses
/// `platform` for the remote cache path so cross-platform binaries are stored
/// separately from the local binary.
async fn pipe_binary_to_remote(
    dest: &SshDest,
    binary: &[u8],
    platform: &RemotePlatform,
    remote_port: Option<u16>,
) -> Result<tokio::process::Child> {
    let hash: String = {
        let digest: [u8; 32] = Sha256::digest(binary).into();
        hex::encode(&digest[..8])
    };

    let os = &platform.os;
    let arch = &platform.arch;
    let quoted_dir = shell_quote(&dest.remote_path);
    let port_arg = match remote_port {
        Some(p) => format!(" --port {p}"),
        None => String::new(),
    };

    let remote_cmd = format!(
        r#"set -e
f="${{HOME:-/tmp}}/.cache/mftp-{os}-{arch}-{hash}"
if [ ! -x "$f" ]; then
  mkdir -p "$(dirname "$f")"
  cat > "$f"
  chmod +x "$f"
  printf '[mftp] binary installed (%s)\n' "$(du -sh "$f" 2>/dev/null | cut -f1 || echo '?')" >&2
else
  cat > /dev/null
  printf '[mftp] using cached binary\n' >&2
fi
d={quoted_dir}
if [ ! -d "$d" ]; then d=$(dirname "$d"); fi
exec "$f" server --output-dir "$d"{port_arg}"#
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
        .context("failed to spawn ssh(1)")?;

    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(binary)
        .await
        .context("writing binary to ssh stdin")?;
    drop(stdin);

    Ok(child)
}

/// Prompt the user on `/dev/tty` to confirm downloading a cross-platform binary.
///
/// Opens `/dev/tty` directly so the prompt works even when stdin is redirected.
/// Returns `false` in non-interactive contexts where `/dev/tty` is unavailable.
fn prompt_download(remote_desc: &str) -> bool {
    use std::io::{BufRead, BufReader, Write};
    let Ok(mut tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        return false;
    };
    let _ = write!(
        tty,
        "Download mftp for {remote_desc} from GitHub releases? [y/N]: "
    );
    let _ = tty.flush();
    let Ok(tty_r) = std::fs::File::open("/dev/tty") else {
        return false;
    };
    let mut answer = String::new();
    BufReader::new(tty_r).read_line(&mut answer).ok();
    let ans = answer.trim();
    ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes")
}

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
/// Returns `Ok(None)` when `dest` looks like a direct `host:port` address —
/// specifically, when it contains no `@` and the portion after `:` is a
/// valid port number.
/// Returns `Err` if the destination looks like an SSH path but no username
/// can be determined (no `user@` prefix and `$USER`/`$LOGNAME` are both unset).
pub fn parse_ssh_dest(dest: &str) -> Result<Option<SshDest>> {
    let Some(colon) = dest.rfind(':') else {
        return Ok(None);
    };
    let before = &dest[..colon];
    let after = &dest[colon + 1..];

    // No '@' and the part after ':' is a port number → plain host:port address.
    if !before.contains('@') && after.parse::<u16>().is_ok() {
        return Ok(None);
    }

    let (user_host, user, host) = if let Some(at) = before.find('@') {
        (
            before.to_owned(),
            before[..at].to_owned(),
            before[at + 1..].to_owned(),
        )
    } else {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .map_err(|_| {
                anyhow::anyhow!(
                    "cannot determine SSH username for {dest:?}: \
                     no user@host prefix and $USER/$LOGNAME are not set"
                )
            })?;
        (before.to_owned(), user, before.to_owned())
    };

    Ok(Some(SshDest {
        user_host,
        user,
        host,
        remote_path: after.to_owned(),
    }))
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
    download_policy: DownloadPolicy,
) -> Result<()> {
    // Fast path: SFTP forced — skip remote server launch entirely and go
    // straight to parallel SFTP over port 22.
    if config.forced_transport == Some(ForcedTransport::Sftp) {
        let n = config.streams.unwrap_or(8);
        return crate::sftp::send_via_sftp(file, dest, n).await;
    }

    // When no pre-installed binary is specified we pipe the local binary to the
    // remote.  That only works if the remote runs the same OS and architecture;
    // probe first so we fail clearly instead of hanging on a bad exec.
    let child = match remote_mftp {
        Some(ref bin) => spawn_remote_binary(&dest, bin, remote_port)?,
        None => {
            let local = local_platform();
            let remote_platform = probe_remote_platform(&dest).await?;
            let compatible = remote_platform
                .as_ref()
                .map(|r| platform_matches(&local, r))
                .unwrap_or(false);

            if !compatible {
                let remote_desc = remote_platform
                    .as_ref()
                    .map(|r| format!("{}/{}", r.os, r.arch))
                    .unwrap_or_else(|| "unknown".to_owned());
                let local_desc = format!("{}/{}", local.os, local.arch);

                if config.forced_transport.is_some() {
                    bail!(
                        "remote platform ({remote_desc}) differs from local ({local_desc}); \
                         cannot pipe the local binary to the remote. \
                         Install mftp on the remote and pass --remote-mftp <path>, \
                         or omit --transport to fall back to SFTP automatically."
                    );
                }

                // Try to download the correct binary from GitHub releases,
                // unless the user opted out or the remote platform is unknown.
                let should_download = remote_platform.is_some()
                    && match download_policy {
                        DownloadPolicy::Always => true,
                        DownloadPolicy::Never => false,
                        DownloadPolicy::Ask => prompt_download(&remote_desc),
                    };

                if should_download {
                    let rp = remote_platform.as_ref().unwrap();
                    match download_remote_binary(rp).await {
                        Ok(binary) => {
                            eprintln!("[mftp] piping downloaded binary to remote ({remote_desc})…");
                            match pipe_binary_to_remote(&dest, &binary, rp, remote_port).await {
                                Ok(child) => child,
                                Err(e) => {
                                    eprintln!(
                                        "[mftp] failed to pipe downloaded binary: {e:#}; \
                                         falling back to SFTP…"
                                    );
                                    let n = config.streams.unwrap_or(8);
                                    return crate::sftp::send_via_sftp(file, dest, n).await;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[mftp] download failed: {e:#}; falling back to SFTP…");
                            let n = config.streams.unwrap_or(8);
                            return crate::sftp::send_via_sftp(file, dest, n).await;
                        }
                    }
                } else {
                    eprintln!(
                        "[mftp] remote platform ({remote_desc}) differs from local \
                         ({local_desc}); falling back to SFTP…"
                    );
                    let n = config.streams.unwrap_or(8);
                    return crate::sftp::send_via_sftp(file, dest, n).await;
                }
            } else {
                pipe_self_to_remote(&dest, remote_port).await?
            }
        }
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
        // A forced transport means the user explicitly chose QUIC or TCP+TLS —
        // do not silently fall back to SFTP.
        if config.forced_transport.is_some() {
            return Err(e.context(format!(
                "direct connection to {direct_addr} failed; \
                 SFTP fallback suppressed by --transport"
            )));
        }
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
    // Use scp-like semantics: if the remote path is not an existing directory,
    // treat it as a file destination and use its parent as the output dir.
    // E.g. host:/data/file writes to /data/file (parent = /data, filename from manifest).
    let quoted_dir = shell_quote(&dest.remote_path);
    let remote_cmd = format!(
        "d={quoted_dir}; if [ ! -d \"$d\" ]; then d=$(dirname \"$d\"); fi; {} server --output-dir \"$d\"{}",
        shell_quote(bin),
        port_arg,
    );
    // Pass the command as a single argument so SSH sends it verbatim to the
    // remote login shell.  Using `sh -c <script>` here would make `server`
    // and `--output-dir` become $0/$1 (ignored) instead of mftp arguments.
    tokio::process::Command::new("ssh")
        .arg(&dest.user_host)
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

    // Embed OS + arch in the cache name so that a shared remote receiving
    // from clients of different platforms stores binaries separately.
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let quoted_dir = shell_quote(&dest.remote_path);
    let port_arg = match remote_port {
        Some(p) => format!(" --port {p}"),
        None => String::new(),
    };

    // Remote script:
    //   • Derive a stable cache path from OS, arch, and binary content hash.
    //   • If the cached file does not exist: write stdin to it and chmod +x.
    //   • Otherwise: drain stdin (cat > /dev/null) so the pipe is clean.
    //   • Exec the cached binary as a one-shot server.
    let remote_cmd = format!(
        r#"set -e
f="${{HOME:-/tmp}}/.cache/mftp-{os}-{arch}-{hash}"
if [ ! -x "$f" ]; then
  mkdir -p "$(dirname "$f")"
  cat > "$f"
  chmod +x "$f"
  printf '[mftp] binary installed (%s)\n' "$(du -sh "$f" 2>/dev/null | cut -f1 || echo '?')" >&2
else
  cat > /dev/null
  printf '[mftp] using cached binary\n' >&2
fi
d={quoted_dir}
if [ ! -d "$d" ]; then d=$(dirname "$d"); fi
exec "$f" server --output-dir "$d"{port_arg}"#
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
    stdin
        .write_all(&binary)
        .await
        .context("writing binary to ssh stdin")?;
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
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .with_context(|| format!("DNS lookup timed out for {host}"))?
    .with_context(|| format!("DNS lookup failed for {host}"))?
    .next()
    .ok_or_else(|| anyhow::anyhow!("no addresses found for {host}"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        download_url, local_platform, parse_remote_platform_output, platform_matches, shell_quote,
        RemotePlatform,
    };

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

    #[test]
    fn parse_remote_platform_linux() {
        let p = parse_remote_platform_output("Linux x86_64\n").unwrap();
        assert_eq!(p.os, "linux");
        assert_eq!(p.arch, "x86_64");
    }

    #[test]
    fn parse_remote_platform_linux_arm() {
        let p = parse_remote_platform_output("Linux aarch64\n").unwrap();
        assert_eq!(p.os, "linux");
        assert_eq!(p.arch, "aarch64");
    }

    #[test]
    fn parse_remote_platform_macos_intel() {
        let p = parse_remote_platform_output("Darwin x86_64\n").unwrap();
        assert_eq!(p.os, "macos");
        assert_eq!(p.arch, "x86_64");
    }

    #[test]
    fn parse_remote_platform_macos_arm() {
        // macOS reports "arm64"; we normalise to Rust's "aarch64".
        let p = parse_remote_platform_output("Darwin arm64\n").unwrap();
        assert_eq!(p.os, "macos");
        assert_eq!(p.arch, "aarch64");
    }

    #[test]
    fn parse_remote_platform_windows_ver() {
        let out = "Microsoft Windows [Version 10.0.19041.1706]\n";
        let p = parse_remote_platform_output(out).unwrap();
        assert_eq!(p.os, "windows");
    }

    #[test]
    fn parse_remote_platform_windows_with_banner() {
        // PowerShell / cmd.exe may print other lines before/after `ver`.
        let out = "some banner line\r\nMicrosoft Windows [Version 11.0.22621.0]\r\n\r\n";
        let p = parse_remote_platform_output(out).unwrap();
        assert_eq!(p.os, "windows");
    }

    #[test]
    fn parse_remote_platform_linux_with_preamble() {
        // Shell startup files can print noise before uname output.
        let out = "Welcome to my server!\nLinux x86_64\n";
        let p = parse_remote_platform_output(out).unwrap();
        assert_eq!(p.os, "linux");
        assert_eq!(p.arch, "x86_64");
    }

    #[test]
    fn parse_remote_platform_garbage() {
        assert!(parse_remote_platform_output("nothing useful here\n").is_none());
        assert!(parse_remote_platform_output("").is_none());
    }

    #[test]
    fn local_platform_matches_env_consts() {
        let p = local_platform();
        assert_eq!(p.os, std::env::consts::OS);
        assert_eq!(p.arch, std::env::consts::ARCH);
    }

    #[test]
    fn platform_matches_same() {
        let a = RemotePlatform {
            os: "linux".into(),
            arch: "x86_64".into(),
        };
        let b = RemotePlatform {
            os: "linux".into(),
            arch: "x86_64".into(),
        };
        assert!(platform_matches(&a, &b));
    }

    #[test]
    fn platform_matches_os_mismatch() {
        let local = RemotePlatform {
            os: "linux".into(),
            arch: "x86_64".into(),
        };
        let remote = RemotePlatform {
            os: "macos".into(),
            arch: "x86_64".into(),
        };
        assert!(!platform_matches(&local, &remote));
    }

    #[test]
    fn platform_matches_arch_mismatch() {
        let local = RemotePlatform {
            os: "linux".into(),
            arch: "x86_64".into(),
        };
        let remote = RemotePlatform {
            os: "linux".into(),
            arch: "aarch64".into(),
        };
        assert!(!platform_matches(&local, &remote));
    }

    #[test]
    fn download_url_linux() {
        let p = RemotePlatform {
            os: "linux".into(),
            arch: "x86_64".into(),
        };
        assert_eq!(
            download_url(&p),
            "https://github.com/OmarHermannsson/mftp/releases/latest/download/mftp-linux-x86_64"
        );
    }

    #[test]
    fn download_url_windows_has_exe_suffix() {
        let p = RemotePlatform {
            os: "windows".into(),
            arch: "x86_64".into(),
        };
        assert!(download_url(&p).ends_with(".exe"));
    }

    #[test]
    fn download_url_macos_aarch64() {
        let p = RemotePlatform {
            os: "macos".into(),
            arch: "aarch64".into(),
        };
        assert_eq!(
            download_url(&p),
            "https://github.com/OmarHermannsson/mftp/releases/latest/download/mftp-macos-aarch64"
        );
    }

    #[test]
    fn platform_matches_windows_ignores_arch() {
        // Windows→Windows is compatible regardless of reported arch.
        let local = RemotePlatform {
            os: "windows".into(),
            arch: "x86_64".into(),
        };
        let remote = RemotePlatform {
            os: "windows".into(),
            arch: "x86_64".into(),
        };
        assert!(platform_matches(&local, &remote));
    }
}
