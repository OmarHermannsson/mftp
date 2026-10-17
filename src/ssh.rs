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
//! path in a private per-user directory (`~/.cache/mftp/mftp-<os>-<arch>-<hash16>`),
//! verifying its SHA-256 before installing it and again before reusing it, so
//! subsequent transfers with the same binary version skip the install (stdin is
//! drained to `/dev/null`).  Only the first transfer — or after a version
//! upgrade — pays the install cost.  See [`remote_bootstrap_script`].
//!
//! When the remote OS/arch differs from the local machine, mftp can instead
//! download the matching release binary from GitHub and pipe *that*.  Such
//! downloads are integrity-checked before they ever run on the remote: against
//! an explicit `--remote-binary-sha256` pin if given (the only defence against a
//! compromised release), otherwise against the release's own published
//! `<asset>.sha256`, with the computed digest always printed.  See
//! [`download_remote_binary`].

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
    let mut child = ssh_command(dest)
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

/// Download the mftp binary for `platform` from GitHub releases and verify its
/// integrity before it is handed to the remote for execution.
///
/// Verification has three layers, strongest first:
/// 1. If `pinned_sha256` is `Some`, the download must match it exactly or this
///    fails.  This is the only layer that defends against a compromised release
///    (the user supplies the expected hash out-of-band, e.g. from the release
///    notes over a trusted channel).
/// 2. The matching `<asset>.sha256` file is fetched from the same release and
///    compared.  This catches transport/CDN corruption and truncated downloads.
///    A *missing* checksum file (older releases) is a soft warning, not fatal.
/// 3. The computed SHA-256 is always printed so the user can compare it against
///    the published release artifacts after the fact.
///
/// `reqwest` follows GitHub's 302 redirect to the CDN automatically.
/// Returns the raw binary bytes.
async fn download_remote_binary(
    platform: &RemotePlatform,
    pinned_sha256: Option<&str>,
) -> Result<Vec<u8>> {
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

    let bytes = resp
        .bytes()
        .await
        .context("reading download body")?
        .to_vec();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let digest_hex = hex::encode(digest);
    eprintln!(
        "[mftp] downloaded {} KiB — sha256 {}",
        bytes.len() / 1024,
        digest_hex
    );

    // Layer 1: explicit user-supplied pin (strongest).
    if let Some(pin) = pinned_sha256 {
        let pin = pin.trim().trim_start_matches("0x");
        if !pin.eq_ignore_ascii_case(&digest_hex) {
            bail!(
                "downloaded binary sha256 {digest_hex} does not match \
                 --remote-binary-sha256 {pin}; refusing to run it on the remote"
            );
        }
        eprintln!("[mftp] verified against --remote-binary-sha256 pin");
        return Ok(bytes);
    }

    // Layer 2: the published per-asset checksum from the same release.
    match fetch_published_sha256(&url).await {
        Ok(Some(expected)) => {
            if !expected.eq_ignore_ascii_case(&digest_hex) {
                bail!(
                    "downloaded binary sha256 {digest_hex} does not match the \
                     published checksum {expected} ({url}.sha256) — the download \
                     may be corrupt or tampered with; refusing to run it"
                );
            }
            eprintln!("[mftp] verified against published {url}.sha256 checksum");
        }
        Ok(None) => {
            eprintln!(
                "[mftp] warning: no published .sha256 checksum found for this \
                 release; integrity rests on TLS only. Compare the sha256 above \
                 against the release page, or pass --remote-binary-sha256 to pin it."
            );
        }
        Err(e) => {
            eprintln!("[mftp] warning: could not fetch published checksum: {e:#}; integrity rests on TLS only");
        }
    }

    Ok(bytes)
}

/// Fetch and parse the `<binary_url>.sha256` artifact from the release.
///
/// Returns `Ok(Some(hex))` when present, `Ok(None)` on a 404 (release predates
/// checksum publishing), or `Err` on a transport failure.  The file follows
/// `sha256sum`/`shasum -a 256` output: `<hex>␠␠<filename>`.
async fn fetch_published_sha256(binary_url: &str) -> Result<Option<String>> {
    let url = format!("{binary_url}.sha256");
    let resp = reqwest::get(&url).await.context("fetch .sha256")?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        bail!("checksum download returned HTTP {}", resp.status());
    }
    let body = resp.text().await.context("read .sha256 body")?;
    let hex = parse_sha256_line(&body)
        .with_context(|| format!("malformed checksum file at {url}: {body:?}"))?;
    Ok(Some(hex))
}

/// Extract the 64-hex-char digest from a `sha256sum`/`shasum -a 256` line of the
/// form `<hex>␠␠<filename>`.  Returns `None` if the first token is not a valid
/// SHA-256 hex digest.
fn parse_sha256_line(body: &str) -> Option<String> {
    body.split_whitespace()
        .next()
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|h| h.to_owned())
}

/// Pipe `binary` (built for `platform`) to the remote over SSH stdin and run
/// it as a one-shot server.
///
/// The remote side caches the binary under a content-addressed name (see
/// [`remote_bootstrap_script`]) so later transfers with the same binary skip
/// the install; the bytes are still streamed and drained on a cache hit.
async fn pipe_binary_to_remote(
    dest: &SshDest,
    binary: &[u8],
    platform: &RemotePlatform,
    remote_port: Option<u16>,
    require_peer: Option<&str>,
) -> Result<tokio::process::Child> {
    let digest: [u8; 32] = Sha256::digest(binary).into();
    let script = remote_bootstrap_script(
        &platform.os,
        &platform.arch,
        &hex::encode(digest),
        binary.len() as u64,
        &dest.remote_path,
        remote_port,
        require_peer,
    );

    let mut child = ssh_command(dest)
        .arg(remote_sh_command(&script))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn ssh(1) — is it installed and in PATH?")?;

    // Write the binary to ssh's stdin, then close it so the remote `cat`
    // sees EOF and the script continues to the exec.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(binary)
        .await
        .context("writing binary to ssh stdin")?;
    drop(stdin);

    Ok(child)
}

/// Build the POSIX `sh` script that installs (or reuses) the piped binary on
/// the remote and execs it as `mftp server`.
///
/// * **Cache location** — `$XDG_CACHE_HOME/mftp`, else `$HOME/.cache/mftp`,
///   else `${TMPDIR:-/tmp}/mftp-<uid>`.  The directory must be owned by the
///   login user and must not be a symlink (so a directory pre-planted in a
///   shared `/tmp` is rejected); otherwise a private `mktemp -d` directory is
///   used for this run only.  It is `chmod 700` and files are created under
///   `umask 077`.
/// * **Integrity** — the full SHA-256 is checked with `sha256sum` or
///   `shasum -a 256` (falling back to a byte-count check, with a warning, on
///   hosts with neither).  A cached file that fails the check is replaced.  A
///   fresh upload is written to a temp file, verified, `chmod`ed and only then
///   atomically `mv`ed into place, so a truncated or interrupted upload can
///   never be executed or poison the cache.
///
/// The script is a **single line** containing no `!` and no backslashes, so it
/// survives being quoted for the remote login shell even when that shell is
/// csh/tcsh (no multi-line quoted strings) or fish (which treats backslash
/// sequences inside single quotes specially).
fn remote_bootstrap_script(
    os: &str,
    arch: &str,
    sha256_hex: &str,
    size: u64,
    remote_path: &str,
    remote_port: Option<u16>,
    require_peer: Option<&str>,
) -> String {
    let short = &sha256_hex[..16.min(sha256_hex.len())];
    let env_prefix = server_env(require_peer);
    let quoted_dir = shell_quote(remote_path);
    let port_arg = match remote_port {
        Some(p) => format!(" --port {p}"),
        None => String::new(),
    };
    [
        "set -e;".to_owned(),
        // Private umask for the cache only; the user's own umask is restored
        // before exec so received files get their normal permissions.
        "um=$(umask); umask 077;".to_owned(),
        format!("want={sha256_hex};"),
        // Pick a per-user cache directory; never a shared world-writable one.
        r#"if [ -n "${XDG_CACHE_HOME:-}" ]; then c="$XDG_CACHE_HOME/mftp"; elif [ -n "${HOME:-}" ]; then c="$HOME/.cache/mftp"; else c="${TMPDIR:-/tmp}/mftp-$(id -u)"; fi;"#.to_owned(),
        r#"mkdir -p "$c" 2>/dev/null || c=$(mktemp -d);"#.to_owned(),
        // Reject a symlink or a directory owned by someone else.
        r#"if [ -L "$c" ]; then c=$(mktemp -d); elif [ -O "$c" ]; then :; else c=$(mktemp -d); fi;"#.to_owned(),
        r#"chmod 700 "$c";"#.to_owned(),
        // ok FILE: does FILE have the expected content?
        format!(
            r#"ok() {{ if command -v sha256sum >/dev/null 2>&1; then h=$(sha256sum "$1" | cut -d" " -f1); elif command -v shasum >/dev/null 2>&1; then h=$(shasum -a 256 "$1" | cut -d" " -f1); else echo "[mftp] warning: no sha256sum/shasum on remote; checking size only" >&2; [ "$(wc -c < "$1" | tr -d " ")" = {size} ]; return; fi; [ "$h" = "$want" ]; }};"#
        ),
        format!(r#"f="$c/mftp-{os}-{arch}-{short}";"#),
        r#"if [ -x "$f" ] && ok "$f"; then cat > /dev/null; echo "[mftp] using cached binary" >&2;"#.to_owned(),
        r#"else t="$f.tmp.$$"; rm -f "$t"; cat > "$t";"#.to_owned(),
        r#"if ok "$t"; then chmod 700 "$t"; mv -f "$t" "$f"; echo "[mftp] binary installed ($(wc -c < "$f" | tr -d " ") bytes)" >&2;"#.to_owned(),
        r#"else rm -f "$t"; echo "[mftp] uploaded binary failed integrity verification; refusing to run it" >&2; exit 1; fi; fi;"#.to_owned(),
        remote_dest_fragment(&quoted_dir),
        format!(r#"umask "$um"; exec {env_prefix}"$f" server --output-dir "$d"{port_arg}"#),
    ]
    .join(" ")
}

/// How long the sender waits for the remote one-shot server to exit after the
/// transfer before tearing the SSH session down.
const REMOTE_EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Environment variable through which the SSH launcher hands the remote
/// one-shot `mftp server` the sender's DeviceId to require.
pub const REQUIRE_PEER_ENV: &str = "MFTP_REQUIRE_PEER";

/// Environment variable through which the SSH launcher tells the remote
/// one-shot `mftp server` to store the transfer under a new name (scp-style
/// `host:/dir/newname`). Empty = keep the sender's name.
pub const OUTPUT_NAME_ENV: &str = "MFTP_OUTPUT_NAME";

/// scp-like destination semantics, as a shell fragment run on the remote:
/// sets `$d` to the output directory and `$n` to the name to store the
/// transfer under (empty = the sender's). An existing directory, or a path
/// ending in `/`, is the output directory itself; anything else is a file
/// destination — its parent is the output directory and its last component
/// the new name.
fn remote_dest_fragment(quoted_path: &str) -> String {
    format!(
        r#"d={quoted_path}; n=; case "$d" in */) ;; *) if [ -d "$d" ]; then :; else n=$(basename "$d"); d=$(dirname "$d"); fi;; esac;"#
    )
}

/// `env MFTP_OUTPUT_NAME="$n" [MFTP_REQUIRE_PEER=<id>] ` prefix for the remote
/// server command (pairs with [`remote_dest_fragment`]). A binary predating
/// these variables just ignores them. Ids that aren't plain hex are dropped
/// rather than interpolated into the remote command.
fn server_env(require_peer: Option<&str>) -> String {
    let mut env = format!(r#"env {OUTPUT_NAME_ENV}="$n" "#);
    if let Some(id) =
        require_peer.filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        env.push_str(&format!("{REQUIRE_PEER_ENV}={id} "));
    }
    env
}

/// Wrap `script` as a single remote command string `sh -c '<script>'`.
///
/// OpenSSH concatenates every argument after the destination with spaces and
/// hands the result to the remote user's *login shell*.  Passing `sh`, `-c`,
/// `script` as separate argv entries therefore makes the login shell run
/// `sh -c set -e …` — `sh` receives only `set` as its script and the login
/// shell (possibly fish/csh) interprets the rest itself, so `set -e` is
/// ineffective.  Quoting the whole script as one word makes every shell hand
/// it to `sh` verbatim.
fn remote_sh_command(script: &str) -> String {
    format!("sh -c {}", shell_quote(script))
}

/// Base `ssh(1)` invocation for `dest`.
///
/// `ControlPath=none` avoids reusing a multiplexed master (whose stdio
/// plumbing interferes with piping the binary).  `--` terminates option
/// parsing so the destination can never be interpreted as an ssh option, even
/// if validation in [`parse_ssh_dest`] were bypassed.
fn ssh_command(dest: &SshDest) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("ssh");
    cmd.arg("-o").arg("ControlPath=none");
    if let Some(port) = dest.port {
        cmd.arg("-p").arg(port.to_string());
    }
    cmd.arg("--").arg(&dest.user_host);
    cmd
}

/// Prompt the user on `/dev/tty` to confirm downloading a cross-platform binary.
///
/// Opens `/dev/tty` directly so the prompt works even when stdin is redirected.
/// Returns `false` in non-interactive contexts where `/dev/tty` is unavailable.
/// The prompt spells out the platform mismatch that triggered the download and
/// that the binary will be integrity-checked before it runs on the remote.
fn prompt_download(local_desc: &str, remote_desc: &str) -> bool {
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
        "Remote is {remote_desc} but this mftp is built for {local_desc}, so it \
         can't be reused there.\nDownload the {remote_desc} mftp binary from \
         GitHub releases (verified by sha256) and run it on the remote? [y/N]: "
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
    /// SSH port, when given explicitly (`ssh://host:port/path`); `None` lets
    /// `ssh(1)` use its config/default and the SFTP fallback use 22.
    pub port: Option<u16>,
}

/// Try to parse `dest` as an SSH destination.
///
/// Returns `Ok(None)` when `dest` looks like a direct `host:port` address —
/// specifically, when it contains no `@` and the portion after `:` is a
/// valid port number.
/// Returns `Err` if the destination looks like an SSH path but no username
/// can be determined (no `user@` prefix and `$USER`/`$LOGNAME` are both unset).
///
/// The URL form `ssh://[user@]host[:port][/path]` is also accepted and is the
/// way to give a non-default SSH port (the port is passed to `ssh -p` and used
/// by the SFTP fallback).  IPv6 hosts may be bracketed (`user@[::1]:/path`).
///
/// Destinations whose user or host begins with `-` are rejected: `ssh(1)`
/// would otherwise parse them as options (e.g. `-oProxyCommand=…`).
pub fn parse_ssh_dest(dest: &str) -> Result<Option<SshDest>> {
    if let Some(rest) = dest.strip_prefix("ssh://") {
        return parse_ssh_url(dest, rest).map(Some);
    }

    let Some(colon) = dest.rfind(':') else {
        return Ok(None);
    };
    let before = &dest[..colon];
    let after = &dest[colon + 1..];

    // No '@' and the part after ':' is a port number → plain host:port address.
    if !before.contains('@') && after.parse::<u16>().is_ok() {
        return Ok(None);
    }

    let (user, host) = split_user_host(before);
    build_dest(dest, user, host, after.to_owned(), None).map(Some)
}

/// Parse the part after `ssh://`: `[user@]host[:port][/path]`.
fn parse_ssh_url(dest: &str, rest: &str) -> Result<SshDest> {
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_owned()),
        None => (rest, ".".to_owned()),
    };
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        // [v6]:port or [v6]
        let close = inner
            .find(']')
            .with_context(|| format!("unterminated '[' in SSH destination {dest:?}"))?;
        let port = match &inner[close + 1..] {
            "" => None,
            p => Some(p.strip_prefix(':').unwrap_or(p)),
        };
        (&inner[..close], port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    let port = port
        .map(|p| {
            p.parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .with_context(|| format!("invalid SSH port {p:?} in {dest:?}"))
        })
        .transpose()?;
    build_dest(
        dest,
        userinfo.map(str::to_owned),
        host.to_owned(),
        path,
        port,
    )
}

/// Split `[user@]host` (host optionally `[bracketed]`).
fn split_user_host(before: &str) -> (Option<String>, String) {
    let (user, host) = match before.find('@') {
        Some(at) => (Some(before[..at].to_owned()), &before[at + 1..]),
        None => (None, before),
    };
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    (user, host.to_owned())
}

fn default_user(dest: &str) -> Result<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| {
            anyhow::anyhow!(
                "cannot determine SSH username for {dest:?}: \
                 no user@host prefix and $USER/$LOGNAME are not set"
            )
        })
}

/// Validate the components and assemble an [`SshDest`].
///
/// With no explicit user, `user_host` is just the host so `ssh(1)` still
/// applies any `User` from ssh_config; `user` (for the SFTP fallback, which
/// does not read ssh_config) defaults to `$USER`/`$LOGNAME`.
fn build_dest(
    dest: &str,
    explicit_user: Option<String>,
    host: String,
    remote_path: String,
    port: Option<u16>,
) -> Result<SshDest> {
    let user = match &explicit_user {
        Some(u) => u.clone(),
        None => default_user(dest)?,
    };
    if host.is_empty() {
        bail!("SSH destination {dest:?} has no host");
    }
    if user.is_empty() {
        bail!("SSH destination {dest:?} has an empty user name");
    }
    // ssh(1) would parse a leading '-' as an option (e.g. -oProxyCommand=…).
    if host.starts_with('-') || user.starts_with('-') {
        bail!("refusing SSH destination {dest:?}: user/host must not start with '-'");
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) || user.contains(char::is_control)
    {
        bail!("refusing SSH destination {dest:?}: invalid characters in user/host");
    }
    // ssh(1) takes IPv6 literals unbracketed.
    let user_host = match explicit_user {
        Some(_) => format!("{user}@{host}"),
        None => host.clone(),
    };
    Ok(SshDest {
        user_host,
        user,
        host,
        remote_path,
        port,
    })
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
    binary_sha256: Option<String>,
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
    // Lock the one-shot remote server to our own DeviceId so another host that
    // reaches its port first can't take the transfer slot.
    let require_peer = config
        .client_identity
        .as_ref()
        .map(|id| id.device_id.as_str());
    let child = match remote_mftp {
        Some(ref bin) => spawn_remote_binary(&dest, bin, remote_port, require_peer)?,
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
                        DownloadPolicy::Ask => prompt_download(&local_desc, &remote_desc),
                    };

                if should_download {
                    let rp = remote_platform.as_ref().unwrap();
                    match download_remote_binary(rp, binary_sha256.as_deref()).await {
                        Ok(binary) => {
                            eprintln!("[mftp] piping downloaded binary to remote ({remote_desc})…");
                            match pipe_binary_to_remote(
                                &dest,
                                &binary,
                                rp,
                                remote_port,
                                require_peer,
                            )
                            .await
                            {
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
                pipe_self_to_remote(&dest, remote_port, require_peer).await?
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

    // Keep draining the server's stdout: it writes heartbeats there (see
    // `spawn_ssh_session_watchdog` in the receiver), and if this process dies
    // the resulting broken pipe is what tears the SSH session — and so the
    // remote server — down.
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
    });

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

    // How many QUIC retries before falling back to SFTP.  Exactly one retry
    // is enough: if the first attempt made progress, the resume bitmap on the
    // receiver lets a second attempt skip already-written chunks cheaply.
    const QUIC_RETRIES: u32 = 1;

    let mut attempt = 0u32;
    let first_result = loop {
        let result =
            crate::transfer::sender::send(file.clone(), direct_addr, direct_cfg.clone()).await;

        match &result {
            Ok(()) => break result,
            Err(e) => {
                // C2a: all data was sent but the receiver's verification
                // response timed out.  Every chunk was individually verified
                // during transfer; retrying or falling back to SFTP would be
                // harmful.  Warn and treat as success.
                if e.downcast_ref::<crate::transfer::sender::AckTimeoutAfterComplete>()
                    .is_some()
                {
                    eprintln!(
                        "[mftp] warning: all data was sent but the receiver's \
                         verification timed out. The transfer likely completed \
                         successfully — check the receiver for errors."
                    );
                    break Ok(());
                }
                // C2: if the transfer made progress (MidTransferFailure marker
                // is present) and we have retries left, retry QUIC rather than
                // falling back to SFTP.  The receiver's resume bitmap means the
                // retry only re-sends missing chunks.
                if attempt < QUIC_RETRIES
                    && e.downcast_ref::<crate::transfer::sender::MidTransferFailure>()
                        .is_some()
                    && config.forced_transport.is_none()
                {
                    attempt += 1;
                    eprintln!(
                        "[mftp] QUIC transfer failed mid-flight ({e:#}); \
                         retrying with resume (attempt {attempt}/{QUIC_RETRIES})…"
                    );
                    // C3: keep `ssh` alive — the remote mftp process is still
                    // running and will accept the reconnect.
                    continue;
                }
                break result;
            }
        }
    };

    if let Err(e) = first_result {
        // The receiver actively rejected the transfer (e.g. destination out of
        // space) — SFTP writes to the same destination and would fail the same
        // way, so surface the error instead of a pointless slow retry.
        if e.downcast_ref::<crate::transfer::sender::ReceiverRejected>()
            .is_some()
        {
            return Err(e);
        }
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

    // Transfer complete — give the remote server a moment to exit cleanly,
    // then KillOnDrop ends the session (bounded: a remote that never exits must
    // not hang the sender).
    let _ = tokio::time::timeout(REMOTE_EXIT_GRACE, ssh.0.wait()).await;
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
    require_peer: Option<&str>,
) -> Result<tokio::process::Child> {
    let port_arg = match remote_port {
        Some(p) => format!(" --port {p}"),
        None => String::new(),
    };
    // scp-like semantics (see `remote_dest_fragment`): host:/data/new.bin
    // writes /data/new.bin, host:/data/ (or an existing dir) writes inside it.
    let quoted_dir = shell_quote(&dest.remote_path);
    let script = format!(
        r#"{} exec {}{} server --output-dir "$d"{}"#,
        remote_dest_fragment(&quoted_dir),
        server_env(require_peer),
        shell_quote(bin),
        port_arg,
    );
    // One `sh -c '<script>'` word, so the POSIX fragment also works when the
    // remote login shell is csh/fish.
    ssh_command(dest)
        .arg(remote_sh_command(&script))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn ssh(1) — is it installed and in PATH?")
}

/// Pipe the local binary to the remote over SSH stdin and run it as a server.
///
/// The remote caches the binary under a content-addressed name so a second
/// call with an identical binary skips the install; see
/// [`remote_bootstrap_script`] for the caching and integrity checks.
async fn pipe_self_to_remote(
    dest: &SshDest,
    remote_port: Option<u16>,
    require_peer: Option<&str>,
) -> Result<tokio::process::Child> {
    let exe = std::env::current_exe().context("cannot locate current executable")?;
    let binary = tokio::fs::read(&exe)
        .await
        .with_context(|| format!("cannot read {}", exe.display()))?;
    // OS + arch are part of the cache name so a shared remote receiving from
    // clients of different platforms stores binaries separately.
    pipe_binary_to_remote(dest, &binary, &local_platform(), remote_port, require_peer).await
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
        download_url, local_platform, parse_remote_platform_output, parse_sha256_line,
        parse_ssh_dest, platform_matches, remote_bootstrap_script, remote_sh_command, server_env,
        shell_quote, RemotePlatform, OUTPUT_NAME_ENV, REQUIRE_PEER_ENV,
    };

    /// scp-like destination resolution, run through a real `sh`: an existing
    /// dir or a trailing `/` is the output dir; anything else is a new name in
    /// its parent.
    #[cfg(unix)]
    #[test]
    fn remote_dest_fragment_resolves_like_scp() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().to_str().unwrap();
        let resolve = |path: &str| {
            let script = format!(
                r#"{} printf "%s|%s" "$d" "$n""#,
                super::remote_dest_fragment(&shell_quote(path))
            );
            let o = std::process::Command::new("sh")
                .arg("-c")
                .arg(&script)
                .output()
                .unwrap();
            assert!(o.status.success());
            String::from_utf8(o.stdout).unwrap()
        };
        assert_eq!(resolve(root), format!("{root}|"));
        assert_eq!(resolve(&format!("{root}/")), format!("{root}/|"));
        assert_eq!(
            resolve(&format!("{root}/new name.bin")),
            format!("{root}|new name.bin")
        );
        // A trailing slash on a missing path still means "directory".
        assert_eq!(
            resolve(&format!("{root}/missing/")),
            format!("{root}/missing/|")
        );
        assert_eq!(resolve("relative.bin"), ".|relative.bin");
    }

    /// The remote command must be ONE shell word after `sh -c`, on one line,
    /// with no `!`/backslashes inside the script (csh/fish compatibility).
    #[test]
    fn remote_command_is_single_quoted_sh_c() {
        let script = remote_bootstrap_script(
            "linux",
            "x86_64",
            &"ab".repeat(32),
            1234,
            "/data/it's here",
            Some(9000),
            Some(&"cd".repeat(32)),
        );
        assert!(!script.contains('\n'), "script must be a single line");
        assert!(!script.contains('!'), "no history-expansion characters");
        // The only backslashes come from shell_quote escaping the path's `'`.
        assert!(!script.replace(r"'\''", "").contains('\\'));
        let cmd = remote_sh_command(&script);
        assert!(cmd.starts_with("sh -c '"));
        assert!(cmd.ends_with('\''));
        assert!(script.contains("--port 9000"));
        assert!(script.contains(&format!("{REQUIRE_PEER_ENV}={}", "cd".repeat(32))));
        assert!(script.contains(&format!(r#"env {OUTPUT_NAME_ENV}="$n""#)));
        // Anything but plain hex is never interpolated into the command.
        assert!(!server_env(Some("x; rm -rf ~")).contains("rm"));
    }

    /// Run the bootstrap exactly as the remote login shell would (`sh -c` of
    /// the quoted command) against a fake "binary", covering install, cache
    /// hit, a tampered cache entry, and a corrupt upload.
    #[cfg(unix)]
    #[test]
    fn bootstrap_script_installs_verifies_and_rejects() {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};

        let home = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        // Reports its args and the umask it was started with.
        let binary = b"#!/bin/sh\necho \"ARGS:$* UMASK:$(umask)\"\n".to_vec();
        let hash = hex::encode(Sha256::digest(&binary));
        let script = remote_bootstrap_script(
            "linux",
            "x86_64",
            &hash,
            binary.len() as u64,
            out.path().to_str().unwrap(),
            None,
            None,
        );
        let cmd = remote_sh_command(&script);

        let run = |stdin_bytes: &[u8]| {
            // The login shell's umask (0022) must reach the server, not the
            // bootstrap's private 077.
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(format!("umask 0022; {cmd}"))
                .env("HOME", home.path())
                .env_remove("XDG_CACHE_HOME")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(stdin_bytes).unwrap();
            let o = child.wait_with_output().unwrap();
            (
                o.status.success(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        };
        let expected = format!(
            "ARGS:server --output-dir {} UMASK:0022",
            out.path().display()
        );
        let cache_dir = home.path().join(".cache/mftp");
        let cached = cache_dir.join(format!("mftp-linux-x86_64-{}", &hash[..16]));

        // 1. First run installs.
        let (ok, stdout, stderr) = run(&binary);
        assert!(ok, "install failed: {stderr}");
        assert_eq!(stdout.trim(), expected);
        assert!(stderr.contains("binary installed"), "{stderr}");
        let mode = std::fs::metadata(&cache_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "cache dir must be private");

        // 2. Second run hits the cache.
        let (ok, stdout, stderr) = run(&binary);
        assert!(ok, "{stderr}");
        assert_eq!(stdout.trim(), expected);
        assert!(stderr.contains("using cached binary"), "{stderr}");

        // 3. A tampered cache entry is detected and replaced.
        std::fs::write(&cached, b"#!/bin/sh\necho EVIL\n").unwrap();
        let (ok, stdout, stderr) = run(&binary);
        assert!(ok, "{stderr}");
        assert_eq!(stdout.trim(), expected, "tampered binary must not run");
        assert!(stderr.contains("binary installed"), "{stderr}");

        // 4. A corrupt upload is refused and never installed.
        std::fs::remove_file(&cached).unwrap();
        let (ok, stdout, stderr) = run(b"#!/bin/sh\necho CORRUPT\n");
        assert!(!ok, "corrupt upload must fail");
        assert!(!stdout.contains("CORRUPT"));
        assert!(stderr.contains("integrity"), "{stderr}");
        assert!(!cached.exists(), "corrupt upload must not reach the cache");
        let leftovers: Vec<_> = std::fs::read_dir(&cache_dir).unwrap().collect();
        assert!(leftovers.is_empty(), "temp file must be cleaned up");
    }

    /// With HOME unset the cache must not land in a shared `/tmp/.cache`; a
    /// per-uid directory under TMPDIR is used instead, and a directory planted
    /// there as a symlink is refused.
    #[cfg(unix)]
    #[test]
    fn bootstrap_script_without_home_uses_private_tmpdir() {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        use std::process::{Command, Stdio};

        let tmp = tempfile::TempDir::new().unwrap();
        let out = tempfile::TempDir::new().unwrap();
        let binary = b"#!/bin/sh\necho OK\n".to_vec();
        let hash = hex::encode(Sha256::digest(&binary));
        let cmd = remote_sh_command(&remote_bootstrap_script(
            "linux",
            "x86_64",
            &hash,
            binary.len() as u64,
            out.path().to_str().unwrap(),
            None,
            None,
        ));
        // Plant a symlink where the per-uid dir would go, pointing elsewhere.
        let uid = unsafe { libc::getuid() };
        let decoy = tempfile::TempDir::new().unwrap();
        std::os::unix::fs::symlink(decoy.path(), tmp.path().join(format!("mftp-{uid}"))).unwrap();

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .env_remove("HOME")
            .env_remove("XDG_CACHE_HOME")
            .env("TMPDIR", tmp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&binary).unwrap();
        let o = child.wait_with_output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "OK");
        assert!(
            std::fs::read_dir(decoy.path()).unwrap().next().is_none(),
            "nothing may be written through a planted symlink"
        );
    }

    #[test]
    fn parse_dest_rejects_option_injection() {
        for d in [
            "-oProxyCommand=touch /tmp/pwn:/x",
            "-oProxyCommand=x@host:/x",
            "user@-oProxyCommand=x:/x",
            "ssh://-oProxyCommand=x/x",
            "ssh://user@-host/x",
        ] {
            assert!(parse_ssh_dest(d).is_err(), "{d:?} must be rejected");
        }
    }

    #[test]
    fn parse_dest_forms() {
        let d = parse_ssh_dest("alice@example.com:/data").unwrap().unwrap();
        assert_eq!(
            (d.user.as_str(), d.host.as_str(), d.user_host.as_str()),
            ("alice", "example.com", "alice@example.com")
        );
        assert_eq!((d.remote_path.as_str(), d.port), ("/data", None));

        // Plain host:port stays a direct address.
        assert!(parse_ssh_dest("example.com:4433").unwrap().is_none());

        // ssh:// URL with a port.
        let d = parse_ssh_dest("ssh://bob@host.example:2222/srv/in")
            .unwrap()
            .unwrap();
        assert_eq!((d.user.as_str(), d.host.as_str()), ("bob", "host.example"));
        assert_eq!((d.remote_path.as_str(), d.port), ("/srv/in", Some(2222)));

        // Bracketed IPv6, both forms.
        let d = parse_ssh_dest("ssh://carol@[::1]:2200/tmp")
            .unwrap()
            .unwrap();
        assert_eq!((d.host.as_str(), d.port), ("::1", Some(2200)));
        let d = parse_ssh_dest("carol@[fe80::1]:/tmp").unwrap().unwrap();
        assert_eq!(d.host, "fe80::1");

        // Bad ports.
        assert!(parse_ssh_dest("ssh://h:0/x").is_err());
        assert!(parse_ssh_dest("ssh://h:99999/x").is_err());
    }

    #[test]
    fn shell_quote_plain() {
        assert_eq!(shell_quote("/tmp/out"), "'/tmp/out'");
    }

    #[test]
    fn sha256_line_parsed() {
        let h = "a".repeat(64);
        // `sha256sum` style: hex, two spaces, filename.
        assert_eq!(
            parse_sha256_line(&format!("{h}  mftp-linux-x86_64")),
            Some(h.clone())
        );
        // `shasum`/BSD style with a single space is also tolerated.
        assert_eq!(parse_sha256_line(&format!("{h} file")), Some(h.clone()));
        // bare digest with trailing newline.
        assert_eq!(parse_sha256_line(&format!("{h}\n")), Some(h));
    }

    #[test]
    fn sha256_line_rejects_malformed() {
        assert_eq!(parse_sha256_line(""), None);
        assert_eq!(parse_sha256_line("not-a-hash  file"), None);
        // Wrong length (63 chars).
        assert_eq!(parse_sha256_line(&"a".repeat(63)), None);
        // Non-hex character in an otherwise 64-char token.
        assert_eq!(parse_sha256_line(&format!("{}g  f", "a".repeat(63))), None);
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
