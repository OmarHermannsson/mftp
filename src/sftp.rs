//! Parallel SFTP fallback transport.
//!
//! When both QUIC and direct TCP are blocked, mftp falls back to writing the
//! file directly over N independent SSH/SFTP connections.  Each connection
//! owns one file segment and writes it with positional I/O — the same
//! approach used by the `zap` tool, which inspired this path.
//!
//! Advantages over the previous SSH port-forward tunnel approach:
//! - Single encryption layer (SSH, not SSH + TLS).
//! - No mftp receiver process needed on the remote — sshd's built-in
//!   sftp-server subsystem handles everything.
//! - Each of the N streams has fully independent congestion control.
//!
//! Authentication tries the SSH agent first, then the default private-key
//! files (`~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa`) in order.  The host
//! key is verified against `~/.ssh/known_hosts`; an unrecognized key is
//! rejected (run `ssh <host>` once to add it).

use std::io::{Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use indicatif::{ProgressBar, ProgressStyle};
use sha1::Sha1;
use ssh2::{MethodType, OpenFlags, OpenType, Session};

use crate::ssh::SshDest;

/// Write buffer per SFTP stream.  Matches zap; larger buffers increase
/// SFTP request size and reduce round-trips.
const SFTP_BUFFER: usize = 1024 * 1024; // 1 MiB

/// Transfer `file` to `dest.remote_path/<filename>` using `n_streams`
/// parallel SFTP connections.
///
/// This is fully synchronous work (libssh2 is blocking), so each stream
/// runs on a dedicated `spawn_blocking` thread.
pub async fn send_via_sftp(file: PathBuf, dest: SshDest, n_streams: usize) -> Result<()> {
    let file_name = file
        .file_name()
        .context("file has no name")?
        .to_string_lossy()
        .into_owned();
    let file_size = tokio::fs::metadata(&file)
        .await
        .with_context(|| format!("stat {}", file.display()))?
        .len();

    let remote_path = format!("{}/{}", dest.remote_path.trim_end_matches('/'), file_name);

    eprintln!(
        "[mftp] SFTP fallback: {n_streams} streams → {} (single SSH encryption layer)",
        dest.user_host
    );

    // Pre-create and sparse-allocate the remote file with one session so
    // all N workers can open it for writing without racing on creation.
    {
        let d = dest.clone();
        let rp = remote_path.clone();
        tokio::task::spawn_blocking(move || create_remote_file(&d, &rp, file_size))
            .await
            .context("SFTP file-creation task panicked")??;
    }

    let segment = file_size.div_ceil(n_streams as u64);
    let progress = Arc::new(AtomicU64::new(0));
    let pb = make_progress_bar(&file_name, file_size);
    let start = Instant::now();

    // Spawn one blocking thread per stream.
    let handles: Vec<_> = (0..n_streams)
        .map(|i| {
            let offset = i as u64 * segment;
            if offset >= file_size {
                return None;
            }
            let len = (file_size - offset).min(segment);
            let d = dest.clone();
            let rp = remote_path.clone();
            let fp = file.clone();
            let prog = Arc::clone(&progress);
            Some(tokio::task::spawn_blocking(move || {
                sftp_worker(&d, &rp, &fp, offset, len, prog)
            }))
        })
        .collect();

    // Update the progress bar every 100 ms while workers run.
    let pb_tick = pb.clone();
    let prog_tick = Arc::clone(&progress);
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            pb_tick.set_position(prog_tick.load(Ordering::Relaxed));
        }
    });

    for h in handles.into_iter().flatten() {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                ticker.abort();
                return Err(e);
            }
            Err(e) => {
                ticker.abort();
                bail!("SFTP worker panicked: {e}");
            }
        }
    }

    ticker.abort();
    pb.finish_and_clear();

    let elapsed = start.elapsed();
    let mib = file_size as f64 / (1024.0 * 1024.0);
    println!(
        "Transfer complete (SFTP): {file_name} ({mib:.0} MiB) in {:.1}s ({:.0} MiB/s).",
        elapsed.as_secs_f64(),
        mib / elapsed.as_secs_f64(),
    );

    Ok(())
}

// ── Per-stream worker ─────────────────────────────────────────────────────────

fn sftp_worker(
    dest: &SshDest,
    remote_path: &str,
    file_path: &Path,
    offset: u64,
    len: u64,
    progress: Arc<AtomicU64>,
) -> Result<()> {
    let sess = ssh_connect(dest).context("SFTP stream connect")?;
    let sftp = sess.sftp().context("open SFTP subsystem")?;

    let mut remote_file = sftp
        .open_mode(
            Path::new(remote_path),
            OpenFlags::WRITE,
            0o644,
            OpenType::File,
        )
        .with_context(|| format!("SFTP open {remote_path}"))?;
    remote_file
        .seek(SeekFrom::Start(offset))
        .context("SFTP seek")?;

    let local_file =
        std::fs::File::open(file_path).with_context(|| format!("open {}", file_path.display()))?;
    let mut buf = vec![0u8; SFTP_BUFFER];
    let mut done = 0u64;

    while done < len {
        let n = ((len - done) as usize).min(buf.len());
        crate::fs_ext::read_exact_at(&local_file, &mut buf[..n], offset + done)
            .context("pread local file")?;
        remote_file.write_all(&buf[..n]).context("SFTP write")?;
        done += n as u64;
        progress.fetch_add(n as u64, Ordering::Relaxed);
    }

    Ok(())
}

// ── Remote file creation ──────────────────────────────────────────────────────

/// Create (or truncate) the remote file and sparse-allocate it to `file_size`
/// bytes so all stream workers can write at arbitrary offsets without
/// extending the file themselves.
fn create_remote_file(dest: &SshDest, remote_path: &str, file_size: u64) -> Result<()> {
    let sess = ssh_connect(dest).context("SFTP creation connect")?;
    let sftp = sess.sftp().context("open SFTP subsystem for creation")?;

    let mut f = sftp
        .open_mode(
            Path::new(remote_path),
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            0o644,
            OpenType::File,
        )
        .with_context(|| format!("SFTP create {remote_path}"))?;

    // Sparse-allocate: write one zero byte at the final position so the
    // remote filesystem reserves the full extent.
    if file_size > 0 {
        f.seek(SeekFrom::Start(file_size.saturating_sub(1)))
            .context("SFTP seek for sparse allocation")?;
        f.write_all(&[0u8])
            .context("SFTP sparse allocation write")?;
    }

    Ok(())
}

// ── SSH connection helpers ────────────────────────────────────────────────────

/// Open a new authenticated SSH session to `dest.host:22`.
fn ssh_connect(dest: &SshDest) -> Result<Session> {
    let tcp = TcpStream::connect((&dest.host[..], 22))
        .with_context(|| format!("TCP connect to {}:22", dest.host))?;
    let mut sess = Session::new().context("create SSH session")?;
    sess.set_tcp_stream(tcp);
    // Prefer ed25519 for host key negotiation — most systems have ed25519 in
    // ~/.ssh/known_hosts (added by the initial `ssh` command), whereas ssh2's
    // default preference order often negotiates ecdsa-sha2-nistp256 instead.
    sess.method_pref(
        MethodType::HostKey,
        "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,rsa-sha2-512,ssh-rsa",
    )
    .context("set host key preference")?;
    sess.handshake().context("SSH handshake")?;

    verify_host_key(&sess, &dest.host)?;
    authenticate(&sess, &dest.user)?;

    Ok(sess)
}

/// Check the remote host key against `~/.ssh/known_hosts`.
///
/// Bypasses libssh2's `KnownHosts` API (which has subtle key-type-matching
/// issues) and directly compares the raw wire-format key bytes from the
/// session against the base64-decoded entries in the known_hosts file.
///
/// Handles both plain entries (`host key-type base64-key`) and OpenSSH hashed
/// entries (`|1|<base64-salt>|<base64-hmac-sha1>  key-type  base64-key`), so
/// this works on Ubuntu/Debian systems where `HashKnownHosts yes` is the
/// default `ssh_config` setting.
///
/// Rejects connections if the key is unknown (run `ssh <host>` once) or
/// has changed (possible MITM), and refuses to proceed if known_hosts is absent.
fn verify_host_key(sess: &Session, host: &str) -> Result<()> {
    let (sess_key, _) = sess
        .host_key()
        .ok_or_else(|| anyhow::anyhow!("remote sent no host key"))?;

    let home = std::env::var("HOME").unwrap_or_default();
    let kh_path = Path::new(&home).join(".ssh").join("known_hosts");

    if !kh_path.exists() {
        bail!(
            "~/.ssh/known_hosts not found — run `ssh {host}` once to accept \
             the host key before using the SFTP fallback path"
        );
    }

    let content = std::fs::read_to_string(&kh_path).context("read ~/.ssh/known_hosts")?;
    let mut host_found = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 3 {
            continue;
        }

        let host_field = parts[0];
        let matches = if host_field.starts_with('|') {
            // Hashed entry: |1|<base64-salt>|<base64-HMAC-SHA1> (OpenSSH HashKnownHosts)
            host_field_matches_hashed(host, host_field)
        } else {
            // Plain entry: comma-separated hostname/IP list
            host_field.split(',').any(|h| h == host)
        };
        if !matches {
            continue;
        }
        host_found = true;

        // parts[2] is the base64-encoded wire-format public key.
        let stored = STANDARD
            .decode(parts[2])
            .or_else(|_| STANDARD_NO_PAD.decode(parts[2]))
            .unwrap_or_default();

        if stored == sess_key {
            return Ok(());
        }
    }

    if host_found {
        bail!(
            "SSH host key MISMATCH for {host} — possible MITM attack; \
             check ~/.ssh/known_hosts"
        )
    } else {
        bail!(
            "SSH host key for {host} not found in ~/.ssh/known_hosts — \
             run `ssh {host}` once to add it"
        )
    }
}

/// Returns `true` if a hashed known_hosts entry (`|1|<salt>|<hash>`) matches
/// the given hostname using HMAC-SHA1, the scheme used by OpenSSH
/// `HashKnownHosts yes` (the default on Ubuntu/Debian).
fn host_field_matches_hashed(hostname: &str, field: &str) -> bool {
    // Expected format when split on '|': ["", "1", salt_b64, hmac_b64]
    let parts: Vec<&str> = field.splitn(4, '|').collect();
    if parts.len() != 4 || !parts[0].is_empty() || parts[1] != "1" {
        return false;
    }
    let salt = match STANDARD
        .decode(parts[2])
        .or_else(|_| STANDARD_NO_PAD.decode(parts[2]))
    {
        Ok(s) => s,
        Err(_) => return false,
    };
    let expected = match STANDARD
        .decode(parts[3])
        .or_else(|_| STANDARD_NO_PAD.decode(parts[3]))
    {
        Ok(h) => h,
        Err(_) => return false,
    };
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&salt) else {
        return false;
    };
    mac.update(hostname.as_bytes());
    mac.finalize().into_bytes().as_slice() == expected.as_slice()
}

/// Authenticate `user` via SSH agent, then default key files.
fn authenticate(sess: &Session, user: &str) -> Result<()> {
    // 1. SSH agent (covers most interactive setups).
    if let Ok(mut agent) = sess.agent() {
        if agent.connect().is_ok() && agent.list_identities().is_ok() {
            for identity in agent.identities().unwrap_or_default() {
                if agent.userauth(user, &identity).is_ok() && sess.authenticated() {
                    return Ok(());
                }
            }
        }
    }

    // 2. Default private-key files.
    let home = std::env::var("HOME").unwrap_or_default();
    for key in &["id_ed25519", "id_rsa", "id_ecdsa"] {
        let path = Path::new(&home).join(".ssh").join(key);
        if path.exists()
            && sess.userauth_pubkey_file(user, None, &path, None).is_ok()
            && sess.authenticated()
        {
            return Ok(());
        }
    }

    bail!("SSH authentication failed for user {user}")
}

// ── Progress bar ──────────────────────────────────────────────────────────────

fn make_progress_bar(file_name: &str, file_size: u64) -> ProgressBar {
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::with_template(
            "[sftp] {spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} \
             {bytes}/{total_bytes} {bytes_per_sec} eta {eta}  {prefix}",
        )
        .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_prefix(file_name.to_owned());
    pb
}
