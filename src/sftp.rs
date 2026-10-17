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
//! key is verified against `~/.ssh/known_hosts`; an unrecognized, changed or
//! `@revoked` key is rejected (run `ssh <host>` once to add it).
//!
//! Limitation: this path talks to sshd directly via libssh2 and does not read
//! `~/.ssh/config` — `HostName`, `Port`, `User` and `ProxyJump`/`ProxyCommand`
//! are not applied.  A non-default port can be given with
//! `ssh://user@host:port/path`.

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
use indicatif::ProgressBar;
use sha1::Sha1;
use ssh2::{MethodType, OpenFlags, OpenType, Session};

use crate::ssh::SshDest;

/// Write buffer per SFTP stream.  Matches zap; larger buffers increase
/// SFTP request size and reduce round-trips.
const SFTP_BUFFER: usize = 1024 * 1024; // 1 MiB

/// Transfer `file` to `dest.remote_path` using `n_streams` parallel SFTP
/// connections, with scp-like destination semantics: an existing remote
/// directory (or a path ending in `/`) receives `<dir>/<filename>`, anything
/// else is the destination file path itself (`host:/dir/newname`).
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

    eprintln!(
        "[mftp] SFTP fallback: {n_streams} streams → {} (single SSH encryption layer)",
        dest.user_host
    );

    // Pre-create and sparse-allocate the remote file with one session so
    // all N workers can open it for writing without racing on creation.
    let remote_path = {
        let d = dest.clone();
        let name = file_name.clone();
        tokio::task::spawn_blocking(move || create_remote_file(&d, &name, file_size))
            .await
            .context("SFTP file-creation task panicked")??
    };

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

/// Resolve the destination file path (see [`send_via_sftp`]), create (or
/// truncate) it and sparse-allocate it to `file_size` bytes so all stream
/// workers can write at arbitrary offsets without extending the file
/// themselves. Returns the resolved remote path.
fn create_remote_file(dest: &SshDest, file_name: &str, file_size: u64) -> Result<String> {
    let sess = ssh_connect(dest).context("SFTP creation connect")?;
    let sftp = sess.sftp().context("open SFTP subsystem for creation")?;

    // `host:` (empty path) means the login directory.
    let target = match dest.remote_path.as_str() {
        "" => ".",
        p => p,
    };
    let is_dir = sftp
        .stat(Path::new(target))
        .map(|st| st.is_dir())
        .unwrap_or(false);
    // Same rules as the direct path's remote shell fragment.
    let (dir, name) = crate::ssh::resolve_scp_dest(target, is_dir);
    let name = name.as_deref().unwrap_or(file_name);
    let remote_path = match dir.trim_end_matches('/') {
        "" => format!("/{name}"),
        d => format!("{d}/{name}"),
    };
    let remote_path = remote_path.as_str();

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

    Ok(remote_path.to_owned())
}

// ── SSH connection helpers ────────────────────────────────────────────────────

/// Bound on the TCP connect to sshd (per resolved address).
const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// libssh2 blocking-call timeout during handshake + authentication.
const SSH_HANDSHAKE_TIMEOUT_MS: u32 = 30_000;
/// libssh2 blocking-call timeout once the session is up (one SFTP write may
/// legitimately take a while on a congested link, but never minutes).
const SSH_IO_TIMEOUT_MS: u32 = 120_000;

/// Shown on connection failures: what the SFTP path does *not* support.
const SSH_CONFIG_LIMITATION: &str = "note: the SFTP fallback connects to the \
     destination host directly and does not read ~/.ssh/config (HostName, Port, \
     ProxyJump/ProxyCommand are ignored); use ssh://user@host:port/path for a \
     non-default port";

/// Open a new authenticated SSH session to `dest.host` (port `dest.port`,
/// default 22).
fn ssh_connect(dest: &SshDest) -> Result<Session> {
    let port = dest.port.unwrap_or(22);
    let tcp = tcp_connect_timeout(&dest.host, port).with_context(|| {
        format!(
            "TCP connect to {}:{port}\n{SSH_CONFIG_LIMITATION}",
            dest.host
        )
    })?;
    let mut sess = Session::new().context("create SSH session")?;
    sess.set_timeout(SSH_HANDSHAKE_TIMEOUT_MS);
    sess.set_tcp_stream(tcp);

    let known_hosts = read_known_hosts(&dest.host)?;
    let lookup = known_hosts_name(&dest.host, port);
    // Ask for a host key type we actually have on file for this host (like
    // OpenSSH does), so a host known only by e.g. its RSA key is not reported
    // as a key mismatch just because ed25519 was negotiated.
    sess.method_pref(
        MethodType::HostKey,
        &host_key_preference(&known_hosts, &lookup),
    )
    .context("set host key preference")?;
    sess.handshake().context("SSH handshake")?;

    verify_host_key(&sess, &known_hosts, &lookup)?;
    authenticate(&sess, &dest.user)?;
    sess.set_timeout(SSH_IO_TIMEOUT_MS);

    Ok(sess)
}

/// Resolve `host:port` and connect to the first reachable address, bounding
/// each attempt by [`SSH_CONNECT_TIMEOUT`].
fn tcp_connect_timeout(host: &str, port: u16) -> Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}"))?
        .collect();
    let mut last_err = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, SSH_CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(anyhow::Error::new(e).context(format!("connect {addr}"))),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no addresses found for {host}")))
}

/// Read `~/.ssh/known_hosts`, failing clearly when it (or `$HOME`) is absent.
fn read_known_hosts(host: &str) -> Result<String> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        anyhow::anyhow!("$HOME is not set — cannot locate ~/.ssh/known_hosts to verify {host}")
    })?;
    let kh_path = Path::new(&home).join(".ssh").join("known_hosts");
    if !kh_path.exists() {
        bail!(
            "~/.ssh/known_hosts not found — run `ssh {host}` once to accept \
             the host key before using the SFTP fallback path"
        );
    }
    std::fs::read_to_string(&kh_path).context("read ~/.ssh/known_hosts")
}

/// The name a host is recorded under in known_hosts: the bare (lowercased)
/// host for port 22, `[host]:port` otherwise.
fn known_hosts_name(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

/// Host-key algorithms we offer, in default preference order.
const DEFAULT_HOST_KEY_PREF: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
];

/// Build the HostKey method preference: algorithms for key types already in
/// known_hosts for `lookup` first (file order), then the remaining defaults.
fn host_key_preference(known_hosts: &str, lookup: &str) -> String {
    let mut pref: Vec<&str> = Vec::new();
    for entry in known_hosts.lines().filter_map(parse_known_hosts_line) {
        if entry.marker.is_some() || !host_patterns_match(entry.hosts, lookup) {
            continue;
        }
        let algs: &[&str] = match entry.key_type {
            "ssh-rsa" => &["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
            t => match DEFAULT_HOST_KEY_PREF.iter().find(|&&d| d == t) {
                Some(d) => std::slice::from_ref(d),
                None => &[],
            },
        };
        for a in algs {
            if !pref.contains(a) {
                pref.push(a);
            }
        }
    }
    for d in DEFAULT_HOST_KEY_PREF {
        if !pref.contains(d) {
            pref.push(d);
        }
    }
    pref.join(",")
}

/// One parsed known_hosts line.
struct KnownHostsEntry<'a> {
    /// `@cert-authority` / `@revoked`, if present.
    marker: Option<&'a str>,
    hosts: &'a str,
    key_type: &'a str,
    key_b64: &'a str,
}

/// Parse a known_hosts line (`[@marker] hosts keytype base64 [comment…]`),
/// splitting on any whitespace.  Returns `None` for blank/comment lines and
/// lines with too few fields.
fn parse_known_hosts_line(line: &str) -> Option<KnownHostsEntry<'_>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut it = line.split_whitespace();
    let mut first = it.next()?;
    let marker = if first.starts_with('@') {
        let m = first;
        first = it.next()?;
        Some(m)
    } else {
        None
    };
    Some(KnownHostsEntry {
        marker,
        hosts: first,
        key_type: it.next()?,
        key_b64: it.next()?,
    })
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .ok()
}

/// The key-type string embedded at the start of an SSH wire-format public key.
fn wire_key_type(key: &[u8]) -> Option<&str> {
    let len = u32::from_be_bytes(key.get(..4)?.try_into().ok()?) as usize;
    std::str::from_utf8(key.get(4..4 + len)?).ok()
}

/// Outcome of checking a host key against known_hosts.
#[derive(Debug, PartialEq, Eq)]
enum HostKeyCheck {
    /// A matching entry carries exactly this key.
    Trusted,
    /// The key appears on an `@revoked` line.
    Revoked,
    /// The host has an entry of the *same* key type with a different key —
    /// the host key changed (possible MITM).
    Changed,
    /// The host is known, but only under other key types.
    OtherTypes(Vec<String>),
    /// No entry for this host.
    Unknown,
}

/// Check `key` (SSH wire format) for host `lookup` against known_hosts text.
///
/// * Lines are split on any whitespace (tabs included) and trailing comments
///   are ignored; plain, wildcard (`*`/`?`), negated (`!pat`), `[host]:port`
///   and hashed (`|1|salt|hmac`) host fields are supported.
/// * `@revoked` lines are a hard failure if they carry this key, regardless
///   of host pattern; `@cert-authority` lines are skipped (host certificates
///   are not supported by this path).
/// * A line whose key fails to decode is skipped with a warning — it can
///   never count as a mismatch.
fn check_known_hosts(content: &str, lookup: &str, key: &[u8]) -> HostKeyCheck {
    let key_type = wire_key_type(key).unwrap_or("");
    let mut trusted = false;
    let mut changed = false;
    let mut other_types: Vec<String> = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        let Some(entry) = parse_known_hosts_line(line) else {
            continue;
        };
        let Some(stored) = decode_b64(entry.key_b64) else {
            tracing::warn!(
                "~/.ssh/known_hosts line {}: undecodable key — skipped",
                lineno + 1
            );
            continue;
        };
        match entry.marker {
            Some("@revoked") => {
                if stored == key {
                    return HostKeyCheck::Revoked;
                }
                continue;
            }
            Some(_) => continue, // @cert-authority or unknown marker
            None => {}
        }
        if !host_patterns_match(entry.hosts, lookup) {
            continue;
        }
        if stored == key {
            trusted = true;
        } else if wire_key_type(&stored).unwrap_or(entry.key_type) == key_type {
            changed = true;
        } else if !other_types.iter().any(|t| t == entry.key_type) {
            other_types.push(entry.key_type.to_owned());
        }
    }

    // Like OpenSSH, any matching line is enough (a host may legitimately have
    // several same-type entries, e.g. after a key rotation).
    if trusted {
        HostKeyCheck::Trusted
    } else if changed {
        HostKeyCheck::Changed
    } else if !other_types.is_empty() {
        HostKeyCheck::OtherTypes(other_types)
    } else {
        HostKeyCheck::Unknown
    }
}

/// Check the remote host key against `~/.ssh/known_hosts`.
///
/// Bypasses libssh2's `KnownHosts` API (which has subtle key-type-matching
/// issues) and directly compares the raw wire-format key bytes from the
/// session against the base64-decoded entries; see [`check_known_hosts`].
///
/// Rejects connections if the key is unknown (run `ssh <host>` once), has
/// changed (possible MITM), or is revoked.
fn verify_host_key(sess: &Session, known_hosts: &str, lookup: &str) -> Result<()> {
    let (sess_key, _) = sess
        .host_key()
        .ok_or_else(|| anyhow::anyhow!("remote sent no host key"))?;

    match check_known_hosts(known_hosts, lookup, sess_key) {
        HostKeyCheck::Trusted => Ok(()),
        HostKeyCheck::Revoked => bail!(
            "SSH host key for {lookup} is marked @revoked in ~/.ssh/known_hosts — refusing to connect"
        ),
        HostKeyCheck::Changed => bail!(
            "SSH host key MISMATCH for {lookup} — possible MITM attack; \
             check ~/.ssh/known_hosts"
        ),
        HostKeyCheck::OtherTypes(types) => bail!(
            "SSH host key for {lookup} is of type {} but ~/.ssh/known_hosts only \
             has {} for it — run `ssh {lookup}` to verify and record this key type",
            wire_key_type(sess_key).unwrap_or("?"),
            types.join(", ")
        ),
        HostKeyCheck::Unknown => bail!(
            "SSH host key for {lookup} not found in ~/.ssh/known_hosts — \
             run `ssh {lookup}` once to add it"
        ),
    }
}

/// Does a known_hosts host field (comma-separated patterns, or a hashed
/// `|1|…` entry) match `lookup`?  A matching negated pattern (`!pat`) vetoes.
fn host_patterns_match(field: &str, lookup: &str) -> bool {
    if field.starts_with('|') {
        return host_field_matches_hashed(lookup, field);
    }
    let lookup = lookup.to_ascii_lowercase();
    let mut matched = false;
    for pat in field.split(',') {
        let pat = pat.to_ascii_lowercase();
        if let Some(neg) = pat.strip_prefix('!') {
            if glob_match(neg.as_bytes(), lookup.as_bytes()) {
                return false;
            }
        } else if glob_match(pat.as_bytes(), lookup.as_bytes()) {
            matched = true;
        }
    }
    matched
}

/// Minimal `*`/`?` glob as used by OpenSSH host patterns.
fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob_match(&pat[1..], s) || (!s.is_empty() && glob_match(pat, &s[1..])),
        (Some(b'?'), Some(_)) => glob_match(&pat[1..], &s[1..]),
        (Some(p), Some(c)) if p == c => glob_match(&pat[1..], &s[1..]),
        _ => false,
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
    let (Some(salt), Some(expected)) = (decode_b64(parts[2]), decode_b64(parts[3])) else {
        return false;
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
    pb.set_style(crate::progress::transfer_style("↑", false));
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_prefix(file_name.to_owned());
    pb
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire-format key blob: string(type) || string(body).
    fn blob(key_type: &str, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        v.extend_from_slice(key_type.as_bytes());
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    fn hashed_field(host: &str, salt: &[u8]) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(salt).unwrap();
        mac.update(host.as_bytes());
        format!(
            "|1|{}|{}",
            STANDARD.encode(salt),
            STANDARD.encode(mac.finalize().into_bytes())
        )
    }

    #[test]
    fn tabs_comments_and_ports() {
        let key = blob("ssh-ed25519", b"good");
        let b64 = STANDARD.encode(&key);
        let kh = format!(
            "# comment\n\nexample.com\tssh-ed25519\t{b64}\tuser@laptop extra words\n\
             [example.com]:2222 ssh-ed25519 {b64}\n"
        );
        assert_eq!(
            check_known_hosts(&kh, &known_hosts_name("Example.COM", 22), &key),
            HostKeyCheck::Trusted
        );
        assert_eq!(
            check_known_hosts(&kh, &known_hosts_name("example.com", 2222), &key),
            HostKeyCheck::Trusted
        );
        // Port 2200 has no entry.
        assert_eq!(
            check_known_hosts(&kh, &known_hosts_name("example.com", 2200), &key),
            HostKeyCheck::Unknown
        );
    }

    #[test]
    fn hashed_wildcard_and_negation() {
        let key = blob("ssh-ed25519", b"good");
        let b64 = STANDARD.encode(&key);
        let kh = format!(
            "{} ssh-ed25519 {b64}\n*.lan,!evil.lan ssh-ed25519 {b64}\n",
            hashed_field("[h.example]:2222", b"saltsaltsaltsaltsalt")
        );
        assert_eq!(
            check_known_hosts(&kh, "[h.example]:2222", &key),
            HostKeyCheck::Trusted
        );
        assert_eq!(
            check_known_hosts(&kh, "nas.lan", &key),
            HostKeyCheck::Trusted
        );
        assert_eq!(
            check_known_hosts(&kh, "evil.lan", &key),
            HostKeyCheck::Unknown
        );
    }

    #[test]
    fn mismatch_revoked_and_other_types() {
        let good = blob("ssh-ed25519", b"good");
        let bad = blob("ssh-ed25519", b"attacker");
        let rsa = blob("ssh-rsa", b"rsa-key");
        let kh = format!(
            "host ssh-ed25519 {}\nrsaonly ssh-rsa {}\n",
            STANDARD.encode(&good),
            STANDARD.encode(&rsa)
        );
        assert_eq!(check_known_hosts(&kh, "host", &bad), HostKeyCheck::Changed);
        assert_eq!(
            check_known_hosts(&kh, "rsaonly", &good),
            HostKeyCheck::OtherTypes(vec!["ssh-rsa".into()])
        );

        // @revoked wins even when a matching trusted line is present.
        let revoked = format!(
            "host ssh-ed25519 {g}\n@revoked * ssh-ed25519 {g}\n",
            g = STANDARD.encode(&good)
        );
        assert_eq!(
            check_known_hosts(&revoked, "host", &good),
            HostKeyCheck::Revoked
        );
        // @cert-authority lines are not treated as host keys.
        let ca = format!(
            "@cert-authority host ssh-ed25519 {}\n",
            STANDARD.encode(&good)
        );
        assert_eq!(check_known_hosts(&ca, "host", &good), HostKeyCheck::Unknown);
    }

    /// An undecodable key must not be read as an empty key → false MITM.
    #[test]
    fn undecodable_line_is_skipped_not_mismatch() {
        let key = blob("ssh-ed25519", b"good");
        let kh = "host ssh-ed25519 !!!not-base64!!!\n";
        assert_eq!(check_known_hosts(kh, "host", &key), HostKeyCheck::Unknown);
        let kh = format!(
            "host ssh-ed25519 %%%\nhost ssh-ed25519 {}\n",
            STANDARD.encode(&key)
        );
        assert_eq!(check_known_hosts(&kh, "host", &key), HostKeyCheck::Trusted);
    }

    #[test]
    fn preference_puts_known_types_first() {
        let kh = format!(
            "other ssh-ed25519 {k}\nhost ssh-rsa {k}\n",
            k = STANDARD.encode(blob("x", b"y"))
        );
        let pref = host_key_preference(&kh, "host");
        assert!(
            pref.starts_with("rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-ed25519"),
            "{pref}"
        );
        // Unknown host → plain defaults.
        assert_eq!(
            host_key_preference(&kh, "nobody"),
            DEFAULT_HOST_KEY_PREF.join(",")
        );
    }

    #[test]
    fn glob_basics() {
        assert!(glob_match(b"*", b"anything"));
        assert!(glob_match(b"10.0.0.?", b"10.0.0.7"));
        assert!(!glob_match(b"10.0.0.?", b"10.0.0.17"));
        assert!(glob_match(b"*.example.com", b"a.b.example.com"));
        assert!(!glob_match(b"*.example.com", b"example.com"));
    }
}
