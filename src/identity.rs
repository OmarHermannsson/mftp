//! Persistent device identity (mftp v2, milestone M2).
//!
//! Before v2 the receiver minted a fresh self-signed certificate on every
//! startup, so its TOFU fingerprint changed each run — every reconnect to a
//! restarted receiver tripped the "fingerprint mismatch — possible MITM" guard
//! and had to be re-trusted. v2 gives each host a **persistent Ed25519 device
//! key** and a certificate bound to it, both stored under `~/.config/mftp/`.
//! The fingerprint is therefore stable across restarts, and the public key is a
//! stable **DeviceId** that later milestones (rendezvous/relay) use to address
//! and authenticate a peer independently of its current IP.
//!
//! The certificate is still self-signed and verified by TOFU / `--trust`; the
//! only change is that it persists. A v1 sender talking to a v2 receiver sees a
//! perfectly ordinary self-signed cert and trusts it via TOFU exactly as
//! before — the persistence is invisible on the wire.

use anyhow::{Context, Result};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// A persistent device identity: an Ed25519 key, the certificate bound to it,
/// and the identifiers derived from each.
#[derive(Clone)]
pub struct Identity {
    /// DER-encoded self-signed certificate (served to peers).
    pub cert: CertificateDer<'static>,
    /// PKCS#8 DER private-key bytes (wrap via [`crate::net::connection::make_private_key`]).
    pub key_bytes: Vec<u8>,
    /// SHA-256 of the certificate DER, hex — the TOFU/`--trust` fingerprint.
    /// Stable across restarts now that the certificate persists.
    pub fingerprint: String,
    /// SHA-256 of the Ed25519 SubjectPublicKeyInfo, hex — a transport- and
    /// cert-independent stable identifier for this device.
    pub device_id: String,
}

/// The full 44-byte DER of an Ed25519 `SubjectPublicKeyInfo`: a 12-byte prefix
/// (RFC 8410, fixed) immediately followed by the 32-byte raw public key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32; // 44

/// Read one DER TLV from `data`, returning `(tag, content, rest)`.
fn der_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    let first_len = *data.get(1)?;
    let (len, hdr) = if first_len & 0x80 == 0 {
        (first_len as usize, 2)
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None; // unsupported / indefinite length
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | (*data.get(2 + i)? as usize);
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((tag, &data[hdr..end], &data[end..]))
}

/// Derive the DeviceId (hex SHA-256 of the Ed25519 SubjectPublicKeyInfo) from a
/// presented certificate by **structurally** navigating the X.509 DER to the
/// real `subjectPublicKeyInfo` field — *not* by scanning for a byte pattern,
/// which an attacker could plant earlier in the DER (e.g. in the subject DN) to
/// forge another device's id. Returns `None` if the cert is malformed or carries
/// a non-Ed25519 key.
pub fn device_id_from_cert(cert: &CertificateDer<'_>) -> Option<String> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (_t, cert_seq, _) = der_tlv(cert.as_ref()).filter(|&(t, _, _)| t == 0x30)?;
    // TBSCertificate ::= SEQUENCE { ... }
    let (_t, mut tbs, _) = der_tlv(cert_seq).filter(|&(t, _, _)| t == 0x30)?;

    // Optional [0] EXPLICIT version (context tag 0xA0) comes first when present.
    let (first_tag, _, after_first) = der_tlv(tbs)?;
    if first_tag == 0xA0 {
        tbs = after_first;
    }
    // Skip serialNumber, signature, issuer, validity, subject (5 fields); the
    // next field is subjectPublicKeyInfo.
    for _ in 0..5 {
        let (_t, _c, rest) = der_tlv(tbs)?;
        tbs = rest;
    }
    // subjectPublicKeyInfo: reconstruct its full TLV slice and require it to be
    // exactly the canonical 44-byte Ed25519 SPKI.
    let (spki_tag, _spki_content, rest_after) = der_tlv(tbs)?;
    if spki_tag != 0x30 {
        return None;
    }
    let spki = &tbs[..tbs.len() - rest_after.len()];
    if spki.len() != ED25519_SPKI_LEN || spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return None; // not an Ed25519 SPKI
    }
    Some(hex::encode(Sha256::digest(spki)))
}

/// The mftp config directory (`~/.config/mftp`), where the device identity and
/// authorized-devices list live. `None` if `$HOME` is unset.
pub fn config_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/mftp"))
}

fn cert_path(dir: &std::path::Path) -> PathBuf {
    dir.join("device_cert.der")
}

fn key_path(dir: &std::path::Path) -> PathBuf {
    dir.join("device_key.der")
}

fn device_id_path(dir: &std::path::Path) -> PathBuf {
    dir.join("device_id")
}

/// Load the persistent identity, generating and storing it on first use.
///
/// Falls back to an ephemeral in-memory identity (with a warning) if `$HOME`
/// is unavailable, so the receiver still works in restricted environments —
/// it just won't have a stable fingerprint there.
pub fn load_or_create() -> Result<Identity> {
    match config_dir() {
        Some(dir) => load_or_create_in(&dir),
        None => {
            tracing::warn!(
                "no $HOME — using an ephemeral device identity (fingerprint will change each run)"
            );
            generate()
        }
    }
}

/// Load-or-create within a specific directory (testable seam).
pub fn load_or_create_in(dir: &std::path::Path) -> Result<Identity> {
    let cert_p = cert_path(dir);
    let key_p = key_path(dir);
    let cert_r = read_opt(&cert_p)?;
    let key_r = read_opt(&key_p)?;
    match (cert_r, key_r) {
        (Some(cert_der), Some(key_bytes)) => load_existing(dir, cert_der, key_bytes),
        (None, None) => {
            // Nothing stored yet — generate and persist. A persist failure is an
            // error: silently running on a fresh identity every start would
            // change the fingerprint/DeviceId each run and break every pin.
            let id = generate()?;
            persist(dir, &id).with_context(|| {
                format!("could not persist the device identity in {}", dir.display())
            })?;
            Ok(id)
        }
        _ => anyhow::bail!(
            "incomplete device identity in {}: exactly one of {} / {} exists. Restore the \
             missing file, or delete both to generate a new identity (peers that pinned \
             the old one will need to re-trust it)",
            dir.display(),
            cert_p.display(),
            key_p.display()
        ),
    }
}

/// Read a file, mapping only "not found" to `None`; other errors propagate
/// (an unreadable identity must not be mistaken for an absent one and
/// regenerated over).
fn read_opt(path: &std::path::Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Build an [`Identity`] from stored cert + key, verifying they belong together.
fn load_existing(dir: &std::path::Path, cert_der: Vec<u8>, key_bytes: Vec<u8>) -> Result<Identity> {
    check_key_permissions(&key_path(dir));
    let cert = CertificateDer::from(cert_der);
    let fingerprint = crate::net::connection::cert_fingerprint(&cert);
    // Always derive the DeviceId from the certificate's actual Ed25519 SPKI —
    // the on-disk `device_id` file is only a cache for humans/scripts and is
    // never trusted (a stale or edited value would silently break
    // --trust-device pins and daemon allowlists).
    let device_id = device_id_from_cert(&cert).with_context(|| {
        format!(
            "{} is not a valid Ed25519 device certificate",
            cert_path(dir).display()
        )
    })?;
    // The private key must be the one the certificate is bound to.
    let key_pair = rcgen::KeyPair::try_from(key_bytes.as_slice())
        .with_context(|| format!("parse device key {}", key_path(dir).display()))?;
    if hex::encode(Sha256::digest(key_pair.public_key_der())) != device_id {
        anyhow::bail!(
            "device key {} does not match certificate {} — the identity files are \
             inconsistent",
            key_path(dir).display(),
            cert_path(dir).display()
        );
    }
    let cached = std::fs::read_to_string(device_id_path(dir)).ok();
    if cached.as_deref().map(str::trim) != Some(device_id.as_str()) {
        if cached.is_some() {
            tracing::warn!(
                "{} is stale; rewriting it from the certificate",
                device_id_path(dir).display()
            );
        }
        if let Err(e) = write_atomic(&device_id_path(dir), device_id.as_bytes(), 0o644) {
            tracing::warn!("could not refresh {}: {e:#}", device_id_path(dir).display());
        }
    }
    Ok(Identity {
        cert,
        key_bytes,
        fingerprint,
        device_id,
    })
}

/// Warn if the private key is readable by group/other, and tighten it to 0600.
#[cfg(unix)]
fn check_key_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(md) = std::fs::metadata(path) else {
        return;
    };
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        tracing::warn!(
            "device key {} has permissions {mode:o} (readable by others); resetting to 600",
            path.display()
        );
        eprintln!(
            "[mftp] warning: device key {} had permissions {mode:o}; reset to 600. \
             If others could read it, consider regenerating the identity.",
            path.display()
        );
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!("could not chmod {}: {e}", path.display());
        }
    }
}

#[cfg(not(unix))]
fn check_key_permissions(_path: &std::path::Path) {}

/// Generate a fresh persistent-style identity (Ed25519 key + bound cert) in
/// memory, without touching disk.
fn generate() -> Result<Identity> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("generate Ed25519 device key")?;
    // SubjectPublicKeyInfo DER → stable, cert-independent DeviceId.
    let spki = key_pair.public_key_der();
    let device_id = hex::encode(Sha256::digest(&spki));

    let params =
        rcgen::CertificateParams::new(vec!["mftp".to_string()]).context("build cert params")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-sign device cert")?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let fingerprint = crate::net::connection::cert_fingerprint(&cert_der);
    let key_bytes = key_pair.serialize_der();

    Ok(Identity {
        cert: cert_der,
        key_bytes,
        fingerprint,
        device_id,
    })
}

/// Persist an identity to `dir`: the private key atomically at mode 0600 (set
/// on the freshly created file, so it holds even if a key file pre-existed),
/// then the public certificate and the device-id cache.
fn persist(dir: &std::path::Path, id: &Identity) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    write_atomic(&key_path(dir), &id.key_bytes, 0o600).context("write device key")?;
    write_atomic(&cert_path(dir), id.cert.as_ref(), 0o644).context("write device cert")?;
    write_atomic(&device_id_path(dir), id.device_id.as_bytes(), 0o644)
        .context("write device id")?;
    Ok(())
}

// ── Authorized-devices store (M4: daemon identity auth) ─────────────────────────
//
// A newline-delimited list of trusted peer DeviceIds at
// `~/.config/mftp/authorized_devices`. When the file is present the daemon
// requires an incoming sender to present a client certificate whose DeviceId is
// listed (mutual TLS) — an existing-but-empty file denies everyone rather than
// silently re-opening the receiver. Only when the file is absent (and there is
// no `acl.toml`) is the receiver open (classic).

fn authorized_path(dir: &std::path::Path) -> PathBuf {
    dir.join("authorized_devices")
}

/// Load the authorized DeviceIds from `dir`, distinguishing "no allowlist file"
/// (`Ok(None)`) from "allowlist file present" (`Ok(Some(ids))`, possibly empty).
///
/// Only a missing file is treated as absent; any other read error (permissions,
/// I/O) is returned, so a daemon never fails *open* because it could not read
/// its allowlist. Ids are trimmed and lower-cased, matching the TLS verifier.
pub fn load_authorized_opt_in(dir: &std::path::Path) -> Result<Option<Vec<String>>> {
    let path = authorized_path(dir);
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(
            s.lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.to_lowercase())
                .collect(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Load the set of authorized DeviceIds from `dir` (empty if the file is absent).
/// Read errors other than "not found" are propagated.
pub fn load_authorized_in(dir: &std::path::Path) -> Result<Vec<String>> {
    Ok(load_authorized_opt_in(dir)?.unwrap_or_default())
}

/// Default-location load (`~/.config/mftp/authorized_devices`).
pub fn load_authorized() -> Result<Vec<String>> {
    match config_dir() {
        Some(d) => load_authorized_in(&d),
        None => Ok(Vec::new()),
    }
}

/// Add a DeviceId to the authorized list in `dir` (idempotent). Returns whether
/// it was newly added.
pub fn add_authorized_in(dir: &std::path::Path, device_id: &str) -> Result<bool> {
    let id = device_id.trim().to_lowercase();
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("invalid device id (expected 64 hex chars): {device_id:?}");
    }
    let mut list = load_authorized_in(dir)?;
    if list.iter().any(|e| e == &id) {
        return Ok(false);
    }
    list.push(id);
    write_authorized(dir, &list)?;
    Ok(true)
}

/// Remove a DeviceId from the authorized list in `dir`. Returns whether it was
/// present.
///
/// Removing the last device leaves an *empty* allowlist file, which keeps the
/// daemon enforcing (deny-all) rather than flipping it to open mode. To return
/// to open mode, delete `authorized_devices` explicitly and reload.
pub fn remove_authorized_in(dir: &std::path::Path, device_id: &str) -> Result<bool> {
    let id = device_id.trim().to_lowercase();
    let mut list = load_authorized_in(dir)?;
    let before = list.len();
    list.retain(|e| e != &id);
    let removed = list.len() != before;
    if removed {
        write_authorized(dir, &list)?;
    }
    Ok(removed)
}

fn write_authorized(dir: &std::path::Path, list: &[String]) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let mut body = list.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    write_atomic(&authorized_path(dir), body.as_bytes(), 0o600).context("write authorized_devices")
}

/// Atomically replace `path` with `bytes`: write a sibling temp file (created
/// with `mode` on Unix), fsync it, rename it over `path`, then fsync the parent
/// directory. A crash leaves either the old or the new contents, never a
/// truncated file.
pub(crate) fn write_atomic(path: &std::path::Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let file_name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    // pid + per-process counter keeps concurrent writers from sharing a temp.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tmp_name.push(format!(".tmp.{}.{seq}", std::process::id()));
    let tmp = parent.join(tmp_name);

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let result = (|| -> Result<()> {
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }
    // Persist the rename itself (best-effort: not all platforms can open dirs).
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(parent) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_in(dir.path()).unwrap();
        let second = load_or_create_in(dir.path()).unwrap();
        assert_eq!(
            first.fingerprint, second.fingerprint,
            "a persisted identity must yield the same fingerprint on reload"
        );
        assert_eq!(first.device_id, second.device_id);
        assert_eq!(first.key_bytes, second.key_bytes);
        // Fingerprint and device_id are 64 hex chars (SHA-256).
        assert_eq!(first.fingerprint.len(), 64);
        assert_eq!(first.device_id.len(), 64);
    }

    #[test]
    fn distinct_dirs_yield_distinct_identities() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ia = load_or_create_in(a.path()).unwrap();
        let ib = load_or_create_in(b.path()).unwrap();
        assert_ne!(ia.fingerprint, ib.fingerprint);
        assert_ne!(ia.device_id, ib.device_id);
    }

    /// A DER `tag||len||content` helper (handles short + 1/2-byte long form).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = content.len();
        if n < 128 {
            v.push(n as u8);
        } else if n < 256 {
            v.push(0x81);
            v.push(n as u8);
        } else {
            v.push(0x82);
            v.push((n >> 8) as u8);
            v.push((n & 0xff) as u8);
        }
        v.extend_from_slice(content);
        v
    }

    /// An attacker who plants a valid-looking Ed25519 SPKI earlier in the DER
    /// (e.g. in the subject field) must NOT be able to forge another device's id:
    /// the structural parse hashes the *real* subjectPublicKeyInfo, not the
    /// first byte-pattern match.
    #[test]
    fn device_id_uses_real_spki_not_planted_bytes() {
        let real_spki = {
            let mut v = ED25519_SPKI_PREFIX.to_vec();
            v.extend_from_slice(&[0xBB; 32]);
            v
        };
        let spoof_spki = {
            let mut v = ED25519_SPKI_PREFIX.to_vec();
            v.extend_from_slice(&[0xAA; 32]);
            v
        };

        // TBSCertificate fields (no version): serial, sig, issuer, validity,
        // subject(holding the spoof bytes), subjectPublicKeyInfo(real).
        let mut tbs_content = Vec::new();
        tbs_content.extend(tlv(0x02, &[0x01])); // serialNumber
        tbs_content.extend(tlv(0x30, &[])); // signature alg
        tbs_content.extend(tlv(0x30, &[])); // issuer
        tbs_content.extend(tlv(0x30, &[])); // validity
        tbs_content.extend(tlv(0x30, &spoof_spki)); // subject (contains spoof)
        tbs_content.extend_from_slice(&real_spki); // subjectPublicKeyInfo (real)

        let mut cert_content = Vec::new();
        cert_content.extend(tlv(0x30, &tbs_content)); // tbsCertificate
        cert_content.extend(tlv(0x30, &[])); // signatureAlgorithm
        cert_content.extend(tlv(0x03, &[0x00])); // signatureValue
        let cert_der = tlv(0x30, &cert_content);

        let cert = CertificateDer::from(cert_der);
        let got = device_id_from_cert(&cert).expect("parses to the real SPKI");
        assert_eq!(got, hex::encode(Sha256::digest(&real_spki)));
        assert_ne!(
            got,
            hex::encode(Sha256::digest(&spoof_spki)),
            "must not be fooled by the planted SPKI in the subject"
        );
    }

    #[test]
    fn device_id_recoverable_from_own_cert() {
        // A client must be able to derive the same DeviceId from the cert it is
        // presented as the receiver computed from its key — this is what makes
        // `--trust-device` verifiable at the TLS layer.
        let dir = tempfile::tempdir().unwrap();
        let id = load_or_create_in(dir.path()).unwrap();
        let from_cert = device_id_from_cert(&id.cert).expect("Ed25519 SPKI present in cert");
        assert_eq!(from_cert, id.device_id);
    }

    #[test]
    fn authorized_devices_add_load_remove() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_authorized_in(dir.path()).unwrap().is_empty());
        assert_eq!(load_authorized_opt_in(dir.path()).unwrap(), None);
        let id = "a".repeat(64);
        assert!(add_authorized_in(dir.path(), &id).unwrap(), "newly added");
        assert!(!add_authorized_in(dir.path(), &id).unwrap(), "idempotent");
        assert_eq!(load_authorized_in(dir.path()).unwrap(), vec![id.clone()]);
        assert!(remove_authorized_in(dir.path(), &id).unwrap());
        // The file stays (empty) so a daemon keeps enforcing (deny-all).
        assert_eq!(load_authorized_opt_in(dir.path()).unwrap(), Some(vec![]));
        // Invalid ids are rejected.
        assert!(add_authorized_in(dir.path(), "nothex").is_err());
    }

    #[test]
    fn authorized_load_normalizes_case() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("authorized_devices"),
            format!("  {}  \n# comment\n", "AB".repeat(32)),
        )
        .unwrap();
        assert_eq!(
            load_authorized_in(dir.path()).unwrap(),
            vec!["ab".repeat(32)]
        );
    }

    #[cfg(unix)]
    #[test]
    fn authorized_unreadable_is_error_not_empty() {
        // A directory where the file should be → read fails with a non-NotFound
        // error, which must propagate (fail closed) instead of meaning "open".
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("authorized_devices")).unwrap();
        assert!(load_authorized_in(dir.path()).is_err());
    }

    #[test]
    fn write_atomic_replaces_contents() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        write_atomic(&p, b"one", 0o600).unwrap();
        write_atomic(&p, b"two", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        // No temp files left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn stale_device_id_cache_is_ignored_and_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let id = load_or_create_in(dir.path()).unwrap();
        std::fs::write(dir.path().join("device_id"), "f".repeat(64)).unwrap();
        let again = load_or_create_in(dir.path()).unwrap();
        assert_eq!(again.device_id, id.device_id, "derived from the cert");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("device_id")).unwrap(),
            id.device_id
        );
    }

    #[test]
    fn partial_or_mismatched_identity_is_an_error_not_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        load_or_create_in(dir.path()).unwrap();
        let cert = std::fs::read(dir.path().join("device_cert.der")).unwrap();
        std::fs::remove_file(dir.path().join("device_key.der")).unwrap();
        assert!(load_or_create_in(dir.path()).is_err(), "key missing");
        // The surviving cert was not overwritten by a fresh identity.
        assert_eq!(
            std::fs::read(dir.path().join("device_cert.der")).unwrap(),
            cert
        );

        // A key from another identity does not match the cert.
        let other = tempfile::tempdir().unwrap();
        load_or_create_in(other.path()).unwrap();
        std::fs::copy(
            other.path().join("device_key.der"),
            dir.path().join("device_key.der"),
        )
        .unwrap();
        assert!(load_or_create_in(dir.path()).is_err(), "key/cert mismatch");
    }

    #[cfg(unix)]
    #[test]
    fn key_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        load_or_create_in(dir.path()).unwrap();
        let key = dir.path().join("device_key.der");
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&key), 0o600);
        // Loosened perms are tightened on the next load.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        load_or_create_in(dir.path()).unwrap();
        assert_eq!(mode(&key), 0o600);
    }

    #[test]
    fn generated_key_wraps_as_valid_private_key() {
        // The persisted PKCS#8 bytes must be usable by the TLS layer.
        let dir = tempfile::tempdir().unwrap();
        let id = load_or_create_in(dir.path()).unwrap();
        crate::net::connection::make_private_key(id.key_bytes).expect("valid PKCS#8 key");
    }
}
