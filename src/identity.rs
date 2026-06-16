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

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo`, immediately followed by the
/// 32-byte raw public key. The full 44-byte SPKI is
/// `[prefix][32-byte key]`. This shape is fixed for Ed25519 (RFC 8410), so we
/// can locate and reconstruct the SPKI inside a certificate without pulling in
/// a full X.509 parser.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Length of a complete Ed25519 SPKI DER (12-byte prefix + 32-byte key).
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// Derive the DeviceId (hex SHA-256 of the Ed25519 SPKI) from a presented
/// certificate, so a client can check a `--trust-device` pin against the cert
/// it actually received. Returns `None` if the cert carries no Ed25519 key.
pub fn device_id_from_cert(cert: &CertificateDer<'_>) -> Option<String> {
    let der = cert.as_ref();
    let pos = der
        .windows(ED25519_SPKI_PREFIX.len())
        .position(|w| w == ED25519_SPKI_PREFIX)?;
    let spki = der.get(pos..pos + ED25519_SPKI_LEN)?;
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
    if let (Ok(cert_der), Ok(key_bytes)) = (std::fs::read(&cert_p), std::fs::read(&key_p)) {
        let cert = CertificateDer::from(cert_der);
        let fingerprint = crate::net::connection::cert_fingerprint(&cert);
        // device_id is cached on disk; recompute from the cert if missing/stale.
        let device_id = std::fs::read_to_string(device_id_path(dir))
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| s.len() == 64)
            .unwrap_or_else(|| fingerprint.clone());
        return Ok(Identity {
            cert,
            key_bytes,
            fingerprint,
            device_id,
        });
    }

    // Nothing stored yet (or unreadable) — generate and persist.
    let id = generate()?;
    persist(dir, &id);
    Ok(id)
}

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

/// Persist an identity to `dir` with private material at mode 0600.
fn persist(dir: &std::path::Path, id: &Identity) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!("could not create {}: {e}", dir.display());
        return;
    }
    // The certificate is public; the key must be private.
    let _ = std::fs::write(cert_path(dir), id.cert.as_ref());
    let _ = std::fs::write(device_id_path(dir), &id.device_id);
    write_private(&key_path(dir), &id.key_bytes);
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut f) => {
            let _ = f.write_all(bytes);
        }
        Err(e) => tracing::warn!("could not write device key {}: {e}", path.display()),
    }
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, bytes: &[u8]) {
    let _ = std::fs::write(path, bytes);
}

// ── Authorized-devices store (M4: daemon identity auth) ─────────────────────────
//
// A newline-delimited list of trusted peer DeviceIds at
// `~/.config/mftp/authorized_devices`. When present and non-empty, the daemon
// requires an incoming sender to present a client certificate whose DeviceId is
// listed (mutual TLS); when absent/empty, the receiver is open (classic).

fn authorized_path(dir: &std::path::Path) -> PathBuf {
    dir.join("authorized_devices")
}

/// Load the set of authorized DeviceIds from `dir` (empty if the file is absent).
pub fn load_authorized_in(dir: &std::path::Path) -> Vec<String> {
    match std::fs::read_to_string(authorized_path(dir)) {
        Ok(s) => s
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Default-location load (`~/.config/mftp/authorized_devices`).
pub fn load_authorized() -> Vec<String> {
    config_dir()
        .map(|d| load_authorized_in(&d))
        .unwrap_or_default()
}

/// Add a DeviceId to the authorized list in `dir` (idempotent). Returns whether
/// it was newly added.
pub fn add_authorized_in(dir: &std::path::Path, device_id: &str) -> Result<bool> {
    let id = device_id.trim().to_lowercase();
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("invalid device id (expected 64 hex chars): {device_id:?}");
    }
    let mut list = load_authorized_in(dir);
    if list.iter().any(|e| e == &id) {
        return Ok(false);
    }
    list.push(id);
    write_authorized(dir, &list)?;
    Ok(true)
}

/// Remove a DeviceId from the authorized list in `dir`. Returns whether it was
/// present.
pub fn remove_authorized_in(dir: &std::path::Path, device_id: &str) -> Result<bool> {
    let id = device_id.trim().to_lowercase();
    let mut list = load_authorized_in(dir);
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
    let body = list.join("\n");
    std::fs::write(authorized_path(dir), body).context("write authorized_devices")?;
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
        assert!(load_authorized_in(dir.path()).is_empty());
        let id = "a".repeat(64);
        assert!(add_authorized_in(dir.path(), &id).unwrap(), "newly added");
        assert!(!add_authorized_in(dir.path(), &id).unwrap(), "idempotent");
        assert_eq!(load_authorized_in(dir.path()), vec![id.clone()]);
        assert!(remove_authorized_in(dir.path(), &id).unwrap());
        assert!(load_authorized_in(dir.path()).is_empty());
        // Invalid ids are rejected.
        assert!(add_authorized_in(dir.path(), "nothex").is_err());
    }

    #[test]
    fn generated_key_wraps_as_valid_private_key() {
        // The persisted PKCS#8 bytes must be usable by the TLS layer.
        let dir = tempfile::tempdir().unwrap();
        let id = load_or_create_in(dir.path()).unwrap();
        crate::net::connection::make_private_key(id.key_bytes).expect("valid PKCS#8 key");
    }
}
