//! Per-peer access control and quotas (mftp v2, milestone M8).
//!
//! Extends the M4 authorized-devices allowlist into a richer policy: each
//! authorized sender DeviceId maps to an **output subdirectory** (so peers are
//! isolated from one another) and an optional **byte quota** (a cap on how much
//! that peer may write). Stored as TOML at `~/.config/mftp/acl.toml`.
//!
//! A peer absent from the ACL is denied when ACLs are in force; the empty ACL
//! means "no policy" (the daemon falls back to the open / M4-allowlist model).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Policy for one authorized peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerPolicy {
    /// Output subdirectory (relative to the daemon's output root) this peer's
    /// files land in. Keeps tenants isolated.
    pub output_subdir: String,
    /// Maximum total bytes this peer may write; `None` = unlimited.
    pub quota_bytes: Option<u64>,
}

/// The full ACL: DeviceId → policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acl {
    #[serde(default)]
    pub peers: BTreeMap<String, PeerPolicy>,
}

impl Acl {
    /// Load the ACL from `dir/acl.toml` (empty if absent).
    ///
    /// The loaded ACL is [validated](Acl::validated): DeviceId keys are
    /// normalized (trim + lowercase, as the TLS allowlist does) and each
    /// peer's `output_subdir` must be a distinct, non-overlapping relative
    /// path. Any violation is an error — the daemon never runs with an ACL it
    /// only partly understood.
    pub fn load(dir: &Path) -> Result<Acl> {
        let path = acl_path(dir);
        match std::fs::read_to_string(&path) {
            Ok(s) => toml::from_str::<Acl>(&s)
                .with_context(|| format!("parse {}", path.display()))?
                .validated()
                .with_context(|| format!("invalid {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Acl::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    /// Normalize and validate an ACL:
    ///   * keys are trimmed + lower-cased and must be 64-hex DeviceIds; two keys
    ///     that normalize to the same id are rejected;
    ///   * every `output_subdir` must be a non-empty relative path with no `.` /
    ///     `..` components;
    ///   * no peer's subdir may equal, contain, or be contained in another's —
    ///     otherwise one tenant could read/overwrite (and be quota-charged for)
    ///     another's files.
    pub fn validated(self) -> Result<Acl> {
        let mut peers = BTreeMap::new();
        let mut dirs: Vec<(String, Vec<String>)> = Vec::new();
        for (raw_id, policy) in self.peers {
            let id = raw_id.trim().to_lowercase();
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                anyhow::bail!("ACL peer {raw_id:?} is not a DeviceId (expected 64 hex chars)");
            }
            let comps = subdir_components(&policy.output_subdir)
                .with_context(|| format!("ACL peer {id}"))?;
            for (other, other_comps) in &dirs {
                let n = comps.len().min(other_comps.len());
                if comps[..n] == other_comps[..n] {
                    anyhow::bail!(
                        "ACL output_subdir {:?} of {id} overlaps that of {other} — each \
                         peer needs its own, non-nested directory",
                        policy.output_subdir
                    );
                }
            }
            dirs.push((id.clone(), comps));
            if peers.insert(id.clone(), policy).is_some() {
                anyhow::bail!("ACL lists device {id} more than once");
            }
        }
        Ok(Acl { peers })
    }

    /// Persist the ACL to `dir/acl.toml`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let body = toml::to_string_pretty(self).context("serialize acl")?;
        std::fs::write(acl_path(dir), body).context("write acl.toml")?;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Look up a peer's policy by DeviceId.
    pub fn policy(&self, device_id: &str) -> Option<&PeerPolicy> {
        self.peers.get(&device_id.to_lowercase())
    }

    /// Authorized DeviceIds (for handing to the mutual-TLS verifier).
    pub fn authorized_ids(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }

    /// Resolve where a peer's files should be written, under `output_root`.
    /// Rejects subdir values containing traversal components.
    pub fn output_dir_for(&self, output_root: &Path, device_id: &str) -> Result<PathBuf> {
        let policy = self
            .policy(device_id)
            .with_context(|| format!("device {device_id} is not in the ACL"))?;
        let sub = Path::new(&policy.output_subdir);
        if sub.is_absolute()
            || sub
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            anyhow::bail!("ACL output_subdir for {device_id} must be a relative path with no `..`");
        }
        Ok(output_root.join(sub))
    }

    /// Check a proposed transfer size against the peer's quota.
    /// `already_used` is the peer's existing on-disk usage.
    pub fn check_quota(&self, device_id: &str, already_used: u64, incoming: u64) -> Result<()> {
        if let Some(p) = self.policy(device_id) {
            if let Some(limit) = p.quota_bytes {
                let total = already_used.saturating_add(incoming);
                if total > limit {
                    anyhow::bail!(
                        "transfer would exceed {device_id}'s quota \
                         ({total} > {limit} bytes)"
                    );
                }
            }
        }
        Ok(())
    }

    pub fn set_peer(&mut self, device_id: &str, policy: PeerPolicy) {
        self.peers.insert(device_id.to_lowercase(), policy);
    }

    pub fn remove_peer(&mut self, device_id: &str) -> bool {
        self.peers.remove(&device_id.to_lowercase()).is_some()
    }
}

/// Split an `output_subdir` into its normal components, rejecting empty, `.`,
/// absolute, and `..`-containing paths.
fn subdir_components(sub: &str) -> Result<Vec<String>> {
    use std::path::Component;
    let mut out = Vec::new();
    for c in Path::new(sub.trim()).components() {
        match c {
            Component::Normal(s) => out.push(s.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => {
                anyhow::bail!("output_subdir {sub:?} must be a relative path with no `..` or root")
            }
        }
    }
    if out.is_empty() {
        anyhow::bail!(
            "output_subdir {sub:?} must name a subdirectory (empty or `.` would share the \
             output root with every peer)"
        );
    }
    Ok(out)
}

fn acl_path(dir: &Path) -> PathBuf {
    dir.join("acl.toml")
}

/// A live, reloadable [`Acl`] shared between the daemon's connection router and
/// the SIGHUP reload path.
///
/// The router reads the *current* ACL on every connection (under a read lock),
/// so the daemon can swap a fresh ACL in place (on SIGHUP) and have new per-peer
/// output dirs / quotas take effect for subsequent connections without
/// rebinding. Cheap to clone (an `Arc`).
#[derive(Clone, Default)]
pub struct ReloadableAcl {
    inner: Arc<RwLock<Acl>>,
}

impl ReloadableAcl {
    pub fn new(acl: Acl) -> Self {
        ReloadableAcl {
            inner: Arc::new(RwLock::new(acl)),
        }
    }

    /// Replace the entire ACL (the SIGHUP-reload operation).
    pub fn replace(&self, acl: Acl) {
        *self.inner.write().expect("acl lock poisoned") = acl;
    }

    /// True when no peer policy is configured (the daemon is in open / allowlist
    /// mode rather than ACL tenant-isolation mode).
    pub fn is_empty(&self) -> bool {
        self.inner.read().expect("acl lock poisoned").is_empty()
    }

    /// Run `f` against the current ACL under a read lock. Used by the router to
    /// resolve a peer's output dir + quota from a consistent snapshot.
    pub fn with<R>(&self, f: impl FnOnce(&Acl) -> R) -> R {
        f(&self.inner.read().expect("acl lock poisoned"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(sub: &str, quota: Option<u64>) -> PeerPolicy {
        PeerPolicy {
            output_subdir: sub.to_string(),
            quota_bytes: quota,
        }
    }

    #[test]
    fn acl_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut acl = Acl::default();
        acl.set_peer(&"a".repeat(64), policy("alice", Some(1_000_000)));
        acl.set_peer(&"b".repeat(64), policy("bob", None));
        acl.save(dir.path()).unwrap();

        let loaded = Acl::load(dir.path()).unwrap();
        assert_eq!(loaded, acl);
        assert_eq!(loaded.authorized_ids().len(), 2);
    }

    #[test]
    fn output_dir_isolates_peers_and_blocks_traversal() {
        let mut acl = Acl::default();
        acl.set_peer(&"a".repeat(64), policy("alice", None));
        acl.set_peer(&"x".repeat(64), policy("../escape", None));
        let root = Path::new("/data");
        assert_eq!(
            acl.output_dir_for(root, &"a".repeat(64)).unwrap(),
            Path::new("/data/alice")
        );
        assert!(acl.output_dir_for(root, &"x".repeat(64)).is_err());
        // Unknown device → denied.
        assert!(acl.output_dir_for(root, &"z".repeat(64)).is_err());
    }

    fn load_str(body: &str) -> Result<Acl> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("acl.toml"), body).unwrap();
        Acl::load(dir.path())
    }

    #[test]
    fn load_normalizes_keys() {
        let upper = "AB".repeat(32);
        let acl = load_str(&format!(
            "[peers.\" {upper} \"]\noutput_subdir = \"alice\"\n"
        ))
        .unwrap();
        assert_eq!(acl.authorized_ids(), vec!["ab".repeat(32)]);
        assert!(acl.policy(&upper).is_some());
    }

    #[test]
    fn load_rejects_bad_subdirs_and_ids() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let one = |sub: &str| format!("[peers.{a}]\noutput_subdir = {sub:?}\n");
        for bad in ["", ".", "./", "../x", "/abs"] {
            assert!(
                load_str(&one(bad)).is_err(),
                "subdir {bad:?} must be rejected"
            );
        }
        let two = |sa: &str, sb: &str| {
            format!("[peers.{a}]\noutput_subdir = {sa:?}\n[peers.{b}]\noutput_subdir = {sb:?}\n")
        };
        assert!(load_str(&two("alice", "bob")).is_ok());
        assert!(load_str(&two("alice", "alice")).is_err(), "same dir");
        assert!(load_str(&two("alice", "alice/sub")).is_err(), "nested");
        assert!(
            load_str(&two("./alice/", "alice")).is_err(),
            "normalized equal"
        );
        assert!(
            load_str(&two("alice", "alicex")).is_ok(),
            "prefix by chars only"
        );
        // Duplicate after normalization.
        let dup = format!(
            "[peers.{a}]\noutput_subdir = \"x\"\n[peers.\"{}\"]\noutput_subdir = \"y\"\n",
            a.to_uppercase()
        );
        assert!(load_str(&dup).is_err(), "case-duplicate ids");
        assert!(load_str("[peers.notanid]\noutput_subdir = \"x\"\n").is_err());
    }

    #[test]
    fn quota_enforced() {
        let mut acl = Acl::default();
        acl.set_peer(&"a".repeat(64), policy("alice", Some(1000)));
        // Under quota.
        assert!(acl.check_quota(&"a".repeat(64), 500, 400).is_ok());
        // Over quota.
        assert!(acl.check_quota(&"a".repeat(64), 500, 600).is_err());
        // No policy / unlimited → always ok.
        assert!(acl.check_quota(&"unknown".repeat(8), 0, u64::MAX).is_ok());
    }
}
