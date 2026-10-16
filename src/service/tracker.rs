//! Feeds received transfers into the persistent [`Queue`] and applies at-rest
//! encryption — the daemon's [`TransferObserver`].
//!
//! Every admitted transfer becomes a job (`Active` → `Completed`/`Failed`) in
//! `queue.json`, which the HTTP `/queue` endpoint and Web UI report (from the
//! in-memory copy). Saves happen on a background writer, off the async workers
//! and outside the queue lock, coalescing bursts of updates (at most one save
//! per [`SAVE_DEBOUNCE`]).
//! With an at-rest key, each received file is encrypted (`<name>.enc`, see
//! [`crate::service::encrypt`]) before the job is marked completed; a failure
//! to encrypt fails the job and is logged (the verified plaintext is left in
//! place rather than lost).

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::service::encrypt;
use crate::service::queue::Queue;
use crate::transfer::receiver::{TransferJob, TransferObserver};

/// Finished jobs kept in `queue.json`; older ones are pruned.
const KEEP_FINISHED: usize = 500;

/// Minimum interval between saves of `queue.json` (updates in between are
/// coalesced into the next save).
const SAVE_DEBOUNCE: Duration = Duration::from_millis(250);

/// Shared job bookkeeping for one daemon.
pub struct JobTracker {
    config_dir: PathBuf,
    encrypt_key: Option<[u8; 32]>,
    queue: Mutex<Queue>,
    /// Wakes the background writer; a permit is kept if it is busy, so no
    /// update is ever left unsaved.
    dirty: Arc<tokio::sync::Notify>,
}

impl JobTracker {
    /// Load `config_dir/queue.json`, marking jobs a previous process left
    /// active as failed. An unreadable queue is set aside (renamed to
    /// `queue.json.corrupt`) rather than blocking startup: it is bookkeeping,
    /// not policy. Must be called inside a Tokio runtime (it spawns the writer).
    pub fn load(config_dir: &Path, encrypt_key: Option<[u8; 32]>) -> Arc<JobTracker> {
        let mut queue = match Queue::load(config_dir) {
            Ok(q) => q,
            Err(e) => {
                let path = config_dir.join("queue.json");
                let aside = config_dir.join("queue.json.corrupt");
                tracing::warn!(
                    "transfer queue unreadable ({e:#}); moving it to {} and starting fresh",
                    aside.display()
                );
                let _ = std::fs::rename(&path, &aside);
                Queue::default()
            }
        };
        queue.fail_interrupted();
        queue.prune_finished(KEEP_FINISHED);
        let tracker = Arc::new(JobTracker {
            config_dir: config_dir.to_path_buf(),
            encrypt_key,
            queue: Mutex::new(queue),
            dirty: Arc::new(tokio::sync::Notify::new()),
        });
        tokio::spawn(write_loop(
            Arc::downgrade(&tracker),
            Arc::clone(&tracker.dirty),
        ));
        tracker.dirty.notify_one();
        tracker
    }

    /// The current queue (as the HTTP API reports it).
    pub fn snapshot(&self) -> Queue {
        self.queue
            .lock()
            .expect("job tracker mutex poisoned")
            .clone()
    }

    /// Save the queue now (e.g. at shutdown), on a blocking thread.
    pub async fn flush(&self) {
        let snapshot = self.snapshot();
        let dir = self.config_dir.clone();
        match tokio::task::spawn_blocking(move || snapshot.save(&dir)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("could not save transfer queue: {e:#}"),
            Err(e) => tracing::warn!("transfer queue save task failed: {e}"),
        }
    }

    /// Record a connection refused before its transfer started (e.g. a peer
    /// already over quota), so operators can see why uploads aren't landing.
    pub fn record_refused(&self, peer: &str, error: &str) {
        self.update(|q| {
            let id = q.enqueue(peer, "(connection refused)", 0);
            let _ = q.fail(id, error);
        });
    }

    /// Whether received files are encrypted at rest.
    pub fn encrypts(&self) -> bool {
        self.encrypt_key.is_some()
    }

    /// The observer to attach to a connection from `peer` (a DeviceId, or a
    /// placeholder when the peer presented none).
    pub fn observer_for(self: &Arc<Self>, peer: &str) -> Arc<dyn TransferObserver> {
        Arc::new(PeerObserver {
            tracker: Arc::clone(self),
            peer: peer.to_string(),
        })
    }

    /// Apply `f` to the in-memory queue and schedule a save. Never blocks on
    /// I/O, and save failures are only logged: bookkeeping must not fail or
    /// stall a transfer.
    fn update(&self, f: impl FnOnce(&mut Queue)) {
        {
            let mut q = self.queue.lock().expect("job tracker mutex poisoned");
            f(&mut q);
            q.prune_finished(KEEP_FINISHED);
        }
        self.dirty.notify_one();
    }
}

/// Background writer: saves the latest snapshot whenever the queue changes,
/// at most once per [`SAVE_DEBOUNCE`]. Exits when the tracker is dropped.
async fn write_loop(tracker: std::sync::Weak<JobTracker>, dirty: Arc<tokio::sync::Notify>) {
    loop {
        dirty.notified().await;
        let Some(t) = tracker.upgrade() else { return };
        t.flush().await;
        drop(t);
        tokio::time::sleep(SAVE_DEBOUNCE).await;
    }
}

struct PeerObserver {
    tracker: Arc<JobTracker>,
    peer: String,
}

impl TransferObserver for PeerObserver {
    fn started(&self, file_name: &str, total_bytes: u64) -> Arc<dyn TransferJob> {
        let mut id = 0;
        self.tracker.update(|q| {
            id = q.enqueue(&self.peer, file_name, total_bytes);
            let _ = q.start(id);
        });
        Arc::new(TrackedJob {
            tracker: Arc::clone(&self.tracker),
            id,
        })
    }
}

struct TrackedJob {
    tracker: Arc<JobTracker>,
    id: u64,
}

impl TransferJob for TrackedJob {
    fn progress(&self, bytes_done: u64) {
        self.tracker.update(|q| {
            let _ = q.set_progress(self.id, bytes_done);
        });
    }

    fn completed(&self, files: Vec<PathBuf>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let tracker = Arc::clone(&self.tracker);
        let id = self.id;
        Box::pin(async move {
            let outcome = match tracker.encrypt_key {
                Some(key) => tokio::task::spawn_blocking(move || encrypt_all(&key, &files))
                    .await
                    .unwrap_or_else(|e| Err(format!("encryption task failed: {e}"))),
                None => Ok(()),
            };
            match outcome {
                Ok(()) => tracker.update(|q| {
                    let _ = q.finish(id, true);
                }),
                Err(e) => {
                    tracing::error!("job {id}: {e}");
                    tracker.update(|q| {
                        let _ = q.fail(id, &e);
                    });
                }
            }
        })
    }

    fn failed(&self, error: &str) {
        self.tracker.update(|q| {
            let _ = q.fail(self.id, error);
        });
    }
}

/// Encrypt every file, continuing past failures so one bad file doesn't leave
/// the rest in plaintext; reports all failures together.
///
/// A file whose `<name>.enc` is itself one of the received files is left in
/// plaintext (and reported): encrypting it would replace that other file. An
/// `.enc` left over from an *earlier* transfer is replaced, like any re-sent
/// file.
fn encrypt_all(key: &[u8; 32], files: &[PathBuf]) -> std::result::Result<(), String> {
    let received: HashSet<&Path> = files.iter().map(PathBuf::as_path).collect();
    let errors: Vec<String> = files
        .iter()
        .filter_map(|f| {
            let mut enc = f.as_os_str().to_os_string();
            enc.push(".enc");
            if received.contains(Path::new(&enc)) {
                return Some(format!(
                    "not encrypting {}: its encrypted name collides with received file {}",
                    f.display(),
                    Path::new(&enc).display()
                ));
            }
            encrypt::encrypt_file(key, f)
                .err()
                .map(|e| format!("encrypt {}: {e:#}", f.display()))
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::queue::JobState;
    use anyhow::Result;

    #[tokio::test]
    async fn tracks_lifecycle_and_encrypts_on_completion() -> Result<()> {
        let cfg = tempfile::tempdir()?;
        let out = tempfile::tempdir()?;
        let key = [3u8; 32];
        let tracker = JobTracker::load(cfg.path(), Some(key));
        let obs = tracker.observer_for("peer-a");

        let ok = obs.started("a.bin", 5);
        let f = out.path().join("a.bin");
        std::fs::write(&f, b"hello")?;
        ok.progress(5);
        ok.completed(vec![f.clone()]).await;
        assert!(!f.exists(), "plaintext removed");
        let mut plain = Vec::new();
        encrypt::decrypt_stream(
            &key,
            std::fs::File::open(out.path().join("a.bin.enc"))?,
            &mut plain,
        )?;
        assert_eq!(plain, b"hello");

        let bad = obs.started("b.bin", 9);
        bad.failed("connection lost");
        let missing = obs.started("c.bin", 1);
        missing.completed(vec![out.path().join("nope")]).await;

        let q = tracker.snapshot();
        let state = |i: usize| (q.jobs()[i].state, q.jobs()[i].error.clone());
        assert_eq!(q.jobs().len(), 3);
        assert_eq!(q.jobs()[0].peer, "peer-a");
        assert_eq!(q.jobs()[0].bytes_done, 5);
        assert_eq!(state(0), (JobState::Completed, None));
        assert_eq!(state(1).0, JobState::Failed);
        assert_eq!(state(1).1.as_deref(), Some("connection lost"));
        assert_eq!(
            state(2).0,
            JobState::Failed,
            "encryption failure fails the job"
        );

        // Persisted by the writer (flush forces it now); a job left active by
        // a crashed daemon is failed on the next load.
        let _dangling = tracker.observer_for("p").started("d.bin", 1);
        tracker.flush().await;
        assert_eq!(Queue::load(cfg.path())?.jobs().len(), 4);
        let reloaded = JobTracker::load(cfg.path(), None);
        assert_eq!(reloaded.snapshot().jobs()[3].state, JobState::Failed);
        Ok(())
    }

    /// Received `report` and `report.enc`: encrypting `report` would replace
    /// the other received file, so it stays plaintext and the job fails;
    /// `report.enc` itself is still encrypted.
    #[tokio::test]
    async fn encryption_never_overwrites_another_received_file() -> Result<()> {
        let out = tempfile::tempdir()?;
        let key = [4u8; 32];
        let a = out.path().join("report");
        let b = out.path().join("report.enc");
        std::fs::write(&a, b"plain report")?;
        std::fs::write(&b, b"user's own enc file")?;
        let err = encrypt_all(&key, &[a.clone(), b.clone()]).unwrap_err();
        assert!(err.contains("collides"), "{err}");
        assert_eq!(std::fs::read(&a)?, b"plain report");
        let mut plain = Vec::new();
        encrypt::decrypt_stream(
            &key,
            std::fs::File::open(out.path().join("report.enc.enc"))?,
            &mut plain,
        )?;
        assert_eq!(plain, b"user's own enc file");
        Ok(())
    }
}
