//! Feeds received transfers into the persistent [`Queue`] and applies at-rest
//! encryption — the daemon's [`TransferObserver`].
//!
//! Every admitted transfer becomes a job (`Active` → `Completed`/`Failed`) in
//! `queue.json`, which the HTTP `/queue` endpoint and Web UI report. Progress is
//! persisted at most once a second; state changes are persisted immediately.
//! With an at-rest key, each received file is encrypted (`<name>.enc`, see
//! [`crate::service::encrypt`]) before the job is marked completed; a failure
//! to encrypt fails the job and is logged (the verified plaintext is left in
//! place rather than lost).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::service::encrypt;
use crate::service::queue::Queue;
use crate::transfer::receiver::{TransferJob, TransferObserver};

/// Finished jobs kept in `queue.json`; older ones are pruned.
const KEEP_FINISHED: usize = 500;

/// Minimum interval between progress-only saves of `queue.json`.
const PROGRESS_SAVE_EVERY: Duration = Duration::from_secs(1);

/// Shared job bookkeeping for one daemon.
pub struct JobTracker {
    config_dir: PathBuf,
    encrypt_key: Option<[u8; 32]>,
    state: Mutex<TrackerState>,
}

struct TrackerState {
    queue: Queue,
    last_save: Option<Instant>,
}

impl JobTracker {
    /// Load `config_dir/queue.json`, marking jobs a previous process left
    /// active as failed. An unreadable queue is set aside (renamed to
    /// `queue.json.corrupt`) rather than blocking startup: it is bookkeeping,
    /// not policy.
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
            state: Mutex::new(TrackerState {
                queue,
                last_save: None,
            }),
        });
        tracker.update(|_| {}, true);
        tracker
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

    /// Apply `f` to the queue and persist it (`force`, or if the last save is
    /// older than [`PROGRESS_SAVE_EVERY`]). Save failures are logged, never
    /// propagated: bookkeeping must not fail a transfer.
    fn update(&self, f: impl FnOnce(&mut Queue), force: bool) {
        let mut st = self.state.lock().expect("job tracker mutex poisoned");
        f(&mut st.queue);
        let due = st
            .last_save
            .is_none_or(|t| t.elapsed() >= PROGRESS_SAVE_EVERY);
        if force || due {
            if force {
                st.queue.prune_finished(KEEP_FINISHED);
            }
            if let Err(e) = st.queue.save(&self.config_dir) {
                tracing::warn!("could not save transfer queue: {e:#}");
            }
            st.last_save = Some(Instant::now());
        }
    }
}

struct PeerObserver {
    tracker: Arc<JobTracker>,
    peer: String,
}

impl TransferObserver for PeerObserver {
    fn started(&self, file_name: &str, total_bytes: u64) -> Arc<dyn TransferJob> {
        let mut id = 0;
        self.tracker.update(
            |q| {
                id = q.enqueue(&self.peer, file_name, total_bytes);
                let _ = q.start(id);
            },
            true,
        );
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
        self.tracker.update(
            |q| {
                let _ = q.set_progress(self.id, bytes_done);
            },
            false,
        );
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
                Ok(()) => tracker.update(
                    |q| {
                        let _ = q.finish(id, true);
                    },
                    true,
                ),
                Err(e) => {
                    tracing::error!("job {id}: {e}");
                    tracker.update(
                        |q| {
                            let _ = q.fail(id, &e);
                        },
                        true,
                    );
                }
            }
        })
    }

    fn failed(&self, error: &str) {
        self.tracker.update(
            |q| {
                let _ = q.fail(self.id, error);
            },
            true,
        );
    }
}

/// Encrypt every file, continuing past failures so one bad file doesn't leave
/// the rest in plaintext; reports all failures together.
fn encrypt_all(key: &[u8; 32], files: &[PathBuf]) -> std::result::Result<(), String> {
    let errors: Vec<String> = files
        .iter()
        .filter_map(|f| {
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

        let q = Queue::load(cfg.path())?;
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

        // A job left active by a crashed daemon is failed on the next load.
        let _dangling = tracker.observer_for("p").started("d.bin", 1);
        let reloaded = JobTracker::load(cfg.path(), None);
        let st = reloaded.state.lock().unwrap();
        assert_eq!(st.queue.jobs()[3].state, JobState::Failed);
        Ok(())
    }
}
