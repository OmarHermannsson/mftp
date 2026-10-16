//! Persistent transfer queue (mftp v2, milestone M8).
//!
//! A crash-safe, file-backed queue of transfer jobs so the daemon can schedule,
//! retry, and report on transfers across restarts. Stored as JSON at
//! `~/.config/mftp/queue.json`. This is the scheduling/bookkeeping layer; the
//! actual transfer is still performed by the existing engine.
//!
//! The daemon records every received transfer here (see
//! [`crate::service::tracker`]) and the HTTP `/queue` endpoint reports it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Lifecycle state of a queued transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    Queued,
    Active,
    Completed,
    Failed,
}

/// One transfer job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: u64,
    /// Peer DeviceId or address this job is for.
    pub peer: String,
    /// Human-readable description (filename / path).
    pub what: String,
    pub total_bytes: u64,
    pub bytes_done: u64,
    pub state: JobState,
    /// How many times this job has been (re)attempted.
    pub attempts: u32,
    /// Why the job failed, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A persistent FIFO-ish queue of jobs (ordering by ascending id).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Queue {
    next_id: u64,
    jobs: Vec<Job>,
}

impl Queue {
    /// Load from `dir/queue.json` (empty if absent).
    pub fn load(dir: &Path) -> Result<Queue> {
        let path = queue_path(dir);
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("parse {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Queue::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    /// Persist to `dir/queue.json` (atomic: write temp then rename).
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let path = queue_path(dir);
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(self).context("serialize queue")?;
        std::fs::write(&tmp, body).context("write queue tmp")?;
        std::fs::rename(&tmp, &path).context("rename queue into place")?;
        Ok(())
    }

    /// Enqueue a new job; returns its assigned id.
    pub fn enqueue(&mut self, peer: &str, what: &str, total_bytes: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.jobs.push(Job {
            id,
            peer: peer.to_string(),
            what: what.to_string(),
            total_bytes,
            bytes_done: 0,
            state: JobState::Queued,
            attempts: 0,
            error: None,
        });
        id
    }

    /// Record why a job failed (and mark it failed).
    pub fn fail(&mut self, id: u64, error: &str) -> Result<()> {
        let j = self.job_mut(id)?;
        j.state = JobState::Failed;
        j.error = Some(error.to_string());
        Ok(())
    }

    /// Mark jobs left `Active` by a previous process (crash/restart) as failed.
    pub fn fail_interrupted(&mut self) {
        for j in &mut self.jobs {
            if j.state == JobState::Active {
                j.state = JobState::Failed;
                j.error = Some("interrupted (daemon restarted)".to_string());
            }
        }
    }

    /// Drop the oldest finished (completed/failed) jobs beyond `keep`, so the
    /// file doesn't grow without bound on a long-running daemon.
    pub fn prune_finished(&mut self, keep: usize) {
        let finished = |j: &Job| matches!(j.state, JobState::Completed | JobState::Failed);
        let n = self.jobs.iter().filter(|j| finished(j)).count();
        let mut excess = n.saturating_sub(keep);
        self.jobs.retain(|j| {
            if excess > 0 && finished(j) {
                excess -= 1;
                false
            } else {
                true
            }
        });
    }

    pub fn jobs(&self) -> &[Job] {
        &self.jobs
    }

    pub fn get(&self, id: u64) -> Option<&Job> {
        self.jobs.iter().find(|j| j.id == id)
    }

    /// The next queued job to run (lowest id in `Queued` state).
    pub fn next_queued(&self) -> Option<u64> {
        self.jobs
            .iter()
            .filter(|j| j.state == JobState::Queued)
            .map(|j| j.id)
            .min()
    }

    /// Mark a job active and bump its attempt count.
    pub fn start(&mut self, id: u64) -> Result<()> {
        let j = self.job_mut(id)?;
        j.state = JobState::Active;
        j.attempts += 1;
        Ok(())
    }

    pub fn set_progress(&mut self, id: u64, bytes_done: u64) -> Result<()> {
        self.job_mut(id)?.bytes_done = bytes_done;
        Ok(())
    }

    /// Mark complete or failed.
    pub fn finish(&mut self, id: u64, ok: bool) -> Result<()> {
        let j = self.job_mut(id)?;
        j.state = if ok {
            JobState::Completed
        } else {
            JobState::Failed
        };
        Ok(())
    }

    /// Re-queue a failed job for retry (if under `max_attempts`). Returns whether
    /// it was re-queued.
    pub fn retry(&mut self, id: u64, max_attempts: u32) -> Result<bool> {
        let j = self.job_mut(id)?;
        if j.state == JobState::Failed && j.attempts < max_attempts {
            j.state = JobState::Queued;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn job_mut(&mut self, id: u64) -> Result<&mut Job> {
        self.jobs
            .iter_mut()
            .find(|j| j.id == id)
            .with_context(|| format!("no job with id {id}"))
    }
}

fn queue_path(dir: &Path) -> PathBuf {
    dir.join("queue.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_run_complete_persist() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = Queue::default();
        let a = q.enqueue("alice", "a.bin", 100);
        let b = q.enqueue("bob", "b.bin", 200);
        assert_eq!(q.next_queued(), Some(a));

        q.start(a).unwrap();
        q.set_progress(a, 50).unwrap();
        q.finish(a, true).unwrap();
        assert_eq!(q.get(a).unwrap().state, JobState::Completed);
        assert_eq!(q.get(a).unwrap().bytes_done, 50);
        // Next queued is now b.
        assert_eq!(q.next_queued(), Some(b));

        q.save(dir.path()).unwrap();
        let loaded = Queue::load(dir.path()).unwrap();
        assert_eq!(loaded.jobs().len(), 2);
        assert_eq!(loaded.get(a).unwrap().state, JobState::Completed);
        // next_id preserved → new ids don't collide.
        let mut loaded = loaded;
        let c = loaded.enqueue("carol", "c.bin", 1);
        assert_eq!(c, 2);
    }

    #[test]
    fn interrupted_and_pruned_jobs() {
        let mut q = Queue::default();
        let ids: Vec<u64> = (0..5)
            .map(|i| q.enqueue("p", &format!("f{i}"), 1))
            .collect();
        for &id in &ids {
            q.start(id).unwrap();
        }
        q.finish(ids[0], true).unwrap();
        q.fail(ids[1], "boom").unwrap();
        q.finish(ids[2], true).unwrap();
        q.fail_interrupted(); // ids[3], ids[4] were still active
        assert_eq!(q.get(ids[4]).unwrap().state, JobState::Failed);
        assert_eq!(q.get(ids[1]).unwrap().error.as_deref(), Some("boom"));
        q.prune_finished(2);
        let left: Vec<u64> = q.jobs().iter().map(|j| j.id).collect();
        assert_eq!(
            left,
            vec![ids[3], ids[4]],
            "oldest finished jobs dropped first"
        );
    }

    #[test]
    fn failed_job_retries_until_cap() {
        let mut q = Queue::default();
        let id = q.enqueue("p", "x", 1);
        q.start(id).unwrap(); // attempts = 1
        q.finish(id, false).unwrap();
        assert!(q.retry(id, 3).unwrap(), "re-queued");
        q.start(id).unwrap(); // attempts = 2
        q.finish(id, false).unwrap();
        assert!(q.retry(id, 3).unwrap());
        q.start(id).unwrap(); // attempts = 3
        q.finish(id, false).unwrap();
        assert!(!q.retry(id, 3).unwrap(), "attempts hit cap");
    }
}
