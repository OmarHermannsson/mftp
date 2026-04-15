//! Cross-platform positional file I/O.
//!
//! On Unix, delegates to `std::os::unix::fs::FileExt` which provides atomic
//! `pread`/`pwrite` syscalls with no shared seek cursor.
//!
//! On Windows, emulates the same semantics via
//! `std::os::windows::fs::FileExt::{seek_read, seek_write}`, which perform
//! overlapped I/O at a specified offset without moving the file pointer.
//! The loop is necessary because Windows `seek_read`/`seek_write` may
//! transfer fewer bytes than requested (like `read`/`write` on Unix).

use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// Read exactly `buf.len()` bytes from `file` at `offset`.
///
/// Equivalent to `read_exact_at` on Unix; loops over `seek_read` on Windows.
pub fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut n = 0usize;
        while n < buf.len() {
            match file.seek_read(&mut buf[n..], offset + n as u64)? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    ))
                }
                k => n += k,
            }
        }
        Ok(())
    }
}

/// Write all of `buf` to `file` at `offset`.
///
/// Equivalent to `write_all_at` on Unix; loops over `seek_write` on Windows.
pub fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut n = 0usize;
        while n < buf.len() {
            match file.seek_write(&buf[n..], offset + n as u64)? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ))
                }
                k => n += k,
            }
        }
        Ok(())
    }
}

/// Write all of `buf` to `file` at `offset`, then advise the kernel to begin
/// flushing the written pages and release them from the page cache.
///
/// On Linux: calls `sync_file_range(SYNC_FILE_RANGE_WRITE)` first to initiate
/// non-blocking writeback, then `posix_fadvise(FADV_DONTNEED)` to drop the
/// pages from the cache.  Together these prevent dirty-page accumulation when
/// many concurrent writers are active — without them, the kernel accumulates
/// dirty pages until the dirty_ratio threshold triggers a synchronous stall.
///
/// Prefer [`write_all_at_deferred`] for sustained parallel writes: calling
/// `FADV_DONTNEED` immediately after `sync_file_range` can stall if the block
/// layer hasn't yet started the submitted I/O.  The deferred variant issues
/// `FADV_DONTNEED` only after a lookahead number of later writes, by which time
/// the earlier writeback is reliably in flight.
///
/// This function is kept for call sites that open a fresh fd per write (e.g.
/// scatter-writes in directory mode), where a shared deferred tracker is not
/// practical.
///
/// On macOS: identical to `write_all_at`; callers should set `F_NOCACHE` on
/// the fd at open time to achieve an equivalent effect for the whole file.
///
/// On Windows: identical to `write_all_at`.
pub fn write_all_at_advise(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    write_all_at(file, buf, offset)?;
    #[cfg(target_os = "linux")]
    {
        let fd = file.as_raw_fd();
        let off = offset as i64;
        let len = buf.len() as i64;
        // Kick off async writeback for this range (non-blocking).
        unsafe {
            libc::sync_file_range(fd, off, len, libc::SYNC_FILE_RANGE_WRITE);
        }
        // Release pages from the page cache so they don't accumulate as dirty.
        unsafe {
            libc::posix_fadvise(fd, off, len, libc::POSIX_FADV_DONTNEED);
        }
    }
    Ok(())
}

/// Write all of `buf` to `file` at `offset`, then record the range in
/// `deferred` for a later `FADV_DONTNEED` call.
///
/// On Linux: calls `sync_file_range(SYNC_FILE_RANGE_WRITE)` to start
/// non-blocking writeback, then hands the range to [`DeferredDontneed`].
/// The DONTNEED is issued only after [`DONTNEED_LOOKAHEAD`] newer writes have
/// been registered, giving the block device time to drain the earlier
/// submission before the pages are evicted from the page cache.  This avoids
/// the brief stalls that occur when `FADV_DONTNEED` is called while the pages
/// are still queued in the block layer.
///
/// On non-Linux: identical to `write_all_at` (DONTNEED is a no-op).
pub fn write_all_at_deferred(
    file: &File,
    buf: &[u8],
    offset: u64,
    deferred: &DeferredDontneed,
) -> io::Result<()> {
    write_all_at(file, buf, offset)?;
    #[cfg(target_os = "linux")]
    {
        let fd = file.as_raw_fd();
        let off = offset as i64;
        let len = buf.len() as i64;
        unsafe {
            libc::sync_file_range(fd, off, len, libc::SYNC_FILE_RANGE_WRITE);
        }
        deferred.push(off, len);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = deferred;
    Ok(())
}

// ── DeferredDontneed ──────────────────────────────────────────────────────────

/// How many writes to buffer before issuing `FADV_DONTNEED` for the oldest
/// entry.  At ~120 MiB/s with 4 MiB chunks and 8 concurrent writers, each
/// write slot is ~34 ms; 32 slots ≈ 136 ms of lookahead — enough for the
/// block device to start draining the earlier submission.
#[cfg(target_os = "linux")]
const DONTNEED_LOOKAHEAD: usize = 32;

/// Deferred `posix_fadvise(FADV_DONTNEED)` tracker.
///
/// Calling `FADV_DONTNEED` immediately after `sync_file_range(WRITE)` can
/// stall briefly when the block layer hasn't yet dispatched the submitted I/O;
/// the kernel then has to flush those pages synchronously before it can drop
/// them.  By buffering recent write ranges and issuing DONTNEED only after
/// [`DONTNEED_LOOKAHEAD`] newer writes have been recorded, we ensure the
/// earlier writeback is reliably in flight before eviction is requested.
///
/// `DeferredDontneed` is `Clone` — clones share the same underlying queue so
/// multiple `spawn_blocking` tasks writing to the same file participate in the
/// same lookahead window.
///
/// On non-Linux platforms this is a zero-size no-op.
#[derive(Clone)]
pub struct DeferredDontneed {
    #[cfg(target_os = "linux")]
    inner: Option<std::sync::Arc<DeferredInner>>,
}

#[cfg(target_os = "linux")]
struct DeferredInner {
    fd: std::os::unix::io::RawFd,
    pending: std::sync::Mutex<std::collections::VecDeque<(i64, i64)>>,
}

impl DeferredDontneed {
    /// Create a tracker bound to `file`.  All clones of this value share the
    /// same lookahead queue and issue DONTNEED on `file`'s fd.
    pub fn new(_file: &File) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                inner: Some(std::sync::Arc::new(DeferredInner {
                    fd: _file.as_raw_fd(),
                    pending: std::sync::Mutex::new(std::collections::VecDeque::new()),
                })),
            }
        }
        #[cfg(not(target_os = "linux"))]
        Self {}
    }

    /// Create a no-op tracker (e.g. for directory-mode transfers where there
    /// is no single persistent fd to track).
    pub fn noop() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self { inner: None }
        }
        #[cfg(not(target_os = "linux"))]
        Self {}
    }

    /// Record that `(offset, len)` has been written and `sync_file_range`'d.
    /// If the lookahead queue is full, evicts the oldest entry with
    /// `FADV_DONTNEED` (outside the lock, so it never serialises other callers).
    #[cfg(target_os = "linux")]
    pub fn push(&self, offset: i64, len: i64) {
        let Some(ref inner) = self.inner else {
            return;
        };
        let evict = {
            let mut q = inner.pending.lock().unwrap();
            q.push_back((offset, len));
            if q.len() > DONTNEED_LOOKAHEAD {
                q.pop_front()
            } else {
                None
            }
        };
        if let Some((off, l)) = evict {
            unsafe {
                libc::posix_fadvise(inner.fd, off, l, libc::POSIX_FADV_DONTNEED);
            }
        }
    }

    /// Flush all remaining pending DONTNEED calls.  Call once after the last
    /// write to ensure no ranges are left in the page cache indefinitely.
    pub fn flush(&self) {
        #[cfg(target_os = "linux")]
        {
            let Some(ref inner) = self.inner else {
                return;
            };
            let entries: Vec<(i64, i64)> = inner.pending.lock().unwrap().drain(..).collect();
            for (off, len) in entries {
                unsafe {
                    libc::posix_fadvise(inner.fd, off, len, libc::POSIX_FADV_DONTNEED);
                }
            }
        }
    }
}
