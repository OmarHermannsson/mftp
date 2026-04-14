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
