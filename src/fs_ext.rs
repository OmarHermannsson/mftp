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
