//! At-rest encryption for received files (mftp v2, milestone M8).
//!
//! Envelope-encrypts a file so a compromised receiver disk doesn't leak
//! payloads. This is independent of the in-transit TLS: it protects data once
//! it has landed on disk.
//!
//! **Status: library-level only.** Nothing in the daemon calls this yet —
//! received files are currently written in plaintext. It is a building block
//! for a future `--encrypt-at-rest` option.
//!
//! Format (v2, magic `MFE2`):
//!
//! ```text
//! header:  magic(4) || salt(32)
//! block*:  [u32 LE ciphertext_len][ciphertext][16-byte GCM tag]
//! ```
//!
//! * **Per-file key**: each file gets a fresh random 32-byte salt, and the
//!   AES-256-GCM key is `BLAKE3-derive_key(CONTEXT, master_key || salt)`. Nonces
//!   therefore only need to be unique *within* a file, so the block counter is
//!   used directly — no random nonce prefix that could collide across files.
//! * **Nonce** = `0u32 || counter_le(8)`.
//! * **AAD** = `counter_le(8) || final_flag(1)`. Binding the counter stops block
//!   reordering/duplication; binding the final flag lets the reader detect
//!   truncation: exactly one block (the last) carries `final = 1`, a stream that
//!   ends without it is rejected, and so is any data after it. An empty file is
//!   a single empty final block.
//!
//! The scheme streams (the file is never held in memory) and fails closed: a
//! tampered, reordered, truncated, or extended stream does not decrypt.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

const MAGIC: [u8; 4] = *b"MFE2"; // mftp-encrypted v2
const SALT_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN;
const BLOCK: usize = 64 * 1024;
const TAG_LEN: usize = 16;
/// BLAKE3 key-derivation context for the per-file key.
const KDF_CONTEXT: &str = "mftp 2026 at-rest encryption v2 per-file key";

fn cipher() -> Cipher {
    Cipher::aes_256_gcm()
}

/// Derive the per-file AES key from the master key and the file's salt.
fn file_key(master: &[u8; 32], salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut material = [0u8; 32 + SALT_LEN];
    material[..32].copy_from_slice(master);
    material[32..].copy_from_slice(salt);
    blake3::derive_key(KDF_CONTEXT, &material)
}

fn block_iv(counter: u64) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[4..].copy_from_slice(&counter.to_le_bytes());
    iv
}

fn block_aad(counter: u64, last: bool) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&counter.to_le_bytes());
    aad[8] = last as u8;
    aad
}

/// Encrypt `reader` to `writer` under the 32-byte master `key`.
pub fn encrypt_stream<R: Read, W: Write>(
    key: &[u8; 32],
    mut reader: R,
    mut writer: W,
) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    openssl::rand::rand_bytes(&mut salt).context("rng")?;
    let fkey = file_key(key, &salt);
    writer.write_all(&MAGIC)?;
    writer.write_all(&salt)?;

    let c = cipher();
    let mut cur = vec![0u8; BLOCK];
    let mut next = vec![0u8; BLOCK];
    let mut cur_n = read_full(&mut reader, &mut cur)?;
    let mut counter: u64 = 0;
    loop {
        // A short block is necessarily the last; a full one is last only if
        // nothing follows it (read one block ahead to know).
        let (last, next_n) = if cur_n < BLOCK {
            (true, 0)
        } else {
            let n = read_full(&mut reader, &mut next)?;
            (n == 0, n)
        };
        let iv = block_iv(counter);
        let aad = block_aad(counter, last);
        let mut tag = [0u8; TAG_LEN];
        let ct = encrypt_aead(c, &fkey, Some(&iv), &aad, &cur[..cur_n], &mut tag)
            .context("AES-GCM encrypt block")?;
        writer.write_all(&(ct.len() as u32).to_le_bytes())?;
        writer.write_all(&ct)?;
        writer.write_all(&tag)?;
        if last {
            break;
        }
        counter = counter.checked_add(1).context("block counter overflow")?;
        std::mem::swap(&mut cur, &mut next);
        cur_n = next_n;
    }
    writer.flush()?;
    Ok(())
}

/// Decrypt a stream produced by [`encrypt_stream`] under the same master `key`.
///
/// Plaintext is written as each block verifies; on error the caller must
/// discard whatever was written (the stream is not authentic as a whole until
/// this returns `Ok`).
pub fn decrypt_stream<R: Read, W: Write>(
    key: &[u8; 32],
    mut reader: R,
    mut writer: W,
) -> Result<()> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).context("read header")?;
    if header[..4] != MAGIC {
        bail!("not an mftp-encrypted v2 file (bad magic)");
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&header[4..]);
    let fkey = file_key(key, &salt);

    let c = cipher();
    let mut counter: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        if read_full(&mut reader, &mut len_buf)? != 4 {
            bail!("encrypted file is truncated (missing final block)");
        }
        let ct_len = u32::from_le_bytes(len_buf) as usize;
        if ct_len > BLOCK {
            bail!("corrupt encrypted file (block length {ct_len} > {BLOCK})");
        }
        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct).context("read ciphertext")?;
        let mut tag = [0u8; TAG_LEN];
        reader.read_exact(&mut tag).context("read tag")?;

        let iv = block_iv(counter);
        // Try the block as non-final first (the common case), then as final;
        // only the variant the writer actually used authenticates.
        let (pt, last) =
            match decrypt_aead(c, &fkey, Some(&iv), &block_aad(counter, false), &ct, &tag) {
                Ok(pt) => (pt, false),
                Err(_) => (
                    decrypt_aead(c, &fkey, Some(&iv), &block_aad(counter, true), &ct, &tag)
                        .context("AES-GCM decrypt/verify block (wrong key or tampered data)")?,
                    true,
                ),
            };
        writer.write_all(&pt)?;
        if last {
            let mut probe = [0u8; 1];
            if read_full(&mut reader, &mut probe)? != 0 {
                bail!("corrupt encrypted file (data after the final block)");
            }
            break;
        }
        counter = counter.checked_add(1).context("block counter overflow")?;
    }
    writer.flush()?;
    Ok(())
}

/// Path of the encrypted output for `path`: the full file name plus `.enc`
/// (`data.bin` → `data.bin.enc`, `archive` → `archive.enc`).
fn enc_path(path: &Path) -> Result<PathBuf> {
    let mut name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?
        .to_os_string();
    name.push(".enc");
    Ok(path.with_file_name(name))
}

/// Encrypt a file in place: `path` → `path.enc`, removing the plaintext on
/// success. Returns the encrypted path.
///
/// The ciphertext is written to a private temp file, fsynced, and renamed into
/// place (then the directory is fsynced), so a crash never leaves a partial
/// `.enc` that looks complete. The plaintext is removed only after that; a
/// failure to remove it is returned as an error (the caller must not assume
/// the plaintext is gone).
pub fn encrypt_file(key: &[u8; 32], path: &Path) -> Result<PathBuf> {
    let enc = enc_path(path)?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(enc.file_name().expect("enc path has a file name"));
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = enc.with_file_name(tmp_name);

    let result = (|| -> Result<()> {
        let r = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut w = opts
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        encrypt_stream(key, std::io::BufReader::new(r), &mut w)?;
        w.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
        std::fs::rename(&tmp, &enc)
            .with_context(|| format!("rename {} -> {}", tmp.display(), enc.display()))?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(parent) = enc.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    std::fs::remove_file(path).with_context(|| {
        format!(
            "encrypted to {} but could not remove plaintext {}",
            enc.display(),
            path.display()
        )
    })?;
    Ok(enc)
}

/// Read up to `buf.len()` bytes, returning the count (short only at EOF).
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("read"),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
        let mut ct = Vec::new();
        encrypt_stream(key, data, &mut ct).unwrap();
        ct
    }

    fn decrypt(key: &[u8; 32], ct: &[u8]) -> Result<Vec<u8>> {
        let mut pt = Vec::new();
        decrypt_stream(key, ct, &mut pt)?;
        Ok(pt)
    }

    /// Byte offset just past block `i` (0-based) in a ciphertext of full blocks.
    fn block_end(i: usize) -> usize {
        HEADER_LEN + (i + 1) * (4 + BLOCK + TAG_LEN)
    }

    fn roundtrip(data: &[u8]) {
        let key = [7u8; 32];
        let ct = encrypt(&key, data);
        assert_eq!(&ct[..4], &MAGIC);
        if !data.is_empty() {
            assert_ne!(
                ct.get(HEADER_LEN + 4..HEADER_LEN + 4 + data.len()),
                Some(data)
            );
        }
        assert_eq!(decrypt(&key, &ct).unwrap(), data);
    }

    #[test]
    fn empty_small_and_multiblock_round_trip() {
        roundtrip(b"");
        roundtrip(b"hello");
        roundtrip(&vec![0xABu8; BLOCK]); // exactly one block
        roundtrip(&vec![0xABu8; BLOCK * 2]); // exact multiple
        roundtrip(&vec![0xCDu8; BLOCK * 3 + 123]); // several blocks + remainder
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(&[1u8; 32], b"secret payload");
        assert!(
            decrypt(&[2u8; 32], &ct).is_err(),
            "decryption under the wrong key must fail (authenticated)"
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [9u8; 32];
        let mut ct = encrypt(&key, &[5u8; 1000]);
        let i = ct.len() / 2;
        ct[i] ^= 0xFF;
        assert!(decrypt(&key, &ct).is_err());
    }

    #[test]
    fn truncation_at_block_boundary_is_detected() {
        let key = [3u8; 32];
        let ct = encrypt(&key, &vec![1u8; BLOCK * 3]);
        // Drop the final block(s) at a clean boundary: previously this decrypted
        // "successfully" to a prefix of the plaintext.
        for keep in [0, 1, 2] {
            let cut = if keep == 0 {
                HEADER_LEN
            } else {
                block_end(keep - 1)
            };
            assert!(
                decrypt(&key, &ct[..cut]).is_err(),
                "truncated to {keep} blocks must fail"
            );
        }
        // Trailing garbage after the final block is rejected too.
        let mut extended = ct.clone();
        extended.extend_from_slice(&ct[HEADER_LEN..block_end(0)]);
        assert!(decrypt(&key, &extended).is_err());
        assert!(decrypt(&key, &ct).is_ok());
    }

    #[test]
    fn block_reorder_is_detected() {
        let key = [4u8; 32];
        let mut data = vec![1u8; BLOCK];
        data.extend(vec![2u8; BLOCK]);
        data.extend(vec![3u8; 10]);
        let ct = encrypt(&key, &data);
        let mut swapped = ct[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&ct[block_end(0)..block_end(1)]);
        swapped.extend_from_slice(&ct[HEADER_LEN..block_end(0)]);
        swapped.extend_from_slice(&ct[block_end(1)..]);
        assert!(decrypt(&key, &swapped).is_err());
    }

    #[test]
    fn same_plaintext_encrypts_differently_per_file() {
        // Fresh salt → fresh per-file key → distinct ciphertexts.
        let key = [6u8; 32];
        assert_ne!(encrypt(&key, b"same"), encrypt(&key, b"same"));
    }

    #[test]
    fn encrypt_file_replaces_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("data.bin");
        let data = vec![3u8; BLOCK + 7];
        std::fs::write(&p, &data).unwrap();

        let key = [4u8; 32];
        let enc = encrypt_file(&key, &p).unwrap();
        assert_eq!(enc, dir.path().join("data.bin.enc"));
        assert!(!p.exists(), "plaintext removed");
        // Only the final file remains (no temp left behind).
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        let mut pt = Vec::new();
        decrypt_stream(&key, std::fs::File::open(&enc).unwrap(), &mut pt).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn enc_path_has_no_double_dot() {
        assert_eq!(
            enc_path(Path::new("/x/archive")).unwrap(),
            Path::new("/x/archive.enc")
        );
        assert_eq!(
            enc_path(Path::new("/x/a.tar.gz")).unwrap(),
            Path::new("/x/a.tar.gz.enc")
        );
    }
}
