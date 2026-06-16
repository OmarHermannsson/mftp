//! At-rest encryption for received files (mftp v2, milestone M8).
//!
//! Optionally envelope-encrypts a received file so a compromised receiver disk
//! doesn't leak payloads. This is independent of the in-transit TLS: it protects
//! data once it has landed on disk.
//!
//! Format: a small header (`magic` + random 4-byte nonce prefix) followed by a
//! sequence of AES-256-GCM blocks, each `[u32 LE ciphertext_len][ciphertext]
//! [16-byte tag]`. Per-block nonce = `prefix(4) || counter_le(8)`, so the scheme
//! streams (no need to hold the whole file in memory) and every block is
//! individually authenticated. Encryption fails closed: a tampered or truncated
//! block fails to decrypt.

use std::io::{Read, Write};

use anyhow::{bail, Context, Result};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

const MAGIC: [u8; 4] = *b"MFE1"; // mftp-encrypted v1
const BLOCK: usize = 64 * 1024;
const TAG_LEN: usize = 16;

fn cipher() -> Cipher {
    Cipher::aes_256_gcm()
}

fn block_iv(prefix: &[u8; 4], counter: u64) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[..4].copy_from_slice(prefix);
    iv[4..].copy_from_slice(&counter.to_le_bytes());
    iv
}

/// Encrypt `plaintext` to `writer` under the 32-byte `key`.
pub fn encrypt_stream<R: Read, W: Write>(
    key: &[u8; 32],
    mut reader: R,
    mut writer: W,
) -> Result<()> {
    let mut prefix = [0u8; 4];
    openssl::rand::rand_bytes(&mut prefix).context("rng")?;
    writer.write_all(&MAGIC)?;
    writer.write_all(&prefix)?;

    let c = cipher();
    let mut buf = vec![0u8; BLOCK];
    let mut counter: u64 = 0;
    loop {
        let n = read_full(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        let iv = block_iv(&prefix, counter);
        let mut tag = [0u8; TAG_LEN];
        let ct = encrypt_aead(c, key, Some(&iv), &[], &buf[..n], &mut tag)
            .context("AES-GCM encrypt block")?;
        writer.write_all(&(ct.len() as u32).to_le_bytes())?;
        writer.write_all(&ct)?;
        writer.write_all(&tag)?;
        counter += 1;
        if n < BLOCK {
            break; // last (short) block
        }
    }
    writer.flush()?;
    Ok(())
}

/// Decrypt a stream produced by [`encrypt_stream`] under the same `key`.
pub fn decrypt_stream<R: Read, W: Write>(
    key: &[u8; 32],
    mut reader: R,
    mut writer: W,
) -> Result<()> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).context("read header")?;
    if header[..4] != MAGIC {
        bail!("not an mftp-encrypted file (bad magic)");
    }
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&header[4..8]);

    let c = cipher();
    let mut counter: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read(&mut len_buf[..1]) {
            Ok(0) => break, // clean EOF at block boundary
            Ok(_) => {}
            Err(e) => return Err(e).context("read block length"),
        }
        reader
            .read_exact(&mut len_buf[1..])
            .context("block length")?;
        let ct_len = u32::from_le_bytes(len_buf) as usize;
        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct).context("read ciphertext")?;
        let mut tag = [0u8; TAG_LEN];
        reader.read_exact(&mut tag).context("read tag")?;

        let iv = block_iv(&prefix, counter);
        let pt = decrypt_aead(c, key, Some(&iv), &[], &ct, &tag)
            .context("AES-GCM decrypt/verify block (wrong key or tampered data)")?;
        writer.write_all(&pt)?;
        counter += 1;
    }
    writer.flush()?;
    Ok(())
}

/// Encrypt a file in place: `path` → `path.enc`, removing the plaintext on
/// success. Returns the encrypted path.
pub fn encrypt_file(key: &[u8; 32], path: &std::path::Path) -> Result<std::path::PathBuf> {
    let enc = path.with_extension(format!(
        "{}.enc",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    {
        let r = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let w = std::fs::File::create(&enc).with_context(|| format!("create {}", enc.display()))?;
        encrypt_stream(key, r, w)?;
    }
    std::fs::remove_file(path).ok();
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

    fn roundtrip(data: &[u8]) {
        let key = [7u8; 32];
        let mut ct = Vec::new();
        encrypt_stream(&key, data, &mut ct).unwrap();
        // Ciphertext carries the header and (for non-empty input) differs from
        // the plaintext bytes.
        assert_eq!(&ct[..4], &MAGIC);
        if !data.is_empty() {
            assert_ne!(ct.get(8..8 + data.len()), Some(data));
        }

        let mut pt = Vec::new();
        decrypt_stream(&key, &ct[..], &mut pt).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn empty_small_and_multiblock_round_trip() {
        roundtrip(b"");
        roundtrip(b"hello");
        roundtrip(&vec![0xABu8; BLOCK]); // exactly one block
        roundtrip(&vec![0xCDu8; BLOCK * 3 + 123]); // several blocks + remainder
    }

    #[test]
    fn wrong_key_fails() {
        let mut ct = Vec::new();
        encrypt_stream(&[1u8; 32], b"secret payload".as_slice(), &mut ct).unwrap();
        let mut pt = Vec::new();
        assert!(
            decrypt_stream(&[2u8; 32], &ct[..], &mut pt).is_err(),
            "decryption under the wrong key must fail (authenticated)"
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [9u8; 32];
        let mut ct = Vec::new();
        encrypt_stream(&key, vec![5u8; 1000].as_slice(), &mut ct).unwrap();
        // Flip a byte in the ciphertext body.
        let i = ct.len() / 2;
        ct[i] ^= 0xFF;
        let mut pt = Vec::new();
        assert!(decrypt_stream(&key, &ct[..], &mut pt).is_err());
    }

    #[test]
    fn encrypt_file_replaces_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("data.bin");
        let data = vec![3u8; BLOCK + 7];
        std::fs::write(&p, &data).unwrap();

        let key = [4u8; 32];
        let enc = encrypt_file(&key, &p).unwrap();
        assert!(!p.exists(), "plaintext removed");
        assert!(enc.exists());

        let mut pt = Vec::new();
        decrypt_stream(&key, std::fs::File::open(&enc).unwrap(), &mut pt).unwrap();
        assert_eq!(pt, data);
    }
}
