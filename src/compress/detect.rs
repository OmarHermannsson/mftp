//! Magic-byte detection for already-compressed formats.

/// Returns true if the data starts with a magic number indicating
/// a compressed or otherwise incompressible format.
pub fn is_already_compressed(data: &[u8]) -> bool {
    let magic = match data.get(..4) {
        Some(m) => m,
        None => return false,
    };
    matches!(
        magic,
        [0x1f, 0x8b, _, _]         // gzip
        | [0x28, 0xb5, 0x2f, 0xfd] // zstd
        | [0x42, 0x5a, 0x68, _]    // bzip2
        | [0x50, 0x4b, 0x03, 0x04] // zip
        | [0x37, 0x7a, 0xbc, 0xaf] // 7-zip
        | [0xfd, 0x37, 0x7a, 0x58] // xz
        | [0xff, 0xd8, 0xff, _]    // jpeg
        | [0x89, 0x50, 0x4e, 0x47] // png
        | [0x66, 0x74, 0x79, 0x70] // mp4/mov
        | [0x1a, 0x45, 0xdf, 0xa3] // mkv/webm
    )
}
