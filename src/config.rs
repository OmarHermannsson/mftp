//! Persistent per-user tuning defaults loaded from
//! `~/.config/mftp/config.toml`.
//!
//! Users on a repeated link (e.g. the same satellite hop every day) shouldn't
//! have to retype `-n 16 --chunk-size … --transport quic …` on every
//! invocation.  This module loads a small TOML file of optional tuning knobs;
//! `main.rs` then merges it under explicit CLI flags.
//!
//! Precedence (highest wins):
//!   explicit CLI flag  >  config file value  >  built-in default
//!
//! Every field is optional.  An absent config file is not an error — it yields
//! `Config::default()` (all `None`/`false`) and the CLI behaves exactly as if
//! this module did not exist.  A present-but-malformed file is a hard error.

use anyhow::{Context, Result};
use serde::Deserialize;

/// All-optional mirror of the persistent tuning knobs exposed on the CLI.
///
/// Only knobs that make sense to pin for a recurring link are included.
/// Per-transfer inputs (`--trust`, source/destination paths, `--download`,
/// `--recursive`, `--preserve`, `--remote-mftp`, …) are intentionally omitted.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Number of parallel streams (`-n` / `--streams`).
    pub streams: Option<usize>,
    /// Chunk size in bytes (`--chunk-size`).
    pub chunk_size: Option<usize>,
    /// Disable adaptive zstd compression (`--no-compress`).
    ///
    /// `true` here is equivalent to passing `--no-compress` on every run.
    /// There is no way to express "force compression on" because the CLI flag
    /// itself is one-way; a CLI `--no-compress` can only add to this, never
    /// override `false` back to compression-off.
    pub no_compress: bool,
    /// Forced transport path: `"quic"`, `"tcp"`, or `"sftp"` (`--transport`).
    pub transport: Option<String>,
    /// In auto mode, switch to TCP+TLS at or below this RTT in ms
    /// (`--tcp-below-rtt`).
    pub tcp_below_rtt: Option<f64>,
    /// Reed-Solomon FEC as `"DATA:PARITY"`, e.g. `"8:2"` (`--fec`).
    pub fec: Option<String>,
    /// Default port for the SSH-launched remote receiver (`--port`).
    pub port: Option<u16>,
}

impl Config {
    /// Load the user config from `~/.config/mftp/config.toml`.
    ///
    /// Returns `Config::default()` (all unset) when the file does not exist —
    /// absence is the normal, no-error case.  Returns an error if the file
    /// exists but cannot be read or parsed.
    pub fn load() -> Result<Config> {
        let Some(dir) = dirs::config_dir() else {
            // No config dir on this platform/user: behave as if no file.
            return Ok(Config::default());
        };
        let path = dir.join("mftp").join("config.toml");
        match std::fs::read_to_string(&path) {
            Ok(contents) => Config::parse(&contents)
                .with_context(|| format!("failed to parse config file {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => {
                Err(e).with_context(|| format!("failed to read config file {}", path.display()))
            }
        }
    }

    /// Parse a TOML string into a `Config`.  Split out from `load` so the
    /// parsing logic is testable without touching the filesystem.
    pub fn parse(contents: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(contents)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let toml = r#"
            streams = 16
            chunk_size = 2097152
            no_compress = true
            transport = "quic"
            tcp_below_rtt = 5.0
            fec = "8:2"
            port = 7777
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.streams, Some(16));
        assert_eq!(cfg.chunk_size, Some(2_097_152));
        assert!(cfg.no_compress);
        assert_eq!(cfg.transport.as_deref(), Some("quic"));
        assert_eq!(cfg.tcp_below_rtt, Some(5.0));
        assert_eq!(cfg.fec.as_deref(), Some("8:2"));
        assert_eq!(cfg.port, Some(7777));
    }

    #[test]
    fn empty_config_is_all_unset() {
        let cfg = Config::parse("").unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.streams, None);
        assert!(!cfg.no_compress);
    }

    #[test]
    fn partial_config_leaves_rest_unset() {
        let cfg = Config::parse("streams = 4\n").unwrap();
        assert_eq!(cfg.streams, Some(4));
        assert_eq!(cfg.chunk_size, None);
        assert_eq!(cfg.tcp_below_rtt, None);
    }

    #[test]
    fn malformed_config_is_error() {
        assert!(Config::parse("streams = \"not a number\"\n").is_err());
        assert!(Config::parse("this is not toml { ").is_err());
    }

    #[test]
    fn unknown_field_is_error() {
        // Guards against silent typos in a hand-edited config file.
        assert!(Config::parse("treams = 8\n").is_err());
    }
}
