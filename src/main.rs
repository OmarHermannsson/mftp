#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use mftp::config::Config;
use mftp::protocol::messages::FecParams;
use mftp::transfer::sender::ForcedTransport;
use mftp::transfer::{receiver, sender};

/// Built-in default for `--tcp-below-rtt` (ms), applied when neither the CLI
/// flag nor the config file sets it.  See the flag's help for the rationale.
const DEFAULT_TCP_BELOW_RTT_MS: f64 = 15.0;

/// Shown under `mftp --help`.  Concrete invocations cover the common cases the
/// flag docs describe abstractly.
const EXAMPLES: &str = "\
EXAMPLES:
  # Send to an already-running receiver (host:port)
  mftp send bigfile.tar 203.0.113.7:7777

  # SSH mode: mftp launches a one-shot receiver on the remote itself
  mftp send bigfile.tar user@host:/data/

  # Recursive directory transfer, preserving mode + mtime
  mftp send -r ./dataset user@host:/data/ --preserve

  # Lossy/satellite link: add Reed-Solomon FEC (8 data : 2 parity shards)
  mftp send bigfile.tar user@host:/data/ --fec 8:2

  # Pin a fingerprint for unattended/scripted runs (no TOFU prompt)
  mftp send bigfile.tar 203.0.113.7:7777 --trust <hex-sha256>

  # Run as a receiver listening on all interfaces
  mftp receive 0.0.0.0:7777 --output-dir /data

EXIT STATUS:
  0  transfer completed and verified
  non-zero  any failure (connection, integrity, disk, user abort);
            safe to retry — interrupted transfers resume automatically.
";

/// Transport path for `--transport`.
#[derive(clap::ValueEnum, Clone)]
enum Transport {
    /// QUIC with BBR congestion control (default when omitted in auto mode).
    /// Fails immediately if QUIC is unreachable — no TCP+TLS or SFTP fallback.
    Quic,
    /// TCP+TLS. Skip the QUIC probe. No SFTP fallback.
    Tcp,
    /// Parallel SFTP through SSH port 22 (SSH mode only, ~22 MiB/s cap).
    /// Skips the remote mftp server launch entirely.
    Sftp,
}

#[derive(Parser)]
#[command(
    name = "mftp",
    about = "High-throughput file transfer over high-latency links",
    version,
    after_help = EXAMPLES,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Number of parallel streams.
    /// Direct mode (QUIC/TCP): default auto-negotiated from RTT + CPU cores.
    /// SFTP fallback: default 8 (each stream is one SSH/SFTP connection;
    /// scales linearly — raise to 12 if the remote sshd allows it).
    #[arg(short = 'n', long, global = true, value_name = "N")]
    streams: Option<usize>,

    /// Chunk size in bytes (default: auto-negotiated from RTT)
    #[arg(long, global = true)]
    chunk_size: Option<usize>,

    /// Number of QUIC connections (paths) to bond for one transfer (default 1).
    ///
    /// Values above 1 open that many connections to the receiver and stripe the
    /// data streams across them — link bonding for multi-homed hosts (e.g. Wi-Fi
    /// plus wired, or two WAN uplinks). Each path runs its own congestion
    /// control, so a faster path naturally carries more chunks. QUIC only;
    /// ignored on the TCP and SFTP paths.
    #[arg(long, global = true, value_name = "N")]
    paths: Option<usize>,

    /// Disable adaptive zstd compression
    #[arg(long, global = true)]
    no_compress: bool,

    /// Enable Reed-Solomon forward error correction.
    ///
    /// Specify as DATA:PARITY (e.g. --fec 8:2 adds 25% bandwidth overhead).
    /// NOTE: this does NOT improve throughput. mftp's chunks ride reliable QUIC
    /// streams, which already retransmit lost packets, so the parity is pure
    /// overhead competing for the link (benchmarked a wash-to-worse up to 30%
    /// loss). Leave it off unless you specifically want the receiver to
    /// reconstruct an occasional corrupt chunk without an in-band repair round.
    /// Automatically disabled when the transport falls back to TCP (reliable delivery).
    #[arg(long, global = true, value_name = "DATA:PARITY")]
    fec: Option<String>,

    /// Force a specific transport path.
    ///
    /// quic — QUIC only; fails immediately if UDP is blocked (no TCP or SFTP fallback).
    ///
    /// tcp  — TCP+TLS only; skip the QUIC probe (no SFTP fallback).
    ///
    /// sftp — parallel SFTP through SSH port 22 (SSH mode only; ~22 MiB/s cap).
    ///        Skips the remote mftp server launch — port 22 is all that's needed.
    ///
    /// Omit to use auto mode: QUIC → TCP+TLS → SFTP (SSH mode only).
    #[arg(long, global = true, value_name = "TRANSPORT")]
    transport: Option<Transport>,

    /// In auto mode, switch to TCP+TLS when measured RTT is at or below this value (ms).
    /// Default 15 ms: QUIC+BBR is slower than TCP+CUBIC at low latency due to slow
    /// congestion window ramp-up.  Set 0 to always use QUIC, or higher to widen the
    /// TCP window.  Ignored when --transport is set.
    ///
    /// Left as `Option` (rather than a clap `default_value`) so the config file
    /// can supply the default; the built-in fallback `DEFAULT_TCP_BELOW_RTT_MS`
    /// is applied in `main` after merging CLI > config.
    #[arg(long, global = true, value_name = "MS")]
    tcp_below_rtt: Option<f64>,

    /// Use multiple parallel file readers instead of a single sequential reader.
    ///
    /// Splits the file into one range per stream and reads them concurrently.
    /// Only beneficial on local NVMe with queue depth ≥ 32; has no measurable
    /// effect on network-bound transfers or spinning disks.
    #[arg(long, global = true, hide = true)]
    parallel_reads: bool,

    /// Verbosity (-v = info, -vv = debug, -vvv = trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Command {
    /// Send a file or directory to a remote host
    Send {
        /// File or directory to send
        file: std::path::PathBuf,
        /// Where to send the file.
        ///
        /// `host:port`          — connect to an already-running `mftp receive`.
        ///
        /// `[user@]host:/path`  — SSH mode: mftp launches a one-shot receiver
        /// on the remote automatically. Falls back through three transports:
        /// QUIC (UDP, needs open port) → TCP+TLS (TCP, needs open port) →
        /// SFTP (port 22 only, ~22 MiB/s cap). Use --port to specify a
        /// firewall-allowed port; without it a random port is used and QUIC/
        /// TCP+TLS will likely fall back to SFTP.
        destination: String,
        /// Pin the receiver's certificate fingerprint (hex SHA-256).
        /// Omit to use TOFU: fingerprint is printed and you are prompted once per
        /// session (requires a TTY; non-interactive use without --trust is rejected).
        /// Fingerprints are not stored between sessions — pass --trust in scripts.
        /// Ignored in SSH mode — fingerprint is obtained automatically.
        #[arg(long)]
        trust: Option<String>,
        /// Pin the receiver's Ed25519 DeviceId (hex), as printed by `mftp receive`
        /// ("Device ID: …"). Unlike --trust this survives the receiver re-issuing
        /// its certificate, and takes precedence over --trust when both are given.
        /// Ignored in SSH mode.
        #[arg(long, value_name = "HEX")]
        trust_device: Option<String>,
        /// Path to a pre-installed mftp binary on the remote (SSH mode only).
        /// By default mftp pipes itself over SSH stdin and caches it at
        /// ~/.cache/mftp-<hash> on the remote; subsequent transfers with the
        /// same binary version skip the copy.
        #[arg(long)]
        remote_mftp: Option<String>,
        /// Port for the remote mftp server to listen on (SSH mode only).
        /// Defaults to a randomly assigned port. Useful when the data-transfer
        /// port must be in a firewall allow-list.
        #[arg(long)]
        port: Option<u16>,
        /// When the remote platform differs from local, automatically download
        /// the correct mftp binary from GitHub releases without prompting.
        /// Mutually exclusive with --no-download.
        #[arg(long, conflicts_with = "no_download")]
        download: bool,
        /// When the remote platform differs from local, skip the download
        /// attempt and fall back to SFTP immediately (no prompt).
        /// Mutually exclusive with --download.
        #[arg(long, conflicts_with = "download")]
        no_download: bool,
        /// Expected SHA-256 (hex) of the cross-platform binary downloaded from
        /// GitHub releases. When set, the download must match exactly or the
        /// transfer aborts before anything runs on the remote. This is the only
        /// check that defends against a compromised release — supply the hash
        /// from a trusted source (e.g. the published `<asset>.sha256`). Without
        /// it, the download is still checked against the release's own checksum
        /// file and the computed hash is printed for manual comparison.
        #[arg(long, value_name = "HEX")]
        remote_binary_sha256: Option<String>,
        /// Transfer directories recursively.
        ///
        /// Required when the source is a directory; silently accepted (no-op) when
        /// the source is a regular file.  The receiver recreates the directory tree
        /// under its --output-dir using the source directory's basename.
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Preserve source file permissions and modification time on the receiver.
        ///
        /// By default the receiver writes files with default umask permissions and
        /// the current time as mtime.  With --preserve, the source mode bits and
        /// mtime are applied in a final pass after all data is written.
        /// Has no effect when the receiver runs on Windows.
        #[arg(long)]
        preserve: bool,
    },
    /// Receive files (run as server)
    Receive {
        /// Address to listen on
        #[arg(default_value = "0.0.0.0:7777")]
        bind: String,
        /// Directory to write received files into
        #[arg(short, long, default_value = ".")]
        output_dir: std::path::PathBuf,
    },
    /// One-shot server mode launched by the sender via SSH (not for direct use)
    #[command(hide = true)]
    Server {
        /// Directory to write received files into
        #[arg(short, long, default_value = ".")]
        output_dir: std::path::PathBuf,
        /// Port to listen on (default: random)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Run the persistent receiver daemon (accept-many) with a local control
    /// socket. Add authorized sender DeviceIds with `mftp daemon-trust` to
    /// enforce mutual-TLS identity auth.
    #[cfg(unix)]
    Daemon {
        /// Address to listen on
        #[arg(default_value = "0.0.0.0:7777")]
        bind: String,
        /// Directory to write received files into
        #[arg(short, long, default_value = ".")]
        output_dir: std::path::PathBuf,
        /// Control socket path (default: $XDG_RUNTIME_DIR/mftpd.sock)
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
        /// LAN discovery name to announce as (default: this host's hostname).
        /// Senders can then use `mftp send <file> <name>`.
        #[arg(long)]
        name: Option<String>,
    },
    /// Query a running daemon's status / identity over its control socket.
    #[cfg(unix)]
    DaemonStatus {
        /// Control socket path (default: $XDG_RUNTIME_DIR/mftpd.sock)
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
    },
    /// Manage the daemon's authorized-sender DeviceId allowlist.
    #[cfg(unix)]
    DaemonTrust {
        /// add <id> | remove <id> | list
        action: String,
        /// DeviceId (hex) for add/remove
        device_id: Option<String>,
        /// Control socket path (default: $XDG_RUNTIME_DIR/mftpd.sock)
        #[arg(long)]
        socket: Option<std::path::PathBuf>,
    },
}

/// Parse a `--fec DATA:PARITY` argument (e.g. `8:2`).
///
/// Returns a hard error on malformed or out-of-range input rather than silently
/// disabling FEC — a user who asked for parity should never unknowingly send
/// without it.  Bounds match the Reed-Solomon limits enforced on the receiver.
fn parse_fec(s: &str) -> Result<FecParams> {
    let (data, parity) = s
        .split_once(':')
        .with_context(|| format!("--fec must be DATA:PARITY (e.g. 8:2), got {s:?}"))?;
    let data_shards: usize = data
        .trim()
        .parse()
        .with_context(|| format!("--fec DATA must be a number, got {data:?}"))?;
    let parity_shards: usize = parity
        .trim()
        .parse()
        .with_context(|| format!("--fec PARITY must be a number, got {parity:?}"))?;
    if data_shards < 2 {
        anyhow::bail!("--fec DATA must be ≥ 2 (got {data_shards})");
    }
    if parity_shards < 1 {
        anyhow::bail!("--fec PARITY must be ≥ 1 (got {parity_shards})");
    }
    if data_shards + parity_shards > 256 {
        anyhow::bail!(
            "--fec DATA + PARITY must be ≤ 256 (got {})",
            data_shards + parity_shards
        );
    }
    Ok(FecParams {
        data_shards,
        parity_shards,
    })
}

/// Map a transport name from the config file to a `ForcedTransport`.
///
/// Accepts the same spellings as the `--transport` CLI flag (case-insensitive).
/// Returns a hard error on anything else so a typo in the config doesn't
/// silently fall back to auto mode.
fn parse_transport(s: &str) -> Result<ForcedTransport> {
    match s.trim().to_ascii_lowercase().as_str() {
        "quic" => Ok(ForcedTransport::Quic),
        "tcp" => Ok(ForcedTransport::Tcp),
        "sftp" => Ok(ForcedTransport::Sftp),
        other => anyhow::bail!("config transport must be quic, tcp, or sftp (got {other:?})"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let file_cfg = Config::load()?;

    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .init();

    match cli.command {
        Command::Send {
            file,
            destination,
            trust,
            trust_device,
            remote_mftp,
            port,
            download,
            no_download,
            recursive,
            preserve,
            remote_binary_sha256,
        } => {
            // Merge persistent tuning knobs: explicit CLI flag > config file >
            // built-in default.  Each `cli.*` Option is `None` only when the
            // flag was omitted, so `.or(...)` makes the CLI win cleanly.
            let tcp_below_rtt = cli
                .tcp_below_rtt
                .or(file_cfg.tcp_below_rtt)
                .unwrap_or(DEFAULT_TCP_BELOW_RTT_MS);
            let tcp_rtt_threshold = std::time::Duration::from_secs_f64(tcp_below_rtt / 1000.0);

            // `--transport` (Option) wins; otherwise fall back to the config's
            // string form, which is parsed (and validated) here.
            let forced_transport = match cli.transport {
                Some(Transport::Quic) => Some(ForcedTransport::Quic),
                Some(Transport::Tcp) => Some(ForcedTransport::Tcp),
                Some(Transport::Sftp) => Some(ForcedTransport::Sftp),
                None => match file_cfg.transport.as_deref() {
                    Some(s) => Some(parse_transport(s)?),
                    None => None,
                },
            };

            let fec = match cli.fec.as_deref().or(file_cfg.fec.as_deref()) {
                Some(s) => Some(parse_fec(s)?),
                None => None,
            };

            // `--no-compress` is a one-way flag: passing it on the CLI or
            // setting it in the config disables compression.  There is no CLI
            // way to force compression back on, so OR is the correct merge.
            let compress = !(cli.no_compress || file_cfg.no_compress);

            let streams = cli.streams.or(file_cfg.streams);
            let chunk_size = cli.chunk_size.or(file_cfg.chunk_size);
            let port = port.or(file_cfg.port);

            // Validate -r / directory combination early to give a clear error.
            if file.is_dir() && !recursive {
                anyhow::bail!(
                    "{} is a directory — pass -r to transfer it recursively",
                    file.display()
                );
            }
            let mut config = sender::SendConfig {
                streams,
                chunk_size,
                compress,
                compress_level: 3,
                trusted_fingerprint: trust,
                trusted_device: trust_device,
                // Present our persistent device identity as a client certificate
                // so daemons enforcing DeviceId auth can verify this sender.
                client_identity: mftp::identity::load_or_create().ok(),
                forced_transport,
                tcp_rtt_threshold,
                fec,
                parallel_reads: cli.parallel_reads,
                paths: cli.paths.unwrap_or(1).max(1),
                recursive,
                preserve,
            };
            let download_policy = match (download, no_download) {
                (true, _) => mftp::ssh::DownloadPolicy::Always,
                (_, true) => mftp::ssh::DownloadPolicy::Never,
                _ => mftp::ssh::DownloadPolicy::Ask,
            };
            if let Some(dest) = mftp::ssh::parse_ssh_dest(&destination)? {
                mftp::ssh::send_via_ssh(
                    file,
                    dest,
                    config,
                    remote_mftp,
                    port,
                    download_policy,
                    remote_binary_sha256,
                )
                .await
            } else if let Ok(addr) = destination.parse::<std::net::SocketAddr>() {
                sender::send(file, addr, config).await
            } else {
                // Not host:port and not an SSH dest — treat it as a LAN name and
                // resolve it via mftp discovery (M5).
                let resolved = mftp::discovery::resolve(
                    &destination,
                    mftp::discovery::multicast_target(),
                    std::time::Duration::from_secs(3),
                )
                .await
                .with_context(|| format!("discovery for {destination:?}"))?
                .with_context(|| {
                    format!(
                        "no mftp receiver named {destination:?} found on the LAN \
                         (is `mftp daemon`/`receive --name` running there?), and it is \
                         not a valid host:port or SSH destination"
                    )
                })?;
                eprintln!(
                    "[mftp] resolved {destination:?} → {} (device {})",
                    resolved.addr, resolved.device_id
                );
                // Auto-pin the discovered DeviceId unless the user pinned trust.
                if config.trusted_fingerprint.is_none() && config.trusted_device.is_none() {
                    config.trusted_device = Some(resolved.device_id);
                }
                sender::send(file, resolved.addr, config).await
            }
        }
        Command::Receive { bind, output_dir } => {
            let addr = bind
                .parse()
                .with_context(|| format!("invalid bind address: {bind}"))?;
            receiver::listen(addr, receiver::ReceiveConfig { output_dir }).await
        }
        Command::Server { output_dir, port } => receiver::serve_one_stdio(output_dir, port).await,
        #[cfg(unix)]
        Command::Daemon {
            bind,
            output_dir,
            socket,
            name,
        } => {
            let addr = bind
                .parse()
                .with_context(|| format!("invalid bind address: {bind}"))?;
            let socket = socket
                .or_else(mftp::daemon::default_socket_path)
                .context("cannot determine control socket path")?;
            let name = name.unwrap_or_else(mftp::discovery::hostname);
            mftp::daemon::run(addr, output_dir, socket, name).await
        }
        #[cfg(unix)]
        Command::DaemonStatus { socket } => {
            let socket = socket
                .or_else(mftp::daemon::default_socket_path)
                .context("cannot determine control socket path")?;
            run_daemon_ctl(&socket, mftp::daemon::DaemonRequest::Status).await?;
            run_daemon_ctl(&socket, mftp::daemon::DaemonRequest::Identity).await
        }
        #[cfg(unix)]
        Command::DaemonTrust {
            action,
            device_id,
            socket,
        } => {
            let socket = socket
                .or_else(mftp::daemon::default_socket_path)
                .context("cannot determine control socket path")?;
            let req = match action.as_str() {
                "list" => mftp::daemon::DaemonRequest::ListTrust,
                "add" => mftp::daemon::DaemonRequest::AddTrust {
                    device_id: device_id.context("`add` requires a device id")?,
                },
                "remove" => mftp::daemon::DaemonRequest::RemoveTrust {
                    device_id: device_id.context("`remove` requires a device id")?,
                },
                other => anyhow::bail!("unknown trust action {other:?} (use add|remove|list)"),
            };
            run_daemon_ctl(&socket, req).await
        }
    }
}

/// Send one control request to the daemon and print the reply.
#[cfg(unix)]
async fn run_daemon_ctl(socket: &std::path::Path, req: mftp::daemon::DaemonRequest) -> Result<()> {
    use mftp::daemon::DaemonResponse;
    match mftp::daemon::client_request(socket, req).await? {
        DaemonResponse::Pong => println!("pong"),
        DaemonResponse::Identity {
            device_id,
            fingerprint,
        } => {
            println!("Device ID:   {device_id}");
            println!("Fingerprint: {fingerprint}");
        }
        DaemonResponse::Trust { devices } => {
            if devices.is_empty() {
                println!("(no authorized devices — receiver is open)");
            } else {
                for d in devices {
                    println!("{d}");
                }
            }
        }
        DaemonResponse::TrustChanged { changed } => {
            println!(
                "{}",
                if changed {
                    "ok (changed)"
                } else {
                    "ok (no change)"
                }
            );
        }
        DaemonResponse::Status {
            listening_on,
            auth_enforced,
            authorized_count,
            transfers_completed,
        } => {
            println!("listening_on:        {listening_on}");
            println!("auth_enforced:       {auth_enforced}");
            println!("authorized_devices:  {authorized_count}");
            println!("transfers_completed: {transfers_completed}");
        }
        DaemonResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_fec;

    #[test]
    fn fec_valid() {
        let f = parse_fec("8:2").unwrap();
        assert_eq!(f.data_shards, 8);
        assert_eq!(f.parity_shards, 2);
        // surrounding whitespace tolerated
        assert!(parse_fec(" 4 : 1 ").is_ok());
    }

    #[test]
    fn fec_rejects_malformed() {
        assert!(parse_fec("8").is_err()); // no separator
        assert!(parse_fec("x:2").is_err()); // non-numeric data
        assert!(parse_fec("8:y").is_err()); // non-numeric parity
        assert!(parse_fec("1:2").is_err()); // data < 2
        assert!(parse_fec("8:0").is_err()); // parity < 1
        assert!(parse_fec("200:100").is_err()); // sum > 256
    }
}
