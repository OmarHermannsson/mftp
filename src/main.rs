#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use mftp::protocol::messages::FecParams;
use mftp::transfer::sender::ForcedTransport;
use mftp::transfer::{receiver, sender};

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
    version
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

    /// Disable adaptive zstd compression
    #[arg(long, global = true)]
    no_compress: bool,

    /// Enable Reed-Solomon forward error correction.
    ///
    /// Specify as DATA:PARITY (e.g. --fec 8:2 adds 25% bandwidth overhead but
    /// tolerates up to 2 lost chunks per 8-chunk stripe without retransmission).
    /// Most useful on high-latency lossy links (satellite, intercontinental).
    /// Automatically disabled when the transport falls back to TCP (reliable delivery).
    #[arg(long, global = true, value_name = "DATA:PARITY")]
    fec: Option<String>,

    /// Dynamically scale the number of parallel streams during transfer.
    ///
    /// Requires both sender and receiver to be protocol version ≥ 2.
    /// The sender measures throughput and receiver congestion every 100 ms and
    /// adjusts the stream count to maximise utilisation without saturating the
    /// receiver.  Stream count is bounded by [2, 2 × min(cores)].
    /// Silently disabled if the peer does not support protocol version ≥ 2.
    #[arg(long, global = true, default_value_t = true, action = clap::ArgAction::Set)]
    adaptive_streams: bool,

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

    /// Force TCP+TLS transport (alias for --transport tcp)
    #[arg(long, global = true, hide = true)]
    tcp: bool,

    /// In auto mode, switch to TCP+TLS when measured RTT is at or below this value (ms).
    /// Default 15 ms: QUIC+BBR is slower than TCP+CUBIC at low latency due to slow
    /// congestion window ramp-up.  Set 0 to always use QUIC, or higher to widen the
    /// TCP window.  Ignored when --transport is set.
    #[arg(long, global = true, default_value = "15", value_name = "MS")]
    tcp_below_rtt: f64,

    /// Use multiple parallel file readers instead of a single sequential reader.
    ///
    /// Splits the file into one range per stream and reads them concurrently.
    /// Only beneficial on local NVMe with queue depth ≥ 32; has no measurable
    /// effect on network-bound transfers or spinning disks.
    #[arg(long, global = true)]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

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
            remote_mftp,
            port,
            download,
            no_download,
            recursive,
            preserve,
        } => {
            let tcp_rtt_threshold = std::time::Duration::from_secs_f64(cli.tcp_below_rtt / 1000.0);
            let forced_transport = match (cli.transport, cli.tcp) {
                (Some(Transport::Quic), _) => Some(ForcedTransport::Quic),
                (Some(Transport::Tcp), _) | (None, true) => Some(ForcedTransport::Tcp),
                (Some(Transport::Sftp), _) => Some(ForcedTransport::Sftp),
                (None, false) => None,
            };
            let fec = cli.fec.as_deref().and_then(|s| {
                let parts: Vec<&str> = s.splitn(2, ':').collect();
                if parts.len() != 2 {
                    eprintln!("[mftp] --fec must be DATA:PARITY (e.g. 8:2); ignoring");
                    return None;
                }
                let data = parts[0].parse::<usize>().ok();
                let parity = parts[1].parse::<usize>().ok();
                match (data, parity) {
                    (Some(d), Some(p)) if d >= 2 && p >= 1 => Some(FecParams {
                        data_shards: d,
                        parity_shards: p,
                    }),
                    _ => {
                        eprintln!(
                            "[mftp] --fec: DATA must be ≥ 2 and PARITY must be ≥ 1; ignoring"
                        );
                        None
                    }
                }
            });
            // Validate -r / directory combination early to give a clear error.
            if file.is_dir() && !recursive {
                anyhow::bail!(
                    "{} is a directory — pass -r to transfer it recursively",
                    file.display()
                );
            }
            let config = sender::SendConfig {
                streams: cli.streams,
                chunk_size: cli.chunk_size,
                compress: !cli.no_compress,
                compress_level: 3,
                trusted_fingerprint: trust,
                forced_transport,
                tcp_rtt_threshold,
                fec,
                adaptive_streams: cli.adaptive_streams,
                parallel_reads: cli.parallel_reads,
                recursive,
                preserve,
            };
            let download_policy = match (download, no_download) {
                (true, _) => mftp::ssh::DownloadPolicy::Always,
                (_, true) => mftp::ssh::DownloadPolicy::Never,
                _ => mftp::ssh::DownloadPolicy::Ask,
            };
            if let Some(dest) = mftp::ssh::parse_ssh_dest(&destination)? {
                mftp::ssh::send_via_ssh(file, dest, config, remote_mftp, port, download_policy)
                    .await
            } else {
                let addr = destination
                    .parse()
                    .with_context(|| format!("invalid address: {destination}"))?;
                sender::send(file, addr, config).await
            }
        }
        Command::Receive { bind, output_dir } => {
            let addr = bind
                .parse()
                .with_context(|| format!("invalid bind address: {bind}"))?;
            if cli.tcp {
                receiver::listen_tcp(addr, receiver::ReceiveConfig { output_dir }).await
            } else {
                receiver::listen(addr, receiver::ReceiveConfig { output_dir }).await
            }
        }
        Command::Server { output_dir, port } => receiver::serve_one_stdio(output_dir, port).await,
    }
}
