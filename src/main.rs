use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use mftp::transfer::{receiver, sender};

#[derive(Parser)]
#[command(name = "mftp", about = "High-throughput file transfer over high-latency links", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Number of parallel streams (default: auto-negotiated from RTT + CPU cores)
    #[arg(short = 'n', long, global = true)]
    streams: Option<usize>,

    /// Chunk size in bytes (default: auto-negotiated from RTT)
    #[arg(long, global = true)]
    chunk_size: Option<usize>,

    /// Disable adaptive zstd compression
    #[arg(long, global = true)]
    no_compress: bool,

    /// Use TCP+TLS instead of QUIC (useful when UDP is blocked)
    #[arg(long, global = true)]
    tcp: bool,

    /// Switch to TCP+TLS when measured RTT is at or below this value (milliseconds).
    /// Prevents QUIC overhead from hurting throughput on LAN / same-datacenter links.
    /// Set to 0 to always use QUIC regardless of RTT.
    #[arg(long, global = true, default_value = "1.0", value_name = "MS")]
    tcp_below_rtt: f64,

    /// Verbosity (-v = info, -vv = debug, -vvv = trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Command {
    /// Send a file to a remote mftp receiver
    Send {
        /// File to send
        file: std::path::PathBuf,
        /// Destination: `host:port` for a running receiver, or
        /// `[user@]host:/path` to launch the receiver automatically via SSH
        destination: String,
        /// Pin the receiver's certificate fingerprint (hex SHA-256).
        /// Omit to use TOFU: fingerprint is printed and accepted on first connect.
        /// Ignored when connecting via SSH (fingerprint is obtained from the server).
        #[arg(long)]
        trust: Option<String>,
        /// Use this pre-installed binary on the remote instead of copying the
        /// local binary.  By default mftp pipes itself to the remote so no
        /// prior installation is required.
        #[arg(long)]
        remote_mftp: Option<String>,
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
        Command::Send { file, destination, trust, remote_mftp } => {
            let tcp_rtt_threshold = std::time::Duration::from_secs_f64(cli.tcp_below_rtt / 1000.0);
            let config = sender::SendConfig {
                streams: cli.streams,
                chunk_size: cli.chunk_size,
                compress: !cli.no_compress,
                compress_level: 3,
                trusted_fingerprint: trust,
                use_tcp: cli.tcp,
                tcp_rtt_threshold,
            };
            if let Some(dest) = mftp::ssh::parse_ssh_dest(&destination) {
                mftp::ssh::send_via_ssh(file, dest, config, remote_mftp).await
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
        Command::Server { output_dir } => {
            receiver::serve_one_stdio(output_dir).await
        }
    }
}
