use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use mftp::transfer::{receiver, sender};

#[derive(Parser)]
#[command(name = "mftp", about = "High-throughput file transfer over high-latency links")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Number of parallel QUIC streams (default: auto-negotiated from RTT + CPU cores)
    #[arg(short = 'n', long, global = true)]
    streams: Option<usize>,

    /// Chunk size in bytes (default: auto-negotiated from RTT)
    #[arg(long, global = true)]
    chunk_size: Option<usize>,

    /// Disable adaptive zstd compression
    #[arg(long, global = true)]
    no_compress: bool,

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
        /// Destination address (host:port or IP:port)
        destination: String,
        /// Pin the receiver's certificate fingerprint (hex SHA-256).
        /// Omit to use TOFU: fingerprint is printed and accepted on first connect.
        #[arg(long)]
        trust: Option<String>,
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
        Command::Send { file, destination, trust } => {
            let addr = destination
                .parse()
                .with_context(|| format!("invalid address: {destination}"))?;
            sender::send(
                file,
                addr,
                sender::SendConfig {
                    streams: cli.streams,
                    chunk_size: cli.chunk_size,
                    compress: !cli.no_compress,
                    compress_level: 3,
                    trusted_fingerprint: trust,
                },
            )
            .await
        }
        Command::Receive { bind, output_dir } => {
            let addr = bind
                .parse()
                .with_context(|| format!("invalid bind address: {bind}"))?;
            receiver::listen(
                addr,
                receiver::ReceiveConfig { output_dir },
            )
            .await
        }
    }
}
