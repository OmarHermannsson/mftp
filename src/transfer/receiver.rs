//! Receiver-side transfer orchestration. See `transfer/mod.rs` for the full flow.

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::compress;
use crate::net::connection::make_server_endpoint;
use crate::protocol::{
    framing,
    messages::{ChunkData, ReceiverMessage, SenderMessage, TransferManifest},
};
use crate::transfer::resume::ResumeState;

pub struct ReceiveConfig {
    pub output_dir: PathBuf,
}

/// A bound QUIC server endpoint, ready to accept incoming transfers.
///
/// Separating bind from serve lets callers (and tests) inspect `local_addr`
/// and `fingerprint` before starting the accept loop.
pub struct Server {
    endpoint: quinn::Endpoint,
    /// The actual bound address — useful when binding on port 0.
    pub local_addr: SocketAddr,
    /// Hex SHA-256 fingerprint of the server's self-signed certificate.
    /// Pass this to the sender's `--trust` flag for non-interactive use.
    pub fingerprint: String,
    output_dir: PathBuf,
}

impl Server {
    pub fn bind(addr: SocketAddr, output_dir: PathBuf) -> Result<Self> {
        let (endpoint, fingerprint) = make_server_endpoint(addr)?;
        let local_addr = endpoint.local_addr()?;
        Ok(Self { endpoint, local_addr, fingerprint, output_dir })
    }

    /// Accept and handle exactly one incoming connection, then return.
    /// Intended for integration tests; production code should use `serve`.
    pub async fn accept_one(&self) -> Result<()> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("endpoint closed before any connection arrived"))?;
        let conn = incoming.await.context("connection setup failed")?;
        info!("connection from {}", conn.remote_address());
        handle_connection(conn, self.output_dir.clone()).await
    }

    /// Accept and handle connections indefinitely.
    pub async fn serve(self) -> Result<()> {
        println!("Listening on {}", self.local_addr);
        println!(
            "Certificate fingerprint (share with sender --trust):\n  {}",
            self.fingerprint
        );
        while let Some(incoming) = self.endpoint.accept().await {
            let out = self.output_dir.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        info!("connection from {}", conn.remote_address());
                        if let Err(e) = handle_connection(conn, out).await {
                            tracing::error!("transfer error: {e:#}");
                        }
                    }
                    Err(e) => warn!("incoming connection failed: {e}"),
                }
            });
        }
        Ok(())
    }
}

/// Convenience wrapper for the CLI; binds and serves indefinitely.
pub async fn listen(bind: SocketAddr, config: ReceiveConfig) -> Result<()> {
    Server::bind(bind, config.output_dir)?.serve().await
}

// ── Per-connection logic ──────────────────────────────────────────────────────

async fn handle_connection(conn: quinn::Connection, output_dir: PathBuf) -> Result<()> {
    // Keep conn alive until the end so we can call conn.closed() before dropping it.
    // ── Handshake ─────────────────────────────────────────────────────────────
    let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;
    let manifest: TransferManifest =
        framing::recv_message_required(&mut ctrl_recv).await?;
    info!(
        file = %manifest.file_name,
        size = manifest.file_size,
        chunks = manifest.total_chunks,
        streams = manifest.num_streams,
        "transfer started"
    );

    // Resume: tell sender which chunks we already have
    let resume = Arc::new(Mutex::new(ResumeState::load_or_new(
        &output_dir,
        &manifest.transfer_id,
        manifest.total_chunks,
    )));
    let have_chunks = resume.lock().unwrap().received_chunks();
    framing::send_message(&mut ctrl_send, &ReceiverMessage::Ready { have_chunks }).await?;

    // ── Pre-allocate output file ──────────────────────────────────────────────
    let out_path = output_dir.join(&manifest.file_name);
    let out_file = Arc::new({
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&out_path)
            .with_context(|| format!("open output {}", out_path.display()))?;
        // Pre-allocate so parallel pwrite calls don't race on extending the file.
        f.set_len(manifest.file_size)?;
        f
    });

    // ── Progress ──────────────────────────────────────────────────────────────
    let pb = Arc::new({
        let pb = ProgressBar::new(manifest.file_size);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] {bar:50.cyan/blue} \
                 {bytes}/{total_bytes} {bytes_per_sec} eta {eta}",
            )
            .unwrap(),
        );
        pb
    });

    // ── Accept exactly num_streams unidirectional data streams ────────────────
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..manifest.num_streams {
        let stream = conn.accept_uni().await.context("accept data stream")?;
        let out_file = out_file.clone();
        let resume = resume.clone();
        let manifest = manifest.clone();
        let pb = pb.clone();
        tasks.spawn(async move {
            recv_stream_worker(stream, out_file, resume, manifest, pb).await
        });
    }

    // Drain all tasks; on first error notify the sender before bailing.
    let mut task_err: Option<anyhow::Error> = None;
    while let Some(res) = tasks.join_next().await {
        if let Err(e) = res? {
            if task_err.is_none() {
                let _ = framing::send_message(
                    &mut ctrl_send,
                    &ReceiverMessage::Error { message: e.to_string() },
                )
                .await;
                task_err = Some(e);
            }
        }
    }
    pb.finish();
    if let Some(e) = task_err {
        bail!("{e}");
    }

    // ── Check completeness ────────────────────────────────────────────────────
    let missing = resume.lock().unwrap().missing_chunks();
    if !missing.is_empty() {
        warn!("{} chunks missing, requesting retransmit", missing.len());
        framing::send_message(
            &mut ctrl_send,
            &ReceiverMessage::Retransmit { chunk_indices: missing },
        )
        .await?;
        bail!("transfer incomplete; retransmit requested");
    }

    // ── Read sender's file hash, then verify our copy ─────────────────────────
    // The sender computed the hash concurrently with the transfer and sends it
    // here, after all data streams are done. We then hash our received file and
    // compare. The connection is kept alive by the sender's keep_alive_interval.
    let expected_hash = match framing::recv_message_required(&mut ctrl_recv).await? {
        SenderMessage::Complete { file_hash } => file_hash,
    };

    info!("verifying file integrity...");
    let file_hash = hash_file(&out_path).await?;
    if file_hash != expected_hash {
        framing::send_message(
            &mut ctrl_send,
            &ReceiverMessage::Error { message: "file hash mismatch".into() },
        )
        .await?;
        bail!("file hash mismatch — file is corrupted");
    }

    framing::send_message(&mut ctrl_send, &ReceiverMessage::Complete { file_hash }).await?;
    let _ = ctrl_send.finish();

    resume.lock().unwrap().delete()?;
    println!("Received: {}", out_path.display());

    // Wait for the sender to close the connection before we drop `conn`.
    // If we drop `conn` first, quinn sends CONNECTION_CLOSE(0) immediately,
    // which can race with the sender reading the Complete message above.
    let _ = conn.closed().await;
    Ok(())
}

async fn recv_stream_worker(
    mut stream: quinn::RecvStream,
    out_file: Arc<std::fs::File>,
    resume: Arc<Mutex<ResumeState>>,
    manifest: TransferManifest,
    pb: Arc<ProgressBar>,
) -> Result<()> {
    loop {
        let chunk: ChunkData = match framing::recv_message(&mut stream).await? {
            Some(c) => c,
            None => break, // sender called finish() — normal stream end
        };

        // Verify chunk integrity
        let computed: [u8; 32] = Sha256::digest(&chunk.payload).into();
        if computed != chunk.chunk_hash {
            bail!("chunk {} hash mismatch", chunk.chunk_index);
        }

        // Decompress if the sender flagged it
        let data = if chunk.compressed {
            compress::decompress_chunk(&chunk.payload)?
        } else {
            chunk.payload
        };

        // pwrite: safe for concurrent callers on the same file descriptor
        let offset = chunk.chunk_index * manifest.chunk_size as u64;
        {
            use std::os::unix::fs::FileExt;
            out_file
                .write_all_at(&data, offset)
                .with_context(|| {
                    format!("write chunk {} at offset {}", chunk.chunk_index, offset)
                })?;
        }

        pb.inc(data.len() as u64);
        resume.lock().unwrap().mark_received(chunk.chunk_index);
        debug!(chunk = chunk.chunk_index, "received");
    }
    Ok(())
}

async fn hash_file(path: &PathBuf) -> Result<[u8; 32]> {
    let path = path.clone();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok::<[u8; 32], anyhow::Error>(hasher.finalize().into())
    })
    .await?
}
