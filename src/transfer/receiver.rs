//! Receiver-side transfer orchestration. See `transfer/mod.rs` for the full flow.

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
    messages::{
        ChunkData, NegotiateRequest, NegotiateResponse, ReceiverMessage, SenderMessage,
        TransferManifest,
    },
};
use crate::transfer::hash::ChunkHasher;
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
    // ── Negotiation ───────────────────────────────────────────────────────────
    let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;

    let neg_req: NegotiateRequest =
        framing::recv_message_required(&mut ctrl_recv).await?;
    let receiver_cores =
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;
    framing::send_message(
        &mut ctrl_send,
        &NegotiateResponse { cpu_cores: receiver_cores },
    )
    .await?;
    debug!(
        sender_cores = neg_req.cpu_cores,
        receiver_cores,
        file_size = neg_req.file_size,
        "negotiation complete"
    );

    // ── Manifest ──────────────────────────────────────────────────────────────
    let manifest: TransferManifest =
        framing::recv_message_required(&mut ctrl_recv).await?;

    // ── Validate manifest — all fields come from an untrusted sender ──────────
    validate_manifest(&manifest)?;

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
    // Path traversal is already ruled out by validate_manifest.
    let out_path = output_dir.join(&manifest.file_name);
    let out_file = Arc::new({
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&out_path)
            .with_context(|| format!("open output {}", out_path.display()))?;
        // fallocate(0) allocates real disk blocks upfront so every subsequent
        // pwrite hits a pre-allocated block — no on-demand extent allocation.
        // Much faster than ftruncate (sparse file) on spinning disks and most
        // SSDs.  Fall back to set_len on kernels/filesystems that don't
        // support fallocate (e.g. tmpfs, NFS, macOS).
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe {
                libc::fallocate(f.as_raw_fd(), 0, 0, manifest.file_size as libc::off_t)
            };
            if rc != 0 {
                f.set_len(manifest.file_size)?;
            }
        }
        #[cfg(not(target_os = "linux"))]
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

    // ── Inline hasher — accumulates the file hash as chunks arrive ────────────
    // Chunks arrive out of order; ChunkHasher buffers ahead-of-time chunks
    // and drains them into SHA-256 in index order.  When the last chunk is
    // received the hash is ready instantly — no extra disk read needed.
    let hasher = Arc::new(ChunkHasher::new(manifest.total_chunks));

    // ── Accept exactly num_streams unidirectional data streams ────────────────
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    for _ in 0..manifest.num_streams {
        let stream = conn.accept_uni().await.context("accept data stream")?;
        let out_file = out_file.clone();
        let resume = resume.clone();
        let manifest = manifest.clone();
        let pb = pb.clone();
        let hasher = hasher.clone();
        tasks.spawn(async move {
            recv_stream_worker(stream, out_file, resume, manifest, pb, hasher).await
        });
    }

    // Drain all tasks; on first error notify the sender before bailing.
    // Convert JoinError (task panic) to a regular error so we always send the
    // ReceiverMessage::Error to the sender rather than silently propagating.
    let mut task_err: Option<anyhow::Error> = None;
    while let Some(join_res) = tasks.join_next().await {
        let task_result = match join_res {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!("stream worker panicked: {e}")),
        };
        if let Err(e) = task_result {
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

    // ── Verify integrity — hash is already computed, no disk re-read ─────────
    let file_hash = Arc::try_unwrap(hasher)
        .expect("all stream tasks finished so no other Arc references exist")
        .finish()?;

    let expected_hash = match framing::recv_message_required(&mut ctrl_recv).await? {
        SenderMessage::Complete { file_hash } => file_hash,
    };

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
    hasher: Arc<ChunkHasher>,
) -> Result<()> {
    // Pipelined processing: keep up to MAX_IN_FLIGHT blocking tasks running
    // concurrently per stream.  While one chunk is being SHA-256 verified and
    // written to disk, the next chunk arrives over the network — overlapping
    // CPU/disk with network receive.  On a fast LAN this is the difference
    // between network being idle half the time and being fully utilised.
    const MAX_IN_FLIGHT: usize = 4;
    let mut processing: JoinSet<Result<()>> = JoinSet::new();

    loop {
        // Before receiving the next chunk, drain any completed tasks and
        // propagate errors early.  When at the pipeline limit, wait for a
        // slot to free up.
        if processing.len() >= MAX_IN_FLIGHT {
            match processing.join_next().await {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(e))) => return Err(e),
                Some(Err(e)) => bail!("chunk processing task panicked: {e}"),
                None => {}
            }
        }

        let chunk: ChunkData = match framing::recv_data_message(&mut stream).await? {
            Some(c) => c,
            None => break, // sender called finish() — normal stream end
        };

        // Reject out-of-range chunk indices before doing any work with them.
        if chunk.chunk_index >= manifest.total_chunks {
            bail!(
                "chunk index {} out of range (total_chunks {})",
                chunk.chunk_index,
                manifest.total_chunks
            );
        }

        let chunk_index = chunk.chunk_index;
        let chunk_size = manifest.chunk_size;
        let out_file = Arc::clone(&out_file);
        let hasher = Arc::clone(&hasher);
        let resume = Arc::clone(&resume);
        let pb = Arc::clone(&pb);

        // spawn_blocking hands SHA-256 + decompress + pwrite to the blocking
        // thread pool.  We do NOT await here — control returns to the top of
        // the loop immediately so the next chunk can arrive while this one
        // is being processed.
        processing.spawn_blocking(move || -> Result<()> {
            let computed: [u8; 32] = Sha256::digest(&chunk.payload).into();
            if computed != chunk.chunk_hash {
                bail!("chunk {} hash mismatch", chunk_index);
            }

            // chunk_size bounds decompressed output against decompression bombs.
            let data = if chunk.compressed {
                compress::decompress_chunk(&chunk.payload, chunk_size)?
            } else {
                chunk.payload
            };

            let offset = chunk_index * chunk_size as u64;
            {
                use std::os::unix::fs::FileExt;
                out_file
                    .write_all_at(&data, offset)
                    .with_context(|| format!("write chunk {chunk_index} at offset {offset}"))?;
            }

            hasher.feed(chunk_index, &data);
            pb.inc(data.len() as u64);
            resume.lock().unwrap().mark_received(chunk_index);
            debug!(chunk = chunk_index, "received");
            Ok(())
        });
    }

    // Drain all remaining in-flight tasks.
    while let Some(res) = processing.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => bail!("chunk processing task panicked: {e}"),
        }
    }

    Ok(())
}

// ── Manifest validation ───────────────────────────────────────────────────────

/// Maximum file size we are willing to accept (16 TiB).
const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024;
/// Chunk size must be between 4 KiB and 128 MiB.
const MIN_CHUNK_SIZE: usize = 4 * 1024;
const MAX_CHUNK_SIZE: usize = 128 * 1024 * 1024;
/// Sanity cap on stream count to prevent an accept_uni loop that never ends.
const MAX_STREAMS: usize = 1024;

fn validate_manifest(m: &crate::protocol::messages::TransferManifest) -> Result<()> {
    // ── file_name: path traversal ─────────────────────────────────────────────
    // Reject empty names, names with directory separators, and names with
    // leading dots that would create hidden files or relative paths.
    if m.file_name.is_empty() {
        bail!("manifest: file_name is empty");
    }
    if m.file_name.contains('/') || m.file_name.contains('\\') {
        bail!("manifest: file_name contains path separator: {:?}", m.file_name);
    }
    if m.file_name == ".." || m.file_name == "." {
        bail!("manifest: file_name is a relative-path component: {:?}", m.file_name);
    }

    // ── file_size ─────────────────────────────────────────────────────────────
    if m.file_size > MAX_FILE_SIZE {
        bail!(
            "manifest: file_size {} exceeds limit of {} bytes",
            m.file_size,
            MAX_FILE_SIZE
        );
    }

    // ── chunk_size ────────────────────────────────────────────────────────────
    if m.chunk_size < MIN_CHUNK_SIZE || m.chunk_size > MAX_CHUNK_SIZE {
        bail!(
            "manifest: chunk_size {} out of allowed range [{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}]",
            m.chunk_size
        );
    }

    // ── total_chunks must be consistent with file_size and chunk_size ─────────
    // This prevents a sender from claiming a huge total_chunks (which would
    // cause the ResumeState bit-vector to allocate gigabytes) independent of
    // what the actual file data warrants.
    let expected = m.file_size.div_ceil(m.chunk_size as u64);
    if m.total_chunks != expected {
        bail!(
            "manifest: total_chunks {} inconsistent with file_size {}/chunk_size {} (expected {})",
            m.total_chunks,
            m.file_size,
            m.chunk_size,
            expected
        );
    }

    // ── num_streams ───────────────────────────────────────────────────────────
    if m.num_streams == 0 || m.num_streams > MAX_STREAMS {
        bail!(
            "manifest: num_streams {} out of allowed range [1, {MAX_STREAMS}]",
            m.num_streams
        );
    }

    Ok(())
}
