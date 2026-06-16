//! End-to-end rendezvous test (M6).
//!
//! Runs a rendezvous broker, a real QUIC receiver (with an Ed25519 identity)
//! that registers itself by DeviceId, and a sender that resolves the DeviceId
//! through the broker and transfers the file over QUIC. This exercises the full
//! signaling → candidate-exchange → connect → transfer path on loopback (no NAT;
//! cross-NAT hole punching is validated at deployment).

use std::net::SocketAddr;
use std::time::Duration;

use mftp::net::connection::make_private_key;
use mftp::reach::relay::RelayServer;
use mftp::reach::{lookup, register, RendezvousServer};
use mftp::transfer::receiver::Server;
use mftp::transfer::sender::{self, ForcedTransport, SendConfig};
use tempfile::TempDir;

fn make_file(dir: &std::path::Path, name: &str, size: usize) -> std::path::PathBuf {
    let path = dir.join(name);
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &data).unwrap();
    path
}

#[tokio::test]
async fn rendezvous_resolves_and_transfers() -> anyhow::Result<()> {
    // 1. Rendezvous broker.
    let broker_srv = RendezvousServer::bind("127.0.0.1:0".parse()?).await?;
    let broker = broker_srv.local_addr()?;
    tokio::spawn(async move {
        let _ = broker_srv.serve().await;
    });

    // 2. Receiver with a persistent Ed25519 identity (so its DeviceId is valid).
    let rcfg = TempDir::new()?;
    let recv_dir = TempDir::new()?;
    let send_dir = TempDir::new()?;
    let id = mftp::identity::load_or_create_in(rcfg.path())?;
    let server = Server::bind_with_cert(
        "127.0.0.1:0".parse()?,
        recv_dir.path().to_owned(),
        id.cert.clone(),
        make_private_key(id.key_bytes.clone())?,
        id.fingerprint.clone(),
    )?;
    let recv_addr = server.local_addr;
    let recv_task = tokio::spawn(async move { server.accept_one().await });

    // 3. Receiver registers at the broker and holds its presence open.
    let mut presence = register(broker, &id.device_id, vec![recv_addr]).await?;
    let _presence_task = tokio::spawn(async move {
        // Drain offers so the presence connection stays alive during the test.
        let _ = presence.next_offer().await;
    });

    // 4. Sender resolves the DeviceId via the broker, then transfers over QUIC.
    let src = make_file(send_dir.path(), "rdv.bin", 512 * 1024);
    let candidates: Vec<SocketAddr> = lookup(broker, &id.device_id, vec![])
        .await?
        .expect("receiver registered");
    assert_eq!(candidates, vec![recv_addr]);

    sender::send(
        src.clone(),
        candidates[0],
        SendConfig {
            streams: Some(2),
            chunk_size: Some(256 * 1024),
            compress: false,
            compress_level: 3,
            trusted_fingerprint: None,
            trusted_device: Some(id.device_id.clone()), // auto-pin the resolved DeviceId
            client_identity: None,
            forced_transport: Some(ForcedTransport::Quic),
            tcp_rtt_threshold: Duration::ZERO,
            fec: None,
            parallel_reads: false,
            paths: 1,
            recursive: false,
            preserve: false,
        },
    )
    .await?;
    recv_task.await??;

    let received = recv_dir.path().join(src.file_name().unwrap());
    assert_eq!(std::fs::read(&src)?, std::fs::read(&received)?);
    Ok(())
}

/// A full mftp QUIC transfer routed through the zero-knowledge UDP relay (M7).
/// The sender aims QUIC at the relay; the relay blindly forwards datagrams to
/// the receiver and back. End-to-end TLS means the relay only ever sees
/// ciphertext. Loopback stands in for the symmetric-NAT case.
#[tokio::test]
async fn transfer_through_relay() -> anyhow::Result<()> {
    let recv_dir = TempDir::new()?;
    let send_dir = TempDir::new()?;

    // Receiver on loopback.
    let server = Server::bind("127.0.0.1:0".parse()?, recv_dir.path().to_owned())?;
    let recv_addr = server.local_addr;
    let fingerprint = server.fingerprint.clone();
    let recv_task = tokio::spawn(async move { server.accept_one().await });

    // Relay forwarding to the receiver; the sender will aim at the relay.
    let relay = RelayServer::bind("127.0.0.1:0".parse()?, recv_addr).await?;
    let relay_addr = relay.local_addr();
    let relay_task = tokio::spawn(async move { relay.run().await });

    let src = make_file(send_dir.path(), "relayed.bin", 768 * 1024);
    sender::send(
        src.clone(),
        relay_addr, // connect to the relay, not the receiver directly
        SendConfig {
            streams: Some(2),
            chunk_size: Some(256 * 1024),
            compress: false,
            compress_level: 3,
            trusted_fingerprint: Some(fingerprint), // TLS is end-to-end to the receiver
            trusted_device: None,
            client_identity: None,
            forced_transport: Some(ForcedTransport::Quic),
            tcp_rtt_threshold: Duration::ZERO,
            fec: None,
            parallel_reads: false,
            paths: 1,
            recursive: false,
            preserve: false,
        },
    )
    .await?;
    recv_task.await??;
    relay_task.abort();

    let received = recv_dir.path().join(src.file_name().unwrap());
    assert_eq!(std::fs::read(&src)?, std::fs::read(&received)?);
    Ok(())
}
