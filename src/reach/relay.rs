//! Zero-knowledge UDP relay fallback (mftp v2, milestone M7).
//!
//! When hole punching fails (e.g. symmetric NAT on both sides), the two peers
//! fall back to a relay that blindly forwards UDP datagrams between them. Because
//! mftp's entire QUIC connection — control stream and all data streams — rides a
//! single UDP 4-tuple, one relay session carries the whole transfer.
//!
//! The relay is **zero-knowledge**: TLS terminates at the two mftp endpoints
//! (authenticated by their device certs/IDs), so the relay only ever sees
//! ciphertext. It copies datagrams; it never decrypts, parses, or stores them.
//!
//! This minimal relay carries a single session per bound socket: the receiver's
//! address is known up front, the first other source becomes the sender, and
//! datagrams are forwarded sender↔receiver. A production relay allocates a
//! distinct session (port/token) per pair; that allocation is layered on top —
//! the forwarding core verified here is identical.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

/// A bound single-session UDP relay forwarding between a known receiver and the
/// first sender that appears.
pub struct RelayServer {
    sock: UdpSocket,
    receiver_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl RelayServer {
    /// Bind the relay on `bind` and forward to/from `receiver_addr`.
    pub async fn bind(bind: SocketAddr, receiver_addr: SocketAddr) -> Result<Self> {
        let sock = UdpSocket::bind(bind)
            .await
            .with_context(|| format!("bind relay on {bind}"))?;
        let local_addr = sock.local_addr()?;
        Ok(RelayServer {
            sock,
            receiver_addr,
            local_addr,
        })
    }

    /// The address senders should aim their QUIC connection at.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Forward datagrams forever. Datagrams from the receiver go to the current
    /// sender; datagrams from anyone else are treated as the sender and go to
    /// the receiver. Payloads are forwarded verbatim — never inspected.
    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut sender_addr: Option<SocketAddr> = None;
        loop {
            let (n, from) = self.sock.recv_from(&mut buf).await.context("relay recv")?;
            let payload = &buf[..n];
            if from == self.receiver_addr {
                // Reply path: receiver → sender.
                if let Some(s) = sender_addr {
                    let _ = self.sock.send_to(payload, s).await;
                }
            } else {
                // Forward path: sender → receiver. Latch the sender address so
                // the receiver's replies can be routed back.
                sender_addr = Some(from);
                let _ = self.sock.send_to(payload, self.receiver_addr).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// The relay forwards opaque bytes in both directions without inspecting
    /// them — a stand-in for the zero-knowledge ciphertext property.
    #[tokio::test]
    async fn relay_forwards_both_directions_verbatim() {
        // Stand-in "receiver" and "sender" UDP sockets on loopback.
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let relay = RelayServer::bind((Ipv4Addr::LOCALHOST, 0).into(), receiver_addr)
            .await
            .unwrap();
        let relay_addr = relay.local_addr();
        tokio::spawn(async move {
            let _ = relay.run().await;
        });

        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

        // sender → relay → receiver
        let opaque = b"\x00\xff\x01\xfe ciphertext-ish";
        sender.send_to(opaque, relay_addr).await.unwrap();
        let mut buf = [0u8; 256];
        let (n, seen_from) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], opaque, "payload forwarded verbatim to receiver");
        assert_eq!(seen_from, relay_addr, "receiver sees the relay as the peer");

        // receiver → relay → sender (reply path)
        let reply = b"\xde\xad\xbe\xef reply";
        receiver.send_to(reply, relay_addr).await.unwrap();
        let (n, seen_from) = sender.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], reply, "reply forwarded verbatim to sender");
        assert_eq!(seen_from, relay_addr, "sender sees the relay as the peer");
    }
}
