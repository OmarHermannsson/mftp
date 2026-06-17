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

    /// Forward datagrams forever. The session is bound to the **first** sender
    /// that appears: thereafter, only datagrams from that sender (forward path)
    /// or the receiver (reply path) are relayed; datagrams from any other source
    /// are dropped. This prevents a stray/spoofed packet from a third party
    /// hijacking the session (redirecting the receiver's replies, breaking or
    /// eavesdropping the in-flight transfer). Payloads are never inspected.
    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut sender_addr: Option<SocketAddr> = None;
        loop {
            let (n, from) = self.sock.recv_from(&mut buf).await.context("relay recv")?;
            let payload = &buf[..n];
            if from == self.receiver_addr {
                // Reply path: receiver → sender (only once a sender is bound).
                if let Some(s) = sender_addr {
                    let _ = self.sock.send_to(payload, s).await;
                }
            } else if sender_addr == Some(from) {
                // Forward path from the bound sender.
                let _ = self.sock.send_to(payload, self.receiver_addr).await;
            } else if sender_addr.is_none() {
                // First sender to appear binds the session.
                sender_addr = Some(from);
                let _ = self.sock.send_to(payload, self.receiver_addr).await;
            }
            // else: a different source after the session is bound — ignore.
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

    /// Once a session is bound to the first sender, a stray datagram from a third
    /// party must not hijack it: the attacker's packet is dropped and the
    /// receiver's replies still go to the original sender.
    #[tokio::test]
    async fn relay_ignores_third_party_after_binding() {
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
        let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut buf = [0u8; 256];

        // Bind the session to `sender`.
        sender.send_to(b"hello", relay_addr).await.unwrap();
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Attacker tries to hijack — its datagram must be dropped (not forwarded).
        attacker.send_to(b"HIJACK", relay_addr).await.unwrap();

        // The receiver's reply must still reach the original sender, not the
        // attacker. Send a reply and confirm `sender` gets it and `attacker`
        // gets nothing within a short window.
        receiver.send_to(b"reply", relay_addr).await.unwrap();
        let (n, _) = sender.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply", "reply still routed to original sender");

        // The attacker must not receive the receiver's reply.
        let mut abuf = [0u8; 256];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            attacker.recv_from(&mut abuf),
        )
        .await;
        assert!(
            got.is_err(),
            "attacker must not receive the receiver's reply"
        );
    }
}
