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
//! address is known up front, and the sender slot is **claimed with a session
//! token** that is part of the relay allocation. The sender's first datagram
//! must be a claim (`CLAIM_MAGIC || token`, see [`claim_datagram`]) sent from
//! the socket its QUIC connection will use; until a valid claim arrives nothing
//! from any third party is forwarded, and a datagram from an unclaimed source
//! can never take over the session. A token holder may re-claim from a new
//! address (NAT rebinding, reconnect). Once claimed, a session that carries no
//! traffic for the idle timeout expires and [`RelayServer::run`] returns.
//!
//! Client side: a QUIC client endpoint built for a relay address that has been
//! armed with [`arm_client_claim`] (or for any address when `MFTP_RELAY_TOKEN`
//! is set) sends the claim from its socket before the QUIC handshake — see
//! `net::connection::make_client_endpoint`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// Prefix of a sender's session-claim datagram.
pub const CLAIM_MAGIC: &[u8; 8] = b"MFTPRLY1";
/// Session token length in bytes.
pub const TOKEN_LEN: usize = 16;
/// Default idle expiry of a claimed session. A live mftp QUIC connection sends
/// keep-alives every few seconds, so this only fires on a dead session.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Environment variable carrying a hex session token, honoured both by
/// [`RelayServer::bind`] (to use a pre-shared token) and by QUIC client
/// endpoints (to claim the relay they connect to).
pub const TOKEN_ENV: &str = "MFTP_RELAY_TOKEN";

/// A relay session token.
pub type RelayToken = [u8; TOKEN_LEN];

/// The datagram a sender emits to claim the relay's sender slot.
pub fn claim_datagram(token: &RelayToken) -> Vec<u8> {
    let mut d = Vec::with_capacity(CLAIM_MAGIC.len() + TOKEN_LEN);
    d.extend_from_slice(CLAIM_MAGIC);
    d.extend_from_slice(token);
    d
}

/// Parse a hex token (as printed by [`RelayServer::token_hex`]).
pub fn parse_token(hex_token: &str) -> Result<RelayToken> {
    let bytes = hex::decode(hex_token.trim()).context("relay token is not hex")?;
    bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "relay token must be {TOKEN_LEN} bytes ({} hex chars)",
            TOKEN_LEN * 2
        )
    })
}

/// Relay addresses this process should claim, with their tokens.
static CLIENT_CLAIMS: Mutex<Option<HashMap<SocketAddr, RelayToken>>> = Mutex::new(None);

/// Arm QUIC client endpoints built for `relay` to claim it with `token`.
pub fn arm_client_claim(relay: SocketAddr, token: RelayToken) {
    CLIENT_CLAIMS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(relay, token);
}

/// Forget a claim armed with [`arm_client_claim`].
pub fn disarm_client_claim(relay: SocketAddr) {
    if let Some(m) = CLIENT_CLAIMS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
    {
        m.remove(&relay);
    }
}

/// The claim datagram a client connecting to `server` should send first, if
/// any: an armed claim for that address, else one from `MFTP_RELAY_TOKEN`.
pub(crate) fn client_claim_for(server: SocketAddr) -> Option<Vec<u8>> {
    if let Some(t) = CLIENT_CLAIMS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(&server).copied())
    {
        return Some(claim_datagram(&t));
    }
    let env = std::env::var(TOKEN_ENV).ok()?;
    match parse_token(&env) {
        Ok(t) => Some(claim_datagram(&t)),
        Err(e) => {
            tracing::warn!("ignoring {TOKEN_ENV}: {e:#}");
            None
        }
    }
}

/// Constant-time equality for the token comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A bound single-session UDP relay forwarding between a known receiver and
/// the sender holding the session token.
pub struct RelayServer {
    sock: UdpSocket,
    receiver_addr: SocketAddr,
    local_addr: SocketAddr,
    token: RelayToken,
    idle_timeout: Duration,
}

impl RelayServer {
    /// Bind the relay on `bind` and forward to/from `receiver_addr`.
    ///
    /// The session token is taken from `MFTP_RELAY_TOKEN` when set (so an
    /// operator can pre-share it), otherwise generated randomly; read it with
    /// [`token`](Self::token) / [`token_hex`](Self::token_hex) and hand it to
    /// the sender as part of the allocation.
    pub async fn bind(bind: SocketAddr, receiver_addr: SocketAddr) -> Result<Self> {
        let token = match std::env::var(TOKEN_ENV) {
            Ok(t) => parse_token(&t).with_context(|| format!("invalid {TOKEN_ENV}"))?,
            Err(_) => {
                let mut t = [0u8; TOKEN_LEN];
                rustls::crypto::ring::default_provider()
                    .secure_random
                    .fill(&mut t)
                    .map_err(|_| anyhow::anyhow!("system RNG failure"))?;
                t
            }
        };
        let sock = UdpSocket::bind(bind)
            .await
            .with_context(|| format!("bind relay on {bind}"))?;
        let local_addr = sock.local_addr()?;
        Ok(RelayServer {
            sock,
            receiver_addr,
            local_addr,
            token,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        })
    }

    /// Use `token` as the session token instead of the generated one.
    pub fn with_token(mut self, token: RelayToken) -> Self {
        self.token = token;
        self
    }

    /// Override the idle expiry of a claimed session.
    pub fn with_idle_timeout(mut self, idle: Duration) -> Self {
        self.idle_timeout = idle;
        self
    }

    /// The address senders should aim their QUIC connection at.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The session token a sender must present in its claim datagram.
    pub fn token(&self) -> RelayToken {
        self.token
    }

    /// The session token, hex-encoded.
    pub fn token_hex(&self) -> String {
        hex::encode(self.token)
    }

    fn is_valid_claim(&self, payload: &[u8]) -> bool {
        payload.len() == CLAIM_MAGIC.len() + TOKEN_LEN
            && payload.starts_with(CLAIM_MAGIC)
            && ct_eq(&payload[CLAIM_MAGIC.len()..], &self.token)
    }

    /// Forward datagrams until the claimed session goes idle.
    ///
    /// Only a datagram carrying the session token ([`claim_datagram`]) can bind
    /// (or re-bind) the sender slot; claims are consumed, not forwarded.
    /// Thereafter only datagrams from the bound sender (forward path) or the
    /// receiver (reply path) are relayed; anything else is dropped, so a
    /// stray/spoofed packet from a third party cannot hijack the session.
    /// Returns `Ok(())` once a claimed session has carried no traffic for the
    /// idle timeout. Payloads are never inspected.
    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut sender_addr: Option<SocketAddr> = None;
        let mut last_activity = Instant::now();
        loop {
            let recv = self.sock.recv_from(&mut buf);
            let (n, from) = if sender_addr.is_some() {
                match tokio::time::timeout_at(last_activity + self.idle_timeout, recv).await {
                    Ok(r) => r.context("relay recv")?,
                    Err(_) => {
                        tracing::info!("relay session idle for {:?}; expiring", self.idle_timeout);
                        return Ok(());
                    }
                }
            } else {
                recv.await.context("relay recv")?
            };
            let payload = &buf[..n];
            if from == self.receiver_addr {
                // Reply path: receiver → sender (only once a sender is bound).
                if let Some(s) = sender_addr {
                    last_activity = Instant::now();
                    let _ = self.sock.send_to(payload, s).await;
                }
            } else if self.is_valid_claim(payload) {
                // Token holder claims (or moves) the sender slot.
                if sender_addr != Some(from) {
                    tracing::debug!("relay session claimed by {from}");
                }
                sender_addr = Some(from);
                last_activity = Instant::now();
            } else if sender_addr == Some(from) {
                // Forward path from the bound sender.
                last_activity = Instant::now();
                let _ = self.sock.send_to(payload, self.receiver_addr).await;
            }
            // else: unclaimed source — drop.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    async fn setup(
        idle: Duration,
    ) -> (
        UdpSocket,
        SocketAddr,
        RelayToken,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let relay = RelayServer::bind((Ipv4Addr::LOCALHOST, 0).into(), receiver_addr)
            .await
            .unwrap()
            .with_token([0x42; TOKEN_LEN])
            .with_idle_timeout(idle);
        let relay_addr = relay.local_addr();
        let token = relay.token();
        let task = tokio::spawn(relay.run());
        (receiver, relay_addr, token, task)
    }

    async fn nothing_within(sock: &UdpSocket, ms: u64) -> bool {
        let mut b = [0u8; 256];
        tokio::time::timeout(Duration::from_millis(ms), sock.recv_from(&mut b))
            .await
            .is_err()
    }

    /// The relay forwards opaque bytes in both directions without inspecting
    /// them — a stand-in for the zero-knowledge ciphertext property.
    #[tokio::test]
    async fn relay_forwards_both_directions_verbatim() {
        let (receiver, relay_addr, token, _t) = setup(DEFAULT_IDLE_TIMEOUT).await;
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        sender
            .send_to(&claim_datagram(&token), relay_addr)
            .await
            .unwrap();

        // sender → relay → receiver
        let opaque = b"\x00\xff\x01\xfe ciphertext-ish";
        sender.send_to(opaque, relay_addr).await.unwrap();
        let mut buf = [0u8; 256];
        let (n, seen_from) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            opaque,
            "payload forwarded verbatim (claim consumed)"
        );
        assert_eq!(seen_from, relay_addr, "receiver sees the relay as the peer");

        // receiver → relay → sender (reply path)
        let reply = b"\xde\xad\xbe\xef reply";
        receiver.send_to(reply, relay_addr).await.unwrap();
        let (n, seen_from) = sender.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], reply, "reply forwarded verbatim to sender");
        assert_eq!(seen_from, relay_addr, "sender sees the relay as the peer");
    }

    /// Without the token nobody gets the sender slot: a first datagram that is
    /// not a valid claim (or carries the wrong token) is dropped, and after a
    /// legitimate claim a third party still cannot hijack the session.
    #[tokio::test]
    async fn relay_requires_token_and_ignores_third_party() {
        let (receiver, relay_addr, token, _t) = setup(DEFAULT_IDLE_TIMEOUT).await;
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut buf = [0u8; 256];

        // Attacker races in first, without/with a wrong token — dropped.
        attacker.send_to(b"HIJACK", relay_addr).await.unwrap();
        attacker
            .send_to(&claim_datagram(&[0u8; TOKEN_LEN]), relay_addr)
            .await
            .unwrap();
        attacker.send_to(b"HIJACK2", relay_addr).await.unwrap();
        assert!(
            nothing_within(&receiver, 200).await,
            "unclaimed traffic forwarded"
        );

        // Legitimate sender claims and is forwarded.
        sender
            .send_to(&claim_datagram(&token), relay_addr)
            .await
            .unwrap();
        sender.send_to(b"hello", relay_addr).await.unwrap();
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Attacker datagram after binding is dropped; replies go to the sender.
        attacker.send_to(b"HIJACK3", relay_addr).await.unwrap();
        receiver.send_to(b"reply", relay_addr).await.unwrap();
        let (n, _) = sender.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply", "reply still routed to original sender");
        assert!(
            nothing_within(&attacker, 200).await,
            "attacker must not receive the receiver's reply"
        );
    }

    /// A claimed session with no traffic expires and `run` returns.
    #[tokio::test]
    async fn relay_session_expires_when_idle() {
        let (_receiver, relay_addr, token, task) = setup(Duration::from_millis(200)).await;
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        sender
            .send_to(&claim_datagram(&token), relay_addr)
            .await
            .unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("idle session must expire");
        assert!(res.unwrap().is_ok());
    }

    #[test]
    fn token_parsing() {
        let t = [0xab; TOKEN_LEN];
        assert_eq!(parse_token(&hex::encode(t)).unwrap(), t);
        assert!(parse_token("abcd").is_err());
        assert!(parse_token("zz").is_err());
    }
}
