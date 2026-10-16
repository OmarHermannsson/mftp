//! Rendezvous + NAT hole punching (mftp v2, milestone M6).
//!
//! Lets two hosts behind NAT reach each other by **DeviceId**, with no public
//! IP or port-forwarding, via a small self-hostable **rendezvous broker** that
//! does signaling only (it never sees file bytes):
//!
//!   1. The receiver registers its DeviceId + candidate addresses (local
//!      interfaces, and the server-reflexive address the broker observed — its
//!      public `ip:port`, i.e. a STUN binding) and holds the connection open.
//!   2. The sender looks up that DeviceId, sending its own candidates. The
//!      broker returns the receiver's candidates to the sender and pushes the
//!      sender's candidates to the receiver as an `Offer`.
//!   3. Both sides now know each other's candidates and fire UDP probes at them
//!      simultaneously from the QUIC socket — punching the NAT mappings — then
//!      run the normal QUIC transfer over the path that comes up.
//!
//! This module implements the broker and the signaling client. The data plane
//! is unchanged: once a candidate pair works, it carries ordinary mftp QUIC.
//!
//! NAT-traversal *success* depends on the NAT types involved (cone NATs punch
//! reliably; symmetric NATs often need the relay — M7). The broker and the
//! candidate-exchange protocol here are verified over loopback; cross-NAT
//! punching is validated at deployment.
//!
//! # Registration proof
//!
//! A `Register` must prove possession of the device's Ed25519 identity key:
//! the broker opens every connection with a fresh random [`SignalMsg::Challenge`]
//! nonce, and the receiver answers with its SubjectPublicKeyInfo plus an
//! Ed25519 signature over a domain-separated transcript of that nonce, the
//! DeviceId and the candidate list (see [`register_transcript`]).  The broker
//! checks that `SHA-256(spki) == device_id` and that the signature verifies,
//! so nobody can register (or hijack an existing registration of) a DeviceId
//! whose private key they do not hold.  The proof is bound to the broker's
//! nonce, so a captured registration cannot be replayed on another connection.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::identity::Identity;
use crate::protocol::framing;

pub mod relay;

/// Signaling messages exchanged with the rendezvous broker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignalMsg {
    /// Receiver → broker: "I am `device_id`, reachable at these candidates",
    /// with proof of key possession: `public_key` is the device's Ed25519
    /// SubjectPublicKeyInfo DER and `signature` is its Ed25519 signature over
    /// [`register_transcript`] for the connection's challenge nonce.
    Register {
        device_id: String,
        candidates: Vec<SocketAddr>,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Sender → broker: "find `target`; here are my candidates."
    Lookup {
        target: String,
        candidates: Vec<SocketAddr>,
    },
    /// Broker → receiver: registration accepted; here is the public address we
    /// saw you from (your server-reflexive / STUN binding).
    Registered { observed: SocketAddr },
    /// Broker → sender: target found; punch toward these candidates.
    Found { candidates: Vec<SocketAddr> },
    /// Broker → receiver (push): someone wants you; punch toward their
    /// candidates simultaneously.
    Offer {
        from: String,
        candidates: Vec<SocketAddr>,
    },
    /// Broker → sender: no such DeviceId registered.
    NotFound,
    /// Broker → client, first message on every connection: a fresh random
    /// nonce a `Register` must sign.
    Challenge { nonce: Vec<u8> },
    /// Broker → receiver: the registration proof was invalid.
    Rejected { reason: String },
}

/// Length of the broker's challenge nonce.
const NONCE_LEN: usize = 32;

/// Domain-separation tag for the registration signature.
const REGISTER_CONTEXT: &[u8] = b"mftp-rendezvous-register-v1\0";

/// How long the broker waits for a client's opening message.
const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The 12-byte DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410),
/// followed by the 32-byte raw key.  Mirrors `identity.rs`.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The bytes a `Register` signature covers: a domain tag, the broker nonce,
/// the DeviceId and the (bincode-encoded) candidate list, so neither the
/// nonce nor the advertised addresses can be swapped under a valid proof.
pub fn register_transcript(nonce: &[u8], device_id: &str, candidates: &[SocketAddr]) -> Vec<u8> {
    let mut t = Vec::with_capacity(REGISTER_CONTEXT.len() + nonce.len() + 128);
    t.extend_from_slice(REGISTER_CONTEXT);
    t.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
    t.extend_from_slice(nonce);
    t.extend_from_slice(&(device_id.len() as u32).to_be_bytes());
    t.extend_from_slice(device_id.as_bytes());
    // bincode of a Vec<SocketAddr> is deterministic.
    t.extend_from_slice(&bincode::serialize(candidates).unwrap_or_default());
    t
}

/// Verify a registration proof. Returns a human-readable reason on failure.
fn verify_registration(
    nonce: &[u8],
    device_id: &str,
    candidates: &[SocketAddr],
    public_key: &[u8],
    signature: &[u8],
) -> std::result::Result<(), String> {
    if public_key.len() != ED25519_SPKI_PREFIX.len() + 32
        || public_key[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX
    {
        return Err("public key is not an Ed25519 SubjectPublicKeyInfo".into());
    }
    let derived = hex::encode(Sha256::digest(public_key));
    if !derived.eq_ignore_ascii_case(device_id) {
        return Err("public key does not match the DeviceId".into());
    }
    let raw_key = &public_key[ED25519_SPKI_PREFIX.len()..];
    let algs = rustls::crypto::ring::default_provider().signature_verification_algorithms;
    let ed25519 = algs
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == rustls::SignatureScheme::ED25519)
        .and_then(|(_, a)| a.first())
        .ok_or("Ed25519 verification unavailable")?;
    let msg = register_transcript(nonce, device_id, candidates);
    ed25519
        .verify_signature(raw_key, &msg, signature)
        .map_err(|_| "invalid registration signature".to_string())
}

/// Sign the registration transcript with `identity`'s Ed25519 key, returning
/// `(spki_der, signature)`.
fn sign_registration(
    identity: &Identity,
    nonce: &[u8],
    candidates: &[SocketAddr],
) -> Result<(Vec<u8>, Vec<u8>)> {
    use rustls::pki_types::PrivatePkcs8KeyDer;
    let der = PrivatePkcs8KeyDer::from(identity.key_bytes.clone());
    let key = rustls::crypto::ring::sign::any_eddsa_type(&der)
        .map_err(|e| anyhow::anyhow!("device key is not Ed25519: {e}"))?;
    let spki = key
        .public_key()
        .context("device key has no public key")?
        .as_ref()
        .to_vec();
    let signer = key
        .choose_scheme(&[rustls::SignatureScheme::ED25519])
        .context("device key cannot sign Ed25519")?;
    let sig = signer
        .sign(&register_transcript(nonce, &identity.device_id, candidates))
        .map_err(|e| anyhow::anyhow!("sign registration: {e}"))?;
    Ok((spki, sig))
}

struct Registration {
    candidates: Vec<SocketAddr>,
    offer_tx: mpsc::Sender<SignalMsg>,
    /// Monotonic id of this registration, so a stale presence task only removes
    /// its OWN entry (a re-registration of the same DeviceId must not be deleted
    /// when the older connection finally drops).
    generation: u64,
}

type Registry = Arc<Mutex<HashMap<String, Registration>>>;

/// Cap on candidate addresses accepted/relayed per peer — bounds the
/// reflected-probe surface (a Lookup can make a receiver punch toward these).
const MAX_CANDIDATES: usize = 8;

/// Drop addresses that should never be hole-punch targets and cap the count.
///
/// Refused: unspecified, multicast, broadcast, port 0, link-local
/// (169.254/16, fe80::/10) and — unless `allow_loopback` — loopback. A peer's
/// loopback/link-local address is meaningless to the other side, and relaying
/// it would let a Lookup make a receiver fire probes at its *own* local
/// services. Private (RFC 1918 / ULA) addresses are kept: LAN peers behind the
/// same NAT legitimately reach each other on them. IPv4-mapped IPv6 addresses
/// are judged by their IPv4 form.
fn sanitize_candidates(cands: Vec<SocketAddr>, allow_loopback: bool) -> Vec<SocketAddr> {
    cands
        .into_iter()
        .filter(|a| {
            let ip = a.ip().to_canonical();
            let link_local = match ip {
                IpAddr::V4(v4) => v4.is_link_local() || v4.is_broadcast(),
                IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
            };
            !ip.is_multicast()
                && !ip.is_unspecified()
                && a.port() != 0
                && !link_local
                && (allow_loopback || !ip.is_loopback())
        })
        .take(MAX_CANDIDATES)
        .collect()
}

/// A running rendezvous broker.
pub struct RendezvousServer {
    listener: TcpListener,
    registry: Registry,
    next_gen: Arc<std::sync::atomic::AtomicU64>,
    allow_loopback: bool,
}

impl RendezvousServer {
    /// Bind the broker on `addr` (use port 0 for an ephemeral port in tests).
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind rendezvous broker on {addr}"))?;
        Ok(RendezvousServer {
            listener,
            registry: Arc::new(Mutex::new(HashMap::new())),
            next_gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            allow_loopback: false,
        })
    }

    /// Accept loopback candidate addresses (off by default). Only for a broker
    /// whose peers all run on the same host — i.e. tests and local demos.
    pub fn allow_loopback_candidates(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;
        self
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Serve signaling connections forever.
    pub async fn serve(self) -> Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await.context("accept signaling")?;
            let registry = Arc::clone(&self.registry);
            let next_gen = Arc::clone(&self.next_gen);
            let allow_loopback = self.allow_loopback;
            tokio::spawn(async move {
                if let Err(e) =
                    handle_signaling_conn(stream, peer, registry, next_gen, allow_loopback).await
                {
                    tracing::debug!("signaling connection from {peer} ended: {e:#}");
                }
            });
        }
    }
}

fn random_nonce() -> Result<Vec<u8>> {
    let mut nonce = vec![0u8; NONCE_LEN];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("system RNG failure"))?;
    Ok(nonce)
}

async fn handle_signaling_conn(
    stream: TcpStream,
    peer: SocketAddr,
    registry: Registry,
    next_gen: Arc<std::sync::atomic::AtomicU64>,
    allow_loopback: bool,
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (mut rd, mut wr) = stream.into_split();
    let nonce = random_nonce()?;
    framing::send_message(
        &mut wr,
        &SignalMsg::Challenge {
            nonce: nonce.clone(),
        },
    )
    .await?;
    let first: SignalMsg =
        match tokio::time::timeout(FIRST_MESSAGE_TIMEOUT, framing::recv_message(&mut rd))
            .await
            .context("timed out waiting for the opening signaling message")??
        {
            Some(m) => m,
            None => return Ok(()),
        };
    match first {
        SignalMsg::Register {
            device_id,
            candidates,
            public_key,
            signature,
        } => {
            // Proof of possession of the DeviceId's key — without it anyone
            // could register (or overwrite) any DeviceId and redirect its
            // senders.
            if let Err(reason) =
                verify_registration(&nonce, &device_id, &candidates, &public_key, &signature)
            {
                framing::send_message(
                    &mut wr,
                    &SignalMsg::Rejected {
                        reason: reason.clone(),
                    },
                )
                .await
                .ok();
                anyhow::bail!("rejected Register for {device_id:?} from {peer}: {reason}");
            }
            let device_id = device_id.to_ascii_lowercase();
            // Presence connection: register, then forward Offers until it drops.
            let (offer_tx, mut offer_rx) = mpsc::channel::<SignalMsg>(8);
            let generation = next_gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            registry.lock().await.insert(
                device_id.clone(),
                Registration {
                    candidates: sanitize_candidates(candidates, allow_loopback),
                    offer_tx,
                    generation,
                },
            );
            framing::send_message(&mut wr, &SignalMsg::Registered { observed: peer }).await?;
            // Pump Offers to the receiver until the connection or registry entry closes.
            while let Some(offer) = offer_rx.recv().await {
                if framing::send_message(&mut wr, &offer).await.is_err() {
                    break;
                }
            }
            // Only remove the entry if it is still OURS — a newer registration of
            // the same DeviceId must survive our teardown.
            let mut reg = registry.lock().await;
            if reg.get(&device_id).map(|r| r.generation) == Some(generation) {
                reg.remove(&device_id);
            }
            Ok(())
        }
        SignalMsg::Lookup { target, candidates } => {
            let candidates = sanitize_candidates(candidates, allow_loopback);
            let target = target.to_ascii_lowercase();
            // Try to deliver the Offer first; only report Found if the receiver's
            // presence is actually live (so the sender isn't told to punch toward
            // a peer that will never punch back).
            let entry = {
                let reg = registry.lock().await;
                reg.get(&target)
                    .map(|e| (e.candidates.clone(), e.offer_tx.clone()))
            };
            match entry {
                Some((cands, offer_tx)) => {
                    let delivered = offer_tx
                        .send(SignalMsg::Offer {
                            from: "sender".to_string(),
                            candidates,
                        })
                        .await
                        .is_ok();
                    if delivered {
                        framing::send_message(&mut wr, &SignalMsg::Found { candidates: cands })
                            .await?;
                    } else {
                        // Presence channel is dead — treat as not registered.
                        framing::send_message(&mut wr, &SignalMsg::NotFound).await?;
                    }
                }
                None => {
                    framing::send_message(&mut wr, &SignalMsg::NotFound).await?;
                }
            }
            Ok(())
        }
        other => {
            framing::send_message(
                &mut wr,
                &SignalMsg::NotFound, // unexpected opening message
            )
            .await
            .ok();
            anyhow::bail!("unexpected opening signaling message: {other:?}")
        }
    }
}

/// A registered presence at the broker. Holds the signaling connection open and
/// yields incoming [`SignalMsg::Offer`]s (sender candidates to punch toward).
pub struct Presence {
    pub observed: SocketAddr,
    rd: tokio::net::tcp::OwnedReadHalf,
    _wr: tokio::net::tcp::OwnedWriteHalf,
}

impl Presence {
    /// Wait for the next sender Offer (candidates to hole-punch toward).
    pub async fn next_offer(&mut self) -> Result<Option<SignalMsg>> {
        framing::recv_message(&mut self.rd).await
    }
}

/// Connect to the broker and read its opening challenge nonce.
async fn connect_broker(
    broker: SocketAddr,
) -> Result<(
    tokio::net::tcp::OwnedReadHalf,
    tokio::net::tcp::OwnedWriteHalf,
    Vec<u8>,
)> {
    let stream = TcpStream::connect(broker)
        .await
        .with_context(|| format!("connect to rendezvous broker {broker}"))?;
    stream.set_nodelay(true).ok();
    let (mut rd, wr) = stream.into_split();
    let nonce = match framing::recv_message_required::<_, SignalMsg>(&mut rd).await? {
        SignalMsg::Challenge { nonce } if nonce.len() == NONCE_LEN => nonce,
        other => anyhow::bail!("unexpected greeting from rendezvous broker: {other:?}"),
    };
    Ok((rd, wr, nonce))
}

/// Register `identity`'s DeviceId with `candidates` at the broker and keep the
/// presence connection open. The registration is signed with the identity's
/// Ed25519 key over the broker's challenge (see the module docs). Returns the
/// presence handle (with the observed public addr).
pub async fn register(
    broker: SocketAddr,
    identity: &Identity,
    candidates: Vec<SocketAddr>,
) -> Result<Presence> {
    let (mut rd, mut wr, nonce) = connect_broker(broker).await?;
    let (public_key, signature) = sign_registration(identity, &nonce, &candidates)?;
    framing::send_message(
        &mut wr,
        &SignalMsg::Register {
            device_id: identity.device_id.clone(),
            candidates,
            public_key,
            signature,
        },
    )
    .await?;
    let observed = match framing::recv_message_required::<_, SignalMsg>(&mut rd).await? {
        SignalMsg::Registered { observed } => observed,
        SignalMsg::Rejected { reason } => {
            anyhow::bail!("rendezvous broker rejected registration: {reason}")
        }
        other => anyhow::bail!("unexpected reply to Register: {other:?}"),
    };
    Ok(Presence {
        observed,
        rd,
        _wr: wr,
    })
}

/// Look up `target` at the broker, sending our own `candidates`. Returns the
/// target's candidate addresses to punch toward, or `None` if not registered.
pub async fn lookup(
    broker: SocketAddr,
    target: &str,
    candidates: Vec<SocketAddr>,
) -> Result<Option<Vec<SocketAddr>>> {
    let (mut rd, mut wr, _nonce) = connect_broker(broker).await?;
    framing::send_message(
        &mut wr,
        &SignalMsg::Lookup {
            target: target.to_string(),
            candidates,
        },
    )
    .await?;
    match framing::recv_message_required::<_, SignalMsg>(&mut rd).await? {
        SignalMsg::Found { candidates } => Ok(Some(candidates)),
        SignalMsg::NotFound => Ok(None),
        other => anyhow::bail!("unexpected reply to Lookup: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    async fn spawn_broker(allow_loopback: bool) -> SocketAddr {
        let server = RendezvousServer::bind(addr(0))
            .await
            .unwrap()
            .allow_loopback_candidates(allow_loopback);
        let broker = server.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = server.serve().await;
        });
        broker
    }

    fn identity() -> (tempfile::TempDir, Identity) {
        let dir = tempfile::TempDir::new().unwrap();
        let id = crate::identity::load_or_create_in(dir.path()).unwrap();
        (dir, id)
    }

    /// End-to-end signaling over loopback: receiver registers, sender looks it
    /// up and gets its candidates, and the receiver is pushed the sender's
    /// candidates — the full rendezvous exchange that precedes hole punching.
    #[tokio::test]
    async fn rendezvous_exchange_round_trip() {
        let broker = spawn_broker(true).await;
        let (_d, id) = identity();

        // Receiver registers and waits for an offer.
        let recv_cands = vec![addr(5000), addr(5001)];
        let mut presence = register(broker, &id, recv_cands.clone()).await.unwrap();
        assert_eq!(presence.observed.ip(), Ipv4Addr::LOCALHOST);

        // Sender looks up the receiver, offering its own candidates.
        let send_cands = vec![addr(6000)];
        let found = lookup(broker, &id.device_id, send_cands.clone())
            .await
            .unwrap()
            .expect("target should be found");
        assert_eq!(found, recv_cands, "sender learns receiver candidates");

        // Receiver is pushed the sender's candidates (to punch toward).
        let offer = tokio::time::timeout(std::time::Duration::from_secs(2), presence.next_offer())
            .await
            .expect("offer should arrive")
            .unwrap()
            .expect("offer present");
        match offer {
            SignalMsg::Offer { candidates, .. } => {
                assert_eq!(candidates, send_cands, "receiver learns sender candidates")
            }
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    /// Looking up an unregistered DeviceId returns NotFound.
    #[tokio::test]
    async fn lookup_unknown_returns_none() {
        let broker = spawn_broker(false).await;
        let got = lookup(broker, &"e".repeat(64), vec![addr(7000)])
            .await
            .unwrap();
        assert!(got.is_none());
    }

    /// Send a raw Register (bypassing the honest client) and return the reply.
    async fn raw_register(broker: SocketAddr, build: impl FnOnce(&[u8]) -> SignalMsg) -> SignalMsg {
        let (mut rd, mut wr, nonce) = connect_broker(broker).await.unwrap();
        framing::send_message(&mut wr, &build(&nonce))
            .await
            .unwrap();
        framing::recv_message_required::<_, SignalMsg>(&mut rd)
            .await
            .unwrap()
    }

    /// A Register for someone else's DeviceId — with the attacker's own key,
    /// a forged signature, or a replayed proof — is rejected, and the
    /// legitimate registration is not displaced.
    #[tokio::test]
    async fn register_requires_proof_of_key_possession() {
        let broker = spawn_broker(true).await;
        let (_d1, victim) = identity();
        let (_d2, attacker) = identity();
        let victim_cands = vec![addr(5000)];
        let _presence = register(broker, &victim, victim_cands.clone())
            .await
            .unwrap();
        let evil = vec![addr(6666)];

        // 1. No/garbage proof.
        let reply = raw_register(broker, |_| SignalMsg::Register {
            device_id: victim.device_id.clone(),
            candidates: evil.clone(),
            public_key: vec![],
            signature: vec![],
        })
        .await;
        assert!(matches!(reply, SignalMsg::Rejected { .. }), "{reply:?}");

        // 2. Attacker signs correctly with ITS key but claims the victim's id.
        let reply = raw_register(broker, |nonce| {
            let (pk, sig) = sign_registration(&attacker, nonce, &evil).unwrap();
            SignalMsg::Register {
                device_id: victim.device_id.clone(),
                candidates: evil.clone(),
                public_key: pk,
                signature: sig,
            }
        })
        .await;
        assert!(matches!(reply, SignalMsg::Rejected { .. }), "{reply:?}");

        // 3. Replay: a valid victim proof for a different nonce.
        let (pk, sig) = sign_registration(&victim, &[7u8; NONCE_LEN], &evil).unwrap();
        let reply = raw_register(broker, |_| SignalMsg::Register {
            device_id: victim.device_id.clone(),
            candidates: evil.clone(),
            public_key: pk,
            signature: sig,
        })
        .await;
        assert!(matches!(reply, SignalMsg::Rejected { .. }), "{reply:?}");

        // 4. Valid proof, but candidates swapped after signing.
        let reply = raw_register(broker, |nonce| {
            let (pk, sig) = sign_registration(&victim, nonce, &victim_cands).unwrap();
            SignalMsg::Register {
                device_id: victim.device_id.clone(),
                candidates: evil.clone(),
                public_key: pk,
                signature: sig,
            }
        })
        .await;
        assert!(matches!(reply, SignalMsg::Rejected { .. }), "{reply:?}");

        // The genuine registration survived all of the above.
        let found = lookup(broker, &victim.device_id, vec![]).await.unwrap();
        assert_eq!(found, Some(victim_cands));
    }

    #[test]
    fn sanitize_refuses_local_only_addresses() {
        let v4 = |a: [u8; 4], p| SocketAddr::from((Ipv4Addr::from(a), p));
        let lan = v4([192, 168, 1, 10], 4433);
        let public = v4([203, 0, 113, 5], 4433);
        let ula = SocketAddr::from(("fd00::1".parse::<Ipv6Addr>().unwrap(), 4433));
        let input = vec![
            lan,
            public,
            ula,
            v4([127, 0, 0, 1], 4433),                      // loopback
            v4([169, 254, 3, 4], 4433),                    // link-local
            v4([0, 0, 0, 0], 4433),                        // unspecified
            v4([224, 0, 0, 1], 4433),                      // multicast
            v4([255, 255, 255, 255], 4433),                // broadcast
            v4([10, 0, 0, 1], 0),                          // port 0
            SocketAddr::from((Ipv6Addr::LOCALHOST, 4433)), // ::1
            SocketAddr::from(("fe80::1".parse::<Ipv6Addr>().unwrap(), 4433)), // v6 link-local
            SocketAddr::from(("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap(), 4433)), // mapped loopback
        ];
        assert_eq!(
            sanitize_candidates(input.clone(), false),
            vec![lan, public, ula]
        );
        // Loopback is allowed only when explicitly enabled.
        let with_lo = sanitize_candidates(input, true);
        assert!(with_lo.contains(&v4([127, 0, 0, 1], 4433)));
        assert!(!with_lo.contains(&v4([169, 254, 3, 4], 4433)));
    }
}
