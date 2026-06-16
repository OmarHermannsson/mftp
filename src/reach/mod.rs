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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::protocol::framing;

pub mod relay;

/// Signaling messages exchanged with the rendezvous broker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignalMsg {
    /// Receiver → broker: "I am `device_id`, reachable at these candidates."
    Register {
        device_id: String,
        candidates: Vec<SocketAddr>,
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
}

struct Registration {
    candidates: Vec<SocketAddr>,
    offer_tx: mpsc::Sender<SignalMsg>,
}

type Registry = Arc<Mutex<HashMap<String, Registration>>>;

/// A running rendezvous broker.
pub struct RendezvousServer {
    listener: TcpListener,
    registry: Registry,
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
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Serve signaling connections forever.
    pub async fn serve(self) -> Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await.context("accept signaling")?;
            let registry = Arc::clone(&self.registry);
            tokio::spawn(async move {
                if let Err(e) = handle_signaling_conn(stream, peer, registry).await {
                    tracing::debug!("signaling connection from {peer} ended: {e:#}");
                }
            });
        }
    }
}

async fn handle_signaling_conn(
    stream: TcpStream,
    peer: SocketAddr,
    registry: Registry,
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (mut rd, mut wr) = stream.into_split();
    let first: SignalMsg = match framing::recv_message(&mut rd).await? {
        Some(m) => m,
        None => return Ok(()),
    };
    match first {
        SignalMsg::Register {
            device_id,
            candidates,
        } => {
            // Presence connection: register, then forward Offers until it drops.
            let (offer_tx, mut offer_rx) = mpsc::channel::<SignalMsg>(8);
            registry.lock().await.insert(
                device_id.clone(),
                Registration {
                    candidates,
                    offer_tx,
                },
            );
            framing::send_message(&mut wr, &SignalMsg::Registered { observed: peer }).await?;
            // Pump Offers to the receiver until the connection or registry entry closes.
            while let Some(offer) = offer_rx.recv().await {
                if framing::send_message(&mut wr, &offer).await.is_err() {
                    break;
                }
            }
            registry.lock().await.remove(&device_id);
            Ok(())
        }
        SignalMsg::Lookup { target, candidates } => {
            let reg = registry.lock().await;
            match reg.get(&target) {
                Some(entry) => {
                    let reply = SignalMsg::Found {
                        candidates: entry.candidates.clone(),
                    };
                    // Notify the receiver so it punches toward the sender too.
                    let _ = entry
                        .offer_tx
                        .send(SignalMsg::Offer {
                            from: "sender".to_string(),
                            candidates,
                        })
                        .await;
                    drop(reg);
                    framing::send_message(&mut wr, &reply).await?;
                }
                None => {
                    drop(reg);
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

/// Register `device_id` with `candidates` at the broker and keep the presence
/// connection open. Returns the presence handle (with the observed public addr).
pub async fn register(
    broker: SocketAddr,
    device_id: &str,
    candidates: Vec<SocketAddr>,
) -> Result<Presence> {
    let stream = TcpStream::connect(broker)
        .await
        .with_context(|| format!("connect to rendezvous broker {broker}"))?;
    stream.set_nodelay(true).ok();
    let (mut rd, mut wr) = stream.into_split();
    framing::send_message(
        &mut wr,
        &SignalMsg::Register {
            device_id: device_id.to_string(),
            candidates,
        },
    )
    .await?;
    let observed = match framing::recv_message_required::<_, SignalMsg>(&mut rd).await? {
        SignalMsg::Registered { observed } => observed,
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
    let stream = TcpStream::connect(broker)
        .await
        .with_context(|| format!("connect to rendezvous broker {broker}"))?;
    stream.set_nodelay(true).ok();
    let (mut rd, mut wr) = stream.into_split();
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
    use std::net::{Ipv4Addr, SocketAddr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    /// End-to-end signaling over loopback: receiver registers, sender looks it
    /// up and gets its candidates, and the receiver is pushed the sender's
    /// candidates — the full rendezvous exchange that precedes hole punching.
    #[tokio::test]
    async fn rendezvous_exchange_round_trip() {
        let server = RendezvousServer::bind(addr(0)).await.unwrap();
        let broker = server.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = server.serve().await;
        });

        // Receiver registers and waits for an offer.
        let recv_cands = vec![addr(5000), addr(5001)];
        let mut presence = register(broker, &"d".repeat(64), recv_cands.clone())
            .await
            .unwrap();
        assert_eq!(presence.observed.ip(), Ipv4Addr::LOCALHOST);

        // Sender looks up the receiver, offering its own candidates.
        let send_cands = vec![addr(6000)];
        let found = lookup(broker, &"d".repeat(64), send_cands.clone())
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
        let server = RendezvousServer::bind(addr(0)).await.unwrap();
        let broker = server.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = server.serve().await;
        });

        let got = lookup(broker, &"e".repeat(64), vec![addr(7000)])
            .await
            .unwrap();
        assert!(got.is_none());
    }
}
