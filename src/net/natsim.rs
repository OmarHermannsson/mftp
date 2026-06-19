//! Userspace NAT simulator for testing NAT traversal / hole-punching (M6).
//!
//! A real NAT can't be created without root + network namespaces, so this models
//! the two behaviours that actually decide whether a UDP hole-punch succeeds,
//! entirely in-process on loopback:
//!
//!   * **Mapping** — how the NAT assigns an external port to an internal source:
//!     - *Endpoint-independent* ("cone"): one external port regardless of the
//!       destination, so a peer learns one address (via STUN) that any other
//!       peer can punch toward. This is what makes hole-punching possible.
//!     - *Endpoint-dependent* ("symmetric"): a fresh external port per
//!       destination, so the address learned toward a STUN server differs from
//!       the one toward the peer — defeating the punch by construction (the
//!       transfer must fall back to a relay).
//!   * **Filtering** — which inbound datagrams are allowed back to the internal
//!     host: none (full cone), address-restricted, or port-restricted. Restricted
//!     filtering is why *both* peers must send outbound probes before either can
//!     receive — the crux of a simultaneous-open punch.
//!
//! A [`Nat`] represents one NAT box in front of one internal endpoint. Outbound
//! datagrams are sent from a mapped "external" UDP socket (its `local_addr` is
//! the NAT's public address for that mapping); inbound datagrams on those sockets
//! are delivered only if they pass the filter. The [`Nat::send`] / [`Nat::recv`]
//! pair is shaped to back a future `AsyncUdpSocket` wrapper (send→`try_send`,
//! recv→`poll_recv`) so a real quinn endpoint can run behind the NAT.
//!
//! Hidden from docs; test-support only.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How the NAT assigns external ports to internal sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapping {
    /// One external port per internal source, regardless of destination ("cone").
    EndpointIndependent,
    /// A fresh external port per distinct destination ("symmetric").
    EndpointDependent,
}

/// Which inbound datagrams the NAT forwards back to the internal host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filtering {
    /// Any external host may send to an open mapping (full cone).
    None,
    /// Only external hosts the internal host has sent to (same IP).
    AddressRestricted,
    /// Only external (IP, port) the internal host has sent to.
    PortRestricted,
}

/// A NAT behaviour: a (mapping, filtering) pair.
#[derive(Clone, Copy, Debug)]
pub struct NatPolicy {
    pub mapping: Mapping,
    pub filtering: Filtering,
}

impl NatPolicy {
    /// Endpoint-independent mapping, no filtering — the easiest to punch.
    pub fn full_cone() -> Self {
        Self {
            mapping: Mapping::EndpointIndependent,
            filtering: Filtering::None,
        }
    }
    /// Cone mapping, address-restricted filtering.
    pub fn restricted_cone() -> Self {
        Self {
            mapping: Mapping::EndpointIndependent,
            filtering: Filtering::AddressRestricted,
        }
    }
    /// Cone mapping, port-restricted filtering (the common consumer-router case).
    pub fn port_restricted_cone() -> Self {
        Self {
            mapping: Mapping::EndpointIndependent,
            filtering: Filtering::PortRestricted,
        }
    }
    /// Endpoint-dependent mapping + port-restricted filtering — cannot be punched.
    pub fn symmetric() -> Self {
        Self {
            mapping: Mapping::EndpointDependent,
            filtering: Filtering::PortRestricted,
        }
    }
}

/// Decide whether an inbound datagram from `from` passes the filter, given the
/// set of external peers the internal host has already sent to.
fn passes_filter(allowed: &HashSet<SocketAddr>, from: SocketAddr, filtering: Filtering) -> bool {
    match filtering {
        Filtering::None => true,
        Filtering::AddressRestricted => allowed.iter().any(|a| a.ip() == from.ip()),
        Filtering::PortRestricted => allowed.contains(&from),
    }
}

enum Cmd {
    Send { dest: SocketAddr, payload: Vec<u8> },
}

/// One NAT box in front of one internal endpoint.
pub struct Nat {
    policy: NatPolicy,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    inbound_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    /// destination → external (mapped) address presented toward it.
    mapped: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
}

impl Nat {
    /// Create a NAT with the given behaviour. Spawns a background engine task, so
    /// must be called from within a tokio runtime.
    pub fn new(policy: NatPolicy) -> Nat {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let allowed = Arc::new(Mutex::new(HashSet::new()));
        let mapped = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(engine(policy, cmd_rx, inbound_tx, allowed, mapped.clone()));
        Nat {
            policy,
            cmd_tx,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
            mapped,
        }
    }

    pub fn policy(&self) -> NatPolicy {
        self.policy
    }

    /// Enqueue an outbound datagram to `dest` (non-blocking — the operation an
    /// `AsyncUdpSocket::try_send` maps to). The engine opens/reuses the mapping
    /// and sends from the external socket.
    pub fn send(&self, dest: SocketAddr, payload: &[u8]) {
        let _ = self.cmd_tx.send(Cmd::Send {
            dest,
            payload: payload.to_vec(),
        });
    }

    /// Await the next inbound datagram that passed the NAT filter, as
    /// `(payload, from)` where `from` is the real external sender.
    pub async fn recv(&self) -> Option<(Vec<u8>, SocketAddr)> {
        self.inbound_rx.lock().await.recv().await
    }

    /// The external (mapped) address the NAT presents toward `dest`, once a
    /// mapping exists. Under cone mapping this is the same for every `dest`;
    /// under symmetric mapping it differs per `dest`.
    pub fn external_addr_for(&self, dest: SocketAddr) -> Option<SocketAddr> {
        self.mapped.lock().unwrap().get(&dest).copied()
    }
}

/// The NAT engine: processes outbound sends one at a time (so mapping creation
/// needs no locking), opening external sockets per the mapping policy and
/// recording filter state. Each external socket gets a reader task that delivers
/// filtered inbound datagrams.
async fn engine(
    policy: NatPolicy,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    inbound_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    allowed: Arc<Mutex<HashSet<SocketAddr>>>,
    mapped: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
) {
    // Endpoint-independent mapping reuses one external socket; endpoint-dependent
    // allocates one per destination.
    let mut eim: Option<Arc<UdpSocket>> = None;
    let mut edm: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();

    while let Some(Cmd::Send { dest, payload }) = cmd_rx.recv().await {
        let sock = match policy.mapping {
            Mapping::EndpointIndependent => match &eim {
                Some(s) => s.clone(),
                None => {
                    let Ok(s) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
                        continue;
                    };
                    let s = Arc::new(s);
                    spawn_reader(
                        s.clone(),
                        policy.filtering,
                        allowed.clone(),
                        inbound_tx.clone(),
                    );
                    eim = Some(s.clone());
                    s
                }
            },
            Mapping::EndpointDependent => match edm.get(&dest) {
                Some(s) => s.clone(),
                None => {
                    let Ok(s) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
                        continue;
                    };
                    let s = Arc::new(s);
                    spawn_reader(
                        s.clone(),
                        policy.filtering,
                        allowed.clone(),
                        inbound_tx.clone(),
                    );
                    edm.insert(dest, s.clone());
                    s
                }
            },
        };

        if let Ok(local) = sock.local_addr() {
            mapped.lock().unwrap().insert(dest, local);
        }
        // Sending outbound to `dest` opens the filter for inbound from `dest`.
        allowed.lock().unwrap().insert(dest);
        let _ = sock.send_to(&payload, dest).await;
    }
}

/// Forward filtered inbound datagrams from one external socket to the internal
/// host's inbound channel.
fn spawn_reader(
    sock: Arc<UdpSocket>,
    filtering: Filtering,
    allowed: Arc<Mutex<HashSet<SocketAddr>>>,
    inbound_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        // Loop ends when the socket errors (closed) or the internal host is gone.
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let pass = passes_filter(&allowed.lock().unwrap(), from, filtering);
            if pass && inbound_tx.send((buf[..n].to_vec(), from)).is_err() {
                break; // internal host gone
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A passive external peer: a plain loopback UDP socket.
    async fn peer() -> UdpSocket {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap()
    }

    /// Send through the NAT to `p` and return the source address `p` observes
    /// (the NAT's mapped external address for that destination).
    async fn observed_src(nat: &Nat, p: &UdpSocket) -> SocketAddr {
        nat.send(p.local_addr().unwrap(), b"probe");
        let mut buf = [0u8; 16];
        let (_, src) = tokio::time::timeout(Duration::from_secs(2), p.recv_from(&mut buf))
            .await
            .expect("peer receives the probe")
            .unwrap();
        src
    }

    #[tokio::test]
    async fn cone_reuses_one_external_mapping() {
        let nat = Nat::new(NatPolicy::full_cone());
        let p1 = peer().await;
        let p2 = peer().await;
        let src1 = observed_src(&nat, &p1).await;
        let src2 = observed_src(&nat, &p2).await;
        assert_eq!(
            src1, src2,
            "cone NAT presents the same external address to every destination"
        );
    }

    #[tokio::test]
    async fn symmetric_maps_per_destination() {
        let nat = Nat::new(NatPolicy::symmetric());
        let p1 = peer().await;
        let p2 = peer().await;
        let src1 = observed_src(&nat, &p1).await;
        let src2 = observed_src(&nat, &p2).await;
        assert_ne!(
            src1, src2,
            "symmetric NAT presents a different external address per destination \
             (why STUN can't help a punch and the transfer must relay)"
        );
    }

    #[tokio::test]
    async fn port_restricted_filtering_blocks_then_admits() {
        let nat = Nat::new(NatPolicy::port_restricted_cone());
        let probed = peer().await;
        let stranger = peer().await;

        // Open a mapping by sending to `probed`; learn the external address.
        let mapped = observed_src(&nat, &probed).await;

        // A stranger the internal host never sent to cannot get in.
        stranger.send_to(b"unsolicited", mapped).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), nat.recv())
                .await
                .is_err(),
            "port-restricted filter drops a datagram from an un-probed source"
        );

        // After the internal host sends outbound to the stranger, its replies pass.
        nat.send(stranger.local_addr().unwrap(), b"now-i-know-you");
        // Drain the outbound datagram the stranger just received.
        let mut buf = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_secs(2), stranger.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        stranger.send_to(b"reply", mapped).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), nat.recv())
            .await
            .expect("inbound now passes the filter")
            .unwrap();
        assert_eq!(got.0, b"reply");
        assert_eq!(got.1, stranger.local_addr().unwrap());
    }

    #[tokio::test]
    async fn full_cone_admits_unsolicited_inbound() {
        // With no filtering, any external host can reach an open mapping — the
        // contrast that makes the restricted-cone test above meaningful.
        let nat = Nat::new(NatPolicy::full_cone());
        let probed = peer().await;
        let stranger = peer().await;
        let mapped = observed_src(&nat, &probed).await;

        stranger.send_to(b"hello-stranger", mapped).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), nat.recv())
            .await
            .expect("full cone admits unsolicited inbound")
            .unwrap();
        assert_eq!(got.0, b"hello-stranger");
    }
}
