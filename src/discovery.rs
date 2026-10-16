//! LAN service discovery (mftp v2, milestone M5).
//!
//! Lets a sender reach a receiver **by name** on the local network without
//! knowing its IP: `mftp send file alice-laptop` instead of `mftp send file
//! 10.0.0.7:7777`. A receiver/daemon announces itself; the sender broadcasts a
//! query and resolves the first matching announcement to an `ip:port`.
//!
//! This is an mftp-specific protocol carried over an admin-scoped IPv4 multicast
//! group (rather than full DNS-SD wire format) — enough for the mftp-to-mftp
//! "resolve a name on the LAN" use case without a DNS-encoder dependency. The
//! announcement also carries the responder's Ed25519 DeviceId.
//!
//! **Announcements are unauthenticated**: anyone on the LAN can answer for any
//! name. Discovery therefore only supplies an *address*; it never establishes
//! trust. The sender either matches the announced DeviceId against an explicit
//! `--trust-device` pin, or goes through normal TOFU certificate verification
//! for the discovered address. Conflicting answers (several distinct DeviceIds
//! for one name) are an error rather than "first responder wins".
//!
//! Production uses the multicast group [`DISCOVERY_GROUP`]:[`DISCOVERY_PORT`];
//! the request/response protocol itself is transport-agnostic and unit-tested
//! over plain unicast loopback.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

/// Admin-scoped ("site-local") multicast group — deliberately *not* the real
/// mDNS group (224.0.0.251), since this carries an mftp-specific payload.
pub const DISCOVERY_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 77, 77);
/// UDP port for discovery announcements/queries.
pub const DISCOVERY_PORT: u16 = 7778;

/// A discovery datagram (one bincode value per UDP packet).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscoveryMsg {
    /// A sender looking for a named receiver. Empty `name` matches any responder
    /// (a "browse all" query).
    Query { name: String },
    /// A receiver advertising itself.
    Announce {
        name: String,
        port: u16,
        device_id: String,
    },
}

/// What [`resolve`] found: where to connect and the responder's DeviceId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub addr: SocketAddr,
    pub device_id: String,
}

fn encode(msg: &DiscoveryMsg) -> Vec<u8> {
    bincode::serialize(msg).expect("DiscoveryMsg serialization cannot fail")
}

fn decode(buf: &[u8]) -> Option<DiscoveryMsg> {
    bincode::deserialize(buf).ok()
}

/// Does an announcement satisfy a query for `wanted`? An empty query name is a
/// "browse all" and matches any announcement; otherwise the names must be equal.
/// An empty *announced* name does NOT wildcard-match a specific query — a
/// nameless/misconfigured responder must not answer (and thus hijack) lookups
/// for a real name.
fn name_matches(wanted: &str, announced: &str) -> bool {
    wanted.is_empty() || wanted == announced
}

/// Run a responder loop: reply to matching [`DiscoveryMsg::Query`]s with an
/// [`DiscoveryMsg::Announce`] for `name`/`port`/`device_id`.
///
/// `sock` should already be bound (and, in production, joined to
/// [`DISCOVERY_GROUP`] — see [`bind_responder`]). Runs until the socket errors.
pub async fn respond_loop(
    sock: UdpSocket,
    name: String,
    port: u16,
    device_id: String,
) -> Result<()> {
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await.context("discovery recv")?;
        if let Some(DiscoveryMsg::Query { name: wanted }) = decode(&buf[..n]) {
            if name_matches(&wanted, &name) {
                let reply = encode(&DiscoveryMsg::Announce {
                    name: name.clone(),
                    port,
                    device_id: device_id.clone(),
                });
                // Reply directly to the querier (unicast); ignore send errors.
                let _ = sock.send_to(&reply, from).await;
            }
        }
    }
}

/// Bind a responder socket on the discovery port and join the multicast group on
/// all interfaces (`0.0.0.0`). Reuse-address is set so multiple tools can share
/// the group on one host.
pub fn bind_responder() -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    let bind: SocketAddr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT));
    sock.bind(&bind.into())?;
    sock.set_multicast_loop_v4(true)?;
    sock.join_multicast_v4(&DISCOVERY_GROUP, &Ipv4Addr::UNSPECIFIED)
        .context("join discovery multicast group")?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into()).context("wrap discovery socket")
}

/// Resolve a receiver `name` by sending a query to `query_target` and awaiting
/// the first matching announcement (or `timeout`).
///
/// In production `query_target` is `DISCOVERY_GROUP:DISCOVERY_PORT`; tests pass
/// a unicast responder address. The resolved IP is the responder's source
/// address; the port is taken from the announcement.
///
/// Prefer [`resolve_all`] + [`choose`] when the result will be connected to:
/// this returns whichever responder answered first.
pub async fn resolve(
    name: &str,
    query_target: SocketAddr,
    timeout: Duration,
) -> Result<Option<Resolved>> {
    Ok(resolve_all(name, query_target, timeout, Duration::ZERO)
        .await?
        .into_iter()
        .next())
}

/// Like [`resolve`], but after the first matching announcement keep listening
/// for `grace` (bounded by `timeout`) and return **every** distinct responder,
/// in arrival order. An empty vec means nothing answered within `timeout`.
///
/// Collecting a short window lets the caller notice that more than one device
/// claims the same name (a misconfiguration — or a spoofing attempt).
pub async fn resolve_all(
    name: &str,
    query_target: SocketAddr,
    timeout: Duration,
    grace: Duration,
) -> Result<Vec<Resolved>> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("bind discovery query socket")?;
    sock.set_broadcast(true).ok();
    let query = encode(&DiscoveryMsg::Query {
        name: name.to_string(),
    });
    sock.send_to(&query, query_target)
        .await
        .context("send discovery query")?;

    let mut buf = vec![0u8; 2048];
    let mut found: Vec<Resolved> = Vec::new();
    let mut deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(found);
        }
        match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if let Some(DiscoveryMsg::Announce {
                    name: ann_name,
                    port,
                    device_id,
                }) = decode(&buf[..n])
                {
                    if name_matches(name, &ann_name) {
                        let r = Resolved {
                            addr: SocketAddr::new(from.ip(), port),
                            device_id: device_id.trim().to_lowercase(),
                        };
                        if found.is_empty() {
                            // First answer: shorten the wait to the grace window.
                            deadline = deadline.min(tokio::time::Instant::now() + grace);
                        }
                        if !found.contains(&r) {
                            found.push(r);
                        }
                        if grace.is_zero() {
                            return Ok(found);
                        }
                    }
                }
                // Non-matching / malformed datagram — keep waiting.
            }
            Ok(Err(e)) => return Err(e).context("discovery recv"),
            Err(_) => return Ok(found), // timed out
        }
    }
}

/// Pick the responder to connect to from [`resolve_all`]'s answers for `name`.
///
/// * With `trusted_device` (the user's `--trust-device` pin), the responder
///   announcing that DeviceId is chosen; if none does, it is an error. The pin
///   is then enforced cryptographically at the TLS layer.
/// * Without a pin, all answers must come from **one** DeviceId; distinct
///   DeviceIds for the same name are an error (ambiguous or spoofed). The
///   result is only an address hint — the caller must still verify the
///   receiver via TOFU, since the announced id is unauthenticated.
pub fn choose(name: &str, found: &[Resolved], trusted_device: Option<&str>) -> Result<Resolved> {
    if let Some(pin) = trusted_device {
        let pin = pin.trim().to_lowercase();
        return found
            .iter()
            .find(|r| r.device_id == pin)
            .cloned()
            .with_context(|| {
                format!(
                    "no LAN responder for {name:?} announced the pinned device {pin} \
                     (answers: {})",
                    describe(found)
                )
            });
    }
    let first = found
        .first()
        .with_context(|| format!("no LAN responder for {name:?}"))?;
    if found.iter().any(|r| r.device_id != first.device_id) {
        anyhow::bail!(
            "multiple devices answered for {name:?} on the LAN: {} — pass --trust-device \
             <id> to pick one, or use host:port",
            describe(found)
        );
    }
    Ok(first.clone())
}

fn describe(found: &[Resolved]) -> String {
    if found.is_empty() {
        return "none".to_string();
    }
    found
        .iter()
        .map(|r| format!("{} at {}", r.device_id, r.addr))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Production multicast target for [`resolve`].
pub fn multicast_target() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(DISCOVERY_GROUP, DISCOVERY_PORT))
}

/// This host's name, used as the default discovery announce name.
/// Falls back to `"mftp-host"` if it can't be determined.
pub fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes at most buf.len() bytes into buf.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if rc == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(s) = std::str::from_utf8(&buf[..end]) {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "mftp-host".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_round_trips() {
        let m = DiscoveryMsg::Announce {
            name: "host".into(),
            port: 7777,
            device_id: "a".repeat(64),
        };
        assert_eq!(decode(&encode(&m)).unwrap(), m);
    }

    #[test]
    fn name_matching_rules() {
        assert!(name_matches("", "anything"), "empty query browses all");
        assert!(
            !name_matches("host", ""),
            "empty announced name must NOT match a specific query"
        );
        assert!(name_matches("host", "host"));
        assert!(!name_matches("host", "other"));
    }

    /// End-to-end over unicast loopback (no multicast needed): a responder
    /// answers a query and `resolve` returns its address + DeviceId.
    #[tokio::test]
    async fn resolve_finds_unicast_responder() {
        // Responder bound on an ephemeral loopback port.
        let resp_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resp_addr = resp_sock.local_addr().unwrap();
        let device_id = "b".repeat(64);
        let dev2 = device_id.clone();
        let h = tokio::spawn(async move {
            let _ = respond_loop(resp_sock, "laptop".into(), 9999, dev2).await;
        });

        let got = resolve("laptop", resp_addr, Duration::from_secs(2))
            .await
            .unwrap()
            .expect("should resolve");
        assert_eq!(got.addr.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(got.addr.port(), 9999, "port comes from the announcement");
        assert_eq!(got.device_id, device_id);
        h.abort();
    }

    fn resolved(id: char, port: u16) -> Resolved {
        Resolved {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            device_id: id.to_string().repeat(64),
        }
    }

    #[test]
    fn choose_rejects_conflicting_devices() {
        let a = resolved('a', 1);
        let a2 = resolved('a', 2); // same device, second interface
        let b = resolved('b', 3);
        assert_eq!(choose("n", &[a.clone(), a2.clone()], None).unwrap(), a);
        assert!(choose("n", &[a.clone(), b.clone()], None).is_err());
        assert!(choose("n", &[], None).is_err());
        // A pin selects the matching responder even amid conflicting answers…
        let pin = "B".repeat(64);
        assert_eq!(choose("n", &[a.clone(), b.clone()], Some(&pin)).unwrap(), b);
        // …and is an error when nobody announces it.
        assert!(choose("n", &[a], Some(&"c".repeat(64))).is_err());
    }

    /// `resolve_all` collects every responder answering within the grace window.
    #[tokio::test]
    async fn resolve_all_collects_multiple_responders() {
        // Two responders for the same name, and a forwarder that fans one query
        // out to both (standing in for the multicast group).
        let r1 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let r2 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (a1, a2) = (r1.local_addr().unwrap(), r2.local_addr().unwrap());
        let h1 = tokio::spawn(respond_loop(r1, "laptop".into(), 1111, "a".repeat(64)));
        let h2 = tokio::spawn(respond_loop(r2, "laptop".into(), 2222, "b".repeat(64)));
        let fan = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let fan_addr = fan.local_addr().unwrap();
        let hf = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (n, from) = fan.recv_from(&mut buf).await.unwrap();
            // Forward the query to each responder and relay its answer back to
            // the querier (responders reply to whoever sent them the query).
            let q = buf[..n].to_vec();
            for target in [a1, a2] {
                let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                s.send_to(&q, target).await.unwrap();
                let mut rb = vec![0u8; 2048];
                let (m, _) = s.recv_from(&mut rb).await.unwrap();
                fan.send_to(&rb[..m], from).await.unwrap();
            }
        });

        let found = resolve_all(
            "laptop",
            fan_addr,
            Duration::from_secs(2),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
        let mut ids: Vec<_> = found.iter().map(|r| r.device_id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["a".repeat(64), "b".repeat(64)]);
        assert!(choose("laptop", &found, None).is_err(), "ambiguous name");
        for h in [h1, h2] {
            h.abort();
        }
        hf.abort();
    }

    /// A query for a different name times out (no match).
    #[tokio::test]
    async fn resolve_times_out_on_no_match() {
        let resp_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resp_addr = resp_sock.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let _ = respond_loop(resp_sock, "laptop".into(), 9999, "c".repeat(64)).await;
        });

        let got = resolve("desktop", resp_addr, Duration::from_millis(300))
            .await
            .unwrap();
        assert!(got.is_none(), "non-matching name must not resolve");
        h.abort();
    }
}
