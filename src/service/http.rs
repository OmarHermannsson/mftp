//! Minimal HTTP status API + Web UI (mftp v2, milestone M8).
//!
//! A tiny read-only HTTP/1.1 surface over the daemon's service state — enough
//! for a browser dashboard and scripting, without pulling in a web framework.
//! Routes:
//!   * `GET /`        → a small HTML page that polls the JSON endpoints
//!   * `GET /status`  → daemon status as JSON
//!   * `GET /queue`   → the transfer queue as JSON
//!
//! Hand-rolled HTTP keeps the dependency footprint at zero; the daemon control
//! plane (UDS + bincode) remains the canonical write API. The CLI and this Web
//! UI are both clients of the same underlying service state.
//!
//! The surface is unauthenticated, so it is hardened for browser exposure: a
//! request-head timeout and size cap, a connection cap, and a `Host` check
//! (IP literal or `localhost` only) that defeats DNS rebinding. Binding it to a
//! non-loopback address logs a loud warning.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::service::queue::Queue;

/// The daemon's live authorization state, as shown on the dashboard.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuthView {
    pub enforced: bool,
    pub authorized_count: usize,
}

/// State the HTTP surface reports on.
pub struct HttpState {
    pub config_dir: PathBuf,
    pub listening_on: String,
    /// Snapshot of the *applied* authorization policy (what the TLS verifier is
    /// actually enforcing), rather than a fresh — possibly unparseable — read of
    /// the files on disk.
    pub auth: Arc<dyn Fn() -> AuthView + Send + Sync>,
}

const INDEX_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>mftpd</title>
<style>body{font:14px system-ui,sans-serif;margin:2rem;max-width:60rem}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:4px 8px;text-align:left}
h1{font-size:1.3rem}code{background:#f4f4f4;padding:1px 4px}</style></head>
<body><h1>mftpd</h1><div id="status"></div><h2>Transfers</h2><table id="q">
<thead><tr><th>id</th><th>peer</th><th>what</th><th>state</th><th>bytes</th></tr></thead>
<tbody></tbody></table>
<script>
async function refresh(){
 const s=await (await fetch('/status')).json();
 document.getElementById('status').innerHTML=
   `listening <code>${s.listening_on}</code> · auth ${s.auth_enforced?'enforced':'open'} · `+
   `${s.authorized_count} authorized · ${s.queued+s.active} pending`;
 const q=await (await fetch('/queue')).json();
 const tb=document.querySelector('#q tbody'); tb.innerHTML='';
 for(const j of q.jobs){const r=tb.insertRow();
   r.insertCell().textContent=j.id; r.insertCell().textContent=j.peer;
   r.insertCell().textContent=j.what; r.insertCell().textContent=j.state;
   r.insertCell().textContent=j.bytes_done+'/'+j.total_bytes;}
}
refresh(); setInterval(refresh,2000);
</script></body></html>"#;

/// Serve the HTTP surface forever.
pub async fn serve(listener: TcpListener, state: Arc<HttpState>) -> Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, _peer) = listener.accept().await.context("accept http")?;
        // Concurrency cap: past MAX_CONNECTIONS in flight, shed new
        // connections immediately rather than spawning without bound.
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!("http: connection limit reached, dropping connection");
            drop(stream);
            continue;
        };
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle(stream, st).await {
                tracing::debug!("http connection error: {e:#}");
            }
        });
    }
}

/// Maximum simultaneously served HTTP connections.
const MAX_CONNECTIONS: usize = 64;
/// Maximum request-head size (request line + headers).
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Time allowed for a client to send its complete request head (slowloris guard).
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Warn loudly when the dashboard is reachable from other hosts: it is
/// unauthenticated and exposes daemon status / transfer metadata.
pub fn warn_if_exposed(addr: std::net::SocketAddr) {
    if !addr.ip().is_loopback() {
        let msg = format!(
            "WARNING: the HTTP dashboard on {addr} is NOT bound to loopback — it is \
             unauthenticated and readable by anyone who can reach this address. \
             Bind it to 127.0.0.1 unless that is intended."
        );
        tracing::warn!("{msg}");
        eprintln!("{msg}");
    }
}

/// DNS-rebinding guard: accept only a `Host` that is an IP literal or
/// `localhost` (optionally with a port). A rebinding attack needs the browser
/// to send the attacker's *hostname*, which this rejects.
fn host_allowed(host: &str) -> bool {
    let host = host.trim();
    // Strip an optional :port (IPv6 literals are bracketed).
    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((ip, tail)) if tail.is_empty() || tail.starts_with(':') => {
                return ip.parse::<std::net::Ipv6Addr>().is_ok();
            }
            _ => return false,
        }
    } else {
        host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
    };
    name.eq_ignore_ascii_case("localhost") || name.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Read the request head (up to the blank line). `Ok(None)` if the client
/// closed first; an error if it is too large.
async fn read_head(stream: &mut tokio::net::TcpStream) -> Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(Some(buf));
        }
        if buf.len() > MAX_HEADER_BYTES {
            anyhow::bail!("request head exceeds {MAX_HEADER_BYTES} bytes");
        }
    }
}

async fn respond(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    ctype: &str,
    body: &str,
) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn handle(mut stream: tokio::net::TcpStream, state: Arc<HttpState>) -> Result<()> {
    let head = match tokio::time::timeout(HEADER_TIMEOUT, read_head(&mut stream)).await {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(_)) => {
            let body = r#"{"error":"request header too large"}"#;
            respond(
                &mut stream,
                "431 Request Header Fields Too Large",
                "application/json",
                body,
            )
            .await?;
            // Half-close and briefly drain the unread remainder so closing with
            // unread input doesn't RST the response away before the client
            // reads it.
            stream.shutdown().await.ok();
            let mut sink = [0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                let mut drained = 0usize;
                while drained < 256 * 1024 {
                    match stream.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => drained += n,
                    }
                }
            })
            .await;
            return Ok(());
        }
        Err(_) => {
            let body = r#"{"error":"request timeout"}"#;
            return respond(&mut stream, "408 Request Timeout", "application/json", body).await;
        }
    };
    let req = String::from_utf8_lossy(&head);
    let mut lines = req.split("\r\n");
    let path = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    let host = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.trim().to_owned());
    if !host.as_deref().is_some_and(host_allowed) {
        let body = r#"{"error":"bad or missing Host header"}"#;
        return respond(&mut stream, "400 Bad Request", "application/json", body).await;
    }

    let (status, ctype, body) = route(&path, &state);
    respond(&mut stream, status, ctype, &body).await
}

/// Route a request path to (status line, content-type, body).
fn route(path: &str, state: &HttpState) -> (&'static str, &'static str, String) {
    // Strip any query string.
    let path = path.split('?').next().unwrap_or(path);
    match path {
        "/" => ("200 OK", "text/html; charset=utf-8", INDEX_HTML.to_string()),
        "/status" => ("200 OK", "application/json", status_json(state)),
        "/queue" => ("200 OK", "application/json", queue_json(state)),
        _ => (
            "404 Not Found",
            "application/json",
            r#"{"error":"not found"}"#.to_string(),
        ),
    }
}

fn status_json(state: &HttpState) -> String {
    let auth = (state.auth)();
    let q = Queue::load(&state.config_dir).unwrap_or_default();
    let queued = q
        .jobs()
        .iter()
        .filter(|j| j.state == crate::service::queue::JobState::Queued)
        .count();
    let active = q
        .jobs()
        .iter()
        .filter(|j| j.state == crate::service::queue::JobState::Active)
        .count();
    serde_json::json!({
        "listening_on": state.listening_on,
        "auth_enforced": auth.enforced,
        "authorized_count": auth.authorized_count,
        "queued": queued,
        "active": active,
    })
    .to_string()
}

fn queue_json(state: &HttpState) -> String {
    let q = Queue::load(&state.config_dir).unwrap_or_default();
    serde_json::json!({ "jobs": q.jobs() }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        http_raw(
            addr,
            format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes(),
        )
        .await
    }

    async fn http_raw(addr: std::net::SocketAddr, req: &[u8]) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).to_string()
    }

    #[tokio::test]
    async fn serves_status_queue_and_index() {
        let dir = tempfile::tempdir().unwrap();
        // Seed a queue so /queue has content.
        let mut q = Queue::default();
        q.enqueue("alice", "a.bin", 100);
        q.save(dir.path()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(HttpState {
            config_dir: dir.path().to_owned(),
            listening_on: "127.0.0.1:7777".into(),
            auth: Arc::new(|| AuthView {
                enforced: true,
                authorized_count: 3,
            }),
        });
        tokio::spawn(async move {
            let _ = serve(listener, state).await;
        });

        let status = http_get(addr, "/status").await;
        assert!(status.contains("200 OK"));
        assert!(status.contains("\"listening_on\""));
        assert!(status.contains("\"auth_enforced\":true"));
        assert!(status.contains("\"authorized_count\":3"));

        let queue = http_get(addr, "/queue").await;
        assert!(queue.contains("a.bin"), "queue JSON lists the job");

        let index = http_get(addr, "/").await;
        assert!(index.contains("<title>mftpd</title>"));

        let missing = http_get(addr, "/nope").await;
        assert!(missing.contains("404 Not Found"));

        // DNS rebinding: a foreign hostname in Host is refused; so is no Host.
        let rebind = http_raw(
            addr,
            b"GET /status HTTP/1.1\r\nHost: evil.example:80\r\n\r\n",
        )
        .await;
        assert!(rebind.contains("400 Bad Request"), "{rebind}");
        let nohost = http_raw(addr, b"GET /status HTTP/1.1\r\n\r\n").await;
        assert!(nohost.contains("400 Bad Request"));
        let local = http_raw(addr, b"GET /status HTTP/1.1\r\nhost: localhost:1\r\n\r\n").await;
        assert!(local.contains("200 OK"));

        // Oversized request head → 431.
        let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
        big.extend(vec![b'a'; 20 * 1024]);
        let resp = http_raw(addr, &big).await;
        assert!(resp.contains("431"), "{resp}");
    }

    #[test]
    fn host_header_rules() {
        for ok in [
            "localhost",
            "LOCALHOST:8080",
            "127.0.0.1",
            "10.0.0.5:7000",
            "[::1]",
            "[::1]:80",
        ] {
            assert!(host_allowed(ok), "{ok}");
        }
        for bad in [
            "evil.example",
            "evil.example:80",
            "localhost.evil.com",
            "[::1",
            "",
        ] {
            assert!(!host_allowed(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn slow_header_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(HttpState {
            config_dir: tempfile::tempdir().unwrap().path().to_owned(),
            listening_on: String::new(),
            auth: Arc::new(AuthView::default),
        });
        tokio::spawn(async move {
            let _ = serve(listener, state).await;
        });
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert!(String::from_utf8_lossy(&out).contains("408"));
    }
}
