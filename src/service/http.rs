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

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::service::acl::Acl;
use crate::service::queue::Queue;

/// State the HTTP surface reports on.
pub struct HttpState {
    pub config_dir: PathBuf,
    pub listening_on: String,
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
    loop {
        let (stream, _peer) = listener.accept().await.context("accept http")?;
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle(stream, st).await {
                tracing::debug!("http connection error: {e:#}");
            }
        });
    }
}

async fn handle(mut stream: tokio::net::TcpStream, state: Arc<HttpState>) -> Result<()> {
    // Read until end of headers (or a sane cap). We only need the request line.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
    }
    let req = String::from_utf8_lossy(&buf);
    let path = req
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, ctype, body) = route(path, &state);
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
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
    let acl = Acl::load(&state.config_dir).unwrap_or_default();
    let authorized = crate::identity::load_authorized_in(&state.config_dir);
    let auth_count = if acl.is_empty() {
        authorized.len()
    } else {
        acl.authorized_ids().len()
    };
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
        "auth_enforced": auth_count > 0,
        "authorized_count": auth_count,
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
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
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
        });
        tokio::spawn(async move {
            let _ = serve(listener, state).await;
        });

        let status = http_get(addr, "/status").await;
        assert!(status.contains("200 OK"));
        assert!(status.contains("\"listening_on\""));

        let queue = http_get(addr, "/queue").await;
        assert!(queue.contains("a.bin"), "queue JSON lists the job");

        let index = http_get(addr, "/").await;
        assert!(index.contains("<title>mftpd</title>"));

        let missing = http_get(addr, "/nope").await;
        assert!(missing.contains("404 Not Found"));
    }
}
