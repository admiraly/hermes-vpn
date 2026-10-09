//! Minimal Prometheus-style metrics for the servers.
//!
//! Servers keep their own atomic counters and build a text snapshot on each
//! scrape with [`Exposition`]; [`serve`] exposes it over a deliberately
//! tiny HTTP/1.1 responder (`GET /metrics`, `GET /health`) so the UDP-only
//! relay doesn't need a web framework.
//!
//! Metrics are **off unless an operator asks for them** by setting a bind
//! address, and should be bound to localhost or an internal interface:
//! they are aggregate counts (no node ids, no IPs), but there is no reason
//! to publish them to the world.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Builder for the Prometheus text exposition format (version 0.0.4).
#[derive(Default)]
pub struct Exposition {
    out: String,
}

impl Exposition {
    /// An empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn header(&mut self, name: &str, help: &str, kind: &str) {
        let _ = writeln!(self.out, "# HELP {name} {help}");
        let _ = writeln!(self.out, "# TYPE {name} {kind}");
    }

    /// A monotonically increasing counter.
    #[must_use]
    pub fn counter(mut self, name: &str, help: &str, value: u64) -> Self {
        self.header(name, help, "counter");
        let _ = writeln!(self.out, "{name} {value}");
        self
    }

    /// A value that can go up and down.
    #[must_use]
    pub fn gauge(mut self, name: &str, help: &str, value: u64) -> Self {
        self.header(name, help, "gauge");
        let _ = writeln!(self.out, "{name} {value}");
        self
    }

    /// A counter split by one label, e.g. `result="accepted"`.
    #[must_use]
    pub fn labeled_counter(
        mut self,
        name: &str,
        help: &str,
        label: &str,
        values: &[(&str, u64)],
    ) -> Self {
        self.header(name, help, "counter");
        for (v, n) in values {
            let _ = writeln!(self.out, "{name}{{{label}=\"{v}\"}} {n}");
        }
        self
    }

    /// The finished text.
    #[must_use]
    pub fn finish(self) -> String {
        self.out
    }
}

/// Produces a fresh snapshot on every scrape.
pub type Render = Arc<dyn Fn() -> String + Send + Sync>;

/// Longest request head we'll read before giving up on a client.
const MAX_REQUEST: usize = 4096;
/// A client has this long to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Bind `bind` and serve `GET /metrics` (the output of `render`) and
/// `GET /health` until the returned task is aborted. Returns the bound
/// address (useful with port 0) and the task.
///
/// # Errors
/// Fails if the address can't be bound.
pub async fn serve(
    bind: SocketAddr,
    render: Render,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(bind).await?;
    let local = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let render = render.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(READ_TIMEOUT * 2, handle(stream, render)).await;
            });
        }
    });
    Ok((local, task))
}

async fn handle(mut stream: TcpStream, render: Render) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    // Read until the end of the request head (or give up).
    let head_done = tokio::time::timeout(READ_TIMEOUT, async {
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok::<bool, std::io::Error>(false);
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                return Ok(true);
            }
            if buf.len() > MAX_REQUEST {
                return Ok(false);
            }
        }
    })
    .await
    .unwrap_or(Ok(false))?;
    if !head_done {
        return respond(
            &mut stream,
            "400 Bad Request",
            "text/plain",
            "bad request\n",
        )
        .await;
    }

    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = path.split('?').next().unwrap_or("");
    match (method, path) {
        ("GET", "/metrics") => {
            respond(
                &mut stream,
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                &render(),
            )
            .await
        }
        ("GET", "/health") => respond(&mut stream, "200 OK", "text/plain", "ok\n").await,
        ("GET", _) => respond(&mut stream, "404 Not Found", "text/plain", "not found\n").await,
        _ => {
            respond(
                &mut stream,
                "405 Method Not Allowed",
                "text/plain",
                "GET only\n",
            )
            .await
        }
    }
}

async fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}

/// Read an optional metrics bind address from an environment variable.
/// Unset or empty means metrics are off.
///
/// # Errors
/// Fails if the variable is set but isn't a socket address.
pub fn bind_from_env(var: &str) -> anyhow::Result<Option<SocketAddr>> {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => v
            .trim()
            .parse()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("{var}={v:?} is not a socket address: {e}")),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(addr: SocketAddr, request: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[test]
    fn exposition_format() {
        let text = Exposition::new()
            .counter("hermes_x_total", "Things.", 7)
            .gauge("hermes_y", "Level.", 3)
            .labeled_counter("hermes_z_total", "By kind.", "kind", &[("a", 1), ("b", 2)])
            .finish();
        assert!(text.contains("# TYPE hermes_x_total counter\nhermes_x_total 7\n"));
        assert!(text.contains("# TYPE hermes_y gauge\nhermes_y 3\n"));
        assert!(text.contains("hermes_z_total{kind=\"a\"} 1\nhermes_z_total{kind=\"b\"} 2\n"));
    }

    #[tokio::test]
    async fn serves_metrics_health_and_rejects_the_rest() {
        let render: Render = Arc::new(|| Exposition::new().gauge("hermes_up", "Up.", 1).finish());
        let (addr, task) = serve("127.0.0.1:0".parse().unwrap(), render).await.unwrap();

        let m = get(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
        assert!(m.contains("version=0.0.4"));
        assert!(m.ends_with("hermes_up 1\n"));

        assert!(get(addr, "GET /health HTTP/1.1\r\n\r\n")
            .await
            .ends_with("ok\n"));
        assert!(get(addr, "GET /nope HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 404"));
        assert!(get(addr, "POST /metrics HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 405"));
        // Query strings are ignored.
        assert!(get(addr, "GET /metrics?x=1 HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 200"));
        // An oversized request head is refused, not buffered forever.
        let junk = format!("GET /metrics HTTP/1.1\r\nX: {}\r\n", "a".repeat(10_000));
        assert!(get(addr, &junk).await.starts_with("HTTP/1.1 400"));
        task.abort();
    }

    #[test]
    fn bind_env_parsing() {
        std::env::remove_var("HERMES_TEST_METRICS");
        assert_eq!(bind_from_env("HERMES_TEST_METRICS").unwrap(), None);
        std::env::set_var("HERMES_TEST_METRICS", "127.0.0.1:9100");
        assert_eq!(
            bind_from_env("HERMES_TEST_METRICS").unwrap(),
            Some("127.0.0.1:9100".parse().unwrap())
        );
        std::env::set_var("HERMES_TEST_METRICS", "not-an-address");
        assert!(bind_from_env("HERMES_TEST_METRICS").is_err());
        std::env::remove_var("HERMES_TEST_METRICS");
    }
}
