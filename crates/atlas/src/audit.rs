//! Non-blocking, fire-and-forget audit emitter -> Watchtower.
//!
//! Mirrors the estate's canonical sink (keystone/sanctum): [`AuditSink`] holds a bounded
//! `tokio::mpsc` sender drained by a spawned worker that POSTs each event to `WATCHTOWER_URL/events`
//! (`Authorization: Bearer AUDIT_INGEST_TOKEN`) over plain HTTP/1.1 with a short timeout.
//! [`AuditSink::emit`] is sync + infallible: it `try_send`s and DROPS (warn + counter) when the
//! queue is full or the worker is gone, so a slow/down Watchtower NEVER blocks, slows, or fails a
//! request. When audit is disabled (the dev/test default) the sink is a no-op — no channel, no
//! worker.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Bounded queue depth. Beyond this, events are dropped rather than blocking the caller.
const QUEUE_CAPACITY: usize = 1024;
/// Per-POST budget (connect + write + read). Watchtower is in-network; keep it short.
const POST_TIMEOUT: Duration = Duration::from_secs(2);
/// Fixed producer name stamped on every event this process emits.
const SOURCE: &str = "atlas";

/// One audit record. Only the logical fields are carried — Watchtower assigns seq/ts/hash.
/// `severity` is one of `info` | `notice` | `warning`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub severity: &'static str,
    pub detail: String,
    pub source: &'static str,
}

impl AuditEvent {
    fn new(severity: &'static str, action: &str, actor: &str, target: &str, detail: &str) -> Self {
        AuditEvent {
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            severity,
            detail: detail.to_string(),
            source: SOURCE,
        }
    }

    /// `notice`-severity event (a deliberate operator action: editing an annotation).
    pub fn notice(action: &str, actor: &str, target: &str, detail: &str) -> Self {
        Self::new("notice", action, actor, target, detail)
    }
}

/// Non-blocking audit sink. Cheap to clone (shared sender + drop counter behind `Arc`). A disabled
/// sink (`inner == None`) makes [`emit`](Self::emit) a no-op.
#[derive(Clone)]
pub struct AuditSink {
    inner: Option<Inner>,
}

#[derive(Clone)]
struct Inner {
    tx: mpsc::Sender<AuditEvent>,
    dropped: Arc<AtomicU64>,
}

impl AuditSink {
    /// Disabled sink: `emit` is a no-op, no channel and no worker. The dev/test default.
    pub fn disabled() -> Self {
        AuditSink { inner: None }
    }

    /// Build the sink from config and (when enabled) spawn the background worker.
    ///
    /// Returns a disabled sink when `enabled` is false, when no ingest `token` is set, or when
    /// `watchtower_url` is unparseable — those misconfigurations only warn and turn audit OFF; they
    /// never fail startup or affect the request path. Must be called from within a tokio runtime
    /// when enabled (the worker is `tokio::spawn`ed).
    pub fn start(enabled: bool, watchtower_url: &str, token: Option<&str>) -> Self {
        if !enabled {
            return Self::disabled();
        }
        let Some(token) = token.filter(|t| !t.is_empty()) else {
            tracing::warn!("AUDIT_ENABLED but AUDIT_INGEST_TOKEN is empty — audit disabled");
            return Self::disabled();
        };
        let Some(target) = Target::parse(watchtower_url) else {
            tracing::warn!(url = %watchtower_url, "invalid WATCHTOWER_URL — audit disabled");
            return Self::disabled();
        };

        let (tx, rx) = mpsc::channel::<AuditEvent>(QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        tokio::spawn(worker(rx, target, token.to_string()));
        tracing::info!(url = %watchtower_url, "audit emitter enabled (watchtower)");
        AuditSink {
            inner: Some(Inner { tx, dropped }),
        }
    }

    /// Emit one event. Sync, non-blocking, infallible: `try_send` only; on a full queue or a dead
    /// worker the event is DROPPED (drop counter + warn). NEVER blocks or errors the request path.
    pub fn emit(&self, event: AuditEvent) {
        let Some(inner) = &self.inner else { return };
        if let Err(e) = inner.tx.try_send(event) {
            let total = inner.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            match e {
                mpsc::error::TrySendError::Full(ev) => tracing::warn!(
                    action = %ev.action,
                    dropped_total = total,
                    "audit queue full — event dropped"
                ),
                mpsc::error::TrySendError::Closed(ev) => tracing::warn!(
                    action = %ev.action,
                    dropped_total = total,
                    "audit worker gone — event dropped"
                ),
            }
        }
    }

    /// Total events dropped so far (full queue or dead worker). `0` for a disabled sink.
    pub fn dropped(&self) -> u64 {
        self.inner
            .as_ref()
            .map(|i| i.dropped.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// Drain the queue and POST each event. Delivery failures only warn — an event is never retried and
/// a down Watchtower never affects anything but this background task.
async fn worker(mut rx: mpsc::Receiver<AuditEvent>, target: Target, token: String) {
    while let Some(event) = rx.recv().await {
        let body = match serde_json::to_string(&event) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "audit event serialize failed — skipped");
                continue;
            }
        };
        match tokio::time::timeout(POST_TIMEOUT, post(&target, &token, &body)).await {
            Ok(Ok(status)) if (200..300).contains(&status) => {
                tracing::debug!(action = %event.action, status, "audit event delivered")
            }
            Ok(Ok(status)) => {
                tracing::warn!(action = %event.action, status, "watchtower rejected audit event")
            }
            Ok(Err(e)) => tracing::warn!(action = %event.action, error = %e, "audit POST failed"),
            Err(_) => tracing::warn!(action = %event.action, "audit POST timed out"),
        }
    }
}

/// Send one `POST /events`. Hand-rolled HTTP/1.1 over a raw TCP stream (the target is the internal
/// plaintext `http://watchtower:8500`, so no TLS client is needed). Returns the response status.
async fn post(target: &Target, token: &str, body: &str) -> std::io::Result<u16> {
    let mut stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        path = target.path,
        authority = target.authority,
        len = body.len(),
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let mut buf = Vec::with_capacity(256);
    stream.read_to_end(&mut buf).await?;
    parse_status(&buf)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no HTTP status line"))
}

/// Parse the numeric status from an HTTP response's first line (`HTTP/1.1 200 OK`).
fn parse_status(buf: &[u8]) -> Option<u16> {
    let line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let line = std::str::from_utf8(&buf[..line_end]).ok()?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Parsed Watchtower target: connect host/port, the `Host` header authority, and the request path.
struct Target {
    host: String,
    port: u16,
    authority: String,
    path: String,
}

impl Target {
    /// Parse `http://host[:port][/base]` into a connect target with `/events` appended. Only plain
    /// `http` is accepted (the internal hop is plaintext); anything else returns `None`.
    fn parse(url: &str) -> Option<Target> {
        let rest = url.strip_prefix("http://")?;
        let (authority, base_path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), 80u16),
        };
        if host.is_empty() {
            return None;
        }
        let base = base_path.trim_end_matches('/');
        Some(Target {
            host,
            port,
            authority: authority.to_string(),
            path: format!("{base}/events"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_sink_is_noop_and_never_drops() {
        let sink = AuditSink::disabled();
        for _ in 0..1000 {
            sink.emit(AuditEvent::notice("atlas.annotate", "a@b", "inkwell", "ok"));
        }
        assert_eq!(sink.dropped(), 0);
    }

    #[test]
    fn target_parse_variants() {
        let t = Target::parse("http://watchtower:8500").unwrap();
        assert_eq!(t.host, "watchtower");
        assert_eq!(t.port, 8500);
        assert_eq!(t.authority, "watchtower:8500");
        assert_eq!(t.path, "/events");

        assert!(Target::parse("https://watchtower:8500").is_none());
        assert!(Target::parse("watchtower:8500").is_none());
        assert!(Target::parse("http://").is_none());
    }

    #[tokio::test]
    async fn emit_never_blocks_when_sink_unreachable() {
        let sink = AuditSink::start(true, "http://127.0.0.1:1/", Some("token"));
        for _ in 0..(QUEUE_CAPACITY * 8) {
            sink.emit(AuditEvent::notice("atlas.annotate", "u", "inkwell", "v1"));
        }
        assert!(
            sink.dropped() > 0,
            "expected drops once the bounded queue saturated, got {}",
            sink.dropped()
        );
    }
}
