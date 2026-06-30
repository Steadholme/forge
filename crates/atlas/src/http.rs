//! Dependency-light outbound HTTP/1.1 GET — used only for the internal Beacon status fetch.
//!
//! Beacon is reachable in-network over plain `http://beacon:8400`, so rather than pull in a full
//! HTTP client (or a TLS stack — sqlx already brings rustls for the DB) we keep the same
//! dependency-light approach the rest of the stack uses: a raw `tokio::net::TcpStream`, a minimal
//! GET, read to EOF, split the body.
//!
//! RESILIENCE IS THE CONTRACT: every failure (DNS, connect, timeout, malformed response) collapses
//! to `None`. The caller turns `None` into an "unavailable" snapshot, so a down or slow Beacon
//! NEVER errors or hangs the dashboard.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Hard cap on the buffered response body. Beacon's status JSON is small; this only stops a
/// misbehaving upstream from exhausting memory.
const MAX_BODY: usize = 1_048_576; // 1 MiB

/// `GET url`, returning the response BODY as a string, or `None` on ANY failure. `timeout` bounds
/// the whole connect + write + read so a stalled backend can never tie up a page load.
pub async fn fetch_text(url: &str, timeout: Duration) -> Option<String> {
    match tokio::time::timeout(timeout, fetch_body(url)).await {
        Ok(Ok(body)) => Some(body),
        Ok(Err(e)) => {
            tracing::warn!(url = %url, error = %e, "backend fetch failed — rendering placeholder");
            None
        }
        Err(_) => {
            tracing::warn!(url = %url, "backend fetch timed out — rendering placeholder");
            None
        }
    }
}

/// Connect, send a minimal HTTP/1.1 GET, and return the response BODY (everything after the header
/// terminator). `Connection: close` lets us read to EOF without parsing the length. Only plain
/// `http://` targets are supported (the Beacon hop is in-network plaintext).
async fn fetch_body(url: &str) -> std::io::Result<String> {
    let (host, port, path) = parse_http_url(url).ok_or_else(|| io_err("invalid or non-http URL"))?;
    let mut stream = TcpStream::connect((host.as_str(), port)).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: atlas/0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut acc: Vec<u8> = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.len() > MAX_BODY {
            break;
        }
    }
    split_body(&acc)
}

/// Split a raw HTTP response into its body (the bytes after the first blank line), returned as a
/// lossy UTF-8 string for JSON parsing.
fn split_body(raw: &[u8]) -> std::io::Result<String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io_err("no HTTP header terminator"))?;
    Ok(String::from_utf8_lossy(&raw[sep + 4..]).into_owned())
}

/// Parse `http://host[:port]/path` into `(host, port, path)`. Minimal by design — the URL is an
/// operator-controlled service URL, not arbitrary user input.
fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return None;
    }
    let path = if path.is_empty() { "/".to_string() } else { path.to_string() };
    Some((host, port, path))
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_body_extracts_payload_after_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        assert_eq!(split_body(raw).unwrap(), "{\"ok\":true}");
    }

    #[test]
    fn parse_http_url_variants() {
        assert_eq!(
            parse_http_url("http://beacon:8400/api/status"),
            Some(("beacon".to_string(), 8400, "/api/status".to_string()))
        );
        assert_eq!(
            parse_http_url("http://beacon:8400"),
            Some(("beacon".to_string(), 8400, "/".to_string()))
        );
        assert_eq!(parse_http_url("https://nope"), None);
        assert_eq!(parse_http_url("ftp://nope"), None);
    }
}
