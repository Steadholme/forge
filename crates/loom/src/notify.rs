use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct KlaxonNotifier {
    url: String,
    token: String,
}

impl KlaxonNotifier {
    /// KLAXON_NOTIFY_URL(完整 http:// URL)+ KLAXON_INGEST_TOKEN;任一缺失 => None(禁用,完全向后兼容)。
    pub fn from_env() -> Option<KlaxonNotifier> {
        let url = std::env::var("KLAXON_NOTIFY_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let token = std::env::var("KLAXON_INGEST_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        Some(KlaxonNotifier { url, token })
    }

    /// fire-and-forget:spawn 一个 detached、带 5s 超时的任务;失败只 warn,绝不冒泡/阻塞调用方。
    pub fn notify(&self, source: &str, user_sub: &str, title: &str, body: &str, url: &str) {
        let this = self.clone();
        let (source, user_sub, title, body, url) = (
            source.to_string(),
            user_sub.to_string(),
            title.to_string(),
            body.to_string(),
            url.to_string(),
        );
        tokio::spawn(async move {
            if let Err(e) = this.post(&source, &user_sub, &title, &body, &url).await {
                tracing::warn!(error = %e, source = %source, "klaxon notify failed");
            }
        });
    }

    async fn post(
        &self,
        source: &str,
        user_sub: &str,
        title: &str,
        body: &str,
        url: &str,
    ) -> Result<(), String> {
        let (host, port, path) = parse_http_url(&self.url)
            .ok_or_else(|| format!("KLAXON_NOTIFY_URL 不是 http:// URL: {}", self.url))?;
        let json = format!(
            "{{\"user_sub\":\"{}\",\"source\":\"{}\",\"severity\":\"info\",\"title\":\"{}\",\"body\":\"{}\",\"url\":\"{}\"}}",
            json_escape(user_sub), json_escape(source), json_escape(title), json_escape(body), json_escape(url),
        );
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{json}",
            token = self.token,
            len = json.len(),
        );
        let fut = async {
            let mut s = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|e| e.to_string())?;
            s.write_all(req.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            let mut buf = Vec::with_capacity(256);
            s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
            Ok::<Vec<u8>, String>(buf)
        };
        let buf = tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .map_err(|_| "klaxon ingest timed out".to_string())??;
        let head = String::from_utf8_lossy(&buf);
        let status = head.lines().next().unwrap_or("");
        if status.contains(" 20") {
            Ok(())
        } else {
            Err(format!("klaxon ingest 返回: {status}"))
        }
    }
}

/// 转义字符串以嵌入 JSON 双引号值(RFC 8259 §7)——防注入。
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// 拆 http://host[:port]/path -> (host, port, path)(默认端口 80、默认路径 /);非 http 返回 None。
fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80u16),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::{json_escape, parse_http_url};

    #[test]
    fn parses_http_notify_urls() {
        assert_eq!(
            parse_http_url("http://klaxon:9050/api/notify"),
            Some(("klaxon".to_string(), 9050, "/api/notify".to_string()))
        );
        assert_eq!(
            parse_http_url("http://klaxon"),
            Some(("klaxon".to_string(), 80, "/".to_string()))
        );
        assert_eq!(parse_http_url("https://klaxon/api/notify"), None);
    }

    #[test]
    fn escapes_json_string_values() {
        assert_eq!(
            json_escape("a\"b\\c\n\r\t\u{0007}"),
            "a\\\"b\\\\c\\n\\r\\t\\u0007"
        );
    }
}
