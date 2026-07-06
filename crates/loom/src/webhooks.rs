use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::config::Config;
use crate::model::{Issue, Pull, Repo, Webhook};
use crate::store::StoreError;
use crate::{random_alnum, AppState};

type HmacSha256 = Hmac<Sha256>;

pub const EVENT_PUSH: &str = "push";
pub const EVENT_PULL_REQUEST: &str = "pull_request";
pub const EVENT_ISSUES: &str = "issues";
pub const EVENT_DEPLOYMENT_READY: &str = "deployment_ready";
pub const EVENT_OPTIONS: [(&str, &str); 3] = [
    (EVENT_PUSH, "Push"),
    (EVENT_PULL_REQUEST, "Pull requests"),
    (EVENT_ISSUES, "Issues"),
];

const DELIVERY_ID_LEN: usize = 16;
const WEBHOOK_TIMEOUT_SECS: u64 = 5;

pub fn validate_webhook_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Webhook URL cannot be empty.".to_string());
    }
    if trimmed.chars().count() > 2048 {
        return Err("Webhook URL is too long.".to_string());
    }
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|_| "Webhook URL must be a valid http:// or https:// URL.".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("Webhook URL must be a valid http:// or https:// URL.".to_string());
    }
    Ok(trimmed.to_string())
}

pub fn normalize_event_csv(raw: &[String]) -> Result<String, String> {
    let mut events = Vec::new();
    for (name, _) in EVENT_OPTIONS {
        if raw.iter().any(|e| e.trim() == name) {
            events.push(name);
        }
    }
    if events.is_empty() {
        return Err("Choose at least one webhook event.".to_string());
    }
    Ok(events.join(","))
}

pub fn webhook_matches_event(webhook: &Webhook, event: &str) -> bool {
    webhook.active
        && webhook
            .events
            .split(',')
            .any(|configured| configured.trim() == event)
}

pub fn emit_push(state: &AppState, repo: &Repo, actor_sub: &str) {
    emit(
        state,
        repo,
        EVENT_PUSH,
        "pushed",
        actor_sub,
        json!({
            "pusher": {
                "subject": actor_sub,
            },
        }),
    );
}

pub fn emit_issue(
    state: &AppState,
    repo: &Repo,
    action: &str,
    actor_sub: &str,
    issue: &Issue,
    labels: &[String],
) {
    emit(
        state,
        repo,
        EVENT_ISSUES,
        action,
        actor_sub,
        issue_extra(issue, &issue.state, labels),
    );
}

pub fn emit_issue_state(
    state: &AppState,
    repo: &Repo,
    action: &str,
    actor_sub: &str,
    issue: &Issue,
    state_name: &str,
    labels: &[String],
) {
    emit(
        state,
        repo,
        EVENT_ISSUES,
        action,
        actor_sub,
        issue_extra(issue, state_name, labels),
    );
}

pub fn emit_pull_request(
    state: &AppState,
    repo: &Repo,
    action: &str,
    actor_sub: &str,
    pull: &Pull,
    state_name: &str,
) {
    emit(
        state,
        repo,
        EVENT_PULL_REQUEST,
        action,
        actor_sub,
        json!({
            "pull_request": {
                "id": pull.id,
                "number": pull.number,
                "title": pull.title,
                "state": state_name,
                "base": pull.base,
                "head": pull.head,
                "author_sub": pull.author_sub,
                "is_draft": pull.is_draft,
            },
        }),
    );
}

pub fn emit_deployment_ready(
    state: &AppState,
    repo: &Repo,
    actor_sub: &str,
    branch: &str,
    preview_url: &str,
    commit_sha: &str,
    pull: i64,
) {
    emit(
        state,
        repo,
        EVENT_DEPLOYMENT_READY,
        "ready",
        actor_sub,
        deployment_ready_extra(branch, preview_url, commit_sha, pull),
    );
}

fn deployment_ready_extra(branch: &str, preview_url: &str, commit_sha: &str, pull: i64) -> Value {
    json!({
        "branch": branch,
        "preview_url": preview_url,
        "commit_sha": commit_sha,
        "pull": pull,
    })
}

fn issue_extra(issue: &Issue, state_name: &str, labels: &[String]) -> Value {
    json!({
        "issue": {
            "id": issue.id,
            "number": issue.number,
            "title": issue.title,
            "state": state_name,
            "author_sub": issue.author_sub,
            "body": issue.body,
            "labels": labels,
        },
    })
}

fn emit(
    state: &AppState,
    repo: &Repo,
    event: &'static str,
    action: &str,
    actor_sub: &str,
    extra: Value,
) {
    let state = state.clone();
    let repo = repo.clone();
    let action = action.to_string();
    let actor_sub = actor_sub.to_string();

    tokio::spawn(async move {
        let targets = delivery_targets(
            state.store.list_webhooks(&repo.id).await,
            state.config.as_ref(),
            &repo,
            event,
        );
        if targets.is_empty() {
            return;
        }

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(WEBHOOK_TIMEOUT_SECS))
            .build()
        {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!(error = %e, repo = repo.id, event, "webhook client build failed");
                return;
            }
        };

        for target in targets {
            let delivery_id = format!("wd_{}", random_alnum(DELIVERY_ID_LEN));
            let payload = delivery_payload(&repo, event, &action, &delivery_id, &actor_sub, &extra);
            let body = match serde_json::to_vec(&payload) {
                Ok(body) => body,
                Err(e) => {
                    tracing::warn!(error = %e, repo = repo.id, event, "webhook payload encode failed");
                    continue;
                }
            };
            let signature = format!("sha256={}", hmac_signature(&target.secret, &body));
            match post_webhook(&client, &target.url, event, &delivery_id, &signature, body).await {
                Ok(status) => tracing::info!(
                    repo = repo.id,
                    webhook = target.id,
                    delivery = delivery_id,
                    event,
                    status,
                    "webhook delivered"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    repo = repo.id,
                    webhook = target.id,
                    delivery = delivery_id,
                    event,
                    "webhook delivery failed"
                ),
            }
        }
    });
}

struct DeliveryTarget {
    id: String,
    url: String,
    secret: String,
}

fn delivery_targets(
    webhooks: Result<Vec<Webhook>, StoreError>,
    config: &Config,
    repo: &Repo,
    event: &'static str,
) -> Vec<DeliveryTarget> {
    let webhooks = webhooks.unwrap_or_else(|e| {
        tracing::warn!(error = %e, repo = repo.id, event, "webhook lookup failed");
        Vec::new()
    });
    let mut targets: Vec<DeliveryTarget> = webhooks
        .into_iter()
        .filter(|webhook| webhook_matches_event(webhook, event))
        .map(DeliveryTarget::from)
        .collect();
    if let Some(target) = estate_delivery_target(config, repo, event) {
        targets.push(target);
    }
    targets
}

fn estate_delivery_target(
    config: &Config,
    repo: &Repo,
    event: &'static str,
) -> Option<DeliveryTarget> {
    let url = config
        .estate_webhook_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())?;
    let Some(secret) = config
        .estate_webhook_secret
        .as_deref()
        .map(str::trim)
        .filter(|secret| !secret.is_empty())
    else {
        tracing::warn!(
            repo = repo.id,
            event,
            "ESTATE_WEBHOOK_URL set without ESTATE_WEBHOOK_SECRET; estate deliveries disabled"
        );
        return None;
    };
    Some(DeliveryTarget {
        id: "estate".to_string(),
        url: url.to_string(),
        secret: secret.to_string(),
    })
}

impl From<Webhook> for DeliveryTarget {
    fn from(webhook: Webhook) -> Self {
        Self {
            id: webhook.id,
            url: webhook.url,
            secret: webhook.secret,
        }
    }
}

fn delivery_payload(
    repo: &Repo,
    event: &str,
    action: &str,
    delivery_id: &str,
    actor_sub: &str,
    extra: &Value,
) -> Value {
    let mut payload = Map::new();
    payload.insert("event".to_string(), json!(event));
    payload.insert("action".to_string(), json!(action));
    payload.insert("delivery".to_string(), json!(delivery_id));
    payload.insert("repository".to_string(), repo_summary(repo));
    payload.insert(
        "sender".to_string(),
        json!({
            "subject": actor_sub,
        }),
    );
    if let Value::Object(extra) = extra {
        payload.extend(extra.clone());
    }
    Value::Object(payload)
}

fn repo_summary(repo: &Repo) -> Value {
    json!({
        "id": repo.id,
        "owner": repo.owner_sub,
        "name": repo.name,
        "full_name": format!("{}/{}", repo.owner_sub, repo.name),
        "private": repo.is_private,
        "default_branch": repo.default_branch,
    })
}

async fn post_webhook(
    client: &reqwest::Client,
    url: &str,
    event: &str,
    delivery_id: &str,
    signature: &str,
    body: Vec<u8>,
) -> Result<u16, String> {
    let fut = client
        .post(url)
        .header(USER_AGENT, "Loom-Webhooks/0.1")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Loom-Event", event)
        .header("X-Loom-Delivery", delivery_id)
        .header("X-Loom-Signature", signature)
        .body(body)
        .send();
    let response = tokio::time::timeout(Duration::from_secs(WEBHOOK_TIMEOUT_SECS), fut)
        .await
        .map_err(|_| "webhook delivery timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let status = response.status();
    if status.is_success() {
        Ok(status.as_u16())
    } else {
        Err(format!("webhook endpoint returned {status}"))
    }
}

fn hmac_signature(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key accepts any size");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::gitops::GitOps;
    use crate::store::InMemoryStore;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    struct CapturedRequest {
        headers: String,
        body: Vec<u8>,
    }

    fn webhook(events: &str, active: bool) -> Webhook {
        Webhook {
            id: "wh1".into(),
            repo_id: "r".into(),
            url: "https://example.test/hook".into(),
            secret: "secret".into(),
            events: events.into(),
            active,
            created_at: 1,
        }
    }

    fn sample_repo() -> Repo {
        Repo {
            id: "r".to_string(),
            owner_sub: "alice".to_string(),
            name: "site".to_string(),
            description: String::new(),
            is_private: false,
            default_branch: "main".to_string(),
            require_approval: false,
            required_approvals: 0,
            require_code_owner_reviews: false,
            protect_default_branch: false,
            forked_from_id: String::new(),
            created_at: 0,
        }
    }

    fn sample_issue() -> Issue {
        Issue {
            id: "iss_1".to_string(),
            repo_id: "r".to_string(),
            number: 7,
            title: "Send to agent".to_string(),
            body: "Please handle this.".to_string(),
            author_sub: "alice".to_string(),
            assignee_sub: String::new(),
            milestone_id: String::new(),
            state: "open".to_string(),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn sample_state(config: Config) -> AppState {
        let config = Arc::new(config);
        AppState {
            config: config.clone(),
            store: Arc::new(InMemoryStore::new()),
            git: GitOps::new(config.as_ref()),
            klaxon: None,
        }
    }

    async fn capture_one_request() -> (String, JoinHandle<CapturedRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test webhook listener");
        let url = format!("http://{}", listener.local_addr().expect("listener addr"));
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept webhook request");
            let mut buffer = Vec::new();
            let header_end = loop {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).await.expect("read webhook request");
                assert!(n > 0, "connection closed before headers");
                buffer.extend_from_slice(&chunk[..n]);
                if let Some(header_end) = find_header_end(&buffer) {
                    break header_end;
                }
            };
            let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
            let content_len = header_value(&headers, "content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            while buffer.len() < header_end + content_len {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).await.expect("read webhook body");
                assert!(n > 0, "connection closed before body");
                buffer.extend_from_slice(&chunk[..n]);
            }
            let body = buffer[header_end..header_end + content_len].to_vec();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("write webhook response");
            CapturedRequest { headers, body }
        });
        (url, handle)
    }

    fn find_header_end(buffer: &[u8]) -> Option<usize> {
        buffer
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|pos| pos + 4)
    }

    fn header_value(headers: &str, name: &str) -> Option<String> {
        headers.lines().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    #[test]
    fn validates_http_and_https_urls() {
        assert!(validate_webhook_url("https://example.test/hook").is_ok());
        assert!(validate_webhook_url("http://example.test/hook").is_ok());
        assert!(validate_webhook_url("ftp://example.test/hook").is_err());
        assert!(validate_webhook_url("https://").is_err());
    }

    #[test]
    fn normalizes_known_events_in_fixed_order() {
        let events = normalize_event_csv(&[
            "issues".to_string(),
            "bogus".to_string(),
            "push".to_string(),
        ])
        .unwrap();
        assert_eq!(events, "push,issues");
        assert!(normalize_event_csv(&["bogus".to_string()]).is_err());
    }

    #[test]
    fn matches_only_active_configured_events() {
        assert!(webhook_matches_event(
            &webhook("push,issues", true),
            "issues"
        ));
        assert!(!webhook_matches_event(
            &webhook("pull_request", true),
            "issues"
        ));
        assert!(!webhook_matches_event(&webhook("issues", false), "issues"));
    }

    #[test]
    fn signs_body_with_hmac_sha256() {
        assert_eq!(
            hmac_signature("key", b"The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn deployment_ready_payload_shape_matches_bridge_contract() {
        let repo = sample_repo();
        let extra = deployment_ready_extra(
            "agent/coder/550e8400-e29b-41d4-a716-446655440000",
            "https://preview.siteflow.test",
            "deadbeefcafebabe",
            42,
        );
        let payload = delivery_payload(
            &repo,
            EVENT_DEPLOYMENT_READY,
            "ready",
            "wd_test",
            "alice",
            &extra,
        );

        assert_eq!(
            payload.get("event").and_then(Value::as_str),
            Some(EVENT_DEPLOYMENT_READY)
        );
        assert_eq!(payload.get("action").and_then(Value::as_str), Some("ready"));
        assert_eq!(
            payload.get("branch").and_then(Value::as_str),
            Some("agent/coder/550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(
            payload.get("preview_url").and_then(Value::as_str),
            Some("https://preview.siteflow.test")
        );
        assert_eq!(
            payload.get("commit_sha").and_then(Value::as_str),
            Some("deadbeefcafebabe")
        );
        assert_eq!(payload.get("pull").and_then(Value::as_i64), Some(42));
        assert_eq!(
            payload
                .get("repository")
                .and_then(|repo| repo.get("full_name"))
                .and_then(Value::as_str),
            Some("alice/site")
        );
        assert_eq!(
            payload
                .get("sender")
                .and_then(|sender| sender.get("subject"))
                .and_then(Value::as_str),
            Some("alice")
        );
    }

    #[test]
    fn issue_payload_includes_body_and_label_names() {
        let repo = sample_repo();
        let issue = sample_issue();
        let labels = vec!["agent".to_string(), "needs-review".to_string()];
        let extra = issue_extra(&issue, &issue.state, &labels);
        let payload = delivery_payload(&repo, EVENT_ISSUES, "opened", "wd_test", "alice", &extra);
        let issue_payload = payload
            .get("issue")
            .and_then(Value::as_object)
            .expect("issue payload");

        assert_eq!(
            issue_payload.get("body").and_then(Value::as_str),
            Some("Please handle this.")
        );
        assert_eq!(
            issue_payload
                .get("labels")
                .and_then(Value::as_array)
                .map(|labels| labels.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
            Some(vec!["agent", "needs-review"])
        );
    }

    #[test]
    fn estate_target_requires_nonempty_secret() {
        let repo = sample_repo();
        let mut config = Config::dev();
        config.estate_webhook_url = Some("https://bridge.test/hooks/loom".to_string());

        assert!(estate_delivery_target(&config, &repo, EVENT_ISSUES).is_none());
        config.estate_webhook_secret = Some("   ".to_string());
        assert!(estate_delivery_target(&config, &repo, EVENT_ISSUES).is_none());
        config.estate_webhook_secret = Some("estate-secret".to_string());

        let target = estate_delivery_target(&config, &repo, EVENT_ISSUES).expect("estate target");
        assert_eq!(target.id, "estate");
        assert_eq!(target.url, "https://bridge.test/hooks/loom");
        assert_eq!(target.secret, "estate-secret");
    }

    #[test]
    fn estate_target_survives_per_repo_lookup_error() {
        let repo = sample_repo();
        let mut config = Config::dev();
        config.estate_webhook_url = Some("https://bridge.test/hooks/loom".to_string());
        config.estate_webhook_secret = Some("estate-secret".to_string());

        let targets = delivery_targets(
            Err(StoreError::Backend("boom".to_string())),
            &config,
            &repo,
            EVENT_ISSUES,
        );

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, "estate");
        assert_eq!(targets[0].secret, "estate-secret");
    }

    #[tokio::test]
    async fn global_sink_delivery_fires_without_per_repo_webhooks() {
        let (url, handle) = capture_one_request().await;
        let mut config = Config::dev();
        config.estate_webhook_url = Some(url);
        config.estate_webhook_secret = Some("estate-secret".to_string());
        let state = sample_state(config);
        let repo = sample_repo();
        let issue = sample_issue();
        let labels = vec!["agent".to_string(), "needs-review".to_string()];

        emit_issue(&state, &repo, "opened", "alice", &issue, &labels);

        let captured = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("global sink did not receive delivery")
            .expect("capture task failed");
        let payload: Value = serde_json::from_slice(&captured.body).expect("webhook JSON body");
        assert_eq!(
            payload.get("event").and_then(Value::as_str),
            Some(EVENT_ISSUES)
        );
        assert_eq!(
            payload.get("action").and_then(Value::as_str),
            Some("opened")
        );
        assert_eq!(
            payload
                .get("issue")
                .and_then(|issue| issue.get("id"))
                .and_then(Value::as_str),
            Some("iss_1")
        );
        assert_eq!(
            payload
                .get("issue")
                .and_then(|issue| issue.get("body"))
                .and_then(Value::as_str),
            Some("Please handle this.")
        );
        assert_eq!(
            payload
                .get("issue")
                .and_then(|issue| issue.get("labels"))
                .and_then(Value::as_array)
                .map(|labels| labels.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
            Some(vec!["agent", "needs-review"])
        );
        assert_eq!(
            header_value(&captured.headers, "x-loom-event").as_deref(),
            Some(EVENT_ISSUES)
        );
        assert!(header_value(&captured.headers, "x-loom-delivery")
            .as_deref()
            .is_some_and(|delivery| delivery.starts_with("wd_")));
        let expected_signature =
            format!("sha256={}", hmac_signature("estate-secret", &captured.body));
        assert_eq!(
            header_value(&captured.headers, "x-loom-signature").as_deref(),
            Some(expected_signature.as_str())
        );
    }
}
