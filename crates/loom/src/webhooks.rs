use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::model::{Issue, Pull, Repo, Webhook};
use crate::{random_alnum, AppState};

type HmacSha256 = Hmac<Sha256>;

pub const EVENT_PUSH: &str = "push";
pub const EVENT_PULL_REQUEST: &str = "pull_request";
pub const EVENT_ISSUES: &str = "issues";
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

pub fn emit_issue(state: &AppState, repo: &Repo, action: &str, actor_sub: &str, issue: &Issue) {
    emit(
        state,
        repo,
        EVENT_ISSUES,
        action,
        actor_sub,
        json!({
            "issue": {
                "id": issue.id,
                "number": issue.number,
                "title": issue.title,
                "state": issue.state,
                "author_sub": issue.author_sub,
            },
        }),
    );
}

pub fn emit_issue_state(
    state: &AppState,
    repo: &Repo,
    action: &str,
    actor_sub: &str,
    issue: &Issue,
    state_name: &str,
) {
    emit(
        state,
        repo,
        EVENT_ISSUES,
        action,
        actor_sub,
        json!({
            "issue": {
                "id": issue.id,
                "number": issue.number,
                "title": issue.title,
                "state": state_name,
                "author_sub": issue.author_sub,
            },
        }),
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
        let webhooks = match state.store.list_webhooks(&repo.id).await {
            Ok(webhooks) => webhooks,
            Err(e) => {
                tracing::warn!(error = %e, repo = repo.id, event, "webhook lookup failed");
                return;
            }
        };
        let matching: Vec<Webhook> = webhooks
            .into_iter()
            .filter(|webhook| webhook_matches_event(webhook, event))
            .collect();
        if matching.is_empty() {
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

        for webhook in matching {
            let delivery_id = format!("wd_{}", random_alnum(DELIVERY_ID_LEN));
            let payload = delivery_payload(&repo, event, &action, &delivery_id, &actor_sub, &extra);
            let body = match serde_json::to_vec(&payload) {
                Ok(body) => body,
                Err(e) => {
                    tracing::warn!(error = %e, repo = repo.id, event, "webhook payload encode failed");
                    continue;
                }
            };
            let signature = format!("sha256={}", hmac_signature(&webhook.secret, &body));
            match post_webhook(&client, &webhook, event, &delivery_id, &signature, body).await {
                Ok(status) => tracing::info!(
                    repo = repo.id,
                    webhook = webhook.id,
                    delivery = delivery_id,
                    event,
                    status,
                    "webhook delivered"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    repo = repo.id,
                    webhook = webhook.id,
                    delivery = delivery_id,
                    event,
                    "webhook delivery failed"
                ),
            }
        }
    });
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
    webhook: &Webhook,
    event: &str,
    delivery_id: &str,
    signature: &str,
    body: Vec<u8>,
) -> Result<u16, String> {
    let fut = client
        .post(&webhook.url)
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
}
