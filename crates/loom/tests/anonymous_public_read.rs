//! Production-mode anonymous public read contract.

use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{header, request::Builder, HeaderMap, Request, StatusCode};
use hmac::{Hmac, Mac};
use loom::auth::{self, ANON_SUBJECT, DEV_SUBJECT};
use loom::{app, build_dev_state_at, AppState};
use sha2::Sha256;
use tower::ServiceExt;

const TEST_GATEWAY_KEY: &str = "anonymous-public-read-test-key";
static INIT_GATEWAY: Once = Once::new();

fn init_prod_gateway() {
    INIT_GATEWAY.call_once(|| {
        std::env::set_var("GATEWAY_HMAC_KEY", TEST_GATEWAY_KEY);
    });
}

fn temp_state() -> AppState {
    init_prod_gateway();
    let dir = std::env::temp_dir().join(format!("loom-anon-test-{}", loom::random_alnum(10)));
    build_dev_state_at(dir.to_string_lossy())
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn now_window() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
        / 60
}

fn sign_identity(subject: &str, groups: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(TEST_GATEWAY_KEY.as_bytes())
        .expect("HMAC accepts any key len");
    mac.update(subject.as_bytes());
    mac.update(b"\n");
    mac.update(groups.as_bytes());
    mac.update(b"\n");
    mac.update(now_window().to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn with_auth(builder: Builder, subject: &str) -> Builder {
    builder
        .header(auth::HEADER_SUBJECT, subject)
        .header(auth::HEADER_EMAIL, format!("{subject}@w33d.xyz"))
        .header(auth::HEADER_SIG, sign_identity(subject, ""))
}

fn get(path: &str, subject: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(subject) = subject {
        b = with_auth(b, subject);
    }
    b.body(Body::empty()).unwrap()
}

fn post_empty(path: &str, subject: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("POST").uri(path);
    if let Some(subject) = subject {
        b = with_auth(b, subject);
    }
    b.body(Body::empty()).unwrap()
}

fn post_form(
    path: &str,
    fields: &[(&str, &str)],
    cookie: &str,
    subject: Option<&str>,
) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={cookie}"));
    if let Some(subject) = subject {
        b = with_auth(b, subject);
    }
    b.body(Body::from(body)).unwrap()
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
    raw: Vec<u8>,
}

impl Resp {
    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    fn csrf_cookie(&self) -> Option<String> {
        for hv in self.headers.get_all(header::SET_COOKIE).iter() {
            let raw = hv.to_str().ok()?;
            if let Some(rest) = raw.strip_prefix("__Host-csrf=") {
                return Some(rest.split(';').next().unwrap_or("").to_string());
            }
        }
        None
    }

    fn content_type(&self) -> String {
        self.headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
}

async fn send(app: &axum::Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
        raw: bytes.to_vec(),
    }
}

async fn create_repo(app: &axum::Router, subject: &str, name: &str, visibility: &str) {
    let page = send(app, get("/new", Some(subject))).await;
    assert_eq!(page.status, StatusCode::OK);
    let csrf = page.csrf_cookie().expect("csrf on GET /new");
    let created = send(
        app,
        post_form(
            "/new",
            &[
                ("csrf_token", &csrf),
                ("name", name),
                ("description", "anonymous contract fixture"),
                ("default_branch", "main"),
                ("visibility", visibility),
            ],
            &csrf,
            Some(subject),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND);
    assert_eq!(created.location(), format!("/r/{subject}/{name}"));
}

fn assert_signin_redirect(res: &Resp, return_to: &str) {
    assert_eq!(res.status, StatusCode::FOUND);
    assert_eq!(res.location(), format!("/signin?return={}", enc(return_to)));
}

#[test]
fn production_identity_without_headers_is_anonymous() {
    init_prod_gateway();

    let anon = auth::identity(&HeaderMap::new());
    assert_eq!(anon.subject, ANON_SUBJECT);
    assert_eq!(anon.email, "");
    assert!(!anon.is_authenticated());
    assert_ne!(anon.subject, DEV_SUBJECT);

    let mut headers = HeaderMap::new();
    headers.insert(auth::HEADER_SUBJECT, "alice".parse().unwrap());
    headers.insert(auth::HEADER_EMAIL, "alice@w33d.xyz".parse().unwrap());
    headers.insert(
        auth::HEADER_SIG,
        sign_identity("alice", "").parse().unwrap(),
    );
    assert!(auth::gateway_identity_ok(&headers));
    let alice = auth::identity(&headers);
    assert_eq!(alice.subject, "alice");
    assert!(alice.is_authenticated());
}

#[tokio::test]
async fn anonymous_reads_public_repos_and_private_repos_404() {
    let state = temp_state();
    let app = app(state);
    create_repo(&app, "alice", "pub", "").await;
    create_repo(&app, "alice", "secret", "private").await;

    let home = send(&app, get("/", None)).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.body.contains(r#"href="/r/alice/pub""#));
    assert!(!home.body.contains("alice/secret"));
    assert!(home
        .body
        .contains(r#"<a class="btn" href="/signin">Sign in</a>"#));
    assert!(!home.body.contains(r#"<div class="usermenu">"#));
    assert!(!home.body.contains(r#"<details class="create-menu">"#));
    assert!(!home.body.contains(r#"href="/pats""#));

    let public_repo = send(&app, get("/r/alice/pub", None)).await;
    assert_eq!(public_repo.status, StatusCode::OK);
    assert!(public_repo.body.contains("/git/alice/pub.git"));

    let private_repo = send(&app, get("/r/alice/secret", None)).await;
    assert_eq!(private_repo.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn anonymous_write_and_auth_only_pages_redirect_to_signin() {
    let state = temp_state();
    let store = state.store.clone();
    let app = app(state);
    create_repo(&app, "alice", "pub", "").await;

    let get_new = send(&app, get("/new", None)).await;
    assert_signin_redirect(&get_new, "/new");

    let post_new = send(&app, post_empty("/new", None)).await;
    assert_signin_redirect(&post_new, "/new");
    assert!(store.get_repo("", "anon").await.unwrap().is_none());

    let get_pats = send(&app, get("/pats", None)).await;
    assert_signin_redirect(&get_pats, "/pats");

    let issue_create = send(&app, post_empty("/r/alice/pub/issues", None)).await;
    assert_signin_redirect(&issue_create, "/r/alice/pub/issues");

    let issue_comment = send(&app, post_empty("/r/alice/pub/issues/1/comment", None)).await;
    assert_signin_redirect(&issue_comment, "/r/alice/pub/issues/1/comment");

    let settings_get = send(&app, get("/r/alice/pub/settings", None)).await;
    assert_signin_redirect(&settings_get, "/r/alice/pub/settings");

    let settings_post = send(&app, post_empty("/r/alice/pub/settings", None)).await;
    assert_signin_redirect(&settings_post, "/r/alice/pub/settings");
}

#[tokio::test]
async fn git_smart_http_is_not_sso_gated() {
    let app = app(temp_state());
    create_repo(&app, "alice", "pub", "").await;

    let fetch = send(
        &app,
        get("/git/alice/pub.git/info/refs?service=git-upload-pack", None),
    )
    .await;
    assert_eq!(fetch.status, StatusCode::OK);
    assert!(fetch
        .content_type()
        .contains("git-upload-pack-advertisement"));
    assert!(String::from_utf8_lossy(&fetch.raw).contains("service=git-upload-pack"));

    let push = send(
        &app,
        get(
            "/git/alice/pub.git/info/refs?service=git-receive-pack",
            None,
        ),
    )
    .await;
    assert_eq!(push.status, StatusCode::UNAUTHORIZED);
    assert!(!push.location().starts_with("/signin"));
}

#[tokio::test]
async fn signin_return_is_not_an_open_redirect() {
    let app = app(temp_state());

    let good = send(&app, get("/signin?return=/r/w33d/x", None)).await;
    assert_eq!(good.status, StatusCode::FOUND);
    assert_eq!(good.location(), "/r/w33d/x");

    let absolute = send(&app, get("/signin?return=https://evil.test", None)).await;
    assert_eq!(absolute.status, StatusCode::FOUND);
    assert_eq!(absolute.location(), "/");

    let protocol_relative = send(&app, get("/signin?return=//evil.test", None)).await;
    assert_eq!(protocol_relative.status, StatusCode::FOUND);
    assert_eq!(protocol_relative.location(), "/");
}

#[tokio::test]
async fn authenticated_signed_repo_create_is_unchanged() {
    let state = temp_state();
    let store = state.store.clone();
    let app = app(state);

    create_repo(&app, "alice", "signed", "").await;

    let repo = store
        .get_repo("alice", "signed")
        .await
        .unwrap()
        .expect("authenticated signed create persisted repo");
    assert_eq!(repo.owner_sub, "alice");
    assert!(!repo.is_private);
}
