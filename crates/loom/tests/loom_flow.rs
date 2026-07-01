//! End-to-end flow tests against the in-memory store (NO database required).
//!
//! Drives the real `Router` in-process via `tower::oneshot`. These exercise the SSO web surface
//! (repo create, issues, PATs) AND the git smart-HTTP surface (the `git http-backend` CGI +
//! PAT/Basic auth policy). They DO shell out to the installed `git` (Loom is a git forge), so the
//! host needs `git` + `git-http-backend` on PATH — true on the build/CI host.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use loom::auth::{hash_token, new_pat_secret};
use loom::model::Pat;
use loom::store::Store;
use loom::{app, build_dev_state_at, now_secs, AppState};
use tower::ServiceExt;

fn temp_state() -> AppState {
    let dir = std::env::temp_dir().join(format!("loom-test-{}", loom::random_alnum(10)));
    build_dev_state_at(dir.to_string_lossy())
}

/// Percent-encode a form value (encode everything that is not an unreserved character).
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
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
        raw: bytes.to_vec(),
    }
}

fn get(path: &str, subject: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(s) = subject {
        b = b
            .header("x-auth-subject", s)
            .header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::empty()).unwrap()
}

fn get_basic(path: &str, password: &str) -> Request<Body> {
    use base64::Engine;
    let cred = base64::engine::general_purpose::STANDARD.encode(format!("git:{password}"));
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Basic {cred}"))
        .body(Body::empty())
        .unwrap()
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
    if let Some(s) = subject {
        b = b
            .header("x-auth-subject", s)
            .header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::from(body)).unwrap()
}

/// Create a repo through the web flow; returns nothing (assertions inline).
async fn create_repo(app: &axum::Router, subject: &str, name: &str, visibility: &str) {
    let page = send(app, get("/", Some(subject))).await;
    let csrf = page.csrf_cookie().expect("csrf on GET /");
    let created = send(
        app,
        post_form(
            "/new",
            &[
                ("csrf_token", &csrf),
                ("name", name),
                ("description", "test repo <x>"),
                ("default_branch", "main"),
                ("visibility", visibility),
            ],
            &csrf,
            Some(subject),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND, "repo create should 302");
    assert_eq!(created.location(), format!("/r/{subject}/{name}"));
}

#[tokio::test]
async fn web_create_repo_issues_and_xss_escaping() {
    let app = app(temp_state());

    create_repo(&app, "alice", "proj", "").await;

    // Repo page: empty repo quick-start + clone URL + escaped description.
    let view = send(&app, get("/r/alice/proj", Some("alice"))).await;
    assert_eq!(view.status, StatusCode::OK);
    assert!(view.body.contains("/git/alice/proj.git"));
    assert!(view.body.contains("Quick start"));
    // The description's "<x>" must be escaped, never raw.
    assert!(!view.body.contains("test repo <x>"));
    assert!(view.body.contains("test repo &lt;x&gt;"));

    // Duplicate name is rejected with an inline error (400).
    let page = send(&app, get("/", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();
    let dup = send(
        &app,
        post_form(
            "/new",
            &[("csrf_token", &csrf), ("name", "proj"), ("default_branch", "main")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(dup.status, StatusCode::BAD_REQUEST);
    assert!(dup.body.contains("already have a repository"));

    // --- issues -----------------------------------------------------------
    let issues_page = send(&app, get("/r/alice/proj/issues", Some("alice"))).await;
    let csrf = issues_page.csrf_cookie().unwrap();
    let opened = send(
        &app,
        post_form(
            "/r/alice/proj/issues",
            &[
                ("csrf_token", &csrf),
                ("title", "Bug: <script>alert(1)</script>"),
                ("body", "steps to repro"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(opened.status, StatusCode::FOUND);

    let list = send(&app, get("/r/alice/proj/issues", Some("alice"))).await;
    assert!(list.body.contains("#1"));
    assert!(list.body.contains("Open"));
    // Script payload is escaped, not live.
    assert!(!list.body.contains("<script>alert(1)</script>"));
    assert!(list.body.contains("&lt;script&gt;"));

    // Toggle the issue closed (author is allowed).
    let csrf = list.csrf_cookie().unwrap();
    let toggled = send(
        &app,
        post_form(
            "/r/alice/proj/issues/1/toggle",
            &[("csrf_token", &csrf)],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(toggled.status, StatusCode::FOUND);
    let after = send(&app, get("/r/alice/proj/issues", Some("alice"))).await;
    assert!(after.body.contains("Closed"));
}

/// Run `git --git-dir=<dir> <args>` feeding `stdin`, asserting success; returns trimmed stdout.
fn git_capture(git_dir: &str, args: &[&str], stdin: &str) -> String {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(args)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "safe.directory")
        .env("GIT_CONFIG_VALUE_0", "*")
        .env("GIT_AUTHOR_NAME", "Seed")
        .env("GIT_AUTHOR_EMAIL", "seed@w33d.xyz")
        .env("GIT_COMMITTER_NAME", "Seed")
        .env("GIT_COMMITTER_EMAIL", "seed@w33d.xyz")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Seed a single flat commit (root-level files only) onto `branch` of a bare repo via plumbing.
fn seed_repo(git_dir: &str, branch: &str, files: &[(&str, &str)]) {
    let mut tree = String::new();
    for (name, content) in files {
        let oid = git_capture(git_dir, &["hash-object", "-w", "--stdin"], content);
        tree.push_str(&format!("100644 blob {oid}\t{name}\n"));
    }
    let tree_oid = git_capture(git_dir, &["mktree"], &tree);
    let commit = git_capture(git_dir, &["commit-tree", &tree_oid, "-m", "seed"], "");
    git_capture(git_dir, &["update-ref", &format!("refs/heads/{branch}"), &commit], "");
}

#[tokio::test]
async fn readme_renders_markdown_and_blob_is_line_numbered() {
    let state = temp_state();
    let git = state.git.clone();
    let app = app(state);
    create_repo(&app, "alice", "docs", "").await;

    let git_dir = git.repo_path("alice", "docs").to_string_lossy().to_string();
    seed_repo(
        &git_dir,
        "main",
        &[
            (
                "README.md",
                "# Hello\n\nSome **bold** text.\n\n<script>alert(1)</script>\n",
            ),
            ("main.rs", "fn main() {\n    println!(\"hi\");\n}\n"),
        ],
    );

    // Repo page renders the README as sanitised HTML (heading + emphasis are live markup).
    let view = send(&app, get("/r/alice/docs", Some("alice"))).await;
    assert_eq!(view.status, StatusCode::OK);
    assert!(view.body.contains("<h1>Hello</h1>"), "README heading rendered");
    assert!(view.body.contains("<strong>bold</strong>"));
    // The raw <script> in the README must be neutralised, not served as live markup.
    assert!(!view.body.contains("<script>alert(1)</script>"));
    assert!(view.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));

    // A non-markdown blob renders as a line-numbered, escaped monospace table.
    let blob = send(&app, get("/r/alice/docs/blob/main.rs", Some("alice"))).await;
    assert_eq!(blob.status, StatusCode::OK);
    assert!(blob.body.contains("blob-line__num"), "line-number gutter present");
    assert!(blob.body.contains("println!"));

    // A markdown blob view renders as sanitised HTML too.
    let md = send(&app, get("/r/alice/docs/blob/README.md", Some("alice"))).await;
    assert_eq!(md.status, StatusCode::OK);
    assert!(md.body.contains("<h1>Hello</h1>"));
    assert!(!md.body.contains("<script>alert(1)</script>"));
}

#[tokio::test]
async fn private_repo_hidden_from_other_users() {
    let app = app(temp_state());
    create_repo(&app, "alice", "secret", "private").await;

    // The owner sees it.
    let owner = send(&app, get("/r/alice/secret", Some("alice"))).await;
    assert_eq!(owner.status, StatusCode::OK);

    // A different signed-in user gets 404 (existence does not leak).
    let intruder = send(&app, get("/r/alice/secret", Some("bob"))).await;
    assert_eq!(intruder.status, StatusCode::NOT_FOUND);

    // And it does not appear in bob's repo list.
    let bob_home = send(&app, get("/", Some("bob"))).await;
    assert!(!bob_home.body.contains("alice/secret"));
}

#[tokio::test]
async fn csrf_required_on_repo_create() {
    let app = app(temp_state());
    let bad = send(
        &app,
        post_form(
            "/new",
            &[("csrf_token", "wrong"), ("name", "x"), ("default_branch", "main")],
            "the-cookie",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pat_mint_shows_secret_once() {
    let app = app(temp_state());
    let page = send(&app, get("/pats", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();
    let minted = send(
        &app,
        post_form(
            "/pats",
            &[("csrf_token", &csrf), ("name", "laptop")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(minted.status, StatusCode::OK);
    // The one-time reveal shows a token with the loom_pat_ prefix.
    assert!(minted.body.contains("loom_pat_"));
    assert!(minted.body.contains("will not be shown again"));

    // Reloading the page never re-shows the secret.
    let reload = send(&app, get("/pats", Some("alice"))).await;
    assert!(!reload.body.contains("loom_pat_"));
    assert!(reload.body.contains("laptop"));
}

// ===========================================================================
// git smart-HTTP: advertisement + PAT auth policy
// ===========================================================================

#[tokio::test]
async fn smart_http_public_fetch_is_anonymous_push_requires_pat() {
    let app = app(temp_state());
    create_repo(&app, "alice", "pub", "").await;

    // Anonymous upload-pack (fetch) advertisement on a PUBLIC repo -> 200.
    let adv = send(
        &app,
        get("/git/alice/pub.git/info/refs?service=git-upload-pack", None),
    )
    .await;
    assert_eq!(adv.status, StatusCode::OK, "anon clone of public repo");
    assert!(adv.content_type().contains("git-upload-pack-advertisement"));
    assert!(
        String::from_utf8_lossy(&adv.raw).contains("service=git-upload-pack"),
        "advertisement body present"
    );

    // Anonymous receive-pack (push) advertisement -> 401 (push always needs a PAT).
    let push_anon = send(
        &app,
        get("/git/alice/pub.git/info/refs?service=git-receive-pack", None),
    )
    .await;
    assert_eq!(push_anon.status, StatusCode::UNAUTHORIZED);
    assert!(push_anon.headers.contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn smart_http_private_and_pat_authorization() {
    let state = temp_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);

    create_repo(&app, "alice", "sec", "private").await;

    // No creds -> 401.
    let anon = send(
        &app,
        get("/git/alice/sec.git/info/refs?service=git-upload-pack", None),
    )
    .await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);

    // Mint a PAT for alice directly in the store (hash only) and use it.
    let secret = new_pat_secret();
    store
        .create_pat(&Pat {
            id: "pt_test".into(),
            owner_sub: "alice".into(),
            name: "ci".into(),
            token_hash: hash_token(&secret),
            created_at: now_secs(),
        })
        .await
        .unwrap();

    let ok = send(
        &app,
        get_basic(
            "/git/alice/sec.git/info/refs?service=git-upload-pack",
            &secret,
        ),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "alice's PAT clones her private repo");

    // A PAT owned by someone else cannot reach alice's repo -> 403.
    let bob_secret = new_pat_secret();
    store
        .create_pat(&Pat {
            id: "pt_bob".into(),
            owner_sub: "bob".into(),
            name: "bob-ci".into(),
            token_hash: hash_token(&bob_secret),
            created_at: now_secs(),
        })
        .await
        .unwrap();
    let forbidden = send(
        &app,
        get_basic(
            "/git/alice/sec.git/info/refs?service=git-upload-pack",
            &bob_secret,
        ),
    )
    .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);

    // A bogus token -> 401.
    let bogus = send(
        &app,
        get_basic("/git/alice/sec.git/info/refs?service=git-upload-pack", "nope"),
    )
    .await;
    assert_eq!(bogus.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn smart_http_unknown_repo_is_404() {
    let app = app(temp_state());
    let missing = send(
        &app,
        get("/git/ghost/none.git/info/refs?service=git-upload-pack", None),
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}
