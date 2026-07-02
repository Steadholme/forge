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

fn post_basic(path: &str, password: &str, body: &str) -> Request<Body> {
    use base64::Engine;
    let cred = base64::engine::general_purpose::STANDARD.encode(format!("git:{password}"));
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Basic {cred}"))
        .header(
            header::CONTENT_TYPE,
            "application/x-git-receive-pack-request",
        )
        .body(Body::from(body.to_string()))
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

/// Like [`post_form`], but also injects an `X-Auth-Groups` header (for admin-gate tests).
fn post_form_groups(
    path: &str,
    fields: &[(&str, &str)],
    cookie: &str,
    subject: &str,
    groups: &str,
) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={cookie}"))
        .header("x-auth-subject", subject)
        .header("x-auth-email", format!("{subject}@w33d.xyz"))
        .header("x-auth-groups", groups)
        .body(Body::from(body))
        .unwrap()
}

fn post_json(path: &str, body: &str, bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// Open an issue through the web flow as `subject`; returns the new issue's detail location.
async fn open_issue(
    app: &axum::Router,
    subject: &str,
    repo: &str,
    title: &str,
    body: &str,
) -> String {
    let page = send(app, get(&format!("/r/{repo}/issues"), Some(subject))).await;
    let csrf = page.csrf_cookie().expect("csrf on issues page");
    let created = send(
        app,
        post_form(
            &format!("/r/{repo}/issues"),
            &[("csrf_token", &csrf), ("title", title), ("body", body)],
            &csrf,
            Some(subject),
        ),
    )
    .await;
    assert_eq!(
        created.status,
        StatusCode::FOUND,
        "issue create should 302 to detail"
    );
    created.location()
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
            &[
                ("csrf_token", &csrf),
                ("name", "proj"),
                ("default_branch", "main"),
            ],
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

#[tokio::test]
async fn issue_detail_comments_filter_and_admin_gate() {
    let app = app(temp_state());
    create_repo(&app, "alice", "proj", "").await;

    // bob (not the repo owner) opens an issue with a markdown body.
    let loc = open_issue(&app, "bob", "alice/proj", "First bug", "**bold** body").await;
    assert_eq!(loc, "/r/alice/proj/issues/1");

    // Detail page: markdown body rendered, and the author (bob) sees the Close button.
    let detail = send(&app, get(&loc, Some("bob"))).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.body.contains("#1"));
    assert!(
        detail.body.contains("<strong>bold</strong>"),
        "issue body markdown rendered"
    );
    assert!(detail.body.contains("Add a comment"));
    assert!(
        detail.body.contains("Close issue"),
        "author sees the close action"
    );

    // carol (neither owner nor author, not admin) sees NO close button on the detail page.
    let carol_view = send(&app, get(&loc, Some("carol"))).await;
    assert!(
        !carol_view.body.contains("Close issue"),
        "non-moderator has no close action"
    );
    assert!(
        carol_view.body.contains("Add a comment"),
        "any signed-in user can comment"
    );
    let carol_csrf = carol_view.csrf_cookie().expect("csrf on detail");

    // carol adds a comment with a markdown + XSS payload; markup is rendered, script is escaped.
    let commented = send(
        &app,
        post_form(
            "/r/alice/proj/issues/1/comment",
            &[
                ("csrf_token", &carol_csrf),
                ("body", "_italic_ <script>alert(1)</script>"),
            ],
            &carol_csrf,
            Some("carol"),
        ),
    )
    .await;
    assert_eq!(commented.status, StatusCode::FOUND);
    assert_eq!(commented.location(), "/r/alice/proj/issues/1");

    let with_comment = send(&app, get(&loc, Some("bob"))).await;
    assert!(
        with_comment.body.contains("<em>italic</em>"),
        "comment markdown rendered"
    );
    assert!(
        !with_comment.body.contains("<script>alert(1)</script>"),
        "script escaped"
    );
    assert!(with_comment.body.contains("&lt;script&gt;"));
    assert!(with_comment.body.contains("carol"), "comment author shown");

    // CSRF is required on comment.
    let no_csrf = send(
        &app,
        post_form(
            "/r/alice/proj/issues/1/comment",
            &[("csrf_token", "wrong"), ("body", "nope")],
            "the-cookie",
            Some("carol"),
        ),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::BAD_REQUEST);

    // Empty comment is rejected inline (400), not stored.
    let empty = send(
        &app,
        post_form(
            "/r/alice/proj/issues/1/comment",
            &[("csrf_token", &carol_csrf), ("body", "   ")],
            &carol_csrf,
            Some("carol"),
        ),
    )
    .await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST);
    assert!(empty.body.contains("Comment cannot be empty."));

    // Second issue, then exercise the open/closed filter.
    open_issue(&app, "bob", "alice/proj", "Second bug", "").await;
    // Close issue #1 (bob is the author).
    let close1 = send(
        &app,
        post_form(
            "/r/alice/proj/issues/1/toggle",
            &[("csrf_token", &carol_csrf)],
            &carol_csrf,
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(close1.status, StatusCode::FOUND);

    let open_only = send(&app, get("/r/alice/proj/issues?state=open", Some("bob"))).await;
    assert!(
        open_only.body.contains("Second bug"),
        "open filter shows the open issue"
    );
    assert!(
        !open_only.body.contains("First bug"),
        "open filter hides the closed issue"
    );
    let closed_only = send(&app, get("/r/alice/proj/issues?state=closed", Some("bob"))).await;
    assert!(
        closed_only.body.contains("First bug"),
        "closed filter shows the closed issue"
    );
    assert!(
        !closed_only.body.contains("Second bug"),
        "closed filter hides the open issue"
    );

    // Admin gate on toggle: carol (non-owner, non-author) is refused without an admin group...
    let forbidden = send(
        &app,
        post_form(
            "/r/alice/proj/issues/2/toggle",
            &[("csrf_token", &carol_csrf)],
            &carol_csrf,
            Some("carol"),
        ),
    )
    .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);

    // ...but succeeds as an estate admin (X-Auth-Groups: admins).
    let admin_close = send(
        &app,
        post_form_groups(
            "/r/alice/proj/issues/2/toggle",
            &[("csrf_token", &carol_csrf)],
            &carol_csrf,
            "carol",
            "admins",
        ),
    )
    .await;
    assert_eq!(
        admin_close.status,
        StatusCode::FOUND,
        "admin may close a foreign issue"
    );
    let both_closed = send(&app, get("/r/alice/proj/issues?state=closed", Some("bob"))).await;
    assert!(both_closed.body.contains("First bug"));
    assert!(
        both_closed.body.contains("Second bug"),
        "admin close landed"
    );

    // Delegated admin: a product-scoped operator (X-Auth-Groups: git-admins) may ALSO moderate a
    // foreign issue — here reopening issue 2 — WITHOUT being in a global admin group.
    let delegated_toggle = send(
        &app,
        post_form_groups(
            "/r/alice/proj/issues/2/toggle",
            &[("csrf_token", &carol_csrf)],
            &carol_csrf,
            "carol",
            "git-admins",
        ),
    )
    .await;
    assert_eq!(
        delegated_toggle.status,
        StatusCode::FOUND,
        "git-admins operator may moderate a foreign issue"
    );
}

#[tokio::test]
async fn issue_detail_missing_is_404() {
    let app = app(temp_state());
    create_repo(&app, "alice", "proj", "").await;
    let missing = send(&app, get("/r/alice/proj/issues/999", Some("alice"))).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn labels_milestones_assignees_and_issue_filters() {
    let state = temp_state();
    let store = state.store.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let repo = store.get_repo("alice", "proj").await.unwrap().unwrap();

    let settings = send(&app, get("/r/alice/proj/settings", Some("alice"))).await;
    let csrf = settings.csrf_cookie().unwrap();
    let label_created = send(
        &app,
        post_form(
            "/r/alice/proj/settings/labels",
            &[("csrf_token", &csrf), ("name", "bug"), ("color", "dc2626")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(label_created.status, StatusCode::FOUND);
    let milestone_created = send(
        &app,
        post_form(
            "/r/alice/proj/settings/milestones",
            &[
                ("csrf_token", &csrf),
                ("title", "v1"),
                ("due", "2026-08-01"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(milestone_created.status, StatusCode::FOUND);

    let label = store.list_labels(&repo.id).await.unwrap().pop().unwrap();
    let milestone = store
        .list_milestones(&repo.id)
        .await
        .unwrap()
        .pop()
        .unwrap();

    let issues_page = send(&app, get("/r/alice/proj/issues", Some("alice"))).await;
    let csrf = issues_page.csrf_cookie().unwrap();
    let opened = send(
        &app,
        post_form(
            "/r/alice/proj/issues",
            &[
                ("csrf_token", &csrf),
                ("title", "Tagged bug"),
                ("body", "fix this"),
                ("assignee", "bob"),
                ("milestone_id", &milestone.id),
                ("labels", &label.id),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(opened.status, StatusCode::FOUND);

    let by_label = send(
        &app,
        get(
            &format!("/r/alice/proj/issues?label={}", label.id),
            Some("alice"),
        ),
    )
    .await;
    assert!(by_label.body.contains("Tagged bug"));
    assert!(by_label.body.contains("bug"));
    assert!(by_label.body.contains("assigned to bob"));

    let by_milestone = send(
        &app,
        get(
            &format!("/r/alice/proj/issues?milestone={}", milestone.id),
            Some("alice"),
        ),
    )
    .await;
    assert!(by_milestone.body.contains("milestone v1"));

    let detail = send(&app, get("/r/alice/proj/issues/1", Some("alice"))).await;
    assert!(detail.body.contains("Assignee: bob"));
    assert!(detail.body.contains("Milestone: v1"));
    assert!(detail.body.contains("bug"));
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
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
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
    git_capture(
        git_dir,
        &["update-ref", &format!("refs/heads/{branch}"), &commit],
        "",
    );
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
    assert!(
        view.body.contains("<h1>Hello</h1>"),
        "README heading rendered"
    );
    assert!(view.body.contains("<strong>bold</strong>"));
    // The raw <script> in the README must be neutralised, not served as live markup.
    assert!(!view.body.contains("<script>alert(1)</script>"));
    assert!(view.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));

    // A non-markdown blob renders as a line-numbered, escaped monospace table.
    let blob = send(&app, get("/r/alice/docs/blob/main.rs", Some("alice"))).await;
    assert_eq!(blob.status, StatusCode::OK);
    assert!(
        blob.body.contains("blob-line__num"),
        "line-number gutter present"
    );
    assert!(blob.body.contains("println!"));

    // A markdown blob view renders as sanitised HTML too.
    let md = send(&app, get("/r/alice/docs/blob/README.md", Some("alice"))).await;
    assert_eq!(md.status, StatusCode::OK);
    assert!(md.body.contains("<h1>Hello</h1>"));
    assert!(!md.body.contains("<script>alert(1)</script>"));
}

#[tokio::test]
async fn blame_view_renders_groups_and_graceful_notices() {
    let state = temp_state();
    let git = state.git.clone();
    let app = app(state);
    create_repo(&app, "alice", "docs", "").await;

    let git_dir = git.repo_path("alice", "docs").to_string_lossy().to_string();
    seed_repo(
        &git_dir,
        "main",
        &[
            ("main.rs", "fn main() {\n    println!(\"<hi>\");\n}\n"),
            ("bin.dat", "a\0b"),
        ],
    );
    let head = git_capture(&git_dir, &["rev-parse", "refs/heads/main"], "");

    let blob = send(&app, get("/r/alice/docs/blob/main.rs", Some("alice"))).await;
    assert_eq!(blob.status, StatusCode::OK);
    assert!(blob
        .body
        .contains(r#"href="/r/alice/docs/blame/HEAD/main.rs""#));

    let blame = send(&app, get("/r/alice/docs/blame/HEAD/main.rs", Some("alice"))).await;
    assert_eq!(blame.status, StatusCode::OK);
    assert!(blame.body.contains("class=\"blame-table\""));
    assert!(blame.body.contains("class=\"blame-row\""));
    assert!(blame.body.contains("class=\"blame-commit\""));
    assert!(blame.body.contains("rowspan=\"3\""));
    assert!(blame.body.contains(&format!("/r/alice/docs/commit/{head}")));
    assert!(!blame.body.contains("println!(\"<hi>\");"));
    assert!(blame.body.contains("println!(&quot;&lt;hi&gt;&quot;);"));

    let binary = send(&app, get("/r/alice/docs/blame/HEAD/bin.dat", Some("alice"))).await;
    assert_eq!(binary.status, StatusCode::OK);
    assert!(binary.body.contains("Binary file blame is not shown."));

    let missing = send(
        &app,
        get("/r/alice/docs/blame/HEAD/missing.rs", Some("alice")),
    )
    .await;
    assert_eq!(missing.status, StatusCode::OK);
    assert!(missing.body.contains("No such file at this ref."));
}

#[tokio::test]
async fn fork_clones_bare_repo_and_shows_attribution() {
    let state = temp_state();
    let git = state.git.clone();
    let store = state.store.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let git_dir = git.repo_path("alice", "proj").to_string_lossy().to_string();
    seed_repo(&git_dir, "main", &[("README.md", "# Fork me\n")]);

    let source_page = send(&app, get("/r/alice/proj", Some("bob"))).await;
    assert_eq!(source_page.status, StatusCode::OK);
    let csrf = source_page.csrf_cookie().unwrap();
    let forked = send(
        &app,
        post_form(
            "/r/alice/proj/fork",
            &[("csrf_token", &csrf), ("name", "proj-fork")],
            &csrf,
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(forked.status, StatusCode::FOUND);
    assert_eq!(forked.location(), "/r/bob/proj-fork");

    let source = store.get_repo("alice", "proj").await.unwrap().unwrap();
    let fork = store.get_repo("bob", "proj-fork").await.unwrap().unwrap();
    assert_eq!(fork.forked_from_id, source.id);
    let fork_dir = git
        .repo_path("bob", "proj-fork")
        .to_string_lossy()
        .to_string();
    let fork_head = git_capture(&fork_dir, &["rev-parse", "refs/heads/main"], "");
    let source_head = git_capture(&git_dir, &["rev-parse", "refs/heads/main"], "");
    assert_eq!(fork_head, source_head);

    let fork_page = send(&app, get("/r/bob/proj-fork", Some("bob"))).await;
    assert!(fork_page.body.contains("Forked from"));
    assert!(fork_page.body.contains("/r/alice/proj"));
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
            &[
                ("csrf_token", "wrong"),
                ("name", "x"),
                ("default_branch", "main"),
            ],
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
// Pull requests: compare (commits ahead + diff), create, gated merge
// ===========================================================================

/// Seed `main` (one commit) and `feature` (a second commit on top of it, so a merge of feature
/// into main fast-forwards). Returns the head OID of `feature`.
fn seed_two_branches(git_dir: &str) -> String {
    // main: file.txt = "one\n"
    let blob_a = git_capture(git_dir, &["hash-object", "-w", "--stdin"], "one\n");
    let tree_a = git_capture(
        git_dir,
        &["mktree"],
        &format!("100644 blob {blob_a}\tfile.txt\n"),
    );
    let commit_a = git_capture(git_dir, &["commit-tree", &tree_a, "-m", "A"], "");
    git_capture(git_dir, &["update-ref", "refs/heads/main", &commit_a], "");

    // feature: file.txt = "one\ntwo\n", parented on A (fast-forward relationship).
    let blob_b = git_capture(git_dir, &["hash-object", "-w", "--stdin"], "one\ntwo\n");
    let tree_b = git_capture(
        git_dir,
        &["mktree"],
        &format!("100644 blob {blob_b}\tfile.txt\n"),
    );
    let commit_b = git_capture(
        git_dir,
        &["commit-tree", &tree_b, "-p", &commit_a, "-m", "B"],
        "",
    );
    git_capture(
        git_dir,
        &["update-ref", "refs/heads/feature", &commit_b],
        "",
    );
    commit_b
}

#[tokio::test]
async fn pull_request_compare_create_and_merge() {
    let state = temp_state();
    let git = state.git.clone();
    let store = state.store.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let repo = store.get_repo("alice", "proj").await.unwrap().unwrap();
    let git_dir = git.repo_path("alice", "proj").to_string_lossy().to_string();
    let feature_oid = seed_two_branches(&git_dir);

    // --- compare: commits ahead + escaped diff -----------------------------
    let cmp = send(
        &app,
        get(
            "/r/alice/proj/compare?base=main&head=feature",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(cmp.status, StatusCode::OK);
    assert!(cmp.body.contains("Create pull request"));
    assert!(
        cmp.body.contains("diff-row--add"),
        "diff shows an added line"
    );
    assert!(cmp.body.contains("two"), "added content present");
    let csrf = cmp.csrf_cookie().expect("csrf on compare");

    // --- create the PR -----------------------------------------------------
    let created = send(
        &app,
        post_form(
            "/r/alice/proj/pulls",
            &[
                ("csrf_token", &csrf),
                ("base", "main"),
                ("head", "feature"),
                ("title", "Add second line"),
                ("body", "please review"),
                ("assignee", "bob"),
                ("reviewer", "carol"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND);
    assert_eq!(created.location(), "/r/alice/proj/pulls/1");
    let pull = store.get_pull(&repo.id, 1).await.unwrap().unwrap();
    assert_eq!(pull.assignee_sub, "bob");
    assert_eq!(pull.reviewer_sub, "carol");

    // List shows the open PR.
    let list = send(&app, get("/r/alice/proj/pulls", Some("alice"))).await;
    assert!(list.body.contains("#1"));
    assert!(list.body.contains("Open"));
    assert!(list.body.contains("assigned to bob"));
    assert!(list.body.contains("reviewer carol"));

    // Detail shows the merge button for the owner.
    let detail = send(&app, get("/r/alice/proj/pulls/1", Some("alice"))).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.body.contains("Merge pull request"));
    assert!(detail.body.contains("assignee bob"));
    assert!(detail.body.contains("reviewer carol"));
    let csrf = detail.csrf_cookie().expect("csrf on detail");

    let meta = send(
        &app,
        post_form(
            "/r/alice/proj/pulls/1/metadata",
            &[
                ("csrf_token", &csrf),
                ("assignee", "dave"),
                ("reviewer", "erin"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(meta.status, StatusCode::FOUND);
    let pull = store.get_pull(&repo.id, 1).await.unwrap().unwrap();
    assert_eq!(pull.assignee_sub, "dave");
    assert_eq!(pull.reviewer_sub, "erin");

    let detail = send(&app, get("/r/alice/proj/pulls/1", Some("alice"))).await;
    assert!(detail.body.contains("assignee dave"));
    assert!(detail.body.contains("reviewer erin"));
    let csrf = detail.csrf_cookie().expect("csrf after metadata update");

    // --- gating: a non-owner, non-author cannot merge (403) ----------------
    let forbidden = send(
        &app,
        post_form(
            "/r/alice/proj/pulls/1/merge",
            &[("csrf_token", "x")],
            "x",
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);

    // --- CSRF is required on merge -----------------------------------------
    let no_csrf = send(
        &app,
        post_form(
            "/r/alice/proj/pulls/1/merge",
            &[("csrf_token", "wrong")],
            "the-cookie",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::BAD_REQUEST);

    // --- merge (owner) -> fast-forward -------------------------------------
    let merged = send(
        &app,
        post_form(
            "/r/alice/proj/pulls/1/merge",
            &[("csrf_token", &csrf)],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(merged.status, StatusCode::FOUND);

    // main now points at feature's commit (the fast-forward landed on disk).
    let main_oid = git_capture(&git_dir, &["rev-parse", "refs/heads/main"], "");
    assert_eq!(main_oid, feature_oid, "base fast-forwarded to head");

    // Detail now reports the PR as merged, and re-merging is refused.
    let after = send(&app, get("/r/alice/proj/pulls/1", Some("alice"))).await;
    assert!(after.body.contains("Merged"));
    let csrf2 = after.csrf_cookie().unwrap();
    let remerge = send(
        &app,
        post_form(
            "/r/alice/proj/pulls/1/merge",
            &[("csrf_token", &csrf2)],
            &csrf2,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(
        remerge.status,
        StatusCode::BAD_REQUEST,
        "merged PR is terminal"
    );
}

#[tokio::test]
async fn pull_reviews_gate_merge_inline_comments_and_close_linked_issues() {
    let state = temp_state();
    let git = state.git.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let git_dir = git.repo_path("alice", "proj").to_string_lossy().to_string();
    let feature_oid = seed_two_branches(&git_dir);
    open_issue(&app, "alice", "alice/proj", "Tracked bug", "").await;

    let settings = send(&app, get("/r/alice/proj/settings", Some("alice"))).await;
    let csrf = settings.csrf_cookie().unwrap();
    let saved = send(
        &app,
        post_form(
            "/r/alice/proj/settings",
            &[
                ("csrf_token", &csrf),
                ("description", "requires reviews"),
                ("default_branch", "main"),
                ("require_approval", "on"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(saved.status, StatusCode::FOUND);

    let cmp = send(
        &app,
        get("/r/alice/proj/compare?base=main&head=feature", Some("bob")),
    )
    .await;
    let csrf = cmp.csrf_cookie().unwrap();
    let created = send(
        &app,
        post_form(
            "/r/alice/proj/pulls",
            &[
                ("csrf_token", &csrf),
                ("base", "main"),
                ("head", "feature"),
                ("title", "Add second line"),
                ("body", "fixes #1"),
            ],
            &csrf,
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND);

    let detail = send(&app, get("/r/alice/proj/pulls/1", Some("alice"))).await;
    let csrf = detail.csrf_cookie().unwrap();
    let blocked = send(
        &app,
        post_form(
            "/r/alice/proj/pulls/1/merge",
            &[("csrf_token", &csrf)],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(blocked.status, StatusCode::BAD_REQUEST);
    assert!(blocked.body.contains("requires at least one approval"));

    let approved = send(
        &app,
        post_form(
            "/r/alice/proj/pulls/1/review",
            &[
                ("csrf_token", &csrf),
                ("verdict", "approve"),
                ("body", "looks good #1"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(approved.status, StatusCode::FOUND);
    let inline = send(
        &app,
        post_form(
            "/r/alice/proj/pulls/1/inline-comment",
            &[
                ("csrf_token", &csrf),
                ("path", "file.txt"),
                ("line", "2"),
                ("body", "line note"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(inline.status, StatusCode::FOUND);

    let reviewed = send(&app, get("/r/alice/proj/pulls/1", Some("alice"))).await;
    assert!(reviewed.body.contains("approved by alice"));
    assert!(reviewed.body.contains("file.txt:2"));
    assert!(
        reviewed.body.contains("/r/alice/proj/issues/1"),
        "#N autolink rendered"
    );
    let csrf = reviewed.csrf_cookie().unwrap();
    let merged = send(
        &app,
        post_form(
            "/r/alice/proj/pulls/1/merge",
            &[("csrf_token", &csrf)],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(merged.status, StatusCode::FOUND);
    let main_oid = git_capture(&git_dir, &["rev-parse", "refs/heads/main"], "");
    assert_eq!(main_oid, feature_oid);

    let closed = send(
        &app,
        get("/r/alice/proj/issues?state=closed", Some("alice")),
    )
    .await;
    assert!(
        closed.body.contains("Tracked bug"),
        "fixes #1 closed the linked issue"
    );
}

// ===========================================================================
// Commit history + commit page + branches/tags + settings
// ===========================================================================

/// Seed `n` linear commits (same tree, subjects `commit-001..commit-00n`) on `branch`; returns
/// the commit OIDs OLDEST-first.
fn seed_linear_commits(git_dir: &str, branch: &str, n: usize) -> Vec<String> {
    let blob = git_capture(git_dir, &["hash-object", "-w", "--stdin"], "x\n");
    let tree = git_capture(
        git_dir,
        &["mktree"],
        &format!("100644 blob {blob}\tfile.txt\n"),
    );
    let mut oids = Vec::with_capacity(n);
    let mut parent: Option<String> = None;
    for i in 1..=n {
        let msg = format!("commit-{i:03}");
        let commit = match &parent {
            Some(p) => git_capture(git_dir, &["commit-tree", &tree, "-p", p, "-m", &msg], ""),
            None => git_capture(git_dir, &["commit-tree", &tree, "-m", &msg], ""),
        };
        parent = Some(commit.clone());
        oids.push(commit);
    }
    git_capture(
        git_dir,
        &[
            "update-ref",
            &format!("refs/heads/{branch}"),
            oids.last().unwrap(),
        ],
        "",
    );
    oids
}

#[tokio::test]
async fn commit_history_keyset_pagination() {
    let state = temp_state();
    let git = state.git.clone();
    let app = app(state);
    create_repo(&app, "alice", "hist", "").await;
    let git_dir = git.repo_path("alice", "hist").to_string_lossy().to_string();
    let oids = seed_linear_commits(&git_dir, "main", 55);

    // Page 1: the newest 50 (commit-055 .. commit-006) and an "Older" keyset link anchored at the
    // last shown commit (commit-006 = oids[5]).
    let p1 = send(&app, get("/r/alice/hist/commits", Some("alice"))).await;
    assert_eq!(p1.status, StatusCode::OK);
    assert!(p1.body.contains("commit-055"));
    assert!(p1.body.contains("commit-006"));
    assert!(!p1.body.contains("commit-005"), "page 1 stops at 50 rows");
    let anchor = &oids[5];
    assert!(
        p1.body.contains(&format!("after={anchor}")),
        "Older link anchors at the last shown commit"
    );
    // Short shas link to the commit page.
    assert!(p1
        .body
        .contains(&format!("/r/alice/hist/commit/{}", oids[54])));

    // Page 2 (keyset): the remaining 5, no further Older link, and a Newest rewind.
    let p2 = send(
        &app,
        get(
            &format!("/r/alice/hist/commits?ref=main&after={anchor}"),
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(p2.status, StatusCode::OK);
    assert!(p2.body.contains("commit-005"));
    assert!(p2.body.contains("commit-001"));
    assert!(
        !p2.body.contains("commit-006"),
        "the anchor itself is not repeated"
    );
    assert!(
        !p2.body.contains("after="),
        "no next page after the last commit"
    );
    assert!(p2.body.contains("Newest"));

    // An unknown branch is a 404; a malformed anchor is a 400.
    let bad_ref = send(&app, get("/r/alice/hist/commits?ref=nope", Some("alice"))).await;
    assert_eq!(bad_ref.status, StatusCode::NOT_FOUND);
    let bad_after = send(
        &app,
        get("/r/alice/hist/commits?after=--not-hex", Some("alice")),
    )
    .await;
    assert_eq!(bad_after.status, StatusCode::BAD_REQUEST);

    // An empty repo shows the empty state, not an error.
    create_repo(&app, "alice", "empty", "").await;
    let empty = send(&app, get("/r/alice/empty/commits", Some("alice"))).await;
    assert_eq!(empty.status, StatusCode::OK);
    assert!(empty.body.contains("no commits yet"));
}

#[tokio::test]
async fn commit_page_renders_diff_and_escapes_remote_input() {
    let state = temp_state();
    let git = state.git.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let git_dir = git.repo_path("alice", "proj").to_string_lossy().to_string();
    let feature_oid = seed_two_branches(&git_dir);

    // The commit page: metadata + the diff of commit B (adds the line "two").
    let page = send(
        &app,
        get(
            &format!("/r/alice/proj/commit/{feature_oid}"),
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains(&feature_oid), "full sha shown");
    assert!(page.body.contains("Seed"), "author shown");
    assert!(
        page.body.contains("diff-row--add"),
        "diff rendered with the diff renderer"
    );
    assert!(
        page.body.contains("1 file changed"),
        "shortstat summary shown"
    );
    // Parent link points at commit A.
    assert!(page.body.contains("/r/alice/proj/commit/"));

    // An abbreviated sha resolves to the same commit.
    let short = &feature_oid[..10];
    let abbrev = send(
        &app,
        get(&format!("/r/alice/proj/commit/{short}"), Some("alice")),
    )
    .await;
    assert_eq!(abbrev.status, StatusCode::OK);
    assert!(abbrev.body.contains(&feature_oid));

    // A commit whose subject carries an XSS payload renders escaped on BOTH the history list and
    // the commit page (commit messages are remote input).
    let blob = git_capture(
        &git_dir,
        &["hash-object", "-w", "--stdin"],
        "one\ntwo\nthree\n",
    );
    let tree = git_capture(
        &git_dir,
        &["mktree"],
        &format!("100644 blob {blob}\tfile.txt\n"),
    );
    let evil = git_capture(
        &git_dir,
        &[
            "commit-tree",
            &tree,
            "-p",
            &feature_oid,
            "-m",
            "evil <script>alert(1)</script>",
        ],
        "",
    );
    git_capture(&git_dir, &["update-ref", "refs/heads/feature", &evil], "");

    let hist = send(
        &app,
        get("/r/alice/proj/commits?ref=feature", Some("alice")),
    )
    .await;
    assert_eq!(hist.status, StatusCode::OK);
    assert!(!hist.body.contains("<script>alert(1)</script>"));
    assert!(hist.body.contains("evil &lt;script&gt;"));

    let evil_page = send(
        &app,
        get(&format!("/r/alice/proj/commit/{evil}"), Some("alice")),
    )
    .await;
    assert_eq!(evil_page.status, StatusCode::OK);
    assert!(!evil_page.body.contains("<script>alert(1)</script>"));
    assert!(evil_page.body.contains("evil &lt;script&gt;"));

    // Malformed sha -> 400; well-formed but unknown -> 404.
    let bad = send(&app, get("/r/alice/proj/commit/not-hex!", Some("alice"))).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let missing = send(
        &app,
        get("/r/alice/proj/commit/deadbeefdead", Some("alice")),
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn commit_status_api_updates_json_and_ssr_checks() {
    let mut state = temp_state();
    Arc::make_mut(&mut state.config).status_token = "status-secret".to_string();
    let git = state.git.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let git_dir = git.repo_path("alice", "proj").to_string_lossy().to_string();
    let feature_oid = seed_two_branches(&git_dir);
    let status_path = format!("/r/alice/proj/statuses/{feature_oid}");

    let before = send(
        &app,
        get("/r/alice/proj/commits?ref=feature", Some("alice")),
    )
    .await;
    assert_eq!(before.status, StatusCode::OK);
    assert!(
        !before.body.contains("title=\"Checks:"),
        "commits without statuses do not render a badge"
    );

    let unauth = send(
        &app,
        post_json(
            &status_path,
            r#"{"state":"pending","context":"ci/anvil"}"#,
            None,
        ),
    )
    .await;
    assert_eq!(unauth.status, StatusCode::UNAUTHORIZED);

    let pending = send(
        &app,
        post_json(
            &status_path,
            r#"{"state":"pending","context":"ci/anvil","description":"queued"}"#,
            Some("status-secret"),
        ),
    )
    .await;
    assert_eq!(pending.status, StatusCode::OK);
    assert!(pending.body.contains(r#""state":"pending""#));

    let success = send(
        &app,
        post_json(
            &status_path,
            r#"{"state":"success","context":"ci/anvil","description":"build <ok>","target_url":"https://ci.example/run/1?x=<y>"}"#,
            Some("status-secret"),
        ),
    )
    .await;
    assert_eq!(success.status, StatusCode::OK);
    assert!(success.body.contains(r#""state":"success""#));

    let failure = send(
        &app,
        post_json(
            &status_path,
            r#"{"state":"failure","context":"test","description":"tests failed","target_url":"https://ci.example/test"}"#,
            Some("status-secret"),
        ),
    )
    .await;
    assert_eq!(failure.status, StatusCode::OK);
    assert!(failure.body.contains(r#""state":"failure""#));

    let json = send(
        &app,
        get(
            &format!("/r/alice/proj/commits/{feature_oid}/status"),
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(json.status, StatusCode::OK);
    assert!(json.content_type().starts_with("application/json"));
    assert!(json.body.contains(r#""state":"failure""#));
    assert!(json.body.contains(r#""context":"ci/anvil""#));
    assert!(json.body.contains(r#""context":"test""#));

    let hist = send(
        &app,
        get("/r/alice/proj/commits?ref=feature", Some("alice")),
    )
    .await;
    assert_eq!(hist.status, StatusCode::OK);
    assert!(hist.body.contains("title=\"Checks: failure\""));
    assert!(hist.body.contains("aria-label=\"Checks: failure\""));

    let commit = send(
        &app,
        get(
            &format!("/r/alice/proj/commit/{feature_oid}"),
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(commit.status, StatusCode::OK);
    assert!(commit.body.contains("title=\"Checks: failure\""));

    let cmp = send(
        &app,
        get("/r/alice/proj/compare?base=main&head=feature", Some("bob")),
    )
    .await;
    let csrf = cmp.csrf_cookie().unwrap();
    let created = send(
        &app,
        post_form(
            "/r/alice/proj/pulls",
            &[
                ("csrf_token", &csrf),
                ("base", "main"),
                ("head", "feature"),
                ("title", "Add second line"),
                ("body", ""),
            ],
            &csrf,
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND);

    let pr = send(&app, get("/r/alice/proj/pulls/1", Some("alice"))).await;
    assert_eq!(pr.status, StatusCode::OK);
    assert!(pr.body.contains("<h2>Checks "));
    assert!(pr.body.contains("Head commit"));
    assert!(pr.body.contains("ci/anvil"));
    assert!(pr.body.contains("test"));
    assert!(pr.body.contains("build &lt;ok&gt;"));
    assert!(pr.body.contains("tests failed"));
    assert!(pr.body.contains("https://ci.example/test"));
}

#[tokio::test]
async fn branches_page_lists_branches_and_tags() {
    let state = temp_state();
    let git = state.git.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let git_dir = git.repo_path("alice", "proj").to_string_lossy().to_string();
    let feature_oid = seed_two_branches(&git_dir);

    // One annotated tag (with a message that needs escaping) and one lightweight tag.
    git_capture(
        &git_dir,
        &[
            "tag",
            "-a",
            "v1.0",
            "-m",
            "first release <tag>",
            &feature_oid,
        ],
        "",
    );
    git_capture(&git_dir, &["tag", "v0-light", &feature_oid], "");

    let page = send(&app, get("/r/alice/proj/branches", Some("alice"))).await;
    assert_eq!(page.status, StatusCode::OK);
    // Both branches, with the default pill on main and a compare link for the topic branch.
    assert!(page.body.contains("main"));
    assert!(page.body.contains("feature"));
    assert!(page.body.contains(">default</span>"), "default-branch pill");
    assert!(
        page.body
            .contains("/r/alice/proj/compare?base=main&amp;head=feature"),
        "compare link into the existing PR compare"
    );
    // Head sha links into the commit page.
    assert!(page
        .body
        .contains(&format!("/r/alice/proj/commit/{feature_oid}")));
    // Tags: the annotated message is shown (escaped); the lightweight tag has none.
    assert!(page.body.contains("v1.0"));
    assert!(page.body.contains("first release &lt;tag&gt;"));
    assert!(!page.body.contains("first release <tag>"));
    assert!(page.body.contains("v0-light"));

    // The tab row is present with Branches active.
    assert!(page
        .body
        .contains("tab--active\" href=\"/r/alice/proj/branches\""));
}

#[tokio::test]
async fn releases_flow_handles_notes_drafts_json_and_delete() {
    let state = temp_state();
    let git = state.git.clone();
    let store = state.store.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let git_dir = git.repo_path("alice", "proj").to_string_lossy().to_string();
    seed_repo(&git_dir, "main", &[("README.md", "# Project\n")]);
    let target = git_capture(&git_dir, &["rev-parse", "refs/heads/main"], "");
    git_capture(&git_dir, &["tag", "v1.0.0", &target], "");

    let form = send(&app, get("/r/alice/proj/releases/new", Some("alice"))).await;
    assert_eq!(form.status, StatusCode::OK);
    let csrf = form.csrf_cookie().expect("csrf on release form");
    let created = send(
        &app,
        post_form(
            "/r/alice/proj/releases/new",
            &[
                ("csrf_token", &csrf),
                ("existing_tag", "v1.0.0"),
                ("title", "Ship <it>"),
                (
                    "body_md",
                    "# Notes\n\nFixes #1\n\n<script>alert(1)</script>",
                ),
                ("is_prerelease", "on"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND);
    assert_eq!(created.location(), "/r/alice/proj/releases/tag/v1.0.0");

    let detail = send(
        &app,
        get("/r/alice/proj/releases/tag/v1.0.0", Some("alice")),
    )
    .await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.body.contains("Ship &lt;it&gt;"));
    assert!(detail.body.contains("<h1>Notes</h1>"));
    assert!(detail.body.contains("/r/alice/proj/issues/1"));
    assert!(!detail.body.contains("<script>alert(1)</script>"));
    assert!(detail.body.contains("&lt;script&gt;"));
    assert!(detail.body.contains("Pre-release"));

    let home = send(&app, get("/r/alice/proj", Some("alice"))).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.body.contains("Latest release"));
    assert!(home.body.contains("Ship &lt;it&gt;"));

    let json = send(&app, get("/r/alice/proj/releases.json", Some("bob"))).await;
    assert_eq!(json.status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_str(&json.body).unwrap();
    assert_eq!(parsed["releases"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["releases"][0]["tag_name"], "v1.0.0");

    let form = send(&app, get("/r/alice/proj/releases/new", Some("alice"))).await;
    let csrf = form.csrf_cookie().expect("csrf on release form");
    let draft_created = send(
        &app,
        post_form(
            "/r/alice/proj/releases/new",
            &[
                ("csrf_token", &csrf),
                ("new_tag", "v2.0.0"),
                ("title", "Draft plan"),
                ("body_md", "not public yet"),
                ("is_draft", "on"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(draft_created.status, StatusCode::FOUND);
    assert_eq!(
        draft_created.location(),
        "/r/alice/proj/releases/tag/v2.0.0"
    );
    assert_eq!(
        git_capture(&git_dir, &["rev-parse", "refs/tags/v2.0.0^{commit}"], ""),
        target
    );

    let bob_list = send(&app, get("/r/alice/proj/releases", Some("bob"))).await;
    assert_eq!(bob_list.status, StatusCode::OK);
    assert!(bob_list.body.contains("v1.0.0"));
    assert!(!bob_list.body.contains("Draft plan"));
    let bob_draft = send(&app, get("/r/alice/proj/releases/tag/v2.0.0", Some("bob"))).await;
    assert_eq!(bob_draft.status, StatusCode::NOT_FOUND);

    let alice_list = send(&app, get("/r/alice/proj/releases", Some("alice"))).await;
    assert_eq!(alice_list.status, StatusCode::OK);
    assert!(alice_list.body.contains("Draft plan"));
    assert!(alice_list.body.contains("Draft"));

    let repo = store.get_repo("alice", "proj").await.unwrap().unwrap();
    let draft = store
        .get_release_by_tag(&repo.id, "v2.0.0")
        .await
        .unwrap()
        .unwrap();
    let bad_delete = send(
        &app,
        post_form(
            &format!("/r/alice/proj/releases/{}/delete", draft.id),
            &[("csrf_token", "wrong")],
            "wrong-cookie",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(bad_delete.status, StatusCode::BAD_REQUEST);

    let detail = send(
        &app,
        get("/r/alice/proj/releases/tag/v2.0.0", Some("alice")),
    )
    .await;
    let csrf = detail.csrf_cookie().expect("csrf on release detail");
    let deleted = send(
        &app,
        post_form(
            &format!("/r/alice/proj/releases/{}/delete", draft.id),
            &[("csrf_token", &csrf)],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::FOUND);
    assert_eq!(deleted.location(), "/r/alice/proj/releases");
    assert!(store
        .get_release_by_tag(&repo.id, "v2.0.0")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn settings_guarded_and_default_branch_validated() {
    let state = temp_state();
    let git = state.git.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let git_dir = git.repo_path("alice", "proj").to_string_lossy().to_string();
    seed_two_branches(&git_dir);

    // A non-owner (no admin groups) gets 403 on GET and POST.
    let bob_get = send(&app, get("/r/alice/proj/settings", Some("bob"))).await;
    assert_eq!(bob_get.status, StatusCode::FORBIDDEN);
    let bob_post = send(
        &app,
        post_form(
            "/r/alice/proj/settings",
            &[
                ("csrf_token", "tok"),
                ("description", "hax"),
                ("default_branch", "main"),
            ],
            "tok",
            Some("bob"),
        ),
    )
    .await;
    assert_eq!(bob_post.status, StatusCode::FORBIDDEN);

    // The owner sees the form.
    let form_page = send(&app, get("/r/alice/proj/settings", Some("alice"))).await;
    assert_eq!(form_page.status, StatusCode::OK);
    assert!(form_page.body.contains("Repository settings"));
    let csrf = form_page.csrf_cookie().expect("csrf on settings");

    // CSRF is required.
    let no_csrf = send(
        &app,
        post_form(
            "/r/alice/proj/settings",
            &[("csrf_token", "wrong"), ("default_branch", "main")],
            "the-cookie",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::BAD_REQUEST);

    // A default branch that does not exist is rejected inline (400).
    let bad_branch = send(
        &app,
        post_form(
            "/r/alice/proj/settings",
            &[
                ("csrf_token", &csrf),
                ("description", "d"),
                ("default_branch", "nope"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(bad_branch.status, StatusCode::BAD_REQUEST);
    assert!(bad_branch.body.contains("existing branch"));

    // A valid update: new description + default branch flipped to `feature`.
    let saved = send(
        &app,
        post_form(
            "/r/alice/proj/settings",
            &[
                ("csrf_token", &csrf),
                ("description", "new words <b>"),
                ("default_branch", "feature"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(saved.status, StatusCode::FOUND);
    assert_eq!(saved.location(), "/r/alice/proj/settings");

    // The description shows (escaped) on the repo home and the bare repo's HEAD moved.
    let home = send(&app, get("/r/alice/proj", Some("alice"))).await;
    assert!(home.body.contains("new words &lt;b&gt;"));
    assert!(!home.body.contains("new words <b>"));
    let head = git_capture(&git_dir, &["symbolic-ref", "HEAD"], "");
    assert_eq!(
        head, "refs/heads/feature",
        "bare-repo HEAD follows the default branch"
    );

    // An estate admin (X-Auth-Groups: admins) may edit a foreign repo's settings.
    let admin_save = send(
        &app,
        post_form_groups(
            "/r/alice/proj/settings",
            &[
                ("csrf_token", &csrf),
                ("description", "admin edit"),
                ("default_branch", "feature"),
            ],
            &csrf,
            "carol",
            "admins",
        ),
    )
    .await;
    assert_eq!(
        admin_save.status,
        StatusCode::FOUND,
        "admin may edit settings"
    );
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
        get(
            "/git/alice/pub.git/info/refs?service=git-receive-pack",
            None,
        ),
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
    assert_eq!(
        ok.status,
        StatusCode::OK,
        "alice's PAT clones her private repo"
    );

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
        get_basic(
            "/git/alice/sec.git/info/refs?service=git-upload-pack",
            "nope",
        ),
    )
    .await;
    assert_eq!(bogus.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn smart_http_blocks_direct_push_to_protected_default_branch() {
    let state = temp_state();
    let store: Arc<dyn Store> = state.store.clone();
    let app = app(state);
    create_repo(&app, "alice", "proj", "").await;
    let repo = store.get_repo("alice", "proj").await.unwrap().unwrap();
    assert!(store
        .update_repo_settings(
            &repo.id,
            &repo.description,
            &repo.default_branch,
            false,
            true
        )
        .await
        .unwrap());

    let secret = new_pat_secret();
    store
        .create_pat(&Pat {
            id: "pt_push".into(),
            owner_sub: "alice".into(),
            name: "push".into(),
            token_hash: hash_token(&secret),
            created_at: now_secs(),
        })
        .await
        .unwrap();

    let blocked = send(
        &app,
        post_basic(
            "/git/alice/proj.git/git-receive-pack",
            &secret,
            "0000 old new refs/heads/main\0 report-status",
        ),
    )
    .await;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
    assert!(blocked.body.contains("protected default branch"));
}

#[tokio::test]
async fn smart_http_unknown_repo_is_404() {
    let app = app(temp_state());
    let missing = send(
        &app,
        get(
            "/git/ghost/none.git/info/refs?service=git-upload-pack",
            None,
        ),
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

/// The additive JSON sibling of the issue open/close form backs the optimistic, no-reload toggle.
/// It shares the CSRF + author/owner/admin gate + audit of the form route (progressive enhancement:
/// the form route still works with JavaScript off) and returns a small JSON envelope.
#[tokio::test]
async fn issue_toggle_json_flips_state_with_same_csrf_gate() {
    let app = app(temp_state());
    create_repo(&app, "alice", "proj", "").await;
    let loc = open_issue(&app, "alice", "alice/proj", "Flaky test", "steps").await;
    assert_eq!(loc, "/r/alice/proj/issues/1");

    // JSON toggle: 200 + JSON (not a 302), and the state really flips to closed.
    let page = send(&app, get("/r/alice/proj/issues/1", Some("alice"))).await;
    let csrf = page.csrf_cookie().unwrap();
    let toggled = send(
        &app,
        post_form(
            "/r/alice/proj/issues/1/toggle.json",
            &[("csrf_token", &csrf)],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(toggled.status, StatusCode::OK);
    assert!(toggled.content_type().contains("application/json"));
    assert!(
        toggled.body.contains("\"state\":\"closed\""),
        "json body: {}",
        toggled.body
    );
    let after = send(&app, get("/r/alice/proj/issues/1", Some("alice"))).await;
    assert!(after.body.contains("Closed"), "issue persisted as closed");

    // Missing/blank CSRF is rejected exactly like the form route.
    let no_csrf = send(
        &app,
        post_form(
            "/r/alice/proj/issues/1/toggle.json",
            &[("csrf_token", "")],
            "",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::BAD_REQUEST);
}
