//! Personal-access-token management: mint once, list, revoke.
//!
//! A PAT is the credential `git`/`docker`-style clients use to authenticate over the smart-HTTP
//! `/git/` routes (username = anything, password = the token). The secret is shown EXACTLY ONCE
//! at mint time; only its SHA-256 hash is stored, so it can never be recovered — a lost token is
//! revoked and replaced. All tokens are scoped to the signed-in subject. POSTs are CSRF-checked.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::auth::{self, Identity};
use crate::error::AppError;
use crate::handlers::{esc, fmt_ts, html_with_csrf, page, redirect};
use crate::model::Pat;
use crate::{now_secs, random_alnum, AppState};

const PAT_ID_LEN: usize = 16;

// ===========================================================================
// GET /pats
// ===========================================================================

pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let pats = state
        .store
        .list_pats(&who.subject)
        .await
        .unwrap_or_default();
    let body = render_pats(&who, &csrf, &pats, None, None);
    html_with_csrf(StatusCode::OK, page_shell(&who, &body), &csrf)
}

// ===========================================================================
// POST /pats — mint a token (shown once)
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub name: String,
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and submit again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);

    let name = form.name.trim();
    let csrf = auth::new_csrf_token();
    if name.is_empty() {
        let pats = state
            .store
            .list_pats(&who.subject)
            .await
            .unwrap_or_default();
        let body = render_pats(
            &who,
            &csrf,
            &pats,
            Some("Token name cannot be empty."),
            None,
        );
        return Ok(html_with_csrf(
            StatusCode::BAD_REQUEST,
            page_shell(&who, &body),
            &csrf,
        ));
    }

    // Mint the secret, persist ONLY its hash, then reveal the secret exactly once.
    let secret = auth::new_pat_secret();
    let pat = Pat {
        id: format!("pt_{}", random_alnum(PAT_ID_LEN)),
        owner_sub: who.subject.clone(),
        name: name.chars().take(100).collect(),
        token_hash: auth::hash_token(&secret),
        created_at: now_secs(),
    };
    state.store.create_pat(&pat).await?;
    tracing::info!(
        owner = who.subject,
        pat = pat.id,
        "personal access token minted"
    );

    let pats = state
        .store
        .list_pats(&who.subject)
        .await
        .unwrap_or_default();
    let body = render_pats(&who, &csrf, &pats, None, Some(&secret));
    Ok(html_with_csrf(
        StatusCode::OK,
        page_shell(&who, &body),
        &csrf,
    ))
}

// ===========================================================================
// POST /pats/{id}/revoke
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<RevokeForm>,
) -> Result<Response, AppError> {
    if !auth::verify_csrf(&headers, &form.csrf_token) {
        return Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ));
    }
    let who = auth::identity(&headers);
    // Ownership-scoped: a user can only revoke their own tokens.
    state.store.revoke_pat(&id, &who.subject).await?;
    Ok(redirect("/pats"))
}

// ===========================================================================
// Rendering
// ===========================================================================

fn page_shell(who: &Identity, body: &str) -> String {
    page("Access tokens", Some(&who.email), who.theme, body)
}

fn render_pats(
    who: &Identity,
    csrf: &str,
    pats: &[Pat],
    error: Option<&str>,
    new_secret: Option<&str>,
) -> String {
    let reveal = match new_secret {
        Some(secret) => format!(
            r##"<div class="token-reveal">
  <p class="token-reveal__label">New token — copy it now, it will not be shown again:</p>
  <code class="token-reveal__value">{secret}</code>
</div>"##,
            secret = esc(secret),
        ),
        None => String::new(),
    };
    let error_block = match error {
        Some(msg) => format!(
            "<div class=\"alert alert-danger\" role=\"alert\">{}</div>",
            esc(msg)
        ),
        None => String::new(),
    };

    let list = if pats.is_empty() {
        "<li class=\"pat-item pat-item--empty\">No tokens yet.</li>".to_string()
    } else {
        pats.iter()
            .map(|p| {
                format!(
                    r##"<li class="pat-item">
  <div class="pat-item__head">
    <span class="pat-item__name">{name}</span>
    <form class="inline-form" method="post" action="/pats/{id}/revoke" onsubmit="return confirm('Revoke this token? Clients using it will stop working.');">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <button class="btn btn-danger btn-sm" type="submit">Revoke</button>
    </form>
  </div>
  <span class="pat-item__meta">created {created}</span>
</li>"##,
                    name = esc(&p.name),
                    id = esc(&p.id),
                    csrf = esc(csrf),
                    created = esc(&fmt_ts(p.created_at)),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r##"<div class="console__head">
  <h1>Access tokens</h1>
  <p class="sub">Personal access tokens authenticate <code>git</code> over HTTPS for {email}. Use the token as the password (any username) when cloning or pushing.</p>
</div>
{reveal}
<div class="layout">
  <section class="card">
    <div class="card__head"><h2>Your tokens</h2></div>
    <div class="card__body"><ul class="pat-list">{list}</ul></div>
  </section>
  <section class="card">
    <div class="card__head"><h2>Generate token</h2></div>
    <div class="card__body">
      {error_block}
      <form method="post" action="/pats">
        <input type="hidden" name="csrf_token" value="{csrf}">
        <div class="field">
          <label for="name">Token name</label>
          <input type="text" id="name" name="name" maxlength="100" placeholder="e.g. laptop" autocomplete="off" required>
        </div>
        <div class="actions">
          <button class="btn btn-primary" type="submit">Generate token</button>
        </div>
      </form>
    </div>
  </section>
</div>"##,
        email = esc(&who.email),
        reveal = reveal,
        list = list,
        error_block = error_block,
        csrf = esc(csrf),
    )
}
