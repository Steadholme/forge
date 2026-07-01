//! Sanitised CommonMark rendering for README files + issue bodies.
//!
//! Reuses the estate's markdown/sanitise approach (agora/echo/inkwell): user-supplied markdown
//! is rendered to HTML, but NEVER allowed to inject script or other active content. Two defenses
//! run over the pulldown-cmark event stream before it is serialised:
//!
//! 1. Raw HTML (`Event::Html` / `Event::InlineHtml`) is downgraded to plain TEXT, so a literal
//!    `<script>…</script>` in a README/issue is shown as text, not executed.
//! 2. Link/image destinations are scheme-checked: only `http`/`https`/`mailto` and relative URLs
//!    survive; anything else (e.g. `javascript:`, `data:`, `vbscript:`) is replaced with `#`, so a
//!    crafted `[x](javascript:…)` can't smuggle an executable href.
//!
//! Everything else (text, code, emphasis, link titles) is escaped by `push_html` itself.

use pulldown_cmark::{html, CowStr, Event, Options, Parser, Tag};

/// Render `md` to sanitised HTML safe to embed directly in a page.
pub fn render(md: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let events = Parser::new_ext(md, options).map(sanitize_event);
    let mut out = String::new();
    html::push_html(&mut out, events);
    out
}

/// Neutralise raw HTML and unsafe link/image schemes for a single event.
fn sanitize_event(event: Event<'_>) -> Event<'_> {
    match event {
        // Raw HTML never reaches the output as markup — render it as text instead.
        Event::Html(s) | Event::InlineHtml(s) => Event::Text(s),
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Link {
            link_type,
            dest_url: safe_url(dest_url),
            title,
            id,
        }),
        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Image {
            link_type,
            dest_url: safe_url(dest_url),
            title,
            id,
        }),
        other => other,
    }
}

/// Pass through a safe URL; replace an unsafe one with `#`.
fn safe_url(url: CowStr<'_>) -> CowStr<'_> {
    if is_safe_url(&url) {
        url
    } else {
        CowStr::Borrowed("#")
    }
}

/// A URL is safe when it is `http(s)`/`mailto`, or relative (no scheme before the first path
/// separator). Any other explicit scheme (`javascript:`, `data:`, …) is rejected.
fn is_safe_url(url: &str) -> bool {
    let u = url.trim();
    if u.is_empty() {
        return false;
    }
    let lower = u.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("mailto:")
    {
        return true;
    }
    // Relative if there is no ':' before the first path separator / query / fragment.
    let sep = u.find(['/', '?', '#']);
    match u.find(':') {
        None => true,
        Some(colon) => matches!(sep, Some(s) if s < colon),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_basic_markdown() {
        let html = render("# Title\n\nHello **world** and `code`.");
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<strong>world</strong>"));
        assert!(html.contains("<code>code</code>"));
    }

    #[test]
    fn fenced_code_block_is_preformatted() {
        let html = render("```\nfn main() {}\n```");
        assert!(html.contains("<pre><code"));
        assert!(html.contains("fn main() {}"));
    }

    #[test]
    fn raw_html_is_not_executed() {
        let html = render("<script>alert(1)</script>\n\nhi");
        assert!(!html.contains("<script>"), "raw <script> must not survive");
        assert!(html.contains("&lt;script&gt;"), "shown as escaped text");
    }

    #[test]
    fn inline_html_is_escaped() {
        let html = render("a <img src=x onerror=alert(1)> b");
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("&lt;img"));
    }

    #[test]
    fn javascript_links_are_defused() {
        let html = render("[click](javascript:alert(1))");
        assert!(!html.contains("javascript:"));
        assert!(html.contains("href=\"#\""));
    }

    #[test]
    fn safe_links_survive() {
        let html = render("[ok](https://w33d.xyz/x) and [rel](/c/general)");
        assert!(html.contains("href=\"https://w33d.xyz/x\""));
        assert!(html.contains("href=\"/c/general\""));
    }

    #[test]
    fn url_scheme_classification() {
        assert!(is_safe_url("https://x.y/z"));
        assert!(is_safe_url("http://x"));
        assert!(is_safe_url("mailto:a@b.c"));
        assert!(is_safe_url("/relative/path"));
        assert!(is_safe_url("#anchor"));
        assert!(is_safe_url("./a:b")); // colon after a path sep -> relative
        assert!(!is_safe_url("javascript:alert(1)"));
        assert!(!is_safe_url("data:text/html;base64,AA"));
        assert!(!is_safe_url("  vbscript:msgbox  "));
        assert!(!is_safe_url(""));
    }
}
