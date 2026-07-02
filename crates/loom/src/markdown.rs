//! Sanitised CommonMark/GFM rendering for README files + issue bodies.
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
//! Everything else (text, code, emphasis, link titles) is escaped by `push_html` itself. After
//! serialisation, Loom adds safe GFM class hooks and links plain-text references outside tags/code.

use pulldown_cmark::{html, CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd};

/// Repository context for GFM references that need to point back into the current repo.
#[derive(Clone, Copy)]
pub struct RenderContext<'a> {
    pub repo_owner: &'a str,
    pub repo_name: &'a str,
}

/// Comment-local context for GitHub-style suggested changes.
#[derive(Clone, Copy)]
pub struct SuggestionContext<'a> {
    pub old: &'a str,
}

/// Render `md` to sanitised HTML safe to embed directly in a page.
pub fn render(md: &str) -> String {
    render_inner(md, None, None)
}

/// Render `md` with repository-scoped GFM reference links (`#123`, `@user`).
pub fn render_with_context(md: &str, context: RenderContext<'_>) -> String {
    render_inner(md, Some(context), None)
}

/// Convenience wrapper for repository-scoped markdown surfaces.
pub fn render_for_repo(md: &str, repo_owner: &str, repo_name: &str) -> String {
    render_with_context(
        md,
        RenderContext {
            repo_owner,
            repo_name,
        },
    )
}

/// Render repository-scoped markdown with special handling for ```suggestion fences.
pub fn render_for_repo_with_suggestion(
    md: &str,
    repo_owner: &str,
    repo_name: &str,
    suggestion: SuggestionContext<'_>,
) -> String {
    render_inner(
        md,
        Some(RenderContext {
            repo_owner,
            repo_name,
        }),
        Some(suggestion),
    )
}

/// Return the first GitHub-style suggested-change fenced code block, if present.
pub fn extract_first_suggestion(md: &str) -> Option<String> {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let mut events = Parser::new_ext(md, options).peekable();
    while let Some(event) = events.next() {
        if let Event::Start(Tag::CodeBlock(kind)) = event {
            let is_suggestion = matches!(
                &kind,
                CodeBlockKind::Fenced(info) if is_suggestion_info(info)
            );
            let mut code = String::new();
            while let Some(inner) = events.next() {
                match inner {
                    Event::End(TagEnd::CodeBlock) => break,
                    Event::Text(s) | Event::Code(s) | Event::Html(s) | Event::InlineHtml(s) => {
                        code.push_str(&s)
                    }
                    Event::SoftBreak | Event::HardBreak => code.push('\n'),
                    _ => {}
                }
            }
            if is_suggestion {
                return Some(code);
            }
        }
    }
    None
}

fn render_inner(
    md: &str,
    context: Option<RenderContext<'_>>,
    suggestion: Option<SuggestionContext<'_>>,
) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let events =
        highlight_code_blocks(Parser::new_ext(md, options).map(sanitize_event), suggestion);
    let mut out = String::new();
    html::push_html(&mut out, events.into_iter());
    add_gfm_classes_and_links(&out, context)
}

fn highlight_code_blocks<'a>(
    events: impl Iterator<Item = Event<'a>>,
    suggestion: Option<SuggestionContext<'_>>,
) -> Vec<Event<'a>> {
    let mut out = Vec::new();
    let mut events = events.peekable();
    while let Some(event) = events.next() {
        match event {
            Event::Start(Tag::CodeBlock(kind)) => {
                let mut code = String::new();
                while let Some(inner) = events.next() {
                    match inner {
                        Event::End(TagEnd::CodeBlock) => break,
                        Event::Text(s) | Event::Code(s) | Event::Html(s) | Event::InlineHtml(s) => {
                            code.push_str(&s)
                        }
                        Event::SoftBreak | Event::HardBreak => code.push('\n'),
                        _ => {}
                    }
                }
                let html =
                    if let (CodeBlockKind::Fenced(info), Some(suggestion)) = (&kind, suggestion) {
                        if is_suggestion_info(info) {
                            render_suggestion_block(suggestion.old, &code)
                        } else {
                            render_code_block(&code, &kind)
                        }
                    } else {
                        render_code_block(&code, &kind)
                    };
                out.push(Event::Html(CowStr::Boxed(html.into_boxed_str())));
            }
            other => out.push(other),
        }
    }
    out
}

fn is_suggestion_info(info: &str) -> bool {
    info.split_whitespace().next() == Some("suggestion")
}

fn render_suggestion_block(old: &str, new: &str) -> String {
    format!(
        "<div class=\"suggestion\"><div class=\"suggestion__diff\"><pre class=\"suggestion__old\"><code>{old}</code></pre><pre class=\"suggestion__new\"><code>{new}</code></pre></div></div>\n",
        old = render_suggestion_lines("-", old),
        new = render_suggestion_lines("+", new),
    )
}

fn render_suggestion_lines(prefix: &str, text: &str) -> String {
    if text.is_empty() {
        return escape_html(prefix);
    }
    let mut out = String::new();
    for raw in text.split_inclusive('\n') {
        out.push_str(prefix);
        out.push(' ');
        out.push_str(&escape_html(raw));
    }
    if !text.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn render_code_block(code: &str, kind: &CodeBlockKind<'_>) -> String {
    let lang = match kind {
        CodeBlockKind::Fenced(info) => crate::highlight::normalize_lang(info),
        CodeBlockKind::Indented => None,
    };
    let class = lang
        .map(|lang| format!(" class=\"language-{lang}\""))
        .unwrap_or_default();
    let code = match lang {
        Some(lang) => crate::highlight::highlight(code, lang),
        None => escape_html(code),
    };
    format!("<pre><code{class}>{code}</code></pre>\n")
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

fn add_gfm_classes_and_links(html: &str, context: Option<RenderContext<'_>>) -> String {
    let html = html
        .replace("<table>", "<table class=\"md-table\">")
        .replace(
            "<li><input disabled=\"\" type=\"checkbox\"",
            "<li class=\"task-list-item\"><input disabled=\"\" type=\"checkbox\"",
        );
    link_plain_text_segments(&html, context)
}

fn link_plain_text_segments(html: &str, context: Option<RenderContext<'_>>) -> String {
    let mut out = String::with_capacity(html.len());
    let mut text = String::new();
    let mut tag = String::new();
    let mut skipped_tags: Vec<String> = Vec::new();
    let mut in_tag = false;

    for ch in html.chars() {
        if in_tag {
            tag.push(ch);
            if ch == '>' {
                update_skipped_tags(&tag, &mut skipped_tags);
                out.push_str(&tag);
                tag.clear();
                in_tag = false;
            }
        } else if ch == '<' {
            flush_text_segment(&mut out, &mut text, context, skipped_tags.is_empty());
            in_tag = true;
            tag.push(ch);
        } else {
            text.push(ch);
        }
    }

    if in_tag {
        text.push_str(&tag);
    }
    flush_text_segment(&mut out, &mut text, context, skipped_tags.is_empty());
    out
}

fn flush_text_segment(
    out: &mut String,
    text: &mut String,
    context: Option<RenderContext<'_>>,
    can_link: bool,
) {
    if text.is_empty() {
        return;
    }
    if can_link {
        out.push_str(&link_plain_text(text, context));
    } else {
        out.push_str(text);
    }
    text.clear();
}

fn update_skipped_tags(tag: &str, skipped_tags: &mut Vec<String>) {
    let Some((name, closing, self_closing)) = parse_tag_name(tag) else {
        return;
    };
    if !suppresses_linking(&name) {
        return;
    }
    if closing {
        if let Some(pos) = skipped_tags.iter().rposition(|tag| tag == &name) {
            skipped_tags.remove(pos);
        }
    } else if !self_closing {
        skipped_tags.push(name);
    }
}

fn parse_tag_name(tag: &str) -> Option<(String, bool, bool)> {
    let body = tag.strip_prefix('<')?.strip_suffix('>')?.trim();
    if body.is_empty() || body.starts_with('!') {
        return None;
    }
    let closing = body.starts_with('/');
    let body = if closing {
        body[1..].trim_start()
    } else {
        body
    };
    let self_closing = body.ends_with('/');
    let name = body
        .split(|c: char| c.is_ascii_whitespace() || c == '/')
        .next()?;
    if name.is_empty() {
        None
    } else {
        Some((name.to_ascii_lowercase(), closing, self_closing))
    }
}

fn suppresses_linking(tag_name: &str) -> bool {
    matches!(tag_name, "a" | "code" | "pre" | "script" | "style")
}

fn link_plain_text(text: &str, context: Option<RenderContext<'_>>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut idx = 0;
    while idx < text.len() {
        if let Some((end, html)) = try_autolink(text, idx) {
            out.push_str(&text[..idx]);
            out.push_str(&html);
            out.push_str(&link_plain_text(&text[end..], context));
            return out;
        }
        if let Some(ctx) = context {
            if let Some((end, html)) = try_issue_ref(text, idx, ctx) {
                out.push_str(&text[..idx]);
                out.push_str(&html);
                out.push_str(&link_plain_text(&text[end..], context));
                return out;
            }
        }
        if let Some((end, html)) = try_mention(text, idx) {
            out.push_str(&text[..idx]);
            out.push_str(&html);
            out.push_str(&link_plain_text(&text[end..], context));
            return out;
        }
        idx += text[idx..].chars().next().map(char::len_utf8).unwrap_or(1);
    }
    text.to_string()
}

fn try_autolink(text: &str, idx: usize) -> Option<(usize, String)> {
    let tail = &text[idx..];
    if !(tail.starts_with("http://") || tail.starts_with("https://")) {
        return None;
    }
    if !left_boundary(text, idx) {
        return None;
    }

    let mut end = idx;
    for (off, ch) in tail.char_indices() {
        if ch.is_whitespace() || matches!(ch, '<' | '"' | '\'') {
            break;
        }
        end = idx + off + ch.len_utf8();
    }
    end = trim_trailing_url_punctuation(text, idx, end);
    if end == idx {
        return None;
    }

    let url = &text[idx..end];
    Some((end, format!("<a href=\"{url}\">{url}</a>", url = url)))
}

fn trim_trailing_url_punctuation(text: &str, start: usize, mut end: usize) -> usize {
    while end > start {
        let Some(ch) = text[..end].chars().next_back() else {
            break;
        };
        if matches!(ch, '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}') {
            end -= ch.len_utf8();
        } else {
            break;
        }
    }
    end
}

fn try_issue_ref(text: &str, idx: usize, context: RenderContext<'_>) -> Option<(usize, String)> {
    if !text[idx..].starts_with('#') || !left_boundary(text, idx) {
        return None;
    }
    let start_digits = idx + 1;
    let mut end = start_digits;
    for (off, ch) in text[start_digits..].char_indices() {
        if ch.is_ascii_digit() {
            end = start_digits + off + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == start_digits {
        return None;
    }

    let n = &text[start_digits..end];
    Some((
        end,
        format!(
            "<a class=\"gfm-ref\" href=\"/r/{}/{}/issues/{}\">#{}</a>",
            escape_html(context.repo_owner),
            escape_html(context.repo_name),
            n,
            n
        ),
    ))
}

fn try_mention(text: &str, idx: usize) -> Option<(usize, String)> {
    if !text[idx..].starts_with('@') || !left_boundary(text, idx) {
        return None;
    }
    let start_name = idx + 1;
    let mut end = start_name;
    for (off, ch) in text[start_name..].char_indices() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            end = start_name + off + ch.len_utf8();
        } else {
            break;
        }
    }
    while end > start_name && text[..end].ends_with('.') {
        end -= '.'.len_utf8();
    }
    if end == start_name {
        return None;
    }

    let name = &text[start_name..end];
    Some((
        end,
        format!(
            "<a class=\"gfm-mention\" href=\"/users/{name}\">@{name}</a>",
            name = escape_html(name)
        ),
    ))
}

fn left_boundary(text: &str, idx: usize) -> bool {
    idx == 0
        || text[..idx]
            .chars()
            .next_back()
            .is_some_and(|c| !c.is_ascii_alphanumeric() && c != '_')
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
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
    fn fenced_code_block_is_highlighted_and_escaped() {
        let html = render("```rust\nfn main() { let x = \"</script><img src=x>\"; }\n```");
        assert!(html.contains("<code class=\"language-rust\">"));
        assert!(html.contains("<span class=\"tok-kw\">fn</span>"));
        assert!(!html.contains("</script>"));
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;/script&gt;&lt;img src=x&gt;"));
    }

    #[test]
    fn unknown_fenced_code_language_degrades_to_escaped_text() {
        let html = render("```wat\n<b>x</b>\n```");
        assert!(html.contains("<pre><code>"));
        assert!(!html.contains("<span class=\"tok-"));
        assert!(!html.contains("<b>x</b>"));
        assert!(html.contains("&lt;b&gt;x&lt;/b&gt;"));
    }

    #[test]
    fn suggestion_fence_renders_review_diff_card() {
        let html = render_for_repo_with_suggestion(
            "Try this:\n\n```suggestion\nnew <b>x</b>\n```",
            "alice",
            "proj",
            SuggestionContext { old: "old <x>" },
        );
        assert!(html.contains("class=\"suggestion\""));
        assert!(html.contains("class=\"suggestion__diff\""));
        assert!(html.contains("class=\"suggestion__old\""));
        assert!(html.contains("class=\"suggestion__new\""));
        assert!(html.contains("- old &lt;x&gt;"));
        assert!(html.contains("+ new &lt;b&gt;x&lt;/b&gt;"));
        assert!(!html.contains("<b>x</b>"));
    }

    #[test]
    fn suggestion_extractor_returns_first_suggestion_body() {
        let suggestion = extract_first_suggestion(
            "```rust\nfn main() {}\n```\n\n```suggestion\nlet x = 1;\n```",
        )
        .unwrap();
        assert_eq!(suggestion, "let x = 1;\n");
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
    fn renders_gfm_tables_task_lists_and_strikethrough() {
        let html =
            render("| item | state |\n| --- | --- |\n| ~~old~~ | <img src=x onerror=alert(1)> |\n\n- [ ] todo\n- [x] done");
        assert!(html.contains("<table class=\"md-table\">"));
        assert!(html.contains("<del>old</del>"));
        assert!(html.contains("class=\"task-list-item\""));
        assert!(html.contains("type=\"checkbox\" checked=\"\""));
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    #[test]
    fn autolinks_bare_http_urls_outside_code_and_links() {
        let html = render(
            "Visit https://example.test/a?x=1.\n\n`https://code.test`\n\n[ok](https://linked.test)\n\njavascript:alert(1)",
        );
        assert!(
            html.contains("<a href=\"https://example.test/a?x=1\">https://example.test/a?x=1</a>.")
        );
        assert!(html.contains("<code>https://code.test</code>"));
        assert!(html.contains("<a href=\"https://linked.test\">ok</a>"));
        assert!(!html.contains("href=\"javascript:"));
    }

    #[test]
    fn links_repo_refs_and_mentions_with_context() {
        let html = render_for_repo("Fixes #123 by @alice. `#456 @bob`", "own&er", "rep\"o");
        assert!(html.contains(
            "<a class=\"gfm-ref\" href=\"/r/own&amp;er/rep&quot;o/issues/123\">#123</a>"
        ));
        assert!(html.contains("<a class=\"gfm-mention\" href=\"/users/alice\">@alice</a>"));
        assert!(html.contains("<code>#456 @bob</code>"));
    }

    #[test]
    fn gfm_xss_payloads_stay_escaped() {
        let html = render_for_repo(
            "~~<script>alert(1)</script>~~\n\n| a |\n| --- |\n| <img src=x onerror=alert(1)> |\n\n[x](javascript:alert(1))",
            "owner",
            "repo",
        );
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("javascript:"));
        assert!(html.contains("<del>&lt;script&gt;alert(1)&lt;/script&gt;</del>"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("href=\"#\""));
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
