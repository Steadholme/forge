//! Lightweight server-side syntax highlighting for repository code views.
//!
//! The highlighter is intentionally small and dependency-free. It always escapes producer input
//! first, then tokenises that escaped text and inserts only fixed `<span class="tok-*">` hooks.

pub const MAX_HIGHLIGHT_BYTES: usize = 256 * 1024;
pub const MAX_HIGHLIGHT_LINES: usize = 2_000;

const DQ: &str = "&quot;";
const SQ: &str = "&#x27;";
const TDQ: &str = "&quot;&quot;&quot;";
const TSQ: &str = "&#x27;&#x27;&#x27;";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Language {
    Rust,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Json,
    Toml,
    Yaml,
    Shell,
    Html,
    Css,
    Markdown,
    Cpp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuoteKind {
    Double,
    Single,
    Backtick,
    TripleDouble,
    TripleSingle,
}

/// Highlight `source` as `lang`, returning HTML safe to embed inside an existing `<code>` tag.
///
/// Unknown languages and oversized sources degrade to plain escaped text.
pub fn highlight(source: &str, lang: &str) -> String {
    let escaped = escape_html(source);
    let Some((_, language)) = parse_lang(lang) else {
        return escaped;
    };
    if !within_highlight_limits(source) {
        return escaped;
    }
    highlight_escaped(&escaped, language)
}

/// True when a source is small enough for synchronous highlighting.
pub fn within_highlight_limits(source: &str) -> bool {
    source.len() <= MAX_HIGHLIGHT_BYTES
        && source.as_bytes().iter().filter(|b| **b == b'\n').count() < MAX_HIGHLIGHT_LINES
}

/// Canonical language class for a user-provided language name or extension.
pub fn normalize_lang(lang: &str) -> Option<&'static str> {
    parse_lang(lang).map(|(canonical, _)| canonical)
}

/// Infer a canonical language from a repository path.
pub fn language_for_path(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "cargo.toml" | "pyproject.toml" => return Some("toml"),
        "package.json" | "tsconfig.json" | "composer.json" => return Some("json"),
        "dockerfile" => return Some("shell"),
        _ => {}
    }
    if lower.ends_with(".d.ts") {
        return Some("ts");
    }
    let ext = lower.rsplit_once('.')?.1;
    normalize_lang(ext)
}

fn parse_lang(lang: &str) -> Option<(&'static str, Language)> {
    let key = lang_key(lang);
    match key.as_str() {
        "rs" | "rust" => Some(("rust", Language::Rust)),
        "js" | "jsx" | "mjs" | "cjs" | "javascript" => Some(("js", Language::JavaScript)),
        "ts" | "tsx" | "typescript" => Some(("ts", Language::TypeScript)),
        "py" | "pyw" | "python" | "python3" => Some(("python", Language::Python)),
        "go" | "golang" => Some(("go", Language::Go)),
        "json" => Some(("json", Language::Json)),
        "toml" => Some(("toml", Language::Toml)),
        "yaml" | "yml" => Some(("yaml", Language::Yaml)),
        "sh" | "bash" | "zsh" | "ksh" | "shell" => Some(("shell", Language::Shell)),
        "html" | "htm" | "xhtml" | "xml" => Some(("html", Language::Html)),
        "css" | "scss" | "sass" | "less" => Some(("css", Language::Css)),
        "md" | "markdown" | "mdown" => Some(("markdown", Language::Markdown)),
        "c" => Some(("c", Language::Cpp)),
        "h" | "cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh" | "c++" => Some(("cpp", Language::Cpp)),
        _ => None,
    }
}

fn lang_key(lang: &str) -> String {
    let token = lang
        .trim()
        .trim_start_matches('.')
        .trim_start_matches('{')
        .trim_start_matches('.')
        .split(|c: char| c.is_ascii_whitespace() || c == ',' || c == '}')
        .next()
        .unwrap_or_default();
    token
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '#' | '-' | '_'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn highlight_escaped(escaped: &str, language: Language) -> String {
    match language {
        Language::Html => highlight_html(escaped),
        Language::Css => highlight_css(escaped),
        Language::Markdown => highlight_markdown(escaped),
        _ => highlight_code(escaped, language),
    }
}

fn highlight_code(s: &str, language: Language) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    let mut i = 0;
    while i < s.len() {
        if let Some(end) = rust_attr_at(s, i, language) {
            push_span(&mut out, "tok-attr", &s[i..end]);
            i = end;
            continue;
        }
        if let Some(end) = python_decorator_at(s, i, language) {
            push_span(&mut out, "tok-attr", &s[i..end]);
            i = end;
            continue;
        }
        if let Some((class, end)) = comment_at(s, i, language) {
            push_span(&mut out, class, &s[i..end]);
            i = end;
            continue;
        }
        if let Some(kind) = quote_at(s, i, language) {
            let end = scan_string(s, i, kind);
            push_span(&mut out, "tok-str", &s[i..end]);
            i = end;
            continue;
        }
        if let Some(len) = entity_len_at(s, i) {
            out.push_str(&s[i..i + len]);
            i += len;
            continue;
        }
        let b = s.as_bytes()[i];
        if b.is_ascii_digit() {
            let end = scan_number(s, i);
            push_span(&mut out, "tok-num", &s[i..end]);
            i = end;
            continue;
        }
        if is_ident_start(language, b) {
            let end = scan_ident(s, i, language);
            let ident = &s[i..end];
            let class = if keywords(language).contains(&ident) {
                Some("tok-kw")
            } else if is_type_ident(language, ident) {
                Some("tok-type")
            } else if is_function_name(s, end) {
                Some("tok-fn")
            } else {
                None
            };
            if let Some(class) = class {
                push_span(&mut out, class, ident);
            } else {
                out.push_str(ident);
            }
            i = end;
            continue;
        }
        if is_punct(b) {
            let len = next_char_len(s, i);
            push_span(&mut out, "tok-punct", &s[i..i + len]);
            i += len;
            continue;
        }
        let len = next_char_len(s, i);
        out.push_str(&s[i..i + len]);
        i += len;
    }
    out
}

fn highlight_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    let mut i = 0;
    while i < s.len() {
        if starts_at(s, i, "&lt;!--") {
            let end = find_after(s, i + "&lt;!--".len(), "--&gt;").unwrap_or(s.len());
            push_span(&mut out, "tok-com", &s[i..end]);
            i = end;
            continue;
        }
        if starts_at(s, i, "&lt;") {
            out.push_str("&lt;");
            i += "&lt;".len();
            if starts_at(s, i, "/") {
                push_span(&mut out, "tok-punct", "/");
                i += 1;
            }
            let name_start = i;
            while i < s.len() {
                let b = s.as_bytes()[i];
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'!' | b':') {
                    i += 1;
                } else {
                    break;
                }
            }
            if i > name_start {
                push_span(&mut out, "tok-kw", &s[name_start..i]);
            }
            while i < s.len() && !starts_at(s, i, "&gt;") {
                if let Some(kind) = quote_at(s, i, Language::Html) {
                    let end = scan_string(s, i, kind);
                    push_span(&mut out, "tok-str", &s[i..end]);
                    i = end;
                    continue;
                }
                if let Some(len) = entity_len_at(s, i) {
                    out.push_str(&s[i..i + len]);
                    i += len;
                    continue;
                }
                let b = s.as_bytes()[i];
                if b.is_ascii_alphabetic() || matches!(b, b'_' | b':' | b'-') {
                    let start = i;
                    i += 1;
                    while i < s.len() {
                        let b = s.as_bytes()[i];
                        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-') {
                            i += 1;
                        } else {
                            break;
                        }
                    }
                    push_span(&mut out, "tok-attr", &s[start..i]);
                    continue;
                }
                if is_punct(b) {
                    let len = next_char_len(s, i);
                    push_span(&mut out, "tok-punct", &s[i..i + len]);
                    i += len;
                    continue;
                }
                let len = next_char_len(s, i);
                out.push_str(&s[i..i + len]);
                i += len;
            }
            if starts_at(s, i, "&gt;") {
                out.push_str("&gt;");
                i += "&gt;".len();
            }
            continue;
        }
        if let Some(len) = entity_len_at(s, i) {
            out.push_str(&s[i..i + len]);
            i += len;
            continue;
        }
        let len = next_char_len(s, i);
        out.push_str(&s[i..i + len]);
        i += len;
    }
    out
}

fn highlight_css(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    let mut i = 0;
    while i < s.len() {
        if let Some((class, end)) = comment_at(s, i, Language::Css) {
            push_span(&mut out, class, &s[i..end]);
            i = end;
            continue;
        }
        if let Some(kind) = quote_at(s, i, Language::Css) {
            let end = scan_string(s, i, kind);
            push_span(&mut out, "tok-str", &s[i..end]);
            i = end;
            continue;
        }
        if let Some(len) = entity_len_at(s, i) {
            out.push_str(&s[i..i + len]);
            i += len;
            continue;
        }
        if starts_at(s, i, "#") && next_byte(s, i + 1).is_some_and(|b| b.is_ascii_hexdigit()) {
            let end = scan_css_hash(s, i);
            push_span(&mut out, "tok-num", &s[i..end]);
            i = end;
            continue;
        }
        let b = s.as_bytes()[i];
        if b == b'@' {
            let end = scan_css_at_rule(s, i);
            push_span(&mut out, "tok-kw", &s[i..end]);
            i = end;
            continue;
        }
        if b.is_ascii_digit() {
            let end = scan_number(s, i);
            push_span(&mut out, "tok-num", &s[i..end]);
            i = end;
            continue;
        }
        if b.is_ascii_alphabetic() || b == b'-' || b == b'_' {
            let end = scan_css_ident(s, i);
            let ident = &s[i..end];
            let class = if css_keywords().contains(&ident) {
                Some("tok-kw")
            } else if next_non_ws_is(s, end, b':') {
                Some("tok-attr")
            } else if is_function_name(s, end) {
                Some("tok-fn")
            } else {
                None
            };
            if let Some(class) = class {
                push_span(&mut out, class, ident);
            } else {
                out.push_str(ident);
            }
            i = end;
            continue;
        }
        if is_punct(b) {
            let len = next_char_len(s, i);
            push_span(&mut out, "tok-punct", &s[i..i + len]);
            i += len;
            continue;
        }
        let len = next_char_len(s, i);
        out.push_str(&s[i..i + len]);
        i += len;
    }
    out
}

fn highlight_markdown(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    let mut i = 0;
    while i < s.len() {
        if starts_at(s, i, "&lt;!--") {
            let end = find_after(s, i + "&lt;!--".len(), "--&gt;").unwrap_or(s.len());
            push_span(&mut out, "tok-com", &s[i..end]);
            i = end;
            continue;
        }
        if is_line_start_after_spaces(s, i) && (starts_at(s, i, "```") || starts_at(s, i, "~~~")) {
            let end = scan_line(s, i);
            push_span(&mut out, "tok-punct", &s[i..end]);
            i = end;
            continue;
        }
        if is_line_start_after_spaces(s, i) && starts_at(s, i, "#") {
            let end = scan_repeated(s, i, b'#');
            if next_byte(s, end).is_some_and(|b| b.is_ascii_whitespace()) {
                push_span(&mut out, "tok-kw", &s[i..end]);
                i = end;
                continue;
            }
        }
        if let Some(kind) = quote_at(s, i, Language::Markdown) {
            let end = scan_string(s, i, kind);
            push_span(&mut out, "tok-str", &s[i..end]);
            i = end;
            continue;
        }
        if let Some(len) = entity_len_at(s, i) {
            out.push_str(&s[i..i + len]);
            i += len;
            continue;
        }
        let b = s.as_bytes()[i];
        if b.is_ascii_digit() {
            let end = scan_number(s, i);
            push_span(&mut out, "tok-num", &s[i..end]);
            i = end;
            continue;
        }
        if matches!(
            b,
            b'[' | b']' | b'(' | b')' | b'*' | b'_' | b'-' | b'>' | b'!'
        ) {
            let len = next_char_len(s, i);
            push_span(&mut out, "tok-punct", &s[i..i + len]);
            i += len;
            continue;
        }
        let len = next_char_len(s, i);
        out.push_str(&s[i..i + len]);
        i += len;
    }
    out
}

fn rust_attr_at(s: &str, i: usize, language: Language) -> Option<usize> {
    if language != Language::Rust || !(starts_at(s, i, "#[") || starts_at(s, i, "#![")) {
        return None;
    }
    find_after(s, i, "]").or(Some(s.len()))
}

fn python_decorator_at(s: &str, i: usize, language: Language) -> Option<usize> {
    if language != Language::Python || !starts_at(s, i, "@") || !is_line_start_after_spaces(s, i) {
        return None;
    }
    let mut end = i + 1;
    while end < s.len() {
        let b = s.as_bytes()[end];
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.') {
            end += 1;
        } else {
            break;
        }
    }
    (end > i + 1).then_some(end)
}

fn comment_at(s: &str, i: usize, language: Language) -> Option<(&'static str, usize)> {
    match language {
        Language::Rust
        | Language::JavaScript
        | Language::TypeScript
        | Language::Go
        | Language::Cpp => {
            if starts_at(s, i, "//") {
                Some(("tok-com", scan_line(s, i)))
            } else if starts_at(s, i, "/*") {
                Some(("tok-com", find_after(s, i + 2, "*/").unwrap_or(s.len())))
            } else {
                None
            }
        }
        Language::Css => {
            if starts_at(s, i, "/*") {
                Some(("tok-com", find_after(s, i + 2, "*/").unwrap_or(s.len())))
            } else {
                None
            }
        }
        Language::Python | Language::Toml | Language::Yaml => {
            starts_at(s, i, "#").then(|| ("tok-com", scan_line(s, i)))
        }
        Language::Shell => {
            if starts_at(s, i, "#")
                && (i == 0 || previous_char(s, i).is_some_and(char::is_whitespace))
            {
                Some(("tok-com", scan_line(s, i)))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn quote_at(s: &str, i: usize, language: Language) -> Option<QuoteKind> {
    let triple = language == Language::Python;
    if triple && starts_at(s, i, TDQ) {
        return Some(QuoteKind::TripleDouble);
    }
    if triple && starts_at(s, i, TSQ) {
        return Some(QuoteKind::TripleSingle);
    }
    if starts_at(s, i, DQ) && allows_double_quote(language) {
        return Some(QuoteKind::Double);
    }
    if starts_at(s, i, SQ) && allows_single_quote(language) {
        return Some(QuoteKind::Single);
    }
    if starts_at(s, i, "`") && allows_backtick(language) {
        return Some(QuoteKind::Backtick);
    }
    None
}

fn allows_double_quote(language: Language) -> bool {
    matches!(
        language,
        Language::Rust
            | Language::JavaScript
            | Language::TypeScript
            | Language::Python
            | Language::Go
            | Language::Json
            | Language::Toml
            | Language::Yaml
            | Language::Shell
            | Language::Html
            | Language::Css
            | Language::Cpp
    )
}

fn allows_single_quote(language: Language) -> bool {
    !matches!(language, Language::Json | Language::Markdown)
}

fn allows_backtick(language: Language) -> bool {
    matches!(
        language,
        Language::JavaScript
            | Language::TypeScript
            | Language::Go
            | Language::Shell
            | Language::Markdown
    )
}

fn scan_string(s: &str, start: usize, kind: QuoteKind) -> usize {
    let delim = match kind {
        QuoteKind::Double => DQ,
        QuoteKind::Single => SQ,
        QuoteKind::Backtick => "`",
        QuoteKind::TripleDouble => TDQ,
        QuoteKind::TripleSingle => TSQ,
    };
    let mut i = start + delim.len();
    while i < s.len() {
        if starts_at(s, i, delim) && !is_backslash_escaped(s, i) {
            return i + delim.len();
        }
        if let Some(len) = entity_len_at(s, i) {
            i += len;
        } else {
            i += next_char_len(s, i);
        }
    }
    s.len()
}

fn is_backslash_escaped(s: &str, i: usize) -> bool {
    let bytes = s.as_bytes();
    let mut count = 0;
    let mut j = i;
    while j > 0 && bytes[j - 1] == b'\\' {
        count += 1;
        j -= 1;
    }
    count % 2 == 1
}

fn scan_number(s: &str, start: usize) -> usize {
    let bytes = s.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.') {
            i += 1;
        } else if matches!(b, b'+' | b'-') && i > start && matches!(bytes[i - 1], b'e' | b'E') {
            i += 1;
        } else {
            break;
        }
    }
    i
}

fn scan_ident(s: &str, start: usize, language: Language) -> usize {
    let bytes = s.as_bytes();
    let mut i = start + 1;
    while i < bytes.len() && is_ident_continue(language, bytes[i]) {
        i += 1;
    }
    i
}

fn scan_line(s: &str, start: usize) -> usize {
    s[start..]
        .find('\n')
        .map(|off| start + off)
        .unwrap_or(s.len())
}

fn scan_repeated(s: &str, start: usize, b: u8) -> usize {
    let mut i = start;
    while i < s.len() && s.as_bytes()[i] == b {
        i += 1;
    }
    i
}

fn scan_css_hash(s: &str, start: usize) -> usize {
    let mut i = start + 1;
    while i < s.len() && s.as_bytes()[i].is_ascii_hexdigit() {
        i += 1;
    }
    i
}

fn scan_css_at_rule(s: &str, start: usize) -> usize {
    let mut i = start + 1;
    while i < s.len() {
        let b = s.as_bytes()[i];
        if b.is_ascii_alphabetic() || b == b'-' {
            i += 1;
        } else {
            break;
        }
    }
    i
}

fn scan_css_ident(s: &str, start: usize) -> usize {
    let mut i = start + 1;
    while i < s.len() {
        let b = s.as_bytes()[i];
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_') {
            i += 1;
        } else {
            break;
        }
    }
    i
}

fn is_ident_start(language: Language, b: u8) -> bool {
    b.is_ascii_alphabetic()
        || b == b'_'
        || (matches!(language, Language::JavaScript | Language::TypeScript) && b == b'$')
}

fn is_ident_continue(language: Language, b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b == b'_'
        || (matches!(language, Language::JavaScript | Language::TypeScript) && b == b'$')
}

fn is_function_name(s: &str, i: usize) -> bool {
    let mut j = i;
    while j < s.len() && matches!(s.as_bytes()[j], b' ' | b'\t' | b'\r') {
        j += 1;
    }
    starts_at(s, j, "(")
}

fn is_type_ident(language: Language, ident: &str) -> bool {
    ident
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_uppercase())
        || type_idents(language).contains(&ident)
}

fn next_non_ws_is(s: &str, i: usize, expected: u8) -> bool {
    let mut j = i;
    while j < s.len() && matches!(s.as_bytes()[j], b' ' | b'\t' | b'\r') {
        j += 1;
    }
    j < s.len() && s.as_bytes()[j] == expected
}

fn find_after(s: &str, start: usize, needle: &str) -> Option<usize> {
    s[start..]
        .find(needle)
        .map(|off| start + off + needle.len())
}

fn starts_at(s: &str, i: usize, needle: &str) -> bool {
    s.get(i..).is_some_and(|tail| tail.starts_with(needle))
}

fn next_byte(s: &str, i: usize) -> Option<u8> {
    s.as_bytes().get(i).copied()
}

fn previous_char(s: &str, i: usize) -> Option<char> {
    s[..i].chars().next_back()
}

fn next_char_len(s: &str, i: usize) -> usize {
    s[i..].chars().next().map(char::len_utf8).unwrap_or(1)
}

fn is_line_start_after_spaces(s: &str, i: usize) -> bool {
    let mut j = i;
    while j > 0 {
        let ch = s[..j].chars().next_back().unwrap();
        if ch == '\n' {
            return true;
        }
        if ch != ' ' && ch != '\t' {
            return false;
        }
        j -= ch.len_utf8();
    }
    true
}

fn entity_len_at(s: &str, i: usize) -> Option<usize> {
    [DQ, SQ, "&amp;", "&lt;", "&gt;"]
        .iter()
        .find(|entity| starts_at(s, i, entity))
        .map(|entity| entity.len())
}

fn is_punct(b: u8) -> bool {
    matches!(
        b,
        b'{' | b'}'
            | b'['
            | b']'
            | b'('
            | b')'
            | b'='
            | b'+'
            | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'!'
            | b','
            | b'.'
            | b':'
            | b';'
            | b'<'
            | b'>'
            | b'|'
            | b'&'
            | b'^'
            | b'~'
            | b'?'
            | b'@'
            | b'#'
            | b'$'
    )
}

fn push_span(out: &mut String, class: &'static str, text: &str) {
    out.push_str("<span class=\"");
    out.push_str(class);
    out.push_str("\">");
    out.push_str(text);
    out.push_str("</span>");
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

fn keywords(language: Language) -> &'static [&'static str] {
    match language {
        Language::Rust => &[
            "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
            "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
            "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super", "trait",
            "true", "type", "unsafe", "use", "where", "while",
        ],
        Language::JavaScript => &[
            "async",
            "await",
            "break",
            "case",
            "catch",
            "class",
            "const",
            "continue",
            "debugger",
            "default",
            "delete",
            "do",
            "else",
            "export",
            "extends",
            "false",
            "finally",
            "for",
            "from",
            "function",
            "if",
            "import",
            "in",
            "instanceof",
            "let",
            "new",
            "null",
            "of",
            "return",
            "static",
            "super",
            "switch",
            "this",
            "throw",
            "true",
            "try",
            "typeof",
            "undefined",
            "var",
            "void",
            "while",
            "yield",
        ],
        Language::TypeScript => &[
            "abstract",
            "as",
            "async",
            "await",
            "break",
            "case",
            "catch",
            "class",
            "const",
            "continue",
            "declare",
            "default",
            "delete",
            "do",
            "else",
            "enum",
            "export",
            "extends",
            "false",
            "finally",
            "for",
            "from",
            "function",
            "if",
            "implements",
            "import",
            "in",
            "interface",
            "keyof",
            "let",
            "namespace",
            "new",
            "null",
            "of",
            "private",
            "protected",
            "public",
            "readonly",
            "return",
            "static",
            "super",
            "switch",
            "this",
            "throw",
            "true",
            "try",
            "type",
            "typeof",
            "undefined",
            "var",
            "void",
            "while",
            "yield",
        ],
        Language::Python => &[
            "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del",
            "elif", "else", "except", "False", "finally", "for", "from", "global", "if", "import",
            "in", "is", "lambda", "None", "nonlocal", "not", "or", "pass", "raise", "return",
            "True", "try", "while", "with", "yield",
        ],
        Language::Go => &[
            "break",
            "case",
            "chan",
            "const",
            "continue",
            "default",
            "defer",
            "else",
            "fallthrough",
            "for",
            "func",
            "go",
            "goto",
            "if",
            "import",
            "interface",
            "map",
            "nil",
            "package",
            "range",
            "return",
            "select",
            "struct",
            "switch",
            "type",
            "var",
        ],
        Language::Json => &["false", "null", "true"],
        Language::Toml | Language::Yaml => &["false", "null", "true"],
        Language::Shell => &[
            "case", "do", "done", "elif", "else", "esac", "fi", "for", "function", "if", "in",
            "select", "then", "until", "while",
        ],
        Language::Cpp => &[
            "alignas",
            "alignof",
            "auto",
            "break",
            "case",
            "catch",
            "class",
            "const",
            "constexpr",
            "continue",
            "default",
            "delete",
            "do",
            "else",
            "enum",
            "extern",
            "false",
            "for",
            "goto",
            "if",
            "inline",
            "namespace",
            "new",
            "nullptr",
            "operator",
            "private",
            "protected",
            "public",
            "return",
            "sizeof",
            "static",
            "struct",
            "switch",
            "template",
            "this",
            "throw",
            "true",
            "try",
            "typedef",
            "typename",
            "union",
            "using",
            "virtual",
            "volatile",
            "while",
        ],
        _ => &[],
    }
}

fn type_idents(language: Language) -> &'static [&'static str] {
    match language {
        Language::Rust => &[
            "bool", "char", "f32", "f64", "i8", "i16", "i32", "i64", "i128", "isize", "str", "u8",
            "u16", "u32", "u64", "u128", "usize",
        ],
        Language::TypeScript => &[
            "any", "bigint", "boolean", "never", "number", "string", "unknown",
        ],
        Language::Go => &[
            "bool",
            "byte",
            "complex64",
            "complex128",
            "error",
            "float32",
            "float64",
            "int",
            "int8",
            "int16",
            "int32",
            "int64",
            "rune",
            "string",
            "uint",
            "uint8",
            "uint16",
            "uint32",
            "uint64",
            "uintptr",
        ],
        Language::Cpp => &[
            "bool", "char", "double", "float", "int", "long", "short", "signed", "unsigned",
            "void", "wchar_t",
        ],
        _ => &[],
    }
}

fn css_keywords() -> &'static [&'static str] {
    &[
        "absolute",
        "auto",
        "block",
        "border-box",
        "center",
        "flex",
        "grid",
        "hidden",
        "inherit",
        "inline",
        "none",
        "relative",
        "solid",
        "transparent",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_only_token_spans(html: &str) {
        let mut rest = html;
        while let Some(pos) = rest.find('<') {
            rest = &rest[pos..];
            assert!(
                rest.starts_with("<span class=\"tok-") || rest.starts_with("</span>"),
                "unexpected live tag in {html}"
            );
            let end = rest.find('>').expect("tag should close");
            rest = &rest[end + 1..];
        }
    }

    #[test]
    fn highlights_common_rust_tokens() {
        let html = highlight("#[derive(Debug)]\nfn main() { let n: u32 = 42; }\n", "rust");
        assert!(html.contains("<span class=\"tok-attr\">#[derive(Debug)]</span>"));
        assert!(html.contains("<span class=\"tok-kw\">fn</span>"));
        assert!(html.contains("<span class=\"tok-fn\">main</span>"));
        assert!(html.contains("<span class=\"tok-type\">u32</span>"));
        assert!(html.contains("<span class=\"tok-num\">42</span>"));
        assert_only_token_spans(&html);
    }

    #[test]
    fn escapes_active_html_before_highlighting() {
        let html = highlight("const x = \"</script><img src=x onerror=alert(1)>\";", "js");
        assert!(!html.contains("</script>"));
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("<span class=\"tok-str\">"));
        assert_only_token_spans(&html);
    }

    #[test]
    fn keeps_html_entities_contiguous() {
        let html = highlight("\" < > & '", "js");
        assert!(html.contains("&quot;"));
        assert!(html.contains("&lt;"));
        assert!(html.contains("&gt;"));
        assert!(html.contains("&amp;"));
        assert!(html.contains("&#x27;"));
        assert_only_token_spans(&html);
    }

    #[test]
    fn unclosed_string_and_comment_are_safe() {
        let unclosed_string = highlight("let s = \"<b>unterminated", "rust");
        assert!(!unclosed_string.contains("<b>"));
        assert!(unclosed_string.contains("&lt;b&gt;unterminated"));
        assert!(unclosed_string.ends_with("</span>"));
        assert_only_token_spans(&unclosed_string);

        let unclosed_comment = highlight("/* </script><img src=x>", "css");
        assert!(!unclosed_comment.contains("</script>"));
        assert!(!unclosed_comment.contains("<img"));
        assert!(unclosed_comment.contains("&lt;/script&gt;&lt;img src=x&gt;"));
        assert!(unclosed_comment.ends_with("</span>"));
        assert_only_token_spans(&unclosed_comment);
    }

    #[test]
    fn unknown_language_degrades_to_plain_escape() {
        let html = highlight("<b>x</b>", "wat");
        assert_eq!(html, "&lt;b&gt;x&lt;/b&gt;");
        assert!(!html.contains("<span"));
    }

    #[test]
    fn oversized_source_degrades_to_plain_escape() {
        let source = "let x = 1;\n".repeat(MAX_HIGHLIGHT_LINES + 1);
        let html = highlight(&source, "rust");
        assert!(html.contains("let x = 1;"));
        assert!(!html.contains("<span"));
    }

    #[test]
    fn infers_languages_from_paths() {
        assert_eq!(language_for_path("src/main.rs"), Some("rust"));
        assert_eq!(language_for_path("web/app.tsx"), Some("ts"));
        assert_eq!(language_for_path("README.md"), Some("markdown"));
        assert_eq!(language_for_path("Makefile"), None);
    }
}
