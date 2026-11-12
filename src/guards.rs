//! Wrapper-level guards that sit between detection and replacement.
//!
//! A guard drops a detected span that is not a sensitive value. The rules:
//!
//! 1. **Env-ref allowlist** — a span that overlaps an environment variable *reference* (`os.environ.get('DB_PASS')`, `process.env.X`, `$PIIF_SECRET_1`) is a false positive: the code names a secret, it does not contain one.
//! 2. **File-reference guard** — a span that lies entirely inside a `path/name.ext:line` reference (`auth.spec.ts:42`, `src/main.rs:10:5`) is a false positive.
//! 3. **User allowlist** — a span whose value matches one of the user's `allow` regexes (`config.toml`) is never redacted, whichever engine found it.
//! 4. **Shape guard** (model spans only, `suppress_model`) — a model span under 4 characters (`ab`, `=1`) is too short to be a secret and is dropped. The model sometimes takes identifiers, hashes, paths, numbers and plain words for secrets: session UUIDs in `~/.claude/projects/…`, git SHAs, image digests, upper-case ids (`C0ABC12DEF`), `sed -n '885,1150p'`, the `please` after a webhook URL. A model span that is wholly one of those shapes is dropped, unless a secret keyword sits right before it (`API_KEY=<uuid>`, `token: <hex>`). The span is judged with the whole token it sits in, since the model often marks part of one (`…-a6eb-f88f6b8694a9` of a UUID), and a span that crosses whitespace is dropped when each piece is such a shape (`for u in U01ABCDEF U02GHIJKL`, `mint endpoint`). A duration (`2m34s`, `7576.3ms`) or timestamp is dropped even after a keyword: CI tables print `pass 2m34s`, listings print `secret\t2026-10-30T…`. Pieces under 4 characters are fragments and do not count against a list. Host names, pod names and SVG path data are shapes too. A value is also dropped when its name says what it is: a URL query value under a name that is not secret-like (`?atlOrigin=eyJ…`), or a JSON value under an id-like key (`"slug":"…"`). A strong keyword on the two lines above counts only in key position (`"credentials": {`), not in prose or a table column. Stand-ins for a value (`sk-...`, `YOUR_API_KEY`, `***`, `••••`, `{b62:20}`) are dropped even after a keyword, and so is a span with no letter or digit (`{`, `": ["`). A gitleaks or key-rule match is never dropped by shape: its rule knows the format.

use regex::Regex;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Suppression {
    EnvReference,
    FileReference,
    Allowlist,
    Identifier,
    StandIn,
    Short,
}

impl Suppression {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnvReference => "env-ref-allowlist",
            Self::FileReference => "file-reference",
            Self::Allowlist => "allowlist",
            Self::Identifier => "identifier",
            Self::StandIn => "stand-in",
            Self::Short => "short",
        }
    }
}

pub struct Guards {
    env_ref: Regex,
    file_ref: Regex,
    allow: Vec<Regex>,
    /// Identifiers, hashes and paths.
    identifiers: Vec<Regex>,
    /// Numbers, versions, ranges, times and addresses.
    numbers: Vec<Regex>,
    /// Code: dropped even after a keyword, since `access_token: Token![:]` names a type, not a value.
    code: Vec<Regex>,
    /// A duration (`2m34s`, `7576.3ms`, `1h2m`): dropped even after a keyword, since CI tables print `pass 2m34s`.
    duration: Regex,
    /// A date or timestamp (`2026-10-30T12:34:56Z`): dropped even after a keyword, since listings print `secret\t2026-10-30T…` with the type in the column before.
    time: Regex,
    /// A word that names the id after it (`container`, `commit`, `request`), removed before matching the shapes.
    id_label: Regex,
    stand_in: Regex,
    /// A URL query parameter name that says its value is secret: `token`, `apiKey`, `X-Amz-Signature`, `code`.
    secret_param: Regex,
    /// A JSON key whose value names a thing rather than holding a secret: `"slug"`, `"id"`, `"sha"`.
    id_key: Regex,
    /// A secret keyword and its separator, ending right where the span starts.
    keyword_before: Regex,
    /// A strong secret keyword in key position on the two lines above the span's line: followed by `:`, `=`, `{` or the end of the line, as in `variable "API_KEY" {`, `"credentials": {`, `echo $API_KEY`. A keyword in prose or a table column (`=== token ===`, `secret\t2026-…`) does not count, and plain `key` is too common to count there.
    keyword_above: Regex,
}

/// Shortest model span kept, in characters, after the quotes and separators around it.
const SHORTEST: usize = 4;

/// Characters that wrap a value without being part of it: quotes, brackets, separators.
const LEADING: &[char] = &['"', '\'', '`', '(', '[', '<', '=', ':', ','];
const TRAILING: &[char] = &['"', '\'', '`', ')', ']', '>', ',', ';', '.'];

impl Guards {
    pub fn new() -> anyhow::Result<Self> {
        Self::with_allowlist(Vec::new())
    }

    /// Guards with the user's `allow` regexes (`Config::allow_patterns`).
    pub fn with_allowlist(allow: Vec<Regex>) -> anyhow::Result<Self> {
        let regexes = |patterns: &[&str]| -> anyhow::Result<Vec<Regex>> {
            patterns
                .iter()
                .map(|p| Regex::new(p).map_err(anyhow::Error::from))
                .collect()
        };
        Ok(Self {
            env_ref: Regex::new(
                r#"os\.environ\.get\(\s*['"][A-Za-z0-9_]+['"]\s*\)|os\.environ\[\s*['"][A-Za-z0-9_]+['"]\s*\]|os\.getenv\(\s*['"][A-Za-z0-9_]+['"]\s*\)|process\.env\.[A-Za-z0-9_]+|\$\{PIIF_[A-Za-z0-9_]+\}|\$PIIF_SECRET_[0-9]+|\$PIIF_[A-Za-z0-9_]+"#,
            )?,
            // name.ext:line[:col], optionally under a path; the extension is letters only.
            file_ref: Regex::new(
                r"(?:[\w.\-]+/)*[\w\-]+(?:\.[\w\-]+)*\.[A-Za-z]{1,6}:\d{1,6}(?::\d{1,4})?\b",
            )?,
            allow,
            identifiers: regexes(&[
                // UUID / GUID: 886dcfc3-25e8-420b-a6eb-f88f6b8694a9, {…}, urn:uuid:…
                r"^(?i:urn:uuid:)?\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?(?:\.[A-Za-z][A-Za-z0-9]{0,7})?$",
                // Hashes with their algorithm: sha256:…, @sha256:…, sha512-… (npm integrity), h1:… (go.sum)
                r"^@?(?i:sha1|sha224|sha256|sha384|sha512|md5|blake2b|blake3|h1)[:\-][A-Za-z0-9+/=_\-]+$",
                // Ids from the Anthropic and OpenAI APIs: toolu_…, msg_…, req_…, chatcmpl-…
                r"^(?:toolu|srvtoolu|msg|msgbatch|req|file|chatcmpl|asst|thread|run|call)[_\-][A-Za-z0-9]{8,}$",
                // AWS resource ids and ARNs: i-0abc…, vpc-…, sg-…, arn:aws:…
                r"^(?:i|vpc|subnet|sg|ami|vol|snap|eni|igw|nat|rtb|acl|eipalloc|lt|tgw|vpce|pcx|fs|fsmt)-[0-9a-f]{8,17}$",
                r"^arn:aws[\w\-]*:[\w\-]*:[\w\-]*:\d*:\S+$",
                // ULID: 26 Crockford base32 characters starting with a time digit
                r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
                // Kubernetes pod and replica set names: deployment-<hash>[-<5>]
                r"^[a-z][a-z0-9\-]*-[a-f0-9]{8,10}(?:-[a-z0-9]{5})?$",
                r"^[a-z][a-z0-9\-]*-[a-z0-9]{8,10}-[a-z0-9]{5}$",
                // Host names with at least three labels: api.eu.example.com, 5f3a…kq.sandbox.example.net
                r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,24}\.?$",
                // Image references by digest: ghcr.io/acme/api@sha256:…
                r"^[\w.\-/:]+@sha256:[0-9a-f]{64}$",
                // Checksum lines: <hash>  dist/app.tar.gz
                r"^[0-9a-f]{32,128}\s+\*?[\w.\-/]+$",
                // Absolute or home paths under a known root: /Users/…, ~/.claude/…, /tmp/…
                r"^(?:~|/(?:Users|home|tmp|private|var|etc|opt|usr|Library|Applications|Volumes|mnt|srv|root|workspace|app|src))/[\w.\-@+~/]*$",
                // Other paths: ./x, ../x, /x/y.ext, a/b/c.ext — a path ends in a file name with an extension
                r"^(?:\.{1,2}/|/|~/)(?:[\w.\-@+~]+/)*[\w.\-@+~]*\.[A-Za-z][A-Za-z0-9]{0,7}$",
                r"^(?:[\w.\-@+~]+/)+[\w.\-@+~]*\.[A-Za-z][A-Za-z0-9]{0,7}$",
                r"^\.{1,2}/[\w.\-@+~/]+$",
                // A file name with a content hash: index-3f9a1c2b.js, app.3f9a1c2b.css
                r"^[\w\-]+[.\-][0-9a-f]{6,}\.[A-Za-z][A-Za-z0-9]{0,7}$",
            ])?,
            code: regexes(&[
                // Paths and macros: token::Paren, Token![:]
                r"::|!\[",
                // Calls: next_placeholder(state, label);
                r"^[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*\([^()]*\);?$",
            ])?,
            duration: Regex::new(r"^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h|d))+$")?,
            // 2026-10-30T12:34:56.789Z, 2026-10-30 12:34:56+02:00
            time: Regex::new(
                r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+\-]\d{2}:?\d{2})?)?$",
            )?,
            numbers: regexes(&[
                // Numbers, ranges and sed addresses: 885,1150p, 45,60, 1-10, 3.14
                r"^\d[\d.,:/\-]*[A-Za-z]?$",
                // Versions: v1.24.3, 2.0.0-rc.1
                r"^v?\d+(?:\.\d+){1,3}(?:[\-+][\w.\-]+)?$",
                // IP addresses with an optional port
                r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$",
                // CSS colours
                r"^#[0-9A-Fa-f]{3,8}$",
                // A plain word: please, Deploy
                r"^[A-Za-z][a-z]+$",
            ])?,
            id_label: Regex::new(
                r"(?i)^(?:container|commit|image|digest|pod|request|trace|span|build|run|job|session|revision|rev|sha|id)\b[\s:#=]*",
            )?,
            stand_in: Regex::new(
                r"(?i)\.\.\.|…|[•*●]{3,}|x{4,}|\{\{|\$\{|\{[a-z0-9_:]*\}|<[^<>]+>|(?:^|[^a-z])(?:your|my)[_\-]?(?:api[_\-]?)?(?:key|token|secret|password|pass)|changeme|example|placeholder|dummy|redacted|(?:^|[^a-z])fake",
            )?,
            secret_param: Regex::new(
                r"(?i)token|jwt|secret|key|sig|pass|pwd|auth|credential|session|sid|code",
            )?,
            id_key: Regex::new(
                r#"(?:^|[^\w\\])\\?"(?:slug|id|sha|hash|digest|etag|uuid|name|title|ref)\\?"\s*:\s*\\?"$"#,
            )?,
            keyword_before: Regex::new(
                r#"(?i)(?:key|token|secret|passw(?:or)?d|pwd|pass|auth|bearer|credentials?|signature|sig)\w*["'\]]?\s*(?:=|:=|:|=>|>|\s+(?:(?:is|was|of)\s+)?)\s*["'`]?$"#,
            )?,
            keyword_above: Regex::new(
                r#"(?im)(?:^|[^a-z])(?:api[_\-]?key|access[_\-]?key|private[_\-]?key|secret|token|passw(?:or)?d|pwd|credentials?|bearer|signature)\w*[ \t"'`\]>)}]*(?::|\{|=(?:[^=]|$)|$)"#,
            )?,
        })
    }

    /// The env-reference guard. `end` is exclusive.
    fn references(&self, text: &str, start: usize, end: usize) -> Option<Suppression> {
        // Env ref: overlapping the reference syntax is enough (the model often
        // includes a leading space or drops the trailing quote/paren).
        if self
            .env_ref
            .find_iter(text)
            .any(|m| start < m.end() && m.start() < end)
        {
            return Some(Suppression::EnvReference);
        }
        None
    }

    /// `suppress`, plus the shape guard, which applies to model spans only.
    pub fn suppress_model(&self, text: &str, start: usize, end: usize) -> Option<Suppression> {
        if let Some(reason) = self.suppress(text, start, end) {
            return Some(reason);
        }
        // `{`, `"`, `": ["`: a span with no letter or digit holds no value.
        if !text.get(start..end)?.chars().any(char::is_alphanumeric) {
            return Some(Suppression::StandIn);
        }
        let (core_start, core) = core(text, start, end)?;
        // A short first piece (`Z` before `\n<hash>`) is the tail of the token before it: judge from the next piece.
        let (core_start, core) = skip_leading_fragment(core_start, core);
        let whole = text.get(start..end)?.trim();
        // Masks and fake-value words mark a stand-in secret.
        if self.stand_in.is_match(whole) || single_character(core) {
            return Some(Suppression::StandIn);
        }
        if core.chars().count() < SHORTEST {
            return Some(Suppression::Short);
        }
        // The value the span starts in, which a span reaching into the next parameter runs past.
        let (value_start, value) = token_around(text, core_start, core_start);
        if core_start + core.len() <= value_start + value.len()
            && self.names_a_thing(&text[..value_start])
        {
            return Some(Suppression::Identifier);
        }
        let (token_start, token) = token_around(text, core_start, core_start + core.len());
        if self
            .code
            .iter()
            .any(|r| r.is_match(core) || r.is_match(whole))
        {
            return Some(Suppression::Identifier);
        }
        if [core, token]
            .into_iter()
            .any(|value| self.duration.is_match(value) || self.time.is_match(value))
        {
            return Some(Suppression::Identifier);
        }
        // The model often takes the word that names the id along: `container 3f9a1c2b7d4e`.
        let bare = self.id_label.replace(core, "");
        let one_shape = [core, bare.as_ref(), token]
            .into_iter()
            .any(|value| self.is_identifier(value))
            || is_base64_blob(base64_run(text, core_start, core_start + core.len()));
        // A list (`U01ABCDEF U02GHIJKL`) or phrase (`mint endpoint`): every piece must be a shape.
        let all_pieces = core.contains(char::is_whitespace)
            && core
                .split_whitespace()
                .map(|piece| piece.trim_matches(LEADING).trim_matches(TRAILING))
                .all(|piece| piece.chars().count() < SHORTEST || self.is_identifier(piece));
        if !one_shape && !all_pieces {
            return None;
        }
        let core_start = token_start.min(core_start);
        // `API_KEY=<uuid>`, `token: <hex>`, `Bearer <id>`: the keyword says it is a secret.
        let line_start = text[..core_start].rfind('\n').map_or(0, |i| i + 1);
        let before = &text[line_start..core_start];
        let mut from = before.len().saturating_sub(64);
        while !before.is_char_boundary(from) {
            from += 1;
        }
        let before = &before[from..];
        if self.keyword_before.is_match(before) {
            return None;
        }
        let above_start = text[..line_start.saturating_sub(1)]
            .rmatch_indices('\n')
            .nth(1)
            .map_or(0, |(i, _)| i + 1);
        if self.keyword_above.is_match(&text[above_start..line_start]) {
            return None;
        }
        Some(Suppression::Identifier)
    }

    /// Whether `before`, the text up to a value, names the value as a thing rather than a secret: a URL query name that is not secret-like (`?atlOrigin=`, `&page=`), or an id-like JSON key (`"slug":"`).
    fn names_a_thing(&self, before: &str) -> bool {
        if let Some(rest) = before.strip_suffix('=') {
            let name_start = rest
                .char_indices()
                .rev()
                .find(|&(_, c)| !(c.is_ascii_alphanumeric() || "_.-".contains(c)))
                .map_or(0, |(i, c)| i + c.len_utf8());
            let name = &rest[name_start..];
            let opener = rest[..name_start].chars().next_back();
            return !name.is_empty()
                && matches!(opener, Some('?' | '&'))
                && !self.secret_param.is_match(name);
        }
        let mut from = before.len().saturating_sub(24);
        while !before.is_char_boundary(from) {
            from += 1;
        }
        self.id_key.is_match(&before[from..])
    }

    /// An identifier, hash, path, number, version, time, upper-case id or plain word: a shape that is not a secret by itself.
    fn is_identifier(&self, value: &str) -> bool {
        self.identifiers.iter().any(|r| r.is_match(value))
            || is_hex_hash(value)
            || is_upper_id(value)
            || self.duration.is_match(value)
            || self.time.is_match(value)
            || is_svg_path(value)
            || self.numbers.iter().any(|r| r.is_match(value))
    }

    /// Classify a detected span by the guards every engine's spans go through: env reference, allowlist and file reference. `end` is exclusive.
    pub fn suppress(&self, text: &str, start: usize, end: usize) -> Option<Suppression> {
        if let Some(reason) = self.references(text, start, end) {
            return Some(reason);
        }
        let span = text.get(start..end)?;
        if !self.allow.is_empty() {
            let value = span.trim();
            if self.allow.iter().any(|r| r.is_match(value)) {
                return Some(Suppression::Allowlist);
            }
        }
        // File reference: the span must lie entirely inside it, so a real secret
        // next to a location (`key=abc123 main.rs:4`) is still redacted. The model
        // often includes a leading space, so the span's edge whitespace is ignored.
        let start = start + (span.len() - span.trim_start().len());
        let end = end - (span.len() - span.trim_end().len());
        if start < end
            && self
                .file_ref
                .find_iter(text)
                .any(|m| start >= m.start() && end <= m.end())
        {
            return Some(Suppression::FileReference);
        }
        None
    }
}

/// The span without edge whitespace and the quotes, brackets and separators around the value, with its start offset.
fn core(text: &str, start: usize, end: usize) -> Option<(usize, &str)> {
    let span = text.get(start..end)?;
    let trimmed = span.trim_start().trim_start_matches(LEADING).trim_start();
    let core_start = start + (span.len() - trimmed.len());
    let core = trimmed.trim_end().trim_end_matches(TRAILING).trim_end();
    (!core.is_empty()).then_some((core_start, core))
}

/// The value without a first whitespace-separated piece under `SHORTEST` characters, when another piece follows.
fn skip_leading_fragment(start: usize, core: &str) -> (usize, &str) {
    let Some(i) = core.find(char::is_whitespace) else {
        return (start, core);
    };
    let rest = core[i..].trim_start();
    if core[..i].chars().count() < SHORTEST && !rest.is_empty() {
        (start + core.len() - rest.len(), rest)
    } else {
        (start, core)
    }
}

/// The token around `start..end`: extended over everything but whitespace, quotes, brackets, `\\` (an escaped quote in JSON text) and `,;=&?`, which end a value. Returns its start and text.
fn token_around(text: &str, start: usize, end: usize) -> (usize, &str) {
    let ends_value = |c: char| c.is_whitespace() || "\"'`()[]{}<>,;=&?\\".contains(c);
    let from = text[..start]
        .char_indices()
        .rev()
        .find(|&(_, c)| ends_value(c))
        .map_or(0, |(i, c)| i + c.len_utf8());
    let to = text[end..]
        .char_indices()
        .find(|&(_, c)| ends_value(c))
        .map_or(text.len(), |(i, _)| end + i);
    (from, &text[from..to])
}

/// An upper-case id, as chat, ticket and cloud APIs print them (`C0ABC12DEF`, `U01ABCDEF`): 8–14 upper-case letters and digits, with at least one digit and two letters.
fn is_upper_id(value: &str) -> bool {
    (8..=14).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().filter(char::is_ascii_uppercase).count() >= 2
}

/// A hash or hex id: git SHAs (7–40), md5, sha256, container ids, Mongo ObjectIds. One case, at least one digit and one letter, so a word or a number is not one; `0x` prefix allowed.
fn is_hex_hash(value: &str) -> bool {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    hex.len() >= 7
        && hex.chars().all(|c| c.is_ascii_hexdigit())
        && hex.chars().any(|c| c.is_ascii_digit())
        && hex.chars().any(|c| c.is_ascii_alphabetic())
        && !(hex.chars().any(|c| c.is_ascii_lowercase())
            && hex.chars().any(|c| c.is_ascii_uppercase()))
}

/// SVG path data (`M54.8,67.4c-1.9,0-3.5`, `9.2v3.4H87V02h7.2z`): path commands and numbers, with at least one command and one decimal.
fn is_svg_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value
        .chars()
        .all(|c| c.is_ascii_digit() || "MLHVCSQTAZmlhvcsqtaz.,-".contains(c))
        && value.chars().any(|c| c.is_ascii_alphabetic())
        && bytes
            .windows(3)
            .any(|w| w[0].is_ascii_digit() && w[1] == b'.' && w[2].is_ascii_digit())
}

/// Shortest base64 run taken for encoded data (an image, a file) rather than a key.
const BLOB: usize = 160;

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"+/=_-".contains(&b)
}

/// The run of base64 characters around `start..end`, which may run past the token (`<data>: parse error`).
fn base64_run(text: &str, start: usize, end: usize) -> &str {
    let bytes = text.as_bytes();
    let from = bytes[..start]
        .iter()
        .rposition(|&b| !is_base64_byte(b))
        .map_or(0, |i| i + 1);
    let to = bytes[end..]
        .iter()
        .position(|&b| !is_base64_byte(b))
        .map_or(bytes.len(), |i| end + i);
    &text[from.min(start)..to.max(end)]
}

/// Encoded data, as `base64 file` or an image payload prints it: at least `BLOB` base64 characters with a `+` or `/`. Keys are shorter; a long token such as an AWS session token comes after its name, which the keyword check catches.
fn is_base64_blob(value: &str) -> bool {
    value.len() >= BLOB
        && value.bytes().all(is_base64_byte)
        && value.bytes().any(|b| b == b'+' || b == b'/')
}

/// `aaaaaaaa`, `00000000`: one character repeated is a stand-in, not a value.
fn single_character(value: &str) -> bool {
    let mut chars = value.chars();
    let first = chars.next();
    value.chars().count() >= 4 && chars.all(|c| Some(c) == first)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guards() -> Guards {
        Guards::new().unwrap()
    }

    /// The shape guard's verdict on `needle` inside `text`.
    fn model(g: &Guards, text: &str, needle: &str) -> Option<Suppression> {
        let start = text
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} in {text}"));
        g.suppress_model(text, start, start + needle.len())
    }

    #[test]
    fn short_model_spans_are_dropped() {
        let g = guards();
        assert_eq!(model(&g, "pw: 'ab1'", "'ab1'"), Some(Suppression::Short));
        assert_eq!(model(&g, "PASSWORD=x9", "x9"), Some(Suppression::Short));
        assert_eq!(model(&g, "PASSWORD=x9Qz", "x9Qz"), None);
    }

    #[test]
    fn spans_inside_base64_data_are_dropped_unless_named() {
        let g = guards();
        let blob = "iVBORw0KGgoAAAANSUhEUgAAA+/kQ7".repeat(7);
        let dump = format!("$ base64 chart.png\n{blob}\n");
        assert_eq!(
            model(&g, &dump, &blob[40..90]),
            Some(Suppression::Identifier)
        );
        let glued = format!("{blob}: parse error at line 3");
        assert_eq!(
            model(&g, &glued, &blob[40..90]),
            Some(Suppression::Identifier)
        );
        let named = format!("aws_session_token = {blob}");
        assert_eq!(model(&g, &named, &blob[40..90]), None);
        let short = &blob[..120];
        assert_eq!(
            model(&g, &format!("data {short} end"), &short[10..60]),
            None
        );
    }

    #[test]
    fn env_reference_span_is_suppressed() {
        let g = guards();
        let text = "password = os.environ.get('DB_PASS')";
        // model span includes the leading space and stops before the closing quote
        assert_eq!(g.suppress(text, 10, 34), Some(Suppression::EnvReference));
    }

    #[test]
    fn env_reference_variants() {
        let g = guards();
        for (text, needle) in [
            ("password = os.environ.get(\"DB_PASS\")", "os"),
            ("password = os.environ['DB_PASSWORD']", "os"),
            ("password = os.getenv('DB_PASS')", "os"),
            ("api_key = process.env.OPENAI_API_KEY", "process"),
        ] {
            let span = text.find(needle).unwrap();
            assert_eq!(
                g.suppress(text, span, text.len()),
                Some(Suppression::EnvReference),
                "{text}"
            );
        }
    }

    #[test]
    fn pif_env_reference_is_suppressed() {
        let g = guards();
        let text = "use this API key $PIIF_SECRET_1";
        let start = text.find("$PIIF_SECRET_1").unwrap();
        assert_eq!(
            g.suppress(text, start, text.len()),
            Some(Suppression::EnvReference)
        );
    }

    #[test]
    fn braced_pif_env_reference_is_suppressed() {
        let g = guards();
        let reference = format!("${{PIIF_SECRET_{}}}", 1);
        let text = format!("use this API key {reference}x");
        let start = text.find(&reference).unwrap();
        assert_eq!(
            g.suppress(&text, start, text.len()),
            Some(Suppression::EnvReference)
        );
    }

    #[test]
    fn text_glued_after_a_bare_name_is_not_part_of_the_reference() {
        let g = guards();
        let reference = format!("$PIIF_SECRET_{}", 7);
        let text = format!("use {reference}tail now");
        let start = text.find(&reference).unwrap();
        let tail = start + reference.len();
        assert_eq!(
            g.suppress(&text, start, tail),
            Some(Suppression::EnvReference)
        );
        assert_eq!(g.suppress(&text, tail, tail + 4), None);
    }

    #[test]
    fn file_reference_secret_is_suppressed() {
        let g = guards();
        for (text, needle) in [
            (
                "Fails at `auth.spec.ts:42`: expected 200",
                "auth.spec.ts:42",
            ),
            (
                "see src/hooks/session.ts:40 for the bug",
                "src/hooks/session.ts:40",
            ),
            ("error at src/main.rs:10:5", "src/main.rs:10:5"),
            // The model often starts the span at the space before the reference.
            ("deploy at src/main.rs:10", " src/main.rs:10"),
        ] {
            let start = text.find(needle).unwrap();
            let end = start + needle.len();
            assert_eq!(
                g.suppress(text, start, end),
                Some(Suppression::FileReference),
                "{text}"
            );
        }
    }

    #[test]
    fn file_reference_guard_is_narrow() {
        let g = guards();
        // A real secret beside a location is not inside it.
        let text = "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 main.rs:4";
        let start = text.find("ghp_").unwrap();
        assert_eq!(g.suppress(text, start, start + 40), None);
        // Password after a colon is not a line number.
        let text = "login admin.user:hunter2";
        let start = text.find("admin").unwrap();
        assert_eq!(g.suppress(text, start, text.len()), None);
    }

    #[test]
    fn real_secrets_are_not_suppressed() {
        let g = guards();
        let text = "Here is my AWS key: AKIAIOSFODNN7EXAMPLE";
        let start = text.find("AKIA").unwrap();
        assert_eq!(g.suppress(text, start, text.len()), None);

        let text = "postgres://admin:hunter2@db.internal:5432/prod";
        let start = text.find(":hunter2").unwrap();
        assert_eq!(g.suppress(text, start, start + 8), None);
    }

    #[test]
    fn identifiers_from_the_model_are_dropped() {
        let g = guards();
        for (text, needle) in [
            ("cd ~/.claude/projects/-Users-me-app/886dcfc3-25e8-420b-a6eb-f88f6b8694a9/scripts", "886dcfc3-25e8-420b-a6eb-f88f6b8694a9"),
            ("guid {886DCFC3-25E8-420B-A6EB-F88F6B8694A9}", "{886DCFC3-25E8-420B-A6EB-F88F6B8694A9}"),
            ("cat ~/.claude/projects/-Users-me-app/f50046b7-1b54-4ac1-b9af-5c8a8b1a3705.jsonl", "/f50046b7-1b54-4ac1-b9af-5c8a8b1a3705.jsonl"),
            ("cat ~/.claude/projects/-Users-me-app/f50046b7-1b54-4ac1-b9af-5c8a8b1a3705.jsonl", "~/.claude/projects/-Users-me-app/f50046b7-1b54-4ac1-b9af-5c8a8b1a3705.jsonl"),
            ("Reverted in commit 3f9a1c2b7d4e5f60718293a4b5c6d7e8f9012345", "3f9a1c2b7d4e5f60718293a4b5c6d7e8f9012345"),
            ("see 3f9a1c2 for the fix", "3f9a1c2"),
            ("hex = '0123456789abcdef'", "'0123456789abcdef'"),
            ("image: ghcr.io/acme/api@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
            ("\"integrity\": \"sha512-q83vEjo2ab+cd/Ef==\"", "\"sha512-q83vEjo2ab+cd/Ef==\""),
            ("tool_use_id: toolu_01AbCdEfGhIjKlMnOpQrStUv", "toolu_01AbCdEfGhIjKlMnOpQrStUv"),
            ("request id req_011CabcdefGHIJKLmnop was rate limited", "req_011CabcdefGHIJKLmnop"),
            ("instance i-0abc123def4567890 stopped", "i-0abc123def4567890"),
            ("id 01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            ("pod api-7d9f8b6c5-x2kqp is Running", "api-7d9f8b6c5-x2kqp"),
            ("dist/assets/index-3f9a1c2b.js", "dist/assets/index-3f9a1c2b.js"),
            ("sed -n '885,1150p' log.jsonl", "885,1150p"),
            ("upgraded to 2.0.0-rc.1", "2.0.0-rc.1"),
            ("started at 2026-10-30T12:34:56.789Z", "2026-10-30T12:34:56.789Z"),
            ("listening on 127.0.0.1:8080", "127.0.0.1:8080"),
            ("SLACK_WEBHOOK_URL=https://hooks.example/T0/B0/x9 please", "please"),
            ("colon_token: Token![:],", "Token![:]"),
            ("let token = next_value(state, label);", "next_value(state, label);"),
        ] {
            assert_eq!(model(&g, text, needle), Some(Suppression::Identifier), "{needle}");
        }
    }

    #[test]
    fn spans_that_run_past_the_id_are_dropped() {
        let g = guards();
        for (text, needle) in [
            ("container 3f9a1c2b7d4e exited with code 0", "container 3f9a1c2b7d4e"),
            (
                "image: ghcr.io/acme/api@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "ghcr.io/acme/api@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            ),
            ("pod api-7d9f8b6c5-x2kqp is Running", "api-7d9f8b6c5"),
            (
                "9f86d081884c7d659a2feaa0c55ad015  dist/app.tar.gz",
                "9f86d081884c7d659a2feaa0c55ad015  dist/app.tar.gz",
            ),
        ] {
            assert_eq!(
                model(&g, text, needle),
                Some(Suppression::Identifier),
                "{needle}"
            );
        }
    }

    #[test]
    fn stand_ins_are_dropped_even_after_a_keyword() {
        let g = guards();
        for (text, needle) in [
            ("use a key like sk-... from the dashboard", "sk-..."),
            ("API_KEY=YOUR_API_KEY_HERE", "YOUR_API_KEY_HERE"),
            ("TOKEN=<your-token>", "<your-token>"),
            ("password: ********", "********"),
            ("token: ••••••••", "••••••••"),
            ("SECRET=xxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxx"),
            ("key = \"sk-{b62:20}\"", "sk-{b62:20}"),
            ("name = \"piifence-example\"", "piifence-example"),
            ("DB_PASSWORD=changeme", "changeme"),
        ] {
            assert_eq!(
                model(&g, text, needle),
                Some(Suppression::StandIn),
                "{needle}"
            );
        }
    }

    #[test]
    fn a_span_without_letters_or_digits_is_dropped() {
        let g = guards();
        let text = r#""secret": {"categories": ["secret"]}"#;
        for needle in ["{", "\"", "\": [\"", "}"] {
            assert_eq!(
                model(&g, text, needle),
                Some(Suppression::StandIn),
                "{needle}"
            );
        }
        assert_eq!(model(&g, "密码：口令是密钥", "口令是密钥"), None);
    }

    #[test]
    fn a_keyword_keeps_an_identifier_shaped_secret() {
        let g = guards();
        for (text, needle) in [
            (
                "HEROKU_API_KEY=886dcfc3-25e8-420b-a6eb-f88f6b8694a9",
                "886dcfc3-25e8-420b-a6eb-f88f6b8694a9",
            ),
            (
                "api_key: \"9f86d081884c7d659a2feaa0c55ad015\"",
                "9f86d081884c7d659a2feaa0c55ad015",
            ),
            (
                "Authorization: Bearer 9f86d081884c7d659a2feaa0c55ad015",
                "9f86d081884c7d659a2feaa0c55ad015",
            ),
            ("password = 48291734", "48291734"),
            ("password: sunshine", "sunshine"),
            (
                "the token is 9f86d081884c7d659a2feaa0c55ad015",
                "9f86d081884c7d659a2feaa0c55ad015",
            ),
        ] {
            assert_eq!(model(&g, text, needle), None, "{text}");
        }
        // A span that is more than the identifier is not an identifier.
        let key = "key=886dcfc3-25e8-420b-a6eb-f88f6b8694a9";
        assert_eq!(g.suppress_model(key, 0, key.len()), None);
    }

    #[test]
    fn a_keyword_on_the_lines_above_keeps_the_value() {
        let g = guards();
        let hex = "9f86d081884c7d659a2feaa0c55ad015";
        for text in [
            "<config><API_KEY>9f86d081884c7d659a2feaa0c55ad015</API_KEY></config>",
            "variable \"API_KEY\" {\n  default = \"9f86d081884c7d659a2feaa0c55ad015\"\n}",
            "{\n  \"credentials\": {\n    \"value\": \"9f86d081884c7d659a2feaa0c55ad015\"",
            "Tool call: Bash {\"command\":\"echo $API_KEY\"}\nTool output:\n9f86d081884c7d659a2feaa0c55ad015",
        ] {
            assert_eq!(model(&g, text, hex), None, "{text}");
        }
    }

    #[test]
    fn a_keyword_further_up_does_not_count() {
        let g = guards();
        // Three lines up, or plain `key` on the line above: still an id.
        let text = "token: abc\nx\ny\ncommit 3f9a1c2b7d4e5f60718293a4b5c6d7e8f9012345";
        assert_eq!(
            model(&g, text, "3f9a1c2b7d4e5f60718293a4b5c6d7e8f9012345"),
            Some(Suppression::Identifier)
        );
        let text = "primary key\n886dcfc3-25e8-420b-a6eb-f88f6b8694a9";
        assert_eq!(
            model(&g, text, "886dcfc3-25e8-420b-a6eb-f88f6b8694a9"),
            Some(Suppression::Identifier)
        );
    }

    #[test]
    fn a_keyword_above_in_prose_or_a_column_does_not_count() {
        let g = guards();
        let text =
            "=== review panel token ===\n  38 chars\naccount: 886dcfc3-25e8-420b-a6eb-f88f6b8694a9";
        assert_eq!(
            model(&g, text, "886dcfc3-25e8-420b-a6eb-f88f6b8694a9"),
            Some(Suppression::Identifier)
        );
        let text = "a1b2c3d\tplan\t2 files\tsecret\t2026-10-30T12:34:56Z\n9f86d081884c7d659a2feaa0c55ad015\tplan";
        assert_eq!(
            model(&g, text, "9f86d081884c7d659a2feaa0c55ad015"),
            Some(Suppression::Identifier)
        );
    }

    #[test]
    fn timestamps_and_fragments_in_a_listing_are_dropped() {
        let g = guards();
        let text = "a1b2c3d\tplan\t8 file\tsecret\t2026-10-30T12:34:56Z\n9f86d081884c7d659a2feaa0c55ad015\tplan";
        assert_eq!(
            model(&g, text, "2026-10-30T12"),
            Some(Suppression::Identifier)
        );
        assert_eq!(
            model(&g, text, "Z\n9f86d081884c7d659a2feaa0c55ad015"),
            Some(Suppression::Identifier)
        );
    }

    #[test]
    fn svg_path_data_is_an_identifier() {
        let g = guards();
        let text = "d=\"M40.8,16.6c-6.9,0-3.5,8.5-2.0,9.2v3.4H87V02h7.2v55h9.9V15H79z\"";
        assert_eq!(
            model(&g, text, "2v3.4H87V02h7.2v55h9.9V15H79z"),
            Some(Suppression::Identifier)
        );
        assert!(!is_svg_path("password"));
        assert!(!is_svg_path("a1b2c3"));
    }

    #[test]
    fn host_and_pod_names_are_identifiers() {
        let g = guards();
        let text = r#"["Access to \"5f3akq9x2m7zp4w1.sandbox.example.net\" is blocked"]"#;
        assert_eq!(
            model(&g, text, "kq9x2m7zp4w1"),
            Some(Suppression::Identifier)
        );
        let text = "      1 ai-content-35p690w7oy-u1f8q ERROR JWT validation error";
        assert_eq!(
            model(&g, text, "content-35p690w7oy-u1f8q"),
            Some(Suppression::Identifier)
        );
    }

    #[test]
    fn a_value_named_as_a_thing_is_dropped() {
        let g = guards();
        let blob = "eyJzb3VyY2UiOiJlbWFpbCIsIm1lZGl1bSI6ImxpbmsifQ";
        // A tracking parameter or a JSON slug names a thing.
        for text in [
            format!("see https://acme.atlassian.net/browse/IF-1?atlOrigin={blob}\n"),
            format!("<https://acme.atlassian.net/browse/IF-1?page=2&xpis={blob}|IF-1>"),
            format!("{{\"node_label\":\"Release\",\"slug\":\"{blob}\",\"name\":\"x\"}}"),
            format!("{{\\\"slug\\\":\\\"{blob}\\\"}}"),
            format!("ссылка?атл=1&page={blob}"),
        ] {
            assert_eq!(
                model(&g, &text, blob),
                Some(Suppression::Identifier),
                "{text}"
            );
        }
        // A secret-like parameter or key, or a span that runs into the next parameter, is judged as usual.
        for text in [
            format!("https://app.example.com/?companionToken={blob}&user"),
            format!("https://app.example.com/?code={blob}"),
            format!("ссылка→token={blob}"),
            format!("{{\"client_secret\":\"{blob}\"}}"),
        ] {
            assert_eq!(model(&g, &text, blob), None, "{text}");
        }
        let text = format!("https://app.example.com/?atlOrigin={blob}&t=AbC9dEf8");
        assert_eq!(model(&g, &text, &format!("{blob}&t=AbC9dEf8")), None);
    }

    #[test]
    fn real_secrets_are_not_shapes() {
        let g = guards();
        for (text, needle) in [
            (
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            ),
            ("login with Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("pw aB3.xYz9kLm2Qw", "aB3.xYz9kLm2Qw"),
            (
                "blob /9j/4AAQSkZJRgABAQEASABIAAD",
                "/9j/4AAQSkZJRgABAQEASABIAAD",
            ),
            ("mixed 9F86d081884C7d659a2feaa0", "9F86d081884C7d659a2feaa0"),
            (
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def456",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def456",
            ),
        ] {
            assert_eq!(model(&g, text, needle), None, "{needle}");
        }
    }

    #[test]
    fn gitleaks_spans_are_not_checked_for_shape() {
        let g = guards();
        let text = "/Users/me/.claude/projects/x/886dcfc3-25e8-420b-a6eb-f88f6b8694a9/scripts";
        let start = text.find("886d").unwrap();
        assert_eq!(g.suppress(text, start, start + 36), None);
    }

    #[test]
    fn durations_are_dropped_even_after_pass() {
        let g = guards();
        for (text, needle) in [
            (
                "test / fallow\tpass\t2m34s\thttps://ci.example/run/1",
                "2m34s",
            ),
            ("Forward pass: 7576.3ms", "7576.3ms"),
            ("lint\tpass\t1h2m3s", "1h2m3s"),
        ] {
            assert_eq!(
                model(&g, text, needle),
                Some(Suppression::Identifier),
                "{text}"
            );
        }
    }

    #[test]
    fn upper_case_ids_are_identifiers() {
        let g = guards();
        for (text, needle) in [
            ("SLACK_CHANNEL = 'C0ABC12DEF'", "C0ABC12DEF"),
            ("--channel D0XYZ9QWE1 --limit 20", "D0XYZ9QWE1"),
            ("\"recipient\":\"U01ABCDEF\"", "U01ABCDEF"),
        ] {
            assert_eq!(
                model(&g, text, needle),
                Some(Suppression::Identifier),
                "{text}"
            );
        }
        // After a secret keyword it is a value.
        assert_eq!(model(&g, "password: K7X9P2M4Q1", "K7X9P2M4Q1"), None);
    }

    #[test]
    fn a_span_is_judged_with_its_whole_token() {
        let g = guards();
        // The model marks the tail of a UUID or the end of an upper-case id.
        assert_eq!(
            model(
                &g,
                "account: d014e9e6-2a28-45fb-a1c1-bd0123456789",
                "a1c1-bd0123456789"
            ),
            Some(Suppression::Identifier)
        );
        assert_eq!(
            model(&g, "SLACK_CHANNEL = 'C0ABC12DEF'", "ABC12DEF"),
            Some(Suppression::Identifier)
        );
        // Part of a token that is not an id shape stays a finding.
        assert_eq!(
            model(&g, "url ?sig=Xk9pQ2vL7mN4rT8wZ1yB5cD3", "Xk9pQ2vL7mN4"),
            None
        );
    }

    #[test]
    fn a_span_across_whitespace_is_dropped_when_every_piece_is_a_shape() {
        let g = guards();
        for (text, needle) in [
            (
                "for u in U01ABCDEF U02GHIJKL U03MNOPQR; do",
                "U01ABCDEF U02GHIJKL U03MNOPQR",
            ),
            ("where we can use mint endpoint b/c", "mint endpoint"),
            (
                "form ids: 522015471 889997274 278312160",
                "522015471 889997274 278312160",
            ),
        ] {
            assert_eq!(
                model(&g, text, needle),
                Some(Suppression::Identifier),
                "{text}"
            );
        }
        // One random-looking piece keeps the span.
        assert_eq!(
            model(&g, "use mint aB3xYz9kLm2Qw", "mint aB3xYz9kLm2Qw"),
            None
        );
        // A keyword before a phrase keeps it: a passphrase.
        assert_eq!(
            model(
                &g,
                "password: correct horse battery",
                "correct horse battery"
            ),
            None
        );
    }

    #[test]
    fn allowlist_drops_matching_values_from_any_engine() {
        let g = Guards::with_allowlist(vec![Regex::new(r"^PROJ-\d+$").unwrap()]).unwrap();
        let text = "fixed in PROJ-1234 today";
        let start = text.find("PROJ").unwrap();
        assert_eq!(
            g.suppress(text, start, start + 9),
            Some(Suppression::Allowlist)
        );
        assert_eq!(g.suppress("PROJ-12x", 0, 8), None);
    }
}
