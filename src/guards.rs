//! Wrapper-level guards that sit between detection and replacement.
//!
//! A guard drops a detected span that is not a sensitive value. The rules:
//!
//! 1. **Placeholder skip guard** — never redact a placeholder the gateway already produced (`<private_email_1>`, `<secret_1>`; corpus case `sec-05`).
//! 2. **Env-ref allowlist** — a span that overlaps an environment variable *reference* (`os.environ.get('DB_PASS')`, `process.env.X`, `$PIIF_SECRET_1`) is a false positive: the code names a secret, it does not contain one.
//! 3. **File-reference guard** — a span that lies entirely inside a `path/name.ext:line` reference (`auth.spec.ts:42`, `src/main.rs:10:5`) is a false positive. Every label but `private_url`, so `host.com:8080` stays detectable as a URL.
//! 4. **User allowlist** — a span whose value matches one of the user's `allow` regexes (`config.toml`) is never redacted, whichever engine found it.
//! 5. **Shape guard** (model spans only, `suppress_model`) — the model labels identifiers, hashes, paths and numbers `secret`: session UUIDs in `~/.claude/projects/…`, git SHAs, image digests, `sed -n '885,1150p'`. A model span that is wholly one of those shapes is dropped, unless a secret keyword sits right before it (`API_KEY=<uuid>`, `token: <hex>`). Stand-ins for a value (`sk-...`, `YOUR_API_KEY`, `***`, `••••`, `{b62:20}`) are dropped even after a keyword. A gitleaks match is never dropped by shape: its rule knows the format.

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Suppression {
    Placeholder,
    EnvReference,
    FileReference,
    Allowlist,
    Identifier,
    StandIn,
}

impl Suppression {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Placeholder => "placeholder",
            Self::EnvReference => "env-ref-allowlist",
            Self::FileReference => "file-reference",
            Self::Allowlist => "allowlist",
            Self::Identifier => "identifier",
            Self::StandIn => "stand-in",
        }
    }
}

pub struct Guards {
    placeholder: Regex,
    env_ref: Regex,
    file_ref: Regex,
    allow: Vec<Regex>,
    /// Identifiers, hashes and paths: dropped for every label.
    identifiers: Vec<Regex>,
    /// Numbers, versions, ranges, times and addresses: dropped for the `secret` label only, since `account_number`, `private_phone` and `private_date` are numbers by nature.
    numbers: Vec<Regex>,
    /// Code: dropped even after a keyword, since `access_token: Token![:]` names a type, not a value.
    code: Vec<Regex>,
    /// A word that names the id after it (`container`, `commit`, `request`), removed before matching the shapes.
    id_label: Regex,
    stand_in: Regex,
    /// A secret keyword and its separator, ending right where the span starts.
    keyword_before: Regex,
    /// A strong secret keyword anywhere on the two lines above the span's line: `variable "API_KEY" {`, `"credentials": {`, `echo $API_KEY`. Plain `key` is too common to count there.
    keyword_above: Regex,
}

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
            // <private_email_1>, <secret_1>
            placeholder: Regex::new(r"<(?:private_)?[a-z_]+_\d+>")?,
            env_ref: Regex::new(
                r#"os\.environ\.get\(\s*['"][A-Za-z0-9_]+['"]\s*\)|os\.environ\[\s*['"][A-Za-z0-9_]+['"]\s*\]|os\.getenv\(\s*['"][A-Za-z0-9_]+['"]\s*\)|process\.env\.[A-Za-z0-9_]+|\$PIIF_[A-Za-z0-9_]+"#,
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
            numbers: regexes(&[
                // Numbers, ranges and sed addresses: 885,1150p, 45,60, 1-10, 3.14
                r"^\d[\d.,:/\-]*[A-Za-z]?$",
                // Versions: v1.24.3, 2.0.0-rc.1
                r"^v?\d+(?:\.\d+){1,3}(?:[\-+][\w.\-]+)?$",
                // Times: 2026-10-30T12:34:56.789Z, 2026-10-30 12:34:56+02:00
                r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+\-]\d{2}:?\d{2})?)?$",
                // IP addresses with an optional port
                r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$",
                // CSS colours
                r"^#[0-9A-Fa-f]{3,8}$",
            ])?,
            id_label: Regex::new(
                r"(?i)^(?:container|commit|image|digest|pod|request|trace|span|build|run|job|session|revision|rev|sha|id)\b[\s:#=]*",
            )?,
            stand_in: Regex::new(
                r"(?i)\.\.\.|…|[•*●]{3,}|x{4,}|\{\{|\$\{|\{[a-z0-9_:]*\}|<[^<>]+>|(?:^|[^a-z])(?:your|my)[_\-]?(?:api[_\-]?)?(?:key|token|secret|password|pass)|changeme|example|placeholder|dummy|redacted|(?:^|[^a-z])fake",
            )?,
            keyword_before: Regex::new(
                r#"(?i)(?:key|token|secret|passw(?:or)?d|pwd|pass|auth|bearer|credentials?|signature|sig)\w*["'\]]?\s*(?:=|:=|:|=>|>|\s+(?:(?:is|was|of)\s+)?)\s*["'`]?$"#,
            )?,
            keyword_above: Regex::new(
                r"(?i)(?:^|[^a-z])(?:api[_\-]?key|access[_\-]?key|private[_\-]?key|secret|token|passw(?:or)?d|pwd|credentials?|bearer|signature)",
            )?,
        })
    }

    /// Classify a detected span by the guards. `end` is exclusive.
    pub fn suppress(&self, text: &str, start: usize, end: usize) -> Option<Suppression> {
        // Placeholder: the model span must lie entirely inside a placeholder token.
        if self
            .placeholder
            .find_iter(text)
            .any(|m| start >= m.start() && end <= m.end())
        {
            return Some(Suppression::Placeholder);
        }
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

    /// `suppress_labeled`, plus the shape guard, which applies to model spans only.
    pub fn suppress_model(
        &self,
        label: &str,
        text: &str,
        start: usize,
        end: usize,
    ) -> Option<Suppression> {
        if let Some(reason) = self.suppress_labeled(label, text, start, end) {
            return Some(reason);
        }
        let (core_start, core) = core(text, start, end)?;
        let whole = text.get(start..end)?.trim();
        let secret = label.eq_ignore_ascii_case("secret");
        // Masks and fake-value words mark a stand-in secret; `alice@example.com` is still a real email.
        if (secret && self.stand_in.is_match(whole)) || single_character(core) {
            return Some(Suppression::StandIn);
        }
        if self
            .code
            .iter()
            .any(|r| r.is_match(core) || r.is_match(whole))
        {
            return Some(Suppression::Identifier);
        }
        // The model often takes the word that names the id along: `container 3f9a1c2b7d4e`.
        let bare = self.id_label.replace(core, "");
        let identifier = [core, bare.as_ref()].into_iter().any(|value| {
            self.identifiers.iter().any(|r| r.is_match(value))
                || is_hex_hash(value)
                || (secret && self.numbers.iter().any(|r| r.is_match(value)))
        });
        if !identifier {
            return None;
        }
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

    /// `suppress`, plus the guards that depend on the span's label and the user's allowlist.
    pub fn suppress_labeled(
        &self,
        label: &str,
        text: &str,
        start: usize,
        end: usize,
    ) -> Option<Suppression> {
        if let Some(reason) = self.suppress(text, start, end) {
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
            && !label.eq_ignore_ascii_case("private_url")
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

    /// The model's verdict on `needle` inside `text`, labelled `secret`.
    fn model(g: &Guards, text: &str, needle: &str) -> Option<Suppression> {
        let start = text
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} in {text}"));
        g.suppress_model("secret", text, start, start + needle.len())
    }

    #[test]
    fn numbered_placeholders_are_shielded() {
        let g = guards();
        let text = "Contact <private_email_1> or <secret_2> now";
        assert_eq!(g.suppress(text, 9, 24), Some(Suppression::Placeholder));
        assert_eq!(g.suppress(text, 30, 37), Some(Suppression::Placeholder));
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
                g.suppress_labeled("secret", text, start, end),
                Some(Suppression::FileReference),
                "{text}"
            );
            assert_eq!(
                g.suppress_labeled("private_person", text, start, end),
                Some(Suppression::FileReference),
                "{text}"
            );
        }
    }

    #[test]
    fn file_reference_guard_is_narrow() {
        let g = guards();
        // Not a secret label: host:port stays detectable.
        let text = "connect to db.internal.com:5432";
        let start = text.find("db.internal").unwrap();
        assert_eq!(
            g.suppress_labeled("private_url", text, start, text.len()),
            None
        );
        // A real secret beside a location is not inside it.
        let text = "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 main.rs:4";
        let start = text.find("ghp_").unwrap();
        assert_eq!(g.suppress_labeled("secret", text, start, start + 40), None);
        // Password after a colon is not a line number.
        let text = "login admin.user:hunter2";
        let start = text.find("admin").unwrap();
        assert_eq!(g.suppress_labeled("secret", text, start, text.len()), None);
    }

    #[test]
    fn real_secret_and_pii_are_not_suppressed() {
        let g = guards();
        let text = "Here is my AWS key: AKIAIOSFODNN7EXAMPLE";
        let start = text.find("AKIA").unwrap();
        assert_eq!(g.suppress(text, start, text.len()), None);

        let text = "postgres://admin:hunter2@db.internal:5432/prod";
        let start = text.find(":hunter2").unwrap();
        assert_eq!(g.suppress(text, start, start + 8), None);

        let text = "Email alice@example.com";
        let start = text.find("alice").unwrap();
        assert_eq!(g.suppress(text, start, start + 17), None);
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
            (
                "the token is 9f86d081884c7d659a2feaa0c55ad015",
                "9f86d081884c7d659a2feaa0c55ad015",
            ),
        ] {
            assert_eq!(model(&g, text, needle), None, "{text}");
        }
        // A span that is more than the identifier is not an identifier.
        let key = "key=886dcfc3-25e8-420b-a6eb-f88f6b8694a9";
        assert_eq!(g.suppress_model("secret", key, 0, key.len()), None);
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
    fn stand_in_words_are_kept_for_personal_data_labels() {
        let g = guards();
        let text = "Contact alice@example.com today";
        let start = text.find("alice").unwrap();
        let end = start + "alice@example.com".len();
        assert_eq!(g.suppress_model("private_email", text, start, end), None);
        assert_eq!(
            g.suppress_model("secret", text, start, end),
            Some(Suppression::StandIn)
        );
    }

    #[test]
    fn numbers_are_kept_for_personal_data_labels() {
        let g = guards();
        let text = "card 4111111111111111";
        let start = text.find("4111").unwrap();
        assert_eq!(
            g.suppress_model("account_number", text, start, text.len()),
            None
        );
        assert_eq!(
            g.suppress_model("secret", text, start, text.len()),
            Some(Suppression::Identifier)
        );
    }

    #[test]
    fn gitleaks_spans_are_not_checked_for_shape() {
        let g = guards();
        let text = "/Users/me/.claude/projects/x/886dcfc3-25e8-420b-a6eb-f88f6b8694a9/scripts";
        let start = text.find("886d").unwrap();
        assert_eq!(g.suppress_labeled("secret", text, start, start + 36), None);
    }

    #[test]
    fn allowlist_drops_matching_values_from_any_engine() {
        let g = Guards::with_allowlist(vec![Regex::new(r"^PROJ-\d+$").unwrap()]).unwrap();
        let text = "fixed in PROJ-1234 today";
        let start = text.find("PROJ").unwrap();
        assert_eq!(
            g.suppress_labeled("secret", text, start, start + 9),
            Some(Suppression::Allowlist)
        );
        assert_eq!(g.suppress_labeled("secret", "PROJ-12x", 0, 8), None);
    }
}
