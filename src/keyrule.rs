//! The key rule: a quoted, random-looking value is a secret when its own key, or the key of the block around it, names a secret.
//!
//! It catches what the model misses when the name is a line or a key away from the value:
//!
//! ```text
//! variable "api_key" {           "credentials": {
//!   default = "3f9a…"              "value": "SYgeCBkAV*dah5"
//! }                              }
//! ```
//!
//! Blocks are tracked by indentation, so it reads pretty-printed JSON, YAML, TOML and HCL, not one-line JSON.

use std::sync::OnceLock;

use regex::Regex;

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid key-rule regex"))
}

fn secret_name() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"(?i)api[_-]?key|secret|passw(?:or)?d|\bpwd\b|token|credential|private[_-]?key|access[_-]?key",
    )
}

fn key_value() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r#"^\s*["']?([\w.-]+)["']?\s*[:=]\s*(?:"([^"\s]+)"|'([^'\s]+)')\s*,?\s*$"#,
    )
}

fn block_open() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"[{\[:]\s*$")
}

fn word() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"[A-Za-z_][\w.-]*")
}

fn uuid() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
}

/// Long, no spaces, and mixing letters with digits and with a second case or a symbol: 32+ hex digits, or 12+ characters such as `SYgeCBkAV*dah5`. A UUID or a plain word is not random-looking.
pub fn random_looking(value: &str) -> bool {
    if value.len() >= 32 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    if value.chars().count() < 12 || uuid().is_match(value) {
        return false;
    }
    let has = |f: fn(&char) -> bool| value.chars().any(|c| f(&c));
    let classes = [
        has(char::is_ascii_lowercase),
        has(char::is_ascii_uppercase),
        has(char::is_ascii_digit),
        has(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|&&present| present)
    .count();
    has(char::is_ascii_alphabetic) && has(char::is_ascii_digit) && classes >= 3
}

fn hex_run() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"[0-9A-Fa-f]{32,128}")
}

/// Words that say a hex value is a hash or an object id, not a key.
fn hash_word() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"(?i)(?:^|[^a-z])(?:sha\d*|hash(?:es|ed)?|commits?|digest|md5|checksums?|integrity|etag|fingerprint|object|revs?|revision|blob|tree|parent|merge|git|image|layer|container|docker|cid|nonce|salt|iv)(?:[^a-z]|$)",
    )
}

/// A secret keyword before the value on its line, which beats a hash word.
fn secret_word() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"(?i)api[_\- ]?key|secret|passw(?:or)?d|token|credential|private[_\- ]?key|access[_\- ]?key|auth|bearer",
    )
}

/// A file name after a value: `<hash>  dist/app.tar.gz`.
fn file_after() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"^[ \t]+\*?[\w.\-/]+\.[A-Za-z0-9]{1,8}(?:\s|$)")
}

/// A column break after a value: a tab or two spaces, then more text, as in a listing whose first column is an id (`gh gist list`).
fn column_after() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"^(?:\t| {2,})\S")
}

/// Byte ranges of bare hex values of 32 to 128 digits that are keys rather than hashes: one case, letters and digits, standing alone (not inside a word, path, file name or host), not before a file name (`<hash>  app.tar.gz`), not the first column of a listing, and on a line where no hash word (`sha`, `commit`, `digest`, `md5`, `git` …) appears in the two lines above or before the value, unless a secret keyword comes first on the value's line. The model takes such a value for a hash: `use a7a6…eb65 for the deploy`.
pub fn hex_spans(text: &str) -> Vec<(usize, usize)> {
    let glued = |c: char| c.is_ascii_alphanumeric() || "_-./@#".contains(c);
    let mut out = Vec::new();
    for m in hex_run().find_iter(text) {
        let value = m.as_str();
        let before = text[..m.start()].chars().next_back();
        let mut after = text[m.end()..].chars();
        let next = after.next();
        let next_glued = match next {
            Some('.') => after.next().is_some_and(|c| c.is_ascii_alphanumeric()),
            Some(c) => glued(c),
            None => false,
        };
        if before.is_some_and(glued) || next_glued {
            continue;
        }
        let lower = value.bytes().any(|b| b.is_ascii_lowercase());
        let upper = value.bytes().any(|b| b.is_ascii_uppercase());
        if (lower && upper) || !value.bytes().any(|b| b.is_ascii_digit()) || !(lower || upper) {
            continue;
        }
        let line_start = text[..m.start()].rfind('\n').map_or(0, |i| i + 1);
        let line_end = text[m.end()..]
            .find('\n')
            .map_or(text.len(), |i| m.end() + i);
        let lead = &text[line_start..m.start()];
        let rest = &text[m.end()..line_end];
        if file_after().is_match(rest) || (lead.trim().is_empty() && column_after().is_match(rest))
        {
            continue;
        }
        let above = text[..line_start.saturating_sub(1)]
            .rmatch_indices('\n')
            .nth(1)
            .map_or(0, |(i, _)| i + 1);
        let last = |re: &Regex, hay: &str| re.find_iter(hay).last().map(|m| m.end());
        let hash = last(hash_word(), &text[above..m.start()]).map(|e| above + e);
        let secret = last(secret_word(), lead).map(|e| line_start + e);
        if hash.is_some_and(|h| secret.is_none_or(|s| h > s)) {
            continue;
        }
        out.push((m.start(), m.end()));
    }
    out
}

/// A word that names a secret, in English and the common languages people write prose in.
fn cue_word() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"(?i)\b(?:passw(?:or)?ds?|passphrases?|passcodes?|secrets?|api[_\- ]?keys?|access[_\- ]?keys?|private[_\- ]?keys?|tokens?|credentials?)\b|парол|ключ|токен|секрет|contraseñ|\bclave|mot de passe|passwort|kennwort|senha|wachtwoord|hasł|\bparol|密码|密碼|密钥|口令|令牌|パスワード|비밀번호|암호",
    )
}

fn token() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"\S+")
}

fn email() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"^[^@\s]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}$")
}

/// A word that reads as a value rather than prose or code: 8 to 128 printable ASCII characters with letters and digits that either carry a symbol, or run to 10 or more and switch between letters and digits at least twice. A path, URL, email or `$`/`{`/`<` reference is not one.
fn cue_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(8..=128).contains(&bytes.len())
        || !bytes.iter().all(|b| b.is_ascii_graphic())
        || !bytes.iter().any(u8::is_ascii_alphabetic)
        || !bytes.iter().any(u8::is_ascii_digit)
        || value.contains('/')
        || value.trim_end_matches('=').contains('=')
        || value.contains("***")
        || value.contains("...")
        || value.starts_with(['$', '{', '<', '%'])
        || email().is_match(value)
    {
        return false;
    }
    let switches = bytes
        .windows(2)
        .filter(|w| {
            w[0].is_ascii_digit() != w[1].is_ascii_digit()
                && w[0].is_ascii_alphanumeric()
                && w[1].is_ascii_alphanumeric()
        })
        .count();
    bytes.iter().any(|b| b"!@#%^&*+=~?".contains(b)) || (switches >= 2 && bytes.len() >= 10)
}

const CUE_REACH: usize = 6;
const LABEL_MAX: usize = 60;

/// Byte ranges of values named by a secret word in prose or by a label line: the first value-like word among the six after a secret word on its line (`the wifi password for the office is K7M2PQ9XWR`, `мой пароль от сервера …`), and a line that is one value-like word or UUID under a short line naming a secret (`## Webhook secret`, then the value). Agnostic of provider and language.
pub fn cue_spans(text: &str) -> Vec<(usize, usize)> {
    let trim = |s: &str| -> (usize, usize) {
        let lead = s.len()
            - s.trim_start_matches(['(', '"', '\'', '«', '`', ':', '='])
                .len();
        let tail = s.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', '"', '\'', '»', '`']);
        (lead, tail.len().max(lead))
    };
    let mut out = Vec::new();
    let mut offset = 0;
    let mut label: Option<&str> = None;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        let glued = |c: char| c.is_ascii_alphanumeric() || "/._-=".contains(c);
        for cue in cue_word().find_iter(body) {
            if body[..cue.start()].chars().next_back().is_some_and(glued)
                || body[cue.end()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
            {
                continue;
            }
            for word in token().find_iter(&body[cue.end()..]).take(CUE_REACH) {
                let (a, b) = trim(word.as_str());
                let value = &word.as_str()[a..b];
                if cue_value(value) {
                    let start = offset + cue.end() + word.start() + a;
                    out.push((start, start + value.len()));
                    break;
                }
            }
        }
        let stripped = body.trim();
        if !stripped.is_empty() {
            if let Some(above) = label {
                let lone = !stripped.contains(char::is_whitespace);
                if lone
                    && !stripped.contains('=')
                    && !above.contains('=')
                    && (random_looking(stripped) || uuid().is_match(stripped))
                    && above.len() <= LABEL_MAX
                    && cue_word().is_match(above)
                    && !hash_word().is_match(above)
                {
                    let start = offset + (body.len() - body.trim_start().len());
                    out.push((start, start + stripped.len()));
                }
            }
            label = Some(stripped);
        }
        offset += line.len();
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn prefixed() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"[A-Za-z][A-Za-z0-9]{1,9}[_-](?:[A-Za-z0-9]{2,8}[_-]){0,2}([A-Za-z0-9_-]{20,128})",
    )
}

fn uuid_inside() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    )
}

/// Ids of the Messages API itself, which every request carries.
const API_IDS: [&str; 6] = [
    "toolu_",
    "srvtoolu_",
    "mcptoolu_",
    "req_",
    "msg_",
    "msgbatch_",
];
const PREFIX_SWITCHES: usize = 4;

/// Byte ranges of keys in the common `<prefix>_<random>` shape of any provider (`tvly-dev-…`, `pa-…`, `rnd_…`): a short prefix of up to three parts (not a hash word such as `sha512-` or `nonce-`), then 20 to 128 characters of mixed case that switch between letters and digits at least four times. Single-case ids (`db-2PSR…`, pod names) are left to the exact provider rules. Not inside a path, host, longer word or base64 run (`sha512-…+…/…==`), not a UUID-bearing id, and not an id of the Messages API (`toolu_…`, `msg_…`).
pub fn prefix_spans(text: &str) -> Vec<(usize, usize)> {
    let edge = |c: char| c.is_ascii_alphanumeric() || "_-./".contains(c);
    let mut out = Vec::new();
    for m in prefixed().captures_iter(text) {
        let (whole, body) = (m.get(0).expect("match"), m.get(1).expect("body"));
        if text[..whole.start()].chars().next_back().is_some_and(edge)
            || text[whole.end()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || "_-+/=".contains(c))
            || API_IDS.iter().any(|id| whole.as_str().starts_with(id))
            || uuid_inside().is_match(whole.as_str())
        {
            continue;
        }
        let bytes = body.as_str().as_bytes();
        if !(bytes.iter().any(u8::is_ascii_uppercase) && bytes.iter().any(u8::is_ascii_lowercase))
            || hash_word().is_match(&text[whole.start()..body.start()])
        {
            continue;
        }
        let switches = bytes
            .windows(2)
            .filter(|w| {
                w[0].is_ascii_alphanumeric()
                    && w[1].is_ascii_alphanumeric()
                    && w[0].is_ascii_digit() != w[1].is_ascii_digit()
            })
            .count();
        if switches >= PREFIX_SWITCHES {
            out.push((whole.start(), whole.end()));
        }
    }
    out
}

/// Byte ranges of the values the key rule marks in `text`.
pub fn spans(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    // (indent, the words of the line that opened the block)
    let mut blocks: Vec<(usize, String)> = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let stripped = line.trim();
        let indent = line.len() - line.trim_start().len();
        if !stripped.is_empty() && !stripped.starts_with(['}', ']']) {
            while blocks.last().is_some_and(|(open, _)| *open >= indent) {
                blocks.pop();
            }
            if let Some(m) = key_value().captures(line) {
                let value = m.get(2).or(m.get(3)).expect("one quote style matches");
                let parent = blocks.last().map_or("", |(_, words)| words.as_str());
                if random_looking(value.as_str())
                    && (secret_name().is_match(&m[1]) || secret_name().is_match(parent))
                {
                    out.push((offset + value.start(), offset + value.end()));
                }
            } else if block_open().is_match(stripped) {
                let words: Vec<&str> = word().find_iter(stripped).map(|m| m.as_str()).collect();
                blocks.push((indent, words.join(" ")));
            }
        }
        offset += line.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "ddfda90b4f613522fb7c9d6c1b7453a9";
    const PW: &str = "SYgeCBkAV*dah5";

    fn found(text: &str) -> Vec<&str> {
        spans(text).into_iter().map(|(a, b)| &text[a..b]).collect()
    }

    #[test]
    fn value_under_a_secret_named_block_is_marked() {
        let hcl = format!("variable \"api_key\" {{\n  default = \"{HEX}\"\n}}\n");
        assert_eq!(found(&hcl), vec![HEX]);
        let json = format!("{{\n  \"service\": \"billing\",\n  \"credentials\": {{\n    \"value\": \"{PW}\"\n  }}\n}}");
        assert_eq!(found(&json), vec![PW]);
        let yaml = format!("db:\n  password: '{PW}'\n");
        assert_eq!(found(&yaml), vec![PW]);
    }

    fn hex_found(text: &str) -> Vec<&str> {
        hex_spans(text)
            .into_iter()
            .map(|(a, b)| &text[a..b])
            .collect()
    }

    fn cue_found(text: &str) -> Vec<&str> {
        cue_spans(text)
            .into_iter()
            .map(|(a, b)| &text[a..b])
            .collect()
    }

    #[test]
    fn a_value_named_in_prose_or_by_a_label_is_marked() {
        let uuid = "3f2a9c1e-7b4d-4e8a-9c2f-1a2b3c4d5e6f";
        for (text, want) in [
            (
                "The wifi password for the office is K7M2PQ9XWR.".to_string(),
                "K7M2PQ9XWR",
            ),
            (format!("мой пароль от сервера {PW} не говори никому"), PW),
            (format!("das Passwort lautet \"{PW}\""), PW),
            (format!("## Webhook secret\n\n{uuid}\n"), uuid),
            (format!("API key:\n  {PW}"), PW),
        ] {
            assert_eq!(cue_found(&text), vec![want], "{text}");
        }
    }

    #[test]
    fn prose_and_code_near_a_secret_word_are_left_alone() {
        for text in [
            "the password policy needs 12 characters and one digit",
            "rotate the token with ./scripts/rotate-v2.sh tomorrow",
            "send the secret to admin42@example.com today",
            "token=$GITHUB_TOKEN2 in CI",
            "the api key lives in config.yaml under section v2",
            "set the password for node18 and python3 images",
            "## Webhook secret\n\nSee the vault for the value.",
            "sha256 of the secret file:\n\nab12cd34ef56ab12",
            "a long line that mentions the secret store and goes on well past sixty characters\nab12cd34ef56",
            "Incorrect API key provided: sk-proj-****...Xk2Q",
            "spring.mail.password=${MAIL_PASSWORD}\nmanagement.server.port=9091",
            "chore: rotate token cache key (v9dd90970)\ndd90b283",
            "GET /api/token/refresh 204 3ms trace=a42d27750554518c39ad39ac758a102e",
            "bad credentials for user_id=00000000-0000-0000-0000-000000000000",
        ] {
            assert!(cue_found(text).is_empty(), "{text}: {:?}", cue_found(text));
        }
    }

    fn prefix_found(text: &str) -> Vec<&str> {
        prefix_spans(text)
            .into_iter()
            .map(|(a, b)| &text[a..b])
            .collect()
    }

    #[test]
    fn a_prefixed_random_key_of_any_provider_is_marked() {
        for key in [
            "tvly-dev-a8Kq2Lm9Zx4Rt7Wv1Bn5Cy3Hd6",
            "pa-Zk3mQ8vR2xL7nB4wT9yC1dF6hJ0sP5gA2eU",
            "xyz_live_9fK2mQ7rT4vW8yB1nC6dH3jL5pS0aZ",
        ] {
            assert_eq!(prefix_found(&format!("export KEY={key}\n")), vec![key]);
            assert_eq!(prefix_found(&format!("use {key}.")), vec![key]);
        }
    }

    #[test]
    fn ids_paths_and_words_with_a_prefix_are_left_alone() {
        for text in [
            "toolu_01A2b3C4d5E6f7G8h9J0kLmN",
            "msg_01XyZ2aB3cD4eF5gH6iJ7kL8",
            "hook-3932a821-e52a-4b1c-9d2e-1f2a3b4c5d6e",
            "/srv/app_v2_build-20260101a1b2c3d4e5/x",
            "some_long_variable_name_without_digits_at_all",
            "release-2026-11-11-build-7",
            "a.tvly-dev-a8Kq2Lm9Zx4Rt7Wv1Bn5Cy3Hd6",
            "\"integrity\": \"sha512-Zk3mQ8vR2xL7nB4wT9yC1dF6h+J0sP5gA2eU/w==\"",
            "id = \"db-2PSR4NDEIME0P49K9Q2IZ4YZQQ\"",
            "pod notify-worker-7d9f8c6b5-x2kqp restarted",
            "script-src 'nonce-axxgAV7i0Rrvz4Jd4mZT0LY2'",
        ] {
            assert!(
                prefix_found(text).is_empty(),
                "{text}: {:?}",
                prefix_found(text)
            );
        }
    }

    #[test]
    fn a_bare_hex_key_is_marked() {
        for text in [
            format!("for the deploy use {HEX} please"),
            format!("密钥是{HEX}请保管"),
            format!("the token, {HEX}, expires tomorrow."),
            format!("key ends the sentence {HEX}."),
            format!("commit then use secret {HEX}"),
        ] {
            assert_eq!(hex_found(&text), vec![HEX], "{text}");
        }
    }

    #[test]
    fn hashes_and_glued_hex_are_left_alone() {
        for text in [
            format!("commit {HEX}"),
            format!("$ git rev-parse HEAD\n{HEX}"),
            format!("sha256 checksum:\n\n{HEX}"),
            format!("{HEX}  dist/app.tar.gz"),
            format!("for the deploy use {HEX}  dist/app.tar.gz please"),
            format!("$ gh gist list\n{HEX}\tnotes\t2 files\tsecret\t2026-01-01T00:00:00Z"),
            format!("ID                                Name\n{HEX}  deploy"),
            format!("index-{HEX}.js"),
            format!("my password is old. The last commit I pushed was {HEX} if it helps"),
            format!("https://example.com/c/{HEX}/x"),
            HEX.to_uppercase().replacen('D', "d", 1),
            "0123456789012345678901234567890123".to_string(),
            "abcdefabcdefabcdefabcdefabcdefabcdef".to_string(),
            format!("x{HEX}"),
        ] {
            assert!(hex_found(&text).is_empty(), "{text}");
        }
    }

    #[test]
    fn look_alikes_are_left_alone() {
        let uuid =
            "{\n  \"credentials\": {\n    \"id\": \"886dcfc3-25e8-420b-a6eb-f88f6b8694a9\"\n  }\n}";
        let word = "{\n  \"secret\": {\n    \"name\": \"billing\"\n  }\n}";
        let other_key = format!("{{\n  \"service\": {{\n    \"value\": \"{HEX}\"\n  }}\n}}");
        let sibling = format!("{{\n  \"credentials\": {{\n    \"user\": \"bob\"\n  }},\n  \"build\": {{\n    \"sha\": \"{HEX}\"\n  }}\n}}");
        for text in [uuid, word, &other_key, &sibling] {
            assert!(found(text).is_empty(), "{text}");
        }
    }
}
