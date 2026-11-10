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
