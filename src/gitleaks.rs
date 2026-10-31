//! gitleaks pre-pass.
//!
//! Runs the `gitleaks` CLI (`gitleaks stdin`) on a single text block with the
//! project config (`gitleaks.toml`, which extends the default rule set) and
//! returns deterministic secret findings with byte offsets. This covers
//! credential shapes the model is known to miss (see `docs/m1-notes.md`,
//! `sec-01`) and dedupes against model spans in `main.rs`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Debug, Deserialize)]
pub struct Finding {
    #[serde(rename = "RuleID")]
    pub rule_id: String,
    #[serde(rename = "Secret")]
    pub secret: String,
    #[serde(rename = "StartColumn", default)]
    pub start_column: usize,
    #[serde(rename = "EndColumn", default)]
    pub end_column: usize,
    #[serde(rename = "StartLine", default)]
    pub start_line: usize,
    #[serde(rename = "Tags", default)]
    pub tags: Vec<String>,
}

impl Finding {
    /// gitleaks decodes base64 (and other encodings) before matching; such findings
    /// report the decoded value as `Secret`, which never appears in the text itself.
    pub fn is_decoded(&self) -> bool {
        self.tags.iter().any(|t| t.starts_with("decoded:"))
    }
}

/// gitleaks config path: `PIIF_GITLEAKS_CONFIG`, else `gitleaks.toml` if present,
/// else the CLI's built-in default config.
pub fn config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PIIF_GITLEAKS_CONFIG") {
        let path = PathBuf::from(p);
        return path.exists().then_some(path);
    }
    let default = PathBuf::from("gitleaks.toml");
    default.exists().then_some(default)
}

/// Scan one text block with `gitleaks stdin` and parse the JSON report.
pub fn scan(text: &str) -> Result<Vec<Finding>> {
    let mut cmd = Command::new("gitleaks");
    cmd.args([
        "stdin",
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--exit-code",
        "0",
        "--no-banner",
        "--no-color",
    ]);
    if let Some(config) = config_path() {
        cmd.arg("-c").arg(config);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context(
        "failed to run `gitleaks` (install it with `brew install gitleaks`, or set PIIF_GITLEAKS=0 to skip the pre-pass)",
    )?;
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(text.as_bytes())
        .context("writing text to gitleaks stdin")?;
    drop(child.stdin.take());

    let output = child.wait_with_output().context("waiting for gitleaks")?;
    anyhow::ensure!(
        output.status.success(),
        "gitleaks exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed).context("parsing gitleaks JSON report")
}

/// Byte offsets of the start and end (exclusive of the newline) of 1-based `line`.
/// Line 0 or a line past the end maps to the first line.
fn line_bounds(text: &str, line: usize) -> (usize, usize) {
    let mut start = 0;
    if line > 1 {
        let mut seen = 1;
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                seen += 1;
                if seen == line {
                    start = i + 1;
                    break;
                }
            }
        }
        if seen < line {
            start = 0;
        }
    }
    let end = text[start..].find('\n').map_or(text.len(), |i| start + i);
    (start, end)
}

/// Every byte range in `text` to redact for `finding`.
///
/// Measured on gitleaks 8.30.1 `stdin`: `StartLine` is 1-based; `StartColumn` is a
/// 1-based byte column on line 1 and one larger on later lines (the preceding newline
/// is counted); `EndColumn = StartColumn + len - 1`. When a rule's capture group is
/// narrower than its match (e.g. `generic-api-key`), the columns describe the whole
/// match, so the secret is searched for inside the reported line instead.
///
/// A plain finding returns its anchor plus every other copy of the secret in the text:
/// gitleaks reports one finding per line, and a copy that only the model would catch
/// must not stay raw. A decoded finding (base64 etc.) returns the encoded segment the
/// columns point at, since the decoded value is not in the text.
pub fn locate(finding: &Finding, text: &str) -> Vec<(usize, usize)> {
    let (line_start, line_end) = line_bounds(text, finding.start_line);
    let shift = if finding.start_line > 1 { 2 } else { 1 };
    if finding.is_decoded() {
        if finding.start_column < shift || finding.end_column + 1 < finding.start_column {
            return Vec::new();
        }
        let mut start = (line_start + finding.start_column - shift).min(line_end);
        let mut end = (line_start + finding.end_column + 1 - shift).min(line_end);
        while start > 0 && !text.is_char_boundary(start) {
            start -= 1;
        }
        while end < text.len() && !text.is_char_boundary(end) {
            end += 1;
        }
        return if start < end {
            vec![(start, end)]
        } else {
            Vec::new()
        };
    }

    let secret = finding.secret.as_str();
    if secret.is_empty() {
        return Vec::new();
    }
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let candidates = [
        finding.start_column.checked_sub(1),
        finding.start_column.checked_sub(2),
    ];
    let anchor = candidates
        .into_iter()
        .flatten()
        .filter(|_| finding.start_column > 0)
        .map(|col| line_start + col)
        .find(|&c| text.get(c..c + secret.len()) == Some(secret))
        .or_else(|| {
            text.get(line_start..line_end)
                .and_then(|line| line.find(secret))
                .map(|i| line_start + i)
        });
    if let Some(start) = anchor {
        ranges.push((start, start + secret.len()));
    }
    for (start, _) in text.match_indices(secret) {
        ranges.push((start, start + secret.len()));
    }
    ranges.sort_unstable();
    ranges.dedup();
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(secret: &str, line: usize, start_column: usize, tags: &[&str]) -> Finding {
        Finding {
            rule_id: "test".to_string(),
            secret: secret.to_string(),
            start_column,
            end_column: start_column + secret.len() - 1,
            start_line: line,
            tags: tags.iter().map(|t| t.to_string()).collect(),
        }
    }

    #[test]
    fn first_line_uses_one_based_column() {
        let text = "key=SECRETVALUE1\n";
        assert_eq!(
            locate(&finding("SECRETVALUE1", 1, 5, &[]), text),
            vec![(4, 16)]
        );
    }

    #[test]
    fn later_lines_are_offset_by_one_more() {
        let text = "first\nkey=SECRETVALUE1\n";
        // gitleaks reports column 6 on line 2 for a value that starts at byte 4 of the line.
        assert_eq!(
            locate(&finding("SECRETVALUE1", 2, 6, &[]), text),
            vec![(10, 22)]
        );
    }

    #[test]
    fn every_copy_is_returned() {
        let text = "a\nuse SECRETVALUE1\nb\nagain SECRETVALUE1\n";
        let ranges = locate(&finding("SECRETVALUE1", 2, 6, &[]), text);
        assert_eq!(ranges, vec![(6, 18), (27, 39)]);
    }

    #[test]
    fn two_copies_on_one_line() {
        let text = "SECRETVALUE1 and SECRETVALUE1\n";
        assert_eq!(
            locate(&finding("SECRETVALUE1", 1, 1, &[]), text),
            vec![(0, 12), (17, 29)]
        );
    }

    #[test]
    fn decoded_finding_redacts_encoded_segment() {
        let text = "data:\n  VALUE: ZW5jb2RlZA==\n";
        // Encoded segment on line 2 starts at byte 9 of the line (column 11), 12 bytes long.
        let mut f = finding("decoded-value", 2, 11, &["decoded:base64"]);
        f.end_column = 11 + 12 - 1;
        assert_eq!(locate(&f, text), vec![(15, 27)]);
        assert_eq!(&text[15..27], "ZW5jb2RlZA==");
    }

    #[test]
    fn bad_columns_do_not_panic() {
        let text = "short\n";
        assert!(locate(&finding("absent-value", 1, 500, &[]), text).is_empty());
        assert!(locate(&finding("absent-value", 9, 500, &["decoded:base64"]), "é").len() <= 1);
    }

    #[test]
    fn columns_after_multibyte_char() {
        let text = "ünï key SECRETVALUE1\n";
        // gitleaks counts bytes: the value starts at byte 10, column 11.
        assert_eq!(
            locate(&finding("SECRETVALUE1", 1, 11, &[]), text),
            vec![(10, 22)]
        );
    }

    #[test]
    fn capture_group_narrower_than_match_is_found_in_line() {
        let text = "first\nAPI_URL=SECRETVALUE1\n";
        // Columns describe the whole match `API_URL=SECRETVALUE1`.
        let mut f = finding("SECRETVALUE1", 2, 2, &[]);
        f.end_column = 21;
        assert_eq!(locate(&f, text), vec![(14, 26)]);
    }
}
