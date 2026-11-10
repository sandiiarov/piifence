//! The gitleaks pass.
//!
//! Runs the `gitleaks` CLI (`gitleaks stdin`) on a single text block with the project rules (`gitleaks.toml`, which extends gitleaks' default rule set) and returns its findings with byte offsets. The rules are built into the binary and written next to the detection cache at startup, so there is one copy and no lookup.

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// The project rules, `gitleaks.toml` at the repository root.
pub const CONFIG: &str = include_str!("../gitleaks.toml");

#[derive(Debug, Deserialize)]
pub struct Finding {
    #[serde(rename = "RuleID")]
    pub rule_id: String,
    #[serde(rename = "Secret")]
    pub secret: String,
    #[serde(rename = "StartLine")]
    pub start_line: usize,
    #[serde(rename = "Tags", default)]
    pub tags: Vec<String>,
}

impl Finding {
    /// gitleaks decodes base64 (and other encodings) before matching; such findings report the decoded value as `Secret`, which never appears in the text itself.
    pub fn is_decoded(&self) -> bool {
        self.tags.iter().any(|t| t.starts_with("decoded:"))
    }
}

/// Write `CONFIG` to `dir/gitleaks.toml` (mode 0600) and return its path.
pub fn write_config(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("gitleaks.toml");
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| file.write_all(CONFIG.as_bytes()))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// `gitleaks version` output. An error when gitleaks is not installed.
pub fn version() -> Result<Vec<u8>> {
    let output = Command::new("gitleaks")
        .arg("version")
        .output()
        .context("run `gitleaks version` (install gitleaks with `brew install gitleaks`)")?;
    anyhow::ensure!(
        output.status.success(),
        "`gitleaks version` exited with {}",
        output.status
    );
    Ok(output.stdout)
}

/// Scan one text block with `gitleaks stdin` and the rules in `config`, and parse the JSON report.
pub fn scan(text: &str, config: &Path) -> Result<Vec<Finding>> {
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
    cmd.arg("-c").arg(config);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .context("failed to run `gitleaks` (install it with `brew install gitleaks`)")?;
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

/// Byte offset where 1-based `line` starts.
fn line_start(text: &str, line: usize) -> Result<usize> {
    anyhow::ensure!(line >= 1, "gitleaks reported line 0");
    if line == 1 {
        return Ok(0);
    }
    text.match_indices('\n')
        .nth(line - 2)
        .map(|(i, _)| i + 1)
        .with_context(|| format!("gitleaks reported line {line}, past the end of the text"))
}

/// A base64 or base64url run long enough for gitleaks to decode.
fn encoded_run() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").expect("encoded-run regex"))
}

/// Every byte range in `text` to redact for `finding`.
///
/// A plain finding: every copy of its secret in the text. gitleaks reports one finding per line, and a copy that only the model would catch must not stay raw. A decoded finding (base64 etc.): every encoded run on the line gitleaks reports, since the decoded value is not in the text. Its columns are not used: gitleaks 8.30.1 reports `EndColumn` 0 for some decoded findings and the key's column for others.
///
/// A finding that cannot be placed is an error, so the request is blocked instead of sent with the secret.
pub fn locate(finding: &Finding, text: &str) -> Result<Vec<(usize, usize)>> {
    if finding.is_decoded() {
        let start = line_start(text, finding.start_line)?;
        let end = text[start..].find('\n').map_or(text.len(), |i| start + i);
        let ranges: Vec<(usize, usize)> = encoded_run()
            .find_iter(&text[start..end])
            .map(|m| (start + m.start(), start + m.end()))
            .collect();
        anyhow::ensure!(
            !ranges.is_empty(),
            "gitleaks finding {} decoded a value on line {}, but the line has no encoded run",
            finding.rule_id,
            finding.start_line
        );
        return Ok(ranges);
    }
    let secret = finding.secret.as_str();
    anyhow::ensure!(
        !secret.is_empty(),
        "gitleaks finding {} has an empty secret",
        finding.rule_id
    );
    let ranges: Vec<(usize, usize)> = text
        .match_indices(secret)
        .map(|(start, _)| (start, start + secret.len()))
        .collect();
    anyhow::ensure!(
        !ranges.is_empty(),
        "gitleaks finding {}: its secret is not in the text",
        finding.rule_id
    );
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(secret: &str, line: usize, tags: &[&str]) -> Finding {
        Finding {
            rule_id: "test".to_string(),
            secret: secret.to_string(),
            start_line: line,
            tags: tags.iter().map(|t| t.to_string()).collect(),
        }
    }

    #[test]
    fn every_copy_is_returned() {
        let text = "a\nuse SECRETVALUE1\nb\nagain SECRETVALUE1 SECRETVALUE1\n";
        let ranges = locate(&finding("SECRETVALUE1", 2, &[]), text).unwrap();
        assert_eq!(ranges, vec![(6, 18), (27, 39), (40, 52)]);
    }

    #[test]
    fn decoded_finding_redacts_the_encoded_runs_on_its_line() {
        let text = "data:\n  VALUE: ZW5jb2RlZC12YWx1ZS1oZXJl\nnext: ZW5jb2RlZC12YWx1ZS1vdGhlcg==\n";
        let ranges = locate(&finding("decoded-value", 2, &["decoded:base64"]), text).unwrap();
        assert_eq!(ranges, vec![(15, 39)]);
        assert_eq!(&text[15..39], "ZW5jb2RlZC12YWx1ZS1oZXJl");
        let ranges = locate(&finding("decoded-value", 3, &["decoded:base64"]), text).unwrap();
        assert_eq!(
            &text[ranges[0].0..ranges[0].1],
            "ZW5jb2RlZC12YWx1ZS1vdGhlcg=="
        );
    }

    #[test]
    fn a_finding_that_cannot_be_placed_is_an_error() {
        assert!(locate(&finding("absent-value", 1, &[]), "short\n").is_err());
        assert!(locate(&finding("x", 9, &["decoded:base64"]), "one line").is_err());
        assert!(locate(&finding("x", 1, &["decoded:base64"]), "no encoded run here").is_err());
    }
}
