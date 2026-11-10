//! The user's configuration: values that are never redacted.
//!
//! The file is `$PIIF_CONFIG`, or `~/.config/piifence/config.toml` when that is unset. A missing file means no exceptions.
//!
//! ```toml
//! allow = ['^PROJ-\d+$']   # values never redacted, matched against each detected value
//! ```
//!
//! An unknown key or an invalid pattern is an error: a typo must not silently change what is redacted.

use std::path::PathBuf;

use anyhow::Context;

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Regexes for values that are never redacted, matched against each detected value (trimmed). Unanchored, so `'^…$'` for a whole value.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// The config file path: `$PIIF_CONFIG`, else `~/.config/piifence/config.toml`.
pub fn path() -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("PIIF_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/piifence/config.toml"))
}

pub fn load() -> anyhow::Result<Config> {
    let path = path()?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read config {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))
}

impl Config {
    /// The `allow` regexes, compiled. An invalid one is an error, not skipped.
    pub fn allow_patterns(&self) -> anyhow::Result<Vec<regex::Regex>> {
        self.allow
            .iter()
            .map(|p| {
                regex::Regex::new(p)
                    .map_err(|e| anyhow::anyhow!("invalid `allow` pattern `{p}`: {e}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_patterns_compile_or_fail() {
        let config: Config = toml::from_str("allow = ['^PROJ-\\d+$']").unwrap();
        assert!(config.allow_patterns().unwrap()[0].is_match("PROJ-12"));
        let config: Config = toml::from_str("allow = ['(']").unwrap();
        assert!(config.allow_patterns().is_err());
    }

    #[test]
    fn removed_settings_are_errors() {
        assert!(toml::from_str::<Config>("categories = [\"secret\"]").is_err());
        assert!(toml::from_str::<Config>("llm_filter = false").is_err());
    }
}
