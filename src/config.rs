//! Category configuration: which entity categories may be detected and redacted.
//!
//! Sources, in priority order:
//!   1. `PIIF_CATEGORIES` env var (comma/space separated names)
//!   2. `PIIF_CONFIG` file, else `~/.config/piifence/config.toml`, else `./piifence.toml`
//!   3. default: all categories
//!
//! File format:
//!   categories = ["secret", "private_email"]
//!
//! Unknown category names are an error (fail closed): a typo must not silently
//! disable redaction for a category the user meant to protect.

use std::collections::HashSet;
use std::path::PathBuf;

pub const ALL_CATEGORIES: [&str; 8] = [
    "account_number",
    "private_address",
    "private_email",
    "private_person",
    "private_phone",
    "private_url",
    "private_date",
    "secret",
];

#[derive(Debug, Default, serde::Deserialize)]
pub struct Config {
    pub categories: Option<Vec<String>>,
    /// Run the neural model for the `secret` category as well as gitleaks.
    /// Defaults to true; set false to make secret-only mode rules-only (fast).
    #[serde(default)]
    pub llm_filter: Option<bool>,
}

fn normalize(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('-', "_")
}

/// Resolve the config file path, if any.
pub fn config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PIIF_CONFIG") {
        return Some(PathBuf::from(path));
    }
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        let candidate = PathBuf::from(dir).join("piifence/config.toml");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let candidate = PathBuf::from(home).join(".config/piifence/config.toml");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let cwd = PathBuf::from("piifence.toml");
    cwd.exists().then_some(cwd)
}

pub fn load() -> anyhow::Result<Config> {
    let mut config = match config_path() {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", path.display()))?;
            toml::from_str(&text)
                .map_err(|e| anyhow::anyhow!("invalid TOML in {}: {e}", path.display()))?
        }
        None => Config::default(),
    };
    if let Ok(raw) = std::env::var("PIIF_CATEGORIES") {
        if !raw.trim().is_empty() {
            config.categories = Some(
                raw.split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect(),
            );
        }
    }
    Ok(config)
}

impl Config {
    pub fn category_set(&self) -> anyhow::Result<Option<HashSet<String>>> {
        let Some(raw) = &self.categories else {
            return Ok(None);
        };
        let mut set = HashSet::new();
        for name in raw {
            let normalized = normalize(name);
            if !ALL_CATEGORIES.contains(&normalized.as_str()) {
                anyhow::bail!(
                    "unknown category `{name}`; valid categories: {}",
                    ALL_CATEGORIES.join(", ")
                );
            }
            set.insert(normalized);
        }
        Ok(Some(set))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_categories_are_accepted() {
        let config = Config {
            categories: Some(ALL_CATEGORIES.iter().map(|s| s.to_string()).collect()),
            llm_filter: None,
        };
        let set = config.category_set().unwrap().unwrap();
        assert_eq!(set.len(), 8);
    }

    #[test]
    fn llm_filter_defaults_to_none_in_file() {
        let config: Config = toml::from_str("categories = [\"secret\"]").unwrap();
        assert!(config.llm_filter.is_none());
    }

    #[test]
    fn unknown_category_is_an_error() {
        let config = Config {
            categories: Some(vec!["private_emial".to_string()]),
            llm_filter: None,
        };
        assert!(config.category_set().is_err());
    }

    #[test]
    fn hyphens_and_case_normalize() {
        let config = Config {
            categories: Some(vec!["Private-Email".to_string()]),
            llm_filter: None,
        };
        let set = config.category_set().unwrap().unwrap();
        assert!(set.contains("private_email"));
    }
}
