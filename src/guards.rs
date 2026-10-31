//! Wrapper-level guards that sit between detection and replacement (M2 pre-work).
//!
//! Two suppression rules, both narrow and evidence-backed by `docs/prior-art.md`:
//!
//! 1. **Placeholder skip guard** — never redact a token we (or a previous
//!    pipeline version) already produced. Two shapes are recognized:
//!    the final `<private_email_1>` / `<secret_1>` scheme and the legacy
//!    `PII_<LABEL>_<8hex>` / `PF_<LABEL>_<8hex>` placeholders used by the M1
//!    corpus (`sec-05`).
//! 2. **Env-ref allowlist** — a `SECRET` span that overlaps an environment
//!    variable *reference* (`os.environ.get('DB_PASS')`, `process.env.X`, ...)
//!    is a false positive: the code names a secret, it does not contain one.
//!    This is the narrow fix for `neg-01`; the model flags only the
//!    single-quoted `password = os.environ.get('DB_PASS')` form.

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppression {
    Placeholder,
    EnvReference,
}

impl Suppression {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Placeholder => "placeholder",
            Self::EnvReference => "env-ref-allowlist",
        }
    }
}

pub struct Guards {
    placeholder: Regex,
    env_ref: Regex,
}

impl Guards {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            // Final scheme: <private_email_1>, <secret_1>; legacy: PII_SECRET_a1b2c3d4.
            placeholder: Regex::new(
                r"<(?:private_)?[a-z_]+_\d+>|\b(?:PII|PF)_[A-Z][A-Z0-9_]*_[0-9a-f]{8}\b",
            )?,
            env_ref: Regex::new(
                r#"os\.environ\.get\(\s*['"][A-Za-z0-9_]+['"]\s*\)|os\.environ\[\s*['"][A-Za-z0-9_]+['"]\s*\]|os\.getenv\(\s*['"][A-Za-z0-9_]+['"]\s*\)|process\.env\.[A-Za-z0-9_]+|\$PIIF_[A-Za-z0-9_]+"#,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guards() -> Guards {
        Guards::new().unwrap()
    }

    #[test]
    fn legacy_placeholder_is_shielded() {
        let text = "OPENAI_API_KEY=<PII_SECRET_a1b2c3d4>";
        let g = guards();
        assert_eq!(g.suppress(text, 16, 35), Some(Suppression::Placeholder));
        assert_eq!(g.suppress(text, 0, 15), None);
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
}
