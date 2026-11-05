//! piifence M1 — model validation harness with guarded post-processing.
//!
//! For every corpus case:
//!   1. model inference (`privacy-filter-rs`, NdArray + Accelerate CPU backend)
//!   2. gitleaks pre-pass (`gitleaks stdin`, project `gitleaks.toml`)
//!   3. guard filter: placeholder skip + env-ref allowlist (`src/guards.rs`)
//!   4. union of model and pre-pass spans, deduped on overlap
//!      and compares the multi-set of normalized entity groups against the corpus
//!      expectation. Suppressed spans are printed with their reason so the wrapper's
//!      effect is auditable; exits non-zero on any mismatch.
//!
//! Env switches: `PIIF_GITLEAKS=0` disables the pre-pass; `PIIF_GUARDS=0`
//! disables the guards; both off reproduces the raw model baseline.

use piifence_m1::detect::Detector;
use piifence_m1::guards::Suppression;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize, Debug)]
struct Case {
    id: String,
    tier: String,
    text: String,
    expect: Vec<String>,
}

fn normalize(label: &str) -> String {
    label.trim().to_uppercase().replace('-', "_")
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v != "0" && v != "off" && v != "false")
        .unwrap_or(true)
}

fn main() -> anyhow::Result<()> {
    let model_dir = PathBuf::from(std::env::var("PIIF_MODEL_DIR").unwrap_or("data".into()));
    anyhow::ensure!(
        model_dir.exists(),
        "model dir not found: {} (run scripts/fetch-weights.sh or set PIIF_MODEL_DIR)",
        model_dir.display()
    );

    let use_gitleaks = env_flag("PIIF_GITLEAKS");
    let use_guards = env_flag("PIIF_GUARDS");

    eprintln!("Loading model from {}", model_dir.display());
    let detector = Detector::load(&model_dir, use_gitleaks, use_guards)?;
    eprintln!("Model loaded.");

    let raw = std::fs::read_to_string("tests/corpus.json")?;
    let corpus: Vec<Case> = serde_json::from_str(&raw)?;

    let mut failures = 0usize;
    let mut by_tier: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    let mut suppressed: std::collections::BTreeMap<Suppression, usize> = Default::default();

    for case in &corpus {
        let detection = detector.detect(&case.text)?;

        let mut got: Vec<String> = detection.kept.iter().map(|s| normalize(&s.label)).collect();
        got.sort();

        let mut want: Vec<String> = case.expect.iter().map(|s| normalize(s)).collect();
        want.sort();

        let pass = got == want;
        let entry = by_tier.entry(case.tier.clone()).or_insert((0, 0));
        entry.1 += 1;
        if pass {
            entry.0 += 1;
        } else {
            failures += 1;
        }

        println!(
            "{} {}: got={:?} want={:?}",
            if pass { "✅" } else { "❌" },
            case.id,
            got,
            want
        );

        for span in &detection.kept {
            println!(
                "    {:>6.3}  {:<18} {:?}  [{}]",
                span.score,
                normalize(&span.label),
                span.word,
                span.source
            );
        }
        for (span, reason) in &detection.suppressed {
            *suppressed.entry(*reason).or_default() += 1;
            println!(
                "    [suppressed:{}] {:>6.3}  {:<18} {:?}  [{}]",
                reason.as_str(),
                span.score,
                normalize(&span.label),
                span.word,
                span.source
            );
        }
    }

    println!("\n--- per-tier ---");
    for (tier, (ok, total)) in &by_tier {
        println!("{:<10} {}/{}", tier, ok, total);
    }
    println!(
        "\ngitleaks pre-pass: {}",
        if use_gitleaks {
            "on (`gitleaks.toml`)"
        } else {
            "off (PIIF_GITLEAKS=0)"
        }
    );
    println!(
        "guards: {}",
        if use_guards {
            // Placeholder and env-ref always show; the other guards only when they fired.
            let count = |reason| suppressed.get(&reason).copied().unwrap_or(0);
            let mut parts = vec![
                format!("placeholder: {}", count(Suppression::Placeholder)),
                format!("env-ref-allowlist: {}", count(Suppression::EnvReference)),
            ];
            parts.extend(
                suppressed
                    .iter()
                    .filter(|(reason, _)| {
                        !matches!(reason, Suppression::Placeholder | Suppression::EnvReference)
                    })
                    .map(|(reason, n)| format!("{}: {n}", reason.as_str())),
            );
            format!(
                "on — suppressed {} spans ({})",
                suppressed.values().sum::<usize>(),
                parts.join(", ")
            )
        } else {
            "off (PIIF_GUARDS=0)".to_string()
        }
    );
    println!("{}/{} passed", corpus.len() - failures, corpus.len());

    std::process::exit(if failures > 0 { 1 } else { 0 });
}
