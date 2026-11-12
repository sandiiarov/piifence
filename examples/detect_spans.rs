//! The gateway's full detection (model in windows, isolate pass, key rule, gitleaks, guards) on arbitrary text, for mining and benchmarking. Reads JSON lines `{"text": …}` on stdin and writes, per line, `{"kept": [[start, end, source], …], "suppressed": [[start, end, source, reason], …]}` in UTF-8 byte offsets.
//!
//! Usage: detect_spans <model dir[:model dir…]> <cache dir>   (gitleaks must be on PATH; the cache dir is created and used like the gateway's)

use std::io::{BufRead, Write};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(model), Some(cache)) = (args.next(), args.next()) else {
        anyhow::bail!("usage: detect_spans <model dir> <cache dir>");
    };
    let detector = piifence::detect::Detector::load(
        &std::env::split_paths(&model).collect::<Vec<_>>(),
        Vec::new(),
        std::path::Path::new(&cache),
    )?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line?)?;
        let text = request["text"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("each line needs a \"text\" string"))?;
        let detection = detector.detect(text)?;
        let kept: Vec<_> = detection
            .kept
            .iter()
            .map(|s| serde_json::json!([s.start, s.end, s.source]))
            .collect();
        let suppressed: Vec<_> = detection
            .suppressed
            .iter()
            .map(|(s, why)| serde_json::json!([s.start, s.end, s.source, why.as_str()]))
            .collect();
        writeln!(
            out,
            "{}",
            serde_json::json!({"kept": kept, "suppressed": suppressed})
        )?;
    }
    Ok(())
}
