//! The secret model alone, for checking the Rust port against the model's Python reference (`bench/models/parity.py`). Reads JSON lines `{"text": …}` on stdin and writes, per line, the spans as `[[start, end, "TYPE"], …]` in UTF-8 byte offsets.
//!
//! Usage: model_spans <model dir>

use std::io::{BufRead, Write};

fn main() -> anyhow::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: model_spans <model dir>"))?;
    let model = piifence::model::SecretModel::load(std::path::Path::new(&dir))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line?)?;
        let text = request["text"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("each line needs a \"text\" string"))?;
        let spans: Vec<(usize, usize, String)> = model
            .predict(text)?
            .into_iter()
            .map(|s| (s.start, s.end, s.kind))
            .collect();
        writeln!(out, "{}", serde_json::to_string(&spans)?)?;
        out.flush()?;
    }
    Ok(())
}
