//! Scrub's raw `SECRET` spans on arbitrary text, for checking the port against Scrub's Python reference. Reads JSON lines `{"text": …}` on stdin and writes, per line, `[[start, end], …]` in UTF-8 byte offsets.
//!
//! Usage: scrub_spans <scrub dir>

use std::io::{BufRead, Write};

fn main() -> anyhow::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: scrub_spans <scrub dir>"))?;
    let model = piifence::scrub::ScrubModel::load(std::path::Path::new(&dir))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line?)?;
        let text = request["text"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("each line needs a \"text\" string"))?;
        let spans: Vec<_> = model
            .predict(text)?
            .iter()
            .map(|s| [s.start, s.end])
            .collect();
        writeln!(out, "{}", serde_json::json!(spans))?;
    }
    Ok(())
}
