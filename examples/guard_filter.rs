//! Apply the gateway's model-span guards to spans from another detector, for `bench/models/shootout.py`.
//!
//! Reads one JSON object per line on stdin, `{"text": "...", "spans": [[start, end], ...]}` with byte offsets, and
//! writes one JSON array per line: the spans the guards keep, as `secret` model spans.
//!
//! Usage: cargo run --release --example guard_filter

use std::io::{BufRead, Write};

use piifence::guards::Guards;

#[derive(serde::Deserialize)]
struct Request {
    text: String,
    spans: Vec<(usize, usize)>,
}

fn main() -> anyhow::Result<()> {
    let guards = Guards::new()?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let request: Request = serde_json::from_str(&line?)?;
        let kept: Vec<(usize, usize)> = request
            .spans
            .into_iter()
            .filter(|&(start, end)| guards.suppress_model(&request.text, start, end).is_none())
            .collect();
        writeln!(out, "{}", serde_json::to_string(&kept)?)?;
        out.flush()?;
    }
    Ok(())
}
