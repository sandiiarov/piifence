//! Quick span probe for candidate placeholder formats / false-positive strings.
//!
//! Usage: cargo run --release --example probe -- "text one" "text two" ...

use privacy_filter_rs::{
    backend::{self, B},
    PrivacyFilterInference,
};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let model_dir = PathBuf::from(std::env::var("PIIF_MODEL_DIR").unwrap_or("data".into()));
    let device = backend::device();
    let engine = PrivacyFilterInference::<B>::load(&model_dir, device)?;

    for text in std::env::args().skip(1) {
        let spans = engine.predict(&text)?;
        let found: Vec<_> = spans
            .iter()
            .map(|s| {
                (
                    s.entity_group.clone(),
                    (s.score * 1000.0).round() / 1000.0,
                    s.word.clone(),
                )
            })
            .collect();
        println!("{text:?}\n  -> {found:?}");
    }
    Ok(())
}
