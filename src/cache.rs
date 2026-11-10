//! Detection results cached per text, in memory and on disk.
//!
//! An entry is keyed by SHA-256 of the detector fingerprint plus the text, and holds only offsets, sources and suppression reasons. Neither the text nor a detected value is stored: on a hit, each span's `word` is cut back out of the text being looked up. The fingerprint covers everything besides the text that decides the result (the binary, the model files, gitleaks, the allowlist), so a change misses instead of returning stale spans.
//!
//! The disk file is append-only JSON lines, written with mode 0600 in a 0700 directory. When the file passes `MAX_FILE_BYTES` at load, it is rewritten with its newest half.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::detect::{DetectedSpan, Detection};
use crate::guards::Suppression;

/// Above this size at load, the file keeps only its newest half. An entry with no spans is about 80 bytes, so this holds hundreds of thousands of text blocks.
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone)]
struct StoredSpan {
    start: usize,
    end: usize,
    source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    suppressed: Option<Suppression>,
}

#[derive(Serialize, Deserialize)]
struct Line {
    key: String,
    spans: Vec<StoredSpan>,
}

pub struct DetectionCache {
    fingerprint: [u8; 32],
    entries: HashMap<String, Vec<StoredSpan>>,
    file: File,
}

impl DetectionCache {
    /// Load the entries in `path` and append new ones to it. A line that does not parse is an error: the file is written one whole line at a time, so a bad line means it was changed by something else.
    pub fn open(path: &Path, fingerprint: [u8; 32]) -> anyhow::Result<Self> {
        let dir = path.parent().context("cache path has no directory")?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create {}", dir.display()))?;
        let mut lines = read_lines(path)?;
        if path.exists() && std::fs::metadata(path)?.len() > MAX_FILE_BYTES {
            lines.drain(..lines.len() / 2);
            rewrite(path, &lines)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        Ok(Self {
            fingerprint,
            entries: lines.into_iter().map(|l| (l.key, l.spans)).collect(),
            file,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn key(&self, text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.fingerprint);
        hasher.update(text.as_bytes());
        hex(&hasher.finalize())
    }

    /// The cached detection for `text`. The key is a SHA-256 of the text, so an entry's offsets always fit it.
    pub fn get(&self, text: &str) -> Option<Detection> {
        let spans = self.entries.get(&self.key(text))?;
        let mut detection = Detection::default();
        for stored in spans {
            let span = DetectedSpan {
                word: text[stored.start..stored.end].to_string(),
                start: stored.start,
                end: stored.end,
                source: stored.source.clone(),
            };
            match stored.suppressed {
                Some(reason) => detection.suppressed.push((span, reason)),
                None => detection.kept.push(span),
            }
        }
        Some(detection)
    }

    /// Cache `detection` for `text` and append it to the disk file.
    pub fn insert(&mut self, text: &str, detection: &Detection) -> anyhow::Result<()> {
        let store = |span: &DetectedSpan, suppressed| StoredSpan {
            start: span.start,
            end: span.end,
            source: span.source.clone(),
            suppressed,
        };
        let spans: Vec<StoredSpan> = detection
            .kept
            .iter()
            .map(|span| store(span, None))
            .chain(
                detection
                    .suppressed
                    .iter()
                    .map(|(span, reason)| store(span, Some(*reason))),
            )
            .collect();
        let line = Line {
            key: self.key(text),
            spans,
        };
        let mut bytes = serde_json::to_vec(&line)?;
        bytes.push(b'\n');
        // One write per line, so concurrent appenders do not interleave within a line.
        self.file
            .write_all(&bytes)
            .context("append to the detection cache")?;
        self.entries.insert(line.key, line.spans);
        Ok(())
    }
}

fn read_lines(path: &Path) -> anyhow::Result<Vec<Line>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    BufReader::new(file)
        .lines()
        .enumerate()
        .map(|(n, line)| {
            let line = line?;
            serde_json::from_str(&line)
                .with_context(|| format!("{} line {}: not a cache entry", path.display(), n + 1))
        })
        .collect()
}

fn rewrite(path: &Path, lines: &[Line]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    for line in lines {
        let mut bytes = serde_json::to_vec(line)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Builds the detector fingerprint from named parts.
#[derive(Default)]
pub struct Fingerprint(Sha256);

impl Fingerprint {
    pub fn add(&mut self, name: &str, value: &[u8]) -> &mut Self {
        for part in [name.as_bytes(), value] {
            self.0.update((part.len() as u64).to_le_bytes());
            self.0.update(part);
        }
        self
    }

    /// Size and modification time of a file.
    pub fn add_file_stamp(&mut self, name: &str, path: &Path) -> anyhow::Result<&mut Self> {
        let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        let modified = meta
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        Ok(self.add(name, format!("{}:{modified}", meta.len()).as_bytes()))
    }

    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(word: &str, start: usize) -> DetectedSpan {
        DetectedSpan {
            word: word.into(),
            start,
            end: start + word.len(),
            source: "gitleaks:generic-api-key".into(),
        }
    }

    fn detection() -> Detection {
        Detection {
            kept: vec![span("hunter2", 4)],
            suppressed: vec![(span("$PIIF_SECRET_1", 16), Suppression::EnvReference)],
        }
    }

    const TEXT: &str = "pw: hunter2 and $PIIF_SECRET_1";

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("piif-cache-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn hit_rebuilds_values_from_the_text() {
        let dir = temp_dir("hit");
        let mut cache = DetectionCache::open(&dir.join("d.jsonl"), [1; 32]).unwrap();
        cache.insert(TEXT, &detection()).unwrap();
        let hit = cache.get(TEXT).unwrap();
        assert_eq!(hit.kept[0].word, "hunter2");
        assert_eq!(hit.suppressed[0].0.word, "$PIIF_SECRET_1");
        assert_eq!(hit.suppressed[0].1, Suppression::EnvReference);
        assert!(cache.get("other text").is_none());
        cache.fingerprint = [2; 32];
        assert!(cache.get(TEXT).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn disk_file_survives_a_restart_and_holds_no_values() {
        let dir = temp_dir("restart");
        let path = dir.join("detections.jsonl");
        let mut first = DetectionCache::open(&path, [1; 32]).unwrap();
        first.insert(TEXT, &detection()).unwrap();
        drop(first);

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("hunter2") && !on_disk.contains("pw:"));
        let mode = |p: &Path| {
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(p).unwrap().permissions())
                & 0o777
        };
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir), 0o700);

        let second = DetectionCache::open(&path, [1; 32]).unwrap();
        assert_eq!(second.get(TEXT).unwrap().kept[0].word, "hunter2");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_line_that_is_not_an_entry_is_an_error() {
        let dir = temp_dir("bad");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("detections.jsonl");
        std::fs::write(&path, "not json\n").unwrap();
        assert!(DetectionCache::open(&path, [1; 32]).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
