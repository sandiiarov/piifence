//! Stored name tables: each conversation's `(name, value, kind)` table, sealed with XChaCha20-Poly1305 under a key kept in the macOS Keychain, in one file per conversation id under `<state dir>/names`. The gateway writes them; this module reads them without changing them, for the gateway and for `piifence reveal`.

use std::path::Path;

use anyhow::Context;

/// Apple's Keychain tool. The key is read and written through it rather than the Keychain API, so the item belongs to a program that does not change when piifence is updated; otherwise macOS asks for access after every update.
pub const SECURITY_TOOL: &str = "/usr/bin/security";
/// The Keychain item (service and account) holding the key.
pub const KEY_SERVICE: &str = "piifence";
pub const KEY_ACCOUNT: &str = "names-key";
/// `security`'s exit code when no item matches.
const KEYCHAIN_NOT_FOUND: i32 = 44;

/// One stored entry: name, value and kind.
pub type Entry = (String, String, String);

pub fn unhex(text: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(text.len().is_multiple_of(2) && text.is_ascii(), "not hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).context("not hex"))
        .collect()
}

/// The key as stored, or None when there is none yet.
pub fn read_key() -> anyhow::Result<Option<[u8; 32]>> {
    let out = std::process::Command::new(SECURITY_TOOL)
        .args([
            "find-generic-password",
            "-s",
            KEY_SERVICE,
            "-a",
            KEY_ACCOUNT,
            "-w",
        ])
        .output()
        .context("run security")?;
    if out.status.code() == Some(KEYCHAIN_NOT_FOUND) {
        return Ok(None);
    }
    anyhow::ensure!(
        out.status.success(),
        "read piifence's key from the Keychain: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let key = unhex(String::from_utf8_lossy(&out.stdout).trim())?;
    Ok(Some(key.try_into().map_err(|_| {
        anyhow::anyhow!("piifence's Keychain key is not 32 bytes")
    })?))
}

/// The table in the file at `path`, which holds `conversation`'s table sealed with `key`. Empty when there is no file. Reading never changes the file, so its age, which decides when it is deleted, stays as it was.
pub fn open(path: &Path, conversation: &str, key: &[u8; 32]) -> anyhow::Result<Vec<Entry>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let sealed = match std::fs::read(path) {
        Ok(sealed) => sealed,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    anyhow::ensure!(sealed.len() > 24, "{} is cut short", path.display());
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(key.into());
    let (nonce, data) = sealed.split_at(24);
    let plain = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: data,
                aad: conversation.as_bytes(),
            },
        )
        .map_err(|_| {
            anyhow::anyhow!(
                "{} does not decrypt with piifence's Keychain key",
                path.display()
            )
        })?;
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(&plain).context("the stored table is not a JSON list")?;
    entries
        .iter()
        .map(|e| {
            let field = |key: &str| {
                e[key]
                    .as_str()
                    .map(str::to_string)
                    .with_context(|| format!("a stored entry has no {key}"))
            };
            Ok((field("name")?, field("value")?, field("kind")?))
        })
        .collect()
}

/// The conversation ids in `dir` that start with `prefix`. Files being written (`<id>.tmp<pid>`) are skipped.
pub fn conversations_with_prefix(dir: &Path, prefix: &str) -> anyhow::Result<Vec<String>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("read {}", dir.display())),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with(prefix) && is_conversation_id(&name) {
            ids.push(name);
        }
    }
    ids.sort();
    Ok(ids)
}

/// Whether `id` is a Claude Code conversation id: 36 characters of hex digits and dashes.
pub fn is_conversation_id(id: &str) -> bool {
    id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}
