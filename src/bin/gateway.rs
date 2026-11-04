//! piifence gateway — input-only redaction proxy for Claude Code.
//!
//! The only supported mode: redact what we send to the AI provider, stream the
//! response through untouched.
//!
//!   1. Claude Code points at it with `ANTHROPIC_BASE_URL=http://127.0.0.1:7788`.
//!   2. `POST /v1/messages` bodies are redacted (system, messages content,
//!      tool_result, tool_use.input) through the shared Detector
//!      (model + gitleaks + guards); spans become opaque numbered placeholders
//!      (`<private_email_1>`, `<secret_1>`, ...), numbered once per value
//!      through a keyed hash, so re-sent history is rewritten identically every turn.
//!   3. The redacted request is forwarded to `PIIF_UPSTREAM` with the original
//!      auth headers.
//!   4. The upstream response is streamed back byte-for-byte, unbuffered and
//!      unmodified. Placeholders are never restored: the provider never sees
//!      the raw value, and the agent sees the placeholder instead.
//!
//! No vault, no rehydration: placeholders are one-way by design. A later scan
//! of the same text (e.g. re-sent conversation history) skips the placeholder
//! through the placeholder guard, so nothing is double-redacted.
//!
//! Env: PIIF_MODEL_DIR (data), PIIF_UPSTREAM (required: provider base URL),
//! PIIF_PORT (7788), PIIF_AUDIT_LOG (/tmp/piifence-audit.log),
//! PIIF_AUDIT_BODY=1 (log the already-redacted request body for verification),
//! PIIF_CACHE_MB (64, detection cache budget).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use axum::Router;
use piifence_m1::detect::{DetectedSpan, Detector};
use regex::Regex;
use serde_json::{json, Value};

struct DetectJob {
    text: String,
    reply: tokio::sync::oneshot::Sender<anyhow::Result<Vec<DetectedSpan>>>,
}

#[derive(Default)]
struct Stats {
    requests: usize,
    redactions: usize,
    /// Distinct placeholders assigned since the gateway started.
    values: usize,
    allowed: usize,
    by_label: BTreeMap<String, usize>,
    recent: VecDeque<Value>,
    redact_ms_total: f64,
    redact_ms_last: f64,
    redact_ms_max: f64,
}

/// How long a "Send raw" approval stays valid. Short, so an approval that is never
/// used (the prompt was blocked or cancelled) cannot let a later request through raw.
const ALLOW_PROMPT_TTL: Duration = Duration::from_secs(60);

/// Largest request body the gateway accepts. Claude Code sends the whole
/// conversation on every turn, which can exceed axum's 2 MB default.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    detector_tx: std::sync::mpsc::Sender<DetectJob>,
    client: reqwest::Client,
    upstream: String,
    port: u16,
    audit: Arc<Mutex<std::fs::File>>,
    audit_body: Arc<Mutex<std::fs::File>>,
    placeholders: Arc<Mutex<Placeholders>>,
    stats: Arc<Mutex<Stats>>,
    allow_prompt_until: Arc<Mutex<Option<Instant>>>,
    /// `auto_approve` from the config file, handed to the approval mod by `/scan`.
    auto_approve: Option<&'static str>,
    /// Per-session settings and `$PIIF_…` values (see `Session`).
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    /// This request's session id (`session_id`), `""` outside a request or without one.
    session: String,
}

/// Consume the one-shot "Send raw" approval. Returns true only if one was granted
/// and has not expired; either way the approval is gone afterwards.
fn take_allow_prompt(state: &AppState) -> bool {
    let mut until = state.allow_prompt_until.lock().unwrap();
    match until.take() {
        Some(deadline) => Instant::now() <= deadline,
        None => false,
    }
}

/// Reject requests a browser page or a DNS-rebinding site could make. Claude Code
/// and the launcher send no `Origin` header and use `127.0.0.1` / `localhost` as Host.
fn is_local_request(state: &AppState, headers: &HeaderMap) -> bool {
    if headers.contains_key("origin") {
        return false;
    }
    let Some(host) = headers.get("host").and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let port = state.port;
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        "127.0.0.1".to_string(),
    ]
    .iter()
    .any(|allowed| host == allowed)
}

/// Masked preview for notices: first 4 + last 4 characters, never the full value.
fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "••••".to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

fn category_for(label: &str) -> &'static str {
    match label.to_ascii_lowercase().as_str() {
        "private_email" => "private_email",
        "private_person" => "private_person",
        "private_phone" => "private_phone",
        "private_address" => "private_address",
        "private_url" => "private_url",
        "private_date" => "private_date",
        "account_number" => "account_number",
        "secret" => "secret",
        _ => "private_entity",
    }
}

/// Placeholder numbers per (category, value), fixed for the life of the process.
/// Claude Code re-sends the raw history every turn, so numbering by value keeps the
/// rewritten history byte-identical across turns (prompt cache hits, valid thinking
/// signatures, consistent references). Values are keyed by a per-process keyed hash
/// and never stored, so there is no way back from a placeholder to its value.
#[derive(Default)]
struct Placeholders {
    hasher: std::collections::hash_map::RandomState,
    assigned: HashMap<(&'static str, u64), usize>,
    next: HashMap<&'static str, usize>,
}

impl Placeholders {
    /// The number for `value` in `category`, assigning the next free one on first sight,
    /// and whether it was assigned by this call (`true` only the first time).
    /// Surrounding whitespace is ignored: model spans sometimes include a leading space.
    fn number_for(&mut self, category: &'static str, value: &str) -> (usize, bool) {
        use std::hash::BuildHasher;
        let key = (category, self.hasher.hash_one(value.trim()));
        if let Some(number) = self.assigned.get(&key) {
            return (*number, false);
        }
        let next = self.next.entry(category).or_insert(0);
        *next += 1;
        self.assigned.insert(key, *next);
        (*next, true)
    }
}

/// The placeholder for `value`, and whether this is the first time it was seen.
fn next_placeholder(state: &AppState, label: &str, value: &str) -> (String, bool) {
    let category = category_for(label);
    let (number, new) = state
        .placeholders
        .lock()
        .unwrap()
        .number_for(category, value);
    let token = if category == "secret" {
        format!("<secret_{number}>")
    } else {
        format!("<{category}_{number}>")
    };
    (token, new)
}

/// Shortest value replaced by name. A shorter one would be replaced inside ordinary words.
const MIN_ENV_VALUE_CHARS: usize = 4;

/// Variables per category per session (`$PIIF_SECRET_1` to `$PIIF_SECRET_9`). The approval mod sets each name with a literal `$.env.set` call, so this must match its `ENV_LIMIT`.
const ENV_LIMIT: usize = 9;

/// The `PIIF_<CATEGORY>_<N>` category for a detection label, or `None` for a label with no variables.
fn env_category(label: &str) -> Option<&'static str> {
    Some(match label.to_ascii_lowercase().as_str() {
        "secret" => "SECRET",
        "private_email" => "EMAIL",
        "private_person" => "PERSON",
        "private_phone" => "PHONE",
        "private_address" => "ADDRESS",
        "private_url" => "URL",
        "private_date" => "DATE",
        "account_number" => "ACCOUNT",
        _ => return None,
    })
}

/// One value with a `$PIIF_…` name.
struct EnvValue {
    value: String,
    name: String,
    label: String,
    /// The variable holds (or is handed out with) this value, so every exact copy of it is replaced by the name. An inactive entry is a name `/scan` proposed for a prompt value the user has not chosen to replace yet.
    active: bool,
    /// Whether the value has been replaced in a request yet, so the notice reports it once.
    seen: bool,
}

/// One session's values with `$PIIF_…` names. The gateway owns the numbering, so a prompt value and a value found in a file never share a name. Commands run with the real value, so their output can contain it (`echo $PIIF_SECRET_1`); the gateway replaces every exact copy of an active value with `$NAME` in all provider-bound text before detection runs, so it never leaves even when detection would miss it. Held in memory only, never logged or written to disk, and lost when the gateway stops.
#[derive(Default)]
struct EnvValues {
    /// Longest value first, so a value that contains another is replaced whole.
    entries: Vec<EnvValue>,
    /// Highest number used per category.
    counters: HashMap<&'static str, usize>,
}

impl EnvValues {
    /// The name for `value`: the one it already has, else the next free one in its category (inactive until used or registered). `None` past `ENV_LIMIT`, for a label with no variables, or for a value too short to replace safely.
    fn name_for(&mut self, value: &str, label: &str) -> Option<String> {
        if let Some(entry) = self.entries.iter().find(|entry| entry.value == value) {
            return Some(entry.name.clone());
        }
        let category = env_category(label)?;
        if value.chars().count() < MIN_ENV_VALUE_CHARS {
            return None;
        }
        let counter = self.counters.entry(category).or_insert(0);
        if *counter >= ENV_LIMIT {
            return None;
        }
        *counter += 1;
        let name = format!("PIIF_{category}_{counter}");
        self.insert(EnvValue {
            value: value.to_string(),
            name: name.clone(),
            label: label.to_string(),
            active: false,
            seen: false,
        });
        Some(name)
    }

    /// Mark `value`'s name active, so every copy of the value is replaced by it.
    fn activate(&mut self, value: &str) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.value == value) {
            entry.active = true;
        }
    }

    /// Record that the mod put `value` into `$name`. This wins over what the gateway had: after a gateway restart the mod re-registers its values, and a name the gateway gave a different value since then is dropped from that value.
    fn register(&mut self, name: &str, value: &str, label: &str) {
        if value.chars().count() < MIN_ENV_VALUE_CHARS {
            return;
        }
        self.entries
            .retain(|entry| entry.value == value || entry.name != name);
        if let Some((category, number)) = parse_env_name(name) {
            let counter = self.counters.entry(category).or_insert(0);
            *counter = (*counter).max(number);
        }
        match self.entries.iter_mut().find(|entry| entry.value == value) {
            Some(entry) => {
                entry.name = name.to_string();
                entry.label = label.to_string();
                entry.active = true;
            }
            None => self.insert(EnvValue {
                value: value.to_string(),
                name: name.to_string(),
                label: label.to_string(),
                active: true,
                seen: false,
            }),
        }
    }

    fn insert(&mut self, entry: EnvValue) {
        self.entries.push(entry);
        self.entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.value.len()));
    }

    /// The values of the active entries named in `names`.
    fn lookup(&self, names: &[String]) -> serde_json::Map<String, Value> {
        self.entries
            .iter()
            .filter(|entry| entry.active && names.contains(&entry.name))
            .map(|entry| (entry.name.clone(), Value::String(entry.value.clone())))
            .collect()
    }
}

/// Per-session state, keyed by the `x-piifence-session` id the wrapper gives each Claude Code session.
#[derive(Default)]
struct Session {
    /// The approval mod's `autoApprovePiiFence` setting, sent with each `/scan`.
    setting: Option<String>,
    env: EnvValues,
}

/// The header carrying the session id: Claude Code sends it on every request (the wrapper sets `ANTHROPIC_CUSTOM_HEADERS`) and the approval mod on its own calls. It is stripped before forwarding.
const SESSION_HEADER: &str = "x-piifence-session";

/// The session id in `headers`, or `""` when it is missing or not 32 hex digits. The id is also what lets the mod fetch values, so only a well-formed one counts.
fn session_id(headers: &HeaderMap) -> String {
    headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or("")
        .to_string()
}

/// Run `f` on this request's session, creating it on first use.
fn with_session<T>(state: &AppState, f: impl FnOnce(&mut Session) -> T) -> T {
    let mut sessions = state.sessions.lock().unwrap();
    f(sessions.entry(state.session.clone()).or_default())
}

/// The choice that applies to values outside the prompt: the mod's `autoApprovePiiFence` when it is set to anything but `ask`, else config.toml's `auto_approve`. Only `replace` changes anything there; every other choice means placeholders. Without a session id nothing could fetch the values, so it is never `replace`.
fn replaces_with_env(state: &AppState) -> bool {
    if state.session.is_empty() {
        return false;
    }
    let setting = with_session(state, |session| session.setting.clone());
    let choice = match setting.as_deref() {
        Some(setting) if setting != "ask" => setting,
        _ => state.auto_approve.unwrap_or("ask"),
    };
    choice == "replace"
}

fn env_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^PIIF_([A-Z]+)_([0-9]+)$").expect("env name regex"))
}

/// The category and number of a `PIIF_<CATEGORY>_<N>` name the gateway could have given out.
fn parse_env_name(name: &str) -> Option<(&'static str, usize)> {
    let caps = env_name_re().captures(name)?;
    let category = [
        "SECRET", "EMAIL", "PERSON", "PHONE", "ADDRESS", "URL", "DATE", "ACCOUNT",
    ]
    .into_iter()
    .find(|category| *category == &caps[1])?;
    let number: usize = caps[2].parse().ok()?;
    (1..=ENV_LIMIT)
        .contains(&number)
        .then_some((category, number))
}

/// The `(name, value, label)` triples of a `/control/env-values` body, `{"values": [{"name", "value", "label"}]}`, or `None` if any entry is malformed. The whole body is rejected so the mod blocks the prompt rather than set a variable the gateway does not track.
fn parse_env_values(body: &[u8]) -> Option<Vec<(String, String, String)>> {
    let parsed: Value = serde_json::from_slice(body).ok()?;
    parsed
        .get("values")?
        .as_array()?
        .iter()
        .map(|entry| {
            let name = entry.get("name")?.as_str()?;
            let value = entry.get("value")?.as_str()?;
            let label = entry
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or("secret");
            (parse_env_name(name).is_some() && !value.is_empty())
                .then(|| (name.to_string(), value.to_string(), label.to_string()))
        })
        .collect()
}

/// Replace every active env value in `text` with `$NAME`, returning the new text and one audit entry per replacement. Offsets are into the text as it stood when that value was replaced, after any longer values.
fn replace_env_values(state: &AppState, text: &str, field: &str) -> (String, Vec<Value>) {
    with_session(state, |session| {
        let mut out = text.to_string();
        let mut audit = Vec::new();
        for entry in session.env.entries.iter_mut() {
            if !entry.active || !out.contains(&entry.value) {
                continue;
            }
            let token = format!("${}", entry.name);
            for (start, _) in out.match_indices(&entry.value) {
                audit.push(json!({
                    "field": field,
                    "label": entry.label,
                    "score": 1.0,
                    "start": start,
                    "end": start + entry.value.len(),
                    "placeholder": token,
                    "new": !entry.seen,
                    "preview": mask_value(&entry.value),
                    "engine": "env",
                }));
                entry.seen = true;
            }
            out = out.replace(&entry.value, &token);
        }
        (out, audit)
    })
}

/// The replacement for one detected value: `$NAME` when this session replaces values with variables and one is free, else the placeholder. Returns the token and whether the value is new to the notice.
fn token_for(state: &AppState, replace: bool, label: &str, value: &str) -> (String, bool) {
    if replace {
        let named = with_session(state, |session| {
            let name = session.env.name_for(value, label)?;
            session.env.activate(value);
            let entry = session
                .env
                .entries
                .iter_mut()
                .find(|entry| entry.value == value)?;
            let new = !entry.seen;
            entry.seen = true;
            Some((format!("${name}"), new))
        });
        if let Some(named) = named {
            return named;
        }
    }
    next_placeholder(state, label, value)
}

fn record_allowed(state: &AppState) {
    let mut stats = state.stats.lock().unwrap();
    stats.requests += 1;
    stats.allowed += 1;
}

impl Stats {
    /// Fold one request's audit entries in. `redactions` counts every replaced
    /// span (history is re-sent every turn, so it grows fast); `values` counts a
    /// value only the first time it gets a placeholder, and `recent` keeps only
    /// those first sightings so the notice can show what is new.
    fn record(&mut self, audit: &[Value], redact_ms: f64) {
        self.requests += 1;
        self.redactions += audit.len();
        self.redact_ms_total += redact_ms;
        self.redact_ms_last = redact_ms;
        self.redact_ms_max = self.redact_ms_max.max(redact_ms);
        for entry in audit {
            if let Some(label) = entry.get("label").and_then(|v| v.as_str()) {
                *self.by_label.entry(label.to_string()).or_insert(0) += 1;
            }
            if entry.get("new").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            self.values += 1;
            self.recent.push_back(entry.clone());
            while self.recent.len() > 20 {
                self.recent.pop_front();
            }
        }
    }
}

fn record_stats(state: &AppState, audit: &[Value], redact_ms: f64) {
    state.stats.lock().unwrap().record(audit, redact_ms);
}

fn audit_line(state: &AppState, entry: Value) {
    let mut guard = state.audit.lock().unwrap();
    let _ = writeln!(guard, "{entry}");
}

async fn detect_kept(state: &AppState, text: &str) -> anyhow::Result<Vec<DetectedSpan>> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    state
        .detector_tx
        .send(DetectJob {
            text: text.to_string(),
            reply: reply_tx,
        })
        .map_err(|_| anyhow::anyhow!("detector worker stopped"))?;
    reply_rx
        .await
        .map_err(|_| anyhow::anyhow!("detector worker dropped the job"))?
}

/// Claude Code bash-mode output (`!command`) arrives as `<bash-input>` /
/// `<bash-stdout>` tags in message text, without a tool_use/tool_result pair.
/// Scan the stdout with the shell command as model context, then run the normal
/// scan over the rest of the text.
async fn redact_text_smart(
    state: &AppState,
    text: &str,
    field: &str,
) -> anyhow::Result<(String, Vec<Value>)> {
    let (bash_redacted, mut audit) = redact_bash_outputs(state, text, field).await?;
    let (out, mut more) = redact_text(state, &bash_redacted, field).await?;
    audit.append(&mut more);
    Ok((out, audit))
}

fn bash_input_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<bash-input>(.*?)</bash-input>").expect("bash-input regex"))
}

fn bash_output_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)<(?:bash-stdout|local-command-stdout)>(.*?)</(?:bash-stdout|local-command-stdout)>")
            .expect("bash-stdout regex")
    })
}

async fn redact_bash_outputs(
    state: &AppState,
    text: &str,
    field: &str,
) -> anyhow::Result<(String, Vec<Value>)> {
    let commands: Vec<(usize, String)> = bash_input_re()
        .captures_iter(text)
        .filter_map(|cap| {
            let full = cap.get(0)?;
            Some((full.start(), cap.get(1)?.as_str().to_string()))
        })
        .collect();
    let mut replacements: Vec<(usize, usize, String, Vec<Value>)> = Vec::new();
    for cap in bash_output_re().captures_iter(text) {
        let Some(full) = cap.get(0) else { continue };
        let Some(inner) = cap.get(1) else { continue };
        let command = commands
            .iter()
            .rev()
            .find(|(start, _)| *start < full.start())
            .map(|(_, command)| command.as_str());
        let context = command.map(|command| format!("Shell command: {command}\nShell output:"));
        let (redacted, audit) = redact_text_with_context(
            state,
            &text[inner.start()..inner.end()],
            field,
            context.as_deref(),
        )
        .await?;
        if !audit.is_empty() {
            replacements.push((inner.start(), inner.end(), redacted, audit));
        }
    }
    if replacements.is_empty() {
        return Ok((text.to_string(), Vec::new()));
    }
    let mut out = text.to_string();
    let mut audit = Vec::new();
    for (start, end, redacted, mut entries) in replacements.into_iter().rev() {
        out.replace_range(start..end, &redacted);
        audit.append(&mut entries);
    }
    Ok((out, audit))
}

/// Redact one text block, returning the rewritten text and the audit entries.
async fn redact_text(
    state: &AppState,
    text: &str,
    field: &str,
) -> anyhow::Result<(String, Vec<Value>)> {
    redact_text_with_context(state, text, field, None).await
}

/// Spans from one detection, mapped onto `text` (the region after the model-only
/// context of `offset` bytes) and made non-overlapping, sorted by start. Overlaps are
/// unioned rather than picked: keeping only one of two overlapping spans used to
/// leave the other's extra bytes visible. A span that starts in the context but ends
/// in the text is clamped to the text. Surrounding ASCII whitespace is trimmed so a
/// placeholder does not swallow the space before a value.
fn normalize_spans(spans: Vec<DetectedSpan>, text: &str, offset: usize) -> Vec<DetectedSpan> {
    let text_end = offset + text.len();
    let bytes = text.as_bytes();
    let mut mapped: Vec<DetectedSpan> = spans
        .into_iter()
        .filter(|span| span.end > offset && span.start < text_end)
        .filter_map(|mut span| {
            let mut start = span.start.max(offset) - offset;
            let mut end = span.end.min(text_end) - offset;
            while start > 0 && !text.is_char_boundary(start) {
                start -= 1;
            }
            while end < text.len() && !text.is_char_boundary(end) {
                end += 1;
            }
            while start < end && bytes[start].is_ascii_whitespace() {
                start += 1;
            }
            while end > start && bytes[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
            if start >= end {
                return None;
            }
            span.start = start;
            span.end = end;
            Some(span)
        })
        .collect();
    mapped.sort_by_key(|span| (span.start, span.end));

    let mut out: Vec<DetectedSpan> = Vec::new();
    for span in mapped {
        match out.last_mut() {
            Some(current) if span.start < current.end => {
                let current_len = current.end - current.start;
                let span_len = span.end - span.start;
                let current_secret = current.label.eq_ignore_ascii_case("secret");
                let span_secret = span.label.eq_ignore_ascii_case("secret");
                let span_wins = if current_secret != span_secret {
                    span_secret
                } else {
                    span_len > current_len
                };
                if span_wins {
                    current.label = span.label.clone();
                    current.source = span.source.clone();
                }
                current.score = current.score.max(span.score);
                current.end = current.end.max(span.end);
                current.word.clear();
            }
            _ => out.push(span),
        }
    }
    out
}

/// Redact a text block, optionally with a synthetic context prepended for the
/// model only (e.g. the tool call that produced a tool_result). Spans wholly in
/// the context region are discarded and spans crossing into `text` are clamped to
/// it (see `normalize_spans`); only `text` is rewritten.
async fn redact_text_with_context(
    state: &AppState,
    text: &str,
    field: &str,
    context: Option<&str>,
) -> anyhow::Result<(String, Vec<Value>)> {
    // Known env values go first, so detection sees `$PIIF_SECRET_1` (which the env-ref guard skips) and never the value itself. The context is shown to the model only, so it is left as is.
    let (text, mut audit) = replace_env_values(state, text, field);
    let text = text.as_str();
    let (input, offset) = match context {
        Some(context) if !context.is_empty() => (format!("{context}\n{text}"), context.len() + 1),
        _ => (text.to_string(), 0),
    };
    let kept = detect_kept(state, &input).await?;
    // Sorted, non-overlapping, so replacing right to left keeps offsets valid.
    let mut accepted = normalize_spans(kept, text, offset);
    if accepted.is_empty() {
        return Ok((text.to_string(), audit));
    }
    accepted.reverse();
    let replace = replaces_with_env(state);
    let mut out = text.to_string();

    // Number left to right so placeholders read in document order; replace right to
    // left so earlier offsets stay valid.
    let tokens: Vec<(String, bool)> = accepted
        .iter()
        .rev()
        .map(|span| token_for(state, replace, &span.label, &text[span.start..span.end]))
        .collect();
    for (span, token) in accepted.iter().zip(tokens.iter().rev()) {
        let preview = mask_value(&text[span.start..span.end]);
        out.replace_range(span.start..span.end, &token.0);
        audit.push(json!({
            "field": field,
            "label": span.label,
            "score": (span.score * 1000.0).round() / 1000.0,
            "start": span.start,
            "end": span.end,
            "placeholder": token.0,
            "new": token.1,
            "preview": preview,
            "engine": span.source.split(':').next().unwrap_or(""),
        }));
    }
    Ok((out, audit))
}

#[async_recursion::async_recursion]
async fn redact_json_strings(
    state: &AppState,
    value: &mut Value,
    field: &str,
) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    match value {
        Value::String(text) => {
            let (out, mut entries) = redact_text(state, text, field).await?;
            if !entries.is_empty() {
                *text = out;
                audit.append(&mut entries);
            }
        }
        Value::Array(items) => {
            for item in items {
                audit.extend(redact_json_strings(state, item, field).await?);
            }
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                audit.extend(redact_json_strings(state, item, field).await?);
            }
        }
        _ => {}
    }
    Ok(audit)
}

#[async_recursion::async_recursion]
async fn redact_content(
    state: &AppState,
    content: &mut Value,
    tool_map: &HashMap<String, (String, String)>,
    skip_text: bool,
) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    match content {
        Value::String(text) => {
            if skip_text {
                return Ok(audit);
            }
            let (out, mut entries) = redact_text_smart(state, text, "content").await?;
            if !entries.is_empty() {
                *text = out;
                audit.append(&mut entries);
            }
        }
        Value::Array(blocks) => {
            for block in blocks {
                audit.extend(redact_block(state, block, tool_map, None, skip_text).await?);
            }
        }
        _ => {}
    }
    Ok(audit)
}

/// The model-only context for a tool_result: the tool call that produced it, so bare
/// values (e.g. `echo $OPENCODE_API_KEY`) are recognised. Long input is cut at 800 bytes.
fn tool_result_context(
    block: &Value,
    tool_map: &HashMap<String, (String, String)>,
) -> Option<String> {
    block
        .get("tool_use_id")
        .and_then(|v| v.as_str())
        .and_then(|id| tool_map.get(id))
        .map(|(name, input)| {
            let mut input = input.clone();
            if input.len() > 800 {
                // `truncate` panics off a char boundary, so back up to one.
                let mut cut = 800;
                while !input.is_char_boundary(cut) {
                    cut -= 1;
                }
                input.truncate(cut);
            }
            format!("Tool call: {name} {input}\nTool output:")
        })
}

/// Redact the string at `block[key]` in place with `redact_text`, if it is a string.
async fn redact_string_field(
    state: &AppState,
    block: &mut Value,
    key: &str,
    field: &str,
) -> anyhow::Result<Vec<Value>> {
    if let Some(Value::String(s)) = block.get_mut(key) {
        let (out, entries) = redact_text(state, s, field).await?;
        if !entries.is_empty() {
            *s = out;
        }
        return Ok(entries);
    }
    Ok(Vec::new())
}

/// Redact one content block in place. Every block type that can carry user text is
/// routed here, so a new block shape has exactly one place to be added. `context` is
/// the originating tool call for blocks nested in a tool_result; it is shown to the
/// model only, never redacted here. Thinking blocks are signed by the provider and
/// images carry no text, so those and unknown types are left untouched.
#[async_recursion::async_recursion]
async fn redact_block(
    state: &AppState,
    block: &mut Value,
    tool_map: &HashMap<String, (String, String)>,
    context: Option<&str>,
    skip_text: bool,
) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    let kind = block
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    match kind.as_str() {
        "text" => {
            if skip_text {
                return Ok(audit);
            }
            if let Some(Value::String(s)) = block.get_mut("text") {
                let (out, mut entries) = match context {
                    Some(context) => {
                        redact_text_with_context(state, s, "tool_result.text", Some(context))
                            .await?
                    }
                    None => redact_text_smart(state, s, "text").await?,
                };
                if !entries.is_empty() {
                    *s = out;
                    audit.append(&mut entries);
                }
            }
        }
        "tool_result" => {
            let context = tool_result_context(block, tool_map);
            match block.get_mut("content") {
                Some(Value::String(text)) => {
                    let (out, mut entries) = match context.as_deref() {
                        Some(context) => {
                            redact_text_with_context(state, text, "tool_result", Some(context))
                                .await?
                        }
                        None => redact_text_smart(state, text, "content").await?,
                    };
                    if !entries.is_empty() {
                        *text = out;
                        audit.append(&mut entries);
                    }
                }
                Some(Value::Array(inner)) => {
                    for item in inner {
                        audit.extend(
                            redact_block(state, item, tool_map, context.as_deref(), false).await?,
                        );
                    }
                }
                _ => {}
            }
        }
        "tool_use" => {
            if let Some(input) = block.get_mut("input") {
                audit.extend(redact_json_strings(state, input, "tool_use.input").await?);
            }
        }
        "document" => {
            let is_text = block
                .get("source")
                .and_then(|s| s.get("type"))
                .and_then(|t| t.as_str())
                == Some("text");
            if is_text {
                if let Some(source) = block.get_mut("source") {
                    audit.extend(
                        redact_string_field(state, source, "data", "document.source.data").await?,
                    );
                }
            }
            audit.extend(redact_string_field(state, block, "title", "document.title").await?);
            audit.extend(redact_string_field(state, block, "context", "document.context").await?);
        }
        "search_result" => {
            audit.extend(redact_string_field(state, block, "title", "search_result.title").await?);
            audit
                .extend(redact_string_field(state, block, "source", "search_result.source").await?);
            if let Some(Value::Array(inner)) = block.get_mut("content") {
                for item in inner {
                    audit.extend(redact_block(state, item, tool_map, context, false).await?);
                }
            }
        }
        _ => {}
    }
    Ok(audit)
}

async fn redact_payload(
    state: &AppState,
    body: &mut Value,
    allow_prompt_once: bool,
) -> anyhow::Result<Vec<Value>> {
    let mut audit = Vec::new();
    // Map tool_use id -> (tool name, serialized input) so tool_result content can
    // be scanned with the call that produced it as model context.
    let mut tool_map: HashMap<String, (String, String)> = HashMap::new();
    if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
        for message in messages {
            if let Some(blocks) = message.get("content").and_then(|c| c.as_array()) {
                for block in blocks {
                    if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                        if let (Some(id), Some(name)) = (
                            block.get("id").and_then(|v| v.as_str()),
                            block.get("name").and_then(|v| v.as_str()),
                        ) {
                            let input = block
                                .get("input")
                                .map(|v| serde_json::to_string(v).unwrap_or_default())
                                .unwrap_or_default();
                            tool_map.insert(id.to_string(), (name.to_string(), input));
                        }
                    }
                }
            }
        }
    }
    if let Some(system) = body.get_mut("system") {
        audit.extend(redact_content(state, system, &tool_map, false).await?);
    }
    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        let last_user = messages
            .iter()
            .rposition(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"));
        for (index, message) in messages.iter_mut().enumerate() {
            if let Some(content) = message.get_mut("content") {
                let skip_text = allow_prompt_once && Some(index) == last_user;
                audit.extend(redact_content(state, content, &tool_map, skip_text).await?);
            }
        }
    }
    if allow_prompt_once {
        audit_line(state, json!({"event":"allowed_prompt"}));
    }
    Ok(audit)
}

async fn proxy(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !is_local_request(&state, &headers) {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from(
                "piifence only accepts local, non-browser requests",
            ))
            .unwrap();
    }
    let state = AppState {
        session: session_id(&headers),
        ..state
    };
    let path = uri.path();
    if path == "/health" {
        // The launcher compares this header to its own upstream before reusing a gateway.
        return Response::builder()
            .status(StatusCode::OK)
            .header("x-piifence-upstream", state.upstream.as_str())
            .body(Body::from("ok"))
            .unwrap();
    }
    if path == "/stats" {
        let stats = state.stats.lock().unwrap();
        let body = json!({
            "requests": stats.requests,
            "redactions": stats.redactions,
            "values": stats.values,
            "allowed": stats.allowed,
            "redact_ms_last": (stats.redact_ms_last * 100.0).round() / 100.0,
            "redact_ms_total": (stats.redact_ms_total * 100.0).round() / 100.0,
            "redact_ms_max": (stats.redact_ms_max * 100.0).round() / 100.0,
            "by_label": stats.by_label,
            "recent": stats.recent.iter().cloned().collect::<Vec<_>>(),
        });
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
    }
    if path == "/scan" && method == Method::POST {
        let parsed = serde_json::from_slice::<Value>(&body).ok();
        let Some(text) = parsed
            .as_ref()
            .and_then(|value| value.get("text"))
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("missing text"))
                .unwrap();
        };
        // The mod's `autoApprovePiiFence`, which decides how this session's tool output is redacted (`replaces_with_env`).
        if let Some(setting) = parsed
            .as_ref()
            .and_then(|value| value.get("setting"))
            .and_then(Value::as_str)
        {
            let setting = setting.to_string();
            with_session(&state, |session| session.setting = Some(setting));
        }
        return match detect_kept(&state, &text).await {
            Ok(spans) => {
                let findings: Vec<Value> = spans
                    .iter()
                    .map(|span| {
                        let value = &text[span.start..span.end];
                        // The name this value gets if the user chooses to replace it; it only takes effect once the mod registers it.
                        let env = with_session(&state, |session| {
                            session.env.name_for(value, &span.label)
                        });
                        json!({
                            "label": span.label,
                            "score": (span.score * 1000.0).round() / 1000.0,
                            "start": text[..span.start].encode_utf16().count(),
                            "end": text[..span.end].encode_utf16().count(),
                            "preview": mask_value(value),
                            "engine": span.source.split(':').next().unwrap_or(""),
                            "env": env,
                        })
                    })
                    .collect();
                let payload = json!({"findings": findings, "auto_approve": state.auto_approve});
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap()
            }
            Err(err) => Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("content-type", "application/json")
                .body(Body::from(json!({"error": err.to_string()}).to_string()))
                .unwrap(),
        };
    }
    if path == "/control/allow-prompt-once" && method == Method::POST {
        *state.allow_prompt_until.lock().unwrap() = Some(Instant::now() + ALLOW_PROMPT_TTL);
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(json!({"ok": true}).to_string()))
            .unwrap();
    }
    if path == "/control/env-values" && method == Method::POST {
        let status = match parse_env_values(&body) {
            Some(values) => {
                with_session(&state, |session| {
                    for (name, value, label) in &values {
                        session.env.register(name, value, label);
                    }
                });
                StatusCode::OK
            }
            None => StatusCode::BAD_REQUEST,
        };
        return Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"ok": status == StatusCode::OK}).to_string(),
            ))
            .unwrap();
    }
    // The approval mod asks for the values behind the `$PIIF_…` names a Bash command uses, so it can set them just before the command runs. Values are handed out only to the session they belong to, so a request without the session id gets nothing.
    if path == "/control/env-lookup" && method == Method::POST {
        let names: Option<Vec<String>> =
            serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|value| {
                    value.get("names")?.as_array().map(|names| {
                        names
                            .iter()
                            .filter_map(|name| name.as_str().map(str::to_string))
                            .collect()
                    })
                });
        let (status, values) = match names {
            _ if state.session.is_empty() => (StatusCode::FORBIDDEN, serde_json::Map::new()),
            Some(names) => (
                StatusCode::OK,
                with_session(&state, |session| session.env.lookup(&names)),
            ),
            None => (StatusCode::BAD_REQUEST, serde_json::Map::new()),
        };
        audit_line(
            &state,
            json!({"event": "env_lookup", "status": status.as_u16(), "found": values.len()}),
        );
        return Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(json!({"values": values}).to_string()))
            .unwrap();
    }

    // Every POST under /v1/messages carries conversation text. Redact the two shapes
    // that share the Messages body (`/v1/messages`, `/v1/messages/count_tokens`) and
    // refuse any other, such as batches, rather than forwarding its text unscanned.
    let is_messages = matches!(path, "/v1/messages" | "/v1/messages/count_tokens");
    let is_other_messages_path = path.starts_with("/v1/messages/") && !is_messages;
    if is_other_messages_path && method == Method::POST {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"type":"error","error":{"type":"piifence_error","message":"this endpoint is not redacted; request blocked"}}).to_string(),
            ))
            .unwrap();
    }
    let mut outgoing = body.clone();

    if is_messages && method == Method::POST {
        let allow_prompt_once = take_allow_prompt(&state);
        match serde_json::from_slice::<Value>(&outgoing) {
            Ok(mut payload) => {
                let started = std::time::Instant::now();
                let result = redact_payload(&state, &mut payload, allow_prompt_once).await;
                let redact_ms = started.elapsed().as_secs_f64() * 1000.0;
                match (result, redact_ms) {
                    (Ok(audit), redact_ms) => {
                        let redacted = serde_json::to_vec(&payload).unwrap_or_default();
                        if !audit.is_empty() {
                            audit_line(
                                &state,
                                json!({"event":"redacted","spans":audit.len(),"details":audit}),
                            );
                            if let Ok(mut f) = state.audit_body.lock() {
                                let _ = writeln!(f, "{}", String::from_utf8_lossy(&redacted));
                            }
                            record_stats(&state, &audit, redact_ms);
                        }
                        if allow_prompt_once {
                            record_allowed(&state);
                        }
                        outgoing = axum::body::Bytes::from(redacted);
                    }
                    (Err(err), _) => {
                        // Fail closed: never forward a payload we could not redact.
                        audit_line(
                            &state,
                            json!({"event":"redact_error","error":err.to_string()}),
                        );
                        return Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .header("content-type", "application/json")
                            .body(Body::from(
                                json!({"type":"error","error":{"type":"piifence_error","message":"redaction failed; request blocked"}}).to_string(),
                            ))
                            .unwrap();
                    }
                }
            }
            Err(err) => {
                audit_line(
                    &state,
                    json!({"event":"parse_error","error":err.to_string()}),
                );
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("invalid JSON"))
                    .unwrap();
            }
        }
    }

    let upstream_url = format!(
        "{}{}",
        state.upstream.trim_end_matches('/'),
        uri.path_and_query().map(|p| p.as_str()).unwrap_or(path)
    );

    let mut forward_headers = HeaderMap::new();
    for (name, value) in headers.iter() {
        if matches!(
            name.as_str(),
            "host" | "content-length" | "accept-encoding" | "connection" | SESSION_HEADER
        ) {
            continue;
        }
        forward_headers.insert(name.clone(), value.clone());
    }

    let upstream = match state
        .client
        .request(method.clone(), &upstream_url)
        .headers(forward_headers)
        .body(outgoing.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            audit_line(
                &state,
                json!({"event":"upstream_error","error":err.to_string()}),
            );
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("upstream error: {err}")))
                .unwrap();
        }
    };

    // Response: byte-for-byte passthrough, streamed as it arrives. No parsing,
    // no buffering, no placeholder rehydration — input-only by design.
    let status = upstream.status();
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream.headers().iter() {
        if matches!(
            name.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap()
}

/// Open a log for appending with owner-only permissions. The mode applies when the
/// file is created, so an existing log keeps its current mode.
fn open_private_append(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let model_dir = PathBuf::from(std::env::var("PIIF_MODEL_DIR").unwrap_or("data".into()));
    let upstream = std::env::var("PIIF_UPSTREAM").map_err(|_| {
        anyhow::anyhow!("PIIF_UPSTREAM is required: set it to the provider's base URL")
    })?;
    let port: u16 = std::env::var("PIIF_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7788);
    let audit_path =
        std::env::var("PIIF_AUDIT_LOG").unwrap_or_else(|_| "/tmp/piifence-audit.log".into());
    let audit_body_path = std::env::var("PIIF_AUDIT_BODY")
        .ok()
        .filter(|v| v != "0")
        .map(|_| "/tmp/piifence-redacted-bodies.jsonl".to_string());

    let audit = open_private_append(&audit_path)?;
    let audit_body = match &audit_body_path {
        Some(path) => open_private_append(path)?,
        None => std::fs::OpenOptions::new().write(true).open("/dev/null")?,
    };

    let config = piifence_m1::config::load()?;
    let categories = config.category_set()?;
    let llm_filter = config.llm_filter.unwrap_or(true);
    let auto_approve = config.auto_approve()?;
    let use_gitleaks = std::env::var("PIIF_GITLEAKS")
        .map(|v| v != "0" && v != "off" && v != "false")
        .unwrap_or(true);
    if use_gitleaks {
        // Fail at startup, not on the first request, when the pre-pass tool is missing.
        let found = std::process::Command::new("gitleaks")
            .arg("version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        anyhow::ensure!(
            found,
            "gitleaks not found (install with `brew install gitleaks`, or set PIIF_GITLEAKS=0)"
        );
    }
    if piifence_m1::detect::needs_model(&categories, llm_filter) {
        anyhow::ensure!(
            model_dir.exists(),
            "model dir not found: {} (run scripts/fetch-weights.sh or set PIIF_MODEL_DIR)",
            model_dir.display()
        );
        eprintln!(
            "Loading detector from {} (upstream {}, port {})",
            model_dir.display(),
            upstream,
            port
        );
    } else {
        eprintln!("secret-only configuration: rules only (gitleaks), model not loaded");
    }
    let detector = Detector::load_with_categories(
        &model_dir,
        use_gitleaks,
        true,
        categories.clone(),
        llm_filter,
    )?;
    eprintln!("Detector loaded; input-only redaction (responses streamed untouched)");
    eprintln!("llm filter: {llm_filter}");
    eprintln!("auto approve: {}", auto_approve.unwrap_or("ask"));
    eprintln!("gitleaks: {use_gitleaks}");
    if use_gitleaks {
        match piifence_m1::gitleaks::config_path() {
            Some(path) => eprintln!("gitleaks config: {}", path.display()),
            None => eprintln!("gitleaks config: default rules (project gitleaks.toml not found)"),
        }
    }
    eprintln!(
        "categories: {}",
        match &categories {
            None => "all".to_string(),
            Some(set) => {
                let mut names: Vec<&str> = set.iter().map(|s| s.as_str()).collect();
                names.sort_unstable();
                names.join(", ")
            }
        }
    );

    // The Burn model is not Sync (Param uses OnceCell), so it stays on one
    // worker thread and requests are served through a channel.
    let (detector_tx, detector_rx) = std::sync::mpsc::channel::<DetectJob>();
    std::thread::spawn(move || {
        while let Ok(job) = detector_rx.recv() {
            let result = detector.detect(&job.text).map(|detection| detection.kept);
            let _ = job.reply.send(result);
        }
    });

    let state = AppState {
        detector_tx,
        client: reqwest::Client::builder()
            .build()
            .expect("build reqwest client"),
        upstream,
        port,
        audit: Arc::new(Mutex::new(audit)),
        audit_body: Arc::new(Mutex::new(audit_body)),
        placeholders: Arc::new(Mutex::new(Placeholders::default())),
        stats: Arc::new(Mutex::new(Stats::default())),
        allow_prompt_until: Arc::new(Mutex::new(None)),
        auto_approve,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        session: String::new(),
    };

    let app = Router::new()
        .fallback(proxy)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("piifence gateway listening on http://127.0.0.1:{port}");
    eprintln!(
        "audit log: {} (body log: {})",
        audit_path,
        audit_body_path.unwrap_or_else(|| "off".to_string())
    );
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_value_keeps_its_number() {
        let mut p = Placeholders::default();
        assert_eq!(p.number_for("secret", "abc"), (1, true));
        assert_eq!(p.number_for("secret", "abc"), (1, false));
    }

    #[test]
    fn new_values_get_the_next_number() {
        let mut p = Placeholders::default();
        assert_eq!(p.number_for("secret", "abc"), (1, true));
        assert_eq!(p.number_for("secret", "def"), (2, true));
        assert_eq!(p.number_for("secret", "abc"), (1, false));
    }

    #[test]
    fn categories_count_independently() {
        let mut p = Placeholders::default();
        assert_eq!(p.number_for("secret", "abc"), (1, true));
        assert_eq!(p.number_for("private_email", "x@example.org"), (1, true));
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        let mut p = Placeholders::default();
        assert_eq!(p.number_for("secret", " abc"), (1, true));
        assert_eq!(p.number_for("secret", "abc"), (1, false));
        assert_eq!(p.number_for("secret", "abc\n"), (1, false));
    }

    /// An AppState whose detector marks every occurrence of `TOKEN` as a secret, so
    /// the block walker can be tested without model weights or gitleaks.
    fn fake_state() -> AppState {
        let (detector_tx, detector_rx) = std::sync::mpsc::channel::<DetectJob>();
        std::thread::spawn(move || {
            while let Ok(job) = detector_rx.recv() {
                let spans = job
                    .text
                    .match_indices("TOKEN")
                    .map(|(start, word)| DetectedSpan {
                        label: "secret".to_string(),
                        score: 1.0,
                        word: word.to_string(),
                        start,
                        end: start + word.len(),
                        source: "fake".to_string(),
                    })
                    .collect();
                let _ = job.reply.send(Ok(spans));
            }
        });
        let null = || {
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .unwrap()
        };
        AppState {
            detector_tx,
            client: reqwest::Client::new(),
            upstream: "http://127.0.0.1:1".to_string(),
            port: 0,
            audit: Arc::new(Mutex::new(null())),
            audit_body: Arc::new(Mutex::new(null())),
            placeholders: Arc::new(Mutex::new(Placeholders::default())),
            stats: Arc::new(Mutex::new(Stats::default())),
            allow_prompt_until: Arc::new(Mutex::new(None)),
            auto_approve: None,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session: "0123456789abcdef0123456789abcdef".to_string(),
        }
    }

    fn span(label: &str, start: usize, end: usize) -> DetectedSpan {
        DetectedSpan {
            label: label.to_string(),
            score: 0.9,
            word: String::new(),
            start,
            end,
            source: "test".to_string(),
        }
    }

    fn ranges(spans: &[DetectedSpan]) -> Vec<(usize, usize, &str)> {
        spans
            .iter()
            .map(|s| (s.start, s.end, s.label.as_str()))
            .collect()
    }

    const TEXT40: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";

    #[test]
    fn covering_span_is_kept_as_union() {
        let out = normalize_spans(
            vec![span("secret", 10, 30), span("private_person", 12, 20)],
            TEXT40,
            0,
        );
        assert_eq!(ranges(&out), vec![(10, 30, "secret")]);
    }

    #[test]
    fn model_span_containing_secret_becomes_secret() {
        let out = normalize_spans(
            vec![span("private_person", 8, 32), span("secret", 10, 30)],
            TEXT40,
            0,
        );
        assert_eq!(ranges(&out), vec![(8, 32, "secret")]);
    }

    #[test]
    fn span_starting_in_context_is_clamped() {
        let out = normalize_spans(vec![span("secret", 15, 40)], &TEXT40[..20], 20);
        assert_eq!(ranges(&out), vec![(0, 20, "secret")]);
    }

    #[test]
    fn leading_space_is_trimmed() {
        let out = normalize_spans(vec![span("secret", 4, 8)], "key: abc", 0);
        assert_eq!(ranges(&out), vec![(5, 8, "secret")]);
    }

    #[test]
    fn touching_spans_stay_separate() {
        let out = normalize_spans(vec![span("secret", 0, 5), span("secret", 5, 9)], TEXT40, 0);
        assert_eq!(ranges(&out), vec![(0, 5, "secret"), (5, 9, "secret")]);
    }

    #[test]
    fn span_entirely_in_context_is_dropped() {
        let out = normalize_spans(vec![span("secret", 3, 12)], &TEXT40[..20], 20);
        assert!(out.is_empty());
    }

    #[test]
    fn multibyte_edges_are_widened() {
        // "é" is two bytes; a span ending inside it is widened to cover it.
        let out = normalize_spans(vec![span("secret", 0, 5)], "abcdé xyz", 0);
        assert_eq!(ranges(&out), vec![(0, 6, "secret")]);
    }

    fn tool_map_with(id: &str) -> HashMap<String, (String, String)> {
        let mut map = HashMap::new();
        map.insert(id.to_string(), ("search".to_string(), "{}".to_string()));
        map
    }

    #[tokio::test]
    async fn document_text_source_is_redacted() {
        let state = fake_state();
        let mut content = json!([{"type": "document", "title": "TOKEN notes",
            "source": {"type": "text", "media_type": "text/plain", "data": "a TOKEN b"}}]);
        let audit = redact_content(&state, &mut content, &HashMap::new(), false)
            .await
            .unwrap();
        assert_eq!(content[0]["source"]["data"], "a <secret_1> b");
        assert_eq!(content[0]["title"], "<secret_1> notes");
        assert_eq!(audit.len(), 2);
    }

    #[tokio::test]
    async fn document_base64_is_untouched() {
        let state = fake_state();
        let mut content = json!([{"type": "document",
            "source": {"type": "base64", "media_type": "application/pdf", "data": "TOKEN"}}]);
        let before = content.clone();
        redact_content(&state, &mut content, &HashMap::new(), false)
            .await
            .unwrap();
        assert_eq!(content, before);
    }

    #[tokio::test]
    async fn search_result_inside_tool_result_is_redacted() {
        let state = fake_state();
        let block = json!([{"type": "tool_result", "tool_use_id": "t1", "content": [
            {"type": "search_result", "title": "Ops", "source": "https://wiki/ops",
             "content": [{"type": "text", "text": "x TOKEN y"}]}]}]);

        let mut with_context = block.clone();
        let audit = redact_content(&state, &mut with_context, &tool_map_with("t1"), false)
            .await
            .unwrap();
        assert_eq!(
            with_context[0]["content"][0]["content"][0]["text"],
            "x <secret_1> y"
        );
        assert_eq!(audit[0]["field"], "tool_result.text");

        let mut without_context = block;
        let audit = redact_content(&state, &mut without_context, &HashMap::new(), false)
            .await
            .unwrap();
        assert_eq!(
            without_context[0]["content"][0]["content"][0]["text"],
            "x <secret_1> y"
        );
        assert_eq!(audit[0]["field"], "text");
    }

    #[tokio::test]
    async fn nested_object_in_tool_result_with_context_is_walked() {
        let state = fake_state();
        let mut content = json!([{"type": "tool_result", "tool_use_id": "t1", "content": [
            {"type": "document", "source": {"type": "text", "media_type": "text/plain",
             "data": "key TOKEN"}}]}]);
        redact_content(&state, &mut content, &tool_map_with("t1"), false)
            .await
            .unwrap();
        assert_eq!(content[0]["content"][0]["source"]["data"], "key <secret_1>");
    }

    #[tokio::test]
    async fn env_value_in_tool_output_becomes_its_name() {
        let state = fake_state();
        let values = parse_env_values(
            br#"{"values":[{"name":"PIIF_SECRET_1","value":"if-ajsdlk231lj","label":"secret"}]}"#,
        )
        .unwrap();
        with_session(&state, |session| {
            for (name, value, label) in &values {
                session.env.register(name, value, label);
            }
        });
        // `echo $PIIF_SECRET_1` printed the value, which detection would miss; TOKEN is still detected.
        let mut content = json!([{"type": "tool_result", "tool_use_id": "t1",
            "content": "if-ajsdlk231lj\nTOKEN"}]);
        let audit = redact_content(&state, &mut content, &tool_map_with("t1"), false)
            .await
            .unwrap();
        assert_eq!(content[0]["content"], "$PIIF_SECRET_1\n<secret_1>");
        assert_eq!(audit[0]["engine"], "env");
        assert_eq!(audit[0]["placeholder"], "$PIIF_SECRET_1");
        assert_eq!(audit[0]["new"], true);

        // Anywhere in the request, and reported as new only once.
        let mut content = json!([{"type": "tool_use", "id": "t2", "name": "Bash",
            "input": {"command": "curl -H 'X-Key: if-ajsdlk231lj' x"}}]);
        let audit = redact_content(&state, &mut content, &HashMap::new(), false)
            .await
            .unwrap();
        assert_eq!(
            content[0]["input"]["command"],
            "curl -H 'X-Key: $PIIF_SECRET_1' x"
        );
        assert_eq!(audit[0]["new"], false);

        // Another session neither sees the value replaced nor can look it up.
        let other = AppState {
            session: "ffffffffffffffffffffffffffffffff".to_string(),
            ..state.clone()
        };
        let (out, _) = replace_env_values(&other, "if-ajsdlk231lj", "text");
        assert_eq!(out, "if-ajsdlk231lj");
        let names = vec!["PIIF_SECRET_1".to_string()];
        assert!(with_session(&other, |s| s.env.lookup(&names)).is_empty());
        assert_eq!(
            with_session(&state, |s| s.env.lookup(&names))["PIIF_SECRET_1"],
            "if-ajsdlk231lj"
        );
    }

    #[tokio::test]
    async fn replace_setting_turns_detected_values_into_variables() {
        let state = fake_state();
        let mut content = json!([{"type": "tool_result", "tool_use_id": "t1",
            "content": "KEY=TOKEN"}]);

        // `ask` (no setting, no config) keeps placeholders.
        let mut asked = content.clone();
        redact_content(&state, &mut asked, &tool_map_with("t1"), false)
            .await
            .unwrap();
        assert_eq!(asked[0]["content"], "KEY=<secret_1>");

        // `replace` hands out a variable, and the value can then be looked up.
        with_session(&state, |s| s.setting = Some("replace".to_string()));
        let audit = redact_content(&state, &mut content, &tool_map_with("t1"), false)
            .await
            .unwrap();
        assert_eq!(content[0]["content"], "KEY=$PIIF_SECRET_1");
        assert_eq!(audit[0]["placeholder"], "$PIIF_SECRET_1");
        let names = vec!["PIIF_SECRET_1".to_string()];
        assert_eq!(
            with_session(&state, |s| s.env.lookup(&names))["PIIF_SECRET_1"],
            "TOKEN"
        );

        // Any other setting means placeholders, and so does a request without a session id.
        with_session(&state, |s| s.setting = Some("send-raw".to_string()));
        assert!(!replaces_with_env(&state));
        let anonymous = AppState {
            session: String::new(),
            ..state.clone()
        };
        with_session(&anonymous, |s| s.setting = Some("replace".to_string()));
        assert!(!replaces_with_env(&anonymous));
    }

    #[test]
    fn env_values_are_validated() {
        assert!(parse_env_values(br#"{"values":[{"name":"HOME","value":"abcdef"}]}"#).is_none());
        assert!(
            parse_env_values(br#"{"values":[{"name":"PIIF_SECRET_10","value":"abcdef"}]}"#)
                .is_none()
        );
        assert!(parse_env_values(br#"{"values":[{"name":"PIIF_SECRET_1","value":""}]}"#).is_none());
        assert!(parse_env_values(b"not json").is_none());
        let mut env = EnvValues::default();
        // Too short to replace safely: no name, and registering it is a no-op.
        assert_eq!(env.name_for("abc", "secret"), None);
        env.register("PIIF_SECRET_1", "abc", "secret");
        assert!(env.entries.is_empty());
        // Names count up per category, and the same value keeps its name.
        assert_eq!(
            env.name_for("abcd", "secret").as_deref(),
            Some("PIIF_SECRET_1")
        );
        assert_eq!(
            env.name_for("a@b.io", "private_email").as_deref(),
            Some("PIIF_EMAIL_1")
        );
        assert_eq!(
            env.name_for("abcd", "secret").as_deref(),
            Some("PIIF_SECRET_1")
        );
        // A proposed name is inactive until used: nothing is replaced or handed out.
        assert!(env.lookup(&["PIIF_SECRET_1".to_string()]).is_empty());
        // The mod's registration wins and moves the counter past it.
        env.register("PIIF_SECRET_1", "efgh", "secret");
        env.register("PIIF_SECRET_5", "ijklmn", "secret");
        assert_eq!(
            env.name_for("opqr", "secret").as_deref(),
            Some("PIIF_SECRET_6")
        );
        // The value that lost its name gets a new one.
        assert_eq!(
            env.name_for("abcd", "secret").as_deref(),
            Some("PIIF_SECRET_7")
        );
        // No more than ENV_LIMIT per category.
        assert_eq!(
            env.name_for("stuv", "secret").as_deref(),
            Some("PIIF_SECRET_8")
        );
        assert_eq!(
            env.name_for("wxyz", "secret").as_deref(),
            Some("PIIF_SECRET_9")
        );
        assert_eq!(env.name_for("0123", "secret"), None);
    }

    #[tokio::test]
    async fn thinking_blocks_are_never_modified() {
        let state = fake_state();
        let mut content = json!([
            {"type": "thinking", "thinking": "TOKEN", "signature": "TOKEN"},
            {"type": "redacted_thinking", "data": "TOKEN"}]);
        let before = content.clone();
        let audit = redact_content(&state, &mut content, &HashMap::new(), false)
            .await
            .unwrap();
        assert_eq!(content, before);
        assert!(audit.is_empty());
    }

    #[test]
    fn same_text_in_two_categories_is_two_values() {
        let mut p = Placeholders::default();
        assert_eq!(p.number_for("secret", "abc"), (1, true));
        assert_eq!(p.number_for("account_number", "abc"), (1, true));
        assert_eq!(p.number_for("secret", "zzz"), (2, true));
    }

    #[test]
    fn record_counts_a_value_once() {
        let mut stats = Stats::default();
        let first = json!({"label": "secret", "placeholder": "<secret_1>", "new": true});
        let again = json!({"label": "secret", "placeholder": "<secret_1>", "new": false});
        stats.record(&[first, again], 1.0);
        assert_eq!(stats.values, 1);
        assert_eq!(stats.redactions, 2);
        assert_eq!(stats.recent.len(), 1);
        assert_eq!(stats.by_label["secret"], 2);
    }

    #[test]
    fn recent_keeps_the_last_twenty_new_entries() {
        let mut stats = Stats::default();
        let audit: Vec<Value> = (1..=25)
            .map(
                |n| json!({"label": "secret", "placeholder": format!("<secret_{n}>"), "new": true}),
            )
            .collect();
        stats.record(&audit, 1.0);
        assert_eq!(stats.values, 25);
        assert_eq!(stats.recent.len(), 20);
        assert_eq!(stats.recent[0]["placeholder"], "<secret_6>");
    }
}
