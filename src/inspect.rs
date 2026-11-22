//! Inspektion eines Request-Bodys: jeden String im JSON scannen, Regeln
//! (Allowlist, Severity-Overrides) anwenden, Policy entscheiden, maskieren.
//!
//! Anbieterunabhängig: Hedge kennt kein Anthropic- oder OpenAI-Schema,
//! sondern besucht jeden String-Wert im Baum. Das erwischt System-Prompts,
//! Nachrichten und Tool-Call-Argumente gleichermaßen.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

use axum::body::Bytes;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::{Allow, Config, Mode};
use crate::detect::{Detectors, Finding, Severity};
use crate::policy::{Decision, decide};

/// Besucht jeden String-Wert im JSON-Baum in Dokumentreihenfolge.
/// Objekt-Schlüssel werden nicht besucht, nur Werte.
pub fn walk_strings(value: &mut Value, visit: &mut dyn FnMut(&mut String)) {
    walk_strings_with_path(value, &mut |_, s| visit(s));
}

/// Wie `walk_strings`, reicht aber den JSON-Pfad des Werts mit,
/// z. B. `messages[0].content[1].text`.
pub fn walk_strings_with_path(value: &mut Value, visit: &mut dyn FnMut(&str, &mut String)) {
    let mut path = String::new();
    walk(value, &mut path, visit);
}

/// Der Pfad wird in einem einzigen String aufgebaut und nach jedem Kind
/// wieder gekürzt – eine Allokation pro Dokument statt eine pro Knoten.
fn walk(value: &mut Value, path: &mut String, visit: &mut dyn FnMut(&str, &mut String)) {
    match value {
        Value::String(s) => visit(path, s),
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                let len = path.len();
                path.push_str(&format!("[{i}]"));
                walk(item, path, visit);
                path.truncate(len);
            }
        }
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                let len = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                walk(item, path, visit);
                path.truncate(len);
            }
        }
        _ => {}
    }
}

/// Ein zusammenhängender Bereich im Text, der maskiert wird.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Span {
    start: usize,
    end: usize,
    /// `kind` des ersten Fundes im Bereich.
    kind: &'static str,
}

/// Führt überlappende oder angrenzende Findings zu disjunkten Spans zusammen.
/// Ergebnis ist nach `start` sortiert.
fn merge_spans(findings: &[Finding]) -> Vec<Span> {
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|f| f.start);

    let mut spans: Vec<Span> = Vec::new();
    for finding in sorted {
        match spans.last_mut() {
            Some(last) if finding.start <= last.end => {
                last.end = last.end.max(finding.end);
            }
            _ => spans.push(Span {
                start: finding.start,
                end: finding.end,
                kind: finding.kind,
            }),
        }
    }
    spans
}

/// Ersetzt alle Fund-Bereiche in `text` durch `[REDACTED:<kind>]`.
/// Von hinten nach vorn, damit die Byte-Offsets der vorderen Bereiche
/// durch die Ersetzung nicht verschoben werden.
pub fn redact(text: &mut String, findings: &[Finding]) {
    for span in merge_spans(findings).iter().rev() {
        text.replace_range(span.start..span.end, &format!("[REDACTED:{}]", span.kind));
    }
}

/// Regeln, die zwischen Detektor und Policy greifen: Was gilt nicht als Fund,
/// und welche Severity hat ein `kind` in dieser Installation.
#[derive(Debug, Default, Clone)]
pub struct Rules {
    allow_values: HashSet<String>,
    allow_domains: Vec<String>,
    severity: BTreeMap<String, Severity>,
}

impl Rules {
    pub fn from_config(cfg: &Config) -> Self {
        Self::new(&cfg.allow, cfg.severity.clone())
    }

    pub fn new(allow: &Allow, severity: BTreeMap<String, Severity>) -> Self {
        Self {
            allow_values: allow.value_set(),
            allow_domains: allow
                .domains
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            severity,
        }
    }

    fn is_allowed(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        if self.allow_values.contains(&lower) {
            return true;
        }
        if let Some((_, domain)) = lower.rsplit_once('@') {
            return self
                .allow_domains
                .iter()
                .any(|d| domain == *d || domain.ends_with(&format!(".{d}")));
        }
        false
    }

    /// Wendet Allowlist und Severity-Overrides auf die Funde eines Strings an.
    pub fn apply(&self, text: &str, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| !self.is_allowed(&text[f.start..f.end]))
            .map(|mut f| {
                if let Some(sev) = self.severity.get(f.kind) {
                    f.severity = *sev;
                }
                f
            })
            .collect()
    }
}

/// Ein Fund mit seinem Ort im Request-JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// JSON-Pfad des Strings, z. B. `messages[0].content`.
    pub path: String,
    pub finding: Finding,
    /// Maskierter Hinweis auf den Wert, z. B. `p…@example.com` oder `…a1b2`.
    pub hint: Option<String>,
    /// Kurzer Hash aus Art und Wert. Bleibt im Speicher und dient nur dazu,
    /// denselben Fund in derselben Session wiederzuerkennen.
    pub fingerprint: u64,
    /// Nur gemeldet: Der Fund hat weder maskiert noch blockiert (Funde eines
    /// Detektors, der noch nicht durchsetzt, z. B. Presidio ohne `enforce`).
    pub advisory: bool,
}

/// Funde zusätzlicher (asynchroner) Detektoren, pro JSON-Pfad.
#[derive(Debug, Default)]
pub struct Extra {
    pub findings: HashMap<String, Vec<Finding>>,
    /// true: Diese Funde werden gemeldet, entscheiden aber nichts.
    pub advisory: bool,
}

/// Wozu ein Text in der Anfrage gehört. Danach richtet sich, was an einen
/// Dienst wie Presidio geht: Was der Mensch tippt und was Tools liefern, ist
/// etwas anderes als der System-Prompt des Agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Part {
    System,
    Tools,
    User,
    Assistant,
    ToolUse,
    ToolResult,
}

/// Ein Hinweis, an dem ein Mensch den Fund wiedererkennt, ohne dass der
/// Wert selbst gespeichert wird: bei E-Mails erster Buchstabe und Domain,
/// bei Secrets die letzten vier Zeichen (wie bei Kartennummern üblich).
pub fn hint_for(finding: &Finding, matched: &str) -> Option<String> {
    if finding.kind == "email" {
        let (local, domain) = matched.split_once('@')?;
        let first = local.chars().next()?;
        return Some(format!("{first}…@{}", domain.to_ascii_lowercase()));
    }
    if finding.detector == "secrets" && finding.kind != "private_key" {
        let chars: Vec<char> = matched.chars().collect();
        if chars.len() >= 16 {
            let tail: String = chars[chars.len() - 4..].iter().collect();
            return Some(format!("…{tail}"));
        }
    }
    // Namen als Initialen, Nummern mit den letzten Ziffern: genug, um einen
    // Fehlalarm ("C… C…" war "Claude Code") zu erkennen, zu wenig, um den
    // Wert zu rekonstruieren.
    match finding.kind {
        "person_name" => {
            let initials: Vec<String> = matched
                .split_whitespace()
                .filter_map(|w| w.chars().find(|c| c.is_alphanumeric()))
                .take(3)
                .map(|c| format!("{}…", c.to_uppercase()))
                .collect();
            (!initials.is_empty()).then(|| initials.join(" "))
        }
        "phone_number" | "credit_card" => {
            let digits: Vec<char> = matched.chars().filter(char::is_ascii_digit).collect();
            let keep = if finding.kind == "credit_card" { 4 } else { 2 };
            (digits.len() >= keep + 4).then(|| {
                let tail: String = digits[digits.len() - keep..].iter().collect();
                format!("…{tail}")
            })
        }
        _ => None,
    }
}

/// Kurzer Fingerabdruck eines Funds (Art + Wert).
pub fn fingerprint(kind: &str, matched: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update([0]);
    h.update(matched.as_bytes());
    let d = h.finalize();
    u64::from_be_bytes(d[..8].try_into().expect("8 bytes"))
}

/// Was mit der Anfrage passiert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Unverändert weiterleiten.
    Forward,
    /// Maskierten Body weiterleiten.
    Redact,
    /// Anfrage ablehnen.
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Forward => "forward",
            Action::Redact => "redact",
            Action::Block => "block",
        }
    }
}

/// Ergebnis der Inspektion eines Request-Bodys.
#[derive(Debug)]
pub struct Outcome {
    pub action: Action,
    /// Body, der weitergeleitet wird. Bei `Forward` byte-identisch mit dem
    /// Original (keine Re-Serialisierung), bei `Redact` neu serialisiert.
    pub body: Bytes,
    pub findings: Vec<Located>,
    /// Das angefragte Modell, falls der Body ein `model`-Feld hat.
    pub model: Option<String>,
    /// Begründung bei `Block`.
    pub reason: Option<String>,
    /// Ob der Body überhaupt JSON war. Nicht-JSON wird ungeprüft durchgereicht.
    pub is_json: bool,
    /// Kurzform der Agent-Session, falls der Body eine verrät.
    pub session: Option<String>,
    /// IDs der Tool-Ergebnisse in der letzten Nachricht (für den Abgleich
    /// mit den Tool-Aufrufen, die Hedge in Antworten gesehen hat).
    pub tool_results: Vec<String>,
}

/// Ein geparster Request-Body. Zwischen `parse` und `finish` kann der
/// Aufrufer zusätzliche (asynchrone) Detektoren laufen lassen.
pub struct Prepared {
    body: Bytes,
    doc: Value,
}

impl Prepared {
    /// `Err` gibt den Body unverändert zurück, wenn er kein JSON ist.
    pub fn parse(body: Bytes) -> Result<Self, Bytes> {
        match serde_json::from_slice::<Value>(&body) {
            Ok(doc) => Ok(Self { body, doc }),
            Err(_) => Err(body),
        }
    }

    pub fn model(&self) -> Option<&str> {
        self.doc.get("model").and_then(Value::as_str)
    }

    pub fn session(&self) -> Option<String> {
        session_of(&self.doc)
    }

    /// Was der Mensch zuletzt selbst geschrieben hat: die Textblöcke der
    /// letzten Nachricht, sofern sie vom Nutzer stammt. Tool-Ergebnisse
    /// zählen nicht dazu – ihr Inhalt kommt vom Agent, nicht vom Menschen.
    pub fn last_user_texts(&self) -> Vec<&str> {
        let Some(last) = self
            .doc
            .get("messages")
            .and_then(Value::as_array)
            .and_then(|m| m.last())
            .filter(|m| m.get("role").and_then(Value::as_str) == Some("user"))
        else {
            return Vec::new();
        };
        match last.get("content") {
            Some(Value::String(s)) => vec![s.as_str()],
            Some(Value::Array(blocks)) => blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Alle String-Werte mit Pfad, für die `want` zustimmt.
    pub fn texts(&self, want: &dyn Fn(&str, &str) -> bool) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut path = String::new();
        visit(&self.doc, &mut path, &mut |p, s| {
            if want(p, s) {
                out.push((p.to_owned(), s.to_owned()));
            }
        });
        out
    }

    /// Alle Texte mit Pfad, deren Platz in der Anfrage bekannt ist und für
    /// die `want` zustimmt. Was sich keinem Teil zuordnen lässt (Modellname,
    /// IDs, Bilddaten, unbekannte Formate), kommt hier nie vor.
    pub fn parts(&self, want: &dyn Fn(Part, &str, &str) -> bool) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut path = String::new();
        walk_parts(&self.doc, &mut path, Ctx::Root, &mut |p, part, s| {
            if want(part, p, s) {
                out.push((p.to_owned(), s.to_owned()));
            }
        });
        out
    }

    /// Scannt, wendet Regeln und Policy an, maskiert bei Bedarf. `extra`
    /// sind Funde zusätzlicher Detektoren pro JSON-Pfad.
    pub fn finish(
        self,
        detectors: &Detectors,
        rules: &Rules,
        mode: Mode,
        extra: &Extra,
    ) -> Outcome {
        let Prepared { body, mut doc } = self;
        let model = doc.get("model").and_then(Value::as_str).map(str::to_owned);
        let session = session_of(&doc);
        let tool_results = last_tool_results(&doc);

        // Funde pro Pfad, damit ein späteres Maskieren exakt dieselben
        // Stellen trifft und nicht neu gescannt werden muss.
        let mut per_path: HashMap<String, Vec<Finding>> = HashMap::new();
        let mut located: Vec<Located> = Vec::new();
        walk_strings_with_path(&mut doc, &mut |path, s| {
            let mut found = detectors.scan(s);
            // Was ein eingebauter Detektor schon gefunden hat (eine IBAN,
            // eine E-Mail), meldet ein zusätzlicher nicht ein zweites Mal.
            let more: Vec<Finding> = extra
                .findings
                .get(path)
                .map(|more| {
                    more.iter()
                        .filter(|m| {
                            m.start < m.end
                                && m.end <= s.len()
                                && s.is_char_boundary(m.start)
                                && s.is_char_boundary(m.end)
                        })
                        .filter(|m| !found.iter().any(|f| f.start < m.end && m.start < f.end))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let mut locate = |findings: &[Finding], advisory: bool| {
                for finding in findings {
                    let matched = &s[finding.start..finding.end];
                    located.push(Located {
                        path: path.to_owned(),
                        finding: finding.clone(),
                        hint: hint_for(finding, matched),
                        fingerprint: fingerprint(finding.kind, matched),
                        advisory,
                    });
                }
            };
            if extra.advisory {
                locate(&rules.apply(s, more), true);
            } else {
                found.extend(more);
            }
            let found = rules.apply(s, found);
            if found.is_empty() {
                return;
            }
            locate(&found, false);
            per_path.insert(path.to_owned(), found);
        });

        // Nur was durchsetzt, entscheidet über die Anfrage.
        let flat: Vec<Finding> = located
            .iter()
            .filter(|l| !l.advisory)
            .map(|l| l.finding.clone())
            .collect();
        let (action, body, reason) = match decide(&flat, mode) {
            Decision::Allow => (Action::Forward, body, None),
            Decision::Block { reason } => (Action::Block, body, Some(reason)),
            Decision::Redact => {
                walk_strings_with_path(&mut doc, &mut |path, s| {
                    if let Some(found) = per_path.get(path) {
                        redact(s, found);
                    }
                });
                let bytes =
                    serde_json::to_vec(&doc).expect("serde_json::Value is always serializable");
                (Action::Redact, Bytes::from(bytes), None)
            }
        };

        Outcome {
            action,
            body,
            findings: located,
            model,
            reason,
            is_json: true,
            session,
            tool_results,
        }
    }
}

/// Scannt jeden String-Wert im JSON-Body mit allen Detektoren, wendet Regeln
/// und Policy an. Nicht-JSON-Bodies werden unverändert durchgereicht.
pub fn inspect(body: Bytes, detectors: &Detectors, rules: &Rules, mode: Mode) -> Outcome {
    match Prepared::parse(body) {
        Ok(prepared) => prepared.finish(detectors, rules, mode, &Extra::default()),
        Err(body) => Outcome {
            action: Action::Forward,
            body,
            findings: Vec::new(),
            model: None,
            reason: None,
            is_json: false,
            session: None,
            tool_results: Vec::new(),
        },
    }
}

/// Nur-lesender Gang über alle String-Werte mit Pfad.
fn visit(value: &Value, path: &mut String, f: &mut dyn FnMut(&str, &str)) {
    match value {
        Value::String(s) => f(path, s),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let len = path.len();
                path.push_str(&format!("[{i}]"));
                visit(item, path, f);
                path.truncate(len);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let len = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                visit(item, path, f);
                path.truncate(len);
            }
        }
        _ => {}
    }
}

/// Wo im Dokument der Gang nach Teilen gerade steht.
#[derive(Clone, Copy)]
enum Ctx {
    /// Wurzel der Anfrage.
    Root,
    /// Liste der Nachrichten (`messages`, `input`, `contents`).
    Messages,
    /// Inhalt einer Rolle: ein String oder Blöcke, die nach `type` gehen.
    Content(Part),
    /// Jeder String darunter gehört zu diesem Teil.
    All(Part),
    /// `tool_calls` einer Assistant-Nachricht (OpenAI).
    ToolCalls,
    /// `source` eines Dokument-Blocks: nur Klartext zählt, nie Base64.
    Source(Part),
    Skip,
}

/// Ein Schritt tiefer: Pfad um Schlüssel oder Index verlängern, absteigen,
/// Pfad wieder kürzen.
fn descend(
    key: Option<&str>,
    index: Option<usize>,
    value: &Value,
    ctx: Ctx,
    path: &mut String,
    f: &mut dyn FnMut(&str, Part, &str),
) {
    if matches!(ctx, Ctx::Skip) {
        return;
    }
    let len = path.len();
    match (key, index) {
        (Some(k), _) => {
            if !path.is_empty() {
                path.push('.');
            }
            path.push_str(k);
        }
        (None, Some(i)) => path.push_str(&format!("[{i}]")),
        (None, None) => {}
    }
    walk_parts(value, path, ctx, f);
    path.truncate(len);
}

/// Geht durch die Anfrage und meldet jeden Text mit dem Teil, zu dem er
/// gehört. Kennt die Formate von Anthropic (Messages), OpenAI (Chat
/// Completions, Responses) und Gemini. Pfade sind dieselben wie in
/// `walk_strings_with_path`.
fn walk_parts(value: &Value, path: &mut String, ctx: Ctx, f: &mut dyn FnMut(&str, Part, &str)) {
    match (ctx, value) {
        (Ctx::Skip, _) => {}
        (Ctx::Content(part) | Ctx::All(part), Value::String(s)) => f(path, part, s),
        // `"input": "…"` der Responses API ist die Eingabe des Menschen.
        (Ctx::Messages, Value::String(s)) => f(path, Part::User, s),

        (Ctx::Root, Value::Object(map)) => {
            for (k, v) in map {
                let ctx = match k.as_str() {
                    "system" | "instructions" | "systemInstruction" | "system_instruction" => {
                        Ctx::Content(Part::System)
                    }
                    "tools" | "functions" => Ctx::All(Part::Tools),
                    "messages" | "input" | "contents" => Ctx::Messages,
                    "prompt" => Ctx::Content(Part::User),
                    _ => Ctx::Skip,
                };
                descend(Some(k), None, v, ctx, path, f);
            }
        }

        (Ctx::Messages, Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                let Value::Object(map) = item else { continue };
                let len = path.len();
                path.push_str(&format!("[{i}]"));
                match map.get("role").and_then(Value::as_str) {
                    Some(role) => {
                        let part = match role {
                            "user" => Some(Part::User),
                            "assistant" | "model" => Some(Part::Assistant),
                            "system" | "developer" => Some(Part::System),
                            "tool" | "function" => Some(Part::ToolResult),
                            _ => None,
                        };
                        if let Some(part) = part {
                            for (k, v) in map {
                                let ctx = match k.as_str() {
                                    "content" | "parts" => Ctx::Content(part),
                                    "tool_calls" => Ctx::ToolCalls,
                                    "function_call" => Ctx::ToolCalls,
                                    _ => Ctx::Skip,
                                };
                                descend(Some(k), None, v, ctx, path, f);
                            }
                        }
                    }
                    // Ohne Rolle ist das Element selbst ein Block
                    // (Responses API: function_call, function_call_output).
                    None => walk_parts(item, path, Ctx::Content(Part::User), f),
                }
                path.truncate(len);
            }
        }

        (Ctx::Content(part), Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                descend(None, Some(i), item, Ctx::Content(part), path, f);
            }
        }
        (Ctx::Content(part), Value::Object(map)) => {
            let ty = map.get("type").and_then(Value::as_str).unwrap_or("");
            for (k, v) in map {
                let ctx = match (ty, k.as_str()) {
                    // Binäres und Verschlüsseltes geht nie an einen Dienst.
                    (
                        "image" | "image_url" | "input_image" | "input_audio" | "audio"
                        | "input_file" | "file" | "redacted_thinking" | "reasoning",
                        _,
                    ) => Ctx::Skip,
                    ("document", "source") => Ctx::Source(part),
                    ("document", _) => Ctx::Skip,
                    ("thinking", "thinking") => Ctx::All(Part::Assistant),
                    ("thinking", _) => Ctx::Skip,
                    ("tool_use" | "server_tool_use" | "mcp_tool_use", "input") => {
                        Ctx::All(Part::ToolUse)
                    }
                    ("function_call" | "custom_tool_call", "arguments" | "input") => {
                        Ctx::All(Part::ToolUse)
                    }
                    (
                        "tool_use" | "server_tool_use" | "mcp_tool_use" | "function_call"
                        | "custom_tool_call",
                        _,
                    ) => Ctx::Skip,
                    (t, "content" | "output")
                        if t.ends_with("tool_result") || t.ends_with("_output") =>
                    {
                        Ctx::Content(Part::ToolResult)
                    }
                    (t, _) if t.ends_with("tool_result") || t.ends_with("_output") => Ctx::Skip,
                    (_, "functionResponse") => Ctx::All(Part::ToolResult),
                    (_, "functionCall") => Ctx::All(Part::ToolUse),
                    (_, "text" | "content" | "parts") => Ctx::Content(part),
                    _ => Ctx::Skip,
                };
                descend(Some(k), None, v, ctx, path, f);
            }
        }

        (Ctx::All(part), Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                descend(None, Some(i), item, Ctx::All(part), path, f);
            }
        }
        (Ctx::All(part), Value::Object(map)) => {
            for (k, v) in map {
                descend(Some(k), None, v, Ctx::All(part), path, f);
            }
        }

        (Ctx::ToolCalls, Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                descend(None, Some(i), item, Ctx::ToolCalls, path, f);
            }
        }
        (Ctx::ToolCalls, Value::Object(map)) => {
            for (k, v) in map {
                let ctx = match k.as_str() {
                    "function" => Ctx::ToolCalls,
                    "arguments" | "input" => Ctx::All(Part::ToolUse),
                    _ => Ctx::Skip,
                };
                descend(Some(k), None, v, ctx, path, f);
            }
        }

        (Ctx::Source(part), Value::Object(map)) => {
            let ty = map.get("type").and_then(Value::as_str).unwrap_or("");
            for (k, v) in map {
                let ctx = match (ty, k.as_str()) {
                    ("text", "data") | ("content", "content") => Ctx::Content(part),
                    _ => Ctx::Skip,
                };
                descend(Some(k), None, v, ctx, path, f);
            }
        }

        _ => {}
    }
}

static SESSION_UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)session(?:[_-]?id)?["':=_\s]+([0-9a-f]{8})-[0-9a-f]{4}-"#)
        .expect("valid regex")
});

/// Eine kurze, stabile Kennung der Agent-Session. Claude Code schickt in
/// `metadata.user_id` eine Session-UUID mit; deren erste 8 Zeichen sind
/// dieselben, die `claude --resume` anzeigt. Fehlt eine UUID, wird der
/// Wert gehasht – der Rohwert (er enthält die Account-ID) wird nie gespeichert.
fn session_of(doc: &Value) -> Option<String> {
    let raw = doc
        .get("metadata")
        .and_then(|m| m.get("user_id"))
        .and_then(Value::as_str)
        .or_else(|| doc.get("user").and_then(Value::as_str))
        .or_else(|| doc.get("prompt_cache_key").and_then(Value::as_str))?;
    if raw.is_empty() {
        return None;
    }
    Some(session_label(raw))
}

/// Kurzform einer Session-Kennung: UUID-Anfang, sonst Hash.
pub fn session_label(raw: &str) -> String {
    if let Some(c) = SESSION_UUID.captures(raw) {
        return c[1].to_ascii_lowercase();
    }
    let bare_uuid = raw.len() == 36
        && raw.char_indices().all(|(i, ch)| match i {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_hexdigit(),
        });
    if bare_uuid {
        return raw[..8].to_ascii_lowercase();
    }
    hex::encode(&Sha256::digest(raw.as_bytes())[..4])
}

/// `tool_use_id`s der Tool-Ergebnisse in der letzten Nachricht.
fn last_tool_results(doc: &Value) -> Vec<String> {
    let Some(last) = doc
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|m| m.last())
    else {
        return Vec::new();
    };
    if last.get("role").and_then(Value::as_str) != Some("user") {
        return Vec::new();
    }
    last.get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("tool_result"))
                .filter_map(|b| b.get("tool_use_id").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Sammelt alle besuchten Strings als Kopien ein.
    fn collect(doc: &mut Value) -> Vec<String> {
        let mut seen = Vec::new();
        walk_strings(doc, &mut |s| seen.push(s.clone()));
        seen
    }

    fn no_rules() -> Rules {
        Rules::default()
    }

    #[test]
    fn visits_all_string_values_in_document_order() {
        let mut doc = json!({
            "model": "m",
            "messages": [
                { "role": "user", "content": "hello" },
                { "role": "user", "content": [ { "type": "text", "text": "nested" } ] }
            ]
        });

        let seen = collect(&mut doc);

        assert_eq!(seen, vec!["m", "user", "hello", "user", "text", "nested"]);
    }

    #[test]
    fn paths_describe_the_location() {
        let mut doc = json!({
            "model": "m",
            "messages": [
                { "role": "user", "content": "hello" },
                { "role": "user", "content": [ { "type": "text", "text": "nested" } ] }
            ]
        });
        let mut seen = Vec::new();

        walk_strings_with_path(&mut doc, &mut |path, s| seen.push(format!("{path}={s}")));

        assert_eq!(
            seen,
            vec![
                "model=m",
                "messages[0].role=user",
                "messages[0].content=hello",
                "messages[1].role=user",
                "messages[1].content[0].type=text",
                "messages[1].content[0].text=nested",
            ]
        );
    }

    #[test]
    fn does_not_visit_object_keys() {
        let mut doc = json!({ "secret_key": "v" });

        let seen = collect(&mut doc);

        assert_eq!(seen, vec!["v"]);
    }

    #[test]
    fn ignores_non_string_scalars_and_empty_containers() {
        let mut doc = json!({
            "n": 42,
            "f": 1.5,
            "b": true,
            "nil": null,
            "empty_obj": {},
            "empty_arr": []
        });

        assert!(collect(&mut doc).is_empty());
    }

    #[test]
    fn visitor_can_mutate_in_place() {
        let mut doc = json!({
            "messages": [ { "content": "hello" }, { "content": [ { "text": "nested" } ] } ]
        });

        walk_strings(&mut doc, &mut |s| s.make_ascii_uppercase());

        assert_eq!(doc["messages"][0]["content"], "HELLO");
        assert_eq!(doc["messages"][1]["content"][0]["text"], "NESTED");
    }

    #[test]
    fn visitor_can_replace_the_whole_string() {
        let mut doc = json!({ "content": "sk-ant-secret" });

        walk_strings(&mut doc, &mut |s| {
            if s.starts_with("sk-ant-") {
                *s = "[REDACTED]".to_owned();
            }
        });

        assert_eq!(doc.to_string(), r#"{"content":"[REDACTED]"}"#);
    }

    // ---- redact / merge_spans ----

    fn finding(kind: &'static str, start: usize, end: usize) -> Finding {
        Finding {
            detector: "test",
            kind,
            severity: Severity::High,
            start,
            end,
        }
    }

    fn fake_key(c: char) -> String {
        format!("sk-ant-{}", c.to_string().repeat(24))
    }

    #[test]
    fn merge_keeps_disjoint_spans_apart_and_sorted() {
        let spans = merge_spans(&[finding("b", 10, 15), finding("a", 0, 5)]);

        assert_eq!(
            spans,
            vec![
                Span {
                    start: 0,
                    end: 5,
                    kind: "a"
                },
                Span {
                    start: 10,
                    end: 15,
                    kind: "b"
                },
            ]
        );
    }

    #[test]
    fn merge_joins_overlapping_and_adjacent_spans_keeping_first_kind() {
        let spans = merge_spans(&[
            finding("a", 0, 5),
            finding("b", 3, 8),  // überlappt a
            finding("c", 8, 12), // grenzt an
            finding("d", 20, 25),
        ]);

        assert_eq!(
            spans,
            vec![
                Span {
                    start: 0,
                    end: 12,
                    kind: "a"
                },
                Span {
                    start: 20,
                    end: 25,
                    kind: "d"
                },
            ]
        );
    }

    #[test]
    fn merge_does_not_shrink_when_inner_span_ends_earlier() {
        let spans = merge_spans(&[finding("a", 0, 10), finding("b", 2, 4)]);

        assert_eq!(
            spans,
            vec![Span {
                start: 0,
                end: 10,
                kind: "a"
            }]
        );
    }

    #[test]
    fn redact_replaces_single_finding_and_keeps_surrounding_text() {
        let key = fake_key('x');
        let mut text = format!("Key: {key} Ende");
        let findings = Detectors::default_set().scan(&text);

        redact(&mut text, &findings);

        assert_eq!(text, "Key: [REDACTED:anthropic_api_key] Ende");
    }

    #[test]
    fn redact_handles_two_findings_with_shifting_offsets() {
        let (k1, k2) = (fake_key('x'), fake_key('y'));
        let mut text = format!("{k1} und {k2}.");
        let findings = Detectors::default_set().scan(&text);
        assert_eq!(findings.len(), 2, "precondition");

        redact(&mut text, &findings);

        assert_eq!(
            text,
            "[REDACTED:anthropic_api_key] und [REDACTED:anthropic_api_key]."
        );
    }

    #[test]
    fn redact_merges_overlapping_findings_from_different_detectors() {
        let mut text = "mail max@example.org fertig".to_owned();
        let findings = [finding("email", 5, 20), finding("domain", 9, 20)];

        redact(&mut text, &findings);

        assert_eq!(text, "mail [REDACTED:email] fertig");
    }

    #[test]
    fn redact_with_no_findings_leaves_text_unchanged() {
        let mut text = "nichts zu sehen".to_owned();

        redact(&mut text, &[]);

        assert_eq!(text, "nichts zu sehen");
    }

    #[test]
    fn redact_respects_multibyte_prefix() {
        let key = fake_key('x');
        let mut text = format!("🔒 Grüße {key}");
        let findings = Detectors::default_set().scan(&text);

        redact(&mut text, &findings);

        assert_eq!(text, "🔒 Grüße [REDACTED:anthropic_api_key]");
    }

    // ---- rules ----

    #[test]
    fn rules_drop_allowed_values_and_domains() {
        let allow = Allow {
            values: vec!["Me@Example.com".into()],
            domains: vec!["corp.example".into()],
        };
        let rules = Rules::new(&allow, BTreeMap::new());
        let text = "me@example.com, bob@mail.corp.example, eve@other.org";
        let findings = Detectors::default_set().scan(text);
        assert_eq!(findings.len(), 3, "precondition");

        let kept = rules.apply(text, findings);

        assert_eq!(kept.len(), 1);
        assert_eq!(&text[kept[0].start..kept[0].end], "eve@other.org");
    }

    #[test]
    fn rules_override_severity_per_kind() {
        let mut sev = BTreeMap::new();
        sev.insert("email".to_owned(), Severity::Low);
        let rules = Rules::new(&Allow::default(), sev);
        let text = "eve@other.org";

        let kept = rules.apply(text, Detectors::default_set().scan(text));

        assert_eq!(kept[0].severity, Severity::Low);
    }

    // ---- inspect ----

    fn anthropic_request(content: &str) -> Bytes {
        Bytes::from(
            json!({
                "model": "claude-x",
                "messages": [{ "role": "user", "content": content }]
            })
            .to_string(),
        )
    }

    #[test]
    fn non_json_body_is_forwarded_untouched() {
        let body = Bytes::from_static(b"not json at all");

        let out = inspect(
            body.clone(),
            &Detectors::default_set(),
            &no_rules(),
            Mode::Block,
        );

        assert_eq!(out.action, Action::Forward);
        assert_eq!(out.body, body);
        assert!(out.findings.is_empty());
        assert!(!out.is_json);
        assert_eq!(out.model, None);
    }

    #[test]
    fn clean_json_is_forwarded_byte_identical() {
        let body = anthropic_request("nur harmloser Text");

        let out = inspect(
            body.clone(),
            &Detectors::default_set(),
            &no_rules(),
            Mode::Block,
        );

        assert_eq!(out.action, Action::Forward);
        assert_eq!(out.body, body);
        assert!(out.findings.is_empty());
        assert_eq!(out.model.as_deref(), Some("claude-x"));
    }

    #[test]
    fn observe_mode_reports_findings_with_path_but_forwards_original() {
        let body = anthropic_request(&format!("mein key {}", fake_key('x')));

        let out = inspect(
            body.clone(),
            &Detectors::default_set(),
            &no_rules(),
            Mode::Observe,
        );

        assert_eq!(out.action, Action::Forward);
        assert_eq!(out.body, body, "observe must not touch the body");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].finding.kind, "anthropic_api_key");
        assert_eq!(out.findings[0].path, "messages[0].content");
    }

    #[test]
    fn redact_mode_masks_secret_and_keeps_structure() {
        let body = anthropic_request(&format!("mein key {} ende", fake_key('x')));

        let out = inspect(body, &Detectors::default_set(), &no_rules(), Mode::Redact);

        assert_eq!(out.action, Action::Redact);
        assert_eq!(out.findings.len(), 1);
        let doc: Value = serde_json::from_slice(&out.body).expect("still valid json");
        assert_eq!(doc["model"], "claude-x");
        assert_eq!(
            doc["messages"][0]["content"],
            "mein key [REDACTED:anthropic_api_key] ende"
        );
    }

    #[test]
    fn block_mode_blocks_high_severity_with_reason() {
        let body = anthropic_request(&fake_key('x'));

        let out = inspect(body, &Detectors::default_set(), &no_rules(), Mode::Block);

        assert_eq!(out.action, Action::Block);
        assert_eq!(out.findings.len(), 1);
        let reason = out.reason.expect("blocked needs a reason");
        assert!(reason.contains("anthropic_api_key"), "got: {reason}");
    }

    #[test]
    fn block_mode_only_redacts_medium_severity() {
        let body = anthropic_request("schreib an max@example.org");

        let out = inspect(body, &Detectors::default_set(), &no_rules(), Mode::Block);

        assert_eq!(out.action, Action::Redact);
        let doc: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(doc["messages"][0]["content"], "schreib an [REDACTED:email]");
    }

    #[test]
    fn allowed_email_is_neither_reported_nor_redacted() {
        let allow = Allow {
            values: vec![],
            domains: vec!["example.org".into()],
        };
        let rules = Rules::new(&allow, BTreeMap::new());
        let body = anthropic_request("schreib an max@example.org");

        let out = inspect(body.clone(), &Detectors::default_set(), &rules, Mode::Block);

        assert_eq!(out.action, Action::Forward);
        assert_eq!(out.body, body);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn severity_override_turns_block_into_redact() {
        let mut sev = BTreeMap::new();
        sev.insert("anthropic_api_key".to_owned(), Severity::Medium);
        let rules = Rules::new(&Allow::default(), sev);
        let body = anthropic_request(&fake_key('x'));

        let out = inspect(body, &Detectors::default_set(), &rules, Mode::Block);

        assert_eq!(out.action, Action::Redact);
    }

    // ---- session, tool results, extra findings ----

    #[test]
    fn session_label_prefers_the_uuid_prefix() {
        let cc = "user_ab12cd_account_0f0f0f0f-1111-2222-3333-444444444444_session_3F2A9C1E-aaaa-bbbb-cccc-dddddddddddd";
        assert_eq!(session_label(cc), "3f2a9c1e");
        let json_style = r#"{"device_id":"x","session_id":"9d8c7b6a-aaaa-bbbb-cccc-dddddddddddd"}"#;
        assert_eq!(session_label(json_style), "9d8c7b6a");
        assert_eq!(
            session_label("0a1b2c3d-aaaa-bbbb-cccc-dddddddddddd"),
            "0a1b2c3d"
        );
        let hashed = session_label("some-opaque-user");
        assert_eq!(hashed.len(), 8);
        assert_eq!(hashed, session_label("some-opaque-user"));
        assert!(!hashed.contains("opaque"));
    }

    #[test]
    fn outcome_carries_session_and_tool_results() {
        let body = Bytes::from(
            json!({
                "model": "claude-x",
                "metadata": { "user_id": "user_x_account_y_session_3f2a9c1e-aaaa-bbbb-cccc-dddddddddddd" },
                "messages": [
                    { "role": "user", "content": "hi" },
                    { "role": "assistant", "content": [
                        { "type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {} } ] },
                    { "role": "user", "content": [
                        { "type": "tool_result", "tool_use_id": "toolu_1", "content": "ok" },
                        { "type": "text", "text": "weiter" } ] }
                ]
            })
            .to_string(),
        );

        let out = inspect(body, &Detectors::default_set(), &no_rules(), Mode::Observe);

        assert_eq!(out.session.as_deref(), Some("3f2a9c1e"));
        assert_eq!(out.tool_results, vec!["toolu_1"]);
    }

    #[test]
    fn extra_findings_are_reported_and_redacted_at_their_path() {
        let body = anthropic_request("Kollege Jörg Müller hat angerufen");
        let prepared = Prepared::parse(body).unwrap();
        let texts = prepared.texts(&|path, _| path.starts_with("messages"));
        assert_eq!(texts.len(), 2, "role and content");
        let (path, text) = texts.iter().find(|(p, _)| p.ends_with("content")).unwrap();
        let start = text.find("Jörg").unwrap();
        let mut extra = Extra::default();
        extra.findings.insert(
            path.clone(),
            vec![Finding {
                detector: "presidio",
                kind: "person_name",
                severity: Severity::Medium,
                start,
                end: start + "Jörg Müller".len(),
            }],
        );

        let out = prepared.finish(&Detectors::default_set(), &no_rules(), Mode::Redact, &extra);

        assert_eq!(out.action, Action::Redact);
        assert_eq!(out.findings[0].finding.kind, "person_name");
        let doc: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            doc["messages"][0]["content"],
            "Kollege [REDACTED:person_name] hat angerufen"
        );
    }

    fn presidio_finding(
        kind: &'static str,
        severity: Severity,
        text: &str,
        needle: &str,
    ) -> Finding {
        let start = text.find(needle).unwrap();
        Finding {
            detector: "presidio",
            kind,
            severity,
            start,
            end: start + needle.len(),
        }
    }

    #[test]
    fn advisory_findings_are_reported_but_decide_nothing() {
        let text = format!("Jörg Müller hat {} geschickt", fake_key('k'));
        let body = anthropic_request(&text);
        let prepared = Prepared::parse(body).unwrap();
        let mut extra = Extra {
            advisory: true,
            ..Extra::default()
        };
        extra.findings.insert(
            "messages[0].content".into(),
            vec![presidio_finding(
                "credit_card",
                Severity::High,
                &text,
                "Jörg Müller",
            )],
        );

        let out = prepared.finish(&Detectors::default_set(), &no_rules(), Mode::Block, &extra);

        // Der High-Fund von Presidio blockiert nicht; der Key tut es.
        assert_eq!(out.action, Action::Block);
        assert_eq!(
            out.reason.as_deref(),
            Some("1 high-severity finding(s): anthropic_api_key")
        );
        let advisory: Vec<_> = out.findings.iter().filter(|l| l.advisory).collect();
        assert_eq!(advisory.len(), 1);
        assert_eq!(advisory[0].finding.kind, "credit_card");

        // Ohne den Key geht die Anfrage unverändert durch, der Fund steht da.
        let text = "Jörg Müller ruft an";
        let prepared = Prepared::parse(anthropic_request(text)).unwrap();
        let mut extra = Extra {
            advisory: true,
            ..Extra::default()
        };
        extra.findings.insert(
            "messages[0].content".into(),
            vec![presidio_finding(
                "person_name",
                Severity::Medium,
                text,
                "Jörg Müller",
            )],
        );
        let out = prepared.finish(&Detectors::default_set(), &no_rules(), Mode::Redact, &extra);
        assert_eq!(out.action, Action::Forward);
        assert_eq!(out.findings.len(), 1);
        assert!(out.findings[0].advisory);
    }

    #[test]
    fn extra_findings_do_not_repeat_what_a_built_in_detector_found() {
        let text = "Mail an max@example.org, Rückruf an Jörg Müller";
        let prepared = Prepared::parse(anthropic_request(text)).unwrap();
        let mut extra = Extra::default();
        extra.findings.insert(
            "messages[0].content".into(),
            vec![
                presidio_finding("email", Severity::Medium, text, "max@example.org"),
                presidio_finding("person_name", Severity::Medium, text, "Jörg Müller"),
                // Ein Offset mitten in einem Zeichen oder hinter dem Text
                // darf nichts kaputt machen.
                Finding {
                    detector: "presidio",
                    kind: "person_name",
                    severity: Severity::Medium,
                    start: text.find('ü').unwrap() + 1,
                    end: text.len() + 10,
                },
            ],
        );

        let out = prepared.finish(&Detectors::default_set(), &no_rules(), Mode::Redact, &extra);

        let kinds: Vec<_> = out
            .findings
            .iter()
            .map(|l| (l.finding.detector, l.finding.kind))
            .collect();
        assert_eq!(kinds, vec![("pii", "email"), ("presidio", "person_name")]);
        let doc: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            doc["messages"][0]["content"],
            "Mail an [REDACTED:email], Rückruf an [REDACTED:person_name]"
        );
    }

    #[test]
    fn hints_for_names_and_numbers_show_just_enough() {
        let hint = |kind: &'static str, matched: &str| {
            hint_for(
                &Finding {
                    detector: "presidio",
                    kind,
                    severity: Severity::Medium,
                    start: 0,
                    end: matched.len(),
                },
                matched,
            )
        };
        assert_eq!(hint("person_name", "Jörg Müller").as_deref(), Some("J… M…"));
        assert_eq!(hint("person_name", "Claude Code").as_deref(), Some("C… C…"));
        assert_eq!(
            hint("person_name", "ödön von horváth junior").as_deref(),
            Some("Ö… V… H…")
        );
        assert_eq!(
            hint("phone_number", "+49 170 1234567").as_deref(),
            Some("…67")
        );
        assert_eq!(
            hint("phone_number", "110"),
            None,
            "too short to hide anything"
        );
        assert_eq!(
            hint("credit_card", "4111 1111 1111 1234").as_deref(),
            Some("…1234")
        );
        assert_eq!(hint("location", "Hamburg"), None);
    }

    fn parts_of(doc: Value) -> Vec<(String, Part, String)> {
        let prepared = Prepared::parse(Bytes::from(doc.to_string())).unwrap();
        let mut out = Vec::new();
        let mut path = String::new();
        walk_parts(&prepared.doc, &mut path, Ctx::Root, &mut |p, part, s| {
            out.push((p.to_owned(), part, s.to_owned()));
        });
        out
    }

    #[test]
    fn anthropic_requests_are_split_into_parts() {
        let parts = parts_of(json!({
            "model": "claude-test",
            "metadata": {"user_id": "user_x_session_3f2a9c1e-aaaa-bbbb-cccc-dddddddddddd"},
            "system": [{"type": "text", "text": "SYSTEM", "cache_control": {"type": "ephemeral"}}],
            "tools": [{"name": "Bash", "description": "TOOLDESC",
                       "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}}}],
            "messages": [
                {"role": "user", "content": "USER1"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "THINK", "signature": "c2lnbmF0dXJl"},
                    {"type": "text", "text": "ASSISTANT"},
                    {"type": "tool_use", "id": "toolu_1", "name": "Write",
                     "input": {"file_path": "/tmp/a.txt", "content": "TOOLINPUT"}}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "RESULT1"},
                    {"type": "tool_result", "tool_use_id": "toolu_2", "content": [
                        {"type": "text", "text": "RESULT2"},
                        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "QkFTRTY0"}}]},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "QkFTRTY0"}},
                    {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "QkFTRTY0"}},
                    {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "DOCTEXT"}},
                    {"type": "text", "text": "USER2"}]}
            ]
        }));

        let got: Vec<(&str, Part, &str)> = parts
            .iter()
            .map(|(p, part, s)| (p.as_str(), *part, s.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("system[0].text", Part::System, "SYSTEM"),
                ("tools[0].name", Part::Tools, "Bash"),
                ("tools[0].description", Part::Tools, "TOOLDESC"),
                ("tools[0].input_schema.type", Part::Tools, "object"),
                (
                    "tools[0].input_schema.properties.command.type",
                    Part::Tools,
                    "string"
                ),
                ("messages[0].content", Part::User, "USER1"),
                ("messages[1].content[0].thinking", Part::Assistant, "THINK"),
                ("messages[1].content[1].text", Part::Assistant, "ASSISTANT"),
                (
                    "messages[1].content[2].input.file_path",
                    Part::ToolUse,
                    "/tmp/a.txt"
                ),
                (
                    "messages[1].content[2].input.content",
                    Part::ToolUse,
                    "TOOLINPUT"
                ),
                (
                    "messages[2].content[0].content",
                    Part::ToolResult,
                    "RESULT1"
                ),
                (
                    "messages[2].content[1].content[0].text",
                    Part::ToolResult,
                    "RESULT2"
                ),
                ("messages[2].content[4].source.data", Part::User, "DOCTEXT"),
                ("messages[2].content[5].text", Part::User, "USER2"),
            ],
            "no model name, no ids, no signature, no base64"
        );
    }

    #[test]
    fn part_paths_match_the_paths_of_the_scanner() {
        // Funde werden über den Pfad zugeordnet: Beide Gänge müssen ihn
        // gleich schreiben.
        let doc = json!({
            "system": "S",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "A"}]},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "t", "name": "n", "input": {"deep": [{"x": "B"}]}}]}
            ]
        });
        let mut all = Vec::new();
        let mut copy = doc.clone();
        walk_strings_with_path(&mut copy, &mut |p, _| all.push(p.to_owned()));
        for (path, _, _) in parts_of(doc) {
            assert!(all.contains(&path), "{path} is not a scanner path");
        }
    }

    #[test]
    fn openai_requests_are_split_into_parts() {
        let chat = parts_of(json!({
            "model": "gpt-test",
            "messages": [
                {"role": "system", "content": "SYSTEM"},
                {"role": "developer", "content": "DEV"},
                {"role": "user", "content": [
                    {"type": "text", "text": "USER"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,QkFTRTY0"}}]},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call_1", "type": "function",
                     "function": {"name": "run", "arguments": "{\"cmd\":\"ARGS\"}"}}]},
                {"role": "tool", "tool_call_id": "call_1", "content": "RESULT"}
            ],
            "tools": [{"type": "function", "function": {"name": "run", "description": "TOOLDESC"}}]
        }));
        let got: Vec<(Part, &str)> = chat
            .iter()
            .filter(|(_, part, _)| *part != Part::Tools)
            .map(|(_, part, s)| (*part, s.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (Part::System, "SYSTEM"),
                (Part::System, "DEV"),
                (Part::User, "USER"),
                (Part::ToolUse, "{\"cmd\":\"ARGS\"}"),
                (Part::ToolResult, "RESULT"),
            ]
        );

        let responses = parts_of(json!({
            "model": "gpt-test",
            "instructions": "SYSTEM",
            "input": [
                {"role": "user", "content": [{"type": "input_text", "text": "USER"},
                                               {"type": "input_image", "image_url": "data:image/png;base64,QkFTRTY0"}]},
                {"type": "function_call", "call_id": "c1", "name": "run", "arguments": "ARGS"},
                {"type": "function_call_output", "call_id": "c1", "output": "RESULT"},
                {"type": "reasoning", "summary": [{"type": "summary_text", "text": "REASON"}],
                 "encrypted_content": "QkFTRTY0"}
            ]
        }));
        let got: Vec<(Part, &str)> = responses
            .iter()
            .map(|(_, part, s)| (*part, s.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (Part::System, "SYSTEM"),
                (Part::User, "USER"),
                (Part::ToolUse, "ARGS"),
                (Part::ToolResult, "RESULT"),
            ]
        );
        assert_eq!(
            parts_of(json!({"input": "PLAIN"})),
            vec![("input".to_owned(), Part::User, "PLAIN".to_owned())]
        );
    }

    #[test]
    fn unknown_shapes_have_no_parts() {
        assert!(parts_of(json!({"foo": {"bar": "text"}, "query": "text", "n": 3})).is_empty());
        assert!(parts_of(json!(["a", "b"])).is_empty());
        assert!(parts_of(json!({"messages": [{"role": "narrator", "content": "x"}]})).is_empty());
    }

    #[test]
    fn hints_identify_without_revealing() {
        let body = anthropic_request(&format!("Patrick.Doe@Example.ORG und {}", fake_key('x')));

        let out = inspect(body, &Detectors::default_set(), &no_rules(), Mode::Observe);

        let hints: Vec<_> = out.findings.iter().map(|l| l.hint.as_deref()).collect();
        assert_eq!(hints, vec![Some("P…@example.org"), Some("…xxxx")]);
        assert_ne!(out.findings[0].fingerprint, out.findings[1].fingerprint);
        assert_eq!(
            out.findings[0].fingerprint,
            fingerprint("email", "Patrick.Doe@Example.ORG"),
            "same kind and value give the same fingerprint"
        );
    }

    #[test]
    fn last_user_texts_are_what_the_human_typed() {
        let prep = |v: Value| Prepared::parse(Bytes::from(v.to_string())).unwrap();

        let p = prep(json!({"messages": [{"role": "user", "content": "approve 12ab34"}]}));
        assert_eq!(p.last_user_texts(), vec!["approve 12ab34"]);

        let p = prep(json!({"messages": [
            {"role": "user", "content": "früher"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": [
                {"type": "text", "text": "<system-reminder>…</system-reminder>"},
                {"type": "tool_result", "tool_use_id": "t1", "content": "approve 12ab34"},
                {"type": "tool_result", "tool_use_id": "t2",
                 "content": [{"type": "text", "text": "approve 12ab34"}]},
                {"type": "text", "text": "deny 12ab34"}
            ]}
        ]}));
        assert_eq!(
            p.last_user_texts(),
            vec!["<system-reminder>…</system-reminder>", "deny 12ab34"],
            "tool results are the agent's words, not the human's"
        );

        let p = prep(json!({"messages": [
            {"role": "user", "content": "approve 12ab34"},
            {"role": "assistant", "content": "ok"}
        ]}));
        assert!(
            p.last_user_texts().is_empty(),
            "only the last message counts"
        );
        assert!(prep(json!({"input": "x"})).last_user_texts().is_empty());
    }
}
