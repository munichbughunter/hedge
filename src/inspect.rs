//! Inspektion eines Request-Bodys: jeden String im JSON scannen, Regeln
//! (Allowlist, Severity-Overrides) anwenden, Policy entscheiden, maskieren.
//!
//! Anbieterunabhängig: Hedge kennt kein Anthropic- oder OpenAI-Schema,
//! sondern besucht jeden String-Wert im Baum. Das erwischt System-Prompts,
//! Nachrichten und Tool-Call-Argumente gleichermaßen.

use std::collections::{BTreeMap, HashSet};

use axum::body::Bytes;
use serde_json::Value;

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
}

/// Scannt jeden String-Wert im JSON-Body mit allen Detektoren, wendet Regeln
/// und Policy an. Nicht-JSON-Bodies werden unverändert durchgereicht.
pub fn inspect(body: Bytes, detectors: &Detectors, rules: &Rules, mode: Mode) -> Outcome {
    let Ok(mut doc) = serde_json::from_slice::<Value>(&body) else {
        return Outcome {
            action: Action::Forward,
            body,
            findings: Vec::new(),
            model: None,
            reason: None,
            is_json: false,
        };
    };

    let model = doc.get("model").and_then(Value::as_str).map(str::to_owned);

    let mut located: Vec<Located> = Vec::new();
    walk_strings_with_path(&mut doc, &mut |path, s| {
        for finding in rules.apply(s, detectors.scan(s)) {
            located.push(Located {
                path: path.to_owned(),
                finding,
            });
        }
    });

    let flat: Vec<Finding> = located.iter().map(|l| l.finding.clone()).collect();

    match decide(&flat, mode) {
        Decision::Allow => Outcome {
            action: Action::Forward,
            body,
            findings: located,
            model,
            reason: None,
            is_json: true,
        },
        Decision::Block { reason } => Outcome {
            action: Action::Block,
            body,
            findings: located,
            model,
            reason: Some(reason),
            is_json: true,
        },
        Decision::Redact => {
            // Zweiter Durchlauf: pro String erneut scannen, damit die Offsets
            // zum jeweiligen String passen, dann maskieren.
            walk_strings(&mut doc, &mut |s| {
                let local = rules.apply(s, detectors.scan(s));
                redact(s, &local);
            });
            let body = serde_json::to_vec(&doc).expect("serde_json::Value is always serializable");
            Outcome {
                action: Action::Redact,
                body: Bytes::from(body),
                findings: located,
                model,
                reason: None,
                is_json: true,
            }
        }
    }
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
            finding("b", 3, 8),
            finding("c", 8, 12),
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
}
