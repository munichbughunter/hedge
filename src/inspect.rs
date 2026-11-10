use crate::detect::Finding;
use serde_json::Value;

/// Besucht jeden String-Wert im JSON-Baum in der Reihenfolge
/// Object-Schlüssel werden nicht durchlaufen nur Werte
pub fn walk_strings(value: &mut Value, visit: &mut dyn FnMut(&mut String)) {
    match value {
        Value::String(s) => visit(s),
        Value::Array(items) => {
            for item in items.iter_mut() {
                walk_strings(item, visit);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                walk_strings(item, visit);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Detectors, Severity};
    use serde_json::json;

    /// Sammelt alle besuchten Strings als Kopien ein.
    fn collect(doc: &mut Value) -> Vec<String> {
        let mut seen = Vec::new();
        walk_strings(doc, &mut |s| seen.push(s.clone()));
        seen
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
        // Zwei Detektoren, die sich überschneiden: einer findet die Adresse,
        // ein anderer nur die Domain.
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
}
