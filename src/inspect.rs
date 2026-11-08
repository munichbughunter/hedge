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
}
