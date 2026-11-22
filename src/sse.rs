//! Antworten verstehen: Server-Sent Events zerlegen und Modell-Antworten
//! (Anthropic Messages API) auswerten – Tokens, Text, Tool-Aufrufe.
//!
//! Dieses Modul ist frei von Policy und I/O. Es bekommt Bytes und meldet,
//! was darin passiert ist; entscheiden tut der Aufrufer (`proxy`).

use std::collections::HashMap;

use axum::body::Bytes;
use serde_json::{Value, json};

/// Obergrenze für gesammelten Text pro Block. Mehr wird durchgereicht,
/// aber nicht mehr für den Scan aufgehoben.
const MAX_TEXT_PER_BLOCK: usize = 1024 * 1024;

/// Schneidet einen Byte-Strom in SSE-Ereignisse. Ein Ereignis endet mit
/// einer Leerzeile (`\n\n` oder `\r\n\r\n`); Chunk-Grenzen des Netzwerks
/// fallen beliebig, auch mitten in ein Ereignis.
#[derive(Default)]
pub struct SseFramer {
    buf: Vec<u8>,
    /// Bis hierhin wurde schon erfolglos nach einem Ende gesucht.
    scanned: usize,
}

impl SseFramer {
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Das nächste vollständige Ereignis inklusive seiner Leerzeile.
    pub fn next_event(&mut self) -> Option<Bytes> {
        let mut i = self.scanned;
        while i < self.buf.len() {
            if self.buf[i] == b'\n' {
                let end = match (self.buf.get(i + 1), self.buf.get(i + 2)) {
                    (Some(b'\n'), _) => Some(i + 2),
                    (Some(b'\r'), Some(b'\n')) => Some(i + 3),
                    _ => None,
                };
                if let Some(end) = end {
                    let rest = self.buf.split_off(end);
                    let event = std::mem::replace(&mut self.buf, rest);
                    self.scanned = 0;
                    return Some(Bytes::from(event));
                }
            }
            i += 1;
        }
        // Die letzten zwei Bytes können der Anfang eines Endes sein.
        self.scanned = self.buf.len().saturating_sub(2);
        None
    }

    /// Was am Ende des Stroms ohne abschließende Leerzeile übrig blieb.
    pub fn take_rest(&mut self) -> Option<Bytes> {
        self.scanned = 0;
        if self.buf.is_empty() {
            None
        } else {
            Some(Bytes::from(std::mem::take(&mut self.buf)))
        }
    }
}

/// Der JSON-Inhalt der `data:`-Zeilen eines Ereignisses, falls vorhanden.
pub fn event_json(raw: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut data = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    if data.is_empty() {
        return None;
    }
    serde_json::from_str(&data).ok()
}

fn sse_event(name: &str, data: &Value) -> Bytes {
    Bytes::from(format!("event: {name}\ndata: {data}\n\n"))
}

/// Token-Verbrauch, auf einen Nenner gebracht.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Usage {
    /// Input ohne Cache-Reads (inklusive Cache-Erzeugung).
    pub input: Option<u64>,
    /// Aus dem Prompt-Cache gelesene Tokens.
    pub cached: Option<u64>,
    pub output: Option<u64>,
}

impl Usage {
    /// Übernimmt ein `usage`-Objekt. Versteht Anthropic (`input_tokens`,
    /// `cache_*_input_tokens`, `output_tokens`) und OpenAI (`prompt_tokens`
    /// bzw. `input_tokens` mit `*_details.cached_tokens`).
    pub fn absorb(&mut self, usage: &Value) {
        if !usage.is_object() {
            return;
        }
        let get = |k: &str| usage.get(k).and_then(Value::as_u64);
        let anthropic = usage.get("cache_read_input_tokens").is_some()
            || usage.get("cache_creation_input_tokens").is_some();

        if let Some(total) = get("input_tokens").or_else(|| get("prompt_tokens")) {
            let (input, cached) = if anthropic {
                (
                    total + get("cache_creation_input_tokens").unwrap_or(0),
                    get("cache_read_input_tokens"),
                )
            } else {
                let cached = ["input_tokens_details", "prompt_tokens_details"]
                    .iter()
                    .find_map(|k| usage.get(*k)?.get("cached_tokens")?.as_u64());
                (total.saturating_sub(cached.unwrap_or(0)), cached)
            };
            // Spätere Ereignisse wiederholen den Input teils mit 0; ein
            // bekannter Wert wird davon nicht überschrieben.
            if input > 0 || self.input.is_none() {
                self.input = Some(input);
            }
            if let Some(c) = cached
                && (c > 0 || self.cached.is_none())
            {
                self.cached = Some(c);
            }
        }
        if let Some(out) = get("output_tokens").or_else(|| get("completion_tokens")) {
            self.output = Some(out);
        }
    }

    /// Was auf Budgets angerechnet wird: Input ohne Cache-Reads plus Output.
    pub fn billable(&self) -> u64 {
        self.input.unwrap_or(0) + self.output.unwrap_or(0)
    }
}

/// Ein vollständiger Tool-Aufruf aus einer Antwort.
#[derive(Debug, Clone)]
pub struct ToolCall {
    /// Index des Content-Blocks in der Antwort.
    pub index: u64,
    pub id: String,
    pub name: String,
    pub input: Value,
    /// Zurückgehaltene Roh-Ereignisse des Blocks (nur im Puffer-Modus).
    pub events: Vec<Bytes>,
}

/// Was der Aufrufer mit einem verarbeiteten Ereignis tun soll.
#[derive(Debug)]
pub enum Step {
    /// Unverändert (oder bereits umgeschrieben) an den Client weitergeben.
    Forward(Bytes),
    /// Ein Textblock ist vollständig; sein Ereignis wurde schon weitergegeben.
    Text { index: u64, text: String },
    /// Ein Tool-Aufruf ist vollständig. Im Puffer-Modus liegen seine
    /// Ereignisse in `events` und wurden dem Client noch nicht gezeigt.
    Tool(ToolCall),
}

enum Block {
    Text(String),
    Tool {
        id: String,
        name: String,
        json: String,
        events: Vec<Bytes>,
    },
    Other,
}

/// Verfolgt eine gestreamte Antwort der Anthropic Messages API.
pub struct Analyzer {
    buffer_tools: bool,
    blocks: HashMap<u64, Block>,
    pub usage: Usage,
    pub stop_reason: Option<String>,
    pub model: Option<String>,
    /// Fehlermeldung eines `error`-Ereignisses im Strom.
    pub error: Option<String>,
    tools_total: usize,
    tools_denied: usize,
    /// Um so viele Stellen sind die Blöcke des Clients gegenüber dem
    /// Upstream verschoben, weil Hedge eigene Hinweis-Blöcke eingefügt hat.
    shift: u64,
}

impl Analyzer {
    /// `buffer_tools`: Tool-Blöcke zurückhalten, bis sie vollständig sind,
    /// damit der Aufrufer sie verwerfen oder anhalten kann.
    pub fn new(buffer_tools: bool) -> Self {
        Self {
            buffer_tools,
            blocks: HashMap::new(),
            usage: Usage::default(),
            stop_reason: None,
            model: None,
            error: None,
            tools_total: 0,
            tools_denied: 0,
            shift: 0,
        }
    }

    /// Fügt vor dem Block `index` (Zählung des Upstreams) einen eigenen
    /// Textblock ein. Alle späteren Blöcke rücken beim Client eins weiter.
    pub fn notice_block(&mut self, index: u64, text: &str) -> Bytes {
        let at = index + self.shift;
        self.shift += 1;
        replacement_events(at, text)
    }

    /// Index eines Upstream-Blocks, wie der Client ihn sieht.
    pub fn shifted(&self, index: u64) -> u64 {
        index + self.shift
    }

    /// Passt den Block-Index eines Ereignisses an die Zählung des Clients
    /// an. Ohne eingefügte Blöcke bleibt das Ereignis Byte für Byte gleich.
    pub fn reindex(&self, raw: Bytes) -> Bytes {
        if self.shift == 0 {
            return raw;
        }
        let Some(mut ev) = event_json(&raw) else {
            return raw;
        };
        let kind = ev
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if !kind.starts_with("content_block_") {
            return raw;
        }
        let Some(index) = ev.get("index").and_then(Value::as_u64) else {
            return raw;
        };
        ev["index"] = json!(index + self.shift);
        sse_event(&kind, &ev)
    }

    /// Der Aufrufer hat den zuletzt gemeldeten Tool-Aufruf verworfen.
    pub fn mark_denied(&mut self) {
        self.tools_denied += 1;
    }

    pub fn on_event(&mut self, raw: Bytes) -> Vec<Step> {
        let mut steps = self.track(raw);
        if self.shift > 0 {
            for step in &mut steps {
                if let Step::Forward(bytes) = step {
                    *bytes = self.reindex(std::mem::take(bytes));
                }
            }
        }
        steps
    }

    fn track(&mut self, raw: Bytes) -> Vec<Step> {
        let Some(ev) = event_json(&raw) else {
            return vec![Step::Forward(raw)];
        };
        let index = ev.get("index").and_then(Value::as_u64).unwrap_or(0);

        match ev.get("type").and_then(Value::as_str).unwrap_or("") {
            "message_start" => {
                if let Some(msg) = ev.get("message") {
                    if let Some(u) = msg.get("usage") {
                        self.usage.absorb(u);
                    }
                    self.model = msg.get("model").and_then(Value::as_str).map(str::to_owned);
                }
                vec![Step::Forward(raw)]
            }
            "content_block_start" => {
                let cb = ev.get("content_block");
                let kind = cb
                    .and_then(|b| b.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match kind {
                    "text" => {
                        let initial = cb
                            .and_then(|b| b.get("text"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        self.blocks.insert(index, Block::Text(initial.to_owned()));
                        vec![Step::Forward(raw)]
                    }
                    "tool_use" => {
                        let field = |k: &str| {
                            cb.and_then(|b| b.get(k))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned()
                        };
                        let mut events = Vec::new();
                        let out = if self.buffer_tools {
                            events.push(raw);
                            Vec::new()
                        } else {
                            vec![Step::Forward(raw)]
                        };
                        self.blocks.insert(
                            index,
                            Block::Tool {
                                id: field("id"),
                                name: field("name"),
                                json: String::new(),
                                events,
                            },
                        );
                        out
                    }
                    _ => {
                        self.blocks.insert(index, Block::Other);
                        vec![Step::Forward(raw)]
                    }
                }
            }
            "content_block_delta" => {
                let delta = ev.get("delta");
                let piece = |k: &str| delta.and_then(|d| d.get(k)).and_then(Value::as_str);
                match self.blocks.get_mut(&index) {
                    Some(Block::Text(text)) => {
                        if let Some(t) = piece("text")
                            && text.len() + t.len() <= MAX_TEXT_PER_BLOCK
                        {
                            text.push_str(t);
                        }
                        vec![Step::Forward(raw)]
                    }
                    Some(Block::Tool { json, events, .. }) => {
                        if let Some(p) = piece("partial_json") {
                            json.push_str(p);
                        }
                        if self.buffer_tools {
                            events.push(raw);
                            Vec::new()
                        } else {
                            vec![Step::Forward(raw)]
                        }
                    }
                    _ => vec![Step::Forward(raw)],
                }
            }
            "content_block_stop" => match self.blocks.remove(&index) {
                Some(Block::Text(text)) => {
                    let mut out = vec![Step::Forward(raw)];
                    if !text.is_empty() {
                        out.push(Step::Text { index, text });
                    }
                    out
                }
                Some(Block::Tool {
                    id,
                    name,
                    json,
                    mut events,
                }) => {
                    self.tools_total += 1;
                    let input = parse_tool_input(&json);
                    let mut out = Vec::new();
                    if self.buffer_tools {
                        events.push(raw);
                    } else {
                        out.push(Step::Forward(raw));
                    }
                    out.push(Step::Tool(ToolCall {
                        index,
                        id,
                        name,
                        input,
                        events,
                    }));
                    out
                }
                _ => vec![Step::Forward(raw)],
            },
            "message_delta" => {
                if let Some(u) = ev.get("usage") {
                    self.usage.absorb(u);
                }
                let stop = ev
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(Value::as_str);
                if let Some(s) = stop {
                    self.stop_reason = Some(s.to_owned());
                }
                // Wurden alle Tool-Aufrufe verworfen, gibt es für den Agent
                // nichts auszuführen: Der Zug endet regulär.
                if stop == Some("tool_use")
                    && self.tools_denied > 0
                    && self.tools_denied == self.tools_total
                {
                    let mut rewritten = ev.clone();
                    rewritten["delta"]["stop_reason"] = json!("end_turn");
                    self.stop_reason = Some("end_turn".into());
                    return vec![Step::Forward(sse_event("message_delta", &rewritten))];
                }
                vec![Step::Forward(raw)]
            }
            "error" => {
                self.error = ev
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| Some("upstream error event".into()));
                vec![Step::Forward(raw)]
            }
            _ => {
                // Andere Formate (OpenAI): wenigstens die Tokens mitnehmen.
                if let Some(u) = ev.get("usage") {
                    self.usage.absorb(u);
                }
                if let Some(u) = ev.get("response").and_then(|r| r.get("usage")) {
                    self.usage.absorb(u);
                }
                if self.model.is_none() {
                    self.model = ev.get("model").and_then(Value::as_str).map(str::to_owned);
                }
                vec![Step::Forward(raw)]
            }
        }
    }

    /// Ereignisse von Tool-Blöcken, die beim Abbruch des Stroms noch
    /// zurückgehalten waren. Unvollständige Aufrufe kann der Agent nicht
    /// ausführen; sie werden trotzdem durchgereicht, damit der Client
    /// dasselbe sieht wie ohne Hedge.
    pub fn drain_pending(&mut self) -> Vec<Bytes> {
        let mut indices: Vec<u64> = self.blocks.keys().copied().collect();
        indices.sort_unstable();
        let mut out = Vec::new();
        for i in indices {
            if let Some(Block::Tool { events, .. }) = self.blocks.remove(&i) {
                out.extend(events.into_iter().map(|e| self.reindex(e)));
            }
        }
        out
    }
}

fn parse_tool_input(json: &str) -> Value {
    if json.trim().is_empty() {
        return json!({});
    }
    serde_json::from_str(json).unwrap_or_else(|_| Value::String(json.to_owned()))
}

/// Ersatz für einen verworfenen Tool-Block: ein Textblock am selben Index,
/// der dem Modell (und dem Menschen) sagt, was passiert ist.
pub fn replacement_events(index: u64, text: &str) -> Bytes {
    let mut out = Vec::new();
    out.extend_from_slice(&sse_event(
        "content_block_start",
        &json!({"type":"content_block_start","index":index,"content_block":{"type":"text","text":""}}),
    ));
    out.extend_from_slice(&sse_event(
        "content_block_delta",
        &json!({"type":"content_block_delta","index":index,"delta":{"type":"text_delta","text":text}}),
    ));
    out.extend_from_slice(&sse_event(
        "content_block_stop",
        &json!({"type":"content_block_stop","index":index}),
    ));
    Bytes::from(out)
}

/// Ein Ping, der eine wartende Verbindung offen hält.
pub fn ping_event() -> Bytes {
    sse_event("ping", &json!({"type":"ping"}))
}

/// Auswertung einer nicht gestreamten Antwort.
#[derive(Debug, Default)]
pub struct MessageSummary {
    pub usage: Usage,
    pub stop_reason: Option<String>,
    pub model: Option<String>,
    pub texts: Vec<(u64, String)>,
    pub tools: Vec<ToolCall>,
}

/// Liest Tokens, Text und Tool-Aufrufe aus einer JSON-Antwort. `None`,
/// wenn das Dokument weder eine Nachricht ist noch Verbrauch meldet.
pub fn summarize_message(doc: &Value) -> Option<MessageSummary> {
    let mut s = MessageSummary::default();
    let mut relevant = false;
    if let Some(u) = doc.get("usage") {
        s.usage.absorb(u);
        relevant = true;
    }
    s.model = doc.get("model").and_then(Value::as_str).map(str::to_owned);
    s.stop_reason = doc
        .get("stop_reason")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(content) = doc.get("content").and_then(Value::as_array) {
        relevant = true;
        for (i, block) in content.iter().enumerate() {
            let index = i as u64;
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(Value::as_str)
                        && !t.is_empty()
                    {
                        s.texts.push((index, t.to_owned()));
                    }
                }
                Some("tool_use") => {
                    let field = |k: &str| {
                        block
                            .get(k)
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned()
                    };
                    s.tools.push(ToolCall {
                        index,
                        id: field("id"),
                        name: field("name"),
                        input: block.get("input").cloned().unwrap_or_else(|| json!({})),
                        events: Vec::new(),
                    });
                }
                _ => {}
            }
        }
    }
    relevant.then_some(s)
}

/// Ersetzt in einer JSON-Antwort den Tool-Block an `index` durch Text und
/// korrigiert `stop_reason`, wenn danach kein Tool-Aufruf mehr übrig ist.
pub fn deny_in_message(doc: &mut Value, index: u64, text: &str) {
    if let Some(block) = doc
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|c| c.get_mut(index as usize))
    {
        *block = json!({"type": "text", "text": text});
    }
    let tools_left = doc
        .get("content")
        .and_then(Value::as_array)
        .map(|c| {
            c.iter()
                .any(|b| b.get("type").and_then(Value::as_str) == Some("tool_use"))
        })
        .unwrap_or(false);
    if !tools_left && doc.get("stop_reason").and_then(Value::as_str) == Some("tool_use") {
        doc["stop_reason"] = json!("end_turn");
    }
}

#[cfg(test)]
pub(crate) mod testdata {
    //! Eine realistische Anthropic-Antwort als SSE, für Tests in mehreren Modulen.

    pub fn event(name: &str, data: serde_json::Value) -> String {
        format!("event: {name}\ndata: {data}\n\n")
    }

    /// Text, dann ein Bash-Aufruf mit `command`, in mehreren JSON-Stücken.
    pub fn message_with_tool(text: &str, command: &str) -> String {
        use serde_json::json;
        let input = json!({ "command": command, "description": "run it" }).to_string();
        let (a, b) = input.split_at(input.len() / 2);
        let mut s = String::new();
        s += &event(
            "message_start",
            json!({"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant",
                "model":"claude-test","content":[],"stop_reason":null,
                "usage":{"input_tokens":12,"cache_creation_input_tokens":3,"cache_read_input_tokens":1000,"output_tokens":1}}}),
        );
        s += &event(
            "content_block_start",
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        );
        s += &event("ping", json!({"type":"ping"}));
        let (t1, t2) = text.split_at(text.len() / 2);
        for t in [t1, t2] {
            s += &event(
                "content_block_delta",
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":t}}),
            );
        }
        s += &event(
            "content_block_stop",
            json!({"type":"content_block_stop","index":0}),
        );
        s += &event(
            "content_block_start",
            json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01","name":"Bash","input":{}}}),
        );
        for p in [a, b] {
            s += &event(
                "content_block_delta",
                json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":p}}),
            );
        }
        s += &event(
            "content_block_stop",
            json!({"type":"content_block_stop","index":1}),
        );
        s += &event(
            "message_delta",
            json!({"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":42}}),
        );
        s += &event("message_stop", json!({"type":"message_stop"}));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::testdata::*;
    use super::*;

    fn frames(stream: &[u8], chunk: usize) -> Vec<Bytes> {
        let mut f = SseFramer::default();
        let mut out = Vec::new();
        for piece in stream.chunks(chunk) {
            f.push(piece);
            while let Some(ev) = f.next_event() {
                out.push(ev);
            }
        }
        assert!(f.take_rest().is_none(), "nothing may be left over");
        out
    }

    #[test]
    fn framer_is_independent_of_chunk_boundaries() {
        let stream = message_with_tool("Hallo Welt", "ls -la");
        let whole = frames(stream.as_bytes(), stream.len());
        assert_eq!(whole.len(), 12);
        for size in [1, 2, 3, 7, 16, 61, 500] {
            assert_eq!(frames(stream.as_bytes(), size), whole, "chunk size {size}");
        }
        let joined: Vec<u8> = whole.iter().flat_map(|b| b.to_vec()).collect();
        assert_eq!(
            joined,
            stream.as_bytes(),
            "framing must not lose or change bytes"
        );
    }

    #[test]
    fn framer_handles_crlf_and_keeps_incomplete_tail() {
        let mut f = SseFramer::default();
        f.push(b"event: a\r\ndata: {}\r\n\r\nevent: b\ndata: {}\n\nevent: c\ndata: {");
        assert_eq!(f.next_event().unwrap(), "event: a\r\ndata: {}\r\n\r\n");
        assert_eq!(f.next_event().unwrap(), "event: b\ndata: {}\n\n");
        assert!(f.next_event().is_none());
        f.push(b"}\n");
        assert!(f.next_event().is_none());
        f.push(b"\n");
        assert_eq!(f.next_event().unwrap(), "event: c\ndata: {}\n\n");
        assert!(f.take_rest().is_none());

        f.push(b"data: [DONE]");
        assert!(f.next_event().is_none());
        assert_eq!(f.take_rest().unwrap(), "data: [DONE]");
    }

    #[test]
    fn event_json_reads_data_lines() {
        assert_eq!(
            event_json(b"event: x\ndata: {\"a\":1}\n\n").unwrap()["a"],
            1
        );
        assert_eq!(event_json(b"data:{\"a\":2}\n\n").unwrap()["a"], 2);
        assert!(event_json(b": comment\n\n").is_none());
        assert!(
            event_json(b"data: [DONE]\n\n").is_none(),
            "[DONE] is not JSON"
        );
        assert!(event_json(b"data: not json\n\n").is_none());
    }

    fn run(stream: &str, buffer: bool) -> (Analyzer, Vec<Step>) {
        let mut a = Analyzer::new(buffer);
        let mut steps = Vec::new();
        for ev in frames(stream.as_bytes(), 9) {
            steps.extend(a.on_event(ev));
        }
        (a, steps)
    }

    fn forwarded(steps: &[Step]) -> String {
        steps
            .iter()
            .filter_map(|s| match s {
                Step::Forward(b) => Some(String::from_utf8(b.to_vec()).unwrap()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn analyzer_passthrough_reports_text_tool_and_usage() {
        let stream = message_with_tool("Ich schaue nach.", "git status");

        let (a, steps) = run(&stream, false);

        assert_eq!(
            forwarded(&steps),
            stream,
            "without buffering every byte passes unchanged"
        );
        assert_eq!(
            a.usage,
            Usage {
                input: Some(15),
                cached: Some(1000),
                output: Some(42)
            }
        );
        assert_eq!(a.usage.billable(), 57);
        assert_eq!(a.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(a.model.as_deref(), Some("claude-test"));

        let texts: Vec<_> = steps
            .iter()
            .filter_map(|s| match s {
                Step::Text { index, text } => Some((*index, text.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(texts, vec![(0, "Ich schaue nach.")]);

        let tools: Vec<_> = steps
            .iter()
            .filter_map(|s| match s {
                Step::Tool(t) => Some(t),
                _ => None,
            })
            .collect();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "Bash");
        assert_eq!(tools[0].id, "toolu_01");
        assert_eq!(tools[0].index, 1);
        assert_eq!(tools[0].input["command"], "git status");
        assert!(tools[0].events.is_empty());
    }

    #[test]
    fn analyzer_buffers_tool_block_until_complete() {
        let stream = message_with_tool("ok", "rm -rf /");

        let (_, steps) = run(&stream, true);

        let fwd = forwarded(&steps);
        assert!(
            !fwd.contains("tool_use\",\"id\""),
            "tool block must be withheld"
        );
        assert!(!fwd.contains("input_json_delta"));
        let tool = steps
            .iter()
            .find_map(|s| match s {
                Step::Tool(t) => Some(t),
                _ => None,
            })
            .unwrap();
        assert_eq!(tool.events.len(), 4, "start, two deltas, stop");
        assert_eq!(tool.input["command"], "rm -rf /");

        // Erlauben = die zurückgehaltenen Ereignisse an ihrer Stelle einsetzen.
        let mut rebuilt = String::new();
        for s in &steps {
            match s {
                Step::Forward(b) => rebuilt.push_str(std::str::from_utf8(b).unwrap()),
                Step::Tool(t) => {
                    for e in &t.events {
                        rebuilt.push_str(std::str::from_utf8(e).unwrap());
                    }
                }
                Step::Text { .. } => {}
            }
        }
        assert_eq!(
            rebuilt, stream,
            "allowed tool calls reproduce the original stream"
        );
    }

    #[test]
    fn denying_the_only_tool_ends_the_turn() {
        let stream = message_with_tool("ok", "rm -rf /");
        let mut a = Analyzer::new(true);
        let mut out = String::new();
        for ev in frames(stream.as_bytes(), 64) {
            for step in a.on_event(ev) {
                match step {
                    Step::Forward(b) => out.push_str(std::str::from_utf8(&b).unwrap()),
                    Step::Tool(t) => {
                        a.mark_denied();
                        let r = replacement_events(t.index, "[hedge] blocked");
                        out.push_str(std::str::from_utf8(&r).unwrap());
                    }
                    Step::Text { .. } => {}
                }
            }
        }

        assert!(!out.contains("rm -rf"));
        assert!(
            !out.contains("tool_use"),
            "neither the block nor the stop reason may remain"
        );
        assert!(out.contains("\"stop_reason\":\"end_turn\""));
        assert!(out.contains("[hedge] blocked"));
        assert_eq!(a.stop_reason.as_deref(), Some("end_turn"));

        // Der umgeschriebene Strom ist selbst wieder eine gültige Nachricht.
        let (b, steps) = run(&out, false);
        assert_eq!(b.usage.output, Some(42));
        let texts: Vec<_> = steps
            .iter()
            .filter_map(|s| match s {
                Step::Text { index, text } => Some((*index, text.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            texts,
            vec![(0, "ok".to_owned()), (1, "[hedge] blocked".to_owned())]
        );
    }

    #[test]
    fn usage_understands_openai_shapes() {
        let mut u = Usage::default();
        u.absorb(&json!({"prompt_tokens": 100, "completion_tokens": 20,
            "prompt_tokens_details": {"cached_tokens": 60}}));
        assert_eq!(
            u,
            Usage {
                input: Some(40),
                cached: Some(60),
                output: Some(20)
            }
        );

        let mut a = Analyzer::new(false);
        a.on_event(Bytes::from(
            "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":50,\"output_tokens\":7}}}\n\n",
        ));
        assert_eq!(
            a.usage,
            Usage {
                input: Some(50),
                cached: None,
                output: Some(7)
            }
        );

        // Ein späteres usage mit input 0 löscht den bekannten Wert nicht.
        let mut u = Usage::default();
        u.absorb(&json!({"input_tokens": 10, "cache_read_input_tokens": 5, "output_tokens": 1}));
        u.absorb(&json!({"input_tokens": 0, "output_tokens": 9}));
        assert_eq!(
            u,
            Usage {
                input: Some(10),
                cached: Some(5),
                output: Some(9)
            }
        );
    }

    #[test]
    fn summarize_and_deny_in_json_message() {
        let mut doc = json!({
            "type": "message", "model": "claude-test", "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "ich lösche"},
                {"type": "tool_use", "id": "toolu_9", "name": "Bash", "input": {"command": "rm -rf /"}}
            ],
            "usage": {"input_tokens": 5, "cache_read_input_tokens": 0, "output_tokens": 8}
        });

        let s = summarize_message(&doc).unwrap();
        assert_eq!(s.texts, vec![(0, "ich lösche".to_owned())]);
        assert_eq!(s.tools.len(), 1);
        assert_eq!(s.tools[0].index, 1);
        assert_eq!(s.tools[0].input["command"], "rm -rf /");
        assert_eq!(s.usage.billable(), 13);

        deny_in_message(&mut doc, 1, "[hedge] blocked");
        assert_eq!(
            doc["content"][1],
            json!({"type": "text", "text": "[hedge] blocked"})
        );
        assert_eq!(doc["stop_reason"], "end_turn");

        assert!(summarize_message(&json!({"id": "x"})).is_none());
        assert!(summarize_message(&json!({"usage": {"prompt_tokens": 1}})).is_some());
    }

    /// Spielt den Strom so durch wie der Proxy: Vor dem Tool-Block steht ein
    /// Hinweis, danach wird der Aufruf freigegeben oder ersetzt.
    fn with_notice(stream: &str, approve: bool) -> (Analyzer, Vec<Value>) {
        let mut a = Analyzer::new(true);
        let mut out: Vec<Bytes> = Vec::new();
        for ev in frames(stream.as_bytes(), 64) {
            for step in a.on_event(ev) {
                match step {
                    Step::Forward(b) => out.push(b),
                    Step::Text { .. } => {}
                    Step::Tool(t) => {
                        out.push(a.notice_block(t.index, "[hedge] waiting"));
                        if approve {
                            out.extend(t.events.into_iter().map(|e| a.reindex(e)));
                        } else {
                            a.mark_denied();
                            out.push(replacement_events(a.shifted(t.index), "[hedge] rejected"));
                        }
                    }
                }
            }
        }
        let joined: Vec<u8> = out.iter().flat_map(|b| b.to_vec()).collect();
        let events = frames(&joined, joined.len())
            .iter()
            .filter_map(|e| event_json(e))
            .collect();
        (a, events)
    }

    /// (Index, Typ) jedes Blocks in der Reihenfolge, in der der Client ihn sieht.
    fn blocks(events: &[Value]) -> Vec<(u64, String)> {
        let mut open: Option<u64> = None;
        let mut out = Vec::new();
        for ev in events {
            let index = ev.get("index").and_then(Value::as_u64);
            match ev["type"].as_str().unwrap() {
                "content_block_start" => {
                    assert!(open.is_none(), "blocks must not overlap");
                    open = index;
                    out.push((
                        index.unwrap(),
                        ev["content_block"]["type"].as_str().unwrap().to_owned(),
                    ));
                }
                "content_block_delta" => assert_eq!(index, open, "delta belongs to the open block"),
                "content_block_stop" => {
                    assert_eq!(index, open, "stop closes the open block");
                    open = None;
                }
                _ => {}
            }
        }
        assert!(open.is_none());
        out
    }

    #[test]
    fn a_notice_block_shifts_everything_after_it() {
        let stream = message_with_tool("ok", "git push --force");

        let (a, events) = with_notice(&stream, true);
        assert_eq!(
            blocks(&events),
            vec![
                (0, "text".into()),
                (1, "text".into()),
                (2, "tool_use".into())
            ],
            "notice sits between the text and the released tool call"
        );
        assert_eq!(a.stop_reason.as_deref(), Some("tool_use"));
        let tool_json: String = events
            .iter()
            .filter(|e| e["delta"]["type"] == "input_json_delta")
            .map(|e| e["delta"]["partial_json"].as_str().unwrap())
            .collect();
        assert_eq!(
            serde_json::from_str::<Value>(&tool_json).unwrap()["command"],
            "git push --force",
            "the released call is intact"
        );

        let (a, events) = with_notice(&stream, false);
        assert_eq!(
            blocks(&events),
            vec![(0, "text".into()), (1, "text".into()), (2, "text".into())]
        );
        assert_eq!(a.stop_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn without_a_notice_nothing_is_rewritten() {
        let a = Analyzer::new(true);
        let ev = Bytes::from(event(
            "content_block_stop",
            json!({"type":"content_block_stop","index":3}),
        ));
        assert_eq!(a.reindex(ev.clone()), ev);
        assert_eq!(a.shifted(3), 3);
    }

    #[test]
    fn interrupted_stream_releases_withheld_events() {
        let stream = message_with_tool("ok", "ls");
        let cut = stream.find("content_block_stop\",\"index\":1").unwrap();
        let mut a = Analyzer::new(true);
        let mut f = SseFramer::default();
        f.push(&stream.as_bytes()[..cut]);
        while let Some(ev) = f.next_event() {
            a.on_event(ev);
        }
        let pending = a.drain_pending();
        assert_eq!(pending.len(), 3, "start and two deltas were withheld");
        assert!(a.drain_pending().is_empty());
    }
}
