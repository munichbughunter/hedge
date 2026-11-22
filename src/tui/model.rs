//! Das Datenmodell der TUI – ohne Terminal, ohne Farben, voll testbar.
//!
//! Quelle ist der Witness: Jede Zeile, die der Proxy schreibt, wird hier zu
//! Session-Zeilen, Zählern und Entscheidungen verdichtet. Die Ansicht fragt
//! das Modell nur noch ab. Was ein Eintrag für einen Menschen bedeutet
//! (`summary` für die Übersicht, `tape` für den Live-Reiter), steht
//! ebenfalls hier – als Text mit einem [`Tone`], den die Ansicht in eine
//! Farbe übersetzt.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chrono::NaiveDate;
use ed25519_dalek::VerifyingKey;

use crate::cli::{Level, counted, flag_help, human_count, parse_ts, severity_of, tool_stopped};
use crate::detect::describe_kind;
use crate::witness::{self, Entry, FindingRecord, Problem, ToolRecord};

/// Schlüssel für Anfragen, die keine Session mitschicken.
pub const NO_SESSION: &str = "-";

/// Bedeutung eines Textstücks; die Ansicht macht daraus eine Farbe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Ink,
    Muted,
    Dim,
    Accent,
    Ok,
    Warn,
    Bad,
}

/// Eine Zeile der Sessions-Tabelle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionRow {
    pub id: String,
    pub client: Option<String>,
    pub models: Vec<String>,
    pub first: String,
    pub last: String,
    /// Sequenznummer des letzten Eintrags – ordnet eindeutig, auch wenn zwei
    /// Einträge in dieselbe Millisekunde fallen.
    pub last_seq: u64,
    pub requests: usize,
    pub tools: usize,
    /// Blockierte Anfragen + gestoppte Tool-Aufrufe (deny, rejected, timeout).
    pub blocked: usize,
    /// Tool-Aufrufe, die eine Freigabe gebraucht haben.
    pub held: usize,
    /// Markierte Tool-Aufrufe (ohne enforce) + Auffälligkeiten.
    pub flagged: usize,
    /// Neue Funde im Prompt + Funde in der Antwort.
    pub findings: usize,
    pub tokens: u64,
    /// Ein Eintrag dieser Session hat die Kettenprüfung nicht bestanden.
    pub broken: bool,
}

/// Summen über alles, was das Modell kennt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Totals {
    pub requests: usize,
    pub blocked: usize,
    pub held: usize,
    pub flagged: usize,
    pub findings: usize,
}

/// Zustand der Hash-Kette.
#[derive(Debug, Default)]
pub struct Chain {
    pub records: usize,
    pub problems: Vec<Problem>,
    /// Kein öffentlicher Schlüssel gefunden: Kette kann nicht geprüft werden.
    pub unchecked: bool,
}

impl Chain {
    pub fn intact(&self) -> bool {
        !self.unchecked && self.problems.is_empty()
    }
}

#[derive(Default)]
pub struct Model {
    pub entries: Vec<Entry>,
    /// Neueste Aktivität zuerst.
    pub sessions: Vec<SessionRow>,
    pub totals: Totals,
    pub chain: Chain,
    /// Jede Entscheidung, die kein schlichtes „erlaubt“ war, in der
    /// Reihenfolge, in der sie fiel.
    pub decisions: Vec<Decision>,
    /// Antworten auf Freigabe-Anfragen (approved, rejected, expired).
    pub answers: Vec<Answer>,
    /// Freigaben, deren Aufruf danach tatsächlich lief.
    ran: BTreeSet<String>,
    tokens_by_day: BTreeMap<NaiveDate, u64>,
    key: Option<VerifyingKey>,
}

impl Model {
    pub fn new(key: Option<VerifyingKey>) -> Self {
        Self {
            chain: Chain {
                unchecked: key.is_none(),
                ..Chain::default()
            },
            key,
            ..Self::default()
        }
    }

    /// Nimmt neue Einträge auf: prüft die Kette weiter, zählt, sortiert.
    pub fn ingest(&mut self, new: Vec<Entry>) {
        if new.is_empty() {
            return;
        }
        self.verify_tail(&new);
        for e in &new {
            self.track(e);
            self.count(e);
        }
        self.entries.extend(new);
        self.chain.records = self.entries.len();
        self.sessions.sort_by_key(|r| std::cmp::Reverse(r.last_seq));
    }

    /// Prüft nur das neue Stück: der letzte bekannte Eintrag dient als
    /// Aufhänger, damit auch die Verkettung über die Nahtstelle geprüft wird.
    fn verify_tail(&mut self, new: &[Entry]) {
        let Some(key) = &self.key else { return };
        let mut slice: Vec<Entry> = Vec::with_capacity(new.len() + 1);
        let carried = self.entries.last().map(|e| e.seq);
        slice.extend(self.entries.last().cloned());
        slice.extend(new.iter().cloned());
        for p in witness::verify(&slice, key).problems {
            if Some(p.seq) == carried || self.chain.problems.contains(&p) {
                continue;
            }
            self.chain.problems.push(p);
        }
        let bad: Vec<u64> = self.chain.problems.iter().map(|p| p.seq).collect();
        for e in new.iter().filter(|e| bad.contains(&e.seq)) {
            let id = session_key(e).to_owned();
            self.row(&id, e).broken = true;
        }
    }

    fn row(&mut self, id: &str, e: &Entry) -> &mut SessionRow {
        let at = match self.sessions.iter().position(|r| r.id == id) {
            Some(i) => i,
            None => {
                self.sessions.push(SessionRow {
                    id: id.to_owned(),
                    client: e.client.clone(),
                    first: e.ts.clone(),
                    last: e.ts.clone(),
                    ..SessionRow::default()
                });
                self.sessions.len() - 1
            }
        };
        &mut self.sessions[at]
    }

    fn count(&mut self, e: &Entry) {
        // Ereignisse (start, hold, approval, …) sind keine Anfragen.
        if e.event.is_some() {
            return;
        }
        let blocked =
            usize::from(e.action == "block") + e.tools.iter().filter(|t| stopped(t)).count();
        let held = e.tools.iter().filter(|t| t.approval.is_some()).count();
        let flagged = e.tools.iter().filter(|t| t.decision == "flag").count() + e.flags.len();
        let findings = e.findings.iter().filter(|f| !f.repeat).count() + e.response_findings.len();
        let tokens = e.tokens_in.unwrap_or(0) + e.tokens_out.unwrap_or(0);

        self.totals.requests += 1;
        self.totals.blocked += blocked;
        self.totals.held += held;
        self.totals.flagged += flagged;
        self.totals.findings += findings;
        if let Some(day) = local_day(&e.ts) {
            *self.tokens_by_day.entry(day).or_default() += tokens;
        }

        let id = session_key(e).to_owned();
        let row = self.row(&id, e);
        row.last = e.ts.clone();
        row.last_seq = e.seq;
        row.requests += 1;
        row.tools += e.tools.len();
        row.blocked += blocked;
        row.held += held;
        row.flagged += flagged;
        row.findings += findings;
        row.tokens += tokens;
        if row.client.is_none() {
            row.client = e.client.clone();
        }
        if let Some(m) = &e.model
            && !row.models.contains(m)
        {
            row.models.push(m.clone());
        }
    }

    pub fn tokens_on(&self, day: NaiveDate) -> u64 {
        self.tokens_by_day.get(&day).copied().unwrap_or(0)
    }

    pub fn session(&self, id: &str) -> Option<&SessionRow> {
        self.sessions.iter().find(|r| r.id == id)
    }
}

fn stopped(t: &ToolRecord) -> bool {
    tool_stopped(&t.decision)
}

pub fn session_key(e: &Entry) -> &str {
    e.session.as_deref().unwrap_or(NO_SESSION)
}

fn local_day(ts: &str) -> Option<NaiveDate> {
    parse_ts(ts).map(|t| t.with_timezone(&chrono::Local).date_naive())
}

/// So viele Einträge holt die Ansicht beim Start mindestens aus abgelegten
/// Segmenten dazu – genug für die letzten Tage, ohne alles zu laden.
const HISTORY: usize = 20_000;

/// Liest den Witness fortlaufend, auch über eine Rotation hinweg. Wird die
/// Datei geleert oder beginnt eine andere Kette, beginnt das Modell von vorn.
pub struct Source {
    follower: witness::Follower,
    key: Option<VerifyingKey>,
}

impl Source {
    pub fn new(path: &Path, key: Option<VerifyingKey>) -> Self {
        Self {
            follower: witness::Follower::new(path).with_history(HISTORY),
            key,
        }
    }

    pub fn path(&self) -> &Path {
        self.follower.path()
    }

    pub fn fresh_model(&self) -> Model {
        Model::new(self.key)
    }

    /// Liefert die neuen Einträge; `true` an erster Stelle heißt: die Kette
    /// hat neu begonnen, das Modell muss verworfen werden.
    pub fn poll(&mut self) -> (bool, Vec<Entry>) {
        self.follower.poll()
    }
}

/// Welche Einträge gerade gezeigt werden.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Kleingeschriebener Suchtext; leer = alles.
    pub query: String,
    /// Nur Auffälliges (wie `hedge tail --alerts`).
    pub alerts: bool,
    /// Nur diese Session.
    pub session: Option<String>,
}

impl Filter {
    pub fn wants(&self, e: &Entry) -> bool {
        if let Some(s) = &self.session
            && session_key(e) != s
        {
            return false;
        }
        if self.alerts && severity_of(e) <= Level::Known {
            return false;
        }
        self.query.is_empty() || haystack(e).contains(&self.query)
    }

    pub fn wants_session(&self, r: &SessionRow) -> bool {
        if self.query.is_empty() {
            return true;
        }
        let hay = format!(
            "{} {} {}",
            r.id,
            r.client.as_deref().unwrap_or(""),
            r.models.join(" ")
        )
        .to_lowercase();
        hay.contains(&self.query)
    }
}

fn haystack(e: &Entry) -> String {
    let mut parts: Vec<&str> = vec![session_key(e), &e.upstream, &e.action, &e.path];
    parts.extend(e.client.as_deref());
    parts.extend(e.model.as_deref());
    parts.extend(e.event.as_deref());
    parts.extend(e.detail.as_deref());
    for t in &e.tools {
        parts.push(&t.name);
        parts.push(&t.decision);
        parts.extend(t.rule.as_deref());
        parts.extend(t.preview.as_deref());
        parts.extend(t.approval.as_deref());
    }
    for f in e.findings.iter().chain(&e.response_findings) {
        parts.push(&f.kind);
        parts.extend(f.hint.as_deref());
    }
    parts.extend(e.flags.iter().map(String::as_str));
    parts.join(" ").to_lowercase()
}

/// Ein Eintrag in einer Zeile: Urteil, worum es geht, Detail, Regel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub label: &'static str,
    pub tone: Tone,
    /// Fett und – bei HOLD – als gefüllte Fläche.
    pub loud: bool,
    pub subject: String,
    pub detail: String,
    pub rule: String,
}

pub fn summary(e: &Entry) -> Summary {
    if let Some(event) = &e.event {
        return event_summary(event, e.detail.as_deref().unwrap_or(""));
    }
    let level = severity_of(e);
    let (label, tone, loud) = match level {
        Level::Block => ("BLOCK", Tone::Bad, true),
        Level::Stop => ("STOP", Tone::Bad, true),
        Level::Hold => ("HOLD", Tone::Warn, true),
        Level::Redact => ("REDACT", Tone::Accent, true),
        Level::Seen => ("SEEN", Tone::Warn, false),
        Level::Flag => ("FLAG", Tone::Warn, false),
        Level::Known => ("seen", Tone::Dim, false),
        Level::Ok => ("ok", Tone::Ok, false),
    };
    let lead = lead_tool(e, level).map(|i| &e.tools[i]);
    let tool_parts = |t: &ToolRecord, note: &str| {
        let rule = match (&t.rule, note.is_empty()) {
            (Some(r), false) => format!("{r} · {note}"),
            (Some(r), true) => r.clone(),
            (None, _) => note.to_owned(),
        };
        (t.name.clone(), t.preview.clone().unwrap_or_default(), rule)
    };
    let (subject, detail, rule) = match level {
        Level::Block => (
            "prompt".to_owned(),
            e.detail
                .clone()
                .unwrap_or_else(|| finding_brief(&e.findings)),
            "blocked".to_owned(),
        ),
        Level::Stop => match lead {
            Some(t) => tool_parts(t, decision_word(&t.decision)),
            None => Default::default(),
        },
        Level::Hold => match lead {
            Some(t) => tool_parts(t, t.approval.as_deref().unwrap_or("")),
            None => Default::default(),
        },
        Level::Redact | Level::Seen => (
            "prompt".to_owned(),
            finding_brief(&e.findings),
            if level == Level::Redact {
                "masked"
            } else {
                "new"
            }
            .to_owned(),
        ),
        Level::Flag => {
            if let Some(t) = lead {
                tool_parts(t, decision_word(&t.decision))
            } else if let Some(f) = e.flags.first() {
                ("flag".to_owned(), f.clone(), flag_help(f).to_owned())
            } else {
                (
                    "answer".to_owned(),
                    finding_brief(&e.response_findings),
                    "in the model's answer".to_owned(),
                )
            }
        }
        Level::Known | Level::Ok => (
            e.model
                .clone()
                .unwrap_or_else(|| format!("{} {}", e.method, e.path)),
            traffic(e),
            if level == Level::Known {
                "history resent".to_owned()
            } else {
                String::new()
            },
        ),
    };
    Summary {
        label,
        tone,
        loud,
        subject,
        detail,
        rule,
    }
}

/// Der Tool-Aufruf, den die Kopfzeile eines Eintrags zeigt: der, der das
/// Urteil bestimmt hat.
fn lead_tool(e: &Entry, level: Level) -> Option<usize> {
    let pick: fn(&ToolRecord) -> bool = match level {
        Level::Stop => stopped,
        Level::Hold => |t| t.decision == "held",
        Level::Flag => |t| t.rule.is_some() && t.decision != "allow",
        _ => return None,
    };
    e.tools.iter().position(pick)
}

fn event_summary(event: &str, detail: &str) -> Summary {
    let (label, tone, loud) = match event {
        "hold" => ("HOLD", Tone::Warn, true),
        "approval" if detail.contains(" approved ") => ("✓", Tone::Ok, false),
        "approval" => ("✗", Tone::Bad, false),
        "config_reload_failed" => ("CONFIG", Tone::Bad, true),
        "presidio_unavailable" => ("OUTAGE", Tone::Bad, true),
        "presidio_ready" => ("✓", Tone::Ok, false),
        _ => ("·", Tone::Dim, false),
    };
    Summary {
        label,
        tone,
        loud,
        subject: event.to_owned(),
        detail: detail.to_owned(),
        rule: String::new(),
    }
}

fn decision_word(decision: &str) -> &'static str {
    match decision {
        "deny" => "denied",
        "rejected" => "rejected by reviewer",
        "timeout" => "approval timed out",
        "approved" => "approved",
        "held" => "needs approval",
        "flag" => "would be stopped",
        _ => "",
    }
}

/// `1.9k in · 212 out · ⚙ Bash ×2`
fn traffic(e: &Entry) -> String {
    let mut parts = Vec::new();
    if e.tokens_in.is_some() || e.tokens_out.is_some() {
        parts.push(format!("{} in", human_count(e.tokens_in.unwrap_or(0))));
        parts.push(format!("{} out", human_count(e.tokens_out.unwrap_or(0))));
    }
    if !e.tools.is_empty() {
        let names: Vec<&str> = e.tools.iter().map(|t| t.name.as_str()).collect();
        parts.push(format!("⚙ {}", counted(&names)));
    }
    match e.status {
        Some(s) if s >= 400 => parts.push(format!("HTTP {s}")),
        None => parts.push("no answer".to_owned()),
        _ => {}
    }
    if e.aborted {
        parts.push("stream ended early".to_owned());
    }
    parts.join(" · ")
}

fn finding_label(f: &FindingRecord) -> String {
    match &f.hint {
        Some(h) => format!("{} {h}", describe_kind(&f.kind)),
        None => describe_kind(&f.kind).to_owned(),
    }
}

/// Der erste neue Fund, mit Stelle und Zahl der übrigen.
fn finding_brief(findings: &[FindingRecord]) -> String {
    let new: Vec<&FindingRecord> = findings.iter().filter(|f| !f.repeat).collect();
    let shown = new.first().copied().or(findings.first());
    match shown {
        Some(f) => {
            let more = new.len().saturating_sub(1);
            let tail = if more > 0 {
                format!("  (+{more} more)")
            } else {
                String::new()
            };
            format!("{} · {}{tail}", finding_label(f), f.path)
        }
        None => String::new(),
    }
}

/// Funde verdichtet: eine Zeile pro Art und Wert; Wiederholungen aus der
/// mitgeschickten Historie schrumpfen auf eine Zeile.
///
/// Der dritte Wert sagt, ob die Gruppe nur gemeldet wurde (Presidio ohne
/// `enforce`): Solche Funde sind nie maskiert, auch wenn die Anfrage es ist.
fn finding_groups(findings: &[FindingRecord]) -> Vec<(String, Tone, bool)> {
    let mut groups: Vec<(&FindingRecord, usize)> = Vec::new();
    for f in findings.iter().filter(|f| !f.repeat) {
        match groups
            .iter_mut()
            .find(|(g, _)| g.kind == f.kind && g.hint == f.hint && g.advisory == f.advisory)
        {
            Some((_, n)) => *n += 1,
            None => groups.push((f, 1)),
        }
    }
    let mut lines: Vec<(String, Tone, bool)> = groups
        .into_iter()
        .map(|(f, n)| {
            let count = if n > 1 {
                format!("{n}× ")
            } else {
                String::new()
            };
            let tone = match f.severity.as_str() {
                "high" => Tone::Bad,
                "medium" => Tone::Warn,
                _ => Tone::Ink,
            };
            (
                format!("{count}{} · {}", finding_label(f), f.path),
                tone,
                f.advisory,
            )
        })
        .collect();
    let known = findings.iter().filter(|f| f.repeat).count();
    if known > 0 {
        lines.push((
            format!("{known} seen before in this session (history is resent with every request)"),
            Tone::Dim,
            false,
        ));
    }
    lines
}

// ---------- Entscheidungen und Freigaben ----------

/// Wie eine Freigabe-Anfrage ausging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Approved,
    Rejected,
    Expired,
}

/// Eine Antwort auf eine Freigabe-Anfrage, gelesen aus dem Witness-Ereignis
/// `approval` (`<id> approved via chat · Bash · HEDGE-SHELL-003`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub id: String,
    pub verdict: Verdict,
    /// Auf welchem Weg: `chat`, `control api`; leer bei Ablauf.
    pub via: String,
    pub tool: String,
    pub rule: String,
    pub ts: String,
    pub session: Option<String>,
}

pub fn parse_answer(e: &Entry) -> Option<Answer> {
    if e.event.as_deref() != Some("approval") {
        return None;
    }
    let detail = e.detail.as_deref()?;
    let mut parts = detail.split(" · ");
    let head = parts.next()?;
    let (id, rest) = head.split_once(' ')?;
    let (verdict, via) = if let Some(via) = rest.strip_prefix("approved via ") {
        (Verdict::Approved, via)
    } else if let Some(via) = rest.strip_prefix("rejected via ") {
        (Verdict::Rejected, via)
    } else if rest.starts_with("timed out") {
        (Verdict::Expired, "")
    } else {
        return None;
    };
    Some(Answer {
        id: id.to_owned(),
        verdict,
        via: via.to_owned(),
        tool: parts.next().unwrap_or("").to_owned(),
        rule: parts.next().unwrap_or("").to_owned(),
        ts: e.ts.clone(),
        session: e.session.clone(),
    })
}

/// Was Hedge entschieden hat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ruling {
    /// Tool-Aufruf angehalten, ein Mensch entscheidet.
    Hold,
    /// Tool-Aufruf verworfen.
    Deny,
    /// Tool-Aufruf nur markiert (ohne `enforce`).
    Flag,
    /// Anfrage abgelehnt.
    Block,
    /// Funde im Prompt maskiert.
    Redact,
}

impl Ruling {
    pub fn label(self) -> &'static str {
        match self {
            Ruling::Hold => "HOLD",
            Ruling::Deny => "DENY",
            Ruling::Flag => "FLAG",
            Ruling::Block => "BLOCK",
            Ruling::Redact => "REDACT",
        }
    }
}

/// Eine Entscheidung, die kein schlichtes „erlaubt“ war.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub seq: u64,
    pub ts: String,
    pub session: String,
    /// Tool-Name, oder `prompt` für Entscheidungen über die Anfrage selbst.
    pub call: String,
    /// Maskierte Vorschau der Eingabe bzw. der Fund.
    pub args: String,
    pub ruling: Ruling,
    /// Regel-ID bei Tool-Aufrufen, sonst der Grund in Worten.
    pub rule: String,
    pub approval: Option<String>,
    /// Ausgang, wie er am Aufruf selbst steht (wartender Modus).
    settled: Option<Verdict>,
}

/// Was aus einer Entscheidung wurde.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    Waiting,
    Blocked,
    Flagged,
    Masked,
    Approved {
        ran: bool,
    },
    Rejected,
    Expired,
    /// Angehalten, aber keine Antwort im Witness und nichts wartet mehr.
    Unanswered,
}

impl Model {
    /// Liest aus einem Eintrag Entscheidungen und Antworten heraus.
    fn track(&mut self, e: &Entry) {
        if let Some(answer) = parse_answer(e) {
            self.answers.push(answer);
            return;
        }
        if e.event.is_some() {
            return;
        }
        let session = session_key(e).to_owned();
        let base = |call: &str, args: String, ruling: Ruling, rule: String| Decision {
            seq: e.seq,
            ts: e.ts.clone(),
            session: session.clone(),
            call: call.to_owned(),
            args,
            ruling,
            rule,
            approval: None,
            settled: None,
        };
        if e.action == "block" {
            let why = e.detail.clone().unwrap_or_else(|| "blocked".into());
            self.decisions.push(base(
                "prompt",
                finding_brief(&e.findings),
                Ruling::Block,
                why,
            ));
        } else if e.action == "redact" && e.findings.iter().any(|f| !f.repeat) {
            self.decisions.push(base(
                "prompt",
                finding_brief(&e.findings),
                Ruling::Redact,
                "secrets or personal data are masked before they leave".into(),
            ));
        }
        for t in e
            .tools
            .iter()
            .filter(|t| t.rule.is_some() && t.decision != "allow")
        {
            let (ruling, settled) = match t.decision.as_str() {
                "deny" => (Ruling::Deny, None),
                "flag" => (Ruling::Flag, None),
                "approved" => (Ruling::Hold, Some(Verdict::Approved)),
                "rejected" => (Ruling::Hold, Some(Verdict::Rejected)),
                "timeout" => (Ruling::Hold, Some(Verdict::Expired)),
                _ => (Ruling::Hold, None),
            };
            if let Some(id) = &t.approval {
                if t.decision == "approved" {
                    self.ran.insert(id.clone());
                }
                // Im Gespräch erscheint derselbe Aufruf zweimal: erst
                // angehalten, nach der Freigabe noch einmal und läuft. Das
                // ist eine Entscheidung, nicht zwei.
                if self
                    .decisions
                    .iter()
                    .any(|d| d.approval.as_deref() == Some(id.as_str()))
                {
                    continue;
                }
            }
            self.decisions.push(Decision {
                approval: t.approval.clone(),
                settled,
                ..base(
                    &t.name,
                    t.preview.clone().unwrap_or_default(),
                    ruling,
                    t.rule.clone().unwrap_or_default(),
                )
            });
        }
    }

    /// Die jüngste Antwort auf eine Anfrage.
    pub fn answer(&self, id: &str) -> Option<&Answer> {
        self.answers.iter().rev().find(|a| a.id == id)
    }

    /// Die Entscheidung, zu der eine Freigabe-ID gehört.
    pub fn decision_of(&self, id: &str) -> Option<&Decision> {
        self.decisions
            .iter()
            .find(|d| d.approval.as_deref() == Some(id))
    }

    /// Was aus einer Entscheidung wurde. `open` sagt, ob eine Freigabe-ID
    /// gerade noch auf einen Menschen wartet (das weiß nur der Proxy).
    pub fn fate(&self, d: &Decision, open: &dyn Fn(&str) -> bool) -> Fate {
        match d.ruling {
            Ruling::Deny | Ruling::Block => Fate::Blocked,
            Ruling::Flag => Fate::Flagged,
            Ruling::Redact => Fate::Masked,
            Ruling::Hold => {
                let id = d.approval.as_deref().unwrap_or("");
                if open(id) {
                    return Fate::Waiting;
                }
                let ran = self.ran.contains(id);
                match self.answer(id).map(|a| a.verdict).or(d.settled) {
                    Some(Verdict::Approved) => Fate::Approved { ran },
                    Some(Verdict::Rejected) => Fate::Rejected,
                    Some(Verdict::Expired) => Fate::Expired,
                    None if ran => Fate::Approved { ran },
                    None => Fate::Unanswered,
                }
            }
        }
    }

    /// Ein Eintrag als Zeilen des Bands: erst die Anfrage, darunter ihre
    /// Funde, Tool-Aufrufe und Auffälligkeiten.
    pub fn tape(&self, e: &Entry, open: &dyn Fn(&str) -> bool) -> Vec<TapeRow> {
        if let Some(event) = &e.event {
            return vec![event_row(e, event)];
        }
        let mut rows = Vec::new();
        let blocked = e.action == "block";
        let row = |evt: &'static str, tone: Tone| TapeRow {
            evt,
            tone,
            tool: String::new(),
            text: String::new(),
            status: String::new(),
            status_tone: Tone::Muted,
            ms: None,
            decision: false,
            approval: false,
        };

        let what = e
            .model
            .clone()
            .unwrap_or_else(|| format!("{} {}", e.method, e.path));
        let (status, status_tone) = match e.status {
            _ if blocked => ("BLOCKED".to_owned(), Tone::Bad),
            Some(code) if code < 400 => (code.to_string(), Tone::Ok),
            Some(code) => (code.to_string(), Tone::Bad),
            None => ("—".to_owned(), Tone::Bad),
        };
        rows.push(TapeRow {
            text: match (blocked, &e.detail) {
                (true, Some(why)) => format!("{what} · {why}"),
                (false, Some(why)) => format!("{what} · {} · {why}", tokens(e)),
                _ => format!("{what} · {}", tokens(e)),
            },
            status,
            status_tone,
            ms: Some(e.duration_ms),
            decision: blocked,
            ..row(
                if blocked { "BLOCK" } else { "MODEL" },
                if blocked { Tone::Bad } else { Tone::Accent },
            )
        });

        let masked = e.action == "redact";
        for (text, tone, advisory) in finding_groups(&e.findings) {
            let known = tone == Tone::Dim;
            rows.push(TapeRow {
                text,
                status: match (known, advisory, blocked, masked) {
                    (true, _, _, _) => "",
                    // Nur gemeldet: an diesem Fund hing keine Entscheidung.
                    (_, true, _, _) => "SEEN",
                    (_, _, true, _) => "BLOCKED",
                    (_, _, _, true) => "MASKED",
                    _ => "SEEN",
                }
                .to_owned(),
                status_tone: if blocked && !advisory {
                    Tone::Bad
                } else {
                    Tone::Accent
                },
                decision: !known && !advisory && (blocked || masked),
                ..row("FIND", tone)
            });
        }
        for (text, tone, _) in finding_groups(&e.response_findings) {
            rows.push(TapeRow {
                text,
                status: "IN ANSWER".to_owned(),
                status_tone: Tone::Warn,
                ..row("FIND", tone)
            });
        }

        for t in &e.tools {
            let hit = t.rule.is_some() && t.decision != "allow";
            let mut r = TapeRow {
                tool: t.name.clone(),
                text: t.preview.clone().unwrap_or_default(),
                status: "OK".to_owned(),
                status_tone: Tone::Ok,
                ..row("TOOL", Tone::Muted)
            };
            if hit {
                let rule = t.rule.as_deref().unwrap_or("");
                r.text = format!("{} · {rule}", r.text);
                r.decision = true;
                r.approval = t.approval.is_some();
                let fate = match (t.decision.as_str(), &t.approval) {
                    ("deny", _) => Fate::Blocked,
                    ("flag", _) => Fate::Flagged,
                    ("approved", _) => Fate::Approved { ran: true },
                    ("rejected", _) => Fate::Rejected,
                    ("timeout", _) => Fate::Expired,
                    (_, Some(id)) => match self.decision_of(id) {
                        Some(d) => self.fate(d, open),
                        None => Fate::Unanswered,
                    },
                    _ => Fate::Unanswered,
                };
                (r.evt, r.tone) = match t.decision.as_str() {
                    "deny" => ("DENY", Tone::Bad),
                    "flag" => ("FLAG", Tone::Warn),
                    "approved" => ("TOOL", Tone::Muted),
                    _ => ("HOLD", Tone::Warn),
                };
                let (status, status_tone) = match fate {
                    Fate::Waiting => ("WAITING", Tone::Warn),
                    Fate::Blocked => ("DENIED", Tone::Bad),
                    Fate::Flagged => ("⚑ RAN", Tone::Warn),
                    Fate::Masked => ("MASKED", Tone::Accent),
                    // Der angehaltene Aufruf selbst lief nicht – erst seine
                    // Wiederholung nach der Freigabe.
                    Fate::Approved { .. } if t.decision == "approved" => {
                        ("APPROVED · RAN", Tone::Ok)
                    }
                    Fate::Approved { .. } => ("APPROVED", Tone::Ok),
                    Fate::Rejected => ("REJECTED", Tone::Bad),
                    Fate::Expired => ("EXPIRED", Tone::Bad),
                    Fate::Unanswered => ("UNANSWERED", Tone::Dim),
                };
                r.status = status.to_owned();
                r.status_tone = status_tone;
            }
            rows.push(r);
        }
        for f in &e.flags {
            rows.push(TapeRow {
                text: format!("{f} — {}", flag_help(f)),
                ..row("FLAG", Tone::Warn)
            });
        }
        if e.aborted {
            rows.push(TapeRow {
                text: "the stream ended early".to_owned(),
                ..row("NOTE", Tone::Dim)
            });
        }
        rows
    }
}

/// Eine Zeile des Bands (Live-Reiter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapeRow {
    /// MODEL, FIND, TOOL, HOLD, DENY, FLAG, BLOCK, START, …
    pub evt: &'static str,
    pub tone: Tone,
    pub tool: String,
    pub text: String,
    pub status: String,
    pub status_tone: Tone,
    pub ms: Option<u64>,
    /// Hedge hat hier eingegriffen oder markiert.
    pub decision: bool,
    /// Gehört zu einer Freigabe (Anfrage oder Antwort).
    pub approval: bool,
}

fn event_row(e: &Entry, event: &str) -> TapeRow {
    let answer = parse_answer(e);
    let (evt, tone, status, status_tone) = match (event, answer.as_ref().map(|a| a.verdict)) {
        ("hold", _) => ("HOLD", Tone::Warn, "ASKED", Tone::Warn),
        (_, Some(Verdict::Approved)) => ("ANSWER", Tone::Ok, "APPROVED", Tone::Ok),
        (_, Some(Verdict::Rejected)) => ("ANSWER", Tone::Bad, "REJECTED", Tone::Bad),
        (_, Some(Verdict::Expired)) => ("ANSWER", Tone::Bad, "EXPIRED", Tone::Bad),
        ("start", _) => ("START", Tone::Dim, "", Tone::Dim),
        ("stop", _) => ("STOP", Tone::Dim, "", Tone::Dim),
        ("config_reload", _) => ("CONFIG", Tone::Muted, "RELOADED", Tone::Muted),
        ("config_reload_failed", _) => ("CONFIG", Tone::Bad, "REJECTED", Tone::Bad),
        ("presidio_unavailable", _) => ("OUTAGE", Tone::Bad, "PRESIDIO DOWN", Tone::Bad),
        ("presidio_ready", _) => ("READY", Tone::Ok, "PRESIDIO", Tone::Ok),
        ("rotate", _) => ("ROTATE", Tone::Muted, "", Tone::Muted),
        ("recovered", _) => ("WITNESS", Tone::Warn, "RECOVERED", Tone::Warn),
        _ => ("EVENT", Tone::Dim, "", Tone::Dim),
    };
    TapeRow {
        evt,
        tone,
        tool: answer.as_ref().map(|a| a.tool.clone()).unwrap_or_default(),
        text: match &answer {
            Some(a) if a.via.is_empty() => {
                format!("{} · nobody answered in time · {}", a.id, a.rule)
            }
            Some(a) => format!("{} · via {} · {}", a.id, a.via, a.rule),
            None => e.detail.clone().unwrap_or_default(),
        },
        status: status.to_owned(),
        status_tone,
        ms: None,
        decision: false,
        approval: matches!(event, "hold" | "approval"),
    }
}

/// `1.4k in · 180 out`
fn tokens(e: &Entry) -> String {
    match (e.tokens_in, e.tokens_out) {
        (None, None) => "no usage reported".to_owned(),
        (i, o) => format!(
            "{} in · {} out",
            human_count(i.unwrap_or(0)),
            human_count(o.unwrap_or(0))
        ),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::witness::{Record, Witness};

    pub(crate) fn request(session: &str) -> Record {
        Record {
            upstream: "anthropic".into(),
            method: "POST".into(),
            path: "/v1/messages".into(),
            model: Some("claude-sonnet-4-5".into()),
            mode: "redact".into(),
            action: "forward".into(),
            status: Some(200),
            session: Some(session.into()),
            tokens_in: Some(1000),
            tokens_out: Some(200),
            ..Record::default()
        }
    }

    pub(crate) fn tool(name: &str, decision: &str, rule: Option<&str>) -> ToolRecord {
        ToolRecord {
            id: "toolu_1".into(),
            name: name.into(),
            preview: Some("git push --force origin main".into()),
            rule: rule.map(str::to_owned),
            decision: decision.into(),
            approval: matches!(decision, "held" | "approved" | "rejected" | "timeout")
                .then(|| "apr-1".to_owned()),
            ..ToolRecord::default()
        }
    }

    pub(crate) fn finding(kind: &str, hint: &str, repeat: bool) -> FindingRecord {
        FindingRecord {
            hint: Some(hint.into()),
            repeat,
            ..FindingRecord::new(kind, "high", "messages[3].content")
        }
    }

    /// Schreibt echte, signierte Einträge und liest sie zurück.
    pub(crate) fn chain(records: Vec<Record>) -> (tempdir::Dir, Vec<Entry>, VerifyingKey) {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("witness.jsonl");
        let key = dir.path().join("witness.key");
        witness::generate_keypair(&key).expect("keypair");
        let w = Witness::open(&path, &key).expect("witness opens");
        for r in records {
            w.record(r).expect("record");
        }
        let entries = witness::read_entries(&path).expect("read");
        let verifying = witness::load_verifying_key(&key).expect("key");
        (dir, entries, verifying)
    }

    /// Kleinstes Temp-Verzeichnis, das sich selbst aufräumt.
    pub(crate) mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(PathBuf);

        impl Dir {
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                let mut bytes = [0u8; 8];
                getrandom::fill(&mut bytes).expect("random");
                let p = std::env::temp_dir().join(format!("hedge-tui-{}", hex::encode(bytes)));
                std::fs::create_dir_all(&p).expect("temp dir");
                Self(p)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn sessions_are_counted_and_sorted_by_last_activity() {
        let mut blocked = request("aaaa1111");
        blocked.action = "block".into();
        blocked.status = None;
        let mut tools = request("bbbb2222");
        tools.tools = vec![
            tool("Bash", "deny", Some("HEDGE-SHELL-001")),
            tool("Bash", "held", Some("HEDGE-SHELL-002")),
            tool("Bash", "flag", Some("HEDGE-EXFIL-001")),
            tool("Read", "allow", None),
        ];
        tools.flags = vec!["unwitnessed_tool_result".into()];
        tools.findings = vec![
            finding("email", "p…@x.example", false),
            finding("email", "p…@x.example", true),
        ];
        let (_dir, entries, key) = chain(vec![request("aaaa1111"), blocked, tools]);

        let mut m = Model::new(Some(key));
        m.ingest(entries);

        assert_eq!(m.sessions.len(), 2);
        assert_eq!(m.sessions[0].id, "bbbb2222", "latest activity first");
        let b = &m.sessions[0];
        assert_eq!(
            (
                b.requests, b.tools, b.blocked, b.held, b.flagged, b.findings
            ),
            (1, 4, 1, 1, 2, 1)
        );
        let a = &m.sessions[1];
        assert_eq!((a.requests, a.blocked, a.tokens), (2, 1, 2400));
        assert_eq!(m.totals.requests, 3);
        assert_eq!(m.totals.blocked, 2);
        assert!(m.chain.intact());
        assert_eq!(m.chain.records, 3);
    }

    #[test]
    fn events_are_not_requests_and_missing_sessions_get_their_own_row() {
        let mut event = request("aaaa1111");
        event.event = Some("hold".into());
        event.detail = Some("apr-1 waiting · Bash · HEDGE-SHELL-002".into());
        let mut anonymous = request("x");
        anonymous.session = None;
        let (_dir, entries, key) = chain(vec![event, anonymous]);

        let mut m = Model::new(Some(key));
        m.ingest(entries);

        assert_eq!(m.totals.requests, 1);
        assert_eq!(m.sessions.len(), 1);
        assert_eq!(m.sessions[0].id, NO_SESSION);
    }

    #[test]
    fn chain_is_checked_across_batches_and_a_tampered_entry_marks_its_session() {
        let (_dir, mut entries, key) = chain(vec![
            request("aaaa1111"),
            request("aaaa1111"),
            request("bbbb2222"),
            request("aaaa1111"),
        ]);
        entries[2].tokens_out = Some(1);

        let mut m = Model::new(Some(key));
        let rest = entries.split_off(2);
        m.ingest(entries);
        assert!(m.chain.intact());
        m.ingest(rest);

        assert!(!m.chain.intact());
        assert!(m.chain.problems.iter().all(|p| p.seq == 3));
        assert!(m.session("bbbb2222").expect("row").broken);
        assert!(!m.session("aaaa1111").expect("row").broken);
    }

    #[test]
    fn removing_an_entry_between_batches_breaks_the_chain() {
        let (_dir, mut entries, key) = chain(vec![request("a"), request("a"), request("a")]);
        let last = entries.pop().expect("three");
        entries.pop();

        let mut m = Model::new(Some(key));
        m.ingest(entries);
        m.ingest(vec![last]);

        assert!(!m.chain.intact());
    }

    #[test]
    fn without_a_key_the_chain_counts_as_unchecked() {
        let (_dir, entries, _key) = chain(vec![request("a")]);
        let mut m = Model::new(None);
        m.ingest(entries);
        assert!(!m.chain.intact());
        assert!(m.chain.unchecked);
    }

    #[test]
    fn source_follows_the_file_and_notices_a_restart() {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("witness.jsonl");
        let key = dir.path().join("witness.key");
        witness::generate_keypair(&key).expect("keypair");
        let w = Witness::open(&path, &key).expect("open");
        w.record(request("a")).expect("record");
        w.record(request("a")).expect("record");

        let mut src = Source::new(&path, None);
        let (restarted, first) = src.poll();
        assert!(!restarted);
        assert_eq!(first.len(), 2);
        assert_eq!(src.poll().1.len(), 0);

        w.record(request("b")).expect("record");
        assert_eq!(src.poll().1.len(), 1);

        std::fs::write(&path, "").expect("truncate");
        let (restarted, entries) = src.poll();
        assert!(restarted);
        assert!(entries.is_empty());
    }

    #[test]
    fn filter_matches_text_alerts_and_session() {
        let mut held = request("bbbb2222");
        held.tools = vec![tool("Bash", "held", Some("HEDGE-SHELL-002"))];
        let (_dir, entries, _key) = chain(vec![request("aaaa1111"), held]);

        let all = Filter::default();
        assert!(entries.iter().all(|e| all.wants(e)));

        let alerts = Filter {
            alerts: true,
            ..Filter::default()
        };
        assert!(!alerts.wants(&entries[0]));
        assert!(alerts.wants(&entries[1]));

        let text = Filter {
            query: "force".into(),
            ..Filter::default()
        };
        assert!(!text.wants(&entries[0]));
        assert!(text.wants(&entries[1]));

        let session = Filter {
            session: Some("aaaa1111".into()),
            ..Filter::default()
        };
        assert!(session.wants(&entries[0]));
        assert!(!session.wants(&entries[1]));
    }

    #[test]
    fn summary_says_what_matters_most() {
        let (_dir, entries, _key) = chain(vec![
            request("a"),
            {
                let mut r = request("a");
                r.tools = vec![tool("Bash", "held", Some("HEDGE-SHELL-002"))];
                r
            },
            {
                let mut r = request("a");
                r.tools = vec![tool("Read", "deny", Some("HEDGE-CRED-001"))];
                r
            },
            {
                let mut r = request("a");
                r.action = "redact".into();
                r.findings = vec![
                    finding("email", "p…@x.example", false),
                    finding("aws_access_key_id", "…a1b2", false),
                ];
                r
            },
            {
                let mut r = request("a");
                r.event = Some("approval".into());
                r.detail = Some("apr-1 approved via chat · Bash · HEDGE-SHELL-002".into());
                r
            },
        ]);

        let ok = summary(&entries[0]);
        assert_eq!((ok.label, ok.subject.as_str()), ("ok", "claude-sonnet-4-5"));
        assert_eq!(ok.detail, "1.0k in · 200 out");

        let hold = summary(&entries[1]);
        assert_eq!(
            (hold.label, hold.tone, hold.loud),
            ("HOLD", Tone::Warn, true)
        );
        assert_eq!(hold.subject, "Bash");
        assert_eq!(hold.rule, "HEDGE-SHELL-002 · apr-1");

        let stop = summary(&entries[2]);
        assert_eq!((stop.label, stop.tone), ("STOP", Tone::Bad));
        assert_eq!(stop.rule, "HEDGE-CRED-001 · denied");

        let redact = summary(&entries[3]);
        assert_eq!(redact.label, "REDACT");
        assert_eq!(
            redact.detail,
            "e-mail address p…@x.example · messages[3].content  (+1 more)"
        );

        let approval = summary(&entries[4]);
        assert_eq!((approval.label, approval.tone), ("✓", Tone::Ok));
    }

    fn event(kind: &str, detail: &str) -> Record {
        let mut r = request("aaaa1111");
        r.event = Some(kind.into());
        r.detail = Some(detail.into());
        r
    }

    #[test]
    fn answers_are_read_from_approval_events() {
        let (_dir, entries, _key) = chain(vec![
            event(
                "approval",
                "0f637d approved via control api · Bash · HEDGE-SHELL-004",
            ),
            event(
                "approval",
                "77a6d5 rejected via chat · Bash · HEDGE-SHELL-003",
            ),
            event(
                "approval",
                "ab0e80 timed out after 5m · Read · HEDGE-CRED-002",
            ),
            event("hold", "ab0e80 waiting · Read · HEDGE-CRED-002"),
            event("approval", "something else entirely"),
        ]);
        let got: Vec<Option<Answer>> = entries.iter().map(parse_answer).collect();
        let a = got[0].as_ref().expect("approved");
        assert_eq!(
            (
                a.id.as_str(),
                a.verdict,
                a.via.as_str(),
                a.tool.as_str(),
                a.rule.as_str()
            ),
            (
                "0f637d",
                Verdict::Approved,
                "control api",
                "Bash",
                "HEDGE-SHELL-004"
            )
        );
        let r = got[1].as_ref().expect("rejected");
        assert_eq!((r.verdict, r.via.as_str()), (Verdict::Rejected, "chat"));
        let x = got[2].as_ref().expect("expired");
        assert_eq!(
            (x.verdict, x.via.as_str(), x.tool.as_str()),
            (Verdict::Expired, "", "Read")
        );
        assert_eq!(got[3], None);
        assert_eq!(got[4], None);
    }

    #[test]
    fn a_call_approved_in_the_chat_is_one_decision_that_ran() {
        // Im Gespräch: angehalten → Antwort → das Modell wiederholt den Aufruf.
        let mut held = request("aaaa1111");
        held.tools = vec![tool("Bash", "held", Some("HEDGE-SHELL-003"))];
        let mut rerun = request("aaaa1111");
        rerun.tools = vec![tool("Bash", "approved", Some("HEDGE-SHELL-003"))];
        let (_dir, mut entries, key) = chain(vec![
            held,
            event(
                "approval",
                "apr-1 approved via chat · Bash · HEDGE-SHELL-003",
            ),
            rerun,
        ]);
        let later = entries.split_off(1);
        let nothing_open = |_: &str| false;
        let waiting = |id: &str| id == "apr-1";

        let mut m = Model::new(Some(key));
        m.ingest(entries);
        assert_eq!(m.decisions.len(), 1);
        assert_eq!(m.fate(&m.decisions[0], &waiting), Fate::Waiting);
        assert_eq!(m.fate(&m.decisions[0], &nothing_open), Fate::Unanswered);

        m.ingest(later[..1].to_vec());
        assert_eq!(
            m.fate(&m.decisions[0], &nothing_open),
            Fate::Approved { ran: false }
        );

        m.ingest(later[1..].to_vec());
        assert_eq!(
            m.decisions.len(),
            1,
            "the repeated call is not a second decision"
        );
        assert_eq!(
            m.fate(&m.decisions[0], &nothing_open),
            Fate::Approved { ran: true }
        );
        assert_eq!(
            m.decision_of("apr-1").map(|d| d.args.as_str()),
            Some("git push --force origin main")
        );
    }

    #[test]
    fn a_waiting_call_carries_its_outcome_itself() {
        // Wartender Modus: ein Eintrag, die Entscheidung steht am Aufruf.
        let outcome = |decision: &str| {
            let mut r = request("aaaa1111");
            r.tools = vec![tool("Bash", decision, Some("HEDGE-SHELL-003"))];
            let (_dir, entries, key) = chain(vec![r]);
            let mut m = Model::new(Some(key));
            m.ingest(entries);
            m.fate(&m.decisions[0], &|_: &str| false)
        };
        assert_eq!(outcome("approved"), Fate::Approved { ran: true });
        assert_eq!(outcome("rejected"), Fate::Rejected);
        assert_eq!(outcome("timeout"), Fate::Expired);
        assert_eq!(outcome("deny"), Fate::Blocked);
        assert_eq!(outcome("flag"), Fate::Flagged);
    }

    #[test]
    fn blocked_and_masked_prompts_are_decisions_but_resent_history_is_not() {
        let mut blocked = request("aaaa1111");
        blocked.action = "block".into();
        blocked.detail = Some("1 high-severity finding(s): aws_access_key_id".into());
        blocked.findings = vec![finding("aws_access_key_id", "…a1b2", false)];
        let mut masked = request("aaaa1111");
        masked.action = "redact".into();
        masked.findings = vec![finding("email", "p…@x.example", false)];
        let mut again = request("aaaa1111");
        again.action = "redact".into();
        again.findings = vec![finding("email", "p…@x.example", true)];
        let (_dir, entries, key) = chain(vec![blocked, masked, again]);

        let mut m = Model::new(Some(key));
        m.ingest(entries);
        let got: Vec<(Ruling, &str)> = m
            .decisions
            .iter()
            .map(|d| (d.ruling, d.call.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![(Ruling::Block, "prompt"), (Ruling::Redact, "prompt")]
        );
        assert_eq!(
            m.decisions[0].rule,
            "1 high-severity finding(s): aws_access_key_id"
        );
        assert!(
            m.decisions[1]
                .args
                .starts_with("e-mail address p…@x.example")
        );
    }

    #[test]
    fn the_tape_spells_a_request_out_row_by_row() {
        let mut r = request("aaaa1111");
        r.action = "redact".into();
        r.findings = vec![
            finding("email", "p…@x.example", false),
            finding("email", "q…@y.example", true),
        ];
        r.tools = vec![
            tool("Read", "allow", None),
            tool("Bash", "deny", Some("HEDGE-SHELL-001")),
            tool("Bash", "held", Some("HEDGE-SHELL-003")),
        ];
        r.flags = vec!["unwitnessed_tool_result".into()];
        let (_dir, entries, key) = chain(vec![
            r,
            event(
                "approval",
                "apr-1 rejected via chat · Bash · HEDGE-SHELL-003",
            ),
            event("start", "version=0.1.0"),
        ]);
        let mut m = Model::new(Some(key));
        m.ingest(entries);
        let open = |_: &str| false;

        let rows = m.tape(&m.entries[0], &open);
        let got: Vec<(&str, &str, &str)> = rows
            .iter()
            .map(|r| (r.evt, r.tool.as_str(), r.status.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("MODEL", "", "200"),
                ("FIND", "", "MASKED"),
                ("FIND", "", ""),
                ("TOOL", "Read", "OK"),
                ("DENY", "Bash", "DENIED"),
                ("HOLD", "Bash", "REJECTED"),
                ("FLAG", "", ""),
            ]
        );
        assert_eq!(rows[0].text, "claude-sonnet-4-5 · 1.0k in · 200 out");
        assert!(rows[5].text.ends_with("· HEDGE-SHELL-003"));
        let marks: Vec<(bool, bool)> = rows.iter().map(|r| (r.decision, r.approval)).collect();
        assert_eq!(
            marks,
            vec![
                (false, false),
                (true, false),
                (false, false),
                (false, false),
                (true, false),
                (true, true),
                (false, false),
            ]
        );

        let answer = &m.tape(&m.entries[1], &open)[0];
        assert_eq!(
            (answer.evt, answer.status.as_str(), answer.approval),
            ("ANSWER", "REJECTED", true)
        );
        assert_eq!(answer.text, "apr-1 · via chat · HEDGE-SHELL-003");
        assert_eq!(m.tape(&m.entries[2], &open)[0].evt, "START");
    }
}
