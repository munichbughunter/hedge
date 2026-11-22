//! `hedge watch` – die Live-Ansicht im Terminal.
//!
//! Aufbau in vier Teilen:
//! - [`model`] – Witness → Sessions, Entscheidungen, Band, Texte (ohne Terminal)
//! - [`theme`] – die Palette und ihre Abstufungen je Farbtiefe
//! - [`view`]  – zeichnet einen [`App`]-Zustand in einen Frame
//! - dieses Modul – Zustand, Tasten, Ereignisschleife
//!
//! Die Schleife blockiert nie: Tasten liest ein eigener Thread, die
//! Steuer-API fragen kurze Tasks ab, beides kommt über einen Kanal zurück.
//! Der Witness wird direkt von der Platte gelesen – deshalb läuft die
//! Ansicht auch, wenn der Proxy gerade nicht läuft (nur Freigaben brauchen
//! ihn).

pub mod model;
pub mod theme;
pub mod view;

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::Value;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::approvals::ApprovalInfo;
use crate::cli::{Control, Remote, Result, load_or_hint};
use crate::tools::ToolPolicy;
use crate::witness::{self, Entry};
use model::{Decision, Fate, Filter, Model, Ruling, SessionRow, Source, TapeRow, Tone};
use theme::{Depth, Theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Live,
    Approvals,
    Permissions,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Overview, Tab::Live, Tab::Approvals, Tab::Permissions];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "OVERVIEW",
            Tab::Live => "LIVE",
            Tab::Approvals => "APPROVALS",
            Tab::Permissions => "PERMISSIONS",
        }
    }
}

/// Was das Band zeigt (`f` schaltet weiter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapeFilter {
    All,
    /// Nur Anfragen, an denen etwas auffällig war (wie `hedge tail --alerts`).
    Alerts,
    /// Nur Zeilen, in denen Hedge eingegriffen oder markiert hat.
    Decisions,
    /// Nur Freigabe-Anfragen und ihre Antworten.
    Approvals,
}

impl TapeFilter {
    pub const ALL: [TapeFilter; 4] = [
        TapeFilter::All,
        TapeFilter::Alerts,
        TapeFilter::Decisions,
        TapeFilter::Approvals,
    ];

    pub fn title(self) -> &'static str {
        match self {
            TapeFilter::All => "All",
            TapeFilter::Alerts => "Alerts",
            TapeFilter::Decisions => "Decisions",
            TapeFilter::Approvals => "Approvals",
        }
    }
}

/// Auswahl im Reiter Permissions (`←`/`→`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chip {
    All,
    Waiting,
    Blocked,
    Held,
    Flagged,
    Masked,
    Approved,
    Rejected,
    Expired,
}

impl Chip {
    pub const ALL: [Chip; 9] = [
        Chip::All,
        Chip::Waiting,
        Chip::Blocked,
        Chip::Held,
        Chip::Flagged,
        Chip::Masked,
        Chip::Approved,
        Chip::Rejected,
        Chip::Expired,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Chip::All => "ALL",
            Chip::Waiting => "WAITING",
            Chip::Blocked => "BLOCKED",
            Chip::Held => "HELD",
            Chip::Flagged => "FLAGGED",
            Chip::Masked => "MASKED",
            Chip::Approved => "APPROVED",
            Chip::Rejected => "REJECTED",
            Chip::Expired => "EXPIRED OR UNANSWERED",
        }
    }

    pub fn wants(self, d: &Decision, fate: Fate) -> bool {
        match self {
            Chip::All => true,
            Chip::Waiting => fate == Fate::Waiting,
            Chip::Blocked => fate == Fate::Blocked,
            Chip::Held => d.ruling == Ruling::Hold,
            Chip::Flagged => fate == Fate::Flagged,
            Chip::Masked => fate == Fate::Masked,
            Chip::Approved => matches!(fate, Fate::Approved { .. }),
            Chip::Rejected => fate == Fate::Rejected,
            Chip::Expired => matches!(fate, Fate::Expired | Fate::Unanswered),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Normal,
    /// Tippt gerade einen Suchtext.
    Filter,
    /// `a` gedrückt: Die Freigabe ist an genau diese Anfrage gebunden und
    /// braucht ein `y` – die Liste kann sich zwischen zwei Tasten ändern.
    Confirm(Box<ApprovalInfo>),
    Help,
}

/// Ist der Proxy über die Steuer-API erreichbar?
#[derive(Debug, Clone, PartialEq)]
pub enum Link {
    Unknown,
    Up,
    Down(String),
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub tone: Tone,
    pub at: Instant,
}

/// Was die Schleife nach einer Taste tun soll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Quit,
    Resolve { id: String, approve: bool },
}

pub struct App {
    pub model: Model,
    pub tab: Tab,
    pub mode: Mode,
    /// Live zeigt nur diese Session (`enter` in der Übersicht, `←`/`→` in Live).
    pub focus: Option<String>,
    /// Wohin `esc` aus einer geöffneten Session zurückführt.
    back: Option<Tab>,
    /// Ausgewählte Session der Übersicht; folgt der ID, nicht der Position.
    pub selected: Option<String>,
    pub sel_approval: usize,
    /// Ausgewählte Zeile des Bands, 0 = die neueste.
    pub cursor: usize,
    pub tape: TapeFilter,
    pub query: String,
    pub chip: Chip,
    /// Ausgewählte Zeile im Reiter Permissions, 0 = die neueste.
    pub sel_decision: usize,
    pub approvals: Vec<ApprovalInfo>,
    pub approvals_at: Instant,
    pub link: Link,
    pub status: Option<Value>,
    pub toast: Option<Toast>,
    /// Adresse der Steuer-API, für Hinweise.
    pub base: String,
    /// Hedge läuft woanders (`--url`): Der Witness kommt über die Steuer-API.
    pub remote: bool,
    /// Warum der entfernte Witness gerade nicht zu lesen ist.
    pub remote_error: Option<String>,
    /// Regel-ID → Begründung in Worten (aus der Config).
    pub rules: BTreeMap<String, String>,
    known_approvals: Vec<String>,
}

impl App {
    pub fn new(model: Model, base: String, remote: bool) -> Self {
        Self {
            model,
            tab: Tab::Overview,
            mode: Mode::Normal,
            focus: None,
            back: None,
            selected: None,
            sel_approval: 0,
            cursor: 0,
            tape: TapeFilter::All,
            query: String::new(),
            chip: Chip::All,
            sel_decision: 0,
            approvals: Vec::new(),
            approvals_at: Instant::now(),
            link: Link::Unknown,
            status: None,
            toast: None,
            base,
            remote,
            remote_error: None,
            rules: BTreeMap::new(),
            known_approvals: Vec::new(),
        }
    }

    /// Wartet diese Freigabe gerade noch auf einen Menschen?
    pub fn is_open(&self, id: &str) -> bool {
        self.approvals.iter().any(|a| a.id == id)
    }

    /// Welche Einträge das Band zeigt. Die Session-Auswahl gilt nur in Live.
    pub fn filter(&self) -> Filter {
        Filter {
            query: self.query.to_lowercase(),
            alerts: self.tape == TapeFilter::Alerts,
            session: self.focus.clone().filter(|_| self.tab == Tab::Live),
        }
    }

    fn row_wanted(&self, r: &TapeRow) -> bool {
        match self.tape {
            TapeFilter::All | TapeFilter::Alerts => true,
            TapeFilter::Decisions => r.decision,
            TapeFilter::Approvals => r.approval,
        }
    }

    fn rows_of<'a>(&'a self, e: &'a Entry) -> impl Iterator<Item = TapeRow> + 'a {
        let open = |id: &str| self.is_open(id);
        self.model
            .tape(e, &open)
            .into_iter()
            .filter(move |r| self.row_wanted(r))
    }

    /// Das Band: neueste Anfrage zuerst, darunter jeweils ihre Zeilen.
    pub fn rows(&self) -> impl Iterator<Item = (&Entry, TapeRow)> + '_ {
        let f = self.filter();
        self.model
            .entries
            .iter()
            .rev()
            .filter(move |e| f.wants(e))
            .flat_map(move |e| self.rows_of(e).map(move |r| (e, r)))
    }

    pub fn visible_sessions(&self) -> Vec<&SessionRow> {
        let f = self.filter();
        self.model
            .sessions
            .iter()
            .filter(|r| f.wants_session(r))
            .collect()
    }

    pub fn selected_index(&self) -> usize {
        let rows = self.visible_sessions();
        self.selected
            .as_ref()
            .and_then(|id| rows.iter().position(|r| &r.id == id))
            .unwrap_or(0)
    }

    pub fn fate(&self, d: &Decision) -> Fate {
        let open = |id: &str| self.is_open(id);
        self.model.fate(d, &open)
    }

    /// Entscheidungen für den Reiter Permissions, neueste zuerst. Ohne
    /// `chip` zählen alle – so entstehen die Zahlen auf den Schaltflächen.
    pub fn decisions(&self, chip: Chip) -> Vec<(&Decision, Fate)> {
        let query = self.query.to_lowercase();
        self.model
            .decisions
            .iter()
            .rev()
            .map(|d| (d, self.fate(d)))
            .filter(|(d, fate)| chip.wants(d, *fate))
            .filter(|(d, _)| {
                query.is_empty()
                    || format!("{} {} {} {}", d.session, d.call, d.args, d.rule)
                        .to_lowercase()
                        .contains(&query)
            })
            .collect()
    }

    /// Die Freigabe, auf die `a`/`d` gerade wirken – dieselbe, die die
    /// Leiste oben zeigt.
    pub fn current_approval(&self) -> Option<&ApprovalInfo> {
        if self.tab == Tab::Approvals {
            return self.approvals.get(self.sel_approval);
        }
        // In Permissions: die Anfrage der gewählten Zeile, wenn sie noch wartet.
        if self.tab == Tab::Permissions
            && let Some((d, Fate::Waiting)) = self.decisions(self.chip).get(self.sel_decision)
            && let Some(a) = self
                .approvals
                .iter()
                .find(|a| Some(a.id.as_str()) == d.approval.as_deref())
        {
            return Some(a);
        }
        if self.tab == Tab::Live
            && let Some(session) = &self.focus
            && let Some(a) = self
                .approvals
                .iter()
                .find(|a| a.session.as_deref() == Some(session.as_str()))
        {
            return Some(a);
        }
        self.approvals.first()
    }

    /// Sekunden bis zum Ablauf, lokal weitergezählt seit der letzten Abfrage.
    pub fn expires_in(&self, a: &ApprovalInfo) -> u64 {
        a.expires_in_secs
            .saturating_sub(self.approvals_at.elapsed().as_secs())
    }

    /// Die Regel in Worten, falls die Config sie kennt.
    pub fn rule_text(&self, id: &str) -> Option<&str> {
        self.rules.get(id).map(String::as_str)
    }

    pub fn say(&mut self, text: impl Into<String>, tone: Tone) {
        self.toast = Some(Toast {
            text: text.into(),
            tone,
            at: Instant::now(),
        });
    }

    /// Neue Einträge aus dem Witness. Wer im Band weiter unten liest, soll
    /// seine Stelle behalten: Die Auswahl rückt um die neuen Zeilen mit.
    pub fn ingest(&mut self, new: Vec<Entry>) {
        let before = self.model.entries.len();
        self.model.ingest(new);
        if self.cursor > 0 && self.tab == Tab::Live {
            let f = self.filter();
            let added: usize = self.model.entries[before..]
                .iter()
                .filter(|e| f.wants(e))
                .map(|e| self.rows_of(e).count())
                .sum();
            self.cursor += added;
        }
    }

    /// Ergebnis einer Abfrage der Steuer-API. Liefert `true`, wenn eine
    /// neue Freigabe dabei ist (dann klingelt das Terminal).
    pub fn on_control(
        &mut self,
        approvals: std::result::Result<Vec<ApprovalInfo>, String>,
        status: Option<Value>,
    ) -> bool {
        match approvals {
            Ok(list) => {
                self.link = Link::Up;
                // Ein Ausfall von Presidio soll nicht nur in der Kopfzeile
                // stehen: einmal sagen, wenn er beginnt und wenn er endet.
                let presidio = |s: &Option<Value>| {
                    s.as_ref()
                        .and_then(|s| s["presidio"]["state"].as_str())
                        .map(str::to_owned)
                };
                match (
                    presidio(&self.status).as_deref(),
                    presidio(&status).as_deref(),
                ) {
                    (Some("ready") | Some("starting"), Some("unavailable")) => {
                        let fail_closed = status.as_ref().is_some_and(|s| s["ready"] == false);
                        self.say(
                            if fail_closed {
                                "presidio is down: requests with text to check are rejected until it is back"
                            } else {
                                "presidio is down: requests continue without name detection"
                            },
                            Tone::Bad,
                        );
                    }
                    (Some("unavailable"), Some("ready")) => {
                        self.say("presidio is back", Tone::Ok);
                    }
                    _ => {}
                }
                self.status = status;
                let fresh: Vec<&ApprovalInfo> = list
                    .iter()
                    .filter(|a| !self.known_approvals.contains(&a.id))
                    .collect();
                let ring = !fresh.is_empty();
                if let Some(a) = fresh.first() {
                    let text = format!("{} needs your approval: {}", a.tool, a.preview);
                    self.say(text, Tone::Warn);
                }
                self.known_approvals = list.iter().map(|a| a.id.clone()).collect();
                // Eine Rückfrage, deren Anfrage verschwunden ist, hat sich erledigt.
                if let Mode::Confirm(a) = &self.mode
                    && !self.known_approvals.contains(&a.id)
                {
                    self.mode = Mode::Normal;
                    self.say("that request was decided elsewhere or expired", Tone::Muted);
                }
                self.approvals = list;
                self.approvals_at = Instant::now();
                self.sel_approval = self
                    .sel_approval
                    .min(self.approvals.len().saturating_sub(1));
                ring
            }
            Err(reason) => {
                self.link = Link::Down(reason);
                self.status = None;
                self.approvals.clear();
                self.known_approvals.clear();
                if matches!(self.mode, Mode::Confirm(_)) {
                    self.mode = Mode::Normal;
                }
                false
            }
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(Action::Quit);
        }
        match self.mode.clone() {
            Mode::Help => {
                self.mode = Mode::Normal;
                None
            }
            Mode::Filter => {
                match key.code {
                    KeyCode::Enter => self.mode = Mode::Normal,
                    KeyCode::Esc => {
                        self.query.clear();
                        self.mode = Mode::Normal;
                    }
                    KeyCode::Backspace => {
                        self.query.pop();
                    }
                    KeyCode::Char(c) => self.query.push(c),
                    _ => {}
                }
                self.cursor = 0;
                self.sel_decision = 0;
                None
            }
            Mode::Confirm(a) => {
                self.mode = Mode::Normal;
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => Some(Action::Resolve {
                        id: a.id,
                        approve: true,
                    }),
                    _ => {
                        self.say("not approved – the request is still waiting", Tone::Muted);
                        None
                    }
                }
            }
            Mode::Normal => self.on_normal_key(key.code),
        }
    }

    fn on_normal_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Char('q') => return Some(Action::Quit),
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('/') => self.mode = Mode::Filter,
            KeyCode::Char('f') => {
                // In Live vier Stufen, sonst nur „alles“ und „Auffälliges“.
                self.tape = match (self.tab, self.tape) {
                    (Tab::Live, t) => {
                        let at = TapeFilter::ALL.iter().position(|x| *x == t).unwrap_or(0);
                        TapeFilter::ALL[(at + 1) % TapeFilter::ALL.len()]
                    }
                    (_, TapeFilter::All) => TapeFilter::Alerts,
                    _ => TapeFilter::All,
                };
                self.cursor = 0;
            }
            KeyCode::Esc => {
                if self.tab == Tab::Live && self.focus.take().is_some() {
                    self.cursor = 0;
                    if let Some(tab) = self.back.take() {
                        self.tab = tab;
                    }
                } else if !self.query.is_empty() {
                    self.query.clear();
                }
            }
            KeyCode::Char('1') => self.go(Tab::Overview),
            KeyCode::Char('2') => self.go(Tab::Live),
            KeyCode::Char('3') => self.go(Tab::Approvals),
            KeyCode::Char('4') => self.go(Tab::Permissions),
            KeyCode::Tab => self.cycle(1),
            KeyCode::BackTab => self.cycle(Tab::ALL.len() - 1),
            KeyCode::Enter => {
                let session = match self.tab {
                    Tab::Overview => self
                        .visible_sessions()
                        .get(self.selected_index())
                        .map(|r| r.id.clone()),
                    Tab::Permissions => self
                        .decisions(self.chip)
                        .get(self.sel_decision)
                        .map(|(d, _)| d.session.clone()),
                    _ => None,
                };
                if let Some(id) = session {
                    if self.tab == Tab::Overview {
                        self.selected = Some(id.clone());
                    }
                    self.back = Some(self.tab);
                    self.tab = Tab::Live;
                    self.focus = Some(id);
                    self.cursor = 0;
                }
            }
            KeyCode::Left | KeyCode::Char('h') => self.side(false),
            KeyCode::Right | KeyCode::Char('l') => self.side(true),
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::PageUp => self.step(-10),
            KeyCode::PageDown => self.step(10),
            KeyCode::Home | KeyCode::Char('g') => self.step(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.step(isize::MAX / 2),
            KeyCode::Char('n') => self.jump(true),
            KeyCode::Char('N') => self.jump(false),
            KeyCode::Char('a') => match self.current_approval().cloned() {
                Some(a) => self.mode = Mode::Confirm(Box::new(a)),
                None => self.nothing_waiting(),
            },
            KeyCode::Char('d') => match self.current_approval() {
                Some(a) => {
                    return Some(Action::Resolve {
                        id: a.id.clone(),
                        approve: false,
                    });
                }
                None => self.nothing_waiting(),
            },
            _ => {}
        }
        None
    }

    fn nothing_waiting(&mut self) {
        match &self.link {
            Link::Down(_) => self.say(
                format!(
                    "hedge is not reachable at {} – is `hedge run` running?",
                    self.base
                ),
                Tone::Bad,
            ),
            _ => self.say("nothing is waiting for approval", Tone::Muted),
        }
    }

    fn go(&mut self, tab: Tab) {
        self.tab = tab;
        self.back = None;
        self.cursor = 0;
    }

    fn cycle(&mut self, by: usize) {
        let at = Tab::ALL.iter().position(|t| *t == self.tab).unwrap_or(0);
        self.go(Tab::ALL[(at + by) % Tab::ALL.len()]);
    }

    /// `←`/`→`: in Live die Session wechseln (davor steht „alle“), in
    /// Permissions die Auswahl-Schaltfläche.
    fn side(&mut self, forward: bool) {
        let turn = |at: usize, len: usize| -> usize {
            if forward {
                (at + 1) % len
            } else {
                (at + len - 1) % len
            }
        };
        match self.tab {
            Tab::Live => {
                let ids: Vec<String> = self.model.sessions.iter().map(|r| r.id.clone()).collect();
                let at = match &self.focus {
                    Some(id) => ids.iter().position(|x| x == id).map_or(0, |i| i + 1),
                    None => 0,
                };
                let next = turn(at, ids.len() + 1);
                self.focus = next.checked_sub(1).map(|i| ids[i].clone());
                self.back = None;
                self.cursor = 0;
            }
            Tab::Permissions => {
                let at = Chip::ALL.iter().position(|c| *c == self.chip).unwrap_or(0);
                self.chip = Chip::ALL[turn(at, Chip::ALL.len())];
                self.sel_decision = 0;
            }
            _ => {}
        }
    }

    /// Bewegt die Auswahl der Liste, die gerade zu sehen ist.
    fn step(&mut self, by: isize) {
        let moved = |at: usize, len: usize| -> usize {
            let max = len.saturating_sub(1) as isize;
            (at as isize).saturating_add(by).clamp(0, max.max(0)) as usize
        };
        match self.tab {
            Tab::Live => self.cursor = moved(self.cursor, self.rows().count()),
            Tab::Approvals => self.sel_approval = moved(self.sel_approval, self.approvals.len()),
            Tab::Permissions => {
                self.sel_decision = moved(self.sel_decision, self.decisions(self.chip).len());
            }
            Tab::Overview => {
                let rows = self.visible_sessions();
                let at = moved(self.selected_index(), rows.len());
                self.selected = rows.get(at).map(|r| r.id.clone());
            }
        }
    }

    /// `n`/`N` im Band: zur nächsten Zeile, in der Hedge eingegriffen hat
    /// oder ein Mensch gefragt war – vorwärts heißt: weiter zurück in der Zeit.
    fn jump(&mut self, forward: bool) {
        if self.tab != Tab::Live {
            return;
        }
        let marks: Vec<bool> = self.rows().map(|(_, r)| r.decision || r.approval).collect();
        let hit = if forward {
            (self.cursor + 1..marks.len()).find(|i| marks[*i])
        } else {
            (0..self.cursor.min(marks.len())).rev().find(|i| marks[*i])
        };
        match hit {
            Some(i) => self.cursor = i,
            None => self.say("no further decision in this direction", Tone::Muted),
        }
    }
}

enum Msg {
    Term(Event),
    Control {
        approvals: std::result::Result<Vec<ApprovalInfo>, String>,
        status: Option<Value>,
    },
    Resolved {
        approve: bool,
        result: std::result::Result<Value, String>,
    },
    /// Witness-Einträge eines entfernten Hedge, gelesen über die Steuer-API.
    Witness {
        restarted: bool,
        entries: Vec<Entry>,
    },
    /// Der entfernte Witness ließ sich nicht lesen.
    WitnessError(String),
}

/// Einstieg für `hedge watch`.
pub async fn run(config_path: &Path, remote: Remote) -> Result<i32> {
    if !std::io::stdout().is_terminal() {
        return Err(
            "`hedge watch` needs a terminal – in pipes and logs use `hedge tail -f` instead".into(),
        );
    }
    let is_remote = remote.url.is_some();
    let mut rules = BTreeMap::new();
    let mut remote_key = None;
    let (mut source, base, control) = if is_remote {
        let control = Control::new(config_path, remote)?;
        // Der entfernte Hedge nennt seinen öffentlichen Schlüssel; damit
        // prüft die Ansicht, dass die gelieferte Kette in sich stimmt.
        if let Ok(status) = control.call(reqwest::Method::GET, "/_hedge/status").await {
            remote_key = status["witness"]["public_key"]
                .as_str()
                .and_then(|k| hex::decode(k).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok());
        }
        (None, control.base.clone(), Ok(Arc::new(control)))
    } else {
        let cfg = load_or_hint(config_path)?;
        let key = witness::load_verifying_key(&cfg.witness_key_path()).ok();
        let source = Source::new(&cfg.witness_path(), key);
        let base = format!("http://{}", cfg.server.listen);
        // Regeln in Worten, für Permissions und Approvals.
        if let Ok(policy) = ToolPolicy::from_config(&cfg.tools) {
            rules = policy
                .rules()
                .iter()
                .map(|r| (r.id.clone(), r.reason.clone()))
                .collect();
        }
        let control = Control::new(config_path, remote)
            .map(Arc::new)
            .map_err(|e| e.to_string());
        (Some(source), base, control)
    };

    let model = match &source {
        Some(s) => s.fresh_model(),
        None => Model::new(remote_key),
    };
    let mut app = App::new(model, base, is_remote);
    app.rules = rules;
    if let Some(s) = &mut source {
        app.ingest(s.poll().1);
    }
    if let Err(reason) = &control {
        app.link = Link::Down(reason.clone());
    }
    let theme = Theme::new(Depth::detect());

    let (tx, mut rx) = unbounded_channel::<Msg>();
    let stop = Arc::new(AtomicBool::new(false));
    spawn_key_reader(tx.clone(), stop.clone());

    let mut terminal = ratatui::init();
    let fetching = Arc::new(AtomicBool::new(false));
    // Entfernter Witness: der Stand, bis zu dem gelesen ist. `None` heißt
    // „noch nichts geholt“ – dann beginnt die Ansicht mit den letzten Einträgen.
    let reading = Arc::new(AtomicBool::new(false));
    let remote_at = Arc::new(std::sync::Mutex::new(None::<u64>));
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut ticks: u64 = 0;
    let outcome: Result<()> = loop {
        if let Err(e) = terminal.draw(|f| view::draw(f, &app, &theme, chrono::Local::now())) {
            break Err(e.into());
        }
        tokio::select! {
            Some(msg) = rx.recv() => match msg {
                Msg::Term(Event::Key(key)) if key.kind != KeyEventKind::Release => {
                    match app.on_key(key) {
                        Some(Action::Quit) => break Ok(()),
                        Some(Action::Resolve { id, approve }) => match &control {
                            Ok(c) => resolve(c.clone(), tx.clone(), id, approve),
                            Err(reason) => app.say(reason.clone(), Tone::Bad),
                        },
                        None => {}
                    }
                }
                Msg::Term(_) => {}
                Msg::Control { approvals, status } => {
                    if app.on_control(approvals, status) {
                        bell();
                    }
                }
                Msg::Witness { restarted, entries } => {
                    if restarted {
                        app.model = Model::new(remote_key);
                        app.cursor = 0;
                    }
                    app.remote_error = None;
                    app.ingest(entries);
                }
                Msg::WitnessError(reason) => app.remote_error = Some(reason),
                Msg::Resolved { approve, result } => {
                    match result {
                        Ok(v) => app.say(resolved_text(&v, approve), if approve { Tone::Ok } else { Tone::Bad }),
                        Err(e) => app.say(e, Tone::Bad),
                    }
                    if let Ok(c) = &control {
                        refresh(c.clone(), tx.clone(), fetching.clone());
                    }
                }
            },
            _ = tick.tick() => {
                if let Some(s) = &mut source {
                    let (restarted, entries) = s.poll();
                    if restarted {
                        app.model = s.fresh_model();
                        app.cursor = 0;
                    }
                    app.ingest(entries);
                }
                // Die Steuer-API einmal pro Sekunde, nie zwei Abfragen zugleich.
                if ticks.is_multiple_of(4)
                    && let Ok(c) = &control
                {
                    refresh(c.clone(), tx.clone(), fetching.clone());
                    if is_remote {
                        read_remote(c.clone(), tx.clone(), reading.clone(), remote_at.clone());
                    }
                }
                ticks += 1;
            }
        }
    };
    stop.store(true, Ordering::Relaxed);
    ratatui::restore();
    outcome.map(|()| 0)
}

/// Liest Tasten in einem eigenen Thread – `event::read` blockiert.
fn spawn_key_reader(tx: UnboundedSender<Msg>, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match event::poll(Duration::from_millis(100)) {
                Ok(true) => match event::read() {
                    Ok(ev) => {
                        if tx.send(Msg::Term(ev)).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                Ok(false) => {}
                Err(_) => break,
            }
        }
    });
}

fn refresh(control: Arc<Control>, tx: UnboundedSender<Msg>, fetching: Arc<AtomicBool>) {
    if fetching.swap(true, Ordering::Relaxed) {
        return;
    }
    tokio::spawn(async move {
        let answer = control
            .call(reqwest::Method::GET, "/_hedge/approvals")
            .await
            .map_err(|e| e.to_string());
        let approvals = answer.and_then(|v| {
            serde_json::from_value::<Vec<ApprovalInfo>>(v).map_err(|e| e.to_string())
        });
        let status = if approvals.is_ok() {
            let answer = control
                .call(reqwest::Method::GET, "/_hedge/status")
                .await
                .map_err(|e| e.to_string());
            answer.ok()
        } else {
            None
        };
        fetching.store(false, Ordering::Relaxed);
        let _ = tx.send(Msg::Control { approvals, status });
    });
}

/// So viele Einträge holt die Ansicht beim Start von einem entfernten Hedge.
const REMOTE_HISTORY: u64 = 20_000;

/// Holt neue Witness-Einträge über die Steuer-API. Nie zwei Abrufe zugleich.
fn read_remote(
    control: Arc<Control>,
    tx: UnboundedSender<Msg>,
    reading: Arc<AtomicBool>,
    at: Arc<std::sync::Mutex<Option<u64>>>,
) {
    if reading.swap(true, Ordering::Relaxed) {
        return;
    }
    tokio::spawn(async move {
        let seen = *at.lock().unwrap_or_else(|e| e.into_inner());
        let query = match seen {
            Some(seq) => format!("after={seq}"),
            None => format!("last={REMOTE_HISTORY}"),
        };
        let mut query = query;
        let mut seen = seen;
        // Bis zum Kopf der Kette weiterlesen – ein Abruf liefert höchstens
        // einige Megabyte, der erste Stand kann mehrere brauchen.
        loop {
            let (entries, last, head) = match control.witness(&query).await {
                Ok(chunk) => chunk,
                Err(e) => {
                    let _ = tx.send(Msg::WitnessError(e.to_string()));
                    break;
                }
            };
            // Der Stand fällt zurück: Dort läuft jetzt eine andere Kette.
            let restarted = seen.is_some_and(|s| last < s);
            let next = if restarted { None } else { Some(last) };
            *at.lock().unwrap_or_else(|e| e.into_inner()) = next;
            let more = !restarted && last < head && seen != next;
            // Auch ein leeres Stück ist eine Nachricht: Der Witness ist lesbar.
            let _ = tx.send(Msg::Witness { restarted, entries });
            if !more {
                break;
            }
            seen = next;
            query = format!("after={last}");
        }
        reading.store(false, Ordering::Relaxed);
    });
}

fn resolve(control: Arc<Control>, tx: UnboundedSender<Msg>, id: String, approve: bool) {
    tokio::spawn(async move {
        let verdict = if approve { "approve" } else { "deny" };
        let result = control
            .call(
                reqwest::Method::POST,
                &format!("/_hedge/approvals/{id}/{verdict}"),
            )
            .await
            .map_err(|e| e.to_string());
        let _ = tx.send(Msg::Resolved { approve, result });
    });
}

/// Was nach einer Entscheidung zu tun bleibt – im Gespräch muss der Mensch
/// dem Agent noch sagen, dass es weitergeht.
fn resolved_text(v: &Value, approve: bool) -> String {
    let tool = v["resolved"]["tool"].as_str().unwrap_or("tool call");
    let chat = v["resolved"]["kind"] == "chat";
    match (approve, chat) {
        (true, true) => format!(
            "✓ approved {tool} – now tell the agent to continue; this exact call passes once"
        ),
        (true, false) => format!("✓ approved {tool} – the agent continues"),
        (false, _) => format!("✗ rejected {tool} – the model is told it was not executed"),
    }
}

fn bell() {
    let mut out = std::io::stdout();
    let _ = out.write_all(b"\x07");
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::model::tests::{chain, request, tool};
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn approval(id: &str, session: &str) -> ApprovalInfo {
        ApprovalInfo {
            id: id.into(),
            created: "2026-11-10T12:00:00.000Z".into(),
            expires_in_secs: 300,
            upstream: "anthropic".into(),
            client: None,
            session: Some(session.into()),
            model: Some("claude-sonnet-4-5".into()),
            tool: "Bash".into(),
            preview: "git push --force origin main".into(),
            rule: "HEDGE-SHELL-003".into(),
            reason: "force push rewrites remote history".into(),
            kind: "chat".into(),
        }
    }

    fn app_of(records: Vec<crate::witness::Record>) -> App {
        let (_dir, entries, key) = chain(records);
        let mut app = App::new(
            Model::new(Some(key)),
            "http://127.0.0.1:18765".into(),
            false,
        );
        app.ingest(entries);
        app
    }

    fn app_with(sessions: &[&str]) -> App {
        app_of(sessions.iter().map(|s| request(s)).collect())
    }

    /// Eine Session mit einem gestoppten, einem markierten und einem
    /// angehaltenen Aufruf, davor und danach je eine ruhige Anfrage.
    fn busy() -> App {
        let mut deny = request("bbbb2222");
        deny.tools = vec![tool("Read", "deny", Some("HEDGE-CRED-001"))];
        let mut hold = request("bbbb2222");
        hold.tools = vec![
            tool("Bash", "flag", Some("HEDGE-EXFIL-001")),
            tool("Bash", "held", Some("HEDGE-SHELL-003")),
        ];
        app_of(vec![
            request("aaaa1111"),
            deny,
            request("bbbb2222"),
            hold,
            request("aaaa1111"),
        ])
    }

    #[test]
    fn selection_follows_the_session_not_the_position() {
        let names = ["aaaa1111", "bbbb2222", "cccc3333", "dddd4444"];
        let (_dir, mut entries, key_) = chain(names.iter().map(|s| request(s)).collect());
        let later = entries.split_off(3);
        let mut app = App::new(Model::new(Some(key_)), "http://x".into(), false);
        app.ingest(entries);
        assert_eq!(app.selected_index(), 0);
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected.as_deref(), Some("bbbb2222"));

        // Eine neue Session rückt nach oben; die Auswahl bleibt bei bbbb2222.
        assert_eq!(app.selected_index(), 1);
        app.ingest(later);
        assert_eq!(app.model.sessions[0].id, "dddd4444");
        assert_eq!(app.selected_index(), 2);

        app.on_key(key(KeyCode::Char('G')));
        assert_eq!(app.selected.as_deref(), Some("aaaa1111"));
        app.on_key(key(KeyCode::Home));
        assert_eq!(app.selected.as_deref(), Some("dddd4444"));
    }

    #[test]
    fn enter_opens_a_session_in_live_and_escape_leads_back() {
        let mut app = app_with(&["aaaa1111", "bbbb2222"]);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.tab, Tab::Live);
        assert_eq!(app.focus.as_deref(), Some("bbbb2222"));
        assert_eq!(app.rows().count(), 1);

        app.on_key(key(KeyCode::Esc));
        assert_eq!((app.tab, app.focus.clone()), (Tab::Overview, None));

        // Über den Reiter geöffnet, bleibt esc in Live und zeigt wieder alles.
        app.on_key(key(KeyCode::Char('2')));
        app.on_key(key(KeyCode::Right));
        assert_eq!(app.focus.as_deref(), Some("bbbb2222"));
        app.on_key(key(KeyCode::Esc));
        assert_eq!((app.tab, app.focus.clone()), (Tab::Live, None));
        assert_eq!(app.rows().count(), 2);
    }

    #[test]
    fn left_and_right_walk_through_all_and_each_session() {
        let mut app = app_with(&["aaaa1111", "bbbb2222"]);
        app.on_key(key(KeyCode::Char('2')));
        let mut seen = Vec::new();
        for _ in 0..3 {
            app.on_key(key(KeyCode::Right));
            seen.push(app.focus.clone());
        }
        assert_eq!(
            seen,
            vec![Some("bbbb2222".into()), Some("aaaa1111".into()), None]
        );
        app.on_key(key(KeyCode::Left));
        assert_eq!(app.focus.as_deref(), Some("aaaa1111"));
    }

    #[test]
    fn approving_needs_a_second_key_and_is_bound_to_the_request_shown() {
        let mut app = app_with(&["aaaa1111"]);
        app.on_control(Ok(vec![approval("apr-1", "aaaa1111")]), None);

        assert_eq!(app.on_key(key(KeyCode::Char('a'))), None);
        assert!(matches!(&app.mode, Mode::Confirm(a) if a.id == "apr-1"));

        // Inzwischen kommt eine zweite Anfrage dazu und steht vorn.
        app.on_control(
            Ok(vec![
                approval("apr-2", "aaaa1111"),
                approval("apr-1", "aaaa1111"),
            ]),
            None,
        );
        assert_eq!(
            app.on_key(key(KeyCode::Char('y'))),
            Some(Action::Resolve {
                id: "apr-1".into(),
                approve: true
            })
        );
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn any_other_key_cancels_an_approval() {
        let mut app = app_with(&["aaaa1111"]);
        app.on_control(Ok(vec![approval("apr-1", "aaaa1111")]), None);
        app.on_key(key(KeyCode::Char('a')));
        assert_eq!(app.on_key(key(KeyCode::Enter)), None);
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn a_confirmation_ends_when_its_request_is_gone() {
        let mut app = app_with(&["aaaa1111"]);
        app.on_control(Ok(vec![approval("apr-1", "aaaa1111")]), None);
        app.on_key(key(KeyCode::Char('a')));
        app.on_control(Ok(vec![]), None);
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.on_key(key(KeyCode::Char('y'))), None);
    }

    #[test]
    fn deny_acts_at_once_and_only_when_something_waits() {
        let mut app = app_with(&["aaaa1111"]);
        assert_eq!(app.on_key(key(KeyCode::Char('d'))), None);
        assert!(app.toast.is_some());

        app.on_control(Ok(vec![approval("apr-1", "aaaa1111")]), None);
        assert_eq!(
            app.on_key(key(KeyCode::Char('d'))),
            Some(Action::Resolve {
                id: "apr-1".into(),
                approve: false
            })
        );
    }

    #[test]
    fn the_bar_shows_the_open_sessions_request_first() {
        let mut app = app_with(&["aaaa1111", "bbbb2222"]);
        app.on_control(
            Ok(vec![
                approval("apr-1", "aaaa1111"),
                approval("apr-2", "bbbb2222"),
            ]),
            None,
        );
        assert_eq!(app.current_approval().map(|a| a.id.as_str()), Some("apr-1"));

        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.focus.as_deref(), Some("bbbb2222"));
        assert_eq!(app.current_approval().map(|a| a.id.as_str()), Some("apr-2"));

        app.on_key(key(KeyCode::Char('3')));
        assert_eq!(app.current_approval().map(|a| a.id.as_str()), Some("apr-1"));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.current_approval().map(|a| a.id.as_str()), Some("apr-2"));
    }

    #[test]
    fn only_new_requests_ring_the_bell() {
        let mut app = app_with(&["aaaa1111"]);
        assert!(app.on_control(Ok(vec![approval("apr-1", "aaaa1111")]), None));
        assert!(!app.on_control(Ok(vec![approval("apr-1", "aaaa1111")]), None));
        assert!(app.on_control(
            Ok(vec![
                approval("apr-1", "aaaa1111"),
                approval("apr-2", "aaaa1111")
            ]),
            None
        ));
        assert!(!app.on_control(Err("connection refused".into()), None));
        assert_eq!(app.link, Link::Down("connection refused".into()));
        assert!(app.approvals.is_empty());
    }

    #[test]
    fn filter_typing_narrows_sessions_and_escape_clears() {
        let mut app = app_with(&["aaaa1111", "bbbb2222"]);
        app.on_key(key(KeyCode::Char('/')));
        for c in "BBB".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        // `q` gehört jetzt zum Suchtext und beendet nichts.
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), None);
        app.on_key(key(KeyCode::Backspace));
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.visible_sessions().len(), 1);
        assert_eq!(app.visible_sessions()[0].id, "bbbb2222");

        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.visible_sessions().len(), 2);
    }

    #[test]
    fn the_tape_cursor_keeps_its_row_when_new_entries_arrive() {
        let mut held = request("aaaa1111");
        held.tools = vec![
            tool("Bash", "held", Some("HEDGE-SHELL-003")),
            tool("Bash", "flag", Some("HEDGE-EXFIL-001")),
        ];
        let (_dir, mut entries, key_) = chain(vec![
            request("aaaa1111"),
            request("aaaa1111"),
            request("aaaa1111"),
            held,
        ]);
        let more = entries.split_off(3);
        let mut app = App::new(Model::new(Some(key_)), "http://x".into(), false);
        app.ingest(entries);
        app.on_key(key(KeyCode::Char('2')));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.cursor, 1);

        app.ingest(more);
        assert_eq!(
            app.cursor, 4,
            "one request with two tool calls came in above"
        );

        app.on_key(key(KeyCode::Home));
        assert_eq!(app.cursor, 0);
        app.on_key(key(KeyCode::End));
        assert_eq!(app.cursor, 5);
    }

    #[test]
    fn f_steps_through_the_tape_filters_in_live_and_toggles_elsewhere() {
        let mut app = busy();
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.tape, TapeFilter::Alerts);
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.tape, TapeFilter::All);

        app.on_key(key(KeyCode::Char('2')));
        // 5 Anfragen + 3 Tool-Aufrufe.
        assert_eq!(app.rows().count(), 8);
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.rows().count(), 5, "two requests with all their rows");
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.tape, TapeFilter::Decisions);
        assert_eq!(app.rows().count(), 3);
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.tape, TapeFilter::Approvals);
        assert_eq!(app.rows().count(), 1);
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.tape, TapeFilter::All);
    }

    #[test]
    fn n_jumps_from_decision_to_decision() {
        let mut app = busy();
        app.on_key(key(KeyCode::Char('2')));
        let evt = |app: &App| app.rows().nth(app.cursor).map(|(_, r)| r.evt);
        assert_eq!(evt(&app), Some("MODEL"));
        app.on_key(key(KeyCode::Char('n')));
        assert_eq!(evt(&app), Some("FLAG"));
        app.on_key(key(KeyCode::Char('n')));
        assert_eq!(evt(&app), Some("HOLD"));
        app.on_key(key(KeyCode::Char('n')));
        assert_eq!(evt(&app), Some("DENY"));
        app.on_key(key(KeyCode::Char('n')));
        assert_eq!(evt(&app), Some("DENY"), "stays on the last one");
        app.on_key(key(KeyCode::Char('N')));
        assert_eq!(evt(&app), Some("HOLD"));
    }

    #[test]
    fn permissions_list_every_decision_with_what_came_of_it() {
        let mut app = busy();
        app.on_key(key(KeyCode::Char('4')));
        let fates = |app: &App, chip: Chip| -> Vec<(String, Fate)> {
            app.decisions(chip)
                .into_iter()
                .map(|(d, f)| (format!("{} {}", d.ruling.label(), d.rule), f))
                .collect()
        };
        // Neueste zuerst; ohne Antwort und ohne offene Anfrage: unbeantwortet.
        assert_eq!(
            fates(&app, Chip::All),
            vec![
                ("HOLD HEDGE-SHELL-003".to_owned(), Fate::Unanswered),
                ("FLAG HEDGE-EXFIL-001".to_owned(), Fate::Flagged),
                ("DENY HEDGE-CRED-001".to_owned(), Fate::Blocked),
            ]
        );

        app.on_control(Ok(vec![approval("apr-1", "bbbb2222")]), None);
        assert_eq!(fates(&app, Chip::Waiting).len(), 1);
        assert_eq!(fates(&app, Chip::Held).len(), 1);
        assert_eq!(fates(&app, Chip::Expired).len(), 0);

        // → wandert über die Schaltflächen, enter öffnet die Session.
        app.on_key(key(KeyCode::Right));
        assert_eq!(app.chip, Chip::Waiting);
        app.on_key(key(KeyCode::Left));
        app.on_key(key(KeyCode::Left));
        assert_eq!(app.chip, Chip::Expired);
        app.on_key(key(KeyCode::Right));
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.sel_decision, 2);
        app.on_key(key(KeyCode::Enter));
        assert_eq!(
            (app.tab, app.focus.as_deref()),
            (Tab::Live, Some("bbbb2222"))
        );
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.tab, Tab::Permissions);
    }

    #[test]
    fn tabs_cycle_and_quit_keys_work() {
        let mut app = app_with(&["aaaa1111"]);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.tab, Tab::Live);
        app.on_key(key(KeyCode::BackTab));
        assert_eq!(app.tab, Tab::Overview);
        app.on_key(key(KeyCode::BackTab));
        assert_eq!(app.tab, Tab::Permissions);
        app.on_key(key(KeyCode::Char('3')));
        assert_eq!(app.tab, Tab::Approvals);
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), Some(Action::Quit));
        assert_eq!(
            app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Action::Quit)
        );
    }
}
