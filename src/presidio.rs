//! Presidio: findet, was kein festes Format hat – Namen, Telefonnummern.
//!
//! Die Regex-Detektoren in `detect` finden, was ein festes Format hat. Für
//! alles andere (ein Name in einem Stacktrace) braucht es ein Modell. Hedge
//! ruft dafür den Presidio-Analyzer per HTTP auf.
//!
//! Was dieses Modul leistet:
//!
//! - **Scope**: Nur die Teile einer Anfrage gehen an Presidio, die es sollen
//!   (Standard: was der Mensch tippt und was Tools liefern, nicht der
//!   System-Prompt des Agents und nie Bilddaten).
//! - **Sprache**: Pro Text wird eine der konfigurierten Sprachen gewählt und
//!   genau einmal analysiert (`lang`).
//! - **Cache**: Ein Agent schickt seine ganze Historie mit jeder Anfrage
//!   erneut; analysiert wird jedes Textstück nur einmal. Im Cache stehen
//!   Hashes und Offsets, nie Text.
//! - **Zustand**: `starting → ready ⇄ unavailable`. Ob Presidio bereit ist,
//!   entscheidet ein Testsatz pro Sprache, nicht eine Versionsnummer. Fällt
//!   Presidio aus, wartet keine Anfrage mehr auf einen Timeout.
//! - **Zeitlimit**: Eine Anfrage wartet höchstens `budget_ms` auf Presidio.
//!   Was bis dahin nicht fertig ist, läuft im Hintergrund weiter und liegt
//!   für die nächste Anfrage im Cache.
//!
//! Den Container, in dem Presidio läuft, verwaltet `sidecar`.

pub mod lang;
pub mod sidecar;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::config::{Presidio as PresidioCfg, PresidioScope};
use crate::detect::{Finding, Severity};
use crate::inspect::Part;

/// So viele Textstücke hält eine Cache-Generation. Ist sie voll, wird sie
/// zur alten Generation; die davor fällt weg.
const CACHE_GENERATION: usize = 20_000;
/// Nach so vielen fehlgeschlagenen Scans in Folge gilt Presidio als weg.
const FAILURES_TO_OPEN: u32 = 2;
/// So lange darf Presidio nach dem Start von Hedge brauchen, bis es als
/// ausgefallen gilt (Modelle laden dauert).
const BOOT_GRACE: Duration = Duration::from_secs(90);
const BOOT_GRACE_MANAGED: Duration = Duration::from_secs(240);
/// Gelingt echter Verkehr, braucht es so lange keine Probe.
const IDLE_BEFORE_PROBE: Duration = Duration::from_secs(30);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const CANARY_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Noch keine bestätigte Antwort seit dem Start (Modelle laden).
    Starting,
    /// Erreichbar und der Testsatz jeder Sprache wurde erkannt.
    Ready,
    /// Antwortet nicht oder kann nicht, was die Config verlangt.
    Unavailable,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Starting => "starting",
            State::Ready => "ready",
            State::Unavailable => "unavailable",
        }
    }
}

/// Ein Zustandswechsel, der bezeugt werden soll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub to: State,
    pub detail: String,
}

/// Was nicht stimmt und – wenn Hedge es weiß – was dagegen hilft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub reason: String,
    pub hint: Option<String>,
}

impl Problem {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// Was ein hedge-presidio über sich sagt (`GET /info`). Ein Presidio aus
/// anderer Quelle hat diesen Endpunkt nicht; dann fehlt die Angabe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub presidio: String,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub models: Vec<String>,
}

struct Health {
    state: State,
    since: DateTime<Utc>,
    reason: Option<String>,
    hint: Option<String>,
    /// Fehlgeschlagene Scans oder Proben in Folge.
    failures: u32,
    last_ok: Option<Instant>,
    /// Wie oft in Folge die Verbindung wieder verloren ging (für die Pause
    /// zwischen den Proben).
    relapses: u32,
    ready_since: Option<Instant>,
    server: Option<ServerInfo>,
    /// Der eigene Container wurde gerade gestartet und lädt Modelle.
    warming: bool,
    /// Was die Container-Verwaltung zuletzt zu beanstanden hatte. Solange
    /// das gilt, erklärt es den Ausfall besser als "antwortet nicht".
    sidecar: Option<Problem>,
}

impl Health {
    /// Grund und Abhilfe, wie ein Mensch sie lesen soll.
    fn why(&self) -> (Option<String>, Option<String>) {
        if self.state == State::Ready {
            return (None, None);
        }
        match &self.sidecar {
            Some(p) => (Some(p.reason.clone()), p.hint.clone()),
            None => (self.reason.clone(), self.hint.clone()),
        }
    }
}

#[derive(Default)]
struct Cache {
    young: HashMap<[u8; 32], Arc<[Finding]>>,
    old: HashMap<[u8; 32], Arc<[Finding]>>,
}

impl Cache {
    fn get(&mut self, key: &[u8; 32]) -> Option<Arc<[Finding]>> {
        if let Some(v) = self.young.get(key) {
            return Some(v.clone());
        }
        let v = self.old.remove(key)?;
        self.put(*key, v.clone());
        Some(v)
    }

    fn put(&mut self, key: [u8; 32], value: Arc<[Finding]>) {
        if self.young.len() >= CACHE_GENERATION {
            self.old = std::mem::take(&mut self.young);
        }
        self.young.insert(key, value);
    }

    fn len(&self) -> usize {
        self.young.len() + self.old.len()
    }
}

#[derive(Default)]
struct Counters {
    analyzed: AtomicU64,
    cached: AtomicU64,
    failed: AtomicU64,
    unscanned: AtomicU64,
}

/// Warum eine Anfrage nicht (vollständig) von Presidio geprüft wurde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gap {
    /// Presidio ist nicht bereit; es wurde nichts gesendet.
    NotReady { state: State, reason: String },
    /// Presidio hat bei mindestens einem Text einen Fehler geliefert.
    Failed { reason: String },
    /// Das Zeitlimit lief ab, bevor alle Texte geprüft waren.
    Timeout { pending: usize, budget_ms: u64 },
}

impl Gap {
    /// Das Flag, das am Witness-Eintrag der Anfrage steht.
    pub fn flag(&self) -> &'static str {
        match self {
            Gap::NotReady { .. } | Gap::Failed { .. } => "presidio_unavailable",
            Gap::Timeout { .. } => "presidio_timeout",
        }
    }

    pub fn reason(&self) -> String {
        match self {
            Gap::NotReady { state, reason } => format!("presidio is {}: {reason}", state.as_str()),
            Gap::Failed { reason } => format!("presidio failed: {reason}"),
            Gap::Timeout { pending, budget_ms } => format!(
                "presidio was still analysing {pending} text(s) after {} s; it finishes in the background",
                budget_ms / 1000
            ),
        }
    }
}

/// Ergebnis der Presidio-Prüfung einer Anfrage.
#[derive(Debug, Default)]
pub struct Scan {
    /// Funde pro JSON-Pfad, mit Byte-Offsets im jeweiligen Text.
    pub findings: HashMap<String, Vec<Finding>>,
    pub gap: Option<Gap>,
    pub analyzed: u64,
    pub cached: u64,
    pub failed: u64,
    /// Dauer jedes einzelnen Aufrufs.
    pub durations_ms: Vec<u64>,
}

/// Ein Treffer, wie `hedge presidio test` ihn zeigt.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TestHit {
    pub entity: String,
    pub kind: &'static str,
    pub severity: &'static str,
    /// Byte-Offsets im Text.
    pub start: usize,
    pub end: usize,
    pub score: f64,
    /// Würde Hedge den Treffer melden?
    pub reported: bool,
    /// Wenn nicht: warum (`below_threshold`, `not_a_name`, `single_word`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TestReport {
    pub language: String,
    pub threshold: f64,
    pub duration_ms: u64,
    pub hits: Vec<TestHit>,
}

#[derive(Debug, Deserialize)]
struct Hit {
    entity_type: String,
    start: usize,
    end: usize,
    #[serde(default)]
    score: f64,
}

pub struct Presidio {
    cfg: PresidioCfg,
    base: String,
    languages: Vec<String>,
    scope: HashSet<PresidioScope>,
    picker: lang::Picker,
    client: reqwest::Client,
    cache: Mutex<Cache>,
    health: Mutex<Health>,
    transitions: Mutex<Vec<Transition>>,
    counters: Counters,
    born: Instant,
}

/// Presidio-Typen auf stabile `kind`-Bezeichner und Severity abbilden.
pub fn kind_of(entity: &str) -> (&'static str, Severity) {
    match entity {
        "PERSON" => ("person_name", Severity::Medium),
        "PHONE_NUMBER" => ("phone_number", Severity::Medium),
        "EMAIL_ADDRESS" => ("email", Severity::Medium),
        "LOCATION" => ("location", Severity::Low),
        "CREDIT_CARD" => ("credit_card", Severity::High),
        "IBAN_CODE" => ("iban", Severity::High),
        "IP_ADDRESS" => ("ip_address", Severity::Low),
        "US_SSN" => ("us_ssn", Severity::High),
        "US_PASSPORT" => ("us_passport", Severity::High),
        "UK_NHS" => ("uk_nhs", Severity::High),
        "MEDICAL_LICENSE" => ("medical_license", Severity::High),
        "DATE_TIME" => ("date_time", Severity::Low),
        "NRP" => ("nationality_religion_politics", Severity::Medium),
        "URL" => ("url", Severity::Low),
        "CRYPTO" => ("crypto_wallet", Severity::Medium),
        "DE_TAX_ID" => ("de_tax_id", Severity::High),
        "DE_ID_CARD" => ("de_id_card", Severity::High),
        "DE_PASSPORT" => ("de_passport", Severity::High),
        "DE_SOCIAL_SECURITY" => ("de_social_security", Severity::High),
        "DE_HEALTH_INSURANCE" => ("de_health_insurance", Severity::High),
        "DE_FUEHRERSCHEIN" => ("de_driving_licence", Severity::High),
        _ => ("pii_other", Severity::Medium),
    }
}

/// Was Hedge von einem Namensfund des Sprachmodells hält.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameVerdict {
    /// Sieht aus wie ein Name.
    Name,
    /// Kann kein Name sein: Bezeichner, Pfad, Kleinschreibung.
    NotAName,
    /// Ein einzelnes Wort ohne Anrede davor.
    SingleWord,
}

/// Wörter, die in Namen klein stehen dürfen.
const PARTICLES: &[&str] = &[
    "von", "van", "de", "der", "den", "del", "della", "la", "le", "da", "di", "du", "dos", "das",
    "do", "bin", "al", "zu", "zur", "ten", "ter", "af", "av", "y",
];
/// Namensanfänge mit Großbuchstaben im Wort (McDonald, DeVries).
const INNER_CAPS: &[&str] = &[
    "Mc", "Mac", "De", "Di", "Du", "La", "Le", "Van", "Fitz", "O'", "D'",
];
/// Anreden, nach denen ein einzelnes Wort ein Name ist.
const TITLES: &[&str] = &[
    "herr", "herrn", "frau", "dr", "prof", "mr", "mrs", "ms", "miss", "sir", "kollege", "kollegin",
    "kollegen",
];

/// Was in jeder Agent-Session vorkommt, wie ein Name geschrieben ist und
/// keiner ist. Eigene Begriffe gehören in `[allow] values`.
const NOT_PEOPLE: &[&str] = &["claude code", "claude", "anthropic", "openai", "codex"];

/// Ein Sprachmodell hält in Code fast jeden großgeschriebenen Bezeichner
/// für einen Namen (`Mutex`, `t.bold`, `worker-3 Retrying`). Diese Prüfung
/// sortiert aus, was nach seiner Schreibung kein Name sein kann, und
/// verlangt für einzelne Wörter eine Anrede davor.
pub fn judge_name(text: &str, start: usize, end: usize, single_names: bool) -> NameVerdict {
    let name = &text[start..end];
    if name.chars().count() > 60
        || name.chars().any(|c| {
            c.is_ascii_digit() || c.is_control() || "_:;/\\(){}[]<>=@#$%&*+|~^\"`!?,".contains(c)
        })
    {
        return NameVerdict::NotAName;
    }
    let words: Vec<&str> = name.split_whitespace().collect();
    if words.is_empty() || words.len() > 5 || NOT_PEOPLE.contains(&name.to_lowercase().as_str()) {
        return NameVerdict::NotAName;
    }
    let mut capitalized = 0;
    for word in &words {
        let core = word.trim_end_matches('.');
        // Ein Punkt im Wort ist ein Pfad oder ein Methodenaufruf.
        if core.is_empty() || core.contains('.') {
            return NameVerdict::NotAName;
        }
        if PARTICLES.contains(&core) {
            continue;
        }
        let mut parts = core.split(['-', '\'', '’']).filter(|p| !p.is_empty());
        let Some(first) = parts.next() else {
            return NameVerdict::NotAName;
        };
        if !first.chars().next().is_some_and(char::is_uppercase)
            || !core.chars().all(|c| c.is_alphabetic() || "-'’".contains(c))
        {
            return NameVerdict::NotAName;
        }
        // CamelCase ist ein Typname, VERSALIEN eine Konstante.
        let chars: Vec<char> = core.chars().collect();
        let inner_caps = chars
            .windows(2)
            .any(|w| w[0].is_lowercase() && w[1].is_uppercase());
        if inner_caps && !INNER_CAPS.iter().any(|p| core.starts_with(p)) {
            return NameVerdict::NotAName;
        }
        if chars.len() > 3 && chars.iter().all(|c| !c.is_lowercase()) {
            return NameVerdict::NotAName;
        }
        capitalized += 1;
    }
    if capitalized == 0 {
        return NameVerdict::NotAName;
    }
    if capitalized >= 2 || single_names {
        return NameVerdict::Name;
    }
    // Ein einzelnes Wort zählt mit Anrede davor: "Frau Wagner", "Dr. Hoffmann".
    let before = text[..start].trim_end();
    let last = before
        .rsplit(|c: char| c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_lowercase();
    if TITLES.contains(&last.as_str()) {
        NameVerdict::Name
    } else {
        NameVerdict::SingleWord
    }
}

fn part_scope(part: Part) -> PresidioScope {
    match part {
        Part::System => PresidioScope::System,
        Part::Tools => PresidioScope::Tools,
        Part::User => PresidioScope::User,
        Part::Assistant => PresidioScope::Assistant,
        Part::ToolUse => PresidioScope::ToolUse,
        Part::ToolResult => PresidioScope::ToolResult,
    }
}

fn now_rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Die Ursache eines reqwest-Fehlers in Worten, die ein Mensch versteht.
fn explain(e: &reqwest::Error, timeout: Duration) -> String {
    if e.is_timeout() {
        return format!("no answer within {} ms", timeout.as_millis());
    }
    let mut source: &dyn std::error::Error = e;
    while let Some(next) = source.source() {
        source = next;
    }
    let text = source.to_string();
    if e.is_connect() {
        format!("cannot connect ({text})")
    } else {
        text
    }
}

impl Presidio {
    pub fn new(cfg: &PresidioCfg) -> reqwest::Result<Self> {
        let languages = cfg.languages();
        Ok(Self {
            base: cfg.url.trim_end_matches('/').to_owned(),
            picker: lang::Picker::new(&languages),
            languages,
            scope: cfg.scope.iter().copied().collect(),
            client: reqwest::Client::builder()
                // Presidio liegt lokal oder im internen Netz: nie über einen
                // Proxy aus der Umgebung, sonst gingen Prompts dorthin.
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .build()?,
            cache: Mutex::new(Cache::default()),
            health: Mutex::new(Health {
                state: State::Starting,
                since: Utc::now(),
                reason: None,
                hint: None,
                failures: 0,
                last_ok: None,
                relapses: 0,
                ready_since: None,
                server: None,
                warming: false,
                sidecar: None,
            }),
            transitions: Mutex::new(Vec::new()),
            counters: Counters::default(),
            born: Instant::now(),
            cfg: cfg.clone(),
        })
    }

    pub fn cfg(&self) -> &PresidioCfg {
        &self.cfg
    }

    pub fn languages(&self) -> &[String] {
        &self.languages
    }

    fn health(&self) -> std::sync::MutexGuard<'_, Health> {
        self.health.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn state(&self) -> State {
        self.health().state
    }

    /// Soll der String an diesem Platz der Anfrage analysiert werden?
    pub fn wants(&self, part: Part, path: &str, text: &str) -> bool {
        self.scope.contains(&part_scope(part))
            && text
                .chars()
                .nth(self.cfg.min_chars.saturating_sub(1))
                .is_some()
            && !text.trim().is_empty()
            && !self.cfg.skip_paths.iter().any(|p| {
                path == p
                    || path
                        .strip_prefix(p.as_str())
                        .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
            })
    }

    // ---------- Zustand ----------

    fn boot_grace(&self) -> Duration {
        if self.cfg.managed {
            BOOT_GRACE_MANAGED
        } else {
            BOOT_GRACE
        }
    }

    fn mark_ready(&self, server: Option<ServerInfo>) {
        let mut h = self.health();
        h.failures = 0;
        h.last_ok = Some(Instant::now());
        if server.is_some() {
            h.server = server;
        }
        if h.state == State::Ready {
            return;
        }
        let was = h.state;
        let waited = (Utc::now() - h.since).num_seconds().max(0);
        h.state = State::Ready;
        h.since = Utc::now();
        h.ready_since = Some(Instant::now());
        h.reason = None;
        h.hint = None;
        h.sidecar = None;
        h.warming = false;
        let how = match was {
            State::Starting => format!("ready {waited} s after start"),
            _ => format!("back after {waited} s"),
        };
        let version = h
            .server
            .as_ref()
            .filter(|s| !s.presidio.is_empty())
            .map(|s| format!(" · presidio {}", s.presidio))
            .unwrap_or_default();
        let detail = format!(
            "{} · {}{version} · {how}",
            self.languages.join(", "),
            self.base
        );
        drop(h);
        self.push(State::Ready, detail);
    }

    fn mark_down(&self, problem: Problem) {
        self.go_down(problem, false);
    }

    /// `at_once`: nicht auf das Ende der Anlaufzeit warten. Für Gründe, die
    /// sich nicht von selbst erledigen (die Container-Laufzeit steht).
    fn go_down(&self, problem: Problem, at_once: bool) {
        let mut h = self.health();
        // Beim Start darf Presidio brauchen, ohne als Ausfall zu gelten.
        let waiting =
            h.state == State::Starting && !at_once && self.born.elapsed() < self.boot_grace();
        // Lädt der gerade gestartete Container noch seine Modelle, ist das
        // die bessere Auskunft als "antwortet nicht".
        if !(waiting && h.warming) {
            h.reason = Some(problem.reason.clone());
            h.hint = problem.hint.clone();
        }
        match h.state {
            State::Unavailable => {}
            State::Starting if waiting => {}
            was => {
                if was == State::Ready {
                    // Hielt die Verbindung nur kurz, wird seltener geprobt.
                    let brief = h
                        .ready_since
                        .is_some_and(|t| t.elapsed() < Duration::from_secs(60));
                    h.relapses = if brief { h.relapses + 1 } else { 0 };
                }
                h.state = State::Unavailable;
                h.since = Utc::now();
                h.ready_since = None;
                h.warming = false;
                let reason = h.why().0.unwrap_or(problem.reason);
                drop(h);
                self.push(
                    State::Unavailable,
                    format!(
                        "{reason} · on_unavailable={}",
                        self.cfg.on_unavailable.as_str()
                    ),
                );
            }
        }
    }

    fn push(&self, to: State, detail: String) {
        self.transitions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Transition { to, detail });
    }

    /// Zustandswechsel seit dem letzten Aufruf. Wer sie abholt, bezeugt sie.
    pub fn take_transitions(&self) -> Vec<Transition> {
        std::mem::take(&mut *self.transitions.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Der Container wurde gerade (neu) gestartet und lädt seine Modelle.
    pub fn note_starting(&self, reason: impl Into<String>) {
        let mut h = self.health();
        h.sidecar = None;
        if h.state != State::Ready {
            h.reason = Some(reason.into());
            h.hint = None;
            h.warming = true;
        }
    }

    /// Die Container-Verwaltung hat nichts zu beanstanden.
    pub fn note_sidecar_ok(&self) {
        self.health().sidecar = None;
    }

    /// Die Container-Verwaltung kann den Container nicht starten (Laufzeit
    /// steht, Image fehlt). Das erledigt sich nicht von selbst: Presidio
    /// gilt sofort als nicht verfügbar, mit diesem Grund und dieser Abhilfe.
    pub fn note_sidecar_problem(&self, problem: Problem) {
        {
            let mut h = self.health();
            if h.state == State::Ready {
                return;
            }
            h.sidecar = Some(problem.clone());
        }
        self.go_down(problem, true);
    }

    /// Wie lange bis zur nächsten Probe.
    pub fn next_probe_in(&self) -> Duration {
        let h = self.health();
        match h.state {
            State::Starting => Duration::from_secs(1),
            State::Ready => Duration::from_secs(10),
            State::Unavailable => Duration::from_secs((3u64 << h.relapses.min(4)).min(60)),
        }
    }

    /// Prüft, ob Presidio da ist und kann, was die Config verlangt, und
    /// setzt den Zustand. Liefert den Zustand danach.
    pub async fn probe(&self) -> State {
        let (state, recently_ok) = {
            let h = self.health();
            (
                h.state,
                h.last_ok.is_some_and(|t| t.elapsed() < IDLE_BEFORE_PROBE),
            )
        };
        // Solange echter Verkehr gelingt, ist das die beste Probe.
        if state == State::Ready && recently_ok {
            return State::Ready;
        }
        match self.check(state != State::Ready).await {
            Ok(server) => self.mark_ready(server),
            Err(problem) => {
                // Eine einzelne verpasste Probe ist noch kein Ausfall: Ein
                // Presidio mit einem Worker kann gerade beschäftigt sein.
                let tolerated = {
                    let mut h = self.health();
                    h.failures += 1;
                    h.state == State::Ready && h.failures < FAILURES_TO_OPEN
                };
                if !tolerated {
                    self.mark_down(problem);
                }
            }
        }
        self.state()
    }

    /// `/health` und – bei `full` – der Testsatz jeder Sprache.
    pub async fn check(&self, full: bool) -> Result<Option<ServerInfo>, Problem> {
        let url = format!("{}/health", self.base);
        let resp = self
            .client
            .get(&url)
            .timeout(PROBE_TIMEOUT)
            .send()
            .await
            .map_err(|e| {
                Problem::new(format!(
                    "{} does not answer: {}",
                    self.base,
                    explain(&e, PROBE_TIMEOUT)
                ))
            })?;
        if !resp.status().is_success() {
            return Err(Problem::new(format!(
                "{url} answered HTTP {}",
                resp.status().as_u16()
            )));
        }
        if !full {
            return Ok(None);
        }
        for language in &self.languages {
            self.check_language(language).await?;
        }
        Ok(self.info().await)
    }

    async fn info(&self) -> Option<ServerInfo> {
        let resp = self
            .client
            .get(format!("{}/info", self.base))
            .timeout(PROBE_TIMEOUT)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json().await.ok()
    }

    fn language_hint(&self) -> String {
        if self.cfg.managed {
            "hedge presidio upgrade   (recreates the container from the image that belongs to this hedge)"
                .into()
        } else {
            format!(
                "run the hedge-presidio image (it has {}), or set [presidio] languages to what this Presidio offers",
                self.languages.join(" + ")
            )
        }
    }

    /// Kann dieses Presidio die Sprache? Für geprüfte Sprachen muss es den
    /// Namen im Testsatz finden, für alle anderen die Sprache annehmen.
    async fn check_language(&self, language: &str) -> Result<(), Problem> {
        let canary = lang::canary(language);
        let text = canary.as_ref().map_or(lang::NEUTRAL, |c| c.text);
        let hits = self
            .call(text, language, &["PERSON".to_owned()], 0.3, CANARY_TIMEOUT)
            .await
            .map_err(|reason| {
                Problem::new(format!(
                    "language {language:?} is not available on this Presidio: {reason}"
                ))
                .with_hint(self.language_hint())
            })?;
        let Some(canary) = canary else { return Ok(()) };
        let chars_before = |byte: usize| text[..byte].chars().count();
        let start = text.find(canary.name).map(chars_before).unwrap_or(0);
        let end = start + canary.name.chars().count();
        let found = hits
            .iter()
            .any(|h| h.entity_type == "PERSON" && h.start < end && start < h.end);
        if found {
            Ok(())
        } else {
            Err(Problem::new(format!(
                "language {language:?}: the name in the test sentence was not found – this Presidio has no working name model for {language:?}"
            ))
            .with_hint(self.language_hint()))
        }
    }

    // ---------- Analyse ----------

    /// Ein Aufruf von `/analyze`. Fehler als Text für Menschen.
    async fn call(
        &self,
        text: &str,
        language: &str,
        entities: &[String],
        threshold: f64,
        timeout: Duration,
    ) -> Result<Vec<Hit>, String> {
        let resp = self
            .client
            .post(format!("{}/analyze", self.base))
            .timeout(timeout)
            .json(&json!({
                "text": text,
                "language": language,
                "entities": entities,
                "score_threshold": threshold,
            }))
            .send()
            .await
            .map_err(|e| explain(&e, timeout))?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            // Die Meldung landet in Status und Witness: kurz halten, damit
            // ein fremdes Presidio dort nichts aus dem Text ablegen kann.
            let msg: String = body["error"]
                .as_str()
                .unwrap_or("no details")
                .chars()
                .take(160)
                .collect();
            return Err(format!("HTTP {}: {msg}", status.as_u16()));
        }
        resp.json()
            .await
            .map_err(|e| format!("unexpected answer: {}", explain(&e, timeout)))
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.cfg.timeout_ms.max(100))
    }

    async fn analyze_chunk(&self, text: &str, key: [u8; 32]) -> Result<Arc<[Finding]>, String> {
        let language = self.picker.pick(text);
        let hits = self
            .call(
                text,
                language,
                &self.cfg.entities,
                self.cfg.score_threshold,
                self.timeout(),
            )
            .await?;
        let findings: Arc<[Finding]> =
            to_findings(text, &hits, self.cfg.score_threshold, self.cfg.single_names).into();
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key, findings.clone());
        Ok(findings)
    }

    /// Analysiert alle Texte (Pfad, Text) einer Anfrage.
    ///
    /// Wartet höchstens `budget_ms`. Was dann noch läuft, läuft im
    /// Hintergrund zu Ende und füllt den Cache – die nächste Anfrage der
    /// Session findet es dort.
    pub async fn scan_all(self: &Arc<Self>, texts: Vec<(String, String)>) -> Scan {
        let mut scan = Scan::default();
        if texts.is_empty() {
            return scan;
        }
        {
            let h = self.health();
            if h.state != State::Ready {
                scan.gap = Some(Gap::NotReady {
                    state: h.state,
                    reason: h.why().0.unwrap_or_else(|| "not checked yet".into()),
                });
                return scan;
            }
        }

        struct Job {
            path: String,
            offset: usize,
            text: String,
            key: [u8; 32],
        }
        let mut jobs: Vec<Job> = Vec::new();
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            for (path, text) in &texts {
                for (offset, chunk) in chunks(text, self.cfg.max_chars) {
                    if chunk.trim().is_empty() {
                        continue;
                    }
                    let key: [u8; 32] = Sha256::digest(chunk.as_bytes()).into();
                    match cache.get(&key) {
                        Some(found) => {
                            scan.cached += 1;
                            add(&mut scan.findings, path, offset, &found);
                        }
                        None => jobs.push(Job {
                            path: path.clone(),
                            offset,
                            text: chunk.to_owned(),
                            key,
                        }),
                    }
                }
            }
        }
        self.counters
            .cached
            .fetch_add(scan.cached, Ordering::Relaxed);
        if jobs.is_empty() {
            self.note_scan(None);
            return scan;
        }

        type Done = (String, usize, Result<Arc<[Finding]>, String>, u64);
        let total = jobs.len();
        let (tx, mut rx) = mpsc::unbounded_channel::<Done>();
        let this = self.clone();
        let concurrency = self.cfg.concurrency.max(1);
        tokio::spawn(async move {
            let mut results = futures_util::stream::iter(jobs)
                .map(|job| {
                    let this = this.clone();
                    async move {
                        let started = Instant::now();
                        let r = this.analyze_chunk(&job.text, job.key).await;
                        (
                            job.path,
                            job.offset,
                            r,
                            started.elapsed().as_millis() as u64,
                        )
                    }
                })
                .buffer_unordered(concurrency);
            let mut errors = 0;
            while let Some(done) = results.next().await {
                if done.2.is_err() {
                    errors += 1;
                }
                // Auch wenn die Anfrage nicht mehr wartet: weiterarbeiten,
                // das Ergebnis liegt dann im Cache.
                let _ = tx.send(done);
                if errors >= 3 {
                    break;
                }
            }
        });

        let budget = Duration::from_millis(self.cfg.budget_ms.max(100));
        let deadline = tokio::time::sleep(budget);
        tokio::pin!(deadline);
        let mut done = 0usize;
        let mut first_error: Option<String> = None;
        loop {
            tokio::select! {
                item = rx.recv() => match item {
                    Some((path, offset, result, ms)) => {
                        done += 1;
                        scan.durations_ms.push(ms);
                        match result {
                            Ok(found) => {
                                scan.analyzed += 1;
                                add(&mut scan.findings, &path, offset, &found);
                            }
                            Err(e) => {
                                scan.failed += 1;
                                first_error.get_or_insert(e);
                            }
                        }
                    }
                    None => break,
                },
                _ = &mut deadline => {
                    scan.gap = Some(Gap::Timeout {
                        pending: total - done,
                        budget_ms: self.cfg.budget_ms,
                    });
                    break;
                }
            }
        }
        self.counters
            .analyzed
            .fetch_add(scan.analyzed, Ordering::Relaxed);
        self.counters
            .failed
            .fetch_add(scan.failed, Ordering::Relaxed);
        match first_error {
            Some(reason) => {
                // Nach dem ersten Fehler bricht die Arbeit ab; was übrig
                // ist, wurde nicht geprüft.
                scan.failed += (total - done) as u64;
                self.note_scan(Some(reason.clone()));
                scan.gap = Some(Gap::Failed { reason });
            }
            // Langsam ist nicht ausgefallen: Ein Zeitlimit öffnet den
            // Schalter nicht.
            None if scan.gap.is_none() => self.note_scan(None),
            None => {}
        }
        for list in scan.findings.values_mut() {
            list.sort_by_key(|f| f.start);
        }
        scan
    }

    /// Ergebnis eines Scans für den Zustand: Zwei Fehler in Folge heißen
    /// "nicht erreichbar".
    fn note_scan(&self, error: Option<String>) {
        match error {
            None => {
                let mut h = self.health();
                h.failures = 0;
                h.last_ok = Some(Instant::now());
            }
            Some(reason) => {
                let open = {
                    let mut h = self.health();
                    h.failures += 1;
                    h.failures >= FAILURES_TO_OPEN
                };
                if open {
                    self.mark_down(Problem::new(reason));
                }
            }
        }
    }

    /// Eine ungeprüfte Anfrage mehr (für `hedge status`).
    pub fn count_unscanned(&self) {
        self.counters.unscanned.fetch_add(1, Ordering::Relaxed);
    }

    /// Analysiert einen Text so, wie Hedge es im Betrieb tut, und zeigt
    /// auch, was unter der Schwelle bleibt. Für `hedge presidio test`.
    pub async fn try_text(&self, text: &str, language: Option<&str>) -> Result<TestReport, String> {
        let language = language
            .map(str::to_owned)
            .unwrap_or_else(|| self.picker.pick(text).to_owned());
        let started = Instant::now();
        let hits = self
            .call(
                text,
                &language,
                &self.cfg.entities,
                0.0,
                self.timeout().max(CANARY_TIMEOUT),
            )
            .await?;
        let duration_ms = started.elapsed().as_millis() as u64;
        let mut byte_of: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
        byte_of.push(text.len());
        let mut out: Vec<TestHit> = hits
            .iter()
            .filter(|h| h.start < h.end && h.end < byte_of.len())
            .map(|h| {
                let (kind, severity) = kind_of(&h.entity_type);
                let (start, end) = (byte_of[h.start], byte_of[h.end]);
                let dropped = if h.score < self.cfg.score_threshold {
                    Some("below_threshold")
                } else if h.entity_type == "PERSON" {
                    match judge_name(text, start, end, self.cfg.single_names) {
                        NameVerdict::Name => None,
                        NameVerdict::NotAName => Some("not_a_name"),
                        NameVerdict::SingleWord => Some("single_word"),
                    }
                } else {
                    None
                };
                TestHit {
                    entity: h.entity_type.clone(),
                    kind,
                    severity: severity.as_str(),
                    start,
                    end,
                    score: h.score,
                    reported: dropped.is_none(),
                    dropped,
                }
            })
            .collect();
        out.sort_by(|a, b| a.start.cmp(&b.start).then(b.score.total_cmp(&a.score)));
        Ok(TestReport {
            language,
            threshold: self.cfg.score_threshold,
            duration_ms,
            hits: out,
        })
    }

    /// Alles, was `hedge status`, die TUI und `/ready` über Presidio wissen
    /// müssen.
    pub fn status(&self) -> Value {
        let h = self.health();
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        json!({
            "enabled": true,
            "state": h.state.as_str(),
            "since": now_rfc3339(h.since),
            "reason": h.why().0,
            "hint": h.why().1,
            "url": self.base,
            "managed": self.cfg.managed,
            "image": self.cfg.managed.then(|| self.cfg.image().to_owned()),
            "server": h.server,
            "languages": self.languages,
            "entities": self.cfg.entities,
            "scope": self.cfg.scope.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "enforce": self.cfg.enforce,
            "on_unavailable": self.cfg.on_unavailable.as_str(),
            "since_start": {
                "analyzed": n(&self.counters.analyzed),
                "cached": n(&self.counters.cached),
                "failed": n(&self.counters.failed),
                "unscanned_requests": n(&self.counters.unscanned),
            },
            "cache_entries": self.cache.lock().unwrap_or_else(|e| e.into_inner()).len(),
        })
    }
}

fn add(out: &mut HashMap<String, Vec<Finding>>, path: &str, offset: usize, found: &[Finding]) {
    if found.is_empty() {
        return;
    }
    out.entry(path.to_owned())
        .or_default()
        .extend(found.iter().map(|f| Finding {
            start: f.start + offset,
            end: f.end + offset,
            ..f.clone()
        }));
}

/// Teilt `text` in Stücke von höchstens `max_chars` Zeichen und liefert sie
/// mit ihrem Byte-Offset. Geschnitten wird nach dem letzten Zeilenumbruch
/// im Stück, sonst nach dem letzten Leerraum, sonst hart – ein Name, der
/// über eine Zeile hinausgeht, ist seltener als einer mitten in der Zeile.
pub fn chunks(text: &str, max_chars: usize) -> Vec<(usize, &str)> {
    let max_chars = max_chars.max(1);
    // Bytes ≥ Zeichen: Passt die Bytelänge, passt auch die Zeichenzahl.
    if text.len() <= max_chars {
        return vec![(0, text)];
    }
    let mut out = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let rest = &text[start..];
        let Some((limit, _)) = rest.char_indices().nth(max_chars) else {
            out.push((start, rest));
            break;
        };
        let window = &rest[..limit];
        // Nicht zu früh schneiden, sonst entstehen lauter kleine Stücke.
        let enough = |cut: &usize| *cut >= limit / 2;
        let cut = window
            .rfind('\n')
            .map(|i| i + 1)
            .filter(enough)
            .or_else(|| {
                window
                    .char_indices()
                    .rev()
                    .find(|(_, c)| c.is_whitespace())
                    .map(|(i, c)| i + c.len_utf8())
                    .filter(enough)
            })
            .unwrap_or(limit);
        out.push((start, &rest[..cut]));
        start += cut;
    }
    out
}

/// Presidio zählt Zeichen (Unicode-Codepoints), Hedge arbeitet mit
/// Byte-Offsets. Hier wird umgerechnet; ungültige Bereiche fallen weg,
/// ebenso Namensfunde, die keine Namen sein können.
fn to_findings(text: &str, hits: &[Hit], threshold: f64, single_names: bool) -> Vec<Finding> {
    let mut byte_of: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
    byte_of.push(text.len());
    let mut findings: Vec<Finding> = hits
        .iter()
        .filter(|h| h.score >= threshold && h.start < h.end && h.end < byte_of.len())
        .filter(|h| {
            h.entity_type != "PERSON"
                || judge_name(text, byte_of[h.start], byte_of[h.end], single_names)
                    == NameVerdict::Name
        })
        .map(|h| {
            let (kind, severity) = kind_of(&h.entity_type);
            Finding {
                detector: "presidio",
                kind,
                severity,
                start: byte_of[h.start],
                end: byte_of[h.end],
            }
        })
        .collect();
    findings.sort_by_key(|f| f.start);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(entity: &str, start: usize, end: usize, score: f64) -> Hit {
        Hit {
            entity_type: entity.into(),
            start,
            end,
            score,
        }
    }

    #[test]
    fn char_offsets_become_byte_offsets() {
        let text = "Grüße von Jörg Müller 🔒 +49 170 1234567";
        let name_start = text.chars().position(|c| c == 'J').unwrap();
        let hits = [
            hit("PERSON", name_start, name_start + 11, 0.85),
            hit("PHONE_NUMBER", 24, 39, 0.4),
            hit("PERSON", 5, 500, 0.9),
        ];

        let findings = to_findings(text, &hits, 0.6, false);

        assert_eq!(
            findings.len(),
            1,
            "low score and out-of-range hits are dropped"
        );
        assert_eq!(findings[0].kind, "person_name");
        assert_eq!(findings[0].detector, "presidio");
        assert_eq!(&text[findings[0].start..findings[0].end], "Jörg Müller");
    }

    #[test]
    fn hit_reaching_the_end_of_text_is_valid() {
        let text = "call Ünal";
        let findings = to_findings(text, &[hit("PERSON", 5, 9, 0.9)], 0.5, true);
        assert_eq!(&text[findings[0].start..findings[0].end], "Ünal");
        assert!(
            to_findings(text, &[hit("PERSON", 5, 9, 0.9)], 0.5, false).is_empty(),
            "a single word needs a title in front or single_names = true"
        );
    }

    #[test]
    fn scope_decides_what_is_sent() {
        let p = Presidio::new(&PresidioCfg::default()).unwrap();
        let long = "Hello, my name is John Smith";
        assert!(p.wants(Part::User, "messages[0].content", long));
        assert!(p.wants(Part::ToolResult, "messages[1].content[0].content", long));
        assert!(!p.wants(Part::User, "messages[0].content", "short"));
        assert!(!p.wants(Part::User, "messages[0].content", "              "));
        assert!(!p.wants(Part::System, "system", long));
        assert!(!p.wants(Part::Tools, "tools[3].description", long));
        assert!(!p.wants(Part::Assistant, "messages[1].content", long));
        assert!(!p.wants(Part::ToolUse, "messages[1].content[0].input.command", long));

        let all = PresidioCfg {
            scope: vec![PresidioScope::System, PresidioScope::Assistant],
            skip_paths: vec!["messages[0]".into()],
            ..PresidioCfg::default()
        };
        let p = Presidio::new(&all).unwrap();
        assert!(p.wants(Part::System, "system[0].text", long));
        assert!(!p.wants(Part::User, "messages[2].content", long));
        assert!(p.wants(Part::Assistant, "messages[1].content", long));
        assert!(
            !p.wants(Part::Assistant, "messages[0].content", long),
            "skip_paths"
        );
        assert!(p.wants(Part::Assistant, "messages[01].content", long));
    }

    #[test]
    fn unknown_entities_map_to_generic_kind() {
        assert_eq!(kind_of("CREDIT_CARD"), ("credit_card", Severity::High));
        assert_eq!(kind_of("DE_TAX_ID"), ("de_tax_id", Severity::High));
        assert_eq!(kind_of("SOMETHING_NEW"), ("pii_other", Severity::Medium));
    }

    fn judge(text: &str, name: &str) -> NameVerdict {
        let start = text.find(name).unwrap();
        judge_name(text, start, start + name.len(), false)
    }

    #[test]
    fn names_look_like_names() {
        for name in [
            "Jörg Müller",
            "Anne-Marie Müller-Lüdenscheidt",
            "Ludwig van Beethoven",
            "Ursula von der Leyen",
            "Dr. Annette Schmidt",
            "J. R. Smith",
            "Conan O'Brien",
            "Ronald McDonald",
            "Élodie Dupont",
        ] {
            assert_eq!(judge(name, name), NameVerdict::Name, "{name}");
        }
    }

    #[test]
    fn identifiers_paths_and_constants_are_not_names() {
        // Alles hier hat ein echtes Presidio als PERSON gemeldet.
        for junk in [
            "prometheus",
            "t.bold",
            "worker-3 Retrying",
            "acme-prod",
            "cfg-if",
            "x-hedge-client-token",
            "Mutex::new",
            "cli.rs",
            "def get_user",
            "PresidioState",
            "t.bold(Tone::Bad",
            "{lang",
            "timestamp",
            "HEDGE_CONFIG",
            "README",
            "Config wird abgelehnt",
            "Zeichen→Byte-Offsets",
            "curve25519-dalek",
            "Claude Code",
            "Claude",
        ] {
            assert_eq!(judge(junk, junk), NameVerdict::NotAName, "{junk}");
        }
    }

    #[test]
    fn a_single_word_needs_a_title_in_front() {
        assert_eq!(judge("let m = Mutex", "Mutex"), NameVerdict::SingleWord);
        assert_eq!(
            judge("Gestern rief er an", "Gestern"),
            NameVerdict::SingleWord
        );
        assert_eq!(
            judge("Das sagt Frau Wagner auch", "Wagner"),
            NameVerdict::Name
        );
        assert_eq!(
            judge("Brief an Herrn Dr. Hoffmann", "Hoffmann"),
            NameVerdict::Name
        );
        assert_eq!(judge("ask Mrs. Smith about it", "Smith"), NameVerdict::Name);
        assert_eq!(judge("call smith", "smith"), NameVerdict::NotAName);

        let text = "let m = Mutex";
        let start = text.find("Mutex").unwrap();
        assert_eq!(
            judge_name(text, start, text.len(), true),
            NameVerdict::Name,
            "single_names = true takes single words"
        );
    }

    #[test]
    fn only_person_hits_are_judged() {
        let text = "karte 4111111111111111 von prometheus";
        let hits = [hit("CREDIT_CARD", 6, 22, 1.0), hit("PERSON", 27, 37, 0.85)];
        let findings = to_findings(text, &hits, 0.6, true);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "credit_card");
    }

    #[test]
    fn short_text_is_one_chunk() {
        assert_eq!(chunks("hallo", 100), vec![(0, "hallo")]);
        assert_eq!(chunks("", 100), vec![(0, "")]);
    }

    #[test]
    fn long_text_is_cut_at_line_breaks_and_offsets_add_up() {
        let line = "Zeile mit Umlauten äöü und einem Namen\n";
        let text = line.repeat(50);
        let parts = chunks(&text, 200);

        assert!(parts.len() > 5);
        let mut rebuilt = String::new();
        for (offset, part) in &parts {
            assert_eq!(*offset, rebuilt.len(), "offsets are byte positions");
            assert!(part.chars().count() <= 200);
            assert!(part.ends_with('\n'), "cut after a line break: {part:?}");
            rebuilt.push_str(part);
        }
        assert_eq!(rebuilt, text);
    }

    #[test]
    fn text_without_breaks_is_cut_at_spaces_or_hard() {
        let words = "wort ".repeat(100);
        for (_, part) in chunks(&words, 42) {
            assert!(part.chars().count() <= 42);
            assert!(part.ends_with(' '));
        }
        let blob = "ä".repeat(1000);
        let parts = chunks(&blob, 300);
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].1.chars().count(), 300);
        assert_eq!(
            parts.iter().map(|(_, p)| p.len()).sum::<usize>(),
            blob.len()
        );
    }

    #[test]
    fn cache_keeps_recent_entries_across_a_generation_change() {
        let mut c = Cache::default();
        let empty: Arc<[Finding]> = Vec::new().into();
        let key = |i: usize| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_be_bytes());
            k
        };
        for i in 0..CACHE_GENERATION {
            c.put(key(i), empty.clone());
        }
        c.put(key(CACHE_GENERATION), empty.clone());
        assert!(c.get(&key(0)).is_some(), "old generation is still readable");
        assert!(c.young.contains_key(&key(0)), "and a hit moves it forward");
        assert_eq!(c.len(), CACHE_GENERATION + 1);
    }

    #[test]
    fn state_machine_records_each_change_once() {
        let p = Presidio::new(&PresidioCfg::default()).unwrap();
        assert_eq!(p.state(), State::Starting);

        // Im Anlauf ist ein Fehler noch kein Ausfall.
        p.mark_down(Problem::new("connection refused"));
        assert_eq!(p.state(), State::Starting);
        assert!(p.take_transitions().is_empty());
        assert_eq!(p.status()["reason"], "connection refused");

        p.mark_ready(None);
        p.mark_ready(None);
        let t = p.take_transitions();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].to, State::Ready);
        assert!(t[0].detail.contains("de, en"), "{}", t[0].detail);

        // Ein einzelner fehlgeschlagener Scan kippt den Zustand nicht.
        p.note_scan(Some("no answer within 5000 ms".into()));
        assert_eq!(p.state(), State::Ready);
        p.note_scan(Some("no answer within 5000 ms".into()));
        assert_eq!(p.state(), State::Unavailable);
        p.note_scan(Some("still nothing".into()));
        let t = p.take_transitions();
        assert_eq!(t.len(), 1, "one event per change");
        assert_eq!(t[0].to, State::Unavailable);
        assert!(t[0].detail.contains("on_unavailable=allow"));

        p.mark_ready(None);
        assert_eq!(p.take_transitions()[0].to, State::Ready);
        assert_eq!(p.status()["reason"], Value::Null);
    }

    #[test]
    fn a_container_problem_explains_the_outage_and_does_not_wait() {
        let p = Presidio::new(&PresidioCfg::default()).unwrap();
        p.mark_down(Problem::new("http://127.0.0.1:5002 does not answer"));
        assert_eq!(p.state(), State::Starting, "still within the start-up time");

        // Die Laufzeit steht: Das wird nicht von selbst besser.
        p.note_sidecar_problem(
            Problem::new("docker is installed but not running").with_hint("open -a OrbStack"),
        );
        assert_eq!(p.state(), State::Unavailable);
        let t = p.take_transitions();
        assert_eq!(t.len(), 1);
        assert!(
            t[0].detail
                .starts_with("docker is installed but not running")
        );

        // Die nächste Probe scheitert wieder; die Erklärung bleibt die bessere.
        p.mark_down(Problem::new("http://127.0.0.1:5002 does not answer"));
        assert_eq!(p.status()["reason"], "docker is installed but not running");
        assert_eq!(p.status()["hint"], "open -a OrbStack");
        assert!(p.take_transitions().is_empty());

        // Der Container läuft wieder an, dann ist Presidio da.
        p.note_starting("container started, loading language models");
        assert_eq!(
            p.status()["reason"],
            "container started, loading language models"
        );
        assert_eq!(p.status()["hint"], Value::Null);

        let fresh = Presidio::new(&PresidioCfg::default()).unwrap();
        fresh.note_starting("container started, loading language models");
        fresh.mark_down(Problem::new("http://127.0.0.1:5002 does not answer"));
        assert_eq!(
            fresh.status()["reason"],
            "container started, loading language models",
            "while the models load, that is the better explanation"
        );
        p.mark_ready(None);
        assert_eq!(p.status()["reason"], Value::Null);
    }

    #[test]
    fn a_success_between_failures_keeps_presidio_ready() {
        let p = Presidio::new(&PresidioCfg::default()).unwrap();
        p.mark_ready(None);
        p.note_scan(Some("slow".into()));
        p.note_scan(None);
        p.note_scan(Some("slow".into()));
        assert_eq!(p.state(), State::Ready);
    }

    #[tokio::test]
    async fn nothing_is_sent_while_presidio_is_not_ready() {
        let p = Arc::new(
            Presidio::new(&PresidioCfg {
                url: "http://127.0.0.1:9".into(),
                ..PresidioCfg::default()
            })
            .unwrap(),
        );
        let started = Instant::now();
        let scan = p
            .scan_all(vec![(
                "messages[0].content".into(),
                "Jörg Müller ruft an".into(),
            )])
            .await;
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "no network call"
        );
        let gap = scan.gap.unwrap();
        assert_eq!(gap.flag(), "presidio_unavailable");
        assert!(gap.reason().contains("starting"), "{}", gap.reason());

        // Ohne Texte gibt es nichts, was ungeprüft bliebe.
        assert!(p.scan_all(Vec::new()).await.gap.is_none());
    }
}
