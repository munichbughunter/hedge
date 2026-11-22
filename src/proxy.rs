//! Der Proxy: nimmt Anfragen unter `/<upstream>/...` an, inspiziert den
//! Request, leitet weiter, liest die Antwort mit (Tokens, Tool-Aufrufe,
//! Funde), greift bei Tool-Aufrufen ein, wenn die Policy es verlangt, und
//! bezeugt das Ergebnis.
//!
//! Harte Regel: Auth-Header (`authorization`, `x-api-key`) werden nur
//! durchgereicht – nie gelesen, geloggt oder in den Witness geschrieben.

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{Path as UrlPath, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};

use crate::approvals::{ApprovalInfo, Approvals, GrantKey, Verdict, parse_chat_command};
use crate::budget::{Budgets, LOCAL};
use crate::config::{Config, Models, ToolAction};
use crate::detect::Detectors;
use crate::inspect::{
    Action, Extra, Outcome, Prepared, Rules, hint_for, inspect, redact, session_label,
};
use crate::presidio::sidecar::{Ensure, Ensured, Sidecar};
use crate::presidio::{Presidio, Scan, State as PresidioState};
use crate::sse::{
    Analyzer, SseFramer, Step, ToolCall, deny_in_message, ping_event, replacement_events,
    summarize_message,
};
use crate::telemetry::Telemetry;
use crate::tools::{ToolPolicy, approval_fingerprint, display, first_string, glob_match, subject};
use crate::witness::{Anchor, FindingRecord, Record, ToolRecord, Witness, sha256_hex};

const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
/// So viele Tool-Aufruf-IDs merkt sich Hedge für den Abgleich mit Ergebnissen.
const MAX_SEEN_TOOLS: usize = 20_000;
/// Header, mit dem sich ein Client im Central-Mode ausweist.
/// So viele Sessions merkt sich Hedge für das Wiedererkennen von Funden.
const MAX_SEEN_SESSIONS: usize = 2_000;
pub const CLIENT_TOKEN_HEADER: &str = "x-hedge-client-token";

/// Alles, was aus der Config entsteht und im Betrieb ausgetauscht werden
/// kann. Eine Anfrage holt sich zu Beginn eine Referenz und arbeitet bis
/// zum Ende damit – ein Reload trifft nie eine halbe Anfrage.
pub struct Runtime {
    pub cfg: Config,
    pub client: reqwest::Client,
    pub detectors: Detectors,
    pub rules: Rules,
    pub tools: ToolPolicy,
    pub presidio: Option<Arc<Presidio>>,
    /// SHA-256 des Client-Tokens → Name.
    clients: HashMap<String, String>,
}

impl Runtime {
    pub fn build(cfg: Config) -> Result<Self, Box<dyn Error>> {
        Self::build_reusing(cfg, None)
    }

    /// Wie `build`, übernimmt aber den Presidio-Client der alten Runtime,
    /// wenn sich an `[presidio]` nichts geändert hat: Zustand und Cache
    /// überleben so jeden Reload, der Presidio nicht betrifft.
    pub fn build_reusing(cfg: Config, old: Option<&Runtime>) -> Result<Self, Box<dyn Error>> {
        cfg.validate()?;
        let client = build_client(&cfg)?;
        let tools = ToolPolicy::from_config(&cfg.tools)?;
        let presidio = if cfg.presidio.enabled {
            match old.and_then(|o| o.presidio.as_ref()) {
                Some(p) if *p.cfg() == cfg.presidio => Some(p.clone()),
                _ => Some(Arc::new(Presidio::new(&cfg.presidio)?)),
            }
        } else {
            None
        };
        let clients = cfg
            .clients
            .iter()
            .map(|c| (c.token_sha256.to_ascii_lowercase(), c.name.clone()))
            .collect();
        Ok(Self {
            detectors: Detectors::from_toggles(&cfg.detectors),
            rules: Rules::from_config(&cfg),
            client,
            tools,
            presidio,
            clients,
            cfg,
        })
    }

    fn client_of(&self, headers: &HeaderMap) -> Option<String> {
        let token = headers.get(CLIENT_TOKEN_HEADER)?.to_str().ok()?;
        self.clients
            .get(&sha256_hex(token.trim().as_bytes()))
            .cloned()
    }
}

pub fn build_client(cfg: &Config) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        // Ein 3xx geht unverändert an den Client zurück. Würde Hedge folgen,
        // wanderten Credentials zu einem Host, den der Agent nie angefragt hat.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(cfg.timeouts.connect_secs))
        // Leerlauf-Timeout statt Gesamt-Timeout: Ein langer Stream darf
        // laufen, solange Daten kommen.
        .read_timeout(Duration::from_secs(cfg.timeouts.request_secs))
        .build()
}

/// Entscheidungen, bei denen der Agent den Aufruf nie bekommen hat.
fn withheld(decision: &str) -> bool {
    matches!(decision, "deny" | "rejected" | "timeout" | "held")
}

/// Entscheidungen, die einen Aufruf endgültig gestoppt haben.
fn stopped(decision: &str) -> bool {
    matches!(decision, "deny" | "rejected" | "timeout")
}

#[derive(Default)]
struct SeenTools {
    order: VecDeque<String>,
    /// ID → wurde der Aufruf von Hedge verworfen?
    known: HashMap<String, bool>,
}

impl SeenTools {
    fn remember(&mut self, id: &str, denied: bool) {
        if id.is_empty() {
            return;
        }
        if self.known.insert(id.to_owned(), denied).is_none() {
            self.order.push_back(id.to_owned());
            if self.order.len() > MAX_SEEN_TOOLS
                && let Some(old) = self.order.pop_front()
            {
                self.known.remove(&old);
            }
        }
    }
}

/// Welche Funde eine Session schon gezeigt hat. Agents schicken mit jeder
/// Anfrage die ganze Unterhaltung erneut; ohne dieses Gedächtnis würde ein
/// einmal getippter Key bei jeder Folgeanfrage neu gezählt.
#[derive(Default)]
struct SeenFindings {
    sessions: HashMap<String, std::collections::HashSet<u64>>,
}

impl SeenFindings {
    /// `true`, wenn der Fund in dieser Session schon bekannt war.
    fn is_repeat(&mut self, session: &str, fingerprint: u64) -> bool {
        if self.sessions.len() >= MAX_SEEN_SESSIONS && !self.sessions.contains_key(session) {
            self.sessions.clear();
        }
        !self
            .sessions
            .entry(session.to_owned())
            .or_default()
            .insert(fingerprint)
    }
}

#[derive(Default)]
struct Stats {
    requests: AtomicU64,
    blocked: AtomicU64,
    redacted: AtomicU64,
    findings: AtomicU64,
    tools: AtomicU64,
    tools_stopped: AtomicU64,
}

pub struct AppState {
    runtime: RwLock<Arc<Runtime>>,
    witness: Option<Witness>,
    pub approvals: Approvals,
    pub budgets: Budgets,
    telemetry: Option<Telemetry>,
    control_token: Option<String>,
    seen_tools: Mutex<SeenTools>,
    seen_findings: Mutex<SeenFindings>,
    started: Instant,
    stats: Stats,
    /// Weckt die Presidio-Aufsicht, wenn sich die Config geändert hat.
    presidio_wake: tokio::sync::Notify,
    /// Wann die Aufsicht zuletzt nach dem Container gesehen hat.
    sidecar_checked: Mutex<Option<Instant>>,
}

impl AppState {
    pub fn new(runtime: Runtime, witness: Option<Witness>) -> Self {
        Self {
            runtime: RwLock::new(Arc::new(runtime)),
            witness,
            approvals: Approvals::default(),
            budgets: Budgets::default(),
            telemetry: None,
            control_token: None,
            seen_tools: Mutex::new(SeenTools::default()),
            seen_findings: Mutex::new(SeenFindings::default()),
            started: Instant::now(),
            stats: Stats::default(),
            presidio_wake: tokio::sync::Notify::new(),
            sidecar_checked: Mutex::new(None),
        }
    }

    pub fn with_control_token(mut self, token: Option<String>) -> Self {
        self.control_token = token.filter(|t| !t.trim().is_empty());
        self
    }

    pub fn with_telemetry(mut self, telemetry: Option<Telemetry>) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// Baut den State komplett aus der Config: Runtime, Witness, Telemetrie,
    /// Steuer-Token; Budgets und bekannte Tool-Aufrufe aus dem Witness.
    pub fn from_config(cfg: Config) -> Result<Self, Box<dyn Error>> {
        let witness = if cfg.witness.enabled {
            Some(Witness::open(&cfg.witness_path(), &cfg.witness_key_path())?)
        } else {
            None
        };
        let telemetry = Telemetry::init(&cfg.telemetry)?;
        let token = std::fs::read_to_string(cfg.control_token_path())
            .ok()
            .map(|t| t.trim().to_owned());
        let state = Self::new(Runtime::build(cfg)?, witness)
            .with_control_token(token)
            .with_telemetry(telemetry);
        state.restore_from_witness();
        Ok(state)
    }

    fn restore_from_witness(&self) {
        let Some(w) = &self.witness else { return };
        let Ok(entries) = crate::witness::read_entries(w.path()) else {
            return;
        };
        self.budgets.seed(&entries);
        let mut seen = self.seen_tools.lock().unwrap_or_else(|e| e.into_inner());
        let from = entries.len().saturating_sub(5_000);
        for e in &entries[from..] {
            for t in &e.tools {
                seen.remember(&t.id, withheld(&t.decision));
            }
        }
    }

    /// Die aktuelle Runtime. Billig: ein Lock und ein Arc-Klon.
    pub fn runtime(&self) -> Arc<Runtime> {
        self.runtime
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn witness(&self) -> Option<&Witness> {
        self.witness.as_ref()
    }

    pub fn telemetry(&self) -> Option<&Telemetry> {
        self.telemetry.as_ref()
    }

    pub fn has_control_token(&self) -> bool {
        self.control_token.is_some()
    }

    /// Nach dem Container wird höchstens alle fünf Sekunden gesehen: Jeder
    /// Blick startet Prozesse der Container-Laufzeit.
    fn sidecar_due(&self) -> bool {
        let mut last = self
            .sidecar_checked
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(5)) {
            return false;
        }
        *last = Some(Instant::now());
        true
    }

    fn remember_tool(&self, id: &str, denied: bool) {
        self.seen_tools
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remember(id, denied);
    }

    fn seen_tool(&self, id: &str) -> Option<bool> {
        self.seen_tools
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .known
            .get(id)
            .copied()
    }

    /// Schreibt ein Ereignis (Start, Stop, Config-Reload) in den Witness.
    pub fn record_event(&self, event: &str, detail: String) {
        self.record_event_for(event, detail, None, None);
    }

    /// Ein Ereignis, das zu einer Agent-Session gehört (Freigaben).
    pub fn record_event_for(
        &self,
        event: &str,
        detail: String,
        client: Option<&str>,
        session: Option<&str>,
    ) {
        let rt = self.runtime();
        let rec = Record {
            upstream: "-".into(),
            method: "-".into(),
            path: "-".into(),
            mode: rt.cfg.mode.as_str().into(),
            action: "event".into(),
            body_sha256_in: sha256_hex(b""),
            client: client.map(str::to_owned),
            session: session.map(str::to_owned),
            event: Some(event.into()),
            detail: Some(detail),
            ..Record::default()
        };
        self.write(rec);
    }

    /// Entscheidet eine Freigabe-Anfrage und bezeugt die Entscheidung.
    /// `via` sagt, auf welchem Weg sie kam (chat, control api).
    pub fn resolve_approval(
        &self,
        id: &str,
        verdict: Verdict,
        via: &str,
        allowed: impl Fn(&ApprovalInfo) -> bool,
    ) -> Option<ApprovalInfo> {
        let info = self.approvals.resolve_where(id, verdict, allowed)?;
        let word = match verdict {
            Verdict::Approved => "approved",
            Verdict::Rejected => "rejected",
        };
        info!(
            approval = %info.id, tool = %info.tool, rule = %info.rule,
            session = info.session.as_deref().unwrap_or("-"),
            "tool call {word} via {via}"
        );
        self.record_event_for(
            "approval",
            format!(
                "{} {word} via {via} · {} · {}",
                info.id, info.tool, info.rule
            ),
            info.client.as_deref(),
            info.session.as_deref(),
        );
        Some(info)
    }

    /// Bezeugt Zustandswechsel von Presidio und meldet sie der Telemetrie.
    /// Aus dem Witness lässt sich so ablesen, von wann bis wann keine
    /// Namenserkennung lief.
    pub fn note_presidio(&self, presidio: &Presidio) {
        for t in presidio.take_transitions() {
            match t.to {
                PresidioState::Ready => {
                    info!("presidio ready: {}", t.detail);
                    self.record_event("presidio_ready", t.detail);
                }
                PresidioState::Unavailable => {
                    let rt = self.runtime();
                    if rt.cfg.presidio_fail_closed() {
                        error!(
                            "presidio unavailable: {} – requests with text to check are rejected until it is back",
                            t.detail
                        );
                    } else {
                        warn!(
                            "presidio unavailable: {} – requests continue without name detection",
                            t.detail
                        );
                    }
                    self.record_event("presidio_unavailable", t.detail);
                }
                PresidioState::Starting => {}
            }
        }
        if let Some(t) = &self.telemetry {
            t.presidio_up(presidio.state() == PresidioState::Ready);
        }
    }

    /// Kann Hedge Anfragen so bedienen, wie die Config es verlangt?
    /// `Err` nennt, worauf noch gewartet wird.
    pub fn readiness(&self) -> Result<(), Vec<String>> {
        let rt = self.runtime();
        let mut waiting = Vec::new();
        if rt.cfg.presidio_fail_closed()
            && let Some(p) = &rt.presidio
            && p.state() != PresidioState::Ready
        {
            waiting.push(format!("presidio ({})", p.state().as_str()));
        }
        if waiting.is_empty() {
            Ok(())
        } else {
            Err(waiting)
        }
    }

    /// Witness und Telemetrie für einen fertigen Eintrag.
    fn write(&self, rec: Record) {
        let anchor = match &self.witness {
            Some(w) => match w.record(rec.clone()) {
                Ok(e) => Some(Anchor {
                    seq: e.seq,
                    hash: e.hash,
                }),
                Err(e) => {
                    // Der Witness darf den Traffic nicht blockieren, aber sein
                    // Ausfall muss laut sein: Ohne Protokoll ist Hedge kein Guard.
                    error!(error = %e, "witness write failed");
                    if let Some(t) = &self.telemetry {
                        t.witness_error();
                    }
                    None
                }
            },
            None => None,
        };
        if let Some(t) = &self.telemetry {
            t.record(&rec, anchor.as_ref());
        }
    }

    /// Schließt eine Anfrage ab: Dauer, Budget, Statistik, Log, Witness, Telemetrie.
    fn complete(&self, mut rec: Record, started: Instant, budget_key: &str) {
        rec.duration_ms = started.elapsed().as_millis() as u64;
        self.budgets.add(
            budget_key,
            rec.session.as_deref(),
            rec.tokens_in.unwrap_or(0) + rec.tokens_out.unwrap_or(0),
        );
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        match rec.action.as_str() {
            "block" => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
            }
            "redact" => {
                self.stats.redacted.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        self.stats.findings.fetch_add(
            (rec.findings.iter().filter(|f| !f.repeat).count() + rec.response_findings.len())
                as u64,
            Ordering::Relaxed,
        );
        self.stats
            .tools
            .fetch_add(rec.tools.len() as u64, Ordering::Relaxed);
        let stopped = rec.tools.iter().filter(|t| stopped(&t.decision)).count();
        self.stats
            .tools_stopped
            .fetch_add(stopped as u64, Ordering::Relaxed);
        let pretty = self.runtime().cfg.log.format == crate::config::LogFormat::Pretty;
        log_record(&rec, pretty);
        self.write(rec);
    }

    pub fn status(&self) -> Value {
        let rt = self.runtime();
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "mode": rt.cfg.mode.as_str(),
            "listen": rt.cfg.server.listen,
            "uptime_secs": self.started.elapsed().as_secs(),
            "since_start": {
                "requests": n(&self.stats.requests),
                "blocked": n(&self.stats.blocked),
                "redacted": n(&self.stats.redacted),
                "findings": n(&self.stats.findings),
                "tool_calls": n(&self.stats.tools),
                "tool_calls_stopped": n(&self.stats.tools_stopped),
            },
            "tools": {
                "enforce": rt.tools.enforce(),
                "rules": rt.tools.rule_count(),
                "approve_in_chat": rt.tools.approve_in_chat(),
                "pending_approvals": self.approvals.len(),
            },
            "witness": self.witness.as_ref().map(|w| json!({
                "path": w.path().display().to_string(),
                "key_id": w.key_id(),
                "head": w.head().map(|a| a.to_string()),
            })),
            "budget": {
                "daily_tokens": rt.cfg.budget.daily_tokens,
                "session_tokens": rt.cfg.budget.session_tokens,
                "used_today": self.budgets.daily_usage().into_iter()
                    .map(|(client, tokens)| json!({"client": client, "tokens": tokens}))
                    .collect::<Vec<_>>(),
            },
            "telemetry": self.telemetry.is_some(),
            "presidio": match &rt.presidio {
                Some(p) => p.status(),
                None => json!({ "enabled": false, "state": "off" }),
            },
            "ready": self.readiness().is_ok(),
            "clients": rt.cfg.clients.len(),
            "require_client": rt.cfg.server.require_client,
        })
    }
}

/// Lädt die Config neu und tauscht die Runtime aus. Bei einem Fehler bleibt
/// die alte Runtime aktiv. Beides wird bezeugt.
pub fn reload(state: &AppState, path: &Path) -> Result<(), String> {
    let attempt = || -> Result<(Runtime, Vec<&'static str>, String), String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let cfg = Config::load(path).map_err(|e| e.to_string())?;
        let old = state.runtime();
        let mut restart = Vec::new();
        if cfg.server.listen != old.cfg.server.listen {
            restart.push("server.listen");
        }
        if cfg.witness.enabled != old.cfg.witness.enabled
            || cfg.witness.path != old.cfg.witness.path
            || cfg.witness.key != old.cfg.witness.key
        {
            restart.push("witness");
        }
        if cfg.telemetry.enabled != old.cfg.telemetry.enabled
            || cfg.telemetry.endpoint != old.cfg.telemetry.endpoint
            || cfg.telemetry.service_name != old.cfg.telemetry.service_name
        {
            restart.push("telemetry");
        }
        if cfg.control.token != old.cfg.control.token {
            restart.push("control");
        }
        if cfg.log.format != old.cfg.log.format || cfg.log.level != old.cfg.log.level {
            restart.push("log");
        }
        let runtime = Runtime::build_reusing(cfg, Some(&old)).map_err(|e| e.to_string())?;
        Ok((runtime, restart, sha256_hex(text.as_bytes())))
    };

    match attempt() {
        Ok((runtime, restart, sha)) => {
            let mode = runtime.cfg.mode.as_str();
            *state.runtime.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(runtime);
            info!(config = %path.display(), mode, "config reloaded");
            if !restart.is_empty() {
                warn!(
                    sections = restart.join(", "),
                    "these settings changed but only take effect after a restart"
                );
            }
            state.record_event("config_reload", format!("sha256={sha} mode={mode}"));
            // Ein neuer oder geänderter Presidio-Eintrag soll nicht bis zur
            // nächsten Runde der Aufsicht warten.
            state.presidio_wake.notify_one();
            Ok(())
        }
        Err(e) => {
            error!(config = %path.display(), error = %e, "config reload failed, keeping the previous config");
            state.record_event("config_reload_failed", e.clone());
            Err(e)
        }
    }
}

/// Beobachtet die Config-Datei (Änderungszeit) und lädt bei Änderung neu.
/// Auf Unix löst auch SIGHUP einen Reload aus.
pub fn spawn_reloader(state: Arc<AppState>, path: PathBuf) -> tokio::task::JoinHandle<()> {
    let mtime = |p: &Path| -> Option<SystemTime> { std::fs::metadata(p).ok()?.modified().ok() };
    tokio::spawn(async move {
        let mut last = mtime(&path);
        #[cfg(unix)]
        let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
        loop {
            #[cfg(unix)]
            let forced = match &mut hup {
                Some(h) => tokio::select! {
                    _ = h.recv() => true,
                    _ = tokio::time::sleep(Duration::from_secs(2)) => false,
                },
                None => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    false
                }
            };
            #[cfg(not(unix))]
            let forced = {
                tokio::time::sleep(Duration::from_secs(2)).await;
                false
            };

            let now = mtime(&path);
            if forced || (now.is_some() && now != last) {
                last = now;
                let _ = reload(&state, &path);
            }
        }
    })
}

/// Eine Runde der Presidio-Aufsicht: prüfen, ob Presidio da ist und kann,
/// was die Config verlangt; den eigenen Container starten, wenn er steht;
/// Zustandswechsel bezeugen. Liefert die Pause bis zur nächsten Runde.
pub async fn presidio_tick(state: &AppState) -> Duration {
    let rt = state.runtime();
    let Some(presidio) = rt.presidio.clone() else {
        return Duration::from_secs(30);
    };
    let state_now = presidio.probe().await;
    // Der eigene Container: starten, was da ist. Geholt oder umgebaut wird
    // hier nichts, das tut nur `hedge presidio enable | upgrade`.
    if state_now != PresidioState::Ready && rt.cfg.presidio.managed && state.sidecar_due() {
        match Sidecar::from_config(&rt.cfg.presidio) {
            Ok(sidecar) => match sidecar.ensure(Ensure::Start).await {
                Ok(Ensured::Running) => presidio.note_sidecar_ok(),
                Ok(Ensured::Started | Ensured::Created) => {
                    info!(
                        container = crate::presidio::sidecar::CONTAINER,
                        "started the presidio container, waiting for its language models"
                    );
                    presidio.note_starting("container started, loading language models");
                }
                Err(problem) => presidio.note_sidecar_problem(problem),
            },
            Err(problem) => presidio.note_sidecar_problem(problem),
        }
    }
    state.note_presidio(&presidio);
    presidio.next_probe_in()
}

/// Hält Presidio im Blick, solange Hedge läuft.
pub fn spawn_presidio_supervisor(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let pause = presidio_tick(&state).await;
            tokio::select! {
                _ = tokio::time::sleep(pause) => {}
                _ = state.presidio_wake.notified() => {}
            }
        }
    })
}

/// Der komplette Router. Separat, damit Integrationstests ihn ohne
/// echten Listener benutzen können.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/_hedge/status", get(control_status))
        .route("/_hedge/approvals", get(control_approvals))
        .route("/_hedge/approvals/{id}/{verdict}", post(control_resolve))
        .route("/{upstream}/{*rest}", any(proxy))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

/// Bereitschaft für Orchestrierung und Load Balancer: 200, wenn Hedge
/// Anfragen so bedient, wie die Config es verlangt; sonst 503 mit dem,
/// worauf es wartet. `/health` sagt nur, dass der Prozess lebt.
async fn ready(State(state): State<Arc<AppState>>) -> Response {
    match state.readiness() {
        Ok(()) => Json(json!({ "ready": true })).into_response(),
        Err(waiting) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ready": false, "waiting_for": waiting })),
        )
            .into_response(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("unknown upstream: {0}")]
    UnknownUpstream(String),

    #[error("request body could not be read: {0}")]
    Body(#[from] axum::Error),

    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),

    #[error("request blocked by hedge: {reason}")]
    Blocked { reason: String },

    #[error("request blocked by hedge: {reason}")]
    ModelNotAllowed { reason: String },

    #[error("request blocked by hedge: {reason}")]
    Budget { reason: String },

    #[error("request rejected by hedge: {reason}")]
    UnknownClient { reason: String },

    #[error("request held back by hedge: {reason}")]
    PresidioUnavailable { reason: String },
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let (status, kind) = match &self {
            Self::UnknownUpstream(_) => (StatusCode::NOT_FOUND, "hedge_unknown_upstream"),
            Self::Body(_) => (StatusCode::BAD_REQUEST, "hedge_bad_request"),
            Self::Upstream(_) => (StatusCode::BAD_GATEWAY, "hedge_upstream_error"),
            Self::Blocked { .. } => (StatusCode::FORBIDDEN, "hedge_blocked"),
            Self::ModelNotAllowed { .. } => (StatusCode::FORBIDDEN, "hedge_model_not_allowed"),
            Self::Budget { .. } => (StatusCode::TOO_MANY_REQUESTS, "hedge_budget_exceeded"),
            Self::UnknownClient { .. } => (StatusCode::UNAUTHORIZED, "hedge_unknown_client"),
            Self::PresidioUnavailable { .. } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "hedge_presidio_unavailable",
            ),
        };
        // Fehler im Format der LLM-APIs, damit Agents wie Claude Code die
        // Begründung dem Nutzer anzeigen statt eines nackten HTTP-Fehlers.
        error_response(status, kind, &self.to_string())
    }
}

fn error_response(status: StatusCode, kind: &str, message: &str) -> Response {
    let body = json!({
        "type": "error",
        "error": { "type": kind, "message": message }
    });
    (status, Json(body)).into_response()
}

fn model_allowed(models: &Models, model: &str) -> bool {
    let hit = |globs: &[String]| globs.iter().any(|g| glob_match(g, model));
    (models.allow.is_empty() || hit(&models.allow)) && !hit(&models.deny)
}

/// Session-Kennung aus Headern, falls der Body keine verrät.
fn session_from_headers(headers: &HeaderMap) -> Option<String> {
    ["x-claude-code-session-id", "session_id", "x-session-id"]
        .iter()
        .find_map(|h| headers.get(*h)?.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(session_label)
}

pub async fn proxy(
    State(state): State<Arc<AppState>>,
    UrlPath((upstream, rest)): UrlPath<(String, String)>,
    req: Request,
) -> Result<Response, ProxyError> {
    let started = Instant::now();
    let rt = state.runtime();

    let target = rt
        .cfg
        .upstream(&upstream)
        .ok_or_else(|| ProxyError::UnknownUpstream(upstream.clone()))?;

    let request_path = format!("/{rest}");
    let mut url = format!("{}{}", target.url.trim_end_matches('/'), request_path);
    if let Some(query) = req.uri().query() {
        url.push('?');
        url.push_str(query);
    }

    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let original = to_bytes(body, MAX_BODY_BYTES).await?;

    let mut rec = Record {
        upstream: upstream.clone(),
        method: method.as_str().to_owned(),
        path: request_path,
        mode: rt.cfg.mode.as_str().to_owned(),
        action: Action::Forward.as_str().to_owned(),
        body_sha256_in: sha256_hex(&original),
        ..Record::default()
    };

    // Wer fragt? (Central-Mode)
    rec.client = rt.client_of(&parts.headers);
    let budget_key = rec.client.clone().unwrap_or_else(|| LOCAL.to_owned());
    if rt.cfg.server.require_client && rec.client.is_none() {
        let reason = format!("missing or unknown client token (header {CLIENT_TOKEN_HEADER})");
        return Err(reject(
            &state,
            rec,
            started,
            &budget_key,
            reason,
            |reason| ProxyError::UnknownClient { reason },
        ));
    }

    let prepared = Prepared::parse(original.clone());
    if let Ok(p) = &prepared {
        rec.model = p.model().map(str::to_owned);
        rec.session = p.session();
    }
    if rec.session.is_none() {
        rec.session = session_from_headers(&parts.headers);
    }

    // Antwortet der Mensch gerade auf eine Freigabe-Frage? Nur was er selbst
    // in dieser Session getippt hat, zählt – und nur für Fragen aus ihr.
    if rt.tools.enforce()
        && rt.tools.approve_in_chat()
        && let Ok(p) = &prepared
    {
        for (verdict, id) in p
            .last_user_texts()
            .into_iter()
            .filter_map(parse_chat_command)
        {
            state.resolve_approval(&id, verdict, "chat", |info| {
                info.kind == "chat" && info.session == rec.session && info.client == rec.client
            });
        }
    }

    // Darf dieses Modell überhaupt angefragt werden?
    if let Some(model) = &rec.model
        && !model_allowed(&rt.cfg.models, model)
    {
        let reason = format!("model {model:?} is not allowed by policy");
        return Err(reject(
            &state,
            rec,
            started,
            &budget_key,
            reason,
            |reason| ProxyError::ModelNotAllowed { reason },
        ));
    }

    // Ist noch Budget da?
    if let Err(reason) = state
        .budgets
        .check(&budget_key, rec.session.as_deref(), &rt.cfg.budget)
    {
        return Err(reject(
            &state,
            rec,
            started,
            &budget_key,
            reason,
            |reason| ProxyError::Budget { reason },
        ));
    }

    // Inspektion: scannen, Regeln und Policy anwenden, ggf. maskieren.
    let outcome: Outcome = match prepared {
        Ok(p) => {
            let extra = match &rt.presidio {
                Some(presidio) => {
                    let texts = p.parts(&|part, path, text| presidio.wants(part, path, text));
                    let scan: Scan = presidio.scan_all(texts).await;
                    let fail_closed = rt.cfg.presidio_fail_closed();
                    state.note_presidio(presidio);
                    if let Some(t) = &state.telemetry {
                        t.presidio_scan(&scan, scan.gap.is_some() && fail_closed);
                    }
                    if let Some(gap) = &scan.gap {
                        presidio.count_unscanned();
                        rec.flags.push(gap.flag().into());
                        // Fail-closed: Was Presidio nicht prüfen konnte,
                        // verlässt das Haus nicht.
                        if fail_closed {
                            let reason = format!(
                                "{}. Nothing was sent to the model. The policy here is not to send prompts that could not be checked for names (presidio.on_unavailable = \"block\")",
                                gap.reason()
                            );
                            return Err(reject(
                                &state,
                                rec,
                                started,
                                &budget_key,
                                reason,
                                |reason| ProxyError::PresidioUnavailable { reason },
                            ));
                        }
                    }
                    Extra {
                        findings: scan.findings,
                        advisory: !rt.cfg.presidio.enforce,
                    }
                }
                None => Extra::default(),
            };
            p.finish(&rt.detectors, &rt.rules, rt.cfg.mode, &extra)
        }
        Err(body) => inspect(body, &rt.detectors, &rt.rules, rt.cfg.mode),
    };
    rec.findings = {
        let mut seen = state
            .seen_findings
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        outcome
            .findings
            .iter()
            .map(|l| {
                let mut f = FindingRecord::from(l);
                if !rt.cfg.witness.hints {
                    f.hint = None;
                }
                // Ohne Session gibt es kein "schon gesehen".
                if let Some(session) = &rec.session {
                    f.repeat = seen.is_repeat(session, l.fingerprint);
                }
                f
            })
            .collect()
    };
    rec.action = outcome.action.as_str().to_owned();

    // Abgleich: Jedes Tool-Ergebnis sollte zu einem Aufruf gehören, den
    // Hedge in einer Antwort gesehen hat.
    for id in &outcome.tool_results {
        let flag = match state.seen_tool(id) {
            None => "unwitnessed_tool_result",
            Some(true) => "result_for_denied_tool",
            Some(false) => continue,
        };
        if !rec.flags.iter().any(|f| f == flag) {
            rec.flags.push(flag.into());
        }
    }

    if outcome.action == Action::Block {
        let reason = outcome.reason.clone().unwrap_or_default();
        return Err(reject(
            &state,
            rec,
            started,
            &budget_key,
            reason,
            |reason| ProxyError::Blocked { reason },
        ));
    }
    if outcome.action == Action::Redact {
        rec.body_sha256_out = Some(sha256_hex(&outcome.body));
    }

    let mut headers = parts.headers;
    // Framing gehört dem Framework: Host, Länge und Chunking setzt reqwest neu.
    headers.remove(header::HOST);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::CONTENT_LENGTH);
    // Unkomprimiert anfordern, damit Hedge die Antwort mitlesen kann.
    headers.remove(header::ACCEPT_ENCODING);
    // Hedge-eigene Header gehen den Upstream nichts an.
    let own: Vec<_> = headers
        .keys()
        .filter(|k| k.as_str().starts_with("x-hedge-"))
        .cloned()
        .collect();
    for k in own {
        headers.remove(k);
    }

    let upstream_resp = match rt
        .client
        .request(method, url)
        .headers(headers)
        .body(outcome.body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            rec.detail = Some(format!("upstream unreachable: {}", root_cause(&e)));
            rec.aborted = true;
            state.complete(rec, started, &budget_key);
            return Err(ProxyError::Upstream(e));
        }
    };

    let status = upstream_resp.status();
    rec.status = Some(status.as_u16());
    let mut resp_headers = upstream_resp.headers().clone();
    resp_headers.remove(header::TRANSFER_ENCODING);
    resp_headers.remove(header::CONTENT_LENGTH);

    let content_type = resp_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let encoded = resp_headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.eq_ignore_ascii_case("identity"));
    let is_sse = content_type.starts_with("text/event-stream");
    let is_json = content_type.starts_with("application/json");
    let wants_analysis = rt.cfg.response.inspect || rt.tools.intervenes();
    if wants_analysis && encoded && (is_sse || is_json) {
        rec.flags.push("response_not_inspected".into());
    }
    let analyze = wants_analysis && !encoded;

    // Nicht gestreamte JSON-Antwort: ganz lesen, auswerten, ggf. umschreiben.
    if analyze && is_json {
        let bytes = match upstream_resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                rec.detail = Some(format!("upstream response error: {}", root_cause(&e)));
                rec.aborted = true;
                state.complete(rec, started, &budget_key);
                return Err(ProxyError::Upstream(e));
            }
        };
        let bytes = analyze_json_response(&state, &rt, &mut rec, bytes).await;
        state.complete(rec, started, &budget_key);
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() = status;
        *response.headers_mut() = resp_headers;
        return Ok(response);
    }

    // Alles andere wird gestreamt: SSE mit Auswertung, der Rest unbesehen.
    rec.stream = is_sse;
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    tokio::spawn(pump(
        upstream_resp,
        tx,
        Pump {
            state: state.clone(),
            rt,
            rec,
            started,
            budget_key,
            analyze: analyze && is_sse,
        },
    ));

    let mut response = Response::new(Body::from_stream(ReceiverStream::new(rx)));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    Ok(response)
}

/// Lehnt eine Anfrage ab, bevor sie den Upstream erreicht, und bezeugt das.
fn reject(
    state: &AppState,
    mut rec: Record,
    started: Instant,
    budget_key: &str,
    reason: String,
    make: impl FnOnce(String) -> ProxyError,
) -> ProxyError {
    rec.action = Action::Block.as_str().to_owned();
    rec.detail = Some(reason.clone());
    state.complete(rec, started, budget_key);
    make(reason)
}

fn root_cause(e: &dyn Error) -> String {
    let mut source = e;
    while let Some(next) = source.source() {
        source = next;
    }
    source.to_string()
}

struct Pump {
    state: Arc<AppState>,
    rt: Arc<Runtime>,
    rec: Record,
    started: Instant,
    budget_key: String,
    analyze: bool,
}

type Tx = mpsc::Sender<Result<Bytes, std::io::Error>>;

/// Reicht die Antwort Stück für Stück an den Client durch und liest dabei
/// mit. Läuft als eigene Task, damit der Client die ersten Bytes sieht,
/// sobald der Upstream sie schickt.
async fn pump(resp: reqwest::Response, tx: Tx, mut p: Pump) {
    let mut stream = Box::pin(resp.bytes_stream());
    let mut framer = SseFramer::default();
    let mut analyzer = p.analyze.then(|| Analyzer::new(p.rt.tools.intervenes()));
    let mut client_gone = false;

    'read: loop {
        let chunk = tokio::select! {
            c = stream.next() => c,
            // Client weg: nicht weiterlesen, das spart dem Nutzer Tokens.
            _ = tx.closed() => { client_gone = true; break 'read; }
        };
        let bytes = match chunk {
            None => break 'read,
            Some(Ok(b)) => b,
            Some(Err(e)) => {
                p.rec.aborted = true;
                p.rec.detail = Some(format!("upstream stream error: {}", root_cause(&e)));
                let _ = tx.send(Err(std::io::Error::other(e))).await;
                break 'read;
            }
        };

        let Some(a) = analyzer.as_mut() else {
            if tx.send(Ok(bytes)).await.is_err() {
                client_gone = true;
                break 'read;
            }
            continue;
        };

        framer.push(&bytes);
        while let Some(event) = framer.next_event() {
            for step in a.on_event(event) {
                match step {
                    Step::Forward(b) => {
                        if tx.send(Ok(b)).await.is_err() {
                            client_gone = true;
                            break 'read;
                        }
                    }
                    Step::Text { index, text } => {
                        scan_response(&p.rt, &mut p.rec, index, "text", &text);
                    }
                    Step::Tool(call) => {
                        scan_response(
                            &p.rt,
                            &mut p.rec,
                            call.index,
                            "input",
                            &subject(&call.input),
                        );
                        let (record, verdict) =
                            judge_tool(&p.state, &p.rt, &p.rec, &call, Some((&tx, &mut *a))).await;
                        p.rec.tools.push(record);
                        let out: Vec<Bytes> = match verdict {
                            ToolVerdict::Pass => {
                                call.events.into_iter().map(|e| a.reindex(e)).collect()
                            }
                            ToolVerdict::Replace(text) => {
                                a.mark_denied();
                                vec![replacement_events(a.shifted(call.index), &text)]
                            }
                            ToolVerdict::ClientGone => {
                                client_gone = true;
                                break 'read;
                            }
                        };
                        for b in out {
                            if tx.send(Ok(b)).await.is_err() {
                                client_gone = true;
                                break 'read;
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(mut a) = analyzer {
        if !client_gone {
            for b in a.drain_pending() {
                let _ = tx.send(Ok(b)).await;
            }
            if let Some(rest) = framer.take_rest() {
                let _ = tx.send(Ok(rest)).await;
            }
        }
        p.rec.tokens_in = a.usage.input;
        p.rec.tokens_out = a.usage.output;
        p.rec.tokens_cached = a.usage.cached;
        p.rec.stop_reason = a.stop_reason.take();
        if let Some(e) = a.error.take() {
            p.rec.detail = Some(format!("upstream error event: {e}"));
        }
    }
    if client_gone {
        p.rec.aborted = true;
        if p.rec.detail.is_none() {
            p.rec.detail = Some("client disconnected".into());
        }
    }
    drop(tx);
    p.state.complete(p.rec, p.started, &p.budget_key);
}

/// Wertet eine vollständige JSON-Antwort aus und schreibt sie um, falls
/// ein Tool-Aufruf verworfen wird.
async fn analyze_json_response(
    state: &AppState,
    rt: &Arc<Runtime>,
    rec: &mut Record,
    bytes: Bytes,
) -> Bytes {
    let Ok(mut doc) = serde_json::from_slice::<Value>(&bytes) else {
        return bytes;
    };
    let Some(summary) = summarize_message(&doc) else {
        return bytes;
    };
    rec.tokens_in = summary.usage.input;
    rec.tokens_out = summary.usage.output;
    rec.tokens_cached = summary.usage.cached;
    rec.stop_reason = summary.stop_reason;
    for (index, text) in &summary.texts {
        scan_response(rt, rec, *index, "text", text);
    }
    let mut changed = false;
    for call in summary.tools {
        scan_response(rt, rec, call.index, "input", &subject(&call.input));
        let (record, verdict) = judge_tool(state, rt, rec, &call, None).await;
        rec.tools.push(record);
        if let ToolVerdict::Replace(text) = verdict {
            deny_in_message(&mut doc, call.index, &text);
            changed = true;
        }
    }
    if !changed {
        return bytes;
    }
    rec.stop_reason = doc
        .get("stop_reason")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Bytes::from(serde_json::to_vec(&doc).expect("serde_json::Value is always serializable"))
}

/// Funde in der Antwort des Modells. Nur beobachtend: Was der Client schon
/// bekommen hat, lässt sich nicht mehr maskieren.
fn scan_response(rt: &Runtime, rec: &mut Record, index: u64, field: &str, text: &str) {
    if !rt.cfg.response.inspect || text.is_empty() {
        return;
    }
    for f in rt.rules.apply(text, rt.detectors.scan(text)) {
        let mut record = FindingRecord::new(
            f.kind,
            f.severity.as_str(),
            &format!("content[{index}].{field}"),
        );
        if rt.cfg.witness.hints {
            record.hint = hint_for(&f, &text[f.start..f.end]);
        }
        rec.response_findings.push(record);
    }
}

enum ToolVerdict {
    /// Aufruf geht (unverändert) an den Agent.
    Pass,
    /// Aufruf wird durch diesen Text ersetzt.
    Replace(String),
    /// Der Client hat die Verbindung beendet, während gewartet wurde.
    ClientGone,
}

/// Kurze, maskierte Fassung für Menschen. Nie länger als `max` Zeichen,
/// Secrets darin werden wie im Request ersetzt.
fn preview(rt: &Runtime, text: &str, max: usize) -> String {
    // Erst grob kürzen (an einer Zeichengrenze), damit der Scan billig bleibt.
    let mut end = text.len().min(4096);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut s = text[..end].to_owned();
    let found = rt.rules.apply(&s, rt.detectors.scan(&s));
    redact(&mut s, &found);
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() > max {
        let cut: String = flat.chars().take(max).collect();
        format!("{cut}…")
    } else {
        flat
    }
}

/// „5 min“, „90 s“ – für Texte an Menschen.
fn human_ttl(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 120 && secs.is_multiple_of(60) {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

/// Die Frage, die im Gespräch anstelle des Tool-Aufrufs erscheint.
fn hold_question(
    tool: &str,
    shown: &str,
    rule: &str,
    reason: &str,
    id: &str,
    ttl: Duration,
) -> String {
    format!(
        "⏸ Hedge paused this tool call. It needs your approval before it runs.\n\n    \
         {tool}: {shown}\n\n\
         Rule {rule}: {reason}\n\n\
         To allow it once, reply with exactly:  approve {id}\n\
         To refuse it, reply with:  deny {id}\n\
         (`hedge approve {id}` in a terminal works too; then tell me to continue.) \
         This request expires in {ttl}.\n\n\
         [Note to the assistant: this tool call was NOT executed and your turn ends here. \
         Do not retry or rephrase it on your own. If the user's next message is \
         \"approve {id}\", issue exactly the same tool call again; it will then go through \
         once. Otherwise leave it.]",
        ttl = human_ttl(ttl),
    )
}

/// Der Hinweis, der im Stream steht, während ein Aufruf auf Freigabe wartet.
fn hold_notice(
    tool: &str,
    shown: &str,
    rule: &str,
    reason: &str,
    id: &str,
    ttl: Duration,
) -> String {
    format!(
        "⏸ Hedge paused this tool call. It is waiting for approval.\n\n    \
         {tool}: {shown}\n\n\
         Rule {rule}: {reason}\n\n\
         Approve it in a terminal with `hedge approve {id}` (reject: `hedge deny {id}`). \
         Without a decision it is rejected in {ttl}.\n\n",
        ttl = human_ttl(ttl),
    )
}

/// Gibt Bescheid, dass eine Freigabe ansteht: Kommando und/oder Webhook.
/// Läuft nebenher; ein Fehler hier darf den Aufruf nie aufhalten.
fn notify(rt: &Arc<Runtime>, info: &ApprovalInfo) {
    let cfg = &rt.cfg.tools;
    if let Some(command) = cfg.notify_command.clone() {
        let vars = [
            ("HEDGE_APPROVAL_ID", info.id.clone()),
            ("HEDGE_APPROVAL_KIND", info.kind.clone()),
            ("HEDGE_TOOL", info.tool.clone()),
            ("HEDGE_PREVIEW", info.preview.clone()),
            ("HEDGE_RULE", info.rule.clone()),
            ("HEDGE_REASON", info.reason.clone()),
            ("HEDGE_SESSION", info.session.clone().unwrap_or_default()),
            ("HEDGE_CLIENT", info.client.clone().unwrap_or_default()),
            ("HEDGE_MODEL", info.model.clone().unwrap_or_default()),
            ("HEDGE_EXPIRES_IN_SECS", info.expires_in_secs.to_string()),
        ];
        tokio::spawn(async move {
            // Die Werte kommen als Umgebungsvariablen, nie als Teil der
            // Kommandozeile: Was das Modell geschrieben hat, wird so nicht
            // von der Shell interpretiert.
            let run = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&command)
                .envs(vars)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .status();
            match tokio::time::timeout(Duration::from_secs(10), run).await {
                Ok(Ok(status)) if status.success() => {}
                Ok(Ok(status)) => warn!(%status, "tools.notify_command failed"),
                Ok(Err(e)) => warn!(error = %e, "tools.notify_command could not be started"),
                Err(_) => warn!("tools.notify_command took longer than 10s and was stopped"),
            }
        });
    }
    if let Some(url) = cfg.notify_webhook.clone() {
        let how = if info.kind == "chat" {
            format!(
                "reply `approve {id}` in the session or run `hedge approve {id}`",
                id = info.id
            )
        } else {
            format!(
                "run `hedge approve {id}` (reject: `hedge deny {id}`)",
                id = info.id
            )
        };
        let who = match (&info.client, &info.session) {
            (Some(c), Some(s)) => format!(" ({c}/{s})"),
            (Some(c), None) => format!(" ({c})"),
            (None, Some(s)) => format!(" (session {s})"),
            (None, None) => String::new(),
        };
        // `text` versteht jeder Slack-kompatible Webhook; der Rest ist für
        // eigene Empfänger.
        let body = json!({
            "text": format!(
                "⏸ Hedge: {tool} needs approval{who}\n> {preview}\nRule {rule}: {reason}\nTo allow: {how}",
                tool = info.tool, preview = info.preview, rule = info.rule, reason = info.reason,
            ),
            "approval": info,
        });
        let rt = rt.clone();
        tokio::spawn(async move {
            let sent = rt
                .client
                .post(&url)
                .timeout(Duration::from_secs(5))
                .json(&body)
                .send()
                .await;
            match sent {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => warn!(status = %r.status(), "tools.notify_webhook answered with an error"),
                Err(e) => warn!(error = %root_cause(&e), "tools.notify_webhook unreachable"),
            }
        });
    }
}

/// Wendet die Tool-Policy auf einen Aufruf an.
///
/// Bei `hold` gibt es zwei Wege: Im Gespräch (`approve_in_chat`) endet der
/// Zug mit einer Frage, und die Antwort des Menschen erlaubt genau diesen
/// Aufruf einmal. Sonst wartet die Funktion auf eine Entscheidung über die
/// Steuer-API, zeigt vorher einen Hinweis im Stream und hält die Verbindung
/// mit Pings offen.
async fn judge_tool(
    state: &AppState,
    rt: &Arc<Runtime>,
    rec: &Record,
    call: &ToolCall,
    mut stream: Option<(&Tx, &mut Analyzer)>,
) -> (ToolRecord, ToolVerdict) {
    let input_json = serde_json::to_vec(&call.input).unwrap_or_default();
    let mut record = ToolRecord {
        id: call.id.clone(),
        name: call.name.clone(),
        input_sha256: sha256_hex(&input_json),
        preview: rt
            .cfg
            .witness
            .tool_preview
            .then(|| first_string(&call.input).map(|s| preview(rt, s, 120)))
            .flatten(),
        rule: None,
        decision: "allow".into(),
        approval: None,
    };
    state.remember_tool(&call.id, false);

    let Some(hit) = rt.tools.evaluate(&call.name, &call.input) else {
        return (record, ToolVerdict::Pass);
    };
    record.rule = Some(hit.rule_id.clone());
    let shown = preview(rt, &display(&call.input), 300);

    if hit.action == ToolAction::Allow {
        return (record, ToolVerdict::Pass);
    }
    if !rt.tools.enforce() {
        record.decision = "flag".into();
        return (record, ToolVerdict::Pass);
    }

    let denial = |what: &str| {
        format!(
            "[hedge] The tool call {name} was {what} (policy {rule}: {reason}). It was NOT executed. \
             Do not retry it in another form. Tell the user what you intended to do and why, \
             and let them decide.",
            name = call.name,
            rule = hit.rule_id,
            reason = hit.reason,
        )
    };
    let ttl = rt.tools.approval_timeout();
    let request = || ApprovalInfo {
        id: String::new(),
        created: String::new(),
        expires_in_secs: ttl.as_secs(),
        upstream: rec.upstream.clone(),
        client: rec.client.clone(),
        session: rec.session.clone(),
        model: rec.model.clone(),
        tool: call.name.clone(),
        preview: shown.clone(),
        rule: hit.rule_id.clone(),
        reason: hit.reason.clone(),
        kind: String::new(),
    };
    let key = GrantKey {
        session: format!(
            "{}/{}",
            rec.client.as_deref().unwrap_or("-"),
            rec.session.as_deref().unwrap_or("-")
        ),
        tool: call.name.clone(),
        input_sha256: approval_fingerprint(&call.input),
    };
    let announce = |id: &str| {
        if let Some(info) = state.approvals.list().into_iter().find(|i| i.id == id) {
            notify(rt, &info);
        }
    };

    match hit.action {
        ToolAction::Deny => {
            record.decision = "deny".into();
            state.remember_tool(&call.id, true);
            warn!(
                tool = %call.name, rule = %hit.rule_id, session = rec.session.as_deref().unwrap_or("-"),
                input = %shown, "tool call denied"
            );
            (record, ToolVerdict::Replace(denial("blocked")))
        }
        ToolAction::Hold if rt.tools.approve_in_chat() => {
            // Hat der Mensch genau diesen Aufruf gerade freigegeben?
            if let Some(id) = state.approvals.take_grant(&key) {
                record.decision = "approved".into();
                record.approval = Some(id.clone());
                info!(approval = %id, tool = %call.name, rule = %hit.rule_id, "approved tool call passes");
                return (record, ToolVerdict::Pass);
            }
            let (id, new) = state.approvals.defer(request(), key, ttl);
            record.decision = "held".into();
            record.approval = Some(id.clone());
            state.remember_tool(&call.id, true);
            if new {
                warn!(
                    approval = %id, tool = %call.name, rule = %hit.rule_id,
                    session = rec.session.as_deref().unwrap_or("-"), input = %shown,
                    "tool call HELD – asked in the session; reply `approve {id}` there or run `hedge approve {id}` (expires in {})",
                    human_ttl(ttl)
                );
                announce(&id);
            }
            (
                record,
                ToolVerdict::Replace(hold_question(
                    &call.name,
                    &shown,
                    &hit.rule_id,
                    &hit.reason,
                    &id,
                    ttl,
                )),
            )
        }
        ToolAction::Hold if !state.has_control_token() => {
            record.decision = "rejected".into();
            state.remember_tool(&call.id, true);
            warn!(
                tool = %call.name, rule = %hit.rule_id,
                "tool call needs approval but no control token exists (run `hedge init`); rejecting"
            );
            (
                record,
                ToolVerdict::Replace(denial(
                    "held for human approval, which is not set up, and therefore rejected",
                )),
            )
        }
        ToolAction::Hold => {
            let (id, mut rx) = state.approvals.request(request(), key, ttl);
            record.approval = Some(id.clone());
            warn!(
                approval = %id, tool = %call.name, rule = %hit.rule_id,
                session = rec.session.as_deref().unwrap_or("-"), input = %shown,
                "tool call HELD – approve with `hedge approve {id}` or reject with `hedge deny {id}` (auto-reject in {})",
                human_ttl(ttl)
            );
            // Sofort sichtbar machen: im Witness (hedge tail -f), bei den
            // konfigurierten Empfängern und im Gespräch selbst.
            state.record_event_for(
                "hold",
                match &record.preview {
                    Some(p) => format!("{id} waiting · {}: {p} · {}", call.name, hit.rule_id),
                    None => format!("{id} waiting · {} · {}", call.name, hit.rule_id),
                },
                rec.client.as_deref(),
                rec.session.as_deref(),
            );
            announce(&id);
            let gone = |record: &mut ToolRecord| {
                state.approvals.cancel(&id);
                record.decision = "timeout".into();
                state.remember_tool(&call.id, true);
            };
            if let Some((tx, analyzer)) = stream.as_mut() {
                let text = hold_notice(&call.name, &shown, &hit.rule_id, &hit.reason, &id, ttl);
                let block = analyzer.notice_block(call.index, &text);
                if tx.send(Ok(block)).await.is_err() {
                    gone(&mut record);
                    return (record, ToolVerdict::ClientGone);
                }
            }

            let deadline = tokio::time::sleep(ttl);
            tokio::pin!(deadline);
            let mut ping = tokio::time::interval(Duration::from_secs(10));
            ping.tick().await;
            let verdict = loop {
                tokio::select! {
                    v = &mut rx => break v.ok(),
                    _ = &mut deadline => {
                        state.approvals.cancel(&id);
                        break None;
                    }
                    _ = ping.tick() => {
                        if let Some((tx, _)) = stream.as_ref()
                            && tx.send(Ok(ping_event())).await.is_err()
                        {
                            gone(&mut record);
                            return (record, ToolVerdict::ClientGone);
                        }
                    }
                }
            };
            match verdict {
                Some(Verdict::Approved) => {
                    record.decision = "approved".into();
                    (record, ToolVerdict::Pass)
                }
                Some(Verdict::Rejected) => {
                    record.decision = "rejected".into();
                    state.remember_tool(&call.id, true);
                    (
                        record,
                        ToolVerdict::Replace(denial("rejected by a human reviewer")),
                    )
                }
                None => {
                    record.decision = "timeout".into();
                    state.remember_tool(&call.id, true);
                    warn!(approval = %id, tool = %call.name, "tool call approval timed out");
                    state.record_event_for(
                        "approval",
                        format!(
                            "{id} timed out after {} · {} · {}",
                            human_ttl(ttl),
                            call.name,
                            hit.rule_id
                        ),
                        rec.client.as_deref(),
                        rec.session.as_deref(),
                    );
                    (
                        record,
                        ToolVerdict::Replace(format!(
                            "[hedge] The tool call {name} was held for human approval (policy {rule}: {reason}) \
                             and nobody decided within {ttl}. It was NOT executed. Do not retry it on your own. \
                             Tell the user that it needs `hedge approve <id>` while it is waiting, and let them \
                             decide whether to try again.",
                            name = call.name,
                            rule = hit.rule_id,
                            reason = hit.reason,
                            ttl = human_ttl(ttl),
                        )),
                    )
                }
            }
        }
        ToolAction::Allow => unreachable!("handled above"),
    }
}

/// Eine Zeile pro Anfrage. Funde nur als `kind@pfad`, nie als Text.
///
/// Für Menschen (`pretty`) steht alles Wesentliche kompakt in der Meldung,
/// leere Angaben entfallen. Für Maschinen (`json`) gibt es feste Felder.
fn log_record(rec: &Record, pretty: bool) {
    let flagged_tools: Vec<String> = rec
        .tools
        .iter()
        .filter(|t| t.rule.is_some() && t.decision != "allow")
        .map(|t| {
            format!(
                "{}:{}:{}",
                t.name,
                t.decision,
                t.rule.as_deref().unwrap_or("-")
            )
        })
        .collect();
    let stopped = rec.tools.iter().any(|t| stopped(&t.decision));
    let held = rec.tools.iter().any(|t| t.decision == "held");

    #[derive(Clone, Copy)]
    enum Lvl {
        Info,
        Warn,
        Error,
    }
    let new_findings = rec.findings.iter().any(|f| !f.repeat);
    let (level, what) = if rec.action == "block" {
        (Lvl::Error, "blocked request")
    } else if stopped {
        (Lvl::Error, "forwarded, tool call stopped")
    } else if held {
        (Lvl::Warn, "forwarded, tool call held for approval")
    } else if rec.action == "redact" && new_findings {
        (Lvl::Warn, "redacted findings, forwarded masked body")
    } else if new_findings {
        (Lvl::Warn, "observed findings, forwarded unchanged")
    } else if !flagged_tools.is_empty()
        || !rec.response_findings.is_empty()
        || !rec.flags.is_empty()
    {
        (Lvl::Warn, "forwarded with notes")
    } else if rec.aborted {
        (Lvl::Warn, "forwarded, stream ended early")
    } else if rec.action == "redact" {
        // Nur Bekanntes aus der mitgeschickten Historie: maskiert, aber kein Alarm.
        (Lvl::Info, "forwarded, known findings masked again")
    } else {
        (Lvl::Info, "forwarded")
    };

    if pretty {
        let mut line = format!("{what}: {} {} {}", rec.upstream, rec.method, rec.path);
        let mut add = |label: &str, value: String| {
            if !value.is_empty() {
                line.push_str(&format!(" {label}={value}"));
            }
        };
        add("model", rec.model.clone().unwrap_or_default());
        add("session", rec.session.clone().unwrap_or_default());
        add("client", rec.client.clone().unwrap_or_default());
        add(
            "status",
            rec.status.map(|s| s.to_string()).unwrap_or_default(),
        );
        add("ms", rec.duration_ms.to_string());
        if rec.tokens_in.is_some() || rec.tokens_out.is_some() {
            add(
                "tokens",
                format!(
                    "{}/{}",
                    rec.tokens_in.unwrap_or(0),
                    rec.tokens_out.unwrap_or(0)
                ),
            );
        }
        add("prompt", summarize(&rec.findings));
        let known = rec.findings.iter().filter(|f| f.repeat).count();
        if known > 0 {
            add("known", known.to_string());
        }
        add("answer", summarize(&rec.response_findings));
        if !rec.tools.is_empty() {
            add("tools", rec.tools.len().to_string());
        }
        add("tool_hits", flagged_tools.join(","));
        add("flags", rec.flags.join(","));
        add("why", rec.detail.clone().unwrap_or_default());
        match level {
            Lvl::Info => info!("{line}"),
            Lvl::Warn => warn!("{line}"),
            Lvl::Error => error!("{line}"),
        }
        return;
    }

    macro_rules! emit {
        ($level:ident) => {
            $level!(
                upstream = %rec.upstream, method = %rec.method, path = %rec.path,
                model = rec.model.as_deref().unwrap_or(""),
                session = rec.session.as_deref().unwrap_or(""),
                client = rec.client.as_deref().unwrap_or(""),
                status = rec.status.unwrap_or(0), duration_ms = rec.duration_ms,
                tokens_in = rec.tokens_in.unwrap_or(0), tokens_out = rec.tokens_out.unwrap_or(0),
                tokens_cached = rec.tokens_cached.unwrap_or(0),
                action = %rec.action,
                findings = rec.findings.iter().filter(|f| !f.repeat).count(),
                findings_repeated = rec.findings.iter().filter(|f| f.repeat).count(),
                r#where = %summarize(&rec.findings),
                response_findings = %summarize(&rec.response_findings),
                tools = rec.tools.len(), tool_hits = %flagged_tools.join(","),
                flags = %rec.flags.join(","), aborted = rec.aborted,
                detail = rec.detail.as_deref().unwrap_or(""),
                "{what}"
            )
        };
    }
    match level {
        Lvl::Info => emit!(info),
        Lvl::Warn => emit!(warn),
        Lvl::Error => emit!(error),
    }
}

/// Neue Funde als `kind(severity)@pfad`; schon bekannte bleiben draußen.
fn summarize(findings: &[FindingRecord]) -> String {
    findings
        .iter()
        .filter(|f| !f.repeat)
        .map(|f| match &f.hint {
            Some(h) => format!("{}({}, {h})@{}", f.kind, f.severity, f.path),
            None => format!("{}({})@{}", f.kind, f.severity, f.path),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------- Steuer-API ----------

/// Vergleich in konstanter Zeit, damit die Antwortzeit nichts über das
/// Token verrät.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `None` = berechtigt; sonst die fertige Fehlerantwort.
fn denied(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let Some(expected) = &state.control_token else {
        return Some(error_response(
            StatusCode::FORBIDDEN,
            "hedge_control_disabled",
            "control API is disabled: no control token found (run `hedge init`, then restart hedge)",
        ));
    };
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if constant_time_eq(given.trim().as_bytes(), expected.as_bytes()) {
        None
    } else {
        Some(error_response(
            StatusCode::UNAUTHORIZED,
            "hedge_unauthorized",
            "missing or wrong control token",
        ))
    }
}

async fn control_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match denied(&state, &headers) {
        Some(r) => r,
        None => Json(state.status()).into_response(),
    }
}

async fn control_approvals(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match denied(&state, &headers) {
        Some(r) => r,
        None => Json(state.approvals.list()).into_response(),
    }
}

async fn control_resolve(
    State(state): State<Arc<AppState>>,
    UrlPath((id, verdict)): UrlPath<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Some(r) = denied(&state, &headers) {
        return r;
    }
    let verdict = match verdict.as_str() {
        "approve" => Verdict::Approved,
        "deny" => Verdict::Rejected,
        other => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "hedge_bad_request",
                &format!("unknown verdict {other:?} (use approve or deny)"),
            );
        }
    };
    match state.resolve_approval(&id, verdict, "control api", |_| true) {
        Some(info) => Json(json!({ "resolved": info, "verdict": match verdict {
            Verdict::Approved => "approved",
            Verdict::Rejected => "rejected",
        }}))
        .into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            "hedge_unknown_approval",
            &format!("no pending approval with id {id:?} (already decided or timed out?)"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_allow_and_deny_globs() {
        let m = |allow: &[&str], deny: &[&str]| Models {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        };
        assert!(model_allowed(&m(&[], &[]), "anything"));
        assert!(model_allowed(&m(&["claude-*"], &[]), "claude-opus-4"));
        assert!(!model_allowed(&m(&["claude-*"], &[]), "gpt-5"));
        assert!(!model_allowed(
            &m(&["claude-*"], &["*-opus-*"]),
            "claude-opus-4"
        ));
        assert!(model_allowed(&m(&[], &["gpt-*"]), "claude-haiku"));
    }

    #[test]
    fn constant_time_eq_compares_content_and_length() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn seen_tools_is_bounded_and_tracks_denials() {
        let mut s = SeenTools::default();
        s.remember("a", false);
        s.remember("b", true);
        s.remember("a", true);
        assert_eq!(s.known.get("a"), Some(&true));
        assert_eq!(s.order.len(), 2, "re-remembering does not grow the queue");
        s.remember("", false);
        assert_eq!(s.order.len(), 2);
    }

    #[test]
    fn preview_masks_secrets_and_truncates() {
        let rt = Runtime::build(Config::default()).unwrap();
        let key = format!("sk-ant-{}", "x".repeat(24));
        let p = preview(&rt, &format!("curl -H 'x-api-key: {key}' https://api"), 200);
        assert!(!p.contains("sk-ant-"), "{p}");
        assert!(p.contains("[REDACTED:anthropic_api_key]"));

        let long = "ä".repeat(500);
        let p = preview(&rt, &long, 50);
        assert_eq!(p.chars().count(), 51, "50 chars plus ellipsis");

        assert_eq!(preview(&rt, "a\nb\tc", 50), "a b c");
    }

    #[test]
    fn session_from_headers_uses_uuid_prefix() {
        let mut h = HeaderMap::new();
        assert_eq!(session_from_headers(&h), None);
        h.insert(
            "x-claude-code-session-id",
            "3f2a9c1e-aaaa-bbbb-cccc-dddddddddddd".parse().unwrap(),
        );
        assert_eq!(session_from_headers(&h).as_deref(), Some("3f2a9c1e"));
    }
}
