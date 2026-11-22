//! Konfiguration von Hedge (`hedge.toml`).
//!
//! Alles außer dem Modus hat Defaults, damit eine minimale Datei reicht.
//! Unbekannte Felder sind Fehler (`deny_unknown_fields`): Ein Tippfehler in
//! einer Policy soll Hedge am Start hindern, nicht still ignoriert werden.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::detect::Severity;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// observe (nur melden), redact (maskieren), block (ablehnen ab High).
    pub mode: Mode,
    pub server: Server,
    pub upstreams: Vec<Upstream>,
    pub timeouts: Timeouts,
    pub detectors: DetectorToggles,
    /// Severity-Overrides pro `kind`, z. B. `email = "low"`.
    pub severity: BTreeMap<String, Severity>,
    pub allow: Allow,
    pub log: Log,
    pub witness: Witness,
    /// Inspektion der Modell-Antworten (nur beobachtend).
    pub response: ResponseCfg,
    /// Regeln für Tool-Aufrufe des Modells (deny / hold / allow).
    pub tools: ToolsCfg,
    pub models: Models,
    pub budget: Budget,
    /// Bekannte Clients im Central-Mode.
    pub clients: Vec<Client>,
    pub control: Control,
    pub telemetry: Telemetry,
    pub presidio: Presidio,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            server: Server::default(),
            upstreams: vec![
                Upstream {
                    name: "anthropic".into(),
                    url: "https://api.anthropic.com".into(),
                },
                Upstream {
                    name: "openai".into(),
                    url: "https://api.openai.com".into(),
                },
            ],
            timeouts: Timeouts::default(),
            detectors: DetectorToggles::default(),
            severity: BTreeMap::new(),
            allow: Allow::default(),
            log: Log::default(),
            witness: Witness::default(),
            response: ResponseCfg::default(),
            tools: ToolsCfg::default(),
            models: Models::default(),
            budget: Budget::default(),
            clients: Vec::new(),
            control: Control::default(),
            telemetry: Telemetry::default(),
            presidio: Presidio::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    pub listen: String,
    /// Central-Mode: Anfragen ohne gültiges Client-Token ablehnen.
    pub require_client: bool,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:18765".into(),
            require_client: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Timeouts {
    /// Verbindungsaufbau zum Upstream.
    pub connect_secs: u64,
    /// Gesamte Anfrage inkl. Antwort. LLM-Antworten dauern, deshalb großzügig.
    pub request_secs: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect_secs: 10,
            request_secs: 600,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DetectorToggles {
    pub secrets: bool,
    pub pii: bool,
}

impl Default for DetectorToggles {
    fn default() -> Self {
        Self {
            secrets: true,
            pii: true,
        }
    }
}

/// Werte, die nie als Fund gelten. Gedacht für die eigene Infrastruktur:
/// die eigene E-Mail-Adresse, die Firmen-Domain.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Allow {
    /// Exakte Treffer (case-insensitive).
    pub values: Vec<String>,
    /// E-Mail-Adressen dieser Domains (inkl. Subdomains) sind erlaubt.
    pub domains: Vec<String>,
}

impl Allow {
    pub fn is_allowed(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        if self.values.iter().any(|v| v.to_ascii_lowercase() == lower) {
            return true;
        }
        if let Some((_, domain)) = lower.rsplit_once('@') {
            return self.domains.iter().any(|d| {
                let d = d.to_ascii_lowercase();
                domain == d || domain.ends_with(&format!(".{d}"))
            });
        }
        false
    }

    pub fn value_set(&self) -> HashSet<String> {
        self.values.iter().map(|v| v.to_ascii_lowercase()).collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    /// pretty (für Menschen am Terminal) oder json (für zentrale Log-Systeme).
    pub format: LogFormat,
    /// tracing-Filter, z. B. "info" oder "hedge=debug".
    pub level: String,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            format: LogFormat::Pretty,
            level: "info".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
}

/// Das bezeugte Protokoll: eine signierte Hash-Kette aller Anfragen.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Witness {
    pub enabled: bool,
    /// Append-only JSONL-Datei. `~` wird expandiert.
    pub path: String,
    /// Ed25519-Signierschlüssel (hex, 32 Byte). Erzeugt `hedge init`.
    pub key: String,
    /// Kurze, maskierte Vorschau jedes Tool-Aufrufs mitschreiben
    /// (z. B. `git status`). Aus = nur Name und Hash der Eingabe.
    pub tool_preview: bool,
    /// Maskierten Hinweis pro Fund mitschreiben (`p…@example.com`, `…a1b2`),
    /// damit ein Mensch erkennt, welche Adresse oder welcher Key gemeint ist.
    pub hints: bool,
}

impl Default for Witness {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "~/.hedge/witness.jsonl".into(),
            key: "~/.hedge/witness.key".into(),
            tool_preview: true,
            hints: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResponseCfg {
    /// Modell-Antworten auf Secrets/PII prüfen und Tool-Aufrufe erfassen.
    pub inspect: bool,
}

impl Default for ResponseCfg {
    fn default() -> Self {
        Self { inspect: true }
    }
}

/// Was mit einem Tool-Aufruf passiert, auf den eine Regel passt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolAction {
    /// Ausdrücklich erlauben (beendet die Regelprüfung).
    Allow,
    /// Aufruf verwerfen; das Modell bekommt die Begründung.
    Deny,
    /// Anhalten, bis ein Mensch freigibt (`hedge approve <id>`).
    Hold,
}

impl ToolAction {
    pub fn as_str(self) -> &'static str {
        match self {
            ToolAction::Allow => "allow",
            ToolAction::Deny => "deny",
            ToolAction::Hold => "hold",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRuleCfg {
    /// Stabile Kennung, erscheint in Log, Witness und Meldung ans Modell.
    pub id: String,
    /// Glob auf den Tool-Namen, mehrere mit `|` (Standard: alle).
    #[serde(default = "star")]
    pub tool: String,
    /// Regex auf die Eingabe des Tools (alle String-Werte, zeilenweise).
    /// Ohne `match` trifft die Regel jeden Aufruf des Tools.
    #[serde(default, rename = "match")]
    pub pattern: Option<String>,
    pub action: ToolAction,
    #[serde(default)]
    pub reason: Option<String>,
}

fn star() -> String {
    "*".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ToolsCfg {
    /// false: Treffer nur melden (flag). true: deny/hold durchsetzen.
    pub enforce: bool,
    /// Eingebaute Regelpakete: destructive-shell, credential-files, exfiltration.
    pub packs: Vec<String>,
    /// Wie lange eine Freigabe-Anfrage (und die erteilte Erlaubnis) gilt.
    pub approval_timeout_secs: u64,
    /// true: Hedge fragt in der Agent-Session; die Antwort `approve <id>`
    /// dort gibt frei. false: Der Aufruf wartet auf `hedge approve <id>`.
    pub approve_in_chat: bool,
    /// Shell-Kommando, das bei jeder Freigabe-Anfrage läuft (HEDGE_*-Variablen).
    pub notify_command: Option<String>,
    /// URL, an die jede Freigabe-Anfrage als JSON geht (Slack-kompatibel).
    pub notify_webhook: Option<String>,
    /// Eigene Regeln, werden vor den Paketen geprüft; erste passende gewinnt.
    pub rules: Vec<ToolRuleCfg>,
}

impl Default for ToolsCfg {
    fn default() -> Self {
        Self {
            enforce: false,
            packs: vec![
                "destructive-shell".into(),
                "credential-files".into(),
                "exfiltration".into(),
            ],
            approval_timeout_secs: 300,
            approve_in_chat: true,
            notify_command: None,
            notify_webhook: None,
            rules: Vec::new(),
        }
    }
}

/// Welche Modelle angefragt werden dürfen. Globs mit `*`. Leer = alle.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Models {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// Token-Budgets (Input ohne Cache-Reads + Output). 0 = unbegrenzt.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Budget {
    /// Pro Client und UTC-Tag.
    pub daily_tokens: u64,
    /// Pro Agent-Session.
    pub session_tokens: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub name: String,
    /// SHA-256 (hex) des Client-Tokens. Das Token selbst steht nie in der Config.
    pub token_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Control {
    /// Token für die Steuer-API (Freigaben, Status). Erzeugt `hedge init`.
    pub token: String,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            token: "~/.hedge/control.token".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Telemetry {
    pub enabled: bool,
    /// OTLP/HTTP-Basis-URL, z. B. http://127.0.0.1:4318
    pub endpoint: String,
    pub service_name: String,
    /// Export-Intervall der Metriken.
    pub interval_secs: u64,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://127.0.0.1:4318".into(),
            service_name: "hedge".into(),
            interval_secs: 15,
        }
    }
}

/// Presidio: Namen, Telefonnummern und andere Dinge ohne festes Format.
///
/// Presidio ist ein Feature von Hedge, kein zweites Produkt: Lokal startet
/// Hedge den Container selbst (`managed = true`, gesetzt von
/// `hedge presidio enable`). Zentral betreibt ihn der Admin neben Hedge,
/// dann zählt nur `url`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Presidio {
    pub enabled: bool,
    /// Hedge startet und überwacht den Container selbst (docker/podman).
    pub managed: bool,
    pub url: String,
    /// Image für den selbst verwalteten Container. Leer = das Image, das zu
    /// dieser Hedge-Version gehört.
    pub image: Option<String>,
    /// Sprachen, in denen analysiert wird. Die erste ist der Rückfall, wenn
    /// sich die Sprache eines Textes nicht erkennen lässt.
    pub languages: Option<Vec<String>>,
    /// Alte Schreibweise für genau eine Sprache. Bleibt gültig.
    pub language: Option<String>,
    pub score_threshold: f64,
    pub entities: Vec<String>,
    /// Auch einzelne Wörter als Namen melden ("Patrick", "Wagner"). Ohne
    /// das zählen nur Namen aus mindestens zwei Wörtern und solche mit
    /// Anrede davor ("Frau Wagner"): In Code hält ein Sprachmodell sonst
    /// jeden großgeschriebenen Bezeichner für einen Namen.
    pub single_names: bool,
    /// Welche Teile einer Anfrage an Presidio gehen: system, tools, user,
    /// assistant, tool_use, tool_result.
    pub scope: Vec<PresidioScope>,
    /// false: Funde nur melden. true: Funde maskieren oder blockieren wie
    /// die der eingebauten Detektoren (je nach `mode`).
    pub enforce: bool,
    /// Was passiert mit einer Anfrage, die Presidio nicht prüfen konnte.
    pub on_unavailable: OnUnavailable,
    /// JSON-Pfade (Präfixe), die zusätzlich ausgenommen sind.
    pub skip_paths: Vec<String>,
    pub min_chars: usize,
    /// Längere Texte werden an Zeilengrenzen in Stücke dieser Länge geteilt.
    pub max_chars: usize,
    /// Zeitlimit eines einzelnen Aufrufs von Presidio.
    pub timeout_ms: u64,
    /// So lange wartet eine Agent-Anfrage insgesamt auf Presidio. Was dann
    /// noch läuft, läuft im Hintergrund zu Ende und liegt für die nächste
    /// Anfrage im Cache.
    pub budget_ms: u64,
    /// Gleichzeitige Anfragen an Presidio pro Agent-Anfrage.
    pub concurrency: usize,
    /// Kommando der Container-Laufzeit: auto, docker, podman oder ein Pfad.
    pub runtime: String,
}

impl Default for Presidio {
    fn default() -> Self {
        Self {
            enabled: false,
            managed: false,
            url: "http://127.0.0.1:5002".into(),
            image: None,
            languages: None,
            language: None,
            score_threshold: 0.6,
            entities: vec![
                "PERSON".into(),
                "PHONE_NUMBER".into(),
                "CREDIT_CARD".into(),
                "IBAN_CODE".into(),
            ],
            single_names: false,
            scope: vec![PresidioScope::User, PresidioScope::ToolResult],
            enforce: false,
            on_unavailable: OnUnavailable::Allow,
            skip_paths: Vec::new(),
            min_chars: 12,
            max_chars: 20_000,
            timeout_ms: 5000,
            budget_ms: 10_000,
            concurrency: 4,
            runtime: "auto".into(),
        }
    }
}

/// Das Image, das zu dieser Hedge-Version gehört und mit ihr getestet ist.
pub const PRESIDIO_IMAGE: &str = concat!(
    "ghcr.io/munichbughunter/hedge-presidio:",
    env!("CARGO_PKG_VERSION")
);

impl Presidio {
    /// Die konfigurierten Sprachen, klein geschrieben, ohne Doppelte.
    pub fn languages(&self) -> Vec<String> {
        let raw: Vec<String> = match (&self.languages, &self.language) {
            (Some(list), _) => list.clone(),
            (None, Some(one)) => vec![one.clone()],
            (None, None) => vec!["de".into(), "en".into()],
        };
        let mut out: Vec<String> = Vec::new();
        for l in raw {
            let l = l.trim().to_ascii_lowercase();
            if !l.is_empty() && !out.contains(&l) {
                out.push(l);
            }
        }
        out
    }

    pub fn image(&self) -> &str {
        self.image
            .as_deref()
            .filter(|i| !i.trim().is_empty())
            .unwrap_or(PRESIDIO_IMAGE)
    }

    /// Host und Port aus `url`, z. B. `("127.0.0.1", 5002)`.
    pub fn host_port(&self) -> Option<(String, u16)> {
        let rest = self
            .url
            .strip_prefix("http://")
            .or_else(|| self.url.strip_prefix("https://"))?;
        let authority = rest.split(['/', '?', '#']).next()?;
        let authority = authority.rsplit('@').next()?;
        let default_port = if self.url.starts_with("https://") {
            443
        } else {
            80
        };
        if let Some(v6) = authority.strip_prefix('[') {
            let (host, tail) = v6.split_once(']')?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse().ok()?,
                None => default_port,
            };
            return Some((host.to_owned(), port));
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => Some((host.to_owned(), port.parse().ok()?)),
            None => Some((authority.to_owned(), default_port)),
        }
    }

    /// Zeigt `url` auf diesen Rechner?
    pub fn is_local(&self) -> bool {
        match self.host_port() {
            Some((host, _)) => {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }
            None => false,
        }
    }

    /// Wie weit weg liegt Presidio? Prompts gehen im Klartext dorthin.
    pub fn exposure(&self) -> PresidioExposure {
        let Some((host, _)) = self.host_port() else {
            return PresidioExposure::Public;
        };
        if self.is_local() {
            return PresidioExposure::Local;
        }
        match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) if ip.is_private() || ip.is_link_local() => {
                PresidioExposure::Private
            }
            Ok(std::net::IpAddr::V6(ip)) if (ip.segments()[0] & 0xfe00) == 0xfc00 => {
                PresidioExposure::Private
            }
            Ok(_) => PresidioExposure::Public,
            // Ein Name ohne Punkt ist ein Dienstname im selben Netz
            // (Compose, Kubernetes), ebenso die üblichen internen Endungen.
            Err(_) => {
                let h = host.to_ascii_lowercase();
                let internal = !h.contains('.')
                    || [".internal", ".local", ".lan", ".svc", ".cluster.local"]
                        .iter()
                        .any(|s| h.ends_with(s));
                if internal {
                    PresidioExposure::Private
                } else {
                    PresidioExposure::Public
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresidioExposure {
    /// Loopback: dieselbe Maschine.
    Local,
    /// Dienstname oder privates Netz.
    Private,
    /// Ein Host mit öffentlichem Namen oder öffentlicher Adresse.
    Public,
}

/// Ein Teil einer Anfrage, nach dem sich der Presidio-Scope richtet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresidioScope {
    /// System-Prompt des Agents.
    System,
    /// Tool-Definitionen (Namen, Beschreibungen, Schemas).
    Tools,
    /// Was der Mensch geschrieben hat.
    User,
    /// Frühere Antworten des Modells.
    Assistant,
    /// Argumente früherer Tool-Aufrufe des Modells.
    ToolUse,
    /// Ergebnisse von Tool-Aufrufen: Dateiinhalte, Kommando-Ausgaben.
    ToolResult,
}

impl PresidioScope {
    pub fn as_str(self) -> &'static str {
        match self {
            PresidioScope::System => "system",
            PresidioScope::Tools => "tools",
            PresidioScope::User => "user",
            PresidioScope::Assistant => "assistant",
            PresidioScope::ToolUse => "tool_use",
            PresidioScope::ToolResult => "tool_result",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnUnavailable {
    /// Anfrage läuft weiter und wird als ungeprüft markiert.
    Allow,
    /// Anfrage wird abgelehnt, nichts geht an den Upstream.
    Block,
}

impl OnUnavailable {
    pub fn as_str(self) -> &'static str {
        match self {
            OnUnavailable::Allow => "allow",
            OnUnavailable::Block => "block",
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Observe,
    Redact,
    Block,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Observe => "observe",
            Mode::Redact => "redact",
            Mode::Block => "block",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config in {path}:\n{source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl Config {
    /// Parst Config aus einem TOML-Text und validiert sie.
    pub fn from_toml(text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(text)
    }

    /// Liest die Datei, parst und validiert sie.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let cfg = Config::from_toml(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Prüft, was serde nicht prüfen kann: Semantik.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.upstreams.is_empty() {
            return Err(ConfigError::Invalid("no upstreams configured".into()));
        }
        let mut seen = HashSet::new();
        for u in &self.upstreams {
            if u.name.is_empty() || u.name.contains('/') {
                return Err(ConfigError::Invalid(format!(
                    "upstream name {:?} must be non-empty and must not contain '/'",
                    u.name
                )));
            }
            if !seen.insert(&u.name) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate upstream name {:?}",
                    u.name
                )));
            }
            if !(u.url.starts_with("http://") || u.url.starts_with("https://")) {
                return Err(ConfigError::Invalid(format!(
                    "upstream {:?}: url must start with http:// or https://",
                    u.name
                )));
            }
        }
        if self.server.listen.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigError::Invalid(format!(
                "server.listen {:?} is not a socket address (e.g. 127.0.0.1:18765)",
                self.server.listen
            )));
        }
        if self.timeouts.connect_secs == 0 || self.timeouts.request_secs == 0 {
            return Err(ConfigError::Invalid("timeouts must be > 0".into()));
        }
        for u in &self.upstreams {
            if u.name.starts_with('_') {
                return Err(ConfigError::Invalid(format!(
                    "upstream name {:?} must not start with '_' (reserved for hedge)",
                    u.name
                )));
            }
        }
        // Tool-Regeln und Pakete vollständig bauen, damit Regex-Fehler hier auffallen.
        crate::tools::ToolPolicy::from_config(&self.tools).map_err(ConfigError::Invalid)?;
        let mut names = HashSet::new();
        for c in &self.clients {
            if c.name.is_empty() || !names.insert(&c.name) {
                return Err(ConfigError::Invalid(format!(
                    "client name {:?} is empty or used twice",
                    c.name
                )));
            }
            if c.token_sha256.len() != 64 || hex::decode(&c.token_sha256).is_err() {
                return Err(ConfigError::Invalid(format!(
                    "client {:?}: token_sha256 must be 64 hex characters (use `hedge client add`)",
                    c.name
                )));
            }
        }
        if self.server.require_client && self.clients.is_empty() {
            return Err(ConfigError::Invalid(
                "server.require_client = true but no [[clients]] configured".into(),
            ));
        }
        if self.telemetry.enabled
            && !(self.telemetry.endpoint.starts_with("http://")
                || self.telemetry.endpoint.starts_with("https://"))
        {
            return Err(ConfigError::Invalid(
                "telemetry.endpoint must start with http:// or https://".into(),
            ));
        }
        self.validate_presidio()?;
        Ok(())
    }

    fn validate_presidio(&self) -> Result<(), ConfigError> {
        let p = &self.presidio;
        let bad = |msg: String| Err(ConfigError::Invalid(msg));
        if !(0.0..=1.0).contains(&p.score_threshold) {
            return bad("presidio.score_threshold must be between 0 and 1".into());
        }
        if p.languages.is_some() && p.language.is_some() {
            return bad(
                "presidio: set either `languages = [\"de\", \"en\"]` or the older `language`, not both"
                    .into(),
            );
        }
        let languages = p.languages();
        if languages.is_empty() {
            return bad(
                "presidio.languages must name at least one language, e.g. [\"de\", \"en\"]".into(),
            );
        }
        for l in &languages {
            let ok =
                (2..=8).contains(&l.len()) && l.chars().all(|c| c.is_ascii_lowercase() || c == '-');
            if !ok {
                return bad(format!(
                    "presidio.languages: {l:?} is not a language code (use codes such as \"de\", \"en\")"
                ));
            }
        }
        if p.max_chars < 1000 {
            return bad("presidio.max_chars must be at least 1000".into());
        }
        if p.concurrency == 0 || p.concurrency > 64 {
            return bad("presidio.concurrency must be between 1 and 64".into());
        }
        if !p.enabled {
            return Ok(());
        }
        if !(p.url.starts_with("http://") || p.url.starts_with("https://")) {
            return bad("presidio.url must start with http:// or https://".into());
        }
        if p.host_port().is_none() {
            return bad(format!(
                "presidio.url {:?} has no usable host and port",
                p.url
            ));
        }
        if p.entities.is_empty() {
            return bad(
                "presidio.entities is empty: there is nothing to look for (e.g. [\"PERSON\"])"
                    .into(),
            );
        }
        if p.scope.is_empty() {
            return bad(
                "presidio.scope is empty: nothing would be analysed (e.g. [\"user\", \"tool_result\"])"
                    .into(),
            );
        }
        if p.managed && !p.is_local() {
            return bad(format!(
                "presidio.managed = true starts a container on this machine, but presidio.url points to {:?}. \
                 Use a local url (http://127.0.0.1:5002) or set managed = false",
                p.url
            ));
        }
        if p.managed && !p.url.starts_with("http://") {
            return bad("presidio.managed = true needs an http:// url (the container speaks plain HTTP on loopback)".into());
        }
        Ok(())
    }

    /// Verändern Presidio-Funde, was mit einer Anfrage passiert?
    pub fn presidio_guards(&self) -> bool {
        self.presidio.enabled && self.presidio.enforce && self.mode != Mode::Observe
    }

    /// Wird eine Anfrage abgelehnt, wenn Presidio sie nicht prüfen kann?
    pub fn presidio_fail_closed(&self) -> bool {
        self.presidio_guards() && self.presidio.on_unavailable == OnUnavailable::Block
    }

    pub fn control_token_path(&self) -> PathBuf {
        expand_tilde(&self.control.token)
    }

    /// Lauscht Hedge nur auf Loopback?
    pub fn is_loopback(&self) -> bool {
        self.server
            .listen
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false)
    }

    pub fn upstream(&self, name: &str) -> Option<&Upstream> {
        self.upstreams.iter().find(|u| u.name == name)
    }

    pub fn witness_path(&self) -> PathBuf {
        expand_tilde(&self.witness.path)
    }

    pub fn witness_key_path(&self) -> PathBuf {
        expand_tilde(&self.witness.key)
    }
}

/// Ersetzt ein führendes `~` durch das Home-Verzeichnis.
pub fn expand_tilde(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(path),
    }
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Standard-Verzeichnis für Config, Schlüssel und Witness.
pub fn default_dir() -> PathBuf {
    home_dir()
        .map(|h| h.join(".hedge"))
        .unwrap_or_else(|| PathBuf::from(".hedge"))
}

/// Sucht die Config: `--config` > `$HEDGE_CONFIG` > `~/.hedge/hedge.toml`.
///
/// Bewusst kein Blick ins aktuelle Verzeichnis: Wo Hedge gestartet wird,
/// darf nicht darüber entscheiden, welche Policy gilt.
pub fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    if let Some(p) = std::env::var_os("HEDGE_CONFIG").filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    default_dir().join("hedge.toml")
}

/// Setzt `key = value` im Abschnitt `[section]` eines TOML-Textes und lässt
/// alles andere stehen, auch Kommentare.
///
/// Steht der Schlüssel schon da, wird die Zeile ersetzt. Steht er nur
/// auskommentiert da (wie in der Vorlage von `hedge init`), wird genau diese
/// Zeile einkommentiert – die Datei liest sich danach, als hätte ein Mensch
/// sie bearbeitet. Fehlt der Abschnitt, kommt er ans Ende. `value` ist
/// fertiges TOML (`true`, `"text"`).
pub fn set_key(text: &str, section: &str, key: &str, value: &str) -> String {
    let header = format!("[{section}]");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let is_header = |l: &str| {
        l.trim_start()
            .strip_prefix(&header)
            .is_some_and(|rest| rest.trim().is_empty() || rest.trim_start().starts_with('#'))
    };
    let Some(start) = lines.iter().position(|l| is_header(l)) else {
        if lines.last().is_some_and(|l| !l.trim().is_empty()) {
            lines.push(String::new());
        }
        lines.push(header);
        lines.push(format!("{key} = {value}"));
        return lines.join("\n") + "\n";
    };
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.trim_start().starts_with('['))
        .map_or(lines.len(), |i| start + 1 + i);

    // Der Rest der Zeile hinter `key =`, falls die Zeile diesen Schlüssel setzt.
    let value_of = |line: &str, commented: bool| -> Option<String> {
        let mut t = line.trim_start();
        if commented {
            t = t.strip_prefix('#')?.trim_start();
        }
        let rest = t.strip_prefix(key)?;
        // `enabled` darf nicht auf `enabled_extra` passen.
        let rest = rest.trim_start().strip_prefix('=')?;
        Some(rest.to_owned())
    };
    let found = (start + 1..end)
        .find(|i| value_of(&lines[*i], false).is_some())
        .map(|i| (i, false))
        .or_else(|| {
            (start + 1..end)
                .find(|i| value_of(&lines[*i], true).is_some())
                .map(|i| (i, true))
        });
    match found {
        Some((i, commented)) => {
            let old = value_of(&lines[i], commented).unwrap_or_default();
            let mut line = format!("{key} = {value}");
            if let Some(comment) = trailing_comment(&old) {
                line.push_str("  ");
                line.push_str(comment);
            }
            lines[i] = line;
        }
        None => lines.insert(start + 1, format!("{key} = {value}")),
    }
    lines.join("\n") + "\n"
}

/// Der Kommentar am Ende eines TOML-Werts, falls einer dasteht. Ein `#`
/// innerhalb einer Zeichenkette zählt nicht.
fn trailing_comment(value: &str) -> Option<&str> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' => return Some(value[i..].trim_end()),
            None => {}
        }
    }
    None
}

/// Die Vorlage, die `hedge init` schreibt. Jede Option dokumentiert, Defaults
/// auskommentiert, damit ein Admin die Datei liest wie eine Anleitung.
pub const TEMPLATE: &str = r#"# hedge.toml – AI Guard Proxy
#
# Hedge sitzt zwischen deinem Coding-Agent und der LLM-API. Der Agent zeigt
# auf Hedge, Hedge prüft jeden Prompt und jede Antwort und leitet weiter:
#
#   export ANTHROPIC_BASE_URL=http://127.0.0.1:18765/anthropic
#
# Diese Datei wird im laufenden Betrieb neu geladen (außer listen, witness,
# telemetry, control – die brauchen einen Neustart). Jede Änderung wird im
# Witness bezeugt.
#
# Modus:  observe  = nur melden, nichts verändern (Standard, zum Einführen)
#         redact   = Funde maskieren und weiterleiten
#         block    = Anfrage ablehnen, sobald ein High-Fund dabei ist
#                    (E-Mails & Co. werden dann maskiert, nicht blockiert)
mode = "observe"

[server]
listen = "127.0.0.1:18765"
# require_client = false   # Central-Mode: nur Anfragen mit Client-Token annehmen

# Jeder Upstream ist unter /<name>/... erreichbar. Andere Ziele gibt es nicht.
[[upstreams]]
name = "anthropic"
url = "https://api.anthropic.com"

[[upstreams]]
name = "openai"
url = "https://api.openai.com"

[timeouts]
# connect_secs = 10
# request_secs = 600

[detectors]
# secrets = true   # API-Keys, Tokens, Private Keys
# pii = true       # E-Mail, IBAN

# Severity pro Fundart überschreiben: low | medium | high
# low    = nur melden/maskieren, nie blockieren
# medium = maskieren (in redact und block)
# high   = blockieren (in block)
[severity]
# email = "low"

# Eigene Infrastruktur, die nie als Fund gilt.
[allow]
# values  = ["me@example.com"]
# domains = ["example.com"]

# Modell-Antworten: Secrets/PII melden, Tool-Aufrufe und Tokens erfassen.
[response]
# inspect = true

# Tool-Aufrufe des Modells (Bash, Write, …) prüfen, bevor der Agent sie sieht.
#   enforce = false  → Treffer werden nur gemeldet (flag)
#   enforce = true   → deny verwirft den Aufruf (das Modell erfährt warum),
#                      hold fragt dich, bevor der Aufruf läuft
[tools]
# enforce = false
# packs = ["destructive-shell", "credential-files", "exfiltration"]

# Freigaben (hold). Standard: Hedge fragt direkt in der Agent-Session; du
# antwortest dort mit `approve <id>` (oder `deny <id>`), dann läuft genau
# dieser eine Aufruf. `hedge approve <id>` im Terminal geht immer.
#   approve_in_chat = false → der Aufruf wartet stattdessen, bis jemand per
#   `hedge approve <id>` entscheidet (für eine zweite Person / zentral).
# approve_in_chat = true
# approval_timeout_secs = 300   # so lange gilt die Anfrage

# Bei jeder Freigabe-Anfrage Bescheid geben (lokal oder ins Team):
# notify_command = "terminal-notifier -title Hedge -message \"$HEDGE_TOOL: $HEDGE_PREVIEW ($HEDGE_APPROVAL_ID)\""
# notify_webhook = "https://hooks.slack.com/services/…"

# Eigene Regeln stehen vor den Paketen; die erste passende gewinnt.
# [[tools.rules]]
# id = "no-prod-db"
# tool = "Bash"                 # Glob, mehrere mit |
# match = "psql .*prod"         # Regex auf die Eingabe
# action = "hold"               # allow | deny | hold
# reason = "Produktionsdatenbank nur mit Freigabe"

# Erlaubte Modelle (Globs). Leer = alle.
[models]
# allow = ["claude-*"]
# deny  = []

# Token-Budgets (Input ohne Cache-Reads + Output). 0 = unbegrenzt.
[budget]
# daily_tokens   = 0     # pro Client und Tag
# session_tokens = 0     # pro Agent-Session

[log]
# format = "pretty"   # pretty | json (json für zentrale Log-Systeme)
# level  = "info"     # z. B. "hedge=debug"

# Bezeugtes Protokoll: jede Anfrage als signierter Eintrag in einer Hash-Kette.
# Prüfen mit: hedge verify
[witness]
# enabled = true
# path = "~/.hedge/witness.jsonl"
# key  = "~/.hedge/witness.key"
# tool_preview = true   # kurze, maskierte Vorschau jedes Tool-Aufrufs
# hints = true          # maskierter Hinweis pro Fund: p…@example.com, …a1b2

# Steuer-API (hedge approve, hedge status). Das Token erzeugt `hedge init`.
[control]
# token = "~/.hedge/control.token"

# OpenTelemetry (OTLP/HTTP): Traces und Metriken nach Grafana & Co.
# Stack zum Ausprobieren: deploy/compose/docker-compose.yml
[telemetry]
# enabled = false
# endpoint = "http://127.0.0.1:4318"
# service_name = "hedge"

# Presidio findet, was kein festes Format hat: Namen, Telefonnummern.
# Einschalten mit einem Befehl:
#
#   hedge presidio enable
#
# Der Befehl holt das Image, startet den Container auf 127.0.0.1, prüft ihn
# mit einem Testsatz und trägt enabled/managed hier ein. Danach startet
# `hedge run` den Container mit. Ohne Presidio laufen die eingebauten
# Detektoren unverändert weiter.
[presidio]
# enabled = false
# managed = false                # true: Hedge startet den Container selbst (lokal)
# url = "http://127.0.0.1:5002"  # zentral: der Dienst im internen Netz
# languages = ["de", "en"]       # die erste gilt, wenn die Sprache unklar ist
# entities = ["PERSON", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE"]
# single_names = false           # true: auch einzelne Wörter als Namen melden
#                                # ("Wagner"); in Code gibt das viele Fehlalarme
# scope = ["user", "tool_result"]  # auch möglich: system, tools, assistant, tool_use
# enforce = false                # false: Funde nur melden. true: maskieren oder
#                                # blockieren wie eingebaute Funde (je nach mode)
# on_unavailable = "allow"       # allow: weiterleiten und markieren
#                                # block: nichts geht hinaus, was Presidio nicht
#                                # prüfen konnte (wirkt, sobald enforce = true
#                                # und mode nicht observe ist)

# Central-Mode: bekannte Clients. Anlegen mit: hedge client add <name>
# [[clients]]
# name = "patrick"
# token_sha256 = "…"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        mode = "observe"

        [server]
        listen = "127.0.0.1:18765"

        [[upstreams]]
        name = "anthropic"
        url = "https://api.anthropic.com"
    "#;

    #[test]
    fn parses_valid_config() {
        let cfg = Config::from_toml(VALID).expect("valid config must parse");

        assert_eq!(cfg.mode, Mode::Observe);
        assert_eq!(cfg.server.listen, "127.0.0.1:18765");
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.upstreams[0].name, "anthropic");
        assert_eq!(cfg.upstreams[0].url, "https://api.anthropic.com");
        cfg.validate().expect("valid");
    }

    #[test]
    fn empty_config_uses_defaults() {
        let cfg = Config::from_toml("").expect("empty config is valid");

        assert_eq!(cfg.mode, Mode::Observe);
        assert_eq!(cfg.server.listen, "127.0.0.1:18765");
        assert_eq!(cfg.upstreams.len(), 2);
        assert!(cfg.detectors.secrets && cfg.detectors.pii);
        assert!(cfg.witness.enabled);
        assert_eq!(cfg.timeouts.request_secs, 600);
        cfg.validate().expect("defaults are valid");
    }

    #[test]
    fn example_file_in_the_repo_is_the_template() {
        assert_eq!(include_str!("../hedge.example.toml"), TEMPLATE);
    }

    #[test]
    fn template_parses_and_validates() {
        let cfg = Config::from_toml(TEMPLATE).expect("template must parse");
        cfg.validate().expect("template must validate");
    }

    #[test]
    fn rejects_unknown_mode() {
        let invalid = VALID.replace("observe", "yolo");

        assert!(
            Config::from_toml(&invalid).is_err(),
            "mode = \"yolo\" must be rejected"
        );
    }

    #[test]
    fn error_message_names_the_problem() {
        let invalid = VALID.replace("observe", "yolo");

        let err = Config::from_toml(&invalid).unwrap_err();

        assert!(err.to_string().contains("yolo"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let typo = VALID.replace("url =", "urll =");

        let err = Config::from_toml(&typo).unwrap_err();

        assert!(err.to_string().contains("urll"), "got: {err}");
    }

    #[test]
    fn severity_overrides_and_allowlist_parse() {
        let cfg = Config::from_toml(
            r#"
            [severity]
            email = "low"

            [allow]
            values = ["Me@Example.com"]
            domains = ["doering-itconsulting.de"]
            "#,
        )
        .unwrap();

        assert_eq!(cfg.severity["email"], Severity::Low);
        assert!(cfg.allow.is_allowed("me@example.com"));
        assert!(cfg.allow.is_allowed("patrick@doering-itconsulting.de"));
        assert!(cfg.allow.is_allowed("x@mail.doering-itconsulting.de"));
        assert!(!cfg.allow.is_allowed("x@notdoering-itconsulting.de"));
        assert!(!cfg.allow.is_allowed("someone@else.org"));
    }

    #[test]
    fn validate_rejects_duplicate_or_bad_upstreams() {
        let dup = Config::from_toml(
            r#"
            [[upstreams]]
            name = "a"
            url = "https://a"
            [[upstreams]]
            name = "a"
            url = "https://b"
            "#,
        )
        .unwrap();
        assert!(
            dup.validate()
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );

        let bad_url = Config::from_toml(
            r#"
            [[upstreams]]
            name = "a"
            url = "ftp://a"
            "#,
        )
        .unwrap();
        assert!(bad_url.validate().is_err());

        let bad_listen = Config::from_toml("[server]\nlisten = \"nope\"").unwrap();
        assert!(
            bad_listen
                .validate()
                .unwrap_err()
                .to_string()
                .contains("listen")
        );
    }

    #[test]
    fn config_lookup_ignores_the_working_directory() {
        // Auch wenn im aktuellen Verzeichnis eine hedge.toml läge: Ohne
        // --config und ohne $HEDGE_CONFIG gilt immer ~/.hedge/hedge.toml.
        if std::env::var_os("HEDGE_CONFIG").is_none() {
            assert_eq!(resolve_config_path(None), default_dir().join("hedge.toml"));
        }
        assert_eq!(
            resolve_config_path(Some(Path::new("/etc/hedge/hedge.toml"))),
            PathBuf::from("/etc/hedge/hedge.toml")
        );
    }

    fn presidio(body: &str) -> Result<Config, String> {
        let cfg = Config::from_toml(&format!("[presidio]\n{body}")).map_err(|e| e.to_string())?;
        cfg.validate().map_err(|e| e.to_string())?;
        Ok(cfg)
    }

    #[test]
    fn presidio_defaults_report_only_and_never_block() {
        let cfg = presidio("enabled = true").unwrap();
        let p = &cfg.presidio;
        assert!(!p.managed && !p.enforce);
        assert_eq!(p.languages(), ["de", "en"]);
        assert_eq!(p.scope, [PresidioScope::User, PresidioScope::ToolResult]);
        assert_eq!(p.on_unavailable, OnUnavailable::Allow);
        assert_eq!(p.image(), PRESIDIO_IMAGE);
        assert!(PRESIDIO_IMAGE.ends_with(env!("CARGO_PKG_VERSION")));
        assert!(!cfg.presidio_guards() && !cfg.presidio_fail_closed());
    }

    #[test]
    fn presidio_languages_accept_the_old_single_key() {
        assert_eq!(
            presidio("language = \"en\"").unwrap().presidio.languages(),
            ["en"]
        );
        assert_eq!(
            presidio("languages = [\"EN\", \"de\", \"en\"]")
                .unwrap()
                .presidio
                .languages(),
            ["en", "de"],
            "lower case, no duplicates, order kept"
        );
        let both = presidio("language = \"en\"\nlanguages = [\"de\"]").unwrap_err();
        assert!(both.contains("not both"), "{both}");
        assert!(presidio("languages = []").is_err());
        assert!(presidio("languages = [\"deutsch!\"]").is_err());
    }

    #[test]
    fn fail_closed_needs_enforce_and_a_mode_that_changes_something() {
        let cfg = |mode: &str, body: &str| {
            let c = Config::from_toml(&format!(
                "mode = \"{mode}\"\n[presidio]\nenabled = true\n{body}"
            ))
            .unwrap();
            c.validate().unwrap();
            c
        };
        let block = "on_unavailable = \"block\"";
        assert!(
            !cfg("redact", block).presidio_fail_closed(),
            "enforce is off"
        );
        assert!(!cfg("observe", &format!("enforce = true\n{block}")).presidio_fail_closed());
        assert!(cfg("redact", &format!("enforce = true\n{block}")).presidio_fail_closed());
        assert!(cfg("block", &format!("enforce = true\n{block}")).presidio_fail_closed());
        assert!(
            !cfg("block", "enforce = true").presidio_fail_closed(),
            "allow is the default"
        );
    }

    #[test]
    fn a_managed_presidio_must_be_local() {
        assert!(presidio("enabled = true\nmanaged = true").is_ok());
        assert!(
            presidio("enabled = true\nmanaged = true\nurl = \"http://localhost:5010\"").is_ok()
        );
        let err =
            presidio("enabled = true\nmanaged = true\nurl = \"http://presidio:3000\"").unwrap_err();
        assert!(err.contains("managed = false"), "{err}");
        assert!(presidio("enabled = true\nurl = \"http://presidio:3000\"").is_ok());
        assert!(presidio("enabled = true\nurl = \"presidio:3000\"").is_err());
        assert!(presidio("enabled = true\nscope = []").is_err());
        assert!(presidio("enabled = true\nscope = [\"everything\"]").is_err());
        assert!(presidio("enabled = true\non_unavailable = \"maybe\"").is_err());
    }

    #[test]
    fn presidio_url_is_read_as_host_and_port_and_judged_by_distance() {
        let p = |url: &str| Presidio {
            url: url.into(),
            ..Presidio::default()
        };
        assert_eq!(
            p("http://127.0.0.1:5002").host_port(),
            Some(("127.0.0.1".into(), 5002))
        );
        assert_eq!(
            p("http://presidio:3000/").host_port(),
            Some(("presidio".into(), 3000))
        );
        assert_eq!(
            p("https://pii.example.com").host_port(),
            Some(("pii.example.com".into(), 443))
        );
        assert_eq!(
            p("http://[::1]:5002").host_port(),
            Some(("::1".into(), 5002))
        );
        assert_eq!(p("http://host:notaport").host_port(), None);

        assert_eq!(
            p("http://127.0.0.1:5002").exposure(),
            PresidioExposure::Local
        );
        assert_eq!(
            p("http://localhost:5002").exposure(),
            PresidioExposure::Local
        );
        assert_eq!(p("http://[::1]:5002").exposure(), PresidioExposure::Local);
        assert_eq!(
            p("http://presidio:3000").exposure(),
            PresidioExposure::Private
        );
        assert_eq!(
            p("http://10.0.3.7:3000").exposure(),
            PresidioExposure::Private
        );
        assert_eq!(
            p("http://presidio.guard.svc.cluster.local:3000").exposure(),
            PresidioExposure::Private
        );
        assert_eq!(
            p("http://pii.example.com:3000").exposure(),
            PresidioExposure::Public
        );
        assert_eq!(
            p("http://203.0.113.9:3000").exposure(),
            PresidioExposure::Public
        );
    }

    #[test]
    fn set_key_uncomments_the_template_line_and_keeps_the_comment() {
        let out = set_key(TEMPLATE, "presidio", "enabled", "true");
        let out = set_key(&out, "presidio", "managed", "true");

        assert!(out.contains("\n[presidio]\nenabled = true\nmanaged = true  # true: Hedge startet den Container selbst (lokal)\n"), "{}", &out[out.find("[presidio]").unwrap()..]);
        assert!(!out.contains("# enabled = false\n# managed"));
        let cfg = Config::from_toml(&out).unwrap();
        assert!(cfg.presidio.enabled && cfg.presidio.managed);
        // Alles andere steht, wo es stand.
        assert_eq!(out.lines().count(), TEMPLATE.lines().count());
        assert!(
            !Config::from_toml(&out).unwrap().telemetry.enabled,
            "[telemetry] enabled untouched"
        );
    }

    #[test]
    fn set_key_replaces_appends_and_respects_sections() {
        let text = "mode = \"observe\"\n\n[telemetry]\nenabled = false\n\n[presidio]\nenabled = false # aus\nurl = \"http://127.0.0.1:5002/#x\"  # lokal\n\n[[clients]]\nname = \"a\"\ntoken_sha256 = \"x\"\n";
        let out = set_key(text, "presidio", "enabled", "true");
        assert!(out.contains("[presidio]\nenabled = true  # aus\n"), "{out}");
        assert!(
            out.contains("[telemetry]\nenabled = false\n"),
            "other sections untouched"
        );

        let out = set_key(&out, "presidio", "url", "\"http://127.0.0.1:5003\"");
        assert!(
            out.contains("url = \"http://127.0.0.1:5003\"  # lokal\n"),
            "{out}"
        );

        let out = set_key(&out, "presidio", "managed", "true");
        assert!(
            out.contains("[presidio]\nmanaged = true\nenabled = true"),
            "new keys go right under the header: {out}"
        );

        let out = set_key("mode = \"observe\"", "presidio", "enabled", "true");
        assert_eq!(out, "mode = \"observe\"\n\n[presidio]\nenabled = true\n");

        // Ein Schlüssel, der nur so anfängt, ist ein anderer.
        let out = set_key(
            "[presidio]\nenabled_extra = 1\n",
            "presidio",
            "enabled",
            "true",
        );
        assert_eq!(out, "[presidio]\nenabled = true\nenabled_extra = 1\n");
    }

    #[test]
    fn expand_tilde_uses_home() {
        let p = expand_tilde("~/.hedge/x");
        assert!(!p.to_string_lossy().starts_with('~'));
        assert_eq!(expand_tilde("/abs/path"), PathBuf::from("/abs/path"));
    }
}
