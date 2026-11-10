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
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    pub listen: String,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:18765".into(),
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
}

impl Default for Witness {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "~/.hedge/witness.jsonl".into(),
            key: "~/.hedge/witness.key".into(),
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
        Ok(())
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

/// Sucht die Config: explizit > $HEDGE_CONFIG > ./hedge.toml > ~/.hedge/hedge.toml.
pub fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    if let Some(p) = std::env::var_os("HEDGE_CONFIG") {
        return PathBuf::from(p);
    }
    let local = PathBuf::from("hedge.toml");
    if local.exists() {
        return local;
    }
    default_dir().join("hedge.toml")
}

/// Die Vorlage, die `hedge init` schreibt. Jede Option dokumentiert, Defaults
/// auskommentiert, damit ein Admin die Datei liest wie eine Anleitung.
pub const TEMPLATE: &str = r#"# hedge.toml – AI Guard Proxy
#
# Hedge sitzt zwischen deinem Coding-Agent und der LLM-API. Der Agent zeigt
# auf Hedge, Hedge prüft jeden Prompt und leitet ihn weiter:
#
#   export ANTHROPIC_BASE_URL=http://127.0.0.1:18765/anthropic
#
# Modus:  observe  = nur melden, nichts verändern (Standard, zum Einführen)
#         redact   = Funde maskieren und weiterleiten
#         block    = Anfrage ablehnen, sobald ein High-Fund dabei ist
#                    (E-Mails & Co. werden dann maskiert, nicht blockiert)
mode = "observe"

[server]
listen = "127.0.0.1:18765"

# Jeder Upstream ist unter /<name>/... erreichbar.
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

[log]
# format = "pretty"   # pretty | json (json für zentrale Log-Systeme)
# level  = "info"     # z. B. "hedge=debug"

# Bezeugtes Protokoll: jede Anfrage als signierter Eintrag in einer Hash-Kette.
# Prüfen mit: hedge verify
[witness]
# enabled = true
# path = "~/.hedge/witness.jsonl"
# key  = "~/.hedge/witness.key"
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
    fn expand_tilde_uses_home() {
        let p = expand_tilde("~/.hedge/x");
        assert!(!p.to_string_lossy().starts_with('~'));
        assert_eq!(expand_tilde("/abs/path"), PathBuf::from("/abs/path"));
    }
}
