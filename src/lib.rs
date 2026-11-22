//! Hedge – AI Guard Proxy.
//!
//! Ein transparenter Reverse Proxy zwischen Coding-Agents (Claude Code,
//! Codex, …) und LLM-APIs. Hedge sieht jeden Prompt und jede Antwort, findet
//! Secrets und PII, maskiert oder blockiert je nach Policy, prüft die
//! Tool-Aufrufe des Modells und bezeugt alles in einer signierten Hash-Kette.
//!
//! Module:
//! - [`config`]    – `hedge.toml`, Defaults, Validierung
//! - [`detect`]    – Detektoren (Trait + Regex-Implementierungen)
//! - [`presidio`]  – Presidio als weiterer Detektor: Client, Zustand, Container
//! - [`policy`]    – Modus + Severity → Entscheidung
//! - [`inspect`]   – JSON-Walker, Regeln, Redacting, Inspektion eines Requests
//! - [`sse`]       – Antworten verstehen: SSE-Framing, Tokens, Tool-Aufrufe
//! - [`tools`]     – Tool-Policy: allow / deny / hold
//! - [`approvals`] – angehaltene Tool-Aufrufe, die auf Freigabe warten
//! - [`budget`]    – Token-Budgets
//! - [`proxy`]     – axum-Handler, Weiterleitung, Streaming, Steuer-API
//! - [`witness`]   – signierte Hash-Kette, Verifikation, Export
//! - [`telemetry`] – OpenTelemetry-Export
//! - [`tui`]       – `hedge watch`: Live-Ansicht im Terminal
//! - [`cli`]       – Kommandos für Entwickler und Admins
//! - [`deploy`]    – `hedge deploy compose`: das Verzeichnis für den zentralen Betrieb

pub mod approvals;
pub mod budget;
pub mod cli;
pub mod config;
pub mod deploy;
pub mod detect;
pub mod inspect;
pub mod policy;
pub mod presidio;
pub mod proxy;
pub mod sse;
pub mod telemetry;
pub mod tools;
pub mod tui;
pub mod witness;
