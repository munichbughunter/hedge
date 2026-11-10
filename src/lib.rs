//! Hedge – AI Guard Proxy.
//!
//! Ein transparenter Reverse Proxy zwischen Coding-Agents (Claude Code,
//! Codex, …) und LLM-APIs. Hedge sieht jeden Prompt, findet Secrets und PII,
//! maskiert oder blockiert je nach Policy und bezeugt jede Anfrage in einer
//! signierten Hash-Kette.
//!
//! Module:
//! - [`config`]  – `hedge.toml`, Defaults, Validierung
//! - [`detect`]  – Detektoren (Trait + Regex-Implementierungen)
//! - [`policy`]  – Modus + Severity → Entscheidung
//! - [`inspect`] – JSON-Walker, Regeln, Redacting, Inspektion eines Bodys
//! - [`proxy`]   – axum-Handler, Weiterleitung, Logging
//! - [`witness`] – signierte Hash-Kette und Verifikation
//! - [`cli`]     – Kommandos für Entwickler und Admins

pub mod cli;
pub mod config;
pub mod detect;
pub mod inspect;
pub mod policy;
pub mod proxy;
pub mod witness;
