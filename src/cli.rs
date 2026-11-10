//! Die Kommandozeile. Alles, was ein Mensch mit Hedge tut, passiert hier:
//! einrichten, starten, prüfen, zuschauen, auswerten.
//!
//! Grundsatz: Jede Ausgabe beantwortet auf einen Blick "Was ist los und was
//! tue ich als Nächstes?". Technische Bezeichner (`kind`, Pfade) werden für
//! Menschen übersetzt, bleiben aber mit `--json` maschinenlesbar.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::EnvFilter;

use crate::config::{self, Config, LogFormat, Mode, TEMPLATE};
use crate::detect::describe_kind;
use crate::proxy::{AppState, router};
use crate::witness::{self, Entry, VerifyReport};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser, Debug)]
#[command(
    name = "hedge",
    version,
    about = "AI Guard Proxy – sieht, was dein Coding-Agent an die LLM-API schickt, und hält Secrets zurück.",
    long_about = None,
    after_help = "Quickstart:\n  hedge init --claude-code   # Config + Schlüssel anlegen, Claude Code umbiegen\n  hedge run                  # Proxy starten\n  hedge tail -f              # zuschauen"
)]
pub struct Cli {
    /// Pfad zur hedge.toml (Standard: ./hedge.toml, dann ~/.hedge/hedge.toml)
    #[arg(short, long, global = true, env = "HEDGE_CONFIG")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Proxy starten (Standard, wenn kein Kommando angegeben ist)
    Run,
    /// Config, Signierschlüssel und Witness anlegen
    Init {
        /// Zielverzeichnis (Standard: ~/.hedge)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// ANTHROPIC_BASE_URL in ~/.claude/settings.json eintragen
        #[arg(long)]
        claude_code: bool,
        /// Vorhandene hedge.toml überschreiben (Schlüssel werden nie überschrieben)
        #[arg(long)]
        force: bool,
    },
    /// Config lesen, validieren und zusammenfassen
    Check,
    /// Witness-Kette offline prüfen (Hashes, Sequenz, Signaturen)
    Verify {
        /// Witness-Datei (Standard: aus Config)
        #[arg(long)]
        witness: Option<PathBuf>,
        /// Öffentlicher Schlüssel, .pub oder .key (Standard: aus Config)
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Letzte Einträge des Witness lesbar anzeigen
    Tail {
        /// Anzahl Einträge
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Weiter zuschauen (wie tail -f)
        #[arg(short, long)]
        follow: bool,
        /// Rohe JSON-Zeilen statt Tabelle
        #[arg(long)]
        json: bool,
    },
    /// Zusammenfassung über alle Anfragen (für Admins)
    Report {
        /// Zeitfenster, z. B. 30m, 24h, 7d (Standard: alles)
        #[arg(long)]
        since: Option<String>,
        /// Als JSON ausgeben
        #[arg(long)]
        json: bool,
    },
    /// Umgebung prüfen: Config, Port, Upstreams, Schlüssel, Kette, Agent-Setup
    Doctor,
}

/// Führt das Kommando aus und liefert den Exit-Code.
pub async fn run(cli: Cli) -> Result<i32> {
    let config_path = config::resolve_config_path(cli.config.as_deref());
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => cmd_run(&config_path).await,
        Command::Init {
            dir,
            claude_code,
            force,
        } => cmd_init(dir, claude_code, force),
        Command::Check => cmd_check(&config_path),
        Command::Verify { witness, key } => cmd_verify(&config_path, witness, key),
        Command::Tail {
            lines,
            follow,
            json,
        } => cmd_tail(&config_path, lines, follow, json).await,
        Command::Report { since, json } => cmd_report(&config_path, since, json),
        Command::Doctor => cmd_doctor(&config_path).await,
    }
}

// ---------- run ----------

async fn cmd_run(config_path: &Path) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    init_tracing(&cfg);

    let listener = tokio::net::TcpListener::bind(&cfg.server.listen).await?;
    let addr = listener.local_addr()?;
    let state = Arc::new(AppState::from_config(cfg)?);

    if state.config().log.format == LogFormat::Pretty {
        print_banner(&state, &addr, config_path);
    }
    tracing::info!(listen = %addr, mode = state.config().mode.as_str(), "hedge started");

    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("hedge stopped");
    Ok(0)
}

fn init_tracing(cfg: &Config) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cfg.log.level.clone()));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    match cfg.log.format {
        LogFormat::Pretty => builder.init(),
        LogFormat::Json => builder.json().flatten_event(true).init(),
    }
}

fn print_banner(state: &AppState, addr: &std::net::SocketAddr, config_path: &Path) {
    let cfg = state.config();
    let upstreams = cfg
        .upstreams
        .iter()
        .map(|u| format!("{} → {}", u.name.bold(), u.url))
        .collect::<Vec<_>>()
        .join("\n              ");
    let witness = match state.witness() {
        Some(w) => {
            let n = witness::read_entries(w.path())
                .map(|e| e.len())
                .unwrap_or(0);
            format!("{} (key {}, {n} entries)", w.path().display(), w.key_id())
        }
        None => "disabled".dimmed().to_string(),
    };
    let first = cfg
        .upstreams
        .first()
        .map(|u| u.name.as_str())
        .unwrap_or("anthropic");

    println!();
    println!(
        "  {} {}   mode: {}",
        "hedge".bold(),
        env!("CARGO_PKG_VERSION"),
        mode_colored(cfg.mode)
    );
    println!("  config      {}", config_path.display());
    println!("  listening   http://{addr}");
    println!("  upstreams   {upstreams}");
    println!("  detectors   {}", detector_list(cfg));
    println!("  witness     {witness}");
    println!();
    println!(
        "  agent setup {}",
        format!("export ANTHROPIC_BASE_URL=http://{addr}/{first}").cyan()
    );
    println!("  watch       {}", "hedge tail -f".cyan());
    println!();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

// ---------- init ----------

fn cmd_init(dir: Option<PathBuf>, claude_code: bool, force: bool) -> Result<i32> {
    let dir = dir.unwrap_or_else(config::default_dir);
    std::fs::create_dir_all(&dir)?;
    let config_path = dir.join("hedge.toml");
    let key_path = dir.join("witness.key");
    let witness_path = dir.join("witness.jsonl");
    let local = PathBuf::from("hedge.toml");
    let local_shadows = local.exists()
        && std::fs::canonicalize(&local).ok() != std::fs::canonicalize(&config_path).ok();

    println!();
    if config_path.exists() && !force {
        println!(
            "  {} config       {} (exists, kept; --force overwrites)",
            "·".dimmed(),
            config_path.display()
        );
    } else {
        let mut text = TEMPLATE.to_owned();
        if dir != config::default_dir() {
            // Witness neben die Config legen, wenn ein eigenes Verzeichnis gewählt wurde.
            text = text
                .replace(
                    "# path = \"~/.hedge/witness.jsonl\"",
                    &format!("path = \"{}\"", witness_path.display()),
                )
                .replace(
                    "# key  = \"~/.hedge/witness.key\"",
                    &format!("key  = \"{}\"", key_path.display()),
                );
        }
        std::fs::write(&config_path, text)?;
        println!("  {} config       {}", ok(), config_path.display());
    }

    if key_path.exists() {
        let vk = witness::load_verifying_key(&key_path)?;
        println!(
            "  {} signing key  {} (exists, key id {})",
            "·".dimmed(),
            key_path.display(),
            witness::key_id_of(&vk)
        );
    } else {
        let vk = witness::generate_keypair(&key_path)?;
        println!(
            "  {} signing key  {} (key id {})",
            ok(),
            key_path.display(),
            witness::key_id_of(&vk)
        );
        println!(
            "  {} public key   {}",
            ok(),
            witness::pub_path(&key_path).display()
        );
    }
    println!(
        "  {} witness log  {} (append-only, starts with the first request)",
        ok(),
        witness_path.display()
    );

    let cfg = Config::load(&config_path)?;
    let first = cfg
        .upstreams
        .first()
        .map(|u| u.name.as_str())
        .unwrap_or("anthropic");
    let base_url = format!("http://{}/{first}", cfg.server.listen);

    if claude_code {
        let settings = claude_settings_path();
        write_claude_code_env(&settings, &base_url)?;
        println!(
            "  {} claude code  {} → env.ANTHROPIC_BASE_URL = {base_url}",
            ok(),
            settings.display()
        );
    }

    println!();
    println!("  {}", "Next:".bold());
    println!("    1. {}   start the proxy", pad("hedge run", 34).cyan());
    if claude_code {
        println!(
            "    2. {}   Claude Code now talks to Hedge (restart running sessions)",
            pad("claude", 34).cyan()
        );
    } else {
        println!(
            "    2. {}   or: hedge init --claude-code",
            pad(&format!("export ANTHROPIC_BASE_URL={base_url}"), 34).cyan()
        );
    }
    println!(
        "    3. {}   watch requests as they happen",
        pad("hedge tail -f", 34).cyan()
    );
    println!();
    if config_path != config::default_dir().join("hedge.toml") {
        println!("  Hint: this config is not at the default location. Use:");
        println!("        export HEDGE_CONFIG={}", config_path.display());
        println!();
    }
    if local_shadows {
        println!(
            "  {} ./hedge.toml exists in this directory and takes precedence over {}",
            "!".yellow().bold(),
            config_path.display()
        );
        println!("    when you run hedge from here. Make sure both agree, or run:");
        println!("        hedge run --config {}", config_path.display());
        println!();
    }
    Ok(0)
}

fn claude_settings_path() -> PathBuf {
    config::home_dir()
        .map(|h| h.join(".claude").join("settings.json"))
        .unwrap_or_else(|| PathBuf::from(".claude/settings.json"))
}

/// Setzt `env.ANTHROPIC_BASE_URL` in Claude Codes settings.json, lässt alles
/// andere unangetastet und legt vorher ein Backup an.
fn write_claude_code_env(settings: &Path, base_url: &str) -> Result<()> {
    let mut doc: serde_json::Value = match std::fs::read_to_string(settings) {
        Ok(text) if !text.trim().is_empty() => serde_json::from_str(&text)
            .map_err(|e| format!("{} is not valid JSON: {e}", settings.display()))?,
        Ok(_) => serde_json::json!({}),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => return Err(e.into()),
    };
    if !doc.is_object() {
        return Err(format!("{} does not contain a JSON object", settings.display()).into());
    }
    if settings.exists() {
        let mut bak = settings.as_os_str().to_owned();
        bak.push(".bak");
        std::fs::copy(settings, PathBuf::from(bak))?;
    } else if let Some(parent) = settings.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let env = doc
        .as_object_mut()
        .expect("checked")
        .entry("env")
        .or_insert_with(|| serde_json::json!({}));
    if !env.is_object() {
        return Err("settings.json: \"env\" is not an object".into());
    }
    env["ANTHROPIC_BASE_URL"] = serde_json::Value::String(base_url.to_owned());
    std::fs::write(settings, serde_json::to_string_pretty(&doc)? + "\n")?;
    Ok(())
}

// ---------- check ----------

fn cmd_check(config_path: &Path) -> Result<i32> {
    let cfg = match Config::load(config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            println!("{} {}", fail(), e);
            return Ok(1);
        }
    };
    println!();
    println!("  {} {}", ok(), config_path.display());
    println!();
    print_config_summary(&cfg);
    println!();
    Ok(0)
}

fn print_config_summary(cfg: &Config) {
    println!(
        "  mode        {}  {}",
        mode_colored(cfg.mode),
        mode_help(cfg.mode).dimmed()
    );
    println!("  listen      {}", cfg.server.listen);
    for u in &cfg.upstreams {
        println!("  upstream    {}  →  {}", pad(&u.name, 10).bold(), u.url);
    }
    println!("  detectors   {}", detector_list(cfg));
    if cfg.severity.is_empty() {
        println!("  severity    defaults");
    } else {
        let s = cfg
            .severity
            .iter()
            .map(|(k, v)| format!("{k}={}", v.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  severity    {s}");
    }
    let allow = cfg.allow.values.len() + cfg.allow.domains.len();
    if allow == 0 {
        println!("  allow       {}", "nothing allowlisted".dimmed());
    } else {
        println!(
            "  allow       {} value(s), {} domain(s)",
            cfg.allow.values.len(),
            cfg.allow.domains.len()
        );
    }
    println!(
        "  timeouts    connect {}s, request {}s",
        cfg.timeouts.connect_secs, cfg.timeouts.request_secs
    );
    println!(
        "  log         {} / {}",
        match cfg.log.format {
            LogFormat::Pretty => "pretty",
            LogFormat::Json => "json",
        },
        cfg.log.level
    );
    if cfg.witness.enabled {
        let key_state = if cfg.witness_key_path().exists() {
            ok().to_string()
        } else {
            format!("{} missing – run hedge init", fail())
        };
        println!(
            "  witness     {}  key {} {key_state}",
            cfg.witness_path().display(),
            cfg.witness_key_path().display()
        );
    } else {
        println!("  witness     {}", "disabled".yellow());
    }
}

// ---------- verify ----------

fn cmd_verify(
    config_path: &Path,
    witness_path: Option<PathBuf>,
    key: Option<PathBuf>,
) -> Result<i32> {
    let cfg = Config::load(config_path).ok();
    let witness_path = witness_path
        .or_else(|| cfg.as_ref().map(|c| c.witness_path()))
        .ok_or("no witness path: pass --witness or provide a config")?;
    let key = key
        .or_else(|| cfg.as_ref().map(|c| c.witness_key_path()))
        .ok_or("no key path: pass --key or provide a config")?;

    let vk = witness::load_verifying_key(&key)?;
    let entries = witness::read_entries(&witness_path)?;
    let report = witness::verify(&entries, &vk);
    print_verify_report(&witness_path, &report);
    Ok(if report.is_ok() { 0 } else { 1 })
}

fn print_verify_report(path: &Path, report: &VerifyReport) {
    println!();
    println!("  witness   {}", path.display());
    println!("  entries   {}", report.entries);
    if let (Some(first), Some(last)) = (&report.first_ts, &report.last_ts) {
        println!("  range     {}  →  {}", human_ts(first), human_ts(last));
    }
    if let Some(k) = &report.key_id {
        println!("  key id    {k}");
    }
    println!();
    if report.is_ok() {
        println!(
            "  {} {}",
            ok(),
            "chain intact: every entry hashed, linked and signed".green()
        );
    } else {
        println!(
            "  {} {}",
            fail(),
            format!("{} problem(s)", report.problems.len()).red().bold()
        );
        for p in &report.problems {
            println!("      entry #{:<6} {}", p.seq, p.reason);
        }
    }
    println!();
}

// ---------- tail ----------

async fn cmd_tail(config_path: &Path, lines: usize, follow: bool, json: bool) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    let path = cfg.witness_path();
    if !path.exists() {
        println!(
            "  {} no witness yet at {} – start `hedge run` and send a request",
            "·".dimmed(),
            path.display()
        );
        if !follow {
            return Ok(0);
        }
    }

    let mut entries = witness::read_entries(&path).unwrap_or_default();
    let start = entries.len().saturating_sub(lines);
    for e in &entries[start..] {
        print_entry(e, json);
    }
    let mut last_seq = entries.last().map(|e| e.seq).unwrap_or(0);

    if !follow {
        return Ok(0);
    }
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
        entries = witness::read_entries(&path).unwrap_or_default();
        let seen = last_seq;
        for e in entries.iter().filter(|e| e.seq > seen) {
            print_entry(e, json);
            last_seq = e.seq;
        }
    }
    Ok(0)
}

fn print_entry(e: &Entry, json: bool) {
    if json {
        println!("{}", serde_json::to_string(e).unwrap_or_default());
        return;
    }
    let action = match e.action.as_str() {
        "block" => pad("BLOCK", 7).red().bold().to_string(),
        "redact" => pad("REDACT", 7).yellow().bold().to_string(),
        _ if e.findings.is_empty() => pad("ok", 7).dimmed().to_string(),
        _ => pad("SEEN", 7).yellow().to_string(),
    };
    let status = match e.status {
        Some(s) if s < 400 => s.to_string().green().to_string(),
        Some(s) => s.to_string().red().to_string(),
        None => "---".red().to_string(),
    };
    let findings = if e.findings.is_empty() {
        String::new()
    } else {
        let list = e
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{} @ {}",
                    color_severity(&f.severity, describe_kind(&f.kind)),
                    f.path.dimmed()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("  {} finding(s): {list}", e.findings.len())
    };
    println!(
        "{}  {action}  {}  {} {}  {}  {status}  {:>6}{findings}",
        human_time(&e.ts).dimmed(),
        pad(&e.upstream, 9),
        e.method,
        pad(&e.path, 22),
        pad(e.model.as_deref().unwrap_or("-"), 24),
        human_duration(e.duration_ms),
    );
}

// ---------- report ----------

fn cmd_report(config_path: &Path, since: Option<String>, json: bool) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    let path = cfg.witness_path();
    let since_dur = since.as_deref().map(parse_duration).transpose()?;
    let cutoff = since_dur.map(|d| Utc::now() - chrono::Duration::from_std(d).unwrap_or_default());

    let entries = witness::read_entries(&path).unwrap_or_default();
    let selected: Vec<&Entry> = entries
        .iter()
        .filter(|e| match cutoff {
            Some(c) => parse_ts(&e.ts).map(|t| t >= c).unwrap_or(true),
            None => true,
        })
        .collect();

    let summary = Summary::from(&selected);
    if json {
        println!("{}", serde_json::to_string_pretty(&summary.to_json())?);
        return Ok(0);
    }

    println!();
    println!(
        "  {}  {}",
        "hedge report".bold(),
        match &since {
            Some(s) => format!("last {s}"),
            None => "all time".into(),
        }
        .dimmed()
    );
    println!("  witness   {}", path.display());
    if let (Some(f), Some(l)) = (&summary.first_ts, &summary.last_ts) {
        println!("  range     {}  →  {}", human_ts(f), human_ts(l));
    }
    println!();
    println!("  requests  {:>6}", summary.total);
    println!(
        "  forwarded {:>6}   {}",
        summary.forwarded,
        "clean, untouched".dimmed()
    );
    println!(
        "  observed  {:>6}   {}",
        summary.observed,
        "findings seen, forwarded unchanged (observe mode)".dimmed()
    );
    println!(
        "  redacted  {:>6}   {}",
        summary.redacted,
        "findings masked before forwarding".dimmed()
    );
    println!(
        "  blocked   {:>6}   {}",
        summary.blocked,
        "rejected, never reached the upstream".dimmed()
    );
    if summary.total > 0 {
        println!(
            "  latency   p50 {}  p95 {}  max {}",
            human_duration(summary.p50),
            human_duration(summary.p95),
            human_duration(summary.max_ms)
        );
    }
    if !summary.by_kind.is_empty() {
        println!();
        println!("  {}", "findings by kind".bold());
        for (kind, n) in sorted_desc(&summary.by_kind) {
            println!(
                "    {:>5}  {}  {}",
                n,
                pad(describe_kind(kind), 22),
                kind.dimmed()
            );
        }
    }
    if !summary.by_path.is_empty() {
        println!();
        println!("  {}", "where findings sit in requests".bold());
        for (p, n) in sorted_desc(&summary.by_path).into_iter().take(8) {
            println!("    {:>5}  {}", n, p);
        }
    }
    if !summary.by_upstream.is_empty() {
        println!();
        println!("  {}", "by upstream".bold());
        for (u, n) in sorted_desc(&summary.by_upstream) {
            println!("    {:>5}  {}", n, u);
        }
    }
    if !summary.by_model.is_empty() {
        println!();
        println!("  {}", "by model".bold());
        for (m, n) in sorted_desc(&summary.by_model) {
            println!("    {:>5}  {}", n, m);
        }
    }
    if summary.by_mode.len() > 1 {
        println!();
        println!(
            "  {}  {}",
            "modes seen".bold(),
            "(mode changed during this window)".dimmed()
        );
        for (m, n) in sorted_desc(&summary.by_mode) {
            println!("    {:>5}  {}", n, m);
        }
    }
    println!();
    Ok(0)
}

#[derive(Default)]
struct Summary {
    total: usize,
    forwarded: usize,
    observed: usize,
    redacted: usize,
    blocked: usize,
    first_ts: Option<String>,
    last_ts: Option<String>,
    p50: u64,
    p95: u64,
    max_ms: u64,
    by_kind: BTreeMap<String, usize>,
    by_path: BTreeMap<String, usize>,
    by_upstream: BTreeMap<String, usize>,
    by_model: BTreeMap<String, usize>,
    by_mode: BTreeMap<String, usize>,
}

impl Summary {
    fn from(entries: &[&Entry]) -> Self {
        let mut s = Summary {
            total: entries.len(),
            first_ts: entries.first().map(|e| e.ts.clone()),
            last_ts: entries.last().map(|e| e.ts.clone()),
            ..Default::default()
        };
        let mut durations: Vec<u64> = Vec::with_capacity(entries.len());
        for e in entries {
            match e.action.as_str() {
                "block" => s.blocked += 1,
                "redact" => s.redacted += 1,
                _ if e.findings.is_empty() => s.forwarded += 1,
                _ => s.observed += 1,
            }
            for f in &e.findings {
                *s.by_kind.entry(f.kind.clone()).or_default() += 1;
                *s.by_path.entry(strip_indices(&f.path)).or_default() += 1;
            }
            *s.by_upstream.entry(e.upstream.clone()).or_default() += 1;
            if let Some(m) = &e.model {
                *s.by_model.entry(m.clone()).or_default() += 1;
            }
            *s.by_mode.entry(e.mode.clone()).or_default() += 1;
            durations.push(e.duration_ms);
        }
        durations.sort_unstable();
        if !durations.is_empty() {
            s.p50 = durations[durations.len() / 2];
            s.p95 = durations[(durations.len() * 95 / 100).min(durations.len() - 1)];
            s.max_ms = *durations.last().unwrap();
        }
        s
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total": self.total,
            "forwarded": self.forwarded,
            "observed": self.observed,
            "redacted": self.redacted,
            "blocked": self.blocked,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "latency_ms": { "p50": self.p50, "p95": self.p95, "max": self.max_ms },
            "by_kind": self.by_kind,
            "by_path": self.by_path,
            "by_upstream": self.by_upstream,
            "by_model": self.by_model,
            "by_mode": self.by_mode,
        })
    }
}

/// `messages[12].content[0].text` → `messages[].content[].text`, damit sich
/// gleiche Stellen über viele Requests aufsummieren.
fn strip_indices(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut in_bracket = false;
    for c in path.chars() {
        match c {
            '[' => {
                in_bracket = true;
                out.push('[');
            }
            ']' => {
                in_bracket = false;
                out.push(']');
            }
            _ if in_bracket => {}
            _ => out.push(c),
        }
    }
    out
}

fn sorted_desc(map: &BTreeMap<String, usize>) -> Vec<(&str, usize)> {
    let mut v: Vec<(&str, usize)> = map.iter().map(|(k, n)| (k.as_str(), *n)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v
}

// ---------- doctor ----------

async fn cmd_doctor(config_path: &Path) -> Result<i32> {
    let mut problems = 0;
    println!();
    println!("  {}", "hedge doctor".bold());
    println!();

    // 1. Config
    let cfg = match Config::load(config_path) {
        Ok(cfg) => {
            println!("  {} config      {}", ok(), config_path.display());
            cfg
        }
        Err(e) => {
            println!("  {} config      {}", fail(), e);
            println!("                 → run `hedge init` or fix the file above");
            println!();
            return Ok(1);
        }
    };

    // 2. Port / läuft Hedge schon?
    match tokio::net::TcpListener::bind(&cfg.server.listen).await {
        Ok(_) => println!(
            "  {} port        {} is free (hedge is not running)",
            ok(),
            cfg.server.listen
        ),
        Err(_) => {
            let health = reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()?
                .get(format!("http://{}/health", cfg.server.listen))
                .send()
                .await;
            match health {
                Ok(r) if r.status().is_success() => println!(
                    "  {} port        {} – hedge is running",
                    ok(),
                    cfg.server.listen
                ),
                _ => {
                    problems += 1;
                    println!(
                        "  {} port        {} is taken by something that is not hedge",
                        fail(),
                        cfg.server.listen
                    );
                }
            }
        }
    }

    // 3. Upstreams erreichbar
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    for u in &cfg.upstreams {
        match client.get(&u.url).send().await {
            Ok(r) => println!(
                "  {} upstream    {}  {}  (HTTP {})",
                ok(),
                pad(&u.name, 10),
                u.url,
                r.status().as_u16()
            ),
            Err(e) => {
                problems += 1;
                println!(
                    "  {} upstream    {}  {}  unreachable: {}",
                    fail(),
                    pad(&u.name, 10),
                    u.url,
                    short_err(&e)
                );
            }
        }
    }

    // 4. Witness
    if cfg.witness.enabled {
        let key = cfg.witness_key_path();
        match witness::load_verifying_key(&key) {
            Ok(vk) => {
                println!(
                    "  {} signing key {} (key id {})",
                    ok(),
                    key.display(),
                    witness::key_id_of(&vk)
                );
                let path = cfg.witness_path();
                match witness::read_entries(&path) {
                    Ok(entries) => {
                        let report = witness::verify(&entries, &vk);
                        if report.is_ok() {
                            println!(
                                "  {} witness     {} – {} entries, chain intact",
                                ok(),
                                path.display(),
                                report.entries
                            );
                        } else {
                            problems += 1;
                            println!(
                                "  {} witness     {} – {} problem(s), run `hedge verify`",
                                fail(),
                                path.display(),
                                report.problems.len()
                            );
                        }
                    }
                    Err(witness::WitnessError::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound =>
                    {
                        println!(
                            "  {} witness     {} – not created yet (first request creates it)",
                            "·".dimmed(),
                            path.display()
                        );
                    }
                    Err(e) => {
                        problems += 1;
                        println!("  {} witness     {}", fail(), e);
                    }
                }
            }
            Err(e) => {
                problems += 1;
                println!("  {} signing key {}", fail(), e);
                println!("                 → run `hedge init`");
            }
        }
    } else {
        println!(
            "  {} witness     disabled in config – requests are not being recorded",
            "!".yellow()
        );
    }

    // 5. Agent-Setup
    let first = cfg
        .upstreams
        .first()
        .map(|u| u.name.as_str())
        .unwrap_or("anthropic");
    let expected = format!("http://{}/{first}", cfg.server.listen);
    let env_now = std::env::var("ANTHROPIC_BASE_URL").ok();
    let settings = claude_settings_path();
    let in_settings = std::fs::read_to_string(&settings)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v["env"]["ANTHROPIC_BASE_URL"].as_str().map(str::to_owned));
    match (env_now.as_deref(), in_settings.as_deref()) {
        (Some(e), _) if e.starts_with(&expected) => {
            println!("  {} claude code ANTHROPIC_BASE_URL={e} (shell)", ok())
        }
        (_, Some(s)) if s.starts_with(&expected) => println!(
            "  {} claude code ANTHROPIC_BASE_URL={s} ({})",
            ok(),
            settings.display()
        ),
        (Some(e), _) => {
            problems += 1;
            println!(
                "  {} claude code ANTHROPIC_BASE_URL={e} does not point to hedge",
                fail()
            );
            println!("                 → export ANTHROPIC_BASE_URL={expected}");
        }
        (None, Some(s)) => {
            problems += 1;
            println!(
                "  {} claude code settings.json points to {s}, not to hedge",
                fail()
            );
            println!("                 → hedge init --claude-code");
        }
        (None, None) => {
            problems += 1;
            println!("  {} claude code not pointed at hedge yet", fail());
            println!(
                "                 → hedge init --claude-code   or   export ANTHROPIC_BASE_URL={expected}"
            );
        }
    }

    println!();
    if problems == 0 {
        println!("  {} {}", ok(), "everything looks good".green());
    } else {
        println!(
            "  {} {}",
            fail(),
            format!("{problems} thing(s) to fix").red()
        );
    }
    println!();
    Ok(if problems == 0 { 0 } else { 1 })
}

// ---------- helpers ----------

fn load_or_hint(path: &Path) -> Result<Config> {
    Config::load(path).map_err(|e| {
        if !path.exists() {
            format!(
                "{e}\n       → no config found. Run `hedge init` to create one at {}",
                config::default_dir().join("hedge.toml").display()
            )
            .into()
        } else {
            e.into()
        }
    })
}

fn ok() -> String {
    "✓".green().to_string()
}

fn fail() -> String {
    "✗".red().to_string()
}

fn pad(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n >= width {
        s.to_owned()
    } else {
        format!("{s}{}", " ".repeat(width - n))
    }
}

fn mode_colored(mode: Mode) -> String {
    match mode {
        Mode::Observe => "observe".blue().to_string(),
        Mode::Redact => "redact".yellow().to_string(),
        Mode::Block => "block".red().to_string(),
    }
}

fn mode_help(mode: Mode) -> &'static str {
    match mode {
        Mode::Observe => "report only, nothing is changed",
        Mode::Redact => "findings are masked before forwarding",
        Mode::Block => "high-severity findings reject the request, others are masked",
    }
}

fn detector_list(cfg: &Config) -> String {
    let mut v = Vec::new();
    if cfg.detectors.secrets {
        v.push("secrets");
    }
    if cfg.detectors.pii {
        v.push("pii");
    }
    if v.is_empty() {
        "none (!)".red().to_string()
    } else {
        v.join(", ")
    }
}

fn color_severity(severity: &str, text: &str) -> String {
    match severity {
        "high" => text.red().to_string(),
        "medium" => text.yellow().to_string(),
        _ => text.to_string(),
    }
}

fn parse_ts(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// `2026-11-09T13:20:11.123Z` → `2026-11-09 13:20:11` in lokaler Zeit.
fn human_ts(ts: &str) -> String {
    parse_ts(ts)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| ts.to_owned())
}

fn human_time(ts: &str) -> String {
    parse_ts(ts)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| ts.to_owned())
}

fn human_duration(ms: u64) -> String {
    if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
    }
}

/// "30m", "24h", "7d"
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration {s:?}, use e.g. 30m, 24h, 7d"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(format!("invalid duration {s:?}, use e.g. 30m, 24h, 7d").into()),
    };
    Ok(Duration::from_secs(secs))
}

fn short_err(e: &reqwest::Error) -> String {
    let mut source: &dyn Error = e;
    while let Some(next) = source.source() {
        source = next;
    }
    source.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
        assert_eq!(
            parse_duration("7d").unwrap(),
            Duration::from_secs(7 * 86_400)
        );
        assert!(parse_duration("7x").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn strip_indices_collapses_array_positions() {
        assert_eq!(
            strip_indices("messages[12].content[0].text"),
            "messages[].content[].text"
        );
        assert_eq!(strip_indices("system"), "system");
    }

    #[test]
    fn human_duration_formats() {
        assert_eq!(human_duration(42), "42ms");
        assert_eq!(human_duration(1234), "1.2s");
    }

    #[test]
    fn claude_code_env_is_merged_not_replaced() {
        let dir = std::env::temp_dir().join(format!("hedge-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let settings = dir.join("settings.json");
        std::fs::write(
            &settings,
            r#"{"permissions":{"allow":["Bash"]},"env":{"FOO":"bar"}}"#,
        )
        .unwrap();

        write_claude_code_env(&settings, "http://127.0.0.1:18765/anthropic").unwrap();

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(
            doc["env"]["ANTHROPIC_BASE_URL"],
            "http://127.0.0.1:18765/anthropic"
        );
        assert_eq!(doc["env"]["FOO"], "bar");
        assert_eq!(doc["permissions"]["allow"][0], "Bash");
        assert!(dir.join("settings.json.bak").exists());
    }

    #[test]
    fn claude_code_env_creates_missing_settings() {
        let dir = std::env::temp_dir().join(format!("hedge-cli-new-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let settings = dir.join(".claude").join("settings.json");

        write_claude_code_env(&settings, "http://127.0.0.1:18765/anthropic").unwrap();

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(
            doc["env"]["ANTHROPIC_BASE_URL"],
            "http://127.0.0.1:18765/anthropic"
        );
    }
}
