//! `hedge presidio …`: Presidio als Feature von Hedge.
//!
//! Lokal ist das ein Befehl: `hedge presidio enable` prüft die
//! Container-Laufzeit, holt das Image, startet den Container auf Loopback,
//! wartet auf die Sprachmodelle, macht einen Selbsttest und trägt erst dann
//! `enabled = true` ein. Geht ein Schritt schief, nennt die Ausgabe den
//! Befehl, der hilft – und die Config bleibt, wie sie war.

use std::io::{IsTerminal, Read};
use std::path::Path;
use std::time::{Duration, Instant};

use colored::Colorize;
use serde_json::Value;

use super::{Control, Remote, Result, fail, human_count, human_duration, load_or_hint, ok, pad};
use crate::config::{self, Config, Mode, OnUnavailable, Presidio as PresidioCfg, PresidioExposure};
use crate::detect::describe_kind;
use crate::presidio::sidecar::{CONTAINER, Ensure, Ensured, Sidecar};
use crate::presidio::{Presidio, Problem, ServerInfo, TestReport};

/// So lange darf der Container nach `enable` zum Laden der Modelle brauchen.
const READY_TIMEOUT: Duration = Duration::from_secs(240);

pub(super) struct EnableOpts {
    pub build: bool,
    pub pull: bool,
    pub image: Option<String>,
    pub port: Option<u16>,
}

fn row(mark: &str, label: &str, text: impl std::fmt::Display) {
    println!("  {mark} {}{text}", pad(label, 14));
}

fn note(label: &str, text: impl std::fmt::Display) {
    row(&"·".dimmed().to_string(), label, text);
}

fn warn(label: &str, text: impl std::fmt::Display) {
    row(&"!".yellow().bold().to_string(), label, text);
}

/// Die Zeile mit dem Befehl, der das Problem behebt.
fn fix(text: &str) {
    println!("  {}→ {}", " ".repeat(17), text.cyan());
}

/// Ein Problem mit Abhilfe ausgeben und 1 liefern.
fn stop(label: &str, problem: &Problem) -> i32 {
    row(&fail(), label, &problem.reason);
    if let Some(hint) = &problem.hint {
        fix(hint);
    }
    println!();
    1
}

fn human_bytes(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1} GB", n as f64 / 1e9)
    } else {
        format!("{} MB", n / 1_000_000)
    }
}

/// Was mit Funden passiert, in einem Satz.
pub(super) fn findings_line(cfg: &Config) -> String {
    let p = &cfg.presidio;
    match (p.enforce, cfg.mode) {
        (false, _) => "reported only (enforce = false)".into(),
        (true, Mode::Observe) => "reported only (mode = observe)".into(),
        (true, Mode::Redact) => "masked before forwarding (mode = redact)".into(),
        (true, Mode::Block) => "masked, high severity blocks the request (mode = block)".into(),
    }
}

/// Was bei einem Ausfall passiert, in einem Satz.
pub(super) fn outage_line(cfg: &Config) -> String {
    match (cfg.presidio.on_unavailable, cfg.presidio_guards()) {
        (OnUnavailable::Allow, _) => "requests continue and are flagged".into(),
        (OnUnavailable::Block, true) => {
            "requests with text to check are rejected (HTTP 503)".into()
        }
        (OnUnavailable::Block, false) => {
            "requests continue and are flagged – block applies once enforce = true and mode is not observe"
                .into()
        }
    }
}

fn sample_for(languages: &[String]) -> (&'static str, &'static str) {
    match languages.first().map(String::as_str) {
        Some("de") => ("Jörg Müller, Tel. +49 170 1234567", "de"),
        _ if languages.iter().any(|l| l == "en") => ("John Smith, phone +1 415 555 0132", "en"),
        _ => ("John Smith, phone +1 415 555 0132", ""),
    }
}

fn kinds_found(report: &TestReport) -> String {
    let mut kinds: Vec<&str> = Vec::new();
    for h in report.hits.iter().filter(|h| h.reported) {
        let k = describe_kind(h.kind);
        if !kinds.contains(&k) {
            kinds.push(k);
        }
    }
    if kinds.is_empty() {
        "nothing".into()
    } else {
        kinds.join(", ")
    }
}

// ---------- enable / upgrade ----------

pub(super) async fn enable(config_path: &Path, opts: EnableOpts, upgrade: bool) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    println!();

    if cfg.presidio.enabled && !cfg.presidio.managed && !cfg.presidio.is_local() {
        note(
            "presidio",
            format!(
                "is an external service here ({}, managed = false)",
                cfg.presidio.url
            ),
        );
        println!(
            "  {}`hedge presidio enable` runs a local container. To check the external one: {}",
            " ".repeat(16),
            "hedge presidio status".cyan()
        );
        println!();
        return Ok(1);
    }
    if upgrade && !cfg.presidio.managed {
        note("presidio", "is not managed by hedge on this machine");
        fix("hedge presidio enable");
        println!();
        return Ok(1);
    }

    // Die Config, wie sie nach diesem Befehl aussehen soll.
    let mut target: PresidioCfg = cfg.presidio.clone();
    target.enabled = true;
    target.managed = true;
    if let Some(image) = &opts.image {
        target.image = Some(image.clone());
    }
    if let Some(port) = opts.port {
        target.url = format!("http://127.0.0.1:{port}");
    }
    if !target.is_local() || !target.url.starts_with("http://") {
        // Eine alte url auf einen fremden Host passt nicht zu einem lokalen Container.
        target.url = PresidioCfg::default().url;
    }

    // 1. Container-Laufzeit
    let sidecar = match Sidecar::from_config(&target) {
        Ok(s) => s,
        Err(p) => return Ok(stop("runtime", &p)),
    };
    match sidecar.daemon().await {
        Ok(name) => row(&ok(), sidecar.runtime(), format!("running ({name})")),
        Err(p) => return Ok(stop(sidecar.runtime(), &p)),
    }

    // 2. Image und Container
    let had_image = sidecar
        .local_image(&sidecar.image)
        .await
        .ok()
        .flatten()
        .is_some();
    if opts.build {
        note("image", format!("building {} …", sidecar.image));
    } else if opts.pull || !had_image {
        note(
            "image",
            format!("pulling {} (about 1 GB, once) …", sidecar.image),
        );
    }
    if opts.pull
        && !opts.build
        && let Err(p) = sidecar.pull().await
    {
        return Ok(stop("image", &p));
    }
    let started = Instant::now();
    let ensured = match sidecar.ensure(Ensure::Converge { build: opts.build }).await {
        Ok(e) => e,
        Err(p) => {
            let label = if p.reason.contains("pull") || p.reason.contains("build") {
                "image"
            } else {
                "container"
            };
            return Ok(stop(label, &p));
        }
    };
    let image = sidecar.local_image(&sidecar.image).await.ok().flatten();
    let image_note = match &image {
        Some(i) => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(l) = &i.languages {
                parts.push(l.replace(',', ", "));
            }
            if !i.arch.is_empty() {
                parts.push(i.arch.clone());
            }
            if i.size_bytes > 0 {
                parts.push(human_bytes(i.size_bytes));
            }
            format!(" ({})", parts.join(" · "))
        }
        None => String::new(),
    };
    row(&ok(), "image", format!("{}{image_note}", sidecar.image));
    if let Some(i) = &image
        && let Some(host) = host_arch()
        && !i.arch.is_empty()
        && i.arch != host
    {
        warn(
            "image",
            format!(
                "is built for {}, this machine is {host}: it runs emulated and slower",
                i.arch
            ),
        );
        if !opts.build {
            fix("hedge presidio upgrade --build   (builds it for this machine)");
        }
    }
    row(
        &ok(),
        "container",
        format!(
            "{CONTAINER} on {}:{} ({})",
            sidecar.host,
            sidecar.port,
            match ensured {
                Ensured::Running => "was running",
                Ensured::Started => "started",
                Ensured::Created => "created",
            }
        ),
    );

    // 3. Warten, bis die Modelle geladen sind
    let presidio = Presidio::new(&target)?;
    if ensured != Ensured::Running {
        note("ready", "loading the language models …");
    }
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if presidio.check(false).await.is_ok() {
            break;
        }
        let crashed = sidecar
            .container()
            .await
            .ok()
            .flatten()
            .is_some_and(|c| !c.running() && c.status != "created");
        if crashed || Instant::now() >= deadline {
            let reason = if crashed {
                "the container stopped while starting".to_owned()
            } else {
                format!(
                    "no answer from {} after {} s",
                    target.url,
                    READY_TIMEOUT.as_secs()
                )
            };
            row(&fail(), "ready", reason);
            for line in sidecar.last_log_lines(8).await {
                println!("  {}{}", " ".repeat(16), line.dimmed());
            }
            fix("hedge presidio logs");
            println!();
            return Ok(1);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // 4. Kann es, was die Config verlangt? (Testsatz pro Sprache)
    let server = match presidio.check(true).await {
        Ok(server) => server,
        Err(p) => return Ok(stop("ready", &p)),
    };
    row(
        &ok(),
        "ready",
        format!(
            "{}{}",
            if ensured == Ensured::Running {
                "answers".to_owned()
            } else {
                format!(
                    "after {}",
                    human_duration(started.elapsed().as_millis() as u64)
                )
            },
            server_note(server.as_ref())
        ),
    );

    // 5. Selbsttest, so wie Hedge im Betrieb fragt
    let (sample, lang) = sample_for(&target.languages());
    let lang = (!lang.is_empty()).then_some(lang);
    match presidio.try_text(sample, lang).await {
        Ok(report) => {
            let shown: String = sample.chars().take(sample.chars().count() - 7).collect();
            row(
                &ok(),
                "self-test",
                format!(
                    "\"{shown}…\" → {} ({} ms)",
                    kinds_found(&report),
                    report.duration_ms
                ),
            );
        }
        Err(e) => return Ok(stop("self-test", &Problem::new(e))),
    }

    // 6. Erst jetzt die Config ändern
    let mut text = std::fs::read_to_string(config_path)?;
    let mut changed: Vec<&str> = Vec::new();
    if !cfg.presidio.enabled {
        text = config::set_key(&text, "presidio", "enabled", "true");
        changed.push("enabled = true");
    }
    if !cfg.presidio.managed {
        text = config::set_key(&text, "presidio", "managed", "true");
        changed.push("managed = true");
    }
    if target.url != cfg.presidio.url {
        text = config::set_key(&text, "presidio", "url", &format!("{:?}", target.url));
        changed.push("url");
    }
    if let Some(image) = &opts.image {
        text = config::set_key(&text, "presidio", "image", &format!("{image:?}"));
        changed.push("image");
    }
    if changed.is_empty() {
        row(&ok(), "config", "already enabled, nothing to change");
    } else {
        Config::from_toml(&text)
            .map_err(|e| e.to_string())
            .and_then(|c| c.validate().map_err(|e| e.to_string()))
            .map_err(|e| format!("the change would break {}: {e}", config_path.display()))?;
        std::fs::write(config_path, &text)?;
        row(
            &ok(),
            "config",
            format!(
                "{}: [presidio] {}",
                config_path.display(),
                changed.join(", ")
            ),
        );
    }

    // 7. Hat ein laufender Hedge es übernommen?
    match live_presidio(config_path, Duration::from_secs(8)).await {
        Live::Ready if changed.is_empty() => {
            row(&ok(), "hedge", "is running and has presidio ready")
        }
        Live::Ready => row(&ok(), "hedge", "picked up the change, no restart needed"),
        Live::NotReady(state) => {
            warn(
                "hedge",
                format!("is running but reports presidio as {state}"),
            );
            fix("hedge presidio status");
        }
        Live::NotRunning => note(
            "hedge",
            format!(
                "is not running – {} starts presidio with it",
                "hedge run".cyan()
            ),
        ),
    }

    let after = Config::load(config_path)?;
    println!();
    println!("  Findings are {}.", findings_line(&after));
    if !after.presidio.enforce {
        println!(
            "  See what it finds in real traffic with {} and {}, try a text with",
            "hedge report".cyan(),
            "hedge tail -f".cyan()
        );
        println!(
            "  {}, then set {} in the config.",
            "hedge presidio test \"<text>\"".cyan(),
            "[presidio] enforce = true".cyan()
        );
    }
    println!();
    Ok(0)
}

fn server_note(server: Option<&ServerInfo>) -> String {
    match server {
        Some(s) if !s.presidio.is_empty() => {
            format!(" · presidio {} · {}", s.presidio, s.models.join(", "))
        }
        _ => String::new(),
    }
}

/// Architektur dieses Rechners, wie Container-Laufzeiten sie nennen.
fn host_arch() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "aarch64" => Some("arm64"),
        "x86_64" => Some("amd64"),
        _ => None,
    }
}

enum Live {
    Ready,
    NotReady(String),
    NotRunning,
}

/// Fragt den laufenden Hedge, bis er Presidio als bereit meldet.
async fn live_presidio(config_path: &Path, patience: Duration) -> Live {
    let Ok(control) = Control::new(config_path, Remote::default()) else {
        return Live::NotRunning;
    };
    let deadline = Instant::now() + patience;
    loop {
        let Ok(s) = control.call(reqwest::Method::GET, "/_hedge/status").await else {
            return Live::NotRunning;
        };
        let state = s["presidio"]["state"].as_str().unwrap_or("off").to_owned();
        if state == "ready" {
            return Live::Ready;
        }
        if Instant::now() >= deadline {
            return Live::NotReady(state);
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

// ---------- disable ----------

pub(super) async fn disable(config_path: &Path, remove: bool) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    println!();
    if cfg.presidio.enabled {
        let text = std::fs::read_to_string(config_path)?;
        let text = config::set_key(&text, "presidio", "enabled", "false");
        Config::from_toml(&text)
            .map_err(|e| e.to_string())
            .and_then(|c| c.validate().map_err(|e| e.to_string()))
            .map_err(|e| format!("the change would break {}: {e}", config_path.display()))?;
        std::fs::write(config_path, text)?;
        row(
            &ok(),
            "config",
            format!("{}: [presidio] enabled = false", config_path.display()),
        );
    } else {
        note("config", "presidio was not enabled");
    }

    if cfg.presidio.managed {
        match Sidecar::from_config(&cfg.presidio) {
            Ok(sidecar) => match sidecar.container().await {
                Ok(Some(c)) if !c.ours => note(
                    "container",
                    format!("{CONTAINER} was not created by hedge, left alone"),
                ),
                Ok(Some(_)) if remove => match sidecar.remove().await {
                    Ok(()) => row(&ok(), "container", format!("{CONTAINER} removed")),
                    Err(p) => return Ok(stop("container", &p)),
                },
                Ok(Some(c)) if c.running() => match sidecar.stop().await {
                    Ok(()) => {
                        row(
                            &ok(),
                            "container",
                            format!("{CONTAINER} stopped, kept for next time"),
                        );
                        println!(
                            "  {}delete it with {}",
                            " ".repeat(16),
                            "hedge presidio disable --remove".cyan()
                        );
                    }
                    Err(p) => return Ok(stop("container", &p)),
                },
                Ok(Some(_)) => note("container", format!("{CONTAINER} was already stopped")),
                Ok(None) => note("container", "none to stop"),
                Err(p) => warn("container", p.reason),
            },
            Err(p) => warn("container", p.reason),
        }
    }
    println!();
    println!("  The built-in detectors (secrets, e-mail, IBAN) keep working.");
    println!();
    Ok(0)
}

// ---------- status ----------

fn state_mark(state: &str) -> String {
    match state {
        "ready" => format!("{} {}", "●".green(), "ready".green().bold()),
        "starting" => format!("{} {}", "◌".yellow(), "starting".yellow().bold()),
        "unavailable" => format!("{} {}", "○".red(), "unavailable".red().bold()),
        other => format!("{} {}", "○".dimmed(), other.dimmed()),
    }
}

/// Die eine Zeile, die `hedge status` und der Banner über Presidio zeigen.
pub(super) fn one_line(p: &Value) -> Option<String> {
    // Ein älterer Hedge meldet nur true/false.
    if let Some(on) = p.as_bool() {
        return on.then(|| "on".to_owned());
    }
    let state = p["state"].as_str().unwrap_or("off");
    if state == "off" {
        return None;
    }
    let languages: Vec<&str> = p["languages"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut line = format!("{}  {}", state_mark(state), languages.join(", "));
    if state == "ready" {
        line.push_str(if p["enforce"].as_bool().unwrap_or(false) {
            " · enforced"
        } else {
            " · reports only"
        });
        let n = |k: &str| p["since_start"][k].as_u64().unwrap_or(0);
        let (analyzed, cached) = (n("analyzed"), n("cached"));
        if analyzed + cached > 0 {
            line.push_str(&format!(
                " · {} texts, {}% from cache",
                human_count(analyzed + cached),
                cached * 100 / (analyzed + cached)
            ));
        }
        if n("unscanned_requests") > 0 {
            line.push_str(
                &format!(" · {} requests unchecked", n("unscanned_requests"))
                    .yellow()
                    .to_string(),
            );
        }
    } else if let Some(reason) = p["reason"].as_str() {
        line.push_str(&format!(" – {reason}"));
    }
    Some(line)
}

pub(super) async fn status(config_path: &Path, remote: Remote, json: bool) -> Result<i32> {
    let is_remote = remote.url.is_some();
    // Was der laufende Hedge sagt, zählt zuerst: Er ist es, der fragt.
    let live: Option<Value> = match Control::new(config_path, remote) {
        Ok(c) => c
            .call(reqwest::Method::GET, "/_hedge/status")
            .await
            .ok()
            .map(|s| s["presidio"].clone()),
        Err(e) if is_remote => return Err(e),
        Err(_) => None,
    };
    if is_remote {
        let Some(p) = live else {
            return Err("that hedge did not answer".into());
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&p)?);
        } else {
            println!();
            match one_line(&p) {
                Some(line) => println!("  presidio    {line}"),
                None => println!("  presidio    {}", "off on that hedge".dimmed()),
            }
            if let Some(hint) = p["hint"].as_str() {
                fix(hint);
            }
            println!();
        }
        return Ok(i32::from(
            p["enabled"].as_bool().unwrap_or(false) && p["state"] != "ready",
        ));
    }

    let cfg = load_or_hint(config_path)?;
    let p = &cfg.presidio;
    if !p.enabled {
        if json {
            println!(
                "{}",
                serde_json::json!({ "enabled": false, "state": "off" })
            );
            return Ok(0);
        }
        println!();
        println!("  presidio    {}", "off".dimmed());
        println!(
            "              names and phone numbers are not detected. Switch it on: {}",
            "hedge presidio enable".cyan()
        );
        println!();
        return Ok(0);
    }

    // Läuft Hedge nicht, fragt dieser Befehl Presidio selbst.
    let direct = match &live {
        Some(v) if v["state"].is_string() && v["state"] != "off" => None,
        _ => Some(Presidio::new(p)?.check(true).await),
    };
    let (state, reason, mut hint, server): (
        String,
        Option<String>,
        Option<String>,
        Option<ServerInfo>,
    ) = match (&live, &direct) {
        (_, Some(Ok(server))) => ("ready".into(), None, None, server.clone()),
        (_, Some(Err(problem))) => (
            "unavailable".into(),
            Some(problem.reason.clone()),
            problem.hint.clone(),
            None,
        ),
        (Some(v), None) => (
            v["state"].as_str().unwrap_or("?").to_owned(),
            v["reason"].as_str().map(str::to_owned),
            v["hint"].as_str().map(str::to_owned),
            serde_json::from_value(v["server"].clone()).ok(),
        ),
        (None, None) => ("unknown".into(), None, None, None),
    };

    // Der eigene Container, falls Hedge ihn verwaltet.
    let mut container_line: Option<String> = None;
    let mut drift: Option<String> = None;
    if p.managed {
        match Sidecar::from_config(p) {
            Ok(sidecar) => match sidecar.daemon().await {
                Ok(_) => match sidecar.container().await {
                    Ok(Some(c)) => {
                        drift = sidecar.drift(&c).await;
                        container_line = Some(format!(
                            "{CONTAINER} · {} · {}",
                            if c.running() {
                                c.status.green().to_string()
                            } else {
                                c.status.red().to_string()
                            },
                            c.image
                        ));
                    }
                    Ok(None) => {
                        container_line = Some("does not exist".red().to_string());
                        hint.get_or_insert("hedge presidio enable".into());
                    }
                    Err(problem) => container_line = Some(problem.reason),
                },
                Err(problem) => {
                    container_line = Some(problem.reason.clone());
                    if state != "ready" {
                        hint = problem.hint;
                    }
                }
            },
            Err(problem) => {
                container_line = Some(problem.reason.clone());
                if state != "ready" {
                    hint = problem.hint;
                }
            }
        }
    }

    // Läuft der Container und antwortet trotzdem nicht, steht der Grund in
    // seiner Ausgabe.
    if state != "ready" && hint.is_none() && p.managed {
        hint = Some("hedge presidio logs".into());
    }

    if json {
        let mut out = live
            .filter(|v| v["state"].is_string() && v["state"] != "off")
            .unwrap_or_else(|| {
                serde_json::json!({
                    "enabled": true,
                    "state": state,
                    "reason": reason,
                    "hint": hint,
                    "url": p.url,
                    "managed": p.managed,
                    "languages": p.languages(),
                    "server": server,
                })
            });
        out["container_drift"] = serde_json::json!(drift);
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(i32::from(state != "ready"));
    }

    println!();
    println!(
        "  presidio    {}{}",
        state_mark(&state),
        if live.is_none() {
            "   (hedge is not running; asked presidio directly)"
                .dimmed()
                .to_string()
        } else {
            String::new()
        }
    );
    if let Some(reason) = &reason {
        println!("              {reason}");
    }
    if let Some(hint) = &hint {
        fix(hint);
    }
    println!(
        "  url         {}  {}",
        p.url,
        if p.managed {
            "(container managed by hedge)"
        } else {
            "(external, managed = false)"
        }
        .dimmed()
    );
    if let Some(line) = container_line {
        println!("  container   {line}");
    }
    if let Some(d) = &drift {
        warn("container", d);
        fix("hedge presidio upgrade");
    }
    if let Some(s) = server.as_ref().filter(|s| !s.presidio.is_empty()) {
        println!(
            "  server      {} · presidio {} · {}",
            s.service,
            s.presidio,
            s.models.join(", ")
        );
    }
    println!(
        "  languages   {}  {}",
        p.languages().join(", "),
        "(the first one is used when a text's language is unclear)".dimmed()
    );
    println!(
        "  looks for   {}  in: {}",
        p.entities.join(", "),
        p.scope
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  findings    {}", findings_line(&cfg));
    println!("  on outage   {}", outage_line(&cfg));
    if let Some(v) = &live {
        let n = |k: &str| v["since_start"][k].as_u64().unwrap_or(0);
        let (analyzed, cached) = (n("analyzed"), n("cached"));
        if analyzed + cached + n("failed") + n("unscanned_requests") > 0 {
            println!(
                "  since start {} texts analysed, {} from cache{}, {} failed, {} requests unchecked",
                human_count(analyzed),
                human_count(cached),
                (cached * 100)
                    .checked_div(analyzed + cached)
                    .map(|pct| format!(" ({pct}%)"))
                    .unwrap_or_default(),
                n("failed"),
                n("unscanned_requests")
            );
        }
    }
    println!();
    Ok(i32::from(state != "ready"))
}

// ---------- test ----------

pub(super) async fn test(
    config_path: &Path,
    words: Vec<String>,
    language: Option<String>,
    json: bool,
) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    let text = if words.is_empty() {
        if std::io::stdin().is_terminal() {
            return Err("give a text to analyse: hedge presidio test \"Jörg Müller ruft an\" (or pipe one in)".into());
        }
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        words.join(" ")
    };
    if text.trim().is_empty() {
        return Err("the text is empty".into());
    }
    if let Some(l) = &language
        && !cfg.presidio.languages().contains(l)
    {
        return Err(format!(
            "language {l:?} is not in [presidio] languages ({})",
            cfg.presidio.languages().join(", ")
        )
        .into());
    }
    let presidio = Presidio::new(&cfg.presidio)?;
    let report = match presidio.try_text(&text, language.as_deref()).await {
        Ok(r) => r,
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({ "error": e }));
                return Ok(1);
            }
            println!();
            row(&fail(), "presidio", format!("{} – {e}", cfg.presidio.url));
            fix(if cfg.presidio.enabled {
                "hedge presidio status"
            } else {
                "hedge presidio enable"
            });
            println!();
            return Ok(1);
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    println!();
    println!(
        "  language    {}{}   {} ms",
        report.language.bold(),
        if language.is_some() {
            ""
        } else if cfg.presidio.languages().len() > 1 {
            " (chosen for this text)"
        } else {
            ""
        },
        report.duration_ms
    );
    if report.hits.is_empty() {
        println!("  findings    {}", "none".dimmed());
    }
    let width = report
        .hits
        .iter()
        .map(|h| text[h.start..h.end].chars().count())
        .max()
        .unwrap_or(0)
        .clamp(8, 40);
    for h in &report.hits {
        let matched: String = text[h.start..h.end]
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let verdict = match h.dropped {
            None => "reported".green().to_string(),
            Some("below_threshold") => format!(
                "not reported: below the threshold of {:.2}",
                report.threshold
            )
            .dimmed()
            .to_string(),
            Some("single_word") => {
                "not reported: a single word without a title (single_names = true reports these)"
                    .dimmed()
                    .to_string()
            }
            Some(_) => "not reported: does not look like a name"
                .dimmed()
                .to_string(),
        };
        println!(
            "  {}  {}  {:.2}  {verdict}",
            pad(&super::truncate(&matched, width), width).bold(),
            pad(describe_kind(h.kind), 20),
            h.score
        );
    }

    // So sähe der Text nach dem Maskieren aus.
    let reported: Vec<crate::detect::Finding> = report
        .hits
        .iter()
        .filter(|h| h.reported)
        .map(|h| crate::detect::Finding {
            detector: "presidio",
            kind: h.kind,
            severity: crate::detect::Severity::Medium,
            start: h.start,
            end: h.end,
        })
        .collect();
    if !reported.is_empty() {
        let mut masked = text.clone();
        crate::inspect::redact(&mut masked, &reported);
        let flat: String = masked
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        println!();
        println!("  masked      {}", super::truncate(&flat, 200));
    }
    println!();
    println!(
        "  {}",
        format!(
            "Looked for {} at a threshold of {:.2}. In live traffic, findings are {}.",
            cfg.presidio.entities.join(", "),
            report.threshold,
            findings_line(&cfg)
        )
        .dimmed()
    );
    println!();
    Ok(0)
}

// ---------- logs ----------

pub(super) async fn logs(config_path: &Path, follow: bool, lines: usize) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    if !cfg.presidio.managed {
        println!();
        note(
            "presidio",
            format!(
                "is not a container managed by hedge here ({}). Its logs are where it runs.",
                cfg.presidio.url
            ),
        );
        println!();
        return Ok(1);
    }
    let sidecar = match Sidecar::from_config(&cfg.presidio) {
        Ok(s) => s,
        Err(p) => {
            println!();
            return Ok(stop("runtime", &p));
        }
    };
    if let Err(p) = sidecar.daemon().await {
        println!();
        return Ok(stop(sidecar.runtime(), &p));
    }
    match sidecar.logs(follow, lines).await {
        Ok(true) => Ok(0),
        Ok(false) => {
            println!();
            fix("hedge presidio enable");
            Ok(1)
        }
        Err(p) => {
            println!();
            Ok(stop("logs", &p))
        }
    }
}

// ---------- doctor ----------

/// Der Presidio-Teil von `hedge doctor`. Liefert die Zahl der Probleme.
pub(super) async fn doctor(cfg: &Config) -> usize {
    let p = &cfg.presidio;
    let label = "presidio";
    if !p.enabled {
        note(
            label,
            format!(
                "off – names and phone numbers are not detected ({})",
                "hedge presidio enable".cyan()
            ),
        );
        return 0;
    }
    let mut problems = 0;

    // Wohin gehen die Prompts?
    match (p.exposure(), p.url.starts_with("https://")) {
        (PresidioExposure::Local, _) => {}
        (PresidioExposure::Private, false) => note(
            label,
            format!(
                "{} is on the internal network without TLS – make sure only hedge can reach it",
                p.url
            ),
        ),
        (PresidioExposure::Private, true) => {}
        (PresidioExposure::Public, false) => {
            problems += 1;
            row(
                &fail(),
                label,
                format!(
                    "{} is a foreign host reached over plain http: every prompt would travel there unencrypted",
                    p.url
                ),
            );
            fix("run presidio next to hedge (hedge presidio enable, or hedge deploy compose)");
        }
        (PresidioExposure::Public, true) => warn(
            label,
            format!(
                "{} is outside this network: every prompt in scope is sent there",
                p.url
            ),
        ),
    }

    // Der eigene Container
    if p.managed {
        match Sidecar::from_config(p) {
            Err(problem) => {
                problems += 1;
                row(&fail(), label, &problem.reason);
                if let Some(h) = &problem.hint {
                    fix(h);
                }
                return problems;
            }
            Ok(sidecar) => {
                if let Err(problem) = sidecar.daemon().await {
                    problems += 1;
                    row(&fail(), label, &problem.reason);
                    if let Some(h) = &problem.hint {
                        fix(h);
                    }
                    return problems;
                }
                match sidecar.container().await {
                    Ok(Some(c)) if !c.ours => {
                        problems += 1;
                        row(
                            &fail(),
                            label,
                            format!(
                                "a container named {CONTAINER} exists, but hedge did not create it"
                            ),
                        );
                        fix(&format!(
                            "{} rm -f {CONTAINER} && hedge presidio enable",
                            sidecar.runtime()
                        ));
                        return problems;
                    }
                    Ok(Some(c)) => {
                        if !c.running() {
                            problems += 1;
                            row(
                                &fail(),
                                label,
                                format!("the container {CONTAINER} is {}", c.status),
                            );
                            fix(&format!(
                                "{} start {CONTAINER}   (`hedge run` does this on its own)",
                                sidecar.runtime()
                            ));
                            return problems;
                        }
                        if let Some(d) = sidecar.drift(&c).await {
                            warn(label, d);
                            fix("hedge presidio upgrade");
                        }
                    }
                    Ok(None) => {
                        problems += 1;
                        row(
                            &fail(),
                            label,
                            format!("the container {CONTAINER} does not exist"),
                        );
                        fix("hedge presidio enable");
                        return problems;
                    }
                    Err(problem) => {
                        problems += 1;
                        row(&fail(), label, &problem.reason);
                        return problems;
                    }
                }
            }
        }
    }

    // Antwortet es, und kann es die Sprachen?
    match Presidio::new(p) {
        Ok(client) => match client.check(true).await {
            Ok(server) => row(
                &ok(),
                label,
                format!(
                    "{} ready – {}{}",
                    p.url,
                    p.languages().join(", "),
                    server_note(server.as_ref())
                ),
            ),
            Err(problem) => {
                problems += 1;
                row(&fail(), label, &problem.reason);
                fix(problem.hint.as_deref().unwrap_or(if p.managed {
                    "hedge presidio logs"
                } else {
                    "start presidio where it runs, then `hedge presidio status`"
                }));
            }
        },
        Err(e) => {
            problems += 1;
            row(&fail(), label, e);
        }
    }

    // Passt die Policy zum Betrieb?
    if p.on_unavailable == OnUnavailable::Block && !cfg.presidio_guards() {
        note(
            label,
            "on_unavailable = \"block\" has no effect yet: it applies once enforce = true and mode is not observe",
        );
    }
    if !cfg.is_loopback() && cfg.presidio_guards() && p.on_unavailable == OnUnavailable::Allow {
        warn(
            label,
            "central setup with on_unavailable = \"allow\": while presidio is down, names pass unnoticed",
        );
        fix("set [presidio] on_unavailable = \"block\"");
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(toml: &str) -> Config {
        let c = Config::from_toml(toml).unwrap();
        c.validate().unwrap();
        c
    }

    #[test]
    fn findings_and_outage_are_said_in_words() {
        let c = cfg("mode = \"redact\"\n[presidio]\nenabled = true");
        assert_eq!(findings_line(&c), "reported only (enforce = false)");
        assert_eq!(outage_line(&c), "requests continue and are flagged");

        let c = cfg(
            "mode = \"redact\"\n[presidio]\nenabled = true\nenforce = true\non_unavailable = \"block\"",
        );
        assert!(findings_line(&c).starts_with("masked"));
        assert!(outage_line(&c).contains("rejected"));

        let c = cfg(
            "mode = \"observe\"\n[presidio]\nenabled = true\nenforce = true\non_unavailable = \"block\"",
        );
        assert_eq!(findings_line(&c), "reported only (mode = observe)");
        assert!(outage_line(&c).contains("block applies once"));
    }

    #[test]
    fn one_line_reads_old_and_new_status() {
        colored::control::set_override(false);
        assert_eq!(one_line(&json!(false)), None);
        assert_eq!(one_line(&json!(true)).as_deref(), Some("on"));
        assert_eq!(one_line(&json!({"enabled": false, "state": "off"})), None);

        let ready = json!({"state": "ready", "languages": ["de", "en"], "enforce": false,
            "since_start": {"analyzed": 200, "cached": 1800, "failed": 0, "unscanned_requests": 0}});
        assert_eq!(
            one_line(&ready).unwrap(),
            "● ready  de, en · reports only · 2.0k texts, 90% from cache"
        );

        let down = json!({"state": "unavailable", "languages": ["de"],
            "reason": "http://127.0.0.1:5002 does not answer: cannot connect"});
        assert_eq!(
            one_line(&down).unwrap(),
            "○ unavailable  de – http://127.0.0.1:5002 does not answer: cannot connect"
        );
    }

    #[test]
    fn the_sample_matches_the_first_language() {
        let l = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(sample_for(&l(&["de", "en"])).1, "de");
        assert_eq!(sample_for(&l(&["en", "de"])).1, "en");
        assert_eq!(sample_for(&l(&["fr", "en"])).1, "en");
        assert_eq!(sample_for(&l(&["fr"])).1, "");
    }
}
