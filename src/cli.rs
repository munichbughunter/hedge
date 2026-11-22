//! Die Kommandozeile. Alles, was ein Mensch mit Hedge tut, passiert hier:
//! einrichten, starten, prüfen, zuschauen, freigeben, auswerten.
//!
//! Grundsatz: Jede Ausgabe beantwortet auf einen Blick "Was ist los und was
//! tue ich als Nächstes?". Technische Bezeichner (`kind`, Pfade) werden für
//! Menschen übersetzt, bleiben aber mit `--json` maschinenlesbar.

use std::collections::BTreeMap;
use std::error::Error;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use serde_json::Value;
use tracing_subscriber::EnvFilter;

use crate::approvals::ApprovalInfo;
use crate::config::{self, Config, LogFormat, Mode, TEMPLATE, ToolAction};
use crate::detect::describe_kind;
use crate::proxy::{self, AppState, CLIENT_TOKEN_HEADER, router};
use crate::tools::ToolPolicy;
use crate::witness::{self, Anchor, Bundle, Entry, FindingRecord, VerifyReport};

mod presidio;

pub(crate) type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser, Debug)]
#[command(
    name = "hedge",
    version,
    about = "AI Guard Proxy – sieht, was dein Coding-Agent mit der LLM-API austauscht, hält Secrets zurück, prüft Tool-Aufrufe und bezeugt alles.",
    long_about = None,
    after_help = "Quickstart:\n  hedge init --claude-code   # Config + Schlüssel anlegen, Claude Code umbiegen\n  hedge run                  # Proxy starten\n  hedge watch                # zuschauen und freigeben (TUI)\n  hedge presidio enable      # optional: Namen und Telefonnummern erkennen\n\nWenn ein Tool-Aufruf eine Freigabe braucht, fragt Hedge in der Agent-Session:\n  approve <id>               # dort antworten – oder im Terminal:\n  hedge approvals            # was wartet?\n  hedge approve <id>         # freigeben   |   hedge deny <id>"
)]
pub struct Cli {
    /// Pfad zur hedge.toml (Standard: ~/.hedge/hedge.toml)
    #[arg(short, long, global = true, env = "HEDGE_CONFIG")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Wie die Steuer-API eines laufenden Hedge erreicht wird.
#[derive(Args, Debug, Clone, Default)]
pub struct Remote {
    /// Adresse eines laufenden Hedge (Standard: aus der Config)
    #[arg(long, env = "HEDGE_URL")]
    pub url: Option<String>,
    /// Steuer-Token (Standard: Datei aus der Config)
    #[arg(long, env = "HEDGE_CONTROL_TOKEN", hide_env_values = true)]
    pub token: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Proxy starten (Standard, wenn kein Kommando angegeben ist)
    Run,
    /// Config, Signierschlüssel, Steuer-Token und Witness anlegen
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
        /// Nur Signierschlüssel und Steuer-Token anlegen, falls sie fehlen,
        /// keine hedge.toml: an den Pfaden der Config, mit --dir in diesem
        /// Verzeichnis (für Container und systemd)
        #[arg(long, conflicts_with_all = ["claude_code", "force"])]
        keys_only: bool,
    },
    /// Config lesen, validieren und zusammenfassen
    Check,
    /// Umgebung prüfen: Config, Port, Upstreams, Schlüssel, Kette, Agent-Setup
    Doctor,
    /// Zustand des laufenden Proxys (Modus, Zähler, Budget, offene Freigaben)
    Status {
        #[command(flatten)]
        remote: Remote,
        #[arg(long)]
        json: bool,
    },
    /// Bereitschaft prüfen (für Healthchecks): Exit-Code 0, wenn Hedge
    /// Anfragen so bedient, wie die Config es verlangt, sonst 1 mit dem Grund
    Ready {
        /// Adresse eines laufenden Hedge (Standard: server.listen aus der Config)
        #[arg(long, env = "HEDGE_URL")]
        url: Option<String>,
    },
    /// Letzte Einträge des Witness lesbar anzeigen
    Tail {
        /// Anzahl Einträge
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Weiter zuschauen (wie tail -f)
        #[arg(short, long)]
        follow: bool,
        /// Nur Einträge dieser Session (Präfix genügt)
        #[arg(long)]
        session: Option<String>,
        /// Nur Auffälliges: Funde, gestoppte oder markierte Tool-Aufrufe, Blocks
        #[arg(short, long)]
        alerts: bool,
        /// Jede Fundstelle und jeden Tool-Aufruf einzeln zeigen
        #[arg(short, long)]
        verbose: bool,
        /// Rohe JSON-Zeilen statt Tabelle
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        remote: Remote,
    },
    /// Live-Ansicht im Terminal: Sessions, Freigaben per Taste, Live-Strom
    Watch {
        #[command(flatten)]
        remote: Remote,
    },
    /// Agent-Sessions mit Anfragen, Tokens, Funden und Tool-Aufrufen
    Sessions {
        /// Zeitfenster, z. B. 30m, 24h, 7d (Standard: alles)
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        remote: Remote,
    },
    /// Zusammenfassung über alle Anfragen (für Admins)
    Report {
        /// Zeitfenster, z. B. 30m, 24h, 7d (Standard: alles)
        #[arg(long)]
        since: Option<String>,
        /// Als JSON ausgeben
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        remote: Remote,
    },
    /// Angehaltene Tool-Aufrufe anzeigen, die auf Freigabe warten
    Approvals {
        #[command(flatten)]
        remote: Remote,
        #[arg(long)]
        json: bool,
    },
    /// Einen angehaltenen Tool-Aufruf freigeben
    Approve {
        id: String,
        #[command(flatten)]
        remote: Remote,
    },
    /// Einen angehaltenen Tool-Aufruf ablehnen
    Deny {
        id: String,
        #[command(flatten)]
        remote: Remote,
    },
    /// Aktive Tool-Regeln anzeigen oder einen Aufruf dagegen testen
    Rules {
        /// Auch die Regex-Muster anzeigen
        #[arg(long)]
        patterns: bool,
        #[command(subcommand)]
        command: Option<RulesCommand>,
    },
    /// Witness-Kette offline prüfen (Hashes, Sequenz, Signaturen)
    Verify {
        /// Witness-Datei (Standard: aus Config)
        #[arg(long)]
        witness: Option<PathBuf>,
        /// Öffentlicher Schlüssel, .pub oder .key (Standard: aus Config)
        #[arg(long)]
        key: Option<PathBuf>,
        /// Ein exportiertes Bundle prüfen statt der lokalen Kette
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Anker `seq:hash` (von `hedge head`), der in der Kette liegen muss
        #[arg(long)]
        anchor: Option<String>,
    },
    /// Aktuellen Kopf der Kette als Anker ausgeben (zum externen Aufbewahren)
    Head,
    /// Aktives Witness-Segment ablegen und ein neues beginnen (Kette läuft weiter)
    Rotate {
        #[command(flatten)]
        remote: Remote,
    },
    /// Einen prüfbaren Auszug der Kette exportieren
    Export {
        /// Alle Einträge einer Session (Präfix genügt)
        #[arg(long)]
        session: Option<String>,
        /// Die letzten N Einträge
        #[arg(long)]
        last: Option<usize>,
        /// Zieldatei
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Clients für den Central-Mode verwalten
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    /// Presidio (Namen, Telefonnummern): einschalten, prüfen, ausprobieren
    Presidio {
        #[command(subcommand)]
        command: PresidioCommand,
    },
    /// Dateien für den zentralen Betrieb schreiben
    Deploy {
        #[command(subcommand)]
        command: DeployCommand,
    },
    /// Admins der Steuer-API verwalten (Freigaben tragen ihren Namen)
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum PresidioCommand {
    /// Einschalten: Image holen, Container starten, prüfen, in die Config eintragen
    Enable {
        /// Image auf diesem Rechner bauen, statt es aus der Registry zu holen
        #[arg(long)]
        build: bool,
        /// Anderes Image verwenden, z. B. aus der eigenen Registry
        #[arg(long)]
        image: Option<String>,
        /// Port auf 127.0.0.1 (Standard: 5002)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Zustand: bereit oder nicht, warum, und welcher Befehl hilft
    Status {
        #[command(flatten)]
        remote: Remote,
        #[arg(long)]
        json: bool,
    },
    /// Einen Text analysieren: was findet Presidio, was würde Hedge melden
    Test {
        /// Der Text (ohne Angabe: von der Standardeingabe)
        text: Vec<String>,
        /// Sprache festlegen, statt sie erkennen zu lassen
        #[arg(short, long)]
        language: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Ausgabe des Containers anzeigen
    Logs {
        /// Weiter zuschauen
        #[arg(short, long)]
        follow: bool,
        /// Anzahl Zeilen
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
    /// Container auf das Image bringen, das zu dieser Hedge-Version gehört
    Upgrade {
        /// Image auf diesem Rechner bauen
        #[arg(long)]
        build: bool,
        /// Image neu aus der Registry holen, auch wenn es schon da ist
        #[arg(long)]
        pull: bool,
    },
    /// Ausschalten und den Container anhalten
    Disable {
        /// Container löschen statt nur anhalten
        #[arg(long)]
        remove: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum DeployCommand {
    /// Compose-Verzeichnis für den zentralen Betrieb: Hedge, Presidio, Grafana
    Compose {
        /// Zielverzeichnis
        #[arg(short, long, default_value = "hedge-central")]
        output: PathBuf,
        /// Client gleich mit anlegen (mehrfach möglich); das Token wird einmal gezeigt
        #[arg(long = "client", value_name = "NAME")]
        clients: Vec<String>,
        /// Grafana mit Dashboard und Alerts einschalten
        #[arg(long)]
        observability: bool,
        /// Caddy für TLS davorschalten (Zertifikat und Name stehen in .env)
        #[arg(long)]
        tls: bool,
        /// Vorhandenes Verzeichnis auffrischen (hedge.toml und .env bleiben)
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum RulesCommand {
    /// Prüfen, welche Regel bei einem Tool-Aufruf greifen würde
    Test {
        /// Tool-Name, z. B. Bash
        tool: String,
        /// Eingabe des Tools (bei Bash der Befehl)
        input: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ClientCommand {
    /// Neuen Client anlegen: erzeugt ein Token und trägt den Hash in die Config ein
    Add {
        name: String,
        /// Config nicht anfassen, nur Token und TOML-Block ausgeben
        /// (für Configs, die aus Git oder einer ConfigMap kommen)
        #[arg(long)]
        print: bool,
        /// Letzter gültiger Tag, JJJJ-MM-TT (UTC)
        #[arg(long)]
        expires: Option<String>,
        /// Eigenes Tagesbudget in Tokens statt [budget] daily_tokens
        #[arg(long)]
        daily_tokens: Option<u64>,
    },
    /// Bekannte Clients auflisten
    List,
    /// Client entfernen; sein Token gilt sofort nicht mehr
    Remove { name: String },
    /// Neues Token für einen Client; das alte gilt sofort nicht mehr
    Rotate {
        name: String,
        /// Config nicht anfassen, nur Token und Hash ausgeben
        #[arg(long)]
        print: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Neuen Admin anlegen: erzeugt ein Token und trägt den Hash in die Config ein
    Add {
        name: String,
        /// Config nicht anfassen, nur Token und TOML-Block ausgeben
        #[arg(long)]
        print: bool,
    },
    /// Bekannte Admins auflisten
    List,
    /// Admin entfernen; sein Token gilt sofort nicht mehr
    Remove { name: String },
    /// Neues Token für einen Admin; das alte gilt sofort nicht mehr
    Rotate {
        name: String,
        /// Config nicht anfassen, nur Token und Hash ausgeben
        #[arg(long)]
        print: bool,
    },
}

/// Führt das Kommando aus und liefert den Exit-Code.
pub async fn run(cli: Cli) -> Result<i32> {
    let config_path = config::resolve_config_path(cli.config.as_deref());
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => cmd_run(&config_path).await,
        Command::Init {
            keys_only: true,
            dir,
            ..
        } => cmd_init_keys(&config_path, dir),
        Command::Init {
            dir,
            claude_code,
            force,
            keys_only: false,
        } => cmd_init(dir, claude_code, force, &config_path),
        Command::Ready { url } => cmd_ready(&config_path, url).await,
        Command::Rotate { remote } => cmd_rotate(&config_path, remote).await,
        Command::Admin { command } => cmd_admin(&config_path, command),
        Command::Check => cmd_check(&config_path),
        Command::Doctor => cmd_doctor(&config_path).await,
        Command::Status { remote, json } => cmd_status(&config_path, remote, json).await,
        Command::Tail {
            lines,
            follow,
            session,
            alerts,
            verbose,
            json,
            remote,
        } => {
            let view = TailView {
                session,
                alerts,
                verbose,
                json,
            };
            cmd_tail(&config_path, lines, follow, view, remote).await
        }
        Command::Watch { remote } => crate::tui::run(&config_path, remote).await,
        Command::Sessions {
            since,
            json,
            remote,
        } => cmd_sessions(&config_path, since, json, remote).await,
        Command::Report {
            since,
            json,
            remote,
        } => cmd_report(&config_path, since, json, remote).await,
        Command::Approvals { remote, json } => cmd_approvals(&config_path, remote, json).await,
        Command::Approve { id, remote } => cmd_resolve(&config_path, remote, &id, true).await,
        Command::Deny { id, remote } => cmd_resolve(&config_path, remote, &id, false).await,
        Command::Rules { patterns, command } => cmd_rules(&config_path, command, patterns),
        Command::Verify {
            witness,
            key,
            bundle,
            anchor,
        } => cmd_verify(&config_path, witness, key, bundle, anchor),
        Command::Head => cmd_head(&config_path),
        Command::Export {
            session,
            last,
            output,
        } => cmd_export(&config_path, session, last, &output),
        Command::Client { command } => cmd_client(&config_path, command),
        Command::Presidio { command } => match command {
            PresidioCommand::Enable { build, image, port } => {
                let opts = presidio::EnableOpts {
                    build,
                    pull: false,
                    image,
                    port,
                };
                presidio::enable(&config_path, opts, false).await
            }
            PresidioCommand::Upgrade { build, pull } => {
                let opts = presidio::EnableOpts {
                    build,
                    pull,
                    image: None,
                    port: None,
                };
                presidio::enable(&config_path, opts, true).await
            }
            PresidioCommand::Status { remote, json } => {
                presidio::status(&config_path, remote, json).await
            }
            PresidioCommand::Test {
                text,
                language,
                json,
            } => presidio::test(&config_path, text, language, json).await,
            PresidioCommand::Logs { follow, lines } => {
                presidio::logs(&config_path, follow, lines).await
            }
            PresidioCommand::Disable { remove } => presidio::disable(&config_path, remove).await,
        },
        Command::Deploy { command } => match command {
            DeployCommand::Compose {
                output,
                clients,
                observability,
                tls,
                force,
            } => cmd_deploy_compose(&output, clients, observability, tls, force),
        },
    }
}

// ---------- run ----------

async fn cmd_run(config_path: &Path) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    init_tracing(&cfg);

    let bind = |addr: String| async move {
        tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("cannot listen on {addr}: {e}"))
    };
    let listener = bind(cfg.server.listen.clone()).await?;
    let addr = listener.local_addr()?;
    // Die Steuer-API bekommt ihre eigene Adresse, wenn die Config es will.
    let control = match cfg.control_listen() {
        Some(a) => Some(bind(a.to_owned()).await?),
        None => None,
    };
    let control_addr = match &control {
        Some(l) => Some(l.local_addr()?),
        None => None,
    };
    let pretty = cfg.log.format == LogFormat::Pretty;
    let state = Arc::new(AppState::from_config(cfg)?);

    let rt = state.runtime();
    state.record_event(
        "start",
        format!(
            "version={} mode={} tools_enforce={}",
            env!("CARGO_PKG_VERSION"),
            rt.cfg.mode.as_str(),
            rt.tools.enforce()
        ),
    );

    // Presidio im Blick behalten. Der erste Blick bekommt einen Moment, damit
    // der Banner den echten Zustand zeigt; länger wartet der Start nie.
    let supervisor = proxy::spawn_presidio_supervisor(state.clone());
    for _ in 0..15 {
        match &rt.presidio {
            Some(p) if p.state() == crate::presidio::State::Starting => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            _ => break,
        }
    }

    if pretty {
        print_banner(&state, &addr, control_addr.as_ref(), config_path);
    }
    tracing::info!(listen = %addr, mode = rt.cfg.mode.as_str(), config = %config_path.display(), "hedge started");
    if let Some(c) = &control_addr {
        tracing::info!(listen = %c, "control API on its own address");
    }
    drop(rt);

    let reloader = proxy::spawn_reloader(state.clone(), config_path.to_path_buf());

    // Ein Signal, zwei Folgen: Beide Listener nehmen nichts Neues mehr an,
    // und die Frist für laufende Antworten beginnt.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    {
        let state = state.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            state.set_draining();
            let _ = stop_tx.send(true);
        });
    }
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|stop| *stop).await;
    };

    let app = match control {
        Some(_) => proxy::proxy_router(state.clone()),
        None => router(state.clone()),
    };
    let serve_proxy = {
        let stop = stopped(stop_rx.clone());
        async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stop)
                .await
        }
    };
    let serve_control = {
        let stop = stopped(stop_rx.clone());
        let app = proxy::control_router(state.clone());
        async move {
            match control {
                Some(l) => axum::serve(l, app).with_graceful_shutdown(stop).await,
                None => Ok(()),
            }
        }
    };
    let deadline = {
        let state = state.clone();
        let stop = stopped(stop_rx.clone());
        async move {
            stop.await;
            match state.runtime().cfg.server.shutdown_grace_secs {
                0 => std::future::pending::<u64>().await,
                secs => {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    secs
                }
            }
        }
    };
    let how = tokio::select! {
        served = async { tokio::try_join!(serve_proxy, serve_control) } => {
            served?;
            "graceful shutdown".to_owned()
        }
        secs = deadline => {
            // Was jetzt noch läuft, wird nicht mehr fertig – aber bezeugt.
            let cut = state.witness_cut_off();
            tracing::warn!("shutdown grace period of {secs}s is over; {cut} running response(s) cut off");
            format!("shutdown after {secs}s grace period, {cut} running response(s) cut off")
        }
    };
    reloader.abort();
    supervisor.abort();

    state.record_event("stop", how);
    if let Some(t) = state.telemetry() {
        t.flush();
    }
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

fn print_banner(
    state: &AppState,
    addr: &std::net::SocketAddr,
    control: Option<&std::net::SocketAddr>,
    config_path: &Path,
) {
    let rt = state.runtime();
    let cfg = &rt.cfg;
    let upstreams = cfg
        .upstreams
        .iter()
        .map(|u| format!("{} → {}", u.name.bold(), u.url))
        .collect::<Vec<_>>()
        .join("\n              ");
    let witness = match state.witness() {
        Some(w) => {
            let head = w.head().map(|a| a.seq).unwrap_or(0);
            format!(
                "{} (key {}, {head} entries)",
                w.path().display(),
                w.key_id()
            )
        }
        None => "disabled".yellow().to_string(),
    };
    println!();
    println!(
        "  {} {}   mode: {}",
        "hedge".bold(),
        env!("CARGO_PKG_VERSION"),
        mode_colored(cfg.mode)
    );
    println!(
        "  config      {}  {}",
        config_path.display(),
        "(reloads on change)".dimmed()
    );
    println!("  listening   http://{addr}");
    if let Some(c) = control {
        println!(
            "  control     http://{c}  {}",
            "(status, approvals, witness – not on the proxy port)".dimmed()
        );
    }
    println!("  upstreams   {upstreams}");
    println!("  detectors   {}", detector_list(cfg));
    println!("  tools       {}", tools_line(cfg, &rt.tools));
    println!("  witness     {witness}");
    if let Some(p) = &rt.presidio {
        let status = p.status();
        if let Some(line) = presidio::one_line(&status) {
            println!("  presidio    {line}");
        }
        if let Some(hint) = status["hint"].as_str() {
            println!("              → {}", hint.cyan());
        }
    }
    if let Some(extra) = extras_line(cfg, state.has_control_token()) {
        println!("  also        {extra}");
    }
    println!();
    let expected = agent_url(cfg);
    match claude_settings_url() {
        Some(url) if url.trim_end_matches('/') == expected => {
            println!("  claude code {} settings.json points here", ok());
        }
        Some(url) => {
            println!(
                "  claude code {} settings.json points to {url}, not here",
                fail()
            );
            println!("              → {}", "hedge init --claude-code".cyan());
        }
        None => println!(
            "  agent setup {}",
            format!("export ANTHROPIC_BASE_URL={expected}").cyan()
        ),
    }
    println!("  watch       {}", "hedge tail -f".cyan());
    println!();
}

fn tools_line(cfg: &Config, policy: &ToolPolicy) -> String {
    let rules = policy.rule_count();
    if rules == 0 {
        return "no rules".dimmed().to_string();
    }
    if cfg.tools.enforce {
        format!(
            "{} {rules} rules, deny stops a call, hold {}",
            "enforce".red(),
            if cfg.tools.approve_in_chat {
                "asks you in the session (reply `approve <id>`)"
            } else {
                "waits for `hedge approve <id>`"
            }
        )
    } else {
        format!(
            "{} {rules} rules, hits are flagged only {}",
            "observe".blue(),
            "(tools.enforce = true to stop them)".dimmed()
        )
    }
}

fn extras_line(cfg: &Config, control: bool) -> Option<String> {
    let mut v = Vec::new();
    if cfg.telemetry.enabled {
        v.push(format!("telemetry → {}", cfg.telemetry.endpoint));
    }
    if cfg.budget.daily_tokens > 0 || cfg.budget.session_tokens > 0 {
        v.push(format!(
            "budget {}/day {}/session",
            human_count(cfg.budget.daily_tokens),
            human_count(cfg.budget.session_tokens)
        ));
    }
    if !cfg.models.allow.is_empty() || !cfg.models.deny.is_empty() {
        v.push("model allowlist".into());
    }
    if cfg.server.require_client {
        v.push(format!("{} clients required", cfg.clients.len()));
    }
    if !control {
        v.push(
            "no control token (hold rules reject; run `hedge init`)"
                .yellow()
                .to_string(),
        );
    }
    (!v.is_empty()).then(|| v.join(" · "))
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

fn cmd_init(dir: Option<PathBuf>, claude_code: bool, force: bool, effective: &Path) -> Result<i32> {
    let dir = dir.unwrap_or_else(config::default_dir);
    std::fs::create_dir_all(&dir)?;
    let config_path = dir.join("hedge.toml");
    let key_path = dir.join("witness.key");
    let witness_path = dir.join("witness.jsonl");
    let token_path = dir.join("control.token");

    println!();
    if config_path.exists() && !force {
        println!(
            "  {} config        {} (exists, kept; --force overwrites)",
            "·".dimmed(),
            config_path.display()
        );
    } else {
        let mut text = TEMPLATE.to_owned();
        if dir != config::default_dir() {
            // Alles neben die Config legen, wenn ein eigenes Verzeichnis gewählt wurde.
            text = text
                .replace(
                    "# path = \"~/.hedge/witness.jsonl\"",
                    &format!("path = \"{}\"", witness_path.display()),
                )
                .replace(
                    "# key  = \"~/.hedge/witness.key\"",
                    &format!("key  = \"{}\"", key_path.display()),
                )
                .replace(
                    "# token = \"~/.hedge/control.token\"",
                    &format!("token = \"{}\"", token_path.display()),
                );
        }
        std::fs::write(&config_path, text)?;
        println!("  {} config        {}", ok(), config_path.display());
    }

    if key_path.exists() {
        let vk = witness::load_verifying_key(&key_path)?;
        println!(
            "  {} signing key   {} (exists, key id {})",
            "·".dimmed(),
            key_path.display(),
            witness::key_id_of(&vk)
        );
    } else {
        let vk = witness::generate_keypair(&key_path)?;
        println!(
            "  {} signing key   {} (key id {})",
            ok(),
            key_path.display(),
            witness::key_id_of(&vk)
        );
        println!(
            "  {} public key    {}",
            ok(),
            witness::pub_path(&key_path).display()
        );
    }

    if token_path.exists() {
        println!(
            "  {} control token {} (exists)",
            "·".dimmed(),
            token_path.display()
        );
    } else {
        witness::write_private(&token_path, random_hex(32)?.as_bytes())?;
        println!(
            "  {} control token {} (for hedge approve / status)",
            ok(),
            token_path.display()
        );
    }
    println!(
        "  {} witness log   {} (append-only, starts with the first request)",
        ok(),
        witness_path.display()
    );

    // Die Agent-URL muss zu der Config passen, die `hedge run` von hier aus
    // tatsächlich benutzt – nicht zwingend zu der, die gerade angelegt wurde.
    let same_file = |a: &Path, b: &Path| matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(x), Ok(y)) if x == y);
    let used_path = if effective.exists() && !same_file(effective, &config_path) {
        effective.to_path_buf()
    } else {
        config_path.clone()
    };
    let cfg = Config::load(&used_path)?;
    let base_url = agent_url(&cfg);
    if used_path != config_path {
        println!(
            "  {} agent url     taken from {} (--config / $HEDGE_CONFIG)",
            "·".dimmed(),
            used_path.display()
        );
    }

    if claude_code {
        let settings = claude_settings_path();
        write_claude_code_env(&settings, &base_url)?;
        println!(
            "  {} claude code   {} → env.ANTHROPIC_BASE_URL = {base_url}",
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
    println!(
        "  Optional: {} finds names and phone numbers too",
        "hedge presidio enable".cyan()
    );
    println!("            (needs Docker or Podman and about 1 GB of memory).");
    println!();
    if config_path != config::default_dir().join("hedge.toml") {
        println!("  Hint: this config is not at the default location. Use:");
        println!("        export HEDGE_CONFIG={}", config_path.display());
        println!();
    }
    Ok(0)
}

// ---------- deploy ----------

fn cmd_deploy_compose(
    dir: &Path,
    clients: Vec<String>,
    observability: bool,
    tls: bool,
    force: bool,
) -> Result<i32> {
    let mut tokens: Vec<(String, String)> = Vec::new();
    let mut new_clients = Vec::new();
    for name in clients {
        if !config::valid_name(&name) {
            return Err(
                "client name must be 1–64 characters of a-z, A-Z, 0-9, '-', '_', '.', '@'".into(),
            );
        }
        if tokens.iter().any(|(n, _)| *n == name) {
            return Err(format!("client {name:?} is named twice").into());
        }
        let token = format!("hc_{}", random_hex(24)?);
        new_clients.push(crate::deploy::NewClient {
            name: name.clone(),
            token_sha256: witness::sha256_hex(token.as_bytes()),
        });
        tokens.push((name, token));
    }
    let opts = crate::deploy::Options {
        clients: new_clients,
        observability,
        tls,
    };
    crate::deploy::validate_central(&crate::deploy::central_config(&opts))
        .map_err(|e| format!("the generated config is not valid (this is a bug in hedge): {e}"))?;
    let written = crate::deploy::write(dir, &opts, force)?;

    println!();
    println!("  {} {}", ok(), dir.display().to_string().bold());
    let kept = |name: &str| written.iter().any(|w| !w.written && w.path.ends_with(name));
    let line = |name: &str, what: &str, was_kept: bool| {
        println!(
            "      {}  {what}{}",
            pad(name, 20),
            if was_kept {
                "  (existed, kept)".yellow().to_string()
            } else {
                String::new()
            }
        );
    };
    line(
        "docker-compose.yml",
        "hedge + presidio; caddy (tls) and grafana as profiles",
        false,
    );
    line(
        ".env",
        "image names, ports, profiles, presidio workers",
        kept(".env"),
    );
    line(
        "hedge/hedge.toml",
        "the central policy, reloaded on change",
        kept("hedge.toml"),
    );
    line(
        "presidio/",
        "build context of the presidio image (de, en)",
        false,
    );
    line("grafana/", "dashboard and alert rules", false);
    line(
        "Caddyfile, certs/",
        if tls {
            "TLS in front of hedge (profile tls is on)"
        } else {
            "TLS in front of hedge, off until COMPOSE_PROFILES=tls"
        },
        false,
    );
    line("README.md", "the steps, in order", false);

    if kept("hedge.toml") && !tokens.is_empty() {
        println!();
        println!(
            "  {} hedge/hedge.toml existed and was kept, so the clients were not added.",
            "!".yellow().bold()
        );
        println!(
            "    Add them with: {}",
            format!(
                "hedge --config {} client add <name>",
                dir.join("hedge/hedge.toml").display()
            )
            .cyan()
        );
    } else if !tokens.is_empty() {
        println!();
        println!("  Client tokens (shown once, the config only holds their hashes):");
        for (name, token) in &tokens {
            println!("    {}  {}", pad(name, 16).bold(), token.yellow());
        }
        println!(
            "    Each developer sets: {}",
            format!("ANTHROPIC_CUSTOM_HEADERS=\"{CLIENT_TOKEN_HEADER}: <token>\"").cyan()
        );
    }

    println!();
    println!("  {}", "Next:".bold());
    let mut n = 0;
    let mut step = |what: String, note: &str| {
        n += 1;
        println!("    {n}. {}   {note}", pad(&what, 32).cyan());
    };
    step(format!("cd {}", dir.display()), "");
    step(
        "docker compose build presidio".into(),
        "until the images are published",
    );
    println!("       {}   (the hedge image: see README.md)", pad("", 32));
    if tls && !kept(".env") {
        step(
            "edit .env".into(),
            "HEDGE_DOMAIN, HEDGE_TLS and HEDGE_ADMIN_CIDRS for caddy",
        );
    }
    step("docker compose up -d".into(), "");
    step(
        "curl -s 127.0.0.1:18765/ready".into(),
        "answers {\"ready\":true} once presidio is up",
    );
    step(
        "hedge status --url http://127.0.0.1:18766".into(),
        "the control API has its own port",
    );
    if tokens.is_empty() && !kept("hedge.toml") {
        step(
            format!(
                "hedge --config {} client add <name>",
                dir.join("hedge/hedge.toml").display()
            ),
            "",
        );
        println!("       then set server.require_client = true");
    }
    println!();
    Ok(0)
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| format!("no randomness available: {e}"))?;
    Ok(hex::encode(buf))
}

/// Die URL, auf die ein Agent für den ersten Upstream zeigen muss.
fn agent_url(cfg: &Config) -> String {
    let first = cfg
        .upstreams
        .first()
        .map(|u| u.name.as_str())
        .unwrap_or("anthropic");
    format!("http://{}/{first}", cfg.server.listen)
}

/// `env.ANTHROPIC_BASE_URL` aus Claude Codes settings.json, falls gesetzt.
fn claude_settings_url() -> Option<String> {
    std::fs::read_to_string(claude_settings_path())
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v["env"]["ANTHROPIC_BASE_URL"].as_str().map(str::to_owned))
}

/// Zeigt Claude Code auf diesen Hedge? Ein Eintrag in settings.json gilt
/// für jede Claude-Code-Session und sticht die Shell-Variable aus – deshalb
/// entscheidet er, sobald er existiert. `Err` = (Problem, Abhilfe).
fn judge_agent_setup(
    expected: &str,
    shell: Option<&str>,
    settings: Option<&str>,
) -> std::result::Result<String, (String, String)> {
    let points_here = |url: &str| url.trim_end_matches('/') == expected;
    match (settings, shell) {
        (Some(s), _) if points_here(s) => Ok(format!("settings.json → {s}")),
        (Some(s), _) => Err((
            format!(
                "settings.json points to {s}, but this hedge listens at {expected}. Claude Code uses settings.json, whatever the shell says"
            ),
            "hedge init --claude-code   (run it from the directory you start hedge in)".into(),
        )),
        (None, Some(e)) if points_here(e) => Ok(format!(
            "ANTHROPIC_BASE_URL={e} (this shell only – start claude from here)"
        )),
        (None, Some(e)) => Err((
            format!("ANTHROPIC_BASE_URL={e} does not point to this hedge ({expected})"),
            format!("export ANTHROPIC_BASE_URL={expected}   or   hedge init --claude-code"),
        )),
        (None, None) => Err((
            "not pointed at hedge yet".into(),
            format!("hedge init --claude-code   or   export ANTHROPIC_BASE_URL={expected}"),
        )),
    }
}

fn claude_settings_path() -> PathBuf {
    config::home_dir()
        .map(|h| h.join(".claude").join("settings.json"))
        .unwrap_or_else(|| PathBuf::from(".claude/settings.json"))
}

/// Setzt `env.ANTHROPIC_BASE_URL` in Claude Codes settings.json, lässt alles
/// andere unangetastet und legt vorher ein Backup an.
fn write_claude_code_env(settings: &Path, base_url: &str) -> Result<()> {
    let mut doc: Value = match std::fs::read_to_string(settings) {
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
    env["ANTHROPIC_BASE_URL"] = Value::String(base_url.to_owned());
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
    let exposure = if cfg.is_loopback() {
        "local only".dimmed().to_string()
    } else if cfg.server.require_client {
        "network, client token required".to_string()
    } else {
        "network, NO client token required – anyone who can reach it can use it"
            .yellow()
            .to_string()
    };
    println!("  listen      {}  {exposure}", cfg.server.listen);
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
        "  response    {}",
        if cfg.response.inspect {
            "inspected (tokens, tool calls, findings)"
        } else {
            "not inspected"
        }
    );
    match ToolPolicy::from_config(&cfg.tools) {
        Ok(policy) => println!("  tools       {}", tools_line(cfg, &policy)),
        Err(e) => println!("  tools       {} {e}", fail()),
    }
    if cfg.models.allow.is_empty() && cfg.models.deny.is_empty() {
        println!("  models      {}", "all allowed".dimmed());
    } else {
        println!(
            "  models      allow [{}]  deny [{}]",
            cfg.models.allow.join(", "),
            cfg.models.deny.join(", ")
        );
    }
    if cfg.budget.daily_tokens == 0 && cfg.budget.session_tokens == 0 {
        println!("  budget      {}", "unlimited".dimmed());
    } else {
        println!(
            "  budget      {} tokens/day per client, {} per session (0 = unlimited)",
            human_count(cfg.budget.daily_tokens),
            human_count(cfg.budget.session_tokens)
        );
    }
    if !cfg.clients.is_empty() || cfg.server.require_client {
        let names: Vec<&str> = cfg.clients.iter().map(|c| c.name.as_str()).collect();
        println!(
            "  clients     {} ({}){}",
            cfg.clients.len(),
            names.join(", "),
            if cfg.server.require_client {
                ", token required"
            } else {
                ", token optional"
            }
        );
    }
    println!(
        "  timeouts    connect {}s, idle {}s, shutdown grace {}",
        cfg.timeouts.connect_secs,
        cfg.timeouts.request_secs,
        match cfg.server.shutdown_grace_secs {
            0 => "unlimited".to_owned(),
            s => format!("{s}s"),
        }
    );
    println!("  body limit  {} MiB", cfg.server.max_body_mb);
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
            ok()
        } else {
            format!("{} missing – run hedge init", fail())
        };
        println!(
            "  witness     {}  key {} {key_state}",
            cfg.witness_path().display(),
            cfg.witness_key_path().display()
        );
        println!(
            "              {}",
            match cfg.witness.rotate_mb {
                0 => "one file, never rotated (witness.rotate_mb = 0)".to_owned(),
                mb => format!("a new segment every {mb} MiB"),
            }
            .dimmed()
        );
    } else {
        println!("  witness     {}", "disabled".yellow());
    }
    let token_state = if cfg.control_token_path().exists() {
        ok()
    } else {
        format!("{} missing – run hedge init", fail())
    };
    println!(
        "  control     {} {token_state}",
        cfg.control_token_path().display()
    );
    let admins: Vec<&str> = cfg.admins.iter().map(|a| a.name.as_str()).collect();
    println!(
        "              {}",
        format!(
            "{}; {}",
            match cfg.control_listen() {
                Some(addr) => format!("on its own address {addr}"),
                None => "on the proxy port".to_owned(),
            },
            if admins.is_empty() {
                "no named admins".to_owned()
            } else {
                format!("admins: {}", admins.join(", "))
            }
        )
        .dimmed()
    );
    if cfg.telemetry.enabled {
        println!(
            "  telemetry   OTLP → {} (service {})",
            cfg.telemetry.endpoint, cfg.telemetry.service_name
        );
    } else {
        println!("  telemetry   {}", "off".dimmed());
    }
    if cfg.presidio.enabled {
        let p = &cfg.presidio;
        println!(
            "  presidio    {}  {}",
            p.url,
            if p.managed {
                "container managed by hedge"
            } else {
                "external service"
            }
            .dimmed()
        );
        println!(
            "              {} · looks for {} in {}",
            p.languages().join(", "),
            p.entities.join(", "),
            p.scope
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("              findings: {}", presidio::findings_line(cfg));
        println!("              on outage: {}", presidio::outage_line(cfg));
    } else {
        println!(
            "  presidio    {}",
            "off (names and phone numbers: hedge presidio enable)".dimmed()
        );
    }
}

// ---------- rules ----------

fn cmd_rules(config_path: &Path, command: Option<RulesCommand>, patterns: bool) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    let policy = ToolPolicy::from_config(&cfg.tools)?;
    match command {
        None => {
            println!();
            println!("  tools       {}", tools_line(&cfg, &policy));
            println!();
            if policy.rules().is_empty() {
                println!("  no rules. Add packs or [[tools.rules]] to the config.");
            }
            for r in policy.rules() {
                println!(
                    "  {}  {}  {}",
                    action_colored(r.action),
                    pad(&r.id, 28).bold(),
                    r.reason
                );
                if patterns {
                    println!("          {} {}", "tool".dimmed(), r.tools());
                }
                if let Some(p) = r.pattern().filter(|_| patterns) {
                    println!("          {} {}", "match".dimmed(), p.dimmed());
                }
            }
            println!();
            println!(
                "  Try one: {}",
                "hedge rules test Bash 'git push --force origin main'".cyan()
            );
            println!();
            Ok(0)
        }
        Some(RulesCommand::Test { tool, input }) => {
            let input = serde_json::json!({ "command": input.join(" ") });
            println!();
            match policy.evaluate(&tool, &input) {
                None => println!("  {} no rule matches – the call passes untouched", ok()),
                Some(m) => {
                    let effect = match (m.action, cfg.tools.enforce) {
                        (ToolAction::Allow, _) => "explicitly allowed",
                        (ToolAction::Deny, true) => {
                            "DENIED – the model is told why, the agent never sees the call"
                        }
                        (ToolAction::Hold, true) if cfg.tools.approve_in_chat => {
                            "HELD – Hedge asks in the session; reply `approve <id>` there to let it run once"
                        }
                        (ToolAction::Hold, true) => "HELD – waits for `hedge approve <id>`",
                        (_, false) => "flagged only (tools.enforce = false)",
                    };
                    println!(
                        "  {}  {}  {}",
                        action_colored(m.action),
                        m.rule_id.bold(),
                        m.reason
                    );
                    println!("          → {effect}");
                }
            }
            println!();
            Ok(0)
        }
    }
}

fn action_colored(a: ToolAction) -> String {
    match a {
        ToolAction::Allow => pad("allow", 6).green().to_string(),
        ToolAction::Deny => pad("deny", 6).red().to_string(),
        ToolAction::Hold => pad("hold", 6).yellow().to_string(),
    }
}

// ---------- verify / head / export ----------

fn cmd_verify(
    config_path: &Path,
    witness_path: Option<PathBuf>,
    key: Option<PathBuf>,
    bundle: Option<PathBuf>,
    anchor: Option<String>,
) -> Result<i32> {
    let anchor =
        match anchor {
            Some(text) => Some(Anchor::parse(&text).ok_or(
                "invalid --anchor, expected <seq>:<64 hex chars> as printed by `hedge head`",
            )?),
            None => None,
        };

    let (label, entries, vk, pinned) = match bundle {
        Some(path) => {
            let b: Bundle = serde_json::from_str(&std::fs::read_to_string(&path)?)
                .map_err(|e| format!("{} is not a hedge bundle: {e}", path.display()))?;
            let (vk, pinned) = match &key {
                Some(k) => (witness::load_verifying_key(k)?, true),
                None => (b.verifying_key()?, false),
            };
            (path, b.entries, vk, pinned)
        }
        None => {
            let cfg = Config::load(config_path).ok();
            let witness_path = witness_path
                .or_else(|| cfg.as_ref().map(|c| c.witness_path()))
                .ok_or("no witness path: pass --witness or provide a config")?;
            let key = key
                .or_else(|| cfg.as_ref().map(|c| c.witness_key_path()))
                .ok_or("no key path: pass --key or provide a config")?;
            let vk = witness::load_verifying_key(&key)?;
            // Abgelegte Segmente gehören zur Kette und werden mitgeprüft.
            let entries = witness::read_chain(&witness_path)?;
            (witness_path, entries, vk, true)
        }
    };

    let mut report = witness::verify(&entries, &vk);
    if let Some(a) = &anchor
        && let Err(p) = witness::check_anchor(&entries, a)
    {
        report.problems.push(p);
    }
    print_verify_report(&label, &report, pinned, anchor.is_some());
    Ok(if report.is_ok() { 0 } else { 1 })
}

fn print_verify_report(path: &Path, report: &VerifyReport, pinned: bool, anchored: bool) {
    println!();
    println!("  witness   {}", path.display());
    println!("  entries   {}", report.entries);
    if let (Some(first), Some(last)) = (&report.first_ts, &report.last_ts) {
        println!("  range     {}  →  {}", human_ts(first), human_ts(last));
    }
    if let Some(k) = &report.key_id {
        let note = if pinned {
            String::new()
        } else {
            format!(
                "  {}",
                "(key taken from the bundle itself – compare this id with the one you trust)"
                    .yellow()
            )
        };
        println!("  key id    {k}{note}");
    }
    if let Some(from) = report.partial_from {
        println!(
            "  extract   starts at entry #{from} {}",
            "(a slice of a longer chain)".dimmed()
        );
    }
    if let Some(head) = &report.head {
        println!("  head      {head}");
    }
    println!();
    if report.is_ok() {
        println!(
            "  {} {}",
            ok(),
            "chain intact: every entry hashed, linked and signed".green()
        );
        if anchored {
            println!(
                "  {} {}",
                ok(),
                "anchor found: the chain was not truncated".green()
            );
        } else if report.entries > 0 {
            println!(
                "  {} cutting off the newest entries cannot be seen from the file alone.",
                "·".dimmed()
            );
            println!(
                "    Keep `hedge head` somewhere else and check with `hedge verify --anchor <seq:hash>`."
            );
        }
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

fn cmd_head(config_path: &Path) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    let entries = witness::read_back(&cfg.witness_path(), |e| !e.is_empty())?;
    match entries.last() {
        Some(e) => {
            println!("{}:{}", e.seq, e.hash);
            Ok(0)
        }
        None => {
            eprintln!("hedge: the witness is empty");
            Ok(1)
        }
    }
}

fn cmd_export(
    config_path: &Path,
    session: Option<String>,
    last: Option<usize>,
    output: &Path,
) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    let entries = witness::read_chain(&cfg.witness_path())?;
    let vk = witness::load_verifying_key(&cfg.witness_key_path())?;
    let head = entries.last().map(|e| Anchor {
        seq: e.seq,
        hash: e.hash.clone(),
    });
    let slice: &[Entry] = match (&session, last) {
        (Some(s), _) => witness::session_range(&entries, s),
        (None, Some(n)) => &entries[entries.len().saturating_sub(n)..],
        (None, None) => &entries,
    };
    if slice.is_empty() {
        eprintln!("hedge: nothing to export (no matching entries)");
        return Ok(1);
    }
    let bundle = Bundle::new(slice.to_vec(), &vk, head);
    std::fs::write(output, serde_json::to_string_pretty(&bundle)? + "\n")?;
    println!();
    println!(
        "  {} exported {} entries (#{} – #{}) to {}",
        ok(),
        slice.len(),
        slice[0].seq,
        slice[slice.len() - 1].seq,
        output.display()
    );
    println!("  key id    {}", bundle.key_id);
    println!();
    println!(
        "  Anyone can check it: {}",
        format!("hedge verify --bundle {}", output.display()).cyan()
    );
    println!("  Give them the key id through another channel, so they know which key to trust.");
    println!();
    Ok(0)
}

// ---------- tail ----------

struct TailView {
    session: Option<String>,
    alerts: bool,
    verbose: bool,
    json: bool,
}

impl TailView {
    fn wants(&self, e: &Entry) -> bool {
        if let Some(s) = &self.session
            && !e
                .session
                .as_deref()
                .is_some_and(|x| x.starts_with(s.as_str()))
        {
            return false;
        }
        !self.alerts || severity_of(e) > Level::Known
    }
}

async fn cmd_tail(
    config_path: &Path,
    lines: usize,
    follow: bool,
    view: TailView,
    remote: Remote,
) -> Result<i32> {
    if remote.url.is_some() {
        return tail_remote(config_path, lines, follow, view, remote).await;
    }
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

    let mut follower = witness::Follower::new(&path);
    let (_, mut entries) = follower.poll();
    // Reicht das aktive Segment nicht für die gewünschten Zeilen, kommen
    // die abgelegten davor dazu.
    for seg in witness::segments(&path).iter().rev() {
        if entries.iter().filter(|e| view.wants(e)).count() >= lines {
            break;
        }
        if let Ok(mut older) = witness::read_entries(&seg.path) {
            older.append(&mut entries);
            entries = older;
        }
    }
    let shown: Vec<&Entry> = entries.iter().filter(|e| view.wants(e)).collect();
    for e in &shown[shown.len().saturating_sub(lines)..] {
        print_entry(e, &view);
    }
    if !follow {
        return Ok(0);
    }
    let bell = !view.json && std::io::stdout().is_terminal();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_millis(400)) => {}
        }
        let (_, new) = follower.poll();
        print_new(&new, &view, bell);
    }
    Ok(0)
}

/// Zeigt neu angekommene Einträge; was auf einen Menschen wartet, klingelt.
fn print_new(new: &[Entry], view: &TailView, bell: bool) {
    for e in new.iter().filter(|e| view.wants(e)) {
        print_entry(e, view);
        if bell && severity_of(e) == Level::Hold {
            print!("\x07");
            let _ = std::io::stdout().flush();
        }
    }
}

/// `hedge tail --url …`: dieselbe Ansicht, gelesen über die Steuer-API.
async fn tail_remote(
    config_path: &Path,
    lines: usize,
    follow: bool,
    view: TailView,
    remote: Remote,
) -> Result<i32> {
    let control = Control::new(config_path, remote)?;
    // Mit Filtern braucht es mehr Einträge, um `lines` passende zu finden.
    let window = (lines as u64).saturating_mul(50).clamp(2_000, 50_000);
    // Bis zum Kopf lesen: Das Fenster kann über mehrere Segmente reichen.
    let entries = control
        .witness_until_head(&format!("last={window}"))
        .await?;
    let mut last = entries.last().map_or(0, |e| e.seq);
    let shown: Vec<&Entry> = entries.iter().filter(|e| view.wants(e)).collect();
    for e in &shown[shown.len().saturating_sub(lines)..] {
        print_entry(e, &view);
    }
    if !follow {
        return Ok(0);
    }
    let bell = !view.json && std::io::stdout().is_terminal();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
        // Ein Aussetzer der Verbindung beendet das Zuschauen nicht.
        if let Ok((new, l, _)) = control.witness(&format!("after={last}")).await {
            // Kleiner als zuvor: Dort läuft jetzt eine andere Kette.
            last = l;
            print_new(&new, &view, bell);
        }
    }
    Ok(0)
}

/// Wie wichtig ist ein Eintrag für einen Menschen?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Ok,
    /// Nur Funde, die diese Session schon gezeigt hat (mitgeschickte Historie).
    Known,
    Flag,
    Seen,
    Redact,
    /// Ein Tool-Aufruf wartet auf die Freigabe eines Menschen.
    Hold,
    Stop,
    Block,
}

pub(crate) fn tool_stopped(decision: &str) -> bool {
    matches!(decision, "deny" | "rejected" | "timeout")
}

pub(crate) fn severity_of(e: &Entry) -> Level {
    if e.action == "block" {
        Level::Block
    } else if e.tools.iter().any(|t| tool_stopped(&t.decision)) {
        Level::Stop
    } else if e.tools.iter().any(|t| t.decision == "held") || e.event.as_deref() == Some("hold") {
        Level::Hold
    } else if e.findings.iter().any(|f| !f.repeat) {
        if e.action == "redact" {
            Level::Redact
        } else {
            Level::Seen
        }
    } else if !e.response_findings.is_empty()
        || !e.flags.is_empty()
        || e.tools
            .iter()
            .any(|t| t.rule.is_some() && t.decision != "allow")
        || matches!(
            e.event.as_deref(),
            Some("config_reload_failed")
                | Some("approval")
                | Some("presidio_unavailable")
                | Some("recovered")
        )
    {
        Level::Flag
    } else if !e.findings.is_empty() {
        Level::Known
    } else {
        Level::Ok
    }
}

fn print_entry(e: &Entry, view: &TailView) {
    if view.json {
        println!("{}", serde_json::to_string(e).unwrap_or_default());
        return;
    }
    let time = human_time(&e.ts).dimmed();

    if let Some(event) = &e.event {
        let detail = e.detail.as_deref().unwrap_or("");
        match event.as_str() {
            // Jemand muss etwas tun: nicht zu übersehen, mit dem Befehl dazu.
            "hold" => {
                let id = detail.split_whitespace().next().unwrap_or("");
                println!(
                    "{time}  {}  {}  {}",
                    pad("HOLD", 7).yellow().bold(),
                    "⏸ waiting for approval".yellow().bold(),
                    detail
                );
                println!(
                    "          {} {}   {}",
                    "│".dimmed(),
                    format!("hedge approve {id}").green(),
                    format!("hedge deny {id}").red()
                );
            }
            "approval" => {
                let mark = if detail.contains(" approved ") {
                    "✓".green().to_string()
                } else {
                    "✗".red().to_string()
                };
                println!("{time}  {}  {mark} {}", pad("·", 7).dimmed(), detail);
            }
            // Ab hier läuft der Verkehr ohne Namenserkennung (oder steht).
            "presidio_unavailable" => println!(
                "{time}  {}  {}  {}",
                pad("OUTAGE", 7).red().bold(),
                "presidio unavailable".red().bold(),
                detail
            ),
            "presidio_ready" => println!(
                "{time}  {}  {} {}  {}",
                pad("·", 7).dimmed(),
                "✓".green(),
                "presidio ready".bold(),
                detail.dimmed()
            ),
            _ => {
                let label = match event.as_str() {
                    "config_reload_failed" => pad("CONFIG", 7).red().bold().to_string(),
                    "recovered" => pad("WITNESS", 7).yellow().bold().to_string(),
                    _ => pad("·", 7).dimmed().to_string(),
                };
                println!("{time}  {label}  {}  {}", event.bold(), detail.dimmed());
            }
        }
        return;
    }

    let label = match severity_of(e) {
        Level::Block => pad("BLOCK", 7).red().bold().to_string(),
        Level::Stop => pad("STOP", 7).red().bold().to_string(),
        Level::Hold => pad("HOLD", 7).yellow().bold().to_string(),
        Level::Redact => pad("REDACT", 7).yellow().bold().to_string(),
        Level::Seen => pad("SEEN", 7).yellow().to_string(),
        Level::Flag => pad("FLAG", 7).yellow().to_string(),
        Level::Known if e.action == "redact" => pad("redact", 7).dimmed().to_string(),
        Level::Known => pad("seen", 7).dimmed().to_string(),
        Level::Ok => pad("ok", 7).dimmed().to_string(),
    };
    let status = match e.status {
        Some(s) if s < 400 => s.to_string().green().to_string(),
        Some(s) => s.to_string().red().to_string(),
        None => "---".red().to_string(),
    };
    // Bei Modell-Anfragen ist das Modell interessant, sonst der Pfad.
    let what = match &e.model {
        Some(m) => m.clone(),
        None => format!("{} {}", e.method, e.path),
    };
    let tokens = match (e.tokens_in, e.tokens_out) {
        (None, None) => String::new(),
        (i, o) => format!(
            "  {}→{}",
            human_count(i.unwrap_or(0)),
            human_count(o.unwrap_or(0))
        ),
    };
    let who = match (&e.client, &e.session) {
        (Some(c), Some(s)) => format!("{c}/{s}"),
        (Some(c), None) => c.clone(),
        (None, Some(s)) => s.clone(),
        (None, None) => "-".into(),
    };
    let clean_tools: Vec<&str> = e
        .tools
        .iter()
        .filter(|t| t.rule.is_none() || t.decision == "allow")
        .map(|t| t.name.as_str())
        .collect();
    let tools_inline = if clean_tools.is_empty() || view.verbose {
        String::new()
    } else {
        format!("  {} {}", "⚙".dimmed(), counted(&clean_tools).dimmed())
    };

    println!(
        "{time}  {label}  {}  {}  {}  {status}  {:>6}{tokens}{tools_inline}",
        pad(&e.upstream, 9),
        pad(&truncate(&what, 26), 26),
        pad(&who, 8).dimmed(),
        human_duration(e.duration_ms),
    );

    let sub = |text: String| println!("          {} {text}", "│".dimmed());
    if let Some(d) = &e.detail {
        sub(format!("{} {d}", pad("why", 7).dimmed()));
    }
    for line in finding_lines(&e.findings, view.verbose) {
        sub(format!("{} {line}", pad("prompt", 7).dimmed()));
    }
    for line in finding_lines(&e.response_findings, view.verbose) {
        sub(format!("{} {line}", pad("answer", 7).dimmed()));
    }
    for t in &e.tools {
        let hit = t.rule.is_some() && t.decision != "allow";
        if !hit && !view.verbose {
            continue;
        }
        let verdict = match t.decision.as_str() {
            "deny" => format!(
                "{} {}",
                "✗ denied".red().bold(),
                t.rule.as_deref().unwrap_or("")
            ),
            "rejected" => format!(
                "{} {}",
                "✗ rejected by reviewer".red().bold(),
                t.rule.as_deref().unwrap_or("")
            ),
            "timeout" => format!(
                "{} {}",
                "✗ approval timed out".red().bold(),
                t.rule.as_deref().unwrap_or("")
            ),
            "approved" => format!(
                "{} {}",
                "✓ approved".green(),
                t.rule.as_deref().unwrap_or("")
            ),
            "held" => {
                let id = t.approval.as_deref().unwrap_or("<id>");
                format!(
                    "{} {}  {} {}",
                    "⏸ needs approval".yellow().bold(),
                    t.rule.as_deref().unwrap_or(""),
                    "→".dimmed(),
                    format!("reply `approve {id}` in the session, or: hedge approve {id}").green()
                )
            }
            "flag" => format!(
                "{} {}",
                "⚑ would be stopped".yellow(),
                t.rule.as_deref().unwrap_or("")
            ),
            _ => String::new(),
        };
        sub(format!(
            "{} {}  {}  {verdict}",
            pad("tool", 7).dimmed(),
            t.name.bold(),
            truncate(t.preview.as_deref().unwrap_or(""), 70),
        ));
    }
    for f in &e.flags {
        sub(format!(
            "{} {}  {}",
            pad("flag", 7).dimmed(),
            f.yellow(),
            flag_help(f).dimmed()
        ));
    }
    if e.aborted && e.detail.is_none() {
        sub(format!("{} stream ended early", pad("note", 7).dimmed()));
    }
    if view.verbose
        && let Some(c) = e.tokens_cached.filter(|c| *c > 0)
    {
        sub(format!(
            "{} {} tokens read from cache",
            pad("cache", 7).dimmed(),
            human_count(c)
        ));
    }
}

/// Funde verdichtet: eine Zeile pro Art und Wert, mit Anzahl und erster
/// Fundstelle. Was die Session schon gezeigt hat, schrumpft auf eine Zeile.
fn finding_lines(findings: &[FindingRecord], verbose: bool) -> Vec<String> {
    let label = |f: &FindingRecord| {
        let name = color_severity(&f.severity, describe_kind(&f.kind));
        let name = match &f.hint {
            Some(h) => format!("{name} {}", h.bold()),
            None => name,
        };
        // Gemeldet, aber nicht maskiert: Presidio ohne `enforce`.
        if f.advisory {
            format!("{name} {}", "(reported only)".dimmed())
        } else {
            name
        }
    };
    if verbose {
        return findings
            .iter()
            .map(|f| {
                format!(
                    "{}  {}{}",
                    label(f),
                    f.path.dimmed(),
                    if f.repeat {
                        "  (seen before in this session)".dimmed().to_string()
                    } else {
                        String::new()
                    }
                )
            })
            .collect();
    }

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
    let mut lines: Vec<String> = groups
        .into_iter()
        .map(|(f, n)| {
            let more = if n > 1 {
                format!(" (+{} more)", n - 1)
            } else {
                String::new()
            };
            format!(
                "{}{}  {}{}",
                if n > 1 {
                    format!("{n}× ")
                } else {
                    String::new()
                },
                label(f),
                f.path.dimmed(),
                more.dimmed()
            )
        })
        .collect();
    let known = findings.iter().filter(|f| f.repeat).count();
    if known > 0 {
        lines.push(
            format!("{known} seen before in this session (history resent with every request)")
                .dimmed()
                .to_string(),
        );
    }
    lines
}

pub(crate) fn flag_help(flag: &str) -> &'static str {
    match flag {
        "unwitnessed_tool_result" => {
            "the agent reported a tool result for a call hedge never saw the model request"
        }
        "result_for_denied_tool" => "the agent reported a result for a tool call hedge had stopped",
        "presidio_unavailable" => {
            "presidio was not available; this request was not checked for names"
        }
        "presidio_timeout" => {
            "presidio did not finish in time; not every text of this request was checked"
        }
        "response_not_inspected" => "the answer was compressed and could not be read",
        _ => "",
    }
}

/// `["Bash","Read","Bash"]` → `Bash ×2, Read`
pub(crate) fn counted(names: &[&str]) -> String {
    let mut groups: Vec<(&str, usize)> = Vec::new();
    for n in names {
        match groups.iter_mut().find(|(g, _)| g == n) {
            Some((_, c)) => *c += 1,
            None => groups.push((n, 1)),
        }
    }
    groups
        .into_iter()
        .map(|(n, c)| {
            if c > 1 {
                format!("{n} ×{c}")
            } else {
                n.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------- sessions ----------

#[derive(Default)]
struct SessionRow {
    session: String,
    client: Option<String>,
    first: String,
    last: String,
    requests: usize,
    tokens_in: u64,
    tokens_out: u64,
    findings: usize,
    tools: usize,
    stopped: usize,
    blocked: usize,
    worst: Option<Level>,
    models: Vec<String>,
}

fn select_since<'a>(entries: &'a [Entry], since: &Option<String>) -> Result<Vec<&'a Entry>> {
    let cutoff = match since {
        Some(s) => {
            Some(Utc::now() - chrono::Duration::from_std(parse_duration(s)?).unwrap_or_default())
        }
        None => None,
    };
    Ok(entries
        .iter()
        .filter(|e| match cutoff {
            Some(c) => parse_ts(&e.ts).map(|t| t >= c).unwrap_or(true),
            None => true,
        })
        .collect())
}

async fn cmd_sessions(
    config_path: &Path,
    since: Option<String>,
    json: bool,
    remote: Remote,
) -> Result<i32> {
    let entries = load_chain(config_path, remote).await?;
    let selected = select_since(&entries, &since)?;

    let mut rows: Vec<SessionRow> = Vec::new();
    for e in selected.iter().filter(|e| e.event.is_none()) {
        let Some(session) = &e.session else { continue };
        let row = match rows.iter_mut().find(|r| &r.session == session) {
            Some(r) => r,
            None => {
                rows.push(SessionRow {
                    session: session.clone(),
                    client: e.client.clone(),
                    first: e.ts.clone(),
                    ..Default::default()
                });
                rows.last_mut().expect("just pushed")
            }
        };
        row.last = e.ts.clone();
        row.requests += 1;
        row.tokens_in += e.tokens_in.unwrap_or(0);
        row.tokens_out += e.tokens_out.unwrap_or(0);
        row.findings += e.findings.iter().filter(|f| !f.repeat).count() + e.response_findings.len();
        row.tools += e.tools.len();
        row.stopped += e.tools.iter().filter(|t| tool_stopped(&t.decision)).count();
        row.blocked += usize::from(e.action == "block");
        row.worst = row.worst.max(Some(severity_of(e)));
        if let Some(m) = &e.model
            && !row.models.contains(m)
        {
            row.models.push(m.clone());
        }
    }
    rows.sort_by(|a, b| b.last.cmp(&a.last));

    if json {
        let out: Vec<Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "session": r.session, "client": r.client, "first": r.first, "last": r.last,
                    "requests": r.requests, "tokens_in": r.tokens_in, "tokens_out": r.tokens_out,
                    "findings": r.findings, "tool_calls": r.tools, "tool_calls_stopped": r.stopped,
                    "blocked": r.blocked, "models": r.models,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(0);
    }

    println!();
    if rows.is_empty() {
        println!("  no sessions recorded yet");
        println!();
        return Ok(0);
    }
    println!(
        "  {}",
        format!(
            "{}  {}  {}  {:>5}  {:>12}  {:>8}  {:>6}  {}",
            pad("session", 8),
            pad("last seen", 19),
            pad("duration", 8),
            "reqs",
            "tokens in→out",
            "findings",
            "tools",
            "models"
        )
        .dimmed()
    );
    for r in rows.iter().take(30) {
        let dur = match (parse_ts(&r.first), parse_ts(&r.last)) {
            (Some(a), Some(b)) => human_duration((b - a).num_milliseconds().max(0) as u64),
            _ => "-".into(),
        };
        let mark = match r.worst {
            Some(Level::Block) | Some(Level::Stop) => "●".red().to_string(),
            Some(Level::Hold) | Some(Level::Redact) | Some(Level::Seen) | Some(Level::Flag) => {
                "●".yellow().to_string()
            }
            _ => "●".green().to_string(),
        };
        let tools = if r.stopped > 0 {
            format!("{} ({} stopped)", r.tools, r.stopped)
                .red()
                .to_string()
        } else {
            r.tools.to_string()
        };
        println!(
            "{mark} {}  {}  {}  {:>5}  {:>12}  {:>8}  {:>6}  {}",
            pad(&r.session, 8).bold(),
            human_ts(&r.last),
            pad(&dur, 8),
            r.requests,
            format!("{}→{}", human_count(r.tokens_in), human_count(r.tokens_out)),
            r.findings,
            tools,
            truncate(&r.models.join(", "), 40).dimmed()
        );
    }
    println!();
    println!(
        "  Look into one: {}   Export as evidence: {}",
        "hedge tail --session <id> -v".cyan(),
        "hedge export --session <id> -o run.json".cyan()
    );
    println!();
    Ok(0)
}

// ---------- report ----------

async fn cmd_report(
    config_path: &Path,
    since: Option<String>,
    json: bool,
    remote: Remote,
) -> Result<i32> {
    let source = match &remote.url {
        Some(url) => format!("{} (via control API)", url.trim_end_matches('/')),
        None => load_or_hint(config_path)?
            .witness_path()
            .display()
            .to_string(),
    };
    let entries = load_chain(config_path, remote).await?;
    let selected = select_since(&entries, &since)?;

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
    println!("  witness   {source}");
    if let (Some(f), Some(l)) = (&summary.first_ts, &summary.last_ts) {
        println!("  range     {}  →  {}", human_ts(f), human_ts(l));
    }
    println!();
    println!(
        "  requests  {:>7}   {} session(s)",
        summary.total, summary.sessions
    );
    println!(
        "  forwarded {:>7}   {}",
        summary.forwarded,
        "clean, untouched".dimmed()
    );
    println!(
        "  observed  {:>7}   {}",
        summary.observed,
        "findings seen, forwarded unchanged (observe mode)".dimmed()
    );
    println!(
        "  redacted  {:>7}   {}",
        summary.redacted,
        "findings masked before forwarding".dimmed()
    );
    println!(
        "  blocked   {:>7}   {}",
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
    if summary.tokens_in + summary.tokens_out > 0 {
        println!(
            "  tokens    {} in, {} out, {} read from cache",
            human_count(summary.tokens_in),
            human_count(summary.tokens_out),
            human_count(summary.tokens_cached)
        );
    }

    section("findings in prompts, by kind", &summary.by_kind, |k| {
        format!("{}  {}", pad(describe_kind(k), 24), k.dimmed())
    });
    if summary.repeated > 0 {
        println!(
            "    {:>6}  {}",
            summary.repeated,
            "more times the same findings came again with the resent conversation history (not counted above)"
                .dimmed()
        );
    }
    section("which values (masked)", &summary.by_value, str::to_owned);
    if summary
        .by_value
        .keys()
        .any(|k| k.starts_with("e-mail address"))
    {
        println!();
        println!(
            "    {}",
            "Your own address or company domain? Then it is not a finding – add to hedge.toml:"
                .dimmed()
        );
        println!(
            "    {}",
            "[allow]  values = [\"you@example.com\"]  or  domains = [\"example.com\"]".cyan()
        );
    }
    section(
        "where they sit in requests",
        &summary.by_path,
        str::to_owned,
    );
    section(
        "findings in model answers",
        &summary.by_response_kind,
        |k| format!("{}  {}", pad(describe_kind(k), 24), k.dimmed()),
    );
    if summary.tool_calls > 0 {
        println!();
        println!(
            "  {}  {} total, {} stopped, {} asked for approval, {} approved, {} flagged",
            "tool calls".bold(),
            summary.tool_calls,
            summary.tools_stopped,
            summary.tools_held,
            summary.tools_approved,
            summary.tools_flagged
        );
        for (name, n) in sorted_desc(&summary.by_tool).into_iter().take(10) {
            println!("    {n:>6}  {name}");
        }
    }
    section("tool rules that fired", &summary.by_rule, str::to_owned);
    section("flags", &summary.by_flag, |f| {
        format!("{}  {}", pad(f, 26), flag_help(f).dimmed())
    });
    section("block reasons", &summary.by_block, str::to_owned);
    section("by client", &summary.by_client, str::to_owned);
    section("by upstream", &summary.by_upstream, str::to_owned);
    section("by model", &summary.by_model, str::to_owned);
    if summary.by_mode.len() > 1 {
        section(
            "modes seen (mode changed in this window)",
            &summary.by_mode,
            str::to_owned,
        );
    }
    section("events", &summary.by_event, str::to_owned);
    println!();
    Ok(0)
}

fn section(title: &str, map: &BTreeMap<String, usize>, show: impl Fn(&str) -> String) {
    if map.is_empty() {
        return;
    }
    println!();
    println!("  {}", title.bold());
    for (k, n) in sorted_desc(map).into_iter().take(10) {
        println!("    {n:>6}  {}", show(k));
    }
}

#[derive(Default)]
struct Summary {
    total: usize,
    sessions: usize,
    forwarded: usize,
    observed: usize,
    redacted: usize,
    blocked: usize,
    first_ts: Option<String>,
    last_ts: Option<String>,
    p50: u64,
    p95: u64,
    max_ms: u64,
    tokens_in: u64,
    tokens_out: u64,
    tokens_cached: u64,
    tool_calls: usize,
    tools_stopped: usize,
    tools_approved: usize,
    /// Aufrufe, die im Gespräch auf eine Freigabe gewartet haben.
    tools_held: usize,
    tools_flagged: usize,
    by_kind: BTreeMap<String, usize>,
    /// Maskierte Werte (`e-mail address  p…@example.com`).
    by_value: BTreeMap<String, usize>,
    /// Funde, die nur wiederholt wurden.
    repeated: usize,
    by_path: BTreeMap<String, usize>,
    by_response_kind: BTreeMap<String, usize>,
    by_tool: BTreeMap<String, usize>,
    by_rule: BTreeMap<String, usize>,
    by_flag: BTreeMap<String, usize>,
    by_block: BTreeMap<String, usize>,
    by_client: BTreeMap<String, usize>,
    by_upstream: BTreeMap<String, usize>,
    by_model: BTreeMap<String, usize>,
    by_mode: BTreeMap<String, usize>,
    by_event: BTreeMap<String, usize>,
}

impl Summary {
    fn from(entries: &[&Entry]) -> Self {
        let mut s = Summary {
            first_ts: entries.first().map(|e| e.ts.clone()),
            last_ts: entries.last().map(|e| e.ts.clone()),
            ..Default::default()
        };
        let mut durations: Vec<u64> = Vec::with_capacity(entries.len());
        let mut sessions = std::collections::BTreeSet::new();
        let bump =
            |m: &mut BTreeMap<String, usize>, k: &str| *m.entry(k.to_owned()).or_default() += 1;

        for e in entries {
            if let Some(event) = &e.event {
                bump(&mut s.by_event, event);
                continue;
            }
            s.total += 1;
            match e.action.as_str() {
                "block" => {
                    s.blocked += 1;
                    bump(&mut s.by_block, &block_category(e));
                }
                "redact" => s.redacted += 1,
                _ if e.findings.is_empty() => s.forwarded += 1,
                _ => s.observed += 1,
            }
            for f in &e.findings {
                // Wiederholungen aus der mitgeschickten Historie nur zählen,
                // nicht als eigene Funde ausweisen.
                if f.repeat {
                    s.repeated += 1;
                    continue;
                }
                bump(&mut s.by_kind, &f.kind);
                bump(&mut s.by_path, &strip_indices(&f.path));
                if let Some(h) = &f.hint {
                    bump(&mut s.by_value, &format!("{}  {h}", describe_kind(&f.kind)));
                }
            }
            for f in &e.response_findings {
                bump(&mut s.by_response_kind, &f.kind);
            }
            for t in &e.tools {
                s.tool_calls += 1;
                bump(&mut s.by_tool, &t.name);
                match t.decision.as_str() {
                    d if tool_stopped(d) => s.tools_stopped += 1,
                    "approved" => s.tools_approved += 1,
                    "held" => s.tools_held += 1,
                    "flag" => s.tools_flagged += 1,
                    _ => {}
                }
                if let Some(rule) = &t.rule {
                    bump(&mut s.by_rule, &format!("{rule}  ({})", t.decision));
                }
            }
            for f in &e.flags {
                bump(&mut s.by_flag, f);
            }
            if let Some(session) = &e.session {
                sessions.insert(session.clone());
            }
            if let Some(c) = &e.client {
                bump(&mut s.by_client, c);
            }
            bump(&mut s.by_upstream, &e.upstream);
            if let Some(m) = &e.model {
                bump(&mut s.by_model, m);
            }
            bump(&mut s.by_mode, &e.mode);
            s.tokens_in += e.tokens_in.unwrap_or(0);
            s.tokens_out += e.tokens_out.unwrap_or(0);
            s.tokens_cached += e.tokens_cached.unwrap_or(0);
            durations.push(e.duration_ms);
        }
        s.sessions = sessions.len();
        durations.sort_unstable();
        if !durations.is_empty() {
            s.p50 = durations[durations.len() / 2];
            s.p95 = durations[(durations.len() * 95 / 100).min(durations.len() - 1)];
            s.max_ms = *durations.last().expect("non-empty");
        }
        s
    }

    fn to_json(&self) -> Value {
        serde_json::json!({
            "total": self.total,
            "sessions": self.sessions,
            "forwarded": self.forwarded,
            "observed": self.observed,
            "redacted": self.redacted,
            "blocked": self.blocked,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "latency_ms": { "p50": self.p50, "p95": self.p95, "max": self.max_ms },
            "tokens": { "in": self.tokens_in, "out": self.tokens_out, "cached": self.tokens_cached },
            "tool_calls": {
                "total": self.tool_calls, "stopped": self.tools_stopped,
                "held": self.tools_held,
                "approved": self.tools_approved, "flagged": self.tools_flagged,
                "by_tool": self.by_tool, "by_rule": self.by_rule,
            },
            "by_kind": self.by_kind,
            "by_value": self.by_value,
            "findings_repeated": self.repeated,
            "by_path": self.by_path,
            "by_response_kind": self.by_response_kind,
            "by_flag": self.by_flag,
            "by_block": self.by_block,
            "by_client": self.by_client,
            "by_upstream": self.by_upstream,
            "by_model": self.by_model,
            "by_mode": self.by_mode,
            "by_event": self.by_event,
        })
    }
}

/// Grobe Ursache eines Blocks, für die Zusammenfassung.
fn block_category(e: &Entry) -> String {
    let d = e.detail.as_deref().unwrap_or("");
    if d.contains("budget") {
        "token budget exhausted".into()
    } else if d.contains("is not allowed by policy") {
        "model not allowed".into()
    } else if d.contains("client token") {
        "unknown client".into()
    } else {
        "high-severity finding in prompt".into()
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

// ---------- Steuer-API: status, approvals ----------

pub(crate) struct Control {
    pub(crate) base: String,
    token: String,
    http: reqwest::Client,
}

/// Ein HTTP-Client für Hedge selbst. Zu einer Adresse auf demselben Rechner
/// geht es nie über einen Proxy aus der Umgebung (`HTTP_PROXY`): Der kennt
/// dieses `127.0.0.1` nicht.
fn hedge_client(base: &str, timeout: Duration) -> Result<reqwest::Client> {
    let local = ["http://127.", "http://localhost", "http://[::1]"]
        .iter()
        .any(|p| base.starts_with(p));
    let builder = reqwest::Client::builder().timeout(timeout);
    Ok(if local {
        builder.no_proxy().build()?
    } else {
        builder.build()?
    })
}

impl Control {
    pub(crate) fn new(config_path: &Path, remote: Remote) -> Result<Self> {
        let loaded = Config::load(config_path);
        // Ohne lesbare Config fehlen Adresse und Token. Ist die Datei da,
        // aber kaputt, läuft Hedge mit der vorigen weiter – das soll die
        // Meldung sagen, statt zu `hedge init` zu raten.
        let missing = |flag: &str| -> String {
            match &loaded {
                Err(e) if config_path.exists() => format!(
                    "the config cannot be read, so hedge cannot be found from it (a running hedge keeps its previous config):\n       {e}\n       → fix the file, or pass {flag}"
                ),
                _ => format!("no config found: pass {flag} or run `hedge init`"),
            }
        };
        let cfg = loaded.as_ref().ok();
        let base = match remote.url {
            Some(u) => u.trim_end_matches('/').to_owned(),
            None => cfg
                .map(Config::control_url)
                .ok_or_else(|| missing("--url"))?,
        };
        let token = match remote.token {
            Some(t) => t,
            None => {
                let path = cfg
                    .map(|c| c.control_token_path())
                    .ok_or_else(|| missing("--token"))?;
                std::fs::read_to_string(&path)
                    .map_err(|_| {
                        format!(
                            "no control token at {} – run `hedge init`, then restart `hedge run`",
                            path.display()
                        )
                    })?
                    .trim()
                    .to_owned()
            }
        };
        Ok(Self {
            http: hedge_client(&base, Duration::from_secs(5))?,
            base,
            token,
        })
    }

    pub(crate) async fn call(&self, method: reqwest::Method, path: &str) -> Result<Value> {
        let resp = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| {
                format!(
                    "cannot reach hedge at {} ({}). Is `hedge run` running?",
                    self.base,
                    short_err(&e)
                )
            })?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let msg = body["error"]["message"]
                .as_str()
                .unwrap_or("unexpected answer")
                .to_owned();
            return Err(format!("hedge answered {}: {msg}", status.as_u16()).into());
        }
        Ok(body)
    }

    /// Ein Stück des Witness: die Einträge, die Sequenznummer des letzten
    /// gelieferten und der Kopf der Kette. `query` ist `after=<seq>` oder
    /// `last=<n>`.
    pub(crate) async fn witness(&self, query: &str) -> Result<(Vec<Entry>, u64, u64)> {
        let resp = self
            .http
            .get(format!("{}/_hedge/witness?{query}", self.base))
            .bearer_auth(&self.token)
            // Ein Stück kann einige Megabyte groß sein.
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .map_err(|e| {
                format!(
                    "cannot reach hedge at {} ({}). Is `hedge run` running?",
                    self.base,
                    short_err(&e)
                )
            })?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            let msg = body["error"]["message"].as_str().unwrap_or("");
            return Err(if msg.contains("unknown upstream") {
                format!(
                    "hedge at {} does not serve its witness over the control API (older version, or the control API has its own address – see control.listen)",
                    self.base
                )
                .into()
            } else {
                format!("hedge answered {}: {msg}", status.as_u16()).into()
            });
        }
        let number = |name: &str| -> u64 {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        };
        let (last, head) = (
            number(proxy::WITNESS_LAST_HEADER),
            number(proxy::WITNESS_HEAD_HEADER),
        );
        let body = resp.bytes().await?;
        let entries = body
            .split(|b| *b == b'\n')
            .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
            .filter_map(|l| serde_json::from_slice::<Entry>(l).ok())
            .collect();
        Ok((entries, last, head))
    }

    /// Alle Einträge ab `query` bis zum Kopf der Kette.
    pub(crate) async fn witness_until_head(&self, query: &str) -> Result<Vec<Entry>> {
        let (mut entries, mut last, mut head) = self.witness(query).await?;
        while last < head {
            let (more, l, h) = self.witness(&format!("after={last}")).await?;
            if l <= last {
                break;
            }
            entries.extend(more);
            (last, head) = (l, h);
        }
        Ok(entries)
    }
}

/// Die ganze Kette: aus den Dateien auf diesem Rechner oder, mit `--url`,
/// über die Steuer-API eines entfernten Hedge.
async fn load_chain(config_path: &Path, remote: Remote) -> Result<Vec<Entry>> {
    if remote.url.is_some() {
        return Control::new(config_path, remote)?
            .witness_until_head("after=0")
            .await;
    }
    let cfg = load_or_hint(config_path)?;
    Ok(witness::read_chain(&cfg.witness_path()).unwrap_or_default())
}

async fn cmd_status(config_path: &Path, remote: Remote, json: bool) -> Result<i32> {
    let control = Control::new(config_path, remote)?;
    let s = control.call(reqwest::Method::GET, "/_hedge/status").await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
        return Ok(0);
    }
    let n = |v: &Value| v.as_u64().unwrap_or(0);
    let since = &s["since_start"];
    println!();
    println!(
        "  {} {}   mode: {}   up {}",
        "hedge".bold(),
        s["version"].as_str().unwrap_or("?"),
        s["mode"].as_str().unwrap_or("?").bold(),
        human_duration(n(&s["uptime_secs"]) * 1000)
    );
    println!("  listening   {}", s["listen"].as_str().unwrap_or("?"));
    if let Some(c) = s["control_listen"].as_str() {
        println!("  control     {c}  {}", "(own address)".dimmed());
    }
    if let Some(why) = s["not_ready"].as_str() {
        println!("  ready       {} {}", fail(), why.red().bold());
    }
    println!(
        "  requests    {} since start – {} blocked, {} redacted, {} findings",
        n(&since["requests"]),
        n(&since["blocked"]),
        n(&since["redacted"]),
        n(&since["findings"])
    );
    println!(
        "  tool calls  {} seen, {} stopped   ({} rules, {})",
        n(&since["tool_calls"]),
        n(&since["tool_calls_stopped"]),
        n(&s["tools"]["rules"]),
        if s["tools"]["enforce"].as_bool().unwrap_or(false) {
            "enforced"
        } else {
            "flag only"
        }
    );
    let pending = n(&s["tools"]["pending_approvals"]);
    if pending > 0 {
        println!(
            "  approvals   {} → {}",
            format!("{pending} waiting").yellow().bold(),
            "hedge approvals".cyan()
        );
    } else {
        println!("  approvals   {}", "none waiting".dimmed());
    }
    if let Some(w) = s["witness"].as_object() {
        println!(
            "  witness     {}  head {}",
            w["path"].as_str().unwrap_or("?"),
            w["head"]
                .as_str()
                .map(|h| truncate(h, 24))
                .unwrap_or_else(|| "-".into())
        );
        // Ältere Versionen melden diese Felder nicht; dann bleibt es bei der Zeile oben.
        if w.get("ok").and_then(Value::as_bool) == Some(false) {
            println!(
                "              {} {}",
                fail(),
                format!(
                    "last write failed – requests pass without a record: {}",
                    w.get("last_error").and_then(Value::as_str).unwrap_or("?")
                )
                .red()
            );
        }
        if let Some(bytes) = w.get("segment_bytes").and_then(Value::as_u64) {
            let closed = w.get("segments").and_then(Value::as_u64).unwrap_or(0);
            let limit = w.get("rotate_mb").and_then(Value::as_u64).unwrap_or(0);
            let mut line = format!(
                "active segment {}, {} entries",
                human_bytes(bytes),
                w.get("segment_entries")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            );
            if limit > 0 {
                line.push_str(&format!(" (rotates at {limit} MiB)"));
            }
            if closed > 0 {
                line.push_str(&format!(
                    " · {closed} closed segment(s), {}",
                    human_bytes(w.get("segments_bytes").and_then(Value::as_u64).unwrap_or(0))
                ));
            }
            println!("              {}", line.dimmed());
        }
    } else {
        println!("  witness     {}", "disabled".yellow());
    }
    match presidio::one_line(&s["presidio"]) {
        Some(line) => {
            println!("  presidio    {line}");
            if s["presidio"]["state"] != "ready"
                && let Some(hint) = s["presidio"]["hint"].as_str()
            {
                println!("              → {}", hint.cyan());
            }
        }
        None => println!("  presidio    {}", "off".dimmed()),
    }
    // Die Zeile "ready" oben nennt den Grund; hier steht, was er bedeutet.
    if s["not_ready"]
        .as_str()
        .is_some_and(|why| why.contains("presidio"))
    {
        println!(
            "              {}",
            "requests that need presidio are rejected until it is back"
                .red()
                .bold()
        );
    }
    let daily = n(&s["budget"]["daily_tokens"]);
    if let Some(used) = s["budget"]["used_today"]
        .as_array()
        .filter(|u| !u.is_empty())
    {
        for u in used {
            let tokens = n(&u["tokens"]);
            // Ein Client kann ein eigenes Tagesbudget haben.
            let daily = u["limit"].as_u64().unwrap_or(daily);
            let limit = if daily > 0 {
                format!(
                    " of {} ({}%)",
                    human_count(daily),
                    tokens * 100 / daily.max(1)
                )
            } else {
                String::new()
            };
            println!(
                "  tokens      {} today: {}{limit}",
                u["client"].as_str().unwrap_or("?"),
                human_count(tokens)
            );
        }
    }
    println!();
    Ok(0)
}

async fn cmd_approvals(config_path: &Path, remote: Remote, json: bool) -> Result<i32> {
    let control = Control::new(config_path, remote)?;
    let v = control
        .call(reqwest::Method::GET, "/_hedge/approvals")
        .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(0);
    }
    let list: Vec<ApprovalInfo> = serde_json::from_value(v)?;
    println!();
    if list.is_empty() {
        println!("  {} nothing is waiting for approval", ok());
        println!();
        return Ok(0);
    }
    for a in &list {
        let left = human_duration(a.expires_in_secs * 1000);
        let chat = a.kind == "chat";
        println!(
            "  {}  {}  {}  {}",
            a.id.yellow().bold(),
            a.tool.bold(),
            a.rule,
            if chat {
                format!("asked in the session, expires in {left}")
            } else {
                format!("the agent is waiting, auto-reject in {left}")
            }
            .dimmed()
        );
        println!("          {}", a.preview);
        println!(
            "          {} {}   session {}   {}",
            "why".dimmed(),
            a.reason,
            match (&a.client, &a.session) {
                (Some(c), Some(s)) => format!("{c}/{s}"),
                (Some(c), None) => c.clone(),
                (None, Some(s)) => s.clone(),
                (None, None) => "-".into(),
            },
            a.model.as_deref().unwrap_or("").dimmed()
        );
        println!(
            "          {}   {}{}",
            format!("hedge approve {}", a.id).green(),
            format!("hedge deny {}", a.id).red(),
            if chat {
                format!("   or reply `approve {}` in the session", a.id)
                    .dimmed()
                    .to_string()
            } else {
                String::new()
            }
        );
        println!();
    }
    Ok(0)
}

async fn cmd_resolve(config_path: &Path, remote: Remote, id: &str, approve: bool) -> Result<i32> {
    let control = Control::new(config_path, remote)?;
    let verdict = if approve { "approve" } else { "deny" };
    let v = control
        .call(
            reqwest::Method::POST,
            &format!("/_hedge/approvals/{id}/{verdict}"),
        )
        .await?;
    let tool = v["resolved"]["tool"].as_str().unwrap_or("tool call");
    let chat = v["resolved"]["kind"] == "chat";
    if approve && chat {
        println!(
            "  {} approved {tool} ({id}) – now tell the agent to continue; this exact call passes once",
            ok()
        );
    } else if approve {
        println!("  {} approved {tool} ({id}) – the agent continues", ok());
    } else {
        println!(
            "  {} rejected {tool} ({id}) – the model is told it was not executed",
            "✗".red()
        );
    }
    Ok(0)
}

// ---------- client ----------

/// Clients und Admins stehen gleich in der Config: als `[[clients]]` bzw.
/// `[[admins]]` mit Name und Hash des Tokens.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Who {
    Client,
    Admin,
}

impl Who {
    fn table(self) -> &'static str {
        match self {
            Who::Client => "clients",
            Who::Admin => "admins",
        }
    }
    fn word(self) -> &'static str {
        match self {
            Who::Client => "client",
            Who::Admin => "admin",
        }
    }
    /// Am Präfix erkennt ein Mensch, wofür ein Token ist.
    fn token(self) -> Result<String> {
        let prefix = match self {
            Who::Client => "hc",
            Who::Admin => "ha",
        };
        Ok(format!("{prefix}_{}", random_hex(24)?))
    }
    fn exists(self, cfg: &Config, name: &str) -> bool {
        match self {
            Who::Client => cfg.clients.iter().any(|c| c.name == name),
            Who::Admin => cfg.admins.iter().any(|a| a.name == name),
        }
    }
}

/// Byte-Bereich des Blocks `[[table]]`, dessen `name` passt. Der Block
/// reicht bis zur nächsten Tabelle; Kommentare und Leerzeilen direkt davor
/// gehören zu ihr und bleiben stehen.
fn table_block(text: &str, table: &str, name: &str) -> Option<(usize, usize)> {
    let header = format!("[[{table}]]");
    let is_header = |line: &str| line.trim_start().starts_with('[');
    let lines: Vec<(usize, &str)> = text
        .split_inclusive('\n')
        .scan(0, |at, line| {
            let start = *at;
            *at += line.len();
            Some((start, line))
        })
        .collect();
    for (i, (start, line)) in lines.iter().enumerate() {
        if line.split('#').next().unwrap_or("").trim() != header {
            continue;
        }
        let next = lines[i + 1..]
            .iter()
            .position(|(_, l)| is_header(l))
            .map_or(lines.len(), |n| i + 1 + n);
        // Was direkt vor der nächsten Tabelle steht, gehört zu ihr.
        let mut end = next;
        while end > i + 1 {
            let l = lines[end - 1].1.trim();
            if l.is_empty() || l.starts_with('#') {
                end -= 1;
            } else {
                break;
            }
        }
        let stop = lines.get(end).map_or(text.len(), |(at, _)| *at);
        let block = &text[*start..stop];
        let matches = toml::from_str::<toml::Table>(block)
            .ok()
            .and_then(|t| {
                t.get(table)?
                    .as_array()?
                    .first()?
                    .get("name")?
                    .as_str()
                    .map(str::to_owned)
            })
            .is_some_and(|n| n == name);
        if matches {
            return Some((*start, stop));
        }
    }
    None
}

/// Entfernt den Block samt einer angrenzenden Leerzeile: der davor, oder –
/// steht direkt über dem Block ein Kommentar – der danach.
fn without_block(text: &str, table: &str, name: &str) -> Option<String> {
    let (start, stop) = table_block(text, table, name)?;
    let (head, tail) = (&text[..start], &text[stop..]);
    Some(match head.strip_suffix("\n\n") {
        Some(h) => format!("{h}\n{tail}"),
        None => format!("{head}{}", tail.strip_prefix('\n').unwrap_or(tail)),
    })
}

/// Ersetzt den Hash des Tokens im Block.
fn with_new_hash(text: &str, table: &str, name: &str, sha: &str) -> Option<String> {
    let (start, stop) = table_block(text, table, name)?;
    let mut done = false;
    let block: String = text[start..stop]
        .split_inclusive('\n')
        .map(|line| {
            let body = line.trim_start();
            if !done && body.starts_with("token_sha256") {
                done = true;
                let indent = &line[..line.len() - body.len()];
                let ending = if line.ends_with('\n') { "\n" } else { "" };
                format!("{indent}token_sha256 = \"{sha}\"{ending}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    done.then(|| format!("{}{block}{}", &text[..start], &text[stop..]))
}

/// Prüft den neuen Text und schreibt ihn erst dann: Eine kaputte Config
/// darf nie entstehen.
fn write_config(config_path: &Path, text: &str, what: &str) -> Result<()> {
    Config::from_toml(text)
        .map_err(|e| e.to_string())
        .and_then(|c| c.validate().map_err(|e| e.to_string()))
        .map_err(|e| format!("{what} would break the config: {e}"))?;
    std::fs::write(config_path, text).map_err(|e| {
        format!(
            "cannot write {}: {e}\n       → if the config comes from Git or a ConfigMap, use --print and add the block there",
            config_path.display()
        )
        .into()
    })
}

fn cmd_client(config_path: &Path, command: ClientCommand) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    match command {
        ClientCommand::List => {
            println!();
            if cfg.clients.is_empty() {
                println!(
                    "  no clients configured. Add one: {}",
                    "hedge client add <name>".cyan()
                );
            }
            let today = Utc::now().format("%Y-%m-%d").to_string();
            for c in &cfg.clients {
                let mut notes = Vec::new();
                if let Some(n) = c.daily_tokens {
                    notes.push(format!("{} tokens/day", human_count(n)));
                }
                match &c.expires {
                    Some(day) if c.expired_on(&today) => {
                        notes.push(format!("expired {day}").red().to_string())
                    }
                    Some(day) => notes.push(format!("until {day}")),
                    None => {}
                }
                println!(
                    "  {}  {}…  {}",
                    pad(&c.name, 20).bold(),
                    &c.token_sha256[..12],
                    notes.join(" · ").dimmed()
                );
            }
            println!(
                "  token required: {}",
                if cfg.server.require_client {
                    "yes"
                } else {
                    "no (server.require_client = false)"
                }
            );
            println!();
            Ok(0)
        }
        ClientCommand::Add {
            name,
            print,
            expires,
            daily_tokens,
        } => {
            let mut extra = String::new();
            if let Some(n) = daily_tokens {
                extra.push_str(&format!("daily_tokens = {n}\n"));
            }
            if let Some(day) = &expires {
                extra.push_str(&format!("expires = \"{day}\"\n"));
            }
            let token = add_person(config_path, &cfg, Who::Client, &name, &extra, print)?;
            let first = cfg
                .upstreams
                .first()
                .map(|u| u.name.as_str())
                .unwrap_or("anthropic");
            println!("  Give {name} these two lines:");
            println!(
                "    {}",
                format!("export ANTHROPIC_BASE_URL=https://<hedge-host>/{first}").cyan()
            );
            println!(
                "    {}",
                format!("export ANTHROPIC_CUSTOM_HEADERS=\"{CLIENT_TOKEN_HEADER}: {token}\"")
                    .cyan()
            );
            if !cfg.server.require_client {
                println!();
                println!(
                    "  {} server.require_client is false: requests without a token are still accepted.",
                    "!".yellow().bold()
                );
            }
            println!();
            Ok(0)
        }
        ClientCommand::Remove { name } => remove_person(config_path, &cfg, Who::Client, &name),
        ClientCommand::Rotate { name, print } => {
            rotate_person(config_path, &cfg, Who::Client, &name, print)
        }
    }
}

fn cmd_admin(config_path: &Path, command: AdminCommand) -> Result<i32> {
    let cfg = load_or_hint(config_path)?;
    match command {
        AdminCommand::List => {
            println!();
            if cfg.admins.is_empty() {
                println!(
                    "  no admins configured. Add one: {}",
                    "hedge admin add <name>".cyan()
                );
                println!(
                    "  {}",
                    "Without admins, only the local control token can approve – and approvals carry no name."
                        .dimmed()
                );
            }
            for a in &cfg.admins {
                println!("  {}  {}…", pad(&a.name, 20).bold(), &a.token_sha256[..12]);
            }
            println!();
            Ok(0)
        }
        AdminCommand::Add { name, print } => {
            let token = add_person(config_path, &cfg, Who::Admin, &name, "", print)?;
            println!("  Give {name} these two lines:");
            println!(
                "    {}",
                "export HEDGE_URL=https://<hedge-admin-host>".cyan()
            );
            println!(
                "    {}",
                format!("export HEDGE_CONTROL_TOKEN={token}").cyan()
            );
            println!(
                "  Then {}, {}, {} and {} work from their machine,",
                "hedge status".cyan(),
                "hedge approvals".cyan(),
                "hedge tail -f".cyan(),
                "hedge watch".cyan()
            );
            println!("  and every approval is recorded as “via control api ({name})”.");
            println!();
            Ok(0)
        }
        AdminCommand::Remove { name } => remove_person(config_path, &cfg, Who::Admin, &name),
        AdminCommand::Rotate { name, print } => {
            rotate_person(config_path, &cfg, Who::Admin, &name, print)
        }
    }
}

/// Legt einen Client oder Admin an und liefert das Token (einmal sichtbar).
fn add_person(
    config_path: &Path,
    cfg: &Config,
    who: Who,
    name: &str,
    extra: &str,
    print: bool,
) -> Result<String> {
    if !config::valid_name(name) {
        return Err(format!(
            "{} name must be 1–64 characters of a-z, A-Z, 0-9, '-', '_', '.', '@'",
            who.word()
        )
        .into());
    }
    if who.exists(cfg, name) {
        return Err(format!("{} {name:?} already exists", who.word()).into());
    }
    let token = who.token()?;
    let sha = witness::sha256_hex(token.as_bytes());
    let block = format!(
        "[[{}]]\nname = \"{name}\"\ntoken_sha256 = \"{sha}\"\n{extra}",
        who.table()
    );
    let mut text = std::fs::read_to_string(config_path)?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push('\n');
    text.push_str(&block);

    println!();
    if print {
        // Auch ohne zu schreiben prüfen, ob der Block zur Config passt.
        Config::from_toml(&text)
            .map_err(|e| e.to_string())
            .and_then(|c| c.validate().map_err(|e| e.to_string()))
            .map_err(|e| format!("this {} would break the config: {e}", who.word()))?;
        println!(
            "  Add this block to the config ({} was not changed):",
            config_path.display()
        );
        println!();
        for line in block.lines() {
            println!("    {line}");
        }
    } else {
        write_config(config_path, &text, &format!("adding the {}", who.word()))?;
        println!(
            "  {} {} {} added to {}",
            ok(),
            who.word(),
            name.bold(),
            config_path.display()
        );
        println!("    A running hedge picks this up within seconds.");
    }
    println!();
    println!("  Token (shown once, hedge only stores its hash):");
    println!("    {}", token.yellow());
    println!();
    Ok(token)
}

fn remove_person(config_path: &Path, cfg: &Config, who: Who, name: &str) -> Result<i32> {
    if !who.exists(cfg, name) {
        return Err(format!("no {} named {name:?}", who.word()).into());
    }
    let text = std::fs::read_to_string(config_path)?;
    let text = without_block(&text, who.table(), name).ok_or_else(|| {
        format!(
            "could not find the [[{}]] block of {name:?} in {} – remove it by hand",
            who.table(),
            config_path.display()
        )
    })?;
    write_config(config_path, &text, &format!("removing the {}", who.word()))?;
    println!();
    println!(
        "  {} {} {} removed from {}",
        ok(),
        who.word(),
        name.bold(),
        config_path.display()
    );
    println!("    A running hedge rejects the token within seconds.");
    println!();
    Ok(0)
}

fn rotate_person(
    config_path: &Path,
    cfg: &Config,
    who: Who,
    name: &str,
    print: bool,
) -> Result<i32> {
    if !who.exists(cfg, name) {
        return Err(format!("no {} named {name:?}", who.word()).into());
    }
    let token = who.token()?;
    let sha = witness::sha256_hex(token.as_bytes());
    println!();
    if print {
        println!(
            "  Replace token_sha256 of {} {} with ({} was not changed):",
            who.word(),
            name.bold(),
            config_path.display()
        );
        println!();
        println!("    token_sha256 = \"{sha}\"");
    } else {
        let text = std::fs::read_to_string(config_path)?;
        let text = with_new_hash(&text, who.table(), name, &sha).ok_or_else(|| {
            format!(
                "could not find the [[{}]] block of {name:?} in {} – use --print and edit by hand",
                who.table(),
                config_path.display()
            )
        })?;
        write_config(
            config_path,
            &text,
            &format!("rotating the {} token", who.word()),
        )?;
        println!(
            "  {} new token for {} {} in {}",
            ok(),
            who.word(),
            name.bold(),
            config_path.display()
        );
        println!("    The old token stops working within seconds.");
    }
    println!();
    println!("  Token (shown once, hedge only stores its hash):");
    println!("    {}", token.yellow());
    println!();
    Ok(0)
}

// ---------- init --keys-only / ready / rotate ----------

/// Legt an, was geheim ist und deshalb nie aus Git oder einer ConfigMap
/// kommt: Signierschlüssel und Steuer-Token. Ohne `--dir` an den Pfaden der
/// Config, mit `--dir` in diesem Verzeichnis. Vorhandenes bleibt unberührt
/// und der Aufruf ist dann still – er darf vor jedem Start laufen.
fn cmd_init_keys(config_path: &Path, dir: Option<PathBuf>) -> Result<i32> {
    let (key_path, token_path) = match dir {
        Some(dir) => (Some(dir.join("witness.key")), dir.join("control.token")),
        None => {
            let cfg = load_or_hint(config_path)?;
            (
                cfg.witness.enabled.then(|| cfg.witness_key_path()),
                cfg.control_token_path(),
            )
        }
    };
    if let Some(key_path) = key_path
        && !key_path.exists()
    {
        if let Some(dir) = key_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let vk = witness::generate_keypair(&key_path)?;
        println!(
            "created signing key {} (key id {}) – back it up, the chain is checked against it",
            key_path.display(),
            witness::key_id_of(&vk)
        );
    }
    if !token_path.exists() {
        if let Some(dir) = token_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        witness::write_private(&token_path, random_hex(32)?.as_bytes())?;
        println!("created control token {}", token_path.display());
    }
    Ok(0)
}

/// Für Healthchecks (Docker, systemd, Monitoring): fragt `/ready` und sagt
/// es mit dem Exit-Code. Braucht kein Token.
async fn cmd_ready(config_path: &Path, url: Option<String>) -> Result<i32> {
    let base = match url {
        Some(u) => u.trim_end_matches('/').to_owned(),
        None => load_or_hint(config_path)?.proxy_url(),
    };
    let http = hedge_client(&base, Duration::from_secs(4))?;
    match http.get(format!("{base}/ready")).send().await {
        Ok(r) if r.status().is_success() => {
            println!("ready");
            Ok(0)
        }
        Ok(r) if r.status().as_u16() == 503 => {
            let body: Value = r.json().await.unwrap_or(Value::Null);
            let waiting: Vec<&str> = body["waiting_for"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if waiting.is_empty() {
                println!("not ready: {base}/ready answered HTTP 503 without a reason");
            } else {
                println!("not ready: {}", waiting.join(", "));
            }
            Ok(1)
        }
        Ok(r) => {
            println!(
                "not ready: {base}/ready answered HTTP {} (is that a hedge of this version?)",
                r.status().as_u16()
            );
            Ok(1)
        }
        Err(e) => {
            println!(
                "not ready: cannot reach hedge at {base} ({})",
                short_err(&e)
            );
            Ok(1)
        }
    }
}

async fn cmd_rotate(config_path: &Path, remote: Remote) -> Result<i32> {
    let control = Control::new(config_path, remote)?;
    let v = control
        .call(reqwest::Method::POST, "/_hedge/witness/rotate")
        .await?;
    println!();
    match v["rotated"].as_object() {
        Some(seg) => {
            println!(
                "  {} segment closed: {}",
                ok(),
                seg["file"].as_str().unwrap_or("?").bold()
            );
            println!(
                "    entries #{} to #{}, {}",
                seg["first"].as_u64().unwrap_or(0),
                seg["last"].as_u64().unwrap_or(0),
                human_bytes(seg["bytes"].as_u64().unwrap_or(0))
            );
            println!(
                "    The chain continues in the active file; `hedge verify` checks all segments."
            );
            println!(
                "    The closed segment never changes again – archive it, and keep `hedge head` somewhere else."
            );
        }
        None => println!(
            "  {} nothing to rotate: the active segment is empty",
            "·".dimmed()
        ),
    }
    println!();
    Ok(0)
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
            println!("  {} config        {}", ok(), config_path.display());
            cfg
        }
        Err(e) => {
            println!("  {} config        {}", fail(), e);
            println!("                   → run `hedge init` or fix the file above");
            println!();
            return Ok(1);
        }
    };
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // 2. Port / läuft Hedge schon?
    let mut running = false;
    match tokio::net::TcpListener::bind(&cfg.server.listen).await {
        Ok(_) => println!(
            "  {} port          {} is free (hedge is not running)",
            ok(),
            cfg.server.listen
        ),
        Err(_) => match hedge_client(&cfg.proxy_url(), Duration::from_secs(5))?
            .get(format!("{}/health", cfg.proxy_url()))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                running = true;
                println!(
                    "  {} port          {} – hedge is running",
                    ok(),
                    cfg.server.listen
                );
            }
            _ => {
                problems += 1;
                println!(
                    "  {} port          {} is taken by something that is not hedge",
                    fail(),
                    cfg.server.listen
                );
            }
        },
    }
    if !cfg.is_loopback() && !cfg.server.require_client {
        problems += 1;
        println!(
            "  {} exposure      listening on the network without client tokens",
            fail()
        );
        println!(
            "                   → set server.require_client = true and add clients with `hedge client add`"
        );
    }

    // 3. Upstreams erreichbar
    for u in &cfg.upstreams {
        match http.get(&u.url).send().await {
            Ok(r) => println!(
                "  {} upstream      {}  {}  (HTTP {})",
                ok(),
                pad(&u.name, 10),
                u.url,
                r.status().as_u16()
            ),
            Err(e) => {
                problems += 1;
                println!(
                    "  {} upstream      {}  {}  unreachable: {}",
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
                    "  {} signing key   {} (key id {})",
                    ok(),
                    key.display(),
                    witness::key_id_of(&vk)
                );
                let path = cfg.witness_path();
                match witness::read_chain(&path) {
                    Ok(entries) => {
                        let report = witness::verify(&entries, &vk);
                        if report.is_ok() {
                            let closed = witness::segments(&path).len();
                            println!(
                                "  {} witness       {} – {} entries, chain intact{}",
                                ok(),
                                path.display(),
                                report.entries,
                                if closed > 0 {
                                    format!(" ({closed} closed segment(s) included)")
                                } else {
                                    String::new()
                                }
                            );
                        } else {
                            problems += 1;
                            println!(
                                "  {} witness       {} – {} problem(s), run `hedge verify`",
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
                            "  {} witness       {} – not created yet (first request creates it)",
                            "·".dimmed(),
                            path.display()
                        );
                    }
                    Err(e) => {
                        problems += 1;
                        println!("  {} witness       {}", fail(), e);
                    }
                }
            }
            Err(e) => {
                problems += 1;
                println!("  {} signing key   {}", fail(), e);
                println!("                   → run `hedge init`");
            }
        }
    } else {
        println!(
            "  {} witness       disabled in config – requests are not being recorded",
            "!".yellow()
        );
    }

    // 5. Steuer-Token und Tool-Policy
    let token_path = cfg.control_token_path();
    let has_token = token_path.exists();
    match ToolPolicy::from_config(&cfg.tools) {
        Ok(policy) => {
            // Im Gespräch freigeben braucht kein Token; nur das Warten auf
            // `hedge approve` hängt an der Steuer-API.
            let needs_token = cfg.tools.enforce
                && !cfg.tools.approve_in_chat
                && policy.rules().iter().any(|r| r.action == ToolAction::Hold);
            if has_token {
                println!("  {} control token {}", ok(), token_path.display());
            } else if needs_token {
                problems += 1;
                println!(
                    "  {} control token missing, but hold rules are enforced – held calls would be rejected",
                    fail()
                );
                println!("                   → run `hedge init`, then restart hedge");
            } else {
                println!(
                    "  {} control token missing – `hedge status` and approvals are unavailable (run `hedge init`)",
                    "!".yellow()
                );
            }
            println!("  {} tools         {}", ok(), tools_line(&cfg, &policy));
        }
        Err(e) => {
            problems += 1;
            println!("  {} tools         {e}", fail());
        }
    }
    if running && has_token {
        match Control::new(config_path, Remote::default()) {
            Ok(c) => match c.call(reqwest::Method::GET, "/_hedge/status").await {
                Ok(s) => {
                    let running_mode = s["mode"].as_str().unwrap_or("?");
                    if running_mode == cfg.mode.as_str() {
                        println!(
                            "  {} running       mode {running_mode}, matches this config",
                            ok()
                        );
                    } else {
                        problems += 1;
                        println!(
                            "  {} running       hedge runs in mode {running_mode}, this config says {} – different config file?",
                            fail(),
                            cfg.mode.as_str()
                        );
                    }
                }
                Err(e) => {
                    problems += 1;
                    println!("  {} running       control API: {e}", fail());
                    println!("                   → restart hedge so it picks up the control token");
                }
            },
            Err(e) => println!("  {} running       {e}", "!".yellow()),
        }
    }

    // 6. Optionale Dienste
    if cfg.telemetry.enabled {
        match http.get(&cfg.telemetry.endpoint).send().await {
            Ok(_) => println!(
                "  {} telemetry     {} answers",
                ok(),
                cfg.telemetry.endpoint
            ),
            Err(e) => {
                problems += 1;
                println!(
                    "  {} telemetry     {} unreachable: {}",
                    fail(),
                    cfg.telemetry.endpoint,
                    short_err(&e)
                );
                println!(
                    "                   → docker compose -f deploy/compose/docker-compose.yml up -d"
                );
            }
        }
    }
    problems += presidio::doctor(&cfg).await;

    // 7. Agent-Setup. Ein zentraler Hedge hat keine Agents auf seinem
    // eigenen Rechner – deren Einstellungen liegen bei den Entwicklern.
    // Zentral heißt: am Netz, oder hinter einem Reverse Proxy mit Clients
    // und Admins.
    let gateway = !cfg.is_loopback()
        || cfg.server.require_client
        || !cfg.clients.is_empty()
        || !cfg.admins.is_empty();
    if !gateway {
        let expected = agent_url(&cfg);
        let shell = std::env::var("ANTHROPIC_BASE_URL").ok();
        let settings = claude_settings_url();
        match judge_agent_setup(&expected, shell.as_deref(), settings.as_deref()) {
            Ok(line) => println!("  {} claude code   {line}", ok()),
            Err((what, fix)) => {
                problems += 1;
                println!("  {} claude code   {what}", fail());
                println!("                   → {fix}");
            }
        }
    } else {
        println!(
            "  {} agents        central gateway: {} client(s), {} admin(s) – agents point here from other machines",
            "·".dimmed(),
            cfg.clients.len(),
            cfg.admins.len()
        );
        if cfg.control_listen().is_none() {
            println!(
                "  {} control API   shares the proxy port – keep /_hedge/* away from developers at the reverse proxy, or set control.listen",
                "!".yellow()
            );
        }
        if cfg.admins.is_empty() {
            println!(
                "  {} admins        none – approvals from other machines need the shared control token and carry no name (hedge admin add <name>)",
                "!".yellow()
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

pub(crate) fn load_or_hint(path: &Path) -> Result<Config> {
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

pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
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
    if cfg.presidio.enabled {
        v.push("presidio");
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

pub(crate) fn parse_ts(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// `2026-11-09T13:20:11.123Z` → `2026-11-09 13:20:11` in lokaler Zeit.
pub(crate) fn human_ts(ts: &str) -> String {
    parse_ts(ts)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| ts.to_owned())
}

pub(crate) fn human_time(ts: &str) -> String {
    parse_ts(ts)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| ts.to_owned())
}

pub(crate) fn human_duration(ms: u64) -> String {
    if ms >= 3_600_000 {
        format!("{:.1}h", ms as f64 / 3_600_000.0)
    } else if ms >= 60_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
    }
}

/// 1234 → `1.2k`, 3_400_000 → `3.4M`
pub(crate) fn human_bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    let n = n as f64;
    if n >= KIB * KIB * KIB {
        format!("{:.1} GiB", n / (KIB * KIB * KIB))
    } else if n >= KIB * KIB {
        format!("{:.1} MiB", n / (KIB * KIB))
    } else if n >= KIB {
        format!("{:.0} KiB", n / KIB)
    } else {
        format!("{n:.0} B")
    }
}

pub(crate) fn human_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// "30m", "24h", "7d"
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let bad = || format!("invalid duration {s:?}, use e.g. 30m, 24h, 7d");
    let unit = s.chars().last().ok_or_else(bad)?;
    let num = &s[..s.len() - unit.len_utf8()];
    let n: u64 = num.parse().map_err(|_| bad())?;
    let secs = match unit {
        's' => n,
        'm' => n * 60,
        'h' => n * 3600,
        'd' => n * 86_400,
        _ => return Err(bad().into()),
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
    use crate::witness::ToolRecord;

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
        assert!(parse_duration("7ä").is_err());
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
    fn human_formats() {
        assert_eq!(human_duration(42), "42ms");
        assert_eq!(human_duration(1234), "1.2s");
        assert_eq!(human_duration(90_000), "1.5m");
        assert_eq!(human_count(999), "999");
        assert_eq!(human_count(1234), "1.2k");
        assert_eq!(human_count(3_400_000), "3.4M");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("äöü", 3), "äöü");
        assert_eq!(counted(&["Bash", "Read", "Bash"]), "Bash ×2, Read");
    }

    fn entry() -> Entry {
        Entry {
            seq: 1,
            ts: "2026-11-10T10:00:00.000Z".into(),
            upstream: "anthropic".into(),
            method: "POST".into(),
            path: "/v1/messages".into(),
            model: Some("claude-x".into()),
            mode: "observe".into(),
            action: "forward".into(),
            findings: vec![],
            body_sha256_in: String::new(),
            body_sha256_out: None,
            status: Some(200),
            duration_ms: 100,
            session: Some("abcd1234".into()),
            client: None,
            tokens_in: Some(1200),
            tokens_out: Some(340),
            tokens_cached: None,
            stop_reason: None,
            tools: vec![],
            response_findings: vec![],
            flags: vec![],
            stream: true,
            aborted: false,
            event: None,
            detail: None,
            key_id: String::new(),
            prev: String::new(),
            hash: String::new(),
            sig: String::new(),
        }
    }

    fn tool(decision: &str, rule: Option<&str>) -> ToolRecord {
        ToolRecord {
            id: "t".into(),
            name: "Bash".into(),
            input_sha256: String::new(),
            preview: Some("x".into()),
            rule: rule.map(str::to_owned),
            decision: decision.into(),
            approval: None,
        }
    }

    fn finding(kind: &str) -> FindingRecord {
        FindingRecord::new(kind, "high", "messages[0].content")
    }

    #[test]
    fn a_call_waiting_for_a_human_outranks_findings_but_not_a_stop() {
        let mut e = entry();
        e.findings = vec![finding("email")];
        e.action = "redact".into();
        e.tools = vec![tool("held", Some("HEDGE-SHELL-003"))];
        assert_eq!(severity_of(&e), Level::Hold);
        e.tools.push(tool("deny", Some("HEDGE-SHELL-001")));
        assert_eq!(severity_of(&e), Level::Stop);

        let mut hold = entry();
        hold.action = "event".into();
        hold.event = Some("hold".into());
        assert_eq!(severity_of(&hold), Level::Hold);
        hold.event = Some("approval".into());
        assert_eq!(
            severity_of(&hold),
            Level::Flag,
            "decisions show up under --alerts"
        );
        hold.event = Some("start".into());
        assert_eq!(severity_of(&hold), Level::Ok);

        let mut held = entry();
        held.tools = vec![tool("held", Some("R")), tool("approved", Some("R"))];
        let s = Summary::from(&[&held]);
        assert_eq!((s.tools_held, s.tools_approved, s.tools_stopped), (1, 1, 0));
        assert_eq!(s.to_json()["tool_calls"]["held"], 1);
    }

    #[test]
    fn severity_ranks_what_a_human_must_see_first() {
        let mut e = entry();
        assert_eq!(severity_of(&e), Level::Ok);
        e.tools = vec![tool("allow", None)];
        assert_eq!(severity_of(&e), Level::Ok);
        e.tools = vec![tool("flag", Some("R"))];
        assert_eq!(severity_of(&e), Level::Flag);
        e.findings = vec![finding("email")];
        assert_eq!(severity_of(&e), Level::Seen);
        e.action = "redact".into();
        assert_eq!(severity_of(&e), Level::Redact);
        e.tools = vec![tool("deny", Some("R"))];
        assert_eq!(severity_of(&e), Level::Stop);
        e.action = "block".into();
        assert_eq!(severity_of(&e), Level::Block);
    }

    #[test]
    fn summary_counts_outcomes_tools_and_tokens() {
        let clean = entry();
        let mut seen = entry();
        seen.findings = vec![finding("email"), finding("email")];
        let mut stopped = entry();
        stopped.session = Some("other".into());
        stopped.tools = vec![tool("deny", Some("HEDGE-SHELL-001")), tool("allow", None)];
        let mut blocked = entry();
        blocked.action = "block".into();
        blocked.detail = Some("daily token budget exhausted for local".into());
        let mut event = entry();
        event.event = Some("config_reload".into());
        event.action = "event".into();
        let all = [clean, seen, stopped, blocked, event];
        let refs: Vec<&Entry> = all.iter().collect();

        let s = Summary::from(&refs);

        assert_eq!(s.total, 4, "events are not requests");
        assert_eq!(
            (s.forwarded, s.observed, s.redacted, s.blocked),
            (2, 1, 0, 1)
        );
        assert_eq!(s.sessions, 2);
        assert_eq!(s.by_kind["email"], 2);
        assert_eq!(s.tool_calls, 2);
        assert_eq!(s.tools_stopped, 1);
        assert_eq!(s.by_rule["HEDGE-SHELL-001  (deny)"], 1);
        assert_eq!(s.by_block["token budget exhausted"], 1);
        assert_eq!(s.by_event["config_reload"], 1);
        assert_eq!(s.tokens_in, 4800);
        assert_eq!(s.to_json()["tool_calls"]["stopped"], 1);
    }

    #[test]
    fn finding_lines_group_by_kind_and_value_and_fold_repeats() {
        let hinted = |kind: &str, hint: &str, repeat: bool| FindingRecord {
            hint: Some(hint.into()),
            repeat,
            ..finding(kind)
        };
        let f = vec![
            hinted("email", "p…@a.org", false),
            finding("anthropic_api_key"),
            hinted("email", "p…@a.org", false),
            hinted("email", "x…@b.org", false),
            hinted("email", "p…@a.org", true),
            hinted("email", "x…@b.org", true),
        ];
        colored::control::set_override(false);

        let lines = finding_lines(&f, false);

        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(
            lines[0].starts_with("2× e-mail address p…@a.org"),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains("(+1 more)"));
        assert!(lines[1].starts_with("Anthropic API key"));
        assert!(lines[2].starts_with("e-mail address x…@b.org"));
        assert!(lines[3].starts_with("2 seen before in this session"));
        assert_eq!(finding_lines(&f, true).len(), 6);
    }

    #[test]
    fn repeated_findings_do_not_raise_the_level() {
        let mut e = entry();
        e.action = "redact".into();
        e.findings = vec![FindingRecord {
            repeat: true,
            ..finding("email")
        }];
        assert_eq!(severity_of(&e), Level::Known);
        let view = TailView {
            session: None,
            alerts: true,
            verbose: false,
            json: false,
        };
        assert!(!view.wants(&e), "--alerts hides requests with nothing new");

        e.findings.push(finding("email"));
        assert_eq!(severity_of(&e), Level::Redact);
        assert!(view.wants(&e));
    }

    #[test]
    fn agent_setup_follows_settings_json_before_the_shell() {
        let here = "http://127.0.0.1:18765/anthropic";
        let other = "http://127.0.0.1:8080/anthropic";

        assert!(judge_agent_setup(here, None, Some(here)).is_ok());
        assert!(judge_agent_setup(here, Some(other), Some(here)).is_ok());
        // Der Fall aus der Praxis: Shell stimmt, settings.json nicht.
        let (what, fix) = judge_agent_setup(here, Some(here), Some(other)).unwrap_err();
        assert!(what.contains("8080") && what.contains("18765"), "{what}");
        assert!(fix.contains("hedge init --claude-code"));

        assert!(judge_agent_setup(here, Some(here), None).is_ok());
        assert!(judge_agent_setup(here, Some(other), None).is_err());
        assert!(judge_agent_setup(here, None, None).is_err());
        assert!(judge_agent_setup(here, None, Some("http://127.0.0.1:18765/anthropic/")).is_ok());
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

        let doc: Value =
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

        let doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(
            doc["env"]["ANTHROPIC_BASE_URL"],
            "http://127.0.0.1:18765/anthropic"
        );
    }

    const CONFIG: &str = r#"mode = "observe"

[server]
listen = "0.0.0.0:18765"
require_client = true

# Die Entwickler
[[clients]]
name = "alice"
token_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
daily_tokens = 5000

[[clients]]
name = "bob"
  token_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"   # eingerückt
expires = "2027-01-31"

# Wer freigeben darf
[[admins]]
name = "anna"
token_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

# [[clients]]
# name = "alice"
# token_sha256 = "…"

[budget]
daily_tokens = 1000
"#;

    #[test]
    fn a_block_is_found_by_table_and_name_only() {
        let (a, b) = table_block(CONFIG, "clients", "alice").expect("alice");
        let block = &CONFIG[a..b];
        assert!(block.starts_with("[[clients]]\nname = \"alice\""));
        assert!(block.ends_with("daily_tokens = 5000\n"), "{block:?}");

        let (a, b) = table_block(CONFIG, "admins", "anna").expect("anna");
        assert!(
            CONFIG[a..b].ends_with("cccc\"\n"),
            "the commented example is not hers"
        );

        assert!(table_block(CONFIG, "admins", "alice").is_none());
        assert!(table_block(CONFIG, "clients", "anna").is_none());
        assert!(table_block(CONFIG, "clients", "nobody").is_none());
    }

    #[test]
    fn removing_a_block_leaves_the_rest_as_it_was() {
        let text = without_block(CONFIG, "clients", "alice").expect("removed");
        let cfg = Config::from_toml(&text).expect("still valid toml");
        assert_eq!(
            cfg.clients
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["bob"]
        );
        assert_eq!(cfg.admins.len(), 1);
        assert_eq!(cfg.budget.daily_tokens, 1000);
        assert!(text.contains("# Die Entwickler\n[[clients]]\nname = \"bob\""));
        assert!(text.contains("# Wer freigeben darf\n[[admins]]"));
        assert!(
            text.contains("# [[clients]]\n# name = \"alice\""),
            "comments stay"
        );
        let (a, b) = table_block(CONFIG, "clients", "alice").unwrap();
        assert_eq!(
            text.len(),
            CONFIG.len() - (b - a) - 1,
            "exactly the block and one blank line"
        );

        // Der letzte Block der Datei.
        let tail = "[[clients]]\nname = \"x\"\ntoken_sha256 = \"dd\"\n\n[[clients]]\nname = \"y\"\ntoken_sha256 = \"ee\"\n";
        assert_eq!(
            without_block(tail, "clients", "y").unwrap(),
            "[[clients]]\nname = \"x\"\ntoken_sha256 = \"dd\"\n"
        );
    }

    #[test]
    fn rotating_replaces_only_the_hash_of_that_block() {
        let new = "f".repeat(64);
        let text = with_new_hash(CONFIG, "clients", "bob", &new).expect("rotated");
        let cfg = Config::from_toml(&text).expect("still valid toml");
        assert_eq!(cfg.clients[1].token_sha256, new);
        assert_eq!(cfg.clients[1].expires.as_deref(), Some("2027-01-31"));
        assert!(
            cfg.clients[0].token_sha256.starts_with("aaaa"),
            "alice keeps hers"
        );
        assert!(cfg.admins[0].token_sha256.starts_with("cccc"));
        assert!(
            text.contains(&format!("  token_sha256 = \"{new}\"\n")),
            "indent kept"
        );
        assert!(with_new_hash(CONFIG, "clients", "nobody", &new).is_none());
    }

    #[test]
    fn sizes_read_like_a_human_would_say_them() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(64 * 1024), "64 KiB");
        assert_eq!(human_bytes(64 * 1024 * 1024), "64.0 MiB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024 / 2), "1.5 GiB");
    }
}
