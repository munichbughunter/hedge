//! `hedge presidio …` von außen: das echte Binary, ein nachgestelltes
//! `docker` und ein nachgestelltes Presidio.
//!
//! Geprüft wird, was ein Mensch erlebt: Der Befehl prüft erst, ändert die
//! Config zuletzt, und nennt bei einem Fehler den Befehl, der hilft.

#![cfg(unix)]

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Output;

use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};
use hedge::config::{self, Config};
use serde_json::{Value, json};

/// Merkt sich seinen Zustand in Dateien neben sich und jeden Aufruf in `calls`.
const FAKE_DOCKER: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
echo "$@" >> "$dir/calls"
case "$1" in
  info)
    [ -f "$dir/daemon-down" ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
    echo "OrbStack|28.5.2" ;;
  inspect)
    [ -f "$dir/container" ] || { echo "Error: No such container: hedge-presidio" >&2; exit 1; }
    printf '{"State":{"Status":"%s"},"Image":"sha256:img","Config":{"Image":"test/presidio:1","Labels":{"dev.hedge.managed":"presidio"}},"HostConfig":{"PortBindings":{"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"%s"}]}}}\n' "$(cat "$dir/container")" "$(cat "$dir/port")" ;;
  image)
    [ -f "$dir/image" ] || { echo "Error: No such image" >&2; exit 1; }
    echo '{"Id":"sha256:img","Architecture":"","Size":1200000000,"Config":{"Labels":{"dev.hedge.presidio.languages":"de,en"}}}' ;;
  pull) touch "$dir/image" ;;
  run)
    echo running > "$dir/container"
    for a in "$@"; do case "$a" in 127.0.0.1:*:3000) echo "$a" | cut -d: -f2 > "$dir/port" ;; esac; done ;;
  start) echo running > "$dir/container" ;;
  stop) echo exited > "$dir/container" ;;
  rm) rm -f "$dir/container" ;;
  logs) echo "hedge-presidio ready" ;;
esac
"#;

async fn spawn_presidio() -> SocketAddr {
    let analyze = |Json(req): Json<Value>| async move {
        let text = req["text"].as_str().unwrap_or("").to_owned();
        let mut hits: Vec<Value> = Vec::new();
        for name in ["Jörg Müller", "John Smith"] {
            if let Some(byte) = text.find(name) {
                let start = text[..byte].chars().count();
                hits.push(json!({"entity_type": "PERSON", "start": start,
                    "end": start + name.chars().count(), "score": 0.85}));
            }
        }
        if let Some(byte) = text.find("+49 170 1234567") {
            let start = text[..byte].chars().count();
            hits.push(json!({"entity_type": "PHONE_NUMBER", "start": start, "end": start + 15, "score": 0.4}));
        }
        Json(Value::Array(hits)).into_response()
    };
    let info = || async {
        Json(json!({"service": "hedge-presidio", "presidio": "2.2.366",
            "languages": ["de", "en"], "models": ["de_core_news_md", "en_core_web_md"]}))
    };
    let app = Router::new()
        .route("/health", get(|| async { "up" }))
        .route("/info", get(info))
        .route("/analyze", post(analyze));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

struct Env {
    home: PathBuf,
    docker_dir: PathBuf,
}

impl Env {
    async fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hedge-cli-{}-{}",
            std::process::id(),
            getrandom::u64().unwrap_or(0)
        ));
        let home = root.join("home");
        let docker_dir = root.join("docker");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&docker_dir).unwrap();
        let docker = docker_dir.join("docker");
        std::fs::write(&docker, FAKE_DOCKER).unwrap();
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();

        let env = Self { home, docker_dir };
        let out = env.hedge(&["init"]).await;
        assert!(out.status.success(), "{}", text(&out));
        // Das nachgestellte docker statt eines echten.
        let cfg = env.config_path();
        let edited = config::set_key(
            &std::fs::read_to_string(&cfg).unwrap(),
            "presidio",
            "runtime",
            &format!("{:?}", docker.to_string_lossy()),
        );
        let edited = config::set_key(&edited, "presidio", "image", "\"test/presidio:1\"");
        // Ein Port, auf dem sicher kein Hedge läuft.
        let edited = config::set_key(&edited, "server", "listen", "\"127.0.0.1:9\"");
        std::fs::write(&cfg, edited).unwrap();
        env
    }

    fn config_path(&self) -> PathBuf {
        self.home.join(".hedge").join("hedge.toml")
    }

    fn config(&self) -> Config {
        Config::load(&self.config_path()).unwrap()
    }

    fn docker_calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.docker_dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(|l| l.split_whitespace().next().unwrap_or("").to_owned())
            .collect()
    }

    async fn hedge(&self, args: &[&str]) -> Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_hedge"))
            .args(args)
            .env("HOME", &self.home)
            .env("NO_COLOR", "1")
            .env_remove("HEDGE_CONFIG")
            .env_remove("HEDGE_URL")
            .env_remove("HEDGE_CONTROL_TOKEN")
            .output()
            .await
            .unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(root) = self.home.parent() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn enable_checks_first_and_writes_the_config_last() {
    let env = Env::new().await;
    let presidio = spawn_presidio().await;
    let port = presidio.port().to_string();

    let out = env.hedge(&["presidio", "enable", "--port", &port]).await;
    let shown = text(&out);
    assert!(out.status.success(), "{shown}");
    for expected in [
        "docker        running (OrbStack)",
        "image         test/presidio:1 (de, en · 1.2 GB)",
        &format!("container     hedge-presidio on 127.0.0.1:{port} (created)"),
        "presidio 2.2.366",
        "self-test     \"Jörg Müller, Tel. +49 170 …\" → person name",
        "[presidio] enabled = true, managed = true, url",
        "hedge         is not running",
        "Findings are reported only (enforce = false).",
    ] {
        assert!(
            shown.contains(expected),
            "missing {expected:?} in:\n{shown}"
        );
    }
    let cfg = env.config();
    assert!(cfg.presidio.enabled && cfg.presidio.managed);
    assert_eq!(cfg.presidio.url, format!("http://127.0.0.1:{port}"));
    assert!(env.docker_calls().contains(&"pull".to_owned()));

    // Noch einmal: nichts zu tun, nichts kaputt.
    let before = std::fs::read_to_string(env.config_path()).unwrap();
    let out = env.hedge(&["presidio", "enable"]).await;
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("already enabled, nothing to change"));
    assert_eq!(std::fs::read_to_string(env.config_path()).unwrap(), before);

    // status: Hedge läuft nicht, also fragt der Befehl Presidio selbst.
    let out = env.hedge(&["presidio", "status"]).await;
    let shown = text(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("● ready"), "{shown}");
    assert!(shown.contains("hedge-presidio · running"), "{shown}");
    assert!(
        shown.contains("on outage   requests continue and are flagged"),
        "{shown}"
    );

    // test: zeigt auch, was unter der Schwelle bleibt.
    let out = env
        .hedge(&[
            "presidio",
            "test",
            "Bitte ruf Jörg Müller an: +49 170 1234567",
        ])
        .await;
    let shown = text(&out);
    assert!(out.status.success(), "{shown}");
    assert!(
        shown.contains("Jörg Müller") && shown.contains("reported"),
        "{shown}"
    );
    assert!(
        shown.contains("not reported: below the threshold of 0.60"),
        "{shown}"
    );
    assert!(
        shown.contains("masked      Bitte ruf [REDACTED:person_name] an: +49 170 1234567"),
        "{shown}"
    );

    // disable: Config zurück, Container angehalten, nicht gelöscht.
    let out = env.hedge(&["presidio", "disable"]).await;
    let shown = text(&out);
    assert!(out.status.success(), "{shown}");
    assert!(
        shown.contains("hedge-presidio stopped, kept for next time"),
        "{shown}"
    );
    let cfg = env.config();
    assert!(!cfg.presidio.enabled && cfg.presidio.managed);
    let calls = env.docker_calls();
    assert!(calls.contains(&"stop".to_owned()) && !calls.contains(&"rm".to_owned()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_step_names_the_fix_and_leaves_the_config_alone() {
    let env = Env::new().await;
    let before = std::fs::read_to_string(env.config_path()).unwrap();

    // Docker läuft nicht.
    std::fs::write(env.docker_dir.join("daemon-down"), "").unwrap();
    let out = env.hedge(&["presidio", "enable"]).await;
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(1), "{shown}");
    assert!(
        shown.contains("docker is installed but not running"),
        "{shown}"
    );
    assert!(shown.contains("→"), "the fix is shown: {shown}");
    std::fs::remove_file(env.docker_dir.join("daemon-down")).unwrap();

    // Der Container kommt, aber auf dem Port antwortet ein Presidio, das
    // kein Deutsch kann.
    let english_only = {
        let analyze = |Json(req): Json<Value>| async move {
            if req["language"] != "en" {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(json!({"error": "language 'de' is not available in this image (available: en)"})),
                )
                    .into_response();
            }
            Json(json!([{"entity_type": "PERSON", "start": 10, "end": 20, "score": 0.85}]))
                .into_response()
        };
        let app = Router::new()
            .route("/health", get(|| async { "up" }))
            .route("/analyze", post(analyze));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    };
    let out = env
        .hedge(&[
            "presidio",
            "enable",
            "--port",
            &english_only.port().to_string(),
        ])
        .await;
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(1), "{shown}");
    assert!(
        shown.contains("language \"de\" is not available on this Presidio"),
        "{shown}"
    );
    assert!(shown.contains("hedge presidio upgrade"), "{shown}");

    assert_eq!(
        std::fs::read_to_string(env.config_path()).unwrap(),
        before,
        "nothing is half enabled"
    );
    assert!(!env.config().presidio.enabled);

    // status und doctor sagen, was zu tun ist.
    let out = env.hedge(&["presidio", "status"]).await;
    assert!(out.status.success());
    assert!(
        text(&out).contains("hedge presidio enable"),
        "{}",
        text(&out)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ready_and_deploy_work_without_a_running_hedge() {
    let env = Env::new().await;

    let out = env.hedge(&["ready"]).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out).starts_with("not ready: cannot reach hedge"),
        "{}",
        text(&out)
    );

    let dir = env.home.join("central");
    let dir_arg = dir.to_string_lossy().into_owned();
    let out = env
        .hedge(&["deploy", "compose", "-o", &dir_arg, "--client", "anna"])
        .await;
    let shown = text(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("hc_"), "the token is shown once: {shown}");
    let cfg = Config::load(&dir.join("hedge/hedge.toml")).unwrap();
    assert!(cfg.server.require_client);
    assert_eq!(cfg.clients[0].name, "anna");
    assert_eq!(cfg.presidio.url, "http://presidio:3000");
    for file in [
        "docker-compose.yml",
        ".env",
        "README.md",
        "presidio/Dockerfile",
    ] {
        assert!(dir.join(file).is_file(), "{file}");
    }

    // Nur Schlüssel anlegen, wie es der Container beim ersten Start tut.
    let keys = env.home.join("keys");
    let keys_arg = keys.to_string_lossy().into_owned();
    let out = env
        .hedge(&["init", "--keys-only", "--dir", &keys_arg])
        .await;
    assert!(out.status.success(), "{}", text(&out));
    assert!(keys.join("witness.key").is_file() && keys.join("control.token").is_file());
    assert!(!keys.join("hedge.toml").exists());
    let again = env
        .hedge(&["init", "--keys-only", "--dir", &keys_arg])
        .await;
    assert!(
        again.status.success() && text(&again).is_empty(),
        "silent when nothing is missing"
    );
}
