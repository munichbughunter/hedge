//! `hedge deploy compose`: das fertige Verzeichnis für den zentralen Betrieb.
//!
//! Wer nur das Binary installiert hat, hat das Repo nicht. Deshalb stecken
//! Compose-Datei, zentrale Config, der Build-Kontext des Presidio-Images und
//! das Grafana-Dashboard im Binary – und passen so immer zur Version, die
//! sie schreibt.

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::presidio::sidecar::IMAGE_FILES;

const COMPOSE: &str = include_str!("../deploy/central/docker-compose.yml");
// Die Vorlage heißt im Repo nicht `.env`: Dateien dieses Namens fallen leicht
// durch globale gitignore-Regeln oder werden von Werkzeugen nicht geschrieben,
// und ohne sie baut Hedge nicht. Im erzeugten Verzeichnis heißt sie `.env`.
const ENV: &str = include_str!("../deploy/central/env.template");
const README: &str = include_str!("../deploy/central/README.md");
const HEDGE_TOML: &str = include_str!("../deploy/central/hedge/hedge.toml");
const CADDYFILE: &str = include_str!("../deploy/central/Caddyfile");
const CERTS_README: &str = include_str!("../deploy/central/certs/README.md");
const DASHBOARDS: &str = include_str!("../deploy/compose/grafana/hedge-dashboards.yaml");
const DASHBOARD: &str = include_str!("../deploy/compose/grafana/dashboards/hedge.json");
const ALERTS: &str = include_str!("../deploy/compose/grafana/alerting/hedge-alerts.yaml");

/// Ein Client, der beim Erzeugen gleich mit angelegt wird.
pub struct NewClient {
    pub name: String,
    pub token_sha256: String,
}

pub struct Options {
    pub clients: Vec<NewClient>,
    /// Grafana-Stack einschalten (Profil + Telemetrie).
    pub observability: bool,
    /// Caddy für TLS davorschalten (Profil).
    pub tls: bool,
}

/// Was `write` getan hat, Datei für Datei.
#[derive(Debug, PartialEq, Eq)]
pub struct Written {
    pub path: PathBuf,
    /// false: Die Datei gab es schon und sie blieb, wie sie war.
    pub written: bool,
}

fn fill(template: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = template.to_owned();
    for (key, value) in pairs {
        out = out.replace(&format!("{{{{{key}}}}}"), value);
    }
    out
}

/// Die zentrale `hedge.toml` für diese Optionen.
pub fn central_config(opts: &Options) -> String {
    let clients = if opts.clients.is_empty() {
        "# [[clients]]\n# name = \"…\"\n# token_sha256 = \"…\"".to_owned()
    } else {
        opts.clients
            .iter()
            .map(|c| {
                format!(
                    "[[clients]]\nname = {:?}\ntoken_sha256 = {:?}\n",
                    c.name, c.token_sha256
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    fill(
        HEDGE_TOML,
        &[
            // Ohne Clients würde Hedge mit require_client = true nicht starten.
            (
                "REQUIRE_CLIENT",
                if opts.clients.is_empty() {
                    "false"
                } else {
                    "true "
                },
            ),
            (
                "TELEMETRY",
                if opts.observability { "true" } else { "false" },
            ),
            ("CLIENTS", &clients),
        ],
    )
}

/// Alle Dateien des Verzeichnisses: (Pfad relativ zum Ziel, Inhalt).
pub fn files(opts: &Options) -> Vec<(PathBuf, String)> {
    let version = env!("CARGO_PKG_VERSION");
    let profiles = match (opts.tls, opts.observability) {
        (true, true) => "COMPOSE_PROFILES=tls,observability",
        (true, false) => "COMPOSE_PROFILES=tls",
        (false, true) => "COMPOSE_PROFILES=observability",
        (false, false) => "# COMPOSE_PROFILES=tls,observability",
    };
    let mut out: Vec<(PathBuf, String)> = vec![
        (
            "docker-compose.yml".into(),
            fill(COMPOSE, &[("VERSION", version)]),
        ),
        (
            ".env".into(),
            fill(ENV, &[("VERSION", version), ("PROFILES", profiles)]),
        ),
        ("README.md".into(), README.to_owned()),
        ("hedge/hedge.toml".into(), central_config(opts)),
        // Liegen immer dabei, auch ohne das Profil: Einschalten ist dann
        // eine Zeile in .env.
        ("Caddyfile".into(), CADDYFILE.to_owned()),
        ("certs/README.md".into(), CERTS_README.to_owned()),
        (
            "grafana/hedge-dashboards.yaml".into(),
            DASHBOARDS.to_owned(),
        ),
        ("grafana/dashboards/hedge.json".into(), DASHBOARD.to_owned()),
        (
            "grafana/alerting/hedge-alerts.yaml".into(),
            ALERTS.to_owned(),
        ),
    ];
    for (name, content) in IMAGE_FILES {
        out.push((Path::new("presidio").join(name), (*content).to_owned()));
    }
    out
}

/// Schreibt das Verzeichnis. Eine vorhandene `hedge/hedge.toml` und `.env`
/// bleiben immer stehen: Das sind die Dateien, die ein Admin anpasst.
/// Alles andere wird nur mit `force` überschrieben.
pub fn write(dir: &Path, opts: &Options, force: bool) -> Result<Vec<Written>, String> {
    let all = files(opts);
    let keep = |rel: &Path| rel == Path::new("hedge/hedge.toml") || rel == Path::new(".env");
    if !force
        && let Some((rel, _)) = all
            .iter()
            .find(|(rel, _)| !keep(rel) && dir.join(rel).exists())
    {
        return Err(format!(
            "{} already exists. Use --force to refresh the directory (hedge/hedge.toml and .env are kept)",
            dir.join(rel).display()
        ));
    }
    let mut done = Vec::new();
    for (rel, content) in all {
        let path = dir.join(&rel);
        if keep(&rel) && path.exists() {
            done.push(Written {
                path,
                written: false,
            });
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, content)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        done.push(Written {
            path,
            written: true,
        });
    }
    Ok(done)
}

/// Prüft, dass eine erzeugte zentrale Config gültig ist.
pub fn validate_central(text: &str) -> Result<Config, String> {
    let cfg = Config::from_toml(text).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Mode, OnUnavailable};

    fn opts(clients: &[&str], observability: bool) -> Options {
        opts_tls(clients, observability, false)
    }

    fn opts_tls(clients: &[&str], observability: bool, tls: bool) -> Options {
        Options {
            clients: clients
                .iter()
                .map(|n| NewClient {
                    name: n.to_string(),
                    token_sha256: "ab".repeat(32),
                })
                .collect(),
            observability,
            tls,
        }
    }

    #[test]
    fn central_config_is_valid_and_starts_observing() {
        let cfg = validate_central(&central_config(&opts(&[], false))).unwrap();
        assert_eq!(cfg.mode, Mode::Observe);
        assert!(
            !cfg.server.require_client,
            "no clients yet, so it must start"
        );
        assert!(!cfg.is_loopback());
        assert!(!cfg.telemetry.enabled);
        assert!(cfg.presidio.enabled && !cfg.presidio.managed);
        assert_eq!(cfg.presidio.url, "http://presidio:3000");
        assert_eq!(cfg.presidio.on_unavailable, OnUnavailable::Block);
        assert!(
            !cfg.presidio_fail_closed(),
            "not before enforce is switched on"
        );
        assert_eq!(cfg.witness.path, "/var/lib/hedge/witness.jsonl");
        assert_eq!(cfg.witness.rotate_mb, 64);
        assert_eq!(
            cfg.control_listen(),
            Some("0.0.0.0:18766"),
            "the control API is not on the agents' port"
        );
    }

    #[test]
    fn clients_and_observability_are_filled_in() {
        let cfg = validate_central(&central_config(&opts(&["anna", "ben"], true))).unwrap();
        assert!(cfg.server.require_client);
        assert_eq!(cfg.clients.len(), 2);
        assert_eq!(cfg.clients[1].name, "ben");
        assert!(cfg.telemetry.enabled);
        assert_eq!(cfg.telemetry.endpoint, "http://lgtm:4318");
    }

    #[test]
    fn no_placeholder_is_left_in_any_file() {
        for (path, content) in files(&opts(&["anna"], true)) {
            assert!(
                !content.contains("{{")
                    || path.ends_with("hedge.json")
                    || path.ends_with("hedge-alerts.yaml"),
                "{} still has a placeholder",
                path.display()
            );
        }
        let all = files(&opts(&[], false));
        let env = &all.iter().find(|(p, _)| p == Path::new(".env")).unwrap().1;
        assert!(env.contains(concat!("hedge-presidio:", env!("CARGO_PKG_VERSION"))));
        assert!(env.contains("# COMPOSE_PROFILES=tls,observability"));
        let names: Vec<String> = all.iter().map(|(p, _)| p.display().to_string()).collect();
        for expected in [
            "docker-compose.yml",
            "hedge/hedge.toml",
            "presidio/Dockerfile",
            "presidio/analyzer.yaml",
            "presidio/server.py",
            "grafana/dashboards/hedge.json",
            "Caddyfile",
            "certs/README.md",
        ] {
            assert!(names.iter().any(|n| n == expected), "{expected} missing");
        }
    }

    #[test]
    fn compose_keeps_presidio_off_the_network() {
        let all = files(&opts(&[], false));
        let compose = &all[0].1;
        let presidio = compose.split("\n  presidio:").nth(1).unwrap();
        let presidio = presidio.split("\n  lgtm:").next().unwrap();
        assert!(
            !presidio.contains("ports:"),
            "presidio must not publish a port"
        );
        assert!(presidio.contains("networks: [guard]"));
        assert!(compose.contains("guard:\n    internal: true"));
        assert!(compose.contains("condition: service_healthy"));
    }

    #[test]
    fn profiles_follow_the_options() {
        let env = |observability, tls| {
            let all = files(&opts_tls(&[], observability, tls));
            all.into_iter()
                .find(|(p, _)| p == Path::new(".env"))
                .unwrap()
                .1
        };
        assert!(env(false, true).contains("\nCOMPOSE_PROFILES=tls\n"));
        assert!(env(true, false).contains("\nCOMPOSE_PROFILES=observability\n"));
        assert!(env(true, true).contains("\nCOMPOSE_PROFILES=tls,observability\n"));
    }

    #[test]
    fn caddy_is_optional_and_guards_the_control_api() {
        let all = files(&opts(&[], false));
        let compose = &all[0].1;
        let caddy = compose.split("\n  caddy:").nth(1).unwrap();
        let caddy = caddy.split("\n  presidio:").next().unwrap();
        assert!(caddy.contains("profiles: [tls]"), "off unless asked for");
        assert!(!caddy.contains("guard"), "caddy never reaches presidio");
        let caddyfile = &all
            .iter()
            .find(|(p, _)| p == Path::new("Caddyfile"))
            .unwrap()
            .1;
        assert!(caddyfile.contains("auto_https disable_redirects"));
        assert!(caddyfile.contains("flush_interval -1"), "answers stream");
        assert!(caddyfile.contains("reverse_proxy hedge:18766"));
        assert!(caddyfile.contains("remote_ip {$HEDGE_ADMIN_CIDRS}"));
        // Der Port der Agents bietet die Steuer-API nicht an.
        assert!(compose.contains(":18766\""));
    }

    #[test]
    fn write_keeps_what_an_admin_edits() {
        let dir = std::env::temp_dir().join(format!(
            "hedge-deploy-{}-{}",
            std::process::id(),
            getrandom::u64().unwrap_or(0)
        ));
        let first = write(&dir, &opts(&[], false), false).unwrap();
        assert!(first.iter().all(|w| w.written));

        std::fs::write(dir.join("hedge/hedge.toml"), "mode = \"block\"\n").unwrap();
        let err = write(&dir, &opts(&[], false), false).unwrap_err();
        assert!(err.contains("--force"), "{err}");

        let second = write(&dir, &opts(&[], false), true).unwrap();
        let kept: Vec<_> = second.iter().filter(|w| !w.written).collect();
        assert_eq!(kept.len(), 2, "hedge.toml and .env");
        assert_eq!(
            std::fs::read_to_string(dir.join("hedge/hedge.toml")).unwrap(),
            "mode = \"block\"\n"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
