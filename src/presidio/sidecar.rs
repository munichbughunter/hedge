//! Der Presidio-Container, den Hedge lokal selbst verwaltet.
//!
//! Lokal soll Presidio ein Befehl sein (`hedge presidio enable`), kein
//! zweites Produkt. Hedge spricht dafür mit der Container-Laufzeit über
//! deren Kommandozeile (`docker`, ersatzweise `podman`) statt über die
//! Engine-API: Das respektiert den Kontext, den der Mensch eingestellt hat
//! (OrbStack, Colima, Docker Desktop), und lässt sich mit einem
//! nachgestellten `docker` testen.
//!
//! Zwei Arten, den Container in Ordnung zu bringen:
//!
//! - `Ensure::Start` (von `hedge run`): startet, was da ist. Lädt nichts
//!   herunter und baut nichts um – ein Proxy-Start darf keine Überraschung
//!   aus dem Netz holen.
//! - `Ensure::Converge` (von `hedge presidio enable | upgrade`): holt oder
//!   baut das Image und legt den Container neu an, wenn er nicht zur Config
//!   passt.
//!
//! Hedge fasst nur Container an, die es selbst angelegt hat (Label).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

use super::Problem;
use crate::config::Presidio as PresidioCfg;

/// Name des Containers. Einer pro Rechner.
pub const CONTAINER: &str = "hedge-presidio";
/// Daran erkennt Hedge seinen Container.
const LABEL_KEY: &str = "dev.hedge.managed";
const LABEL_VALUE: &str = "presidio";
/// Port des Dienstes im Container.
const CONTAINER_PORT: u16 = 3000;
const QUICK: Duration = Duration::from_secs(20);

/// Die Dateien, aus denen das Image gebaut wird. Sie liegen im Repo unter
/// `deploy/presidio` und stecken im Binary, damit `hedge presidio enable
/// --build` und `hedge deploy compose` auch ohne Repo funktionieren.
pub const IMAGE_FILES: &[(&str, &str)] = &[
    (
        "Dockerfile",
        include_str!("../../deploy/presidio/Dockerfile"),
    ),
    (
        "analyzer.yaml",
        include_str!("../../deploy/presidio/analyzer.yaml"),
    ),
    ("server.py", include_str!("../../deploy/presidio/server.py")),
    (
        "requirements.txt",
        include_str!("../../deploy/presidio/requirements.txt"),
    ),
];

/// Schreibt die Dateien des Images in ein Verzeichnis (Build-Kontext).
pub fn write_image_files(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (name, content) in IMAGE_FILES {
        std::fs::write(dir.join(name), content)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ensure {
    /// Starten, was da ist. Kein Pull, kein Umbau.
    Start,
    /// Image beschaffen und den Container an die Config angleichen.
    Converge { build: bool },
}

/// Was `ensure` getan hat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ensured {
    /// Lief schon.
    Running,
    /// War angehalten und wurde gestartet.
    Started,
    /// Wurde neu angelegt.
    Created,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    /// running, exited, created, paused, restarting …
    pub status: String,
    /// Image, mit dem der Container angelegt wurde (Name mit Tag).
    pub image: String,
    pub image_id: String,
    /// Von Hedge angelegt?
    pub ours: bool,
    /// Adresse und Port auf dem Rechner, auf die der Dienst gelegt ist.
    pub host_ip: String,
    pub host_port: Option<u16>,
    pub started_at: String,
}

impl Container {
    pub fn running(&self) -> bool {
        self.status == "running"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub id: String,
    pub arch: String,
    pub size_bytes: u64,
    pub languages: Option<String>,
}

pub struct Sidecar {
    /// Kommando der Laufzeit (`docker`, `podman` oder ein Pfad).
    bin: String,
    pub image: String,
    pub host: String,
    pub port: u16,
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Out {
    /// Die letzte nicht leere Zeile der Fehlerausgabe: das, was die Laufzeit
    /// dem Menschen sagen wollte.
    fn error(&self) -> String {
        let text = if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        text.lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("no error message")
            .trim()
            .to_owned()
    }
}

/// Sucht ein Kommando im `PATH`.
fn on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

fn start_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "open -a OrbStack   (or: open -a Docker)"
    } else {
        "sudo systemctl start docker   (rootless: systemctl --user start docker)"
    }
}

fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "install a container runtime, e.g. `brew install --cask orbstack`"
    } else {
        "install Docker Engine or Podman (https://docs.docker.com/engine/install/)"
    }
}

impl Sidecar {
    /// Findet die Laufzeit und liest Ziel und Image aus der Config.
    pub fn from_config(cfg: &PresidioCfg) -> Result<Self, Problem> {
        let (host, port) = cfg.host_port().ok_or_else(|| {
            Problem::new(format!("presidio.url {:?} has no host and port", cfg.url))
        })?;
        let bin = match cfg.runtime.trim() {
            "" | "auto" => ["docker", "podman"]
                .into_iter()
                .find(|b| on_path(b).is_some())
                .map(str::to_owned)
                .ok_or_else(|| {
                    Problem::new("no container runtime found (looked for docker and podman)")
                        .with_hint(install_hint())
                })?,
            explicit => {
                let found = if explicit.contains('/') {
                    Path::new(explicit).is_file()
                } else {
                    on_path(explicit).is_some()
                };
                if !found {
                    return Err(Problem::new(format!(
                        "presidio.runtime = {explicit:?} was not found"
                    ))
                    .with_hint("set [presidio] runtime to \"auto\", \"docker\" or \"podman\""));
                }
                explicit.to_owned()
            }
        };
        // `localhost` kann auf ::1 zeigen; der Port wird auf IPv4 gelegt.
        let host = if host.eq_ignore_ascii_case("localhost") {
            "127.0.0.1".to_owned()
        } else {
            host
        };
        Ok(Self {
            bin,
            image: cfg.image().to_owned(),
            host,
            port,
        })
    }

    /// Name der Laufzeit für Ausgaben (`docker`, `podman`).
    pub fn runtime(&self) -> &str {
        Path::new(&self.bin)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&self.bin)
    }

    fn is_podman(&self) -> bool {
        self.runtime().contains("podman")
    }

    async fn exec(&self, args: &[&str], limit: Duration) -> Result<Out, Problem> {
        let run = Command::new(&self.bin)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output();
        match tokio::time::timeout(limit, run).await {
            Ok(Ok(o)) => Ok(Out {
                ok: o.status.success(),
                stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            }),
            Ok(Err(e)) => Err(
                Problem::new(format!("could not run `{}`: {e}", self.runtime()))
                    .with_hint(install_hint()),
            ),
            Err(_) => Err(Problem::new(format!(
                "`{} {}` did not finish within {} s",
                self.runtime(),
                args.first().copied().unwrap_or(""),
                limit.as_secs()
            ))
            .with_hint(start_hint())),
        }
    }

    /// Wie `exec`, aber die Ausgabe geht direkt ins Terminal (Pull, Build,
    /// Logs): Der Mensch soll den Fortschritt sehen.
    async fn exec_visible(&self, args: &[&str]) -> Result<bool, Problem> {
        let status = Command::new(&self.bin)
            .args(args)
            .stdin(Stdio::null())
            .status()
            .await
            .map_err(|e| {
                Problem::new(format!("could not run `{}`: {e}", self.runtime()))
                    .with_hint(install_hint())
            })?;
        Ok(status.success())
    }

    /// Läuft der Dienst der Laufzeit? Liefert seinen Namen für die Ausgabe,
    /// z. B. `OrbStack` oder `Docker Engine 29.1`.
    pub async fn daemon(&self) -> Result<String, Problem> {
        let format = if self.is_podman() {
            "podman {{.Version.Version}}"
        } else {
            "{{.OperatingSystem}}|{{.ServerVersion}}"
        };
        let out = self.exec(&["info", "--format", format], QUICK).await?;
        let line = out.stdout.trim();
        if !out.ok || line.is_empty() || line == "|" {
            let raw = out.error();
            // Der Dienst läuft, aber dieser Benutzer darf nicht an den Socket.
            if raw.to_ascii_lowercase().contains("permission denied") {
                return Err(Problem::new(format!(
                    "{} is running, but this user may not use it (permission denied on its socket)",
                    self.runtime()
                ))
                .with_hint("sudo usermod -aG docker $USER   then log out and in again"));
            }
            return Err(
                Problem::new(format!("{} is installed but not running", self.runtime()))
                    .with_hint(start_hint()),
            );
        }
        Ok(match line.split_once('|') {
            Some(("", version)) => format!("docker {version}"),
            Some((os, _)) => os.to_owned(),
            None => line.to_owned(),
        })
    }

    /// Der Container, falls es ihn gibt.
    pub async fn container(&self) -> Result<Option<Container>, Problem> {
        let out = self
            .exec(
                &[
                    "inspect",
                    "--type",
                    "container",
                    "--format",
                    "{{json .}}",
                    CONTAINER,
                ],
                QUICK,
            )
            .await?;
        if !out.ok {
            let e = out.error().to_ascii_lowercase();
            if e.contains("no such") || e.contains("not found") || e.contains("no container") {
                return Ok(None);
            }
            return Err(Problem::new(format!(
                "{} inspect failed: {}",
                self.runtime(),
                out.error()
            ))
            .with_hint(start_hint()));
        }
        let doc: Value = serde_json::from_str(out.stdout.trim()).map_err(|e| {
            Problem::new(format!(
                "{} inspect gave unreadable output: {e}",
                self.runtime()
            ))
        })?;
        // podman liefert je nach Version ein Array.
        let doc = match doc {
            Value::Array(mut items) if !items.is_empty() => items.remove(0),
            other => other,
        };
        let binding = &doc["HostConfig"]["PortBindings"][format!("{CONTAINER_PORT}/tcp")][0];
        Ok(Some(Container {
            status: doc["State"]["Status"]
                .as_str()
                .unwrap_or("unknown")
                .to_owned(),
            image: doc["Config"]["Image"].as_str().unwrap_or("").to_owned(),
            image_id: doc["Image"].as_str().unwrap_or("").to_owned(),
            ours: doc["Config"]["Labels"][LABEL_KEY] == LABEL_VALUE,
            host_ip: binding["HostIp"].as_str().unwrap_or("").to_owned(),
            host_port: binding["HostPort"]
                .as_str()
                .and_then(|p| p.parse().ok())
                .or_else(|| binding["HostPort"].as_u64().map(|p| p as u16)),
            started_at: doc["State"]["StartedAt"].as_str().unwrap_or("").to_owned(),
        }))
    }

    /// Das Image, falls es lokal liegt.
    pub async fn local_image(&self, image: &str) -> Result<Option<Image>, Problem> {
        let out = self
            .exec(
                &["image", "inspect", "--format", "{{json .}}", image],
                QUICK,
            )
            .await?;
        if !out.ok {
            return Ok(None);
        }
        let doc: Value = serde_json::from_str(out.stdout.trim()).unwrap_or(Value::Null);
        let doc = match doc {
            Value::Array(mut items) if !items.is_empty() => items.remove(0),
            other => other,
        };
        let labels = if doc["Config"]["Labels"].is_object() {
            &doc["Config"]["Labels"]
        } else {
            &doc["Labels"]
        };
        Ok(Some(Image {
            id: doc["Id"].as_str().unwrap_or("").to_owned(),
            arch: doc["Architecture"].as_str().unwrap_or("").to_owned(),
            size_bytes: doc["Size"].as_u64().unwrap_or(0),
            languages: labels["dev.hedge.presidio.languages"]
                .as_str()
                .map(str::to_owned),
        }))
    }

    /// Holt das Image aus der Registry. Der Fortschritt ist sichtbar.
    pub async fn pull(&self) -> Result<(), Problem> {
        if self.exec_visible(&["pull", &self.image]).await? {
            return Ok(());
        }
        Err(Problem::new(format!(
            "could not pull {} (see the output above)",
            self.image
        ))
        .with_hint(
            "hedge presidio enable --build   (builds the image on this machine; takes a few minutes and needs about 1.5 GB)",
        ))
    }

    /// Baut das Image aus den eingebetteten Dateien.
    pub async fn build(&self, context: &Path) -> Result<(), Problem> {
        write_image_files(context).map_err(|e| {
            Problem::new(format!(
                "could not write the build files to {}: {e}",
                context.display()
            ))
        })?;
        let dir = context.to_string_lossy();
        if self
            .exec_visible(&["build", "--tag", &self.image, &dir])
            .await?
        {
            return Ok(());
        }
        Err(Problem::new(format!(
            "building {} failed (see the output above)",
            self.image
        ))
        .with_hint(format!(
            "the build files are in {dir}; the build needs network access to pypi.org and github.com"
        )))
    }

    async fn run_new(&self) -> Result<(), Problem> {
        let publish = format!("{}:{}:{CONTAINER_PORT}", self.host, self.port);
        let label = format!("{LABEL_KEY}={LABEL_VALUE}");
        let version = format!("dev.hedge.version={}", env!("CARGO_PKG_VERSION"));
        let out = self
            .exec(
                &[
                    "run",
                    "--detach",
                    "--name",
                    CONTAINER,
                    // Nach einem Neustart des Rechners ist Presidio ohne
                    // Wartezeit wieder da.
                    "--restart",
                    "unless-stopped",
                    // Nur auf Loopback: Presidio bekommt Prompts im Klartext
                    // und hat keine eigene Anmeldung.
                    "--publish",
                    &publish,
                    "--label",
                    &label,
                    "--label",
                    &version,
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    &self.image,
                ],
                Duration::from_secs(60),
            )
            .await?;
        if out.ok {
            return Ok(());
        }
        let e = out.error();
        let lower = e.to_ascii_lowercase();
        if lower.contains("already allocated")
            || lower.contains("address already in use")
            || lower.contains("port is already")
        {
            // Der halb angelegte Container würde den Namen blockieren.
            let _ = self.exec(&["rm", "--force", CONTAINER], QUICK).await;
            return Err(Problem::new(format!(
                "{}:{} is already in use by something else",
                self.host, self.port
            ))
            .with_hint(format!(
                "pick another port: set [presidio] url = \"http://127.0.0.1:{}\" and run this again",
                self.port + 1
            )));
        }
        Err(Problem::new(format!("could not start the container: {e}")))
    }

    /// Bringt den Container in Ordnung.
    pub async fn ensure(&self, mode: Ensure) -> Result<Ensured, Problem> {
        self.daemon().await?;
        let existing = self.container().await?;

        if let Some(c) = &existing
            && !c.ours
        {
            return Err(Problem::new(format!(
                "a container named {CONTAINER} exists, but hedge did not create it"
            ))
            .with_hint(format!(
                "{} rm -f {CONTAINER}   then run `hedge presidio enable`",
                self.runtime()
            )));
        }

        match mode {
            Ensure::Start => match existing {
                Some(c) if c.running() => Ok(Ensured::Running),
                Some(_) => {
                    self.start().await?;
                    Ok(Ensured::Started)
                }
                None => {
                    if self.local_image(&self.image).await?.is_none() {
                        return Err(Problem::new(format!(
                            "the presidio container does not exist and its image {} is not on this machine",
                            self.image
                        ))
                        .with_hint("hedge presidio enable"));
                    }
                    self.run_new().await?;
                    Ok(Ensured::Created)
                }
            },
            Ensure::Converge { build } => {
                if build {
                    self.build(&crate::config::default_dir().join("presidio-image"))
                        .await?;
                } else if self.local_image(&self.image).await?.is_none() {
                    self.pull().await?;
                }
                let wanted = self.local_image(&self.image).await?.ok_or_else(|| {
                    Problem::new(format!(
                        "image {} is missing after it was fetched",
                        self.image
                    ))
                })?;
                match existing {
                    Some(c) if self.matches(&c, &wanted) => {
                        if c.running() {
                            Ok(Ensured::Running)
                        } else {
                            self.start().await?;
                            Ok(Ensured::Started)
                        }
                    }
                    Some(_) => {
                        self.remove().await?;
                        self.run_new().await?;
                        Ok(Ensured::Created)
                    }
                    None => {
                        self.run_new().await?;
                        Ok(Ensured::Created)
                    }
                }
            }
        }
    }

    /// Passt der Container zu Image und Port aus der Config?
    fn matches(&self, c: &Container, wanted: &Image) -> bool {
        let same_image = if !wanted.id.is_empty() && !c.image_id.is_empty() {
            c.image_id == wanted.id
        } else {
            c.image == self.image
        };
        same_image && c.host_port == Some(self.port) && c.host_ip == self.host
    }

    /// Was am Container nicht zur Config passt, in Worten. `None` = passt.
    pub async fn drift(&self, c: &Container) -> Option<String> {
        if c.host_port != Some(self.port) || c.host_ip != self.host {
            return Some(format!(
                "the container listens on {}:{}, the config says {}:{}",
                c.host_ip,
                c.host_port.map_or("?".into(), |p| p.to_string()),
                self.host,
                self.port
            ));
        }
        match self.local_image(&self.image).await {
            Ok(Some(wanted)) if !wanted.id.is_empty() && wanted.id != c.image_id => Some(format!(
                "the container runs an older build of {}",
                self.image
            )),
            Ok(Some(_)) => None,
            _ if c.image != self.image => Some(format!(
                "the container runs {}, this hedge expects {}",
                c.image, self.image
            )),
            _ => None,
        }
    }

    pub async fn start(&self) -> Result<(), Problem> {
        let out = self
            .exec(&["start", CONTAINER], Duration::from_secs(60))
            .await?;
        if out.ok {
            Ok(())
        } else {
            Err(
                Problem::new(format!("could not start the container: {}", out.error()))
                    .with_hint("hedge presidio logs"),
            )
        }
    }

    pub async fn stop(&self) -> Result<(), Problem> {
        let out = self
            .exec(&["stop", "--time", "5", CONTAINER], Duration::from_secs(60))
            .await?;
        if out.ok {
            Ok(())
        } else {
            Err(Problem::new(format!(
                "could not stop the container: {}",
                out.error()
            )))
        }
    }

    pub async fn remove(&self) -> Result<(), Problem> {
        let out = self
            .exec(&["rm", "--force", CONTAINER], Duration::from_secs(60))
            .await?;
        if out.ok {
            Ok(())
        } else {
            Err(Problem::new(format!(
                "could not remove the container: {}",
                out.error()
            )))
        }
    }

    /// Zeigt die Ausgabe des Containers im Terminal.
    pub async fn logs(&self, follow: bool, tail: usize) -> Result<bool, Problem> {
        let tail = tail.to_string();
        let mut args = vec!["logs", "--tail", &tail];
        if follow {
            args.push("--follow");
        }
        args.push(CONTAINER);
        self.exec_visible(&args).await
    }

    /// Die letzten Zeilen der Ausgabe, für Fehlermeldungen.
    pub async fn last_log_lines(&self, n: usize) -> Vec<String> {
        let n = n.to_string();
        match self.exec(&["logs", "--tail", &n, CONTAINER], QUICK).await {
            Ok(out) => format!("{}{}", out.stdout, out.stderr)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(str::to_owned)
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Ein nachgestelltes `docker`: merkt sich seinen Zustand in Dateien
    /// und schreibt jeden Aufruf in `calls`.
    const FAKE: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
echo "$@" >> "$dir/calls"
case "$1" in
  info)
    [ -f "$dir/daemon-down" ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
    echo "OrbStack|28.5.2" ;;
  inspect)
    [ -f "$dir/container" ] || { echo "Error: No such container: hedge-presidio" >&2; exit 1; }
    status="$(cat "$dir/container")"
    label="presidio"; [ -f "$dir/foreign" ] && label="other"
    port="5002"; [ -f "$dir/port" ] && port="$(cat "$dir/port")"
    printf '{"State":{"Status":"%s","StartedAt":"2026-11-20T10:00:00Z"},"Image":"%s","Config":{"Image":"img:1","Labels":{"dev.hedge.managed":"%s"}},"HostConfig":{"PortBindings":{"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"%s"}]}}}\n' "$status" "$(cat "$dir/container-image" 2>/dev/null)" "$label" "$port" ;;
  image)
    [ -f "$dir/image" ] || { echo "Error: No such image" >&2; exit 1; }
    printf '{"Id":"%s","Architecture":"arm64","Size":1200000000,"Config":{"Labels":{"dev.hedge.presidio.languages":"de,en"}}}\n' "$(cat "$dir/image")" ;;
  pull)
    [ -f "$dir/registry-empty" ] && { echo "manifest unknown" >&2; exit 1; }
    echo "sha256:new" > "$dir/image" ;;
  build)
    echo "sha256:built" > "$dir/image" ;;
  run)
    [ -f "$dir/port-taken" ] && { echo "Bind for 127.0.0.1:5002 failed: port is already allocated" >&2; exit 125; }
    echo running > "$dir/container"; cp "$dir/image" "$dir/container-image"; rm -f "$dir/port" ;;
  start) echo running > "$dir/container" ;;
  stop) echo exited > "$dir/container" ;;
  rm) rm -f "$dir/container" "$dir/container-image" ;;
  logs) echo "hedge-presidio ready" ;;
esac
"#;

    struct Fake {
        dir: PathBuf,
        sidecar: Sidecar,
    }

    impl Fake {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "hedge-sidecar-{}-{}",
                std::process::id(),
                getrandom::u64().unwrap_or(0)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let bin = dir.join("docker");
            std::fs::write(&bin, FAKE).unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            let cfg = PresidioCfg {
                enabled: true,
                managed: true,
                runtime: bin.to_string_lossy().into_owned(),
                image: Some("img:1".into()),
                ..PresidioCfg::default()
            };
            Self {
                sidecar: Sidecar::from_config(&cfg).unwrap(),
                dir,
            }
        }

        fn set(&self, file: &str, content: &str) {
            std::fs::write(self.dir.join(file), content).unwrap();
        }

        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.join("calls"))
                .unwrap_or_default()
                .lines()
                .map(|l| l.split_whitespace().next().unwrap_or("").to_owned())
                .collect()
        }

        fn ran(&self, verb: &str) -> bool {
            self.calls().iter().any(|c| c == verb)
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    async fn daemon_name_is_shown_and_a_stopped_daemon_gets_a_fix() {
        let f = Fake::new();
        assert_eq!(f.sidecar.daemon().await.unwrap(), "OrbStack");
        assert_eq!(f.sidecar.runtime(), "docker");

        f.set("daemon-down", "");
        let p = f.sidecar.ensure(Ensure::Start).await.unwrap_err();
        assert!(p.reason.contains("not running"), "{}", p.reason);
        assert!(p.hint.is_some());
    }

    #[tokio::test]
    async fn start_never_pulls() {
        let f = Fake::new();
        let p = f.sidecar.ensure(Ensure::Start).await.unwrap_err();
        assert!(p.reason.contains("not on this machine"), "{}", p.reason);
        assert_eq!(p.hint.as_deref(), Some("hedge presidio enable"));
        assert!(!f.ran("pull") && !f.ran("run"));
    }

    #[tokio::test]
    async fn start_creates_from_a_local_image_and_restarts_a_stopped_container() {
        let f = Fake::new();
        f.set("image", "sha256:abc");
        assert_eq!(
            f.sidecar.ensure(Ensure::Start).await.unwrap(),
            Ensured::Created
        );
        assert_eq!(
            f.sidecar.ensure(Ensure::Start).await.unwrap(),
            Ensured::Running
        );

        f.set("container", "exited");
        assert_eq!(
            f.sidecar.ensure(Ensure::Start).await.unwrap(),
            Ensured::Started
        );
        assert!(f.sidecar.container().await.unwrap().unwrap().running());
        assert!(!f.ran("pull"));
    }

    #[tokio::test]
    async fn converge_pulls_once_and_recreates_on_a_new_image() {
        let f = Fake::new();
        assert_eq!(
            f.sidecar
                .ensure(Ensure::Converge { build: false })
                .await
                .unwrap(),
            Ensured::Created
        );
        assert!(f.ran("pull"));
        let c = f.sidecar.container().await.unwrap().unwrap();
        assert!(c.ours);
        assert_eq!(c.host_port, Some(5002));
        assert!(f.sidecar.drift(&c).await.is_none());

        // Dasselbe noch einmal ändert nichts.
        let before = f.calls().len();
        assert_eq!(
            f.sidecar
                .ensure(Ensure::Converge { build: false })
                .await
                .unwrap(),
            Ensured::Running
        );
        assert!(
            !f.calls()[before..]
                .iter()
                .any(|c| c == "pull" || c == "run")
        );

        // Ein neues Image unter demselben Namen: der Container wird ersetzt.
        f.set("image", "sha256:newer");
        let c = f.sidecar.container().await.unwrap().unwrap();
        assert!(f.sidecar.drift(&c).await.unwrap().contains("older build"));
        assert_eq!(
            f.sidecar
                .ensure(Ensure::Converge { build: false })
                .await
                .unwrap(),
            Ensured::Created
        );
        assert!(f.ran("rm"));
    }

    #[tokio::test]
    async fn a_changed_port_recreates_the_container() {
        let f = Fake::new();
        f.set("image", "sha256:abc");
        f.sidecar.ensure(Ensure::Start).await.unwrap();
        f.set("port", "5999");
        let c = f.sidecar.container().await.unwrap().unwrap();
        assert!(f.sidecar.drift(&c).await.unwrap().contains("5999"));
        assert_eq!(
            f.sidecar
                .ensure(Ensure::Converge { build: false })
                .await
                .unwrap(),
            Ensured::Created
        );
    }

    #[tokio::test]
    async fn pull_failure_points_to_the_local_build() {
        let f = Fake::new();
        f.set("registry-empty", "");
        let p = f
            .sidecar
            .ensure(Ensure::Converge { build: false })
            .await
            .unwrap_err();
        assert!(p.reason.contains("could not pull img:1"), "{}", p.reason);
        assert!(p.hint.unwrap().contains("--build"));
    }

    #[tokio::test]
    async fn a_taken_port_names_the_next_one() {
        let f = Fake::new();
        f.set("image", "sha256:abc");
        f.set("port-taken", "");
        let p = f.sidecar.ensure(Ensure::Start).await.unwrap_err();
        assert!(
            p.reason.contains("127.0.0.1:5002 is already in use"),
            "{}",
            p.reason
        );
        assert!(p.hint.unwrap().contains("5003"));
    }

    #[tokio::test]
    async fn foreign_containers_are_left_alone() {
        let f = Fake::new();
        f.set("image", "sha256:abc");
        f.set("container", "running");
        f.set("foreign", "");
        let p = f
            .sidecar
            .ensure(Ensure::Converge { build: false })
            .await
            .unwrap_err();
        assert!(p.reason.contains("did not create it"), "{}", p.reason);
        assert!(!f.ran("rm") && !f.ran("run"));
    }

    #[test]
    fn missing_runtime_is_a_clear_problem() {
        let cfg = PresidioCfg {
            runtime: "/nonexistent/docker".into(),
            ..PresidioCfg::default()
        };
        let p = Sidecar::from_config(&cfg).err().unwrap();
        assert!(p.reason.contains("was not found"), "{}", p.reason);
    }

    #[test]
    fn image_files_are_complete() {
        let names: Vec<&str> = IMAGE_FILES.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            [
                "Dockerfile",
                "analyzer.yaml",
                "server.py",
                "requirements.txt"
            ]
        );
        let dockerfile = IMAGE_FILES[0].1;
        for (name, _) in &IMAGE_FILES[1..] {
            assert!(dockerfile.contains(name), "Dockerfile copies {name}");
        }
    }
}
