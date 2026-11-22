//! Der Witness: ein bezeugtes Protokoll aller Anfragen.
//!
//! Jede Anfrage wird als Eintrag an eine JSONL-Datei angehängt. Jeder
//! Eintrag enthält den Hash seines Vorgängers (Hash-Kette) und ist mit
//! Ed25519 signiert. `hedge verify` prüft die Kette offline: Ein geänderter,
//! gelöschter oder eingeschobener Eintrag fällt auf.
//!
//! Was NICHT im Protokoll steht: Prompt-Text, Antworten, Auth-Header. Nur
//! Hashes der Bodies, Fundarten mit Pfad, Entscheidung, Tokens und – wenn
//! eingeschaltet – eine kurze, maskierte Vorschau jedes Tool-Aufrufs.
//! Das Protokoll darf deshalb zentral gesammelt werden, ohne selbst zum
//! Datenleck zu werden.
//!
//! Formatstabilität: Neue Felder werden nur serialisiert, wenn sie gesetzt
//! sind. Einträge aus älteren Versionen behalten so ihren Hash.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::inspect::Located;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingRecord {
    pub kind: String,
    pub severity: String,
    pub path: String,
    /// Maskierter Hinweis auf den Wert (`p…@example.com`, `…a1b2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Derselbe Fund kam in dieser Session schon vor – Agents schicken die
    /// ganze Unterhaltung mit jeder Anfrage erneut.
    #[serde(default, skip_serializing_if = "is_false")]
    pub repeat: bool,
    /// Nur gemeldet: Der Fund hat an der Anfrage nichts geändert, auch wenn
    /// der Modus maskiert oder blockiert (Presidio ohne `enforce`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub advisory: bool,
}

impl FindingRecord {
    pub fn new(kind: &str, severity: &str, path: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            severity: severity.to_owned(),
            path: path.to_owned(),
            hint: None,
            repeat: false,
            advisory: false,
        }
    }
}

impl From<&Located> for FindingRecord {
    fn from(l: &Located) -> Self {
        Self {
            kind: l.finding.kind.to_owned(),
            severity: l.finding.severity.as_str().to_owned(),
            path: l.path.clone(),
            hint: l.hint.clone(),
            repeat: false,
            advisory: l.advisory,
        }
    }
}

/// Ein Tool-Aufruf, den das Modell angefordert hat.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolRecord {
    pub id: String,
    pub name: String,
    /// SHA-256 der Eingabe (kompaktes JSON).
    pub input_sha256: String,
    /// Kurze, maskierte Vorschau (erster String-Wert der Eingabe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// Regel, die gegriffen hat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// allow | flag | deny | held | approved | rejected | timeout
    pub decision: String,
    /// ID der Freigabe-Anfrage, falls der Aufruf eine gebraucht hat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Ein Eintrag der Kette. Feldreihenfolge ist Teil des Formats: Hash und
/// Signatur werden über die kanonische JSON-Form mit leerem `hash`/`sig`
/// gebildet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    /// RFC 3339, UTC, Millisekunden.
    pub ts: String,
    pub upstream: String,
    pub method: String,
    /// Pfad der Anfrage beim Upstream, z. B. `/v1/messages`.
    pub path: String,
    pub model: Option<String>,
    pub mode: String,
    /// forward | redact | block
    pub action: String,
    pub findings: Vec<FindingRecord>,
    /// SHA-256 des Request-Bodys, wie er vom Agent kam.
    pub body_sha256_in: String,
    /// SHA-256 des Bodys, wie er weitergeleitet wurde – nur bei Maskierung.
    pub body_sha256_out: Option<String>,
    /// HTTP-Status der Upstream-Antwort; None, wenn blockiert.
    pub status: Option<u16>,
    pub duration_ms: u64,
    /// Agent-Session (Kurzform), falls der Agent eine mitschickt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Client im Central-Mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Input-Tokens ohne Cache-Reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_out: Option<u64>,
    /// Aus dem Prompt-Cache gelesene Tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_cached: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    /// Tool-Aufrufe aus der Antwort, mit Entscheidung.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolRecord>,
    /// Funde in der Modell-Antwort (nur beobachtet).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_findings: Vec<FindingRecord>,
    /// Auffälligkeiten, z. B. `unwitnessed_tool_result`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// Antwort wurde gestreamt.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stream: bool,
    /// Strom endete vorzeitig (Client weg oder Upstream-Fehler).
    #[serde(default, skip_serializing_if = "is_false")]
    pub aborted: bool,
    /// Ereignis statt Anfrage, z. B. `config_reload`, `start`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// Begründung oder Detail (Block-Grund, Config-Hash, Fehler).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Erste 16 Hex-Zeichen des öffentlichen Schlüssels.
    pub key_id: String,
    /// Hash des Vorgängers (GENESIS beim ersten Eintrag).
    pub prev: String,
    pub hash: String,
    pub sig: String,
}

impl Entry {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut stripped = self.clone();
        stripped.hash = String::new();
        stripped.sig = String::new();
        serde_json::to_vec(&stripped).expect("Entry serializes")
    }

    fn compute_hash(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }

    pub fn finding_summary(&self) -> String {
        if self.findings.is_empty() {
            return "-".into();
        }
        self.findings
            .iter()
            .map(|f| format!("{}@{}", f.kind, f.path))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Die Fakten zu einem Eintrag. Kette und Signatur ergänzt der Witness.
#[derive(Debug, Clone, Default)]
pub struct Record {
    pub upstream: String,
    pub method: String,
    pub path: String,
    pub model: Option<String>,
    pub mode: String,
    pub action: String,
    pub findings: Vec<FindingRecord>,
    pub body_sha256_in: String,
    /// Nur gesetzt, wenn sich der Body durch Maskierung geändert hat.
    pub body_sha256_out: Option<String>,
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub session: Option<String>,
    pub client: Option<String>,
    pub tokens_in: Option<u64>,
    pub tokens_out: Option<u64>,
    pub tokens_cached: Option<u64>,
    pub stop_reason: Option<String>,
    pub tools: Vec<ToolRecord>,
    pub response_findings: Vec<FindingRecord>,
    pub flags: Vec<String>,
    pub stream: bool,
    pub aborted: bool,
    pub event: Option<String>,
    pub detail: Option<String>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Ein Punkt der Kette, der außerhalb aufbewahrt werden kann. Wer einen
/// Anker hat, erkennt auch das Abschneiden oder Neuschreiben des Endes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u64,
    pub hash: String,
}

impl Anchor {
    /// Liest `seq:hash`.
    pub fn parse(text: &str) -> Option<Anchor> {
        let (seq, hash) = text.trim().split_once(':')?;
        let seq = seq.parse().ok()?;
        (hash.len() == 64 && hex::decode(hash).is_ok()).then(|| Anchor {
            seq,
            hash: hash.to_owned(),
        })
    }
}

impl std::fmt::Display for Anchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.seq, self.hash)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("witness io error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("witness key at {path} is invalid: {reason}")]
    Key { path: PathBuf, reason: String },
    #[error("witness file {path} line {line}: {reason}")]
    Corrupt {
        path: PathBuf,
        line: usize,
        reason: String,
    },
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> WitnessError + '_ {
    move |source| WitnessError::Io {
        path: path.to_path_buf(),
        source,
    }
}

struct Inner {
    file: File,
    prev: String,
    next_seq: u64,
}

pub struct Witness {
    path: PathBuf,
    signing: SigningKey,
    key_id: String,
    inner: Mutex<Inner>,
}

impl Witness {
    /// Öffnet (oder erzeugt) die Kette und setzt sie fort, falls sie existiert.
    pub fn open(path: &Path, key_path: &Path) -> Result<Self, WitnessError> {
        let signing = load_signing_key(key_path)?;
        let key_id = key_id_of(&signing.verifying_key());

        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(io_err(path))?;
        }

        let (prev, next_seq) = match read_entries(path) {
            Ok(entries) => match entries.last() {
                Some(last) => (last.hash.clone(), last.seq + 1),
                None => (GENESIS.to_owned(), 1),
            },
            Err(WitnessError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                (GENESIS.to_owned(), 1)
            }
            Err(e) => return Err(e),
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(io_err(path))?;

        Ok(Self {
            path: path.to_path_buf(),
            signing,
            key_id,
            inner: Mutex::new(Inner {
                file,
                prev,
                next_seq,
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Der letzte Eintrag als Anker, falls es schon einen gibt.
    pub fn head(&self) -> Option<Anchor> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (inner.next_seq > 1).then(|| Anchor {
            seq: inner.next_seq - 1,
            hash: inner.prev.clone(),
        })
    }

    /// Hängt einen Eintrag an. Hash-Kette und Signatur werden hier gebildet;
    /// der Aufrufer liefert nur Fakten.
    pub fn record(&self, r: Record) -> Result<Entry, WitnessError> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let mut entry = Entry {
            seq: inner.next_seq,
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            upstream: r.upstream,
            method: r.method,
            path: r.path,
            model: r.model,
            mode: r.mode,
            action: r.action,
            findings: r.findings,
            body_sha256_in: r.body_sha256_in,
            body_sha256_out: r.body_sha256_out,
            status: r.status,
            duration_ms: r.duration_ms,
            session: r.session,
            client: r.client,
            tokens_in: r.tokens_in,
            tokens_out: r.tokens_out,
            tokens_cached: r.tokens_cached,
            stop_reason: r.stop_reason,
            tools: r.tools,
            response_findings: r.response_findings,
            flags: r.flags,
            stream: r.stream,
            aborted: r.aborted,
            event: r.event,
            detail: r.detail,
            key_id: self.key_id.clone(),
            prev: inner.prev.clone(),
            hash: String::new(),
            sig: String::new(),
        };
        entry.hash = entry.compute_hash();
        entry.sig = hex::encode(self.signing.sign(entry.hash.as_bytes()).to_bytes());

        let mut line = serde_json::to_vec(&entry).expect("Entry serializes");
        line.push(b'\n');
        inner.file.write_all(&line).map_err(io_err(&self.path))?;
        inner.file.flush().map_err(io_err(&self.path))?;

        inner.prev = entry.hash.clone();
        inner.next_seq += 1;
        Ok(entry)
    }
}

/// Liest alle Einträge, ohne sie zu verifizieren.
pub fn read_entries(path: &Path) -> Result<Vec<Entry>, WitnessError> {
    let file = File::open(path).map_err(io_err(path))?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line.map_err(io_err(path))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: Entry = serde_json::from_str(&line).map_err(|e| WitnessError::Corrupt {
            path: path.to_path_buf(),
            line: i + 1,
            reason: e.to_string(),
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Liest die Einträge ab einem Byte-Offset (für `tail -f`). Liefert die
/// neuen Einträge und den Offset hinter der letzten vollständigen Zeile.
pub fn read_entries_from(path: &Path, offset: u64) -> Result<(Vec<Entry>, u64), WitnessError> {
    let mut file = File::open(path).map_err(io_err(path))?;
    let len = file.metadata().map_err(io_err(path))?.len();
    // Datei wurde ersetzt oder gekürzt: von vorn beginnen.
    let offset = if offset > len { 0 } else { offset };
    file.seek(SeekFrom::Start(offset)).map_err(io_err(path))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(io_err(path))?;

    let complete = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let mut entries = Vec::new();
    for line in buf[..complete].split(|b| *b == b'\n') {
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        if let Ok(entry) = serde_json::from_slice::<Entry>(line) {
            entries.push(entry);
        }
    }
    Ok((entries, offset + complete as u64))
}

/// Ergebnis einer Verifikation.
#[derive(Debug)]
pub struct VerifyReport {
    pub entries: usize,
    pub first_ts: Option<String>,
    pub last_ts: Option<String>,
    pub key_id: Option<String>,
    /// Gesetzt, wenn die geprüften Einträge nicht bei 1 beginnen (Auszug).
    pub partial_from: Option<u64>,
    /// Letzter Eintrag der geprüften Kette.
    pub head: Option<Anchor>,
    /// Leer = Kette intakt.
    pub problems: Vec<Problem>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Problem {
    pub seq: u64,
    pub reason: String,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Prüft Hash-Kette, Sequenz und Signaturen gegen den öffentlichen Schlüssel.
pub fn verify(entries: &[Entry], verifying: &VerifyingKey) -> VerifyReport {
    let mut problems = Vec::new();
    let mut expected_seq = entries.first().map(|e| e.seq).unwrap_or(1);
    // Ein Auszug beginnt mitten in der Kette: Sein erster `prev` zeigt auf
    // einen Eintrag, der nicht vorliegt, und kann nicht geprüft werden.
    let partial_from = (expected_seq != 1).then_some(expected_seq);
    let mut prev_hash = match (partial_from, entries.first()) {
        (Some(_), Some(first)) => first.prev.clone(),
        _ => GENESIS.to_owned(),
    };
    let key_id = key_id_of(verifying);

    for entry in entries {
        if entry.seq != expected_seq {
            problems.push(Problem {
                seq: entry.seq,
                reason: format!("sequence gap: expected {expected_seq}, found {}", entry.seq),
            });
        }
        if entry.prev != prev_hash {
            problems.push(Problem {
                seq: entry.seq,
                reason: "chain broken: prev does not match previous entry's hash".into(),
            });
        }
        if entry.compute_hash() != entry.hash {
            problems.push(Problem {
                seq: entry.seq,
                reason: "content modified: hash does not match entry".into(),
            });
        }
        if entry.key_id != key_id {
            problems.push(Problem {
                seq: entry.seq,
                reason: format!("signed by other key {} (expected {key_id})", entry.key_id),
            });
        }
        match hex::decode(&entry.sig)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        {
            Some(bytes) => {
                let sig = Signature::from_bytes(&bytes);
                if verifying
                    .verify_strict(entry.hash.as_bytes(), &sig)
                    .is_err()
                {
                    problems.push(Problem {
                        seq: entry.seq,
                        reason: "signature invalid".into(),
                    });
                }
            }
            None => problems.push(Problem {
                seq: entry.seq,
                reason: "signature malformed".into(),
            }),
        }
        prev_hash = entry.hash.clone();
        expected_seq = entry.seq + 1;
    }

    VerifyReport {
        entries: entries.len(),
        first_ts: entries.first().map(|e| e.ts.clone()),
        last_ts: entries.last().map(|e| e.ts.clone()),
        key_id: Some(key_id),
        partial_from,
        head: entries.last().map(|e| Anchor {
            seq: e.seq,
            hash: e.hash.clone(),
        }),
        problems,
    }
}

/// Prüft, ob die Kette den Anker enthält. Fehlt er, wurde das Ende
/// abgeschnitten oder die Kette ab dort neu geschrieben.
pub fn check_anchor(entries: &[Entry], anchor: &Anchor) -> Result<(), Problem> {
    match entries.iter().find(|e| e.seq == anchor.seq) {
        Some(e) if e.hash == anchor.hash => Ok(()),
        Some(_) => Err(Problem {
            seq: anchor.seq,
            reason: "anchor mismatch: entry has a different hash (chain was rewritten)".into(),
        }),
        None => Err(Problem {
            seq: anchor.seq,
            reason: "anchor missing: entry is not in the chain (chain was truncated)".into(),
        }),
    }
}

/// Ein Auszug der Kette zum Weitergeben: Einträge plus öffentlicher
/// Schlüssel. Prüfbar mit `hedge verify --bundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub exported_at: String,
    pub public_key: String,
    pub key_id: String,
    /// Kopf der gesamten Kette zum Zeitpunkt des Exports.
    pub head: Option<Anchor>,
    pub entries: Vec<Entry>,
}

pub const BUNDLE_FORMAT: &str = "hedge-bundle/1";

impl Bundle {
    pub fn new(entries: Vec<Entry>, verifying: &VerifyingKey, head: Option<Anchor>) -> Self {
        Self {
            format: BUNDLE_FORMAT.into(),
            exported_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            public_key: hex::encode(verifying.to_bytes()),
            key_id: key_id_of(verifying),
            head,
            entries,
        }
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, String> {
        let bytes =
            hex::decode(&self.public_key).map_err(|e| format!("public_key not hex: {e}"))?;
        let bytes = <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| "public_key must be 32 bytes".to_owned())?;
        VerifyingKey::from_bytes(&bytes).map_err(|e| e.to_string())
    }
}

/// Der zusammenhängende Abschnitt der Kette, der alle Einträge einer
/// Session enthält (inklusive fremder Einträge dazwischen, damit die
/// Verkettung prüfbar bleibt).
pub fn session_range<'a>(entries: &'a [Entry], session: &str) -> &'a [Entry] {
    let is = |e: &Entry| e.session.as_deref().is_some_and(|s| s.starts_with(session));
    match (entries.iter().position(is), entries.iter().rposition(is)) {
        (Some(a), Some(b)) => &entries[a..=b],
        _ => &[],
    }
}

// ---- Schlüssel ----

pub fn key_id_of(verifying: &VerifyingKey) -> String {
    hex::encode(verifying.to_bytes())[..16].to_owned()
}

/// Erzeugt ein neues Schlüsselpaar und schreibt `<key>` (secret, 0600) und
/// `<key>.pub` daneben. Überschreibt nichts.
pub fn generate_keypair(key_path: &Path) -> Result<VerifyingKey, WitnessError> {
    if key_path.exists() {
        return Err(WitnessError::Key {
            path: key_path.to_path_buf(),
            reason: "already exists (refusing to overwrite a signing key)".into(),
        });
    }
    if let Some(dir) = key_path.parent() {
        fs::create_dir_all(dir).map_err(io_err(key_path))?;
    }
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| WitnessError::Key {
        path: key_path.to_path_buf(),
        reason: format!("no randomness available: {e}"),
    })?;
    let signing = SigningKey::from_bytes(&secret);

    write_private(key_path, hex::encode(secret).as_bytes())?;
    fs::write(
        pub_path(key_path),
        hex::encode(signing.verifying_key().to_bytes()),
    )
    .map_err(io_err(key_path))?;
    Ok(signing.verifying_key())
}

/// Schreibt eine geheime Datei (0600), ohne eine vorhandene zu überschreiben.
#[cfg(unix)]
pub fn write_private(path: &Path, content: &[u8]) -> Result<(), WitnessError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err(path))?;
    f.write_all(content).map_err(io_err(path))
}

#[cfg(not(unix))]
pub fn write_private(path: &Path, content: &[u8]) -> Result<(), WitnessError> {
    fs::write(path, content).map_err(io_err(path))
}

pub fn pub_path(key_path: &Path) -> PathBuf {
    let mut p = key_path.as_os_str().to_owned();
    p.push(".pub");
    PathBuf::from(p)
}

pub fn load_signing_key(path: &Path) -> Result<SigningKey, WitnessError> {
    let text = fs::read_to_string(path).map_err(io_err(path))?;
    let bytes = decode_key(path, text.trim())?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Lädt den öffentlichen Schlüssel: aus `<key>.pub`, oder abgeleitet aus
/// dem geheimen Schlüssel, falls nur der vorliegt.
pub fn load_verifying_key(key_path: &Path) -> Result<VerifyingKey, WitnessError> {
    let pubp = pub_path(key_path);
    if pubp.exists() {
        let text = fs::read_to_string(&pubp).map_err(io_err(&pubp))?;
        let bytes = decode_key(&pubp, text.trim())?;
        return VerifyingKey::from_bytes(&bytes).map_err(|e| WitnessError::Key {
            path: pubp,
            reason: e.to_string(),
        });
    }
    if key_path.extension().is_some_and(|e| e == "pub") {
        let text = fs::read_to_string(key_path).map_err(io_err(key_path))?;
        let bytes = decode_key(key_path, text.trim())?;
        return VerifyingKey::from_bytes(&bytes).map_err(|e| WitnessError::Key {
            path: key_path.to_path_buf(),
            reason: e.to_string(),
        });
    }
    Ok(load_signing_key(key_path)?.verifying_key())
}

fn decode_key(path: &Path, hex_text: &str) -> Result<[u8; 32], WitnessError> {
    let bytes = hex::decode(hex_text).map_err(|e| WitnessError::Key {
        path: path.to_path_buf(),
        reason: format!("not hex: {e}"),
    })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| WitnessError::Key {
        path: path.to_path_buf(),
        reason: format!("expected 32 bytes, found {}", bytes.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Finding, Severity};
    use crate::inspect::Located;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hedge-witness-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn draft(upstream: &str, findings: &[Located]) -> Record {
        Record {
            upstream: upstream.into(),
            method: "POST".into(),
            path: "/v1/messages".into(),
            model: Some("claude-x".into()),
            mode: "redact".into(),
            action: "redact".into(),
            findings: findings.iter().map(FindingRecord::from).collect(),
            body_sha256_in: sha256_hex(b"{\"a\":1}"),
            body_sha256_out: Some(sha256_hex(b"{\"a\":2}")),
            status: Some(200),
            duration_ms: 42,
            ..Record::default()
        }
    }

    fn located() -> Vec<Located> {
        vec![Located {
            path: "messages[0].content".into(),
            finding: Finding {
                detector: "secrets",
                kind: "anthropic_api_key",
                severity: Severity::High,
                start: 0,
                end: 1,
            },
            hint: Some("…wxyz".into()),
            fingerprint: 7,
            advisory: false,
        }]
    }

    #[test]
    fn keypair_is_generated_once_and_loadable() {
        let dir = temp_dir("keys");
        let key = dir.join("witness.key");

        let vk = generate_keypair(&key).unwrap();

        assert!(key.exists());
        assert!(pub_path(&key).exists());
        assert_eq!(load_verifying_key(&key).unwrap(), vk);
        assert_eq!(load_signing_key(&key).unwrap().verifying_key(), vk);
        assert!(generate_keypair(&key).is_err(), "must not overwrite");
    }

    #[test]
    fn chain_is_written_resumed_and_verifies() {
        let dir = temp_dir("chain");
        let key = dir.join("witness.key");
        let log = dir.join("witness.jsonl");
        let vk = generate_keypair(&key).unwrap();
        let findings = located();

        {
            let w = Witness::open(&log, &key).unwrap();
            let e1 = w.record(draft("anthropic", &findings)).unwrap();
            let e2 = w.record(draft("openai", &[])).unwrap();
            assert_eq!(e1.seq, 1);
            assert_eq!(e1.prev, GENESIS);
            assert_eq!(e2.seq, 2);
            assert_eq!(e2.prev, e1.hash);
            assert_eq!(e1.findings[0].kind, "anthropic_api_key");
            assert_eq!(e1.findings[0].path, "messages[0].content");
        }

        // Neu öffnen: Kette wird fortgesetzt, nicht neu begonnen.
        let w = Witness::open(&log, &key).unwrap();
        let e3 = w.record(draft("anthropic", &[])).unwrap();
        assert_eq!(e3.seq, 3);

        let entries = read_entries(&log).unwrap();
        assert_eq!(entries.len(), 3);
        let report = verify(&entries, &vk);
        assert!(report.is_ok(), "{:?}", report.problems);
        assert_eq!(report.entries, 3);
    }

    #[test]
    fn tampering_is_detected() {
        let dir = temp_dir("tamper");
        let key = dir.join("witness.key");
        let log = dir.join("witness.jsonl");
        let vk = generate_keypair(&key).unwrap();
        {
            let w = Witness::open(&log, &key).unwrap();
            for _ in 0..3 {
                w.record(draft("anthropic", &[])).unwrap();
            }
        }
        let mut entries = read_entries(&log).unwrap();

        // 1. Inhalt ändern
        let mut modified = entries.clone();
        modified[1].action = "forward".into();
        let r = verify(&modified, &vk);
        assert!(
            r.problems
                .iter()
                .any(|p| p.seq == 2 && p.reason.contains("content modified"))
        );

        // 2. Eintrag löschen
        let mut deleted = entries.clone();
        deleted.remove(1);
        let r = verify(&deleted, &vk);
        assert!(
            r.problems
                .iter()
                .any(|p| p.seq == 3 && p.reason.contains("chain broken"))
        );
        assert!(
            r.problems
                .iter()
                .any(|p| p.seq == 3 && p.reason.contains("sequence gap"))
        );

        // 3. Mit fremdem Schlüssel neu signieren
        let other_key = dir.join("other.key");
        let other_vk = generate_keypair(&other_key).unwrap();
        let other = load_signing_key(&other_key).unwrap();
        entries[2].sig = hex::encode(other.sign(entries[2].hash.as_bytes()).to_bytes());
        let r = verify(&entries, &vk);
        assert!(
            r.problems
                .iter()
                .any(|p| p.seq == 3 && p.reason.contains("signature invalid"))
        );
        let _ = other_vk;
    }

    #[test]
    fn entries_never_contain_body_text() {
        let dir = temp_dir("privacy");
        let key = dir.join("witness.key");
        let log = dir.join("witness.jsonl");
        generate_keypair(&key).unwrap();
        let w = Witness::open(&log, &key).unwrap();
        let secret_body = b"{\"content\":\"sk-ant-supersecret\"}";
        let mut d = draft("anthropic", &[]);
        d.body_sha256_in = sha256_hex(secret_body);
        d.body_sha256_out = None;
        w.record(d).unwrap();

        let raw = fs::read_to_string(&log).unwrap();
        assert!(!raw.contains("supersecret"));
        assert!(raw.contains(&hex::encode(Sha256::digest(secret_body))));
    }

    /// Ein Eintrag im Format von v0.1 (ohne die neuen Felder) muss mit der
    /// aktuellen Version denselben Hash ergeben, sonst bräche jedes Update
    /// die bestehende Kette.
    #[test]
    fn entries_without_new_fields_keep_their_hash() {
        let dir = temp_dir("compat");
        let key = dir.join("witness.key");
        let log = dir.join("witness.jsonl");
        let vk = generate_keypair(&key).unwrap();
        let w = Witness::open(&log, &key).unwrap();
        let e = w.record(draft("anthropic", &[])).unwrap();

        let line = fs::read_to_string(&log).unwrap();
        for field in [
            "session",
            "tokens_in",
            "tools",
            "flags",
            "stream",
            "event",
            "detail",
        ] {
            assert!(
                !line.contains(&format!("\"{field}\"")),
                "{field} must be omitted when unset"
            );
        }
        let v01_keys = [
            "seq",
            "ts",
            "upstream",
            "method",
            "path",
            "model",
            "mode",
            "action",
            "findings",
            "body_sha256_in",
            "body_sha256_out",
            "status",
            "duration_ms",
            "key_id",
            "prev",
            "hash",
            "sig",
        ];
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        let keys: Vec<&str> = parsed
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys, v01_keys,
            "field set and order of a plain entry are part of the format"
        );

        let reread = read_entries(&log).unwrap();
        assert_eq!(reread[0], e);
        assert!(verify(&reread, &vk).is_ok());
    }

    #[test]
    fn new_fields_are_covered_by_the_hash() {
        let dir = temp_dir("v2");
        let key = dir.join("witness.key");
        let log = dir.join("witness.jsonl");
        let vk = generate_keypair(&key).unwrap();
        let w = Witness::open(&log, &key).unwrap();
        let mut r = draft("anthropic", &[]);
        r.session = Some("abcd1234".into());
        r.tokens_in = Some(10);
        r.tokens_out = Some(5);
        r.stream = true;
        r.tools = vec![ToolRecord {
            id: "toolu_1".into(),
            name: "Bash".into(),
            input_sha256: sha256_hex(b"{}"),
            preview: Some("git status".into()),
            rule: Some("HEDGE-SHELL-003".into()),
            decision: "deny".into(),
            approval: None,
        }];
        w.record(r).unwrap();

        let mut entries = read_entries(&log).unwrap();
        assert!(verify(&entries, &vk).is_ok());
        entries[0].tools[0].decision = "allow".into();
        assert!(
            !verify(&entries, &vk).is_ok(),
            "tool decisions are tamper-evident"
        );
    }

    #[test]
    fn partial_chains_verify_and_anchors_detect_truncation() {
        let dir = temp_dir("anchor");
        let key = dir.join("witness.key");
        let log = dir.join("witness.jsonl");
        let vk = generate_keypair(&key).unwrap();
        let w = Witness::open(&log, &key).unwrap();
        assert!(w.head().is_none());
        for i in 0..5 {
            let mut r = draft("anthropic", &[]);
            r.session = Some(if i == 1 || i == 3 { "sess-a" } else { "sess-b" }.into());
            w.record(r).unwrap();
        }
        let entries = read_entries(&log).unwrap();
        let head = w.head().unwrap();
        assert_eq!(head.seq, 5);
        assert_eq!(Anchor::parse(&head.to_string()), Some(head.clone()));
        assert!(Anchor::parse("5:zz").is_none());

        // Auszug einer Session: zusammenhängender Abschnitt, prüfbar.
        let range = session_range(&entries, "sess-a");
        assert_eq!(
            range.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
        let report = verify(range, &vk);
        assert!(report.is_ok(), "{:?}", report.problems);
        assert_eq!(report.partial_from, Some(2));
        assert!(session_range(&entries, "nope").is_empty());

        // Abschneiden des Endes besteht `verify`, aber nicht den Anker.
        let truncated = &entries[..3];
        assert!(verify(truncated, &vk).is_ok());
        assert!(
            check_anchor(truncated, &head)
                .unwrap_err()
                .reason
                .contains("truncated")
        );
        assert!(check_anchor(&entries, &head).is_ok());
        let wrong = Anchor {
            seq: 2,
            hash: head.hash.clone(),
        };
        assert!(
            check_anchor(&entries, &wrong)
                .unwrap_err()
                .reason
                .contains("rewritten")
        );

        // Bundle: Schlüssel reist mit.
        let bundle = Bundle::new(range.to_vec(), &vk, Some(head));
        let json = serde_json::to_string(&bundle).unwrap();
        let back: Bundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.format, BUNDLE_FORMAT);
        assert!(verify(&back.entries, &back.verifying_key().unwrap()).is_ok());
    }

    #[test]
    fn incremental_read_follows_appends() {
        let dir = temp_dir("follow");
        let key = dir.join("witness.key");
        let log = dir.join("witness.jsonl");
        generate_keypair(&key).unwrap();
        let w = Witness::open(&log, &key).unwrap();
        w.record(draft("a", &[])).unwrap();
        let (first, off) = read_entries_from(&log, 0).unwrap();
        assert_eq!(first.len(), 1);
        let (none, off2) = read_entries_from(&log, off).unwrap();
        assert!(none.is_empty());
        assert_eq!(off, off2);
        w.record(draft("b", &[])).unwrap();
        w.record(draft("c", &[])).unwrap();
        let (more, _) = read_entries_from(&log, off).unwrap();
        assert_eq!(
            more.iter().map(|e| e.upstream.as_str()).collect::<Vec<_>>(),
            vec!["b", "c"]
        );
    }
}
