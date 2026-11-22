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
    /// Länge des aktiven Segments bis zum letzten vollständigen Eintrag.
    len: u64,
    /// Sequenznummer des ersten Eintrags im aktiven Segment (0 = leer).
    first_seq: u64,
    /// Byte-Offset jedes Eintrags im aktiven Segment.
    offsets: Vec<u64>,
    /// Ein Schreibversuch ist gescheitert und der Rückbau auch: Vor dem
    /// nächsten Eintrag muss die Datei auf `len` gekürzt werden.
    dirty: bool,
}

pub struct Witness {
    path: PathBuf,
    signing: SigningKey,
    key_id: String,
    inner: Mutex<Inner>,
}

/// Was beim Öffnen einer Kette herauskommt.
pub struct Opened {
    pub witness: Witness,
    /// Die Einträge des aktiven Segments (für Budgets und den Tool-Abgleich).
    pub entries: Vec<Entry>,
    /// Gesetzt, wenn eine unvollständige letzte Zeile entfernt wurde.
    pub recovered: Option<Recovered>,
}

/// Eine unvollständige letzte Zeile, die beim Öffnen entfernt wurde – der
/// Rest eines Schreibvorgangs, den ein Absturz oder eine volle Platte
/// unterbrochen hat. Die Bytes sind nicht verloren, sie liegen in `saved_to`.
#[derive(Debug, Clone)]
pub struct Recovered {
    pub bytes: u64,
    pub sha256: String,
    pub saved_to: PathBuf,
}

/// Ein abgelegtes Segment der Kette: `<name>.<erste>-<letzte>.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Segment {
    pub path: PathBuf,
    pub first: u64,
    pub last: u64,
    pub bytes: u64,
}

/// Ein Stück der Kette für Leser aus der Ferne.
#[derive(Debug)]
pub struct Chunk {
    /// Vollständige JSONL-Zeilen.
    pub bytes: Vec<u8>,
    /// Sequenznummer des letzten gelieferten Eintrags; ohne Einträge der
    /// Stand, von dem der Leser weiterfragen soll.
    pub last: u64,
    /// Aktueller Kopf der Kette.
    pub head: u64,
}

/// Größe und Lage des aktiven Segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Active {
    pub bytes: u64,
    pub entries: u64,
    /// Sequenznummer des ersten Eintrags (0 = leer).
    pub first: u64,
}

/// Ergebnis des Lesens der aktiven Datei.
struct Scan {
    entries: Vec<Entry>,
    offsets: Vec<u64>,
    /// Bis hierhin ist die Datei in Ordnung.
    good_len: u64,
    /// Start und Inhalt einer unvollständigen letzten Zeile.
    torn: Option<(u64, Vec<u8>)>,
    /// Der letzte Eintrag ist vollständig, aber ohne Zeilenende.
    unterminated: bool,
}

/// Liest die aktive Datei Zeile für Zeile. Eine unlesbare Zeile mitten in
/// der Datei ist ein Fehler; ist es die letzte, gilt sie als abgerissen.
fn scan(path: &Path, bytes: &[u8]) -> Result<Scan, WitnessError> {
    let mut out = Scan {
        entries: Vec::new(),
        offsets: Vec::new(),
        good_len: 0,
        torn: None,
        unterminated: false,
    };
    let blank = |b: &[u8]| b.iter().all(u8::is_ascii_whitespace);
    let mut pos = 0;
    let mut line_no = 0;
    while pos < bytes.len() {
        line_no += 1;
        let (end, terminated) = match bytes[pos..].iter().position(|b| *b == b'\n') {
            Some(i) => (pos + i, true),
            None => (bytes.len(), false),
        };
        let line = &bytes[pos..end];
        let next = if terminated { end + 1 } else { end };
        if blank(line) {
            pos = next;
            if terminated {
                out.good_len = next as u64;
            }
            continue;
        }
        match serde_json::from_slice::<Entry>(line) {
            Ok(entry) => {
                out.entries.push(entry);
                out.offsets.push(pos as u64);
                out.good_len = next as u64;
                out.unterminated = !terminated;
            }
            Err(_) if blank(&bytes[next..]) => {
                out.torn = Some((pos as u64, bytes[pos..].to_vec()));
                out.good_len = pos as u64;
                break;
            }
            Err(e) => {
                return Err(WitnessError::Corrupt {
                    path: path.to_path_buf(),
                    line: line_no,
                    reason: e.to_string(),
                });
            }
        }
        pos = next;
    }
    Ok(out)
}

/// Sequenznummer einer Zeile, ohne sie ganz zu parsen. `seq` ist das erste
/// Feld jedes Eintrags.
fn seq_of_line(line: &[u8]) -> Option<u64> {
    let rest = line.strip_prefix(b"{\"seq\":")?;
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()
}

/// Pfad eines abgelegten Segments neben der aktiven Datei.
pub fn segment_path(active: &Path, first: u64, last: u64) -> PathBuf {
    let stem = active
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("witness");
    let name = match active.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{stem}.{first:010}-{last:010}.{ext}"),
        None => format!("{stem}.{first:010}-{last:010}"),
    };
    active.with_file_name(name)
}

/// Die abgelegten Segmente neben der aktiven Datei, älteste zuerst.
pub fn segments(active: &Path) -> Vec<Segment> {
    let (Some(dir), Some(stem)) = (active.parent(), active.file_stem().and_then(|s| s.to_str()))
    else {
        return Vec::new();
    };
    let ext = active.extension().and_then(|e| e.to_str());
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<Segment> = read
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_str()?;
            let rest = name.strip_prefix(stem)?.strip_prefix('.')?;
            let range = match ext {
                Some(ext) => rest.strip_suffix(ext)?.strip_suffix('.')?,
                None => rest,
            };
            let (first, last) = range.split_once('-')?;
            let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
            if !digits(first) || !digits(last) {
                return None;
            }
            Some(Segment {
                path: e.path(),
                first: first.parse().ok()?,
                last: last.parse().ok()?,
                bytes: e.metadata().map(|m| m.len()).unwrap_or(0),
            })
        })
        .collect();
    found.sort_by_key(|s| s.first);
    found
}

/// Der letzte Eintrag einer Datei, ohne sie ganz zu lesen.
fn last_entry(path: &Path) -> Result<Option<Entry>, WitnessError> {
    const WINDOW: u64 = 1024 * 1024;
    let mut file = File::open(path).map_err(io_err(path))?;
    let len = file.metadata().map_err(io_err(path))?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(WINDOW)))
        .map_err(io_err(path))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(io_err(path))?;
    let from_tail = buf
        .split(|b| *b == b'\n')
        .rev()
        .find(|l| !l.iter().all(u8::is_ascii_whitespace))
        .and_then(|l| serde_json::from_slice::<Entry>(l).ok());
    match from_tail {
        Some(e) => Ok(Some(e)),
        // Eine Zeile, die nicht ins Fenster passt: die ganze Datei lesen.
        None => Ok(read_entries(path)?.pop()),
    }
}

impl Witness {
    /// Öffnet (oder erzeugt) die Kette und setzt sie fort, falls sie existiert.
    pub fn open(path: &Path, key_path: &Path) -> Result<Self, WitnessError> {
        Self::open_full(path, key_path).map(|o| o.witness)
    }

    /// Wie [`Witness::open`], liefert aber auch die gelesenen Einträge und
    /// sagt, ob eine abgerissene letzte Zeile entfernt wurde.
    pub fn open_full(path: &Path, key_path: &Path) -> Result<Opened, WitnessError> {
        let signing = load_signing_key(key_path)?;
        let key_id = key_id_of(&signing.verifying_key());

        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(io_err(path))?;
        }

        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(io_err(path)(e)),
        };
        let found = scan(path, &bytes)?;

        // Eine abgerissene letzte Zeile ist kein Eintrag der Kette: Sie wird
        // gesichert und entfernt, sonst hinge der nächste Eintrag an ihr.
        let recovered = match &found.torn {
            Some((_, torn)) => {
                let saved_to = torn_path(path);
                fs::write(&saved_to, torn).map_err(|source| WitnessError::Io {
                    path: saved_to.clone(),
                    source,
                })?;
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .and_then(|f| f.set_len(found.good_len))
                    .map_err(io_err(path))?;
                Some(Recovered {
                    bytes: torn.len() as u64,
                    sha256: sha256_hex(torn),
                    saved_to,
                })
            }
            None => None,
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(io_err(path))?;
        let mut len = found.good_len;
        if found.unterminated {
            file.write_all(b"\n").map_err(io_err(path))?;
            len += 1;
        }

        let (prev, next_seq) = match found.entries.last() {
            Some(last) => (last.hash.clone(), last.seq + 1),
            // Leeres aktives Segment: Die Kette läuft dort weiter, wo das
            // letzte abgelegte Segment endet.
            None => match segments(path).last() {
                Some(seg) => match last_entry(&seg.path)? {
                    Some(last) => (last.hash, last.seq + 1),
                    None => (GENESIS.to_owned(), 1),
                },
                None => (GENESIS.to_owned(), 1),
            },
        };

        let witness = Self {
            path: path.to_path_buf(),
            signing,
            key_id,
            inner: Mutex::new(Inner {
                file,
                prev,
                next_seq,
                len,
                first_seq: found.entries.first().map_or(0, |e| e.seq),
                offsets: found.offsets,
                dirty: false,
            }),
        };
        Ok(Opened {
            witness,
            entries: found.entries,
            recovered,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Öffentlicher Schlüssel (hex), mit dem sich die Kette prüfen lässt.
    pub fn public_key(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// Der letzte Eintrag als Anker, falls es schon einen gibt.
    pub fn head(&self) -> Option<Anchor> {
        let inner = self.lock();
        (inner.next_seq > 1).then(|| Anchor {
            seq: inner.next_seq - 1,
            hash: inner.prev.clone(),
        })
    }

    /// Größe des aktiven Segments.
    pub fn active(&self) -> Active {
        let inner = self.lock();
        Active {
            bytes: inner.len,
            entries: inner.offsets.len() as u64,
            first: inner.first_seq,
        }
    }

    /// Hängt einen Eintrag an. Hash-Kette und Signatur werden hier gebildet;
    /// der Aufrufer liefert nur Fakten.
    pub fn record(&self, r: Record) -> Result<Entry, WitnessError> {
        let mut inner = self.lock();
        self.append(&mut inner, r)
    }

    fn append(&self, inner: &mut Inner, r: Record) -> Result<Entry, WitnessError> {
        if inner.dirty {
            let len = inner.len;
            inner.file.set_len(len).map_err(io_err(&self.path))?;
            inner.dirty = false;
        }

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
        if let Err(e) = inner
            .file
            .write_all(&line)
            .and_then(|()| inner.file.flush())
        {
            // Eine halbe Zeile darf nicht liegen bleiben: Der nächste Eintrag
            // würde an sie angehängt und die Datei wäre ab hier unlesbar.
            let len = inner.len;
            inner.dirty = inner.file.set_len(len).is_err();
            return Err(io_err(&self.path)(e));
        }

        let at = inner.len;
        inner.offsets.push(at);
        inner.len += line.len() as u64;
        if inner.first_seq == 0 {
            inner.first_seq = entry.seq;
        }
        inner.prev = entry.hash.clone();
        inner.next_seq += 1;
        Ok(entry)
    }

    /// Legt das aktive Segment ab und beginnt ein neues. Die Kette läuft
    /// weiter: Der nächste Eintrag trägt die folgende Sequenznummer und den
    /// Hash des letzten abgelegten. `None`, wenn das Segment leer ist.
    pub fn rotate(&self) -> Result<Option<Segment>, WitnessError> {
        let mut inner = self.lock();
        self.rotate_locked(&mut inner)
    }

    /// Wie [`Witness::rotate`], schreibt aber im selben Zug den ersten
    /// Eintrag des neuen Segments – kein anderer Eintrag kommt dazwischen.
    /// So beginnt jedes Segment mit dem Vermerk, welches ihm vorausging.
    ///
    /// Rotiert nur, wenn das aktive Segment mindestens `min_bytes` groß
    /// ist. Die Prüfung liegt unter demselben Lock wie die Rotation: Zwei
    /// Anfragen, die gleichzeitig „voll“ feststellen, rotieren nur einmal.
    pub fn rotate_noting(
        &self,
        min_bytes: u64,
        note: impl FnOnce(&Segment) -> Record,
    ) -> Result<Option<(Segment, Entry)>, WitnessError> {
        let mut inner = self.lock();
        if inner.len < min_bytes {
            return Ok(None);
        }
        let Some(segment) = self.rotate_locked(&mut inner)? else {
            return Ok(None);
        };
        let entry = self.append(&mut inner, note(&segment))?;
        Ok(Some((segment, entry)))
    }

    fn rotate_locked(&self, inner: &mut Inner) -> Result<Option<Segment>, WitnessError> {
        if inner.first_seq == 0 {
            return Ok(None);
        }
        if inner.dirty {
            let len = inner.len;
            inner.file.set_len(len).map_err(io_err(&self.path))?;
            inner.dirty = false;
        }
        let segment = Segment {
            path: segment_path(&self.path, inner.first_seq, inner.next_seq - 1),
            first: inner.first_seq,
            last: inner.next_seq - 1,
            bytes: inner.len,
        };
        if segment.path.exists() {
            return Err(WitnessError::Io {
                path: segment.path,
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "segment already exists",
                ),
            });
        }
        // Erst sichern, dann umbenennen: Das Segment soll vollständig auf der
        // Platte liegen, bevor es als abgeschlossen gilt.
        let _ = inner.file.sync_all();
        fs::rename(&self.path, &segment.path).map_err(io_err(&self.path))?;
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => inner.file = file,
            Err(e) => {
                // Zurück zum alten Stand; das offene Handle zeigt ohnehin
                // weiter auf dieselbe Datei.
                let _ = fs::rename(&segment.path, &self.path);
                return Err(io_err(&self.path)(e));
            }
        }
        inner.len = 0;
        inner.first_seq = 0;
        inner.offsets.clear();
        // Abgelegte Segmente ändern sich nie mehr.
        if let Ok(meta) = fs::metadata(&segment.path) {
            let mut perms = meta.permissions();
            perms.set_readonly(true);
            let _ = fs::set_permissions(&segment.path, perms);
        }
        Ok(Some(segment))
    }

    /// Die Einträge nach `after` als rohe JSONL-Zeilen, höchstens
    /// `max_bytes` (aber immer mindestens ein Eintrag). Reicht `after` vor
    /// das aktive Segment zurück, kommen die Zeilen aus dem abgelegten.
    pub fn read_after(&self, after: u64, max_bytes: usize) -> Result<Chunk, WitnessError> {
        let inner = self.lock();
        let head = inner.next_seq - 1;
        if after >= head {
            return Ok(Chunk {
                bytes: Vec::new(),
                last: head,
                head,
            });
        }
        let want = after + 1;
        if inner.first_seq == 0 || want < inner.first_seq {
            let first_active = inner.first_seq;
            drop(inner);
            // Das erste Segment, das den gesuchten Eintrag oder spätere hält.
            if let Some(seg) = segments(&self.path).into_iter().find(|s| s.last >= want) {
                return read_segment_after(&seg, after, max_bytes, head);
            }
            if first_active == 0 {
                return Ok(Chunk {
                    bytes: Vec::new(),
                    last: head,
                    head,
                });
            }
            // Ältere Segmente liegen nicht mehr hier: mit dem aktiven weiter.
            return self.read_after(first_active - 1, max_bytes);
        }

        let n = inner.offsets.len();
        let end_of = |i: usize| -> u64 {
            if i + 1 < n {
                inner.offsets[i + 1]
            } else {
                inner.len
            }
        };
        let first = (want - inner.first_seq) as usize;
        let start = inner.offsets[first];
        let limit = start.saturating_add(max_bytes as u64);
        let mut last = first;
        while last + 1 < n && end_of(last + 1) <= limit {
            last += 1;
        }
        let mut bytes = vec![0u8; (end_of(last) - start) as usize];
        let mut file = File::open(&self.path).map_err(io_err(&self.path))?;
        file.seek(SeekFrom::Start(start))
            .and_then(|_| file.read_exact(&mut bytes))
            .map_err(io_err(&self.path))?;
        Ok(Chunk {
            bytes,
            last: inner.first_seq + last as u64,
            head,
        })
    }
}

/// Name der Sicherung einer abgerissenen letzten Zeile.
fn torn_path(active: &Path) -> PathBuf {
    let mut name = active.as_os_str().to_owned();
    name.push(format!(".torn-{}", Utc::now().format("%Y%m%dT%H%M%SZ")));
    PathBuf::from(name)
}

/// Zeilen eines abgelegten Segments nach `after`.
fn read_segment_after(
    seg: &Segment,
    after: u64,
    max_bytes: usize,
    head: u64,
) -> Result<Chunk, WitnessError> {
    let data = fs::read(&seg.path).map_err(io_err(&seg.path))?;
    let mut bytes = Vec::new();
    let mut last = after;
    for line in data.split_inclusive(|b| *b == b'\n') {
        let Some(seq) = seq_of_line(line) else {
            continue;
        };
        if seq <= after {
            continue;
        }
        if !bytes.is_empty() && bytes.len() + line.len() > max_bytes {
            break;
        }
        bytes.extend_from_slice(line);
        if !line.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        last = seq;
    }
    // Nichts Neues in diesem Segment: beim nächsten weiterlesen.
    if bytes.is_empty() {
        last = seg.last.max(after);
    }
    Ok(Chunk { bytes, last, head })
}

/// Alle Einträge der Kette: abgelegte Segmente, dann das aktive.
pub fn read_chain(active: &Path) -> Result<Vec<Entry>, WitnessError> {
    let older = segments(active);
    let mut entries = Vec::new();
    for seg in &older {
        entries.extend(read_entries(&seg.path)?);
    }
    match read_entries(active) {
        Ok(e) => entries.extend(e),
        Err(WitnessError::Io { source, .. })
            if !older.is_empty() && source.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(entries)
}

/// Liest von hinten: erst das aktive Segment, dann ältere, bis `enough`
/// zufrieden ist. Fehlt alles, ist das Ergebnis leer.
pub fn read_back(
    active: &Path,
    enough: impl Fn(&[Entry]) -> bool,
) -> Result<Vec<Entry>, WitnessError> {
    let mut entries = match read_entries(active) {
        Ok(e) => e,
        Err(WitnessError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Vec::new()
        }
        Err(e) => return Err(e),
    };
    for seg in segments(active).iter().rev() {
        if enough(&entries) {
            break;
        }
        let mut older = read_entries(&seg.path)?;
        older.append(&mut entries);
        entries = older;
    }
    Ok(entries)
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

/// Folgt dem Witness, auch über eine Rotation hinweg: Wird das aktive
/// Segment abgelegt, liest der Follower dessen Rest aus der abgelegten
/// Datei nach und macht im neuen Segment weiter.
pub struct Follower {
    path: PathBuf,
    offset: u64,
    /// Der letzte gelieferte Eintrag (Sequenznummer 0 = noch keiner).
    last_seq: u64,
    last_hash: String,
    /// So viele ältere Einträge aus abgelegten Segmenten holt der erste
    /// Aufruf mindestens dazu, wenn es sie gibt.
    history: usize,
    started: bool,
}

impl Follower {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            offset: 0,
            last_seq: 0,
            last_hash: String::new(),
            history: 0,
            started: false,
        }
    }

    /// Beim ersten Lesen auch Einträge aus abgelegten Segmenten liefern,
    /// bis mindestens `entries` zusammen sind.
    pub fn with_history(mut self, entries: usize) -> Self {
        self.history = entries;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn seen(&mut self, entries: &[Entry]) {
        if let Some(e) = entries.last() {
            self.last_seq = e.seq;
            self.last_hash = e.hash.clone();
        }
    }

    /// Die neuen Einträge. `true` an erster Stelle heißt: Die Kette hat
    /// neu begonnen (Datei geleert, andere Kette) – was der Leser bisher
    /// gesehen hat, gilt nicht mehr.
    pub fn poll(&mut self) -> (bool, Vec<Entry>) {
        let Ok((mut entries, next)) = read_entries_from(&self.path, self.offset) else {
            return (false, Vec::new());
        };
        let first_time = !self.started;
        self.started = true;
        let shrunk = next < self.offset;
        self.offset = next;

        if first_time {
            for seg in segments(&self.path).iter().rev() {
                if entries.len() >= self.history {
                    break;
                }
                if let Ok(mut older) = read_entries(&seg.path) {
                    older.append(&mut entries);
                    entries = older;
                }
            }
            self.seen(&entries);
            return (false, entries);
        }

        // Lückenlos weiter? Dann ist nichts Besonderes passiert.
        let continues = match entries.first() {
            Some(e) => self.last_seq == 0 || e.seq == self.last_seq + 1,
            None => true,
        };
        if !shrunk && continues {
            self.seen(&entries);
            return (false, entries);
        }

        // Die aktive Datei wurde ersetzt. Alles zusammensuchen, was nach dem
        // letzten gesehenen Eintrag kommt: aus abgelegten Segmenten, dann
        // aus der aktiven Datei von vorn.
        let mut pool: Vec<Entry> = Vec::new();
        for seg in segments(&self.path)
            .iter()
            .filter(|s| s.last >= self.last_seq)
        {
            pool.extend(read_entries(&seg.path).unwrap_or_default());
        }
        let (active, next) = read_entries_from(&self.path, 0).unwrap_or_default();
        self.offset = next;
        let from_segments = pool.len();
        pool.extend(active);

        if self.last_seq == 0 {
            self.seen(&pool);
            return (false, pool);
        }
        let known = pool
            .iter()
            .position(|e| e.seq == self.last_seq && e.hash == self.last_hash);
        match known {
            // Dieselbe Kette, nur über Dateien verteilt.
            Some(at) => {
                let fresh = pool.split_off(at + 1);
                self.seen(&fresh);
                (false, fresh)
            }
            // Was der Leser kannte, gibt es nicht mehr: eine neue Kette.
            None => {
                let active = pool.split_off(from_segments);
                self.last_seq = 0;
                self.last_hash.clear();
                self.seen(&active);
                (true, active)
            }
        }
    }
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
    /// Öffnet eine frische Kette mit `n` Einträgen.
    fn chain_of(name: &str, n: usize) -> (PathBuf, PathBuf, Witness) {
        let dir = temp_dir(name);
        let key = dir.join("witness.key");
        let log = dir.join("witness.jsonl");
        generate_keypair(&key).unwrap();
        let w = Witness::open(&log, &key).unwrap();
        for i in 0..n {
            w.record(draft(&format!("u{i}"), &[])).unwrap();
        }
        (log, key, w)
    }

    fn seqs(entries: &[Entry]) -> Vec<u64> {
        entries.iter().map(|e| e.seq).collect()
    }

    #[test]
    fn a_torn_last_line_is_saved_aside_and_the_chain_continues() {
        let (log, key, w) = chain_of("torn", 2);
        drop(w);
        // Ein Absturz mitten im Schreiben: eine halbe Zeile ohne Zeilenende.
        let torn = b"{\"seq\":3,\"ts\":\"2026-11-20T10:0";
        let mut f = OpenOptions::new().append(true).open(&log).unwrap();
        f.write_all(torn).unwrap();
        drop(f);
        assert!(
            read_entries(&log).is_err(),
            "the file is unreadable as it is"
        );

        let opened = Witness::open_full(&log, &key).unwrap();
        let r = opened.recovered.expect("the torn line is reported");
        assert_eq!(r.bytes, torn.len() as u64);
        assert_eq!(r.sha256, sha256_hex(torn));
        assert_eq!(
            fs::read(&r.saved_to).unwrap(),
            torn,
            "nothing is thrown away"
        );
        assert_eq!(seqs(&opened.entries), [1, 2]);

        // Die Kette läuft mit der Nummer weiter, die die halbe Zeile gehabt hätte.
        let e = opened.witness.record(draft("after", &[])).unwrap();
        assert_eq!(e.seq, 3);
        let all = read_entries(&log).unwrap();
        assert_eq!(seqs(&all), [1, 2, 3]);
        assert!(verify(&all, &load_verifying_key(&key).unwrap()).is_ok());

        // Ein zweites Öffnen findet nichts mehr zu reparieren.
        drop(opened.witness);
        assert!(Witness::open_full(&log, &key).unwrap().recovered.is_none());
    }

    #[test]
    fn a_complete_last_entry_without_line_end_keeps_the_next_one_apart() {
        let (log, key, w) = chain_of("no-newline", 2);
        drop(w);
        let text = fs::read_to_string(&log).unwrap();
        fs::write(&log, text.trim_end()).unwrap();

        let opened = Witness::open_full(&log, &key).unwrap();
        assert!(opened.recovered.is_none(), "a whole entry is not torn");
        opened.witness.record(draft("next", &[])).unwrap();
        let all = read_entries(&log).unwrap();
        assert_eq!(seqs(&all), [1, 2, 3]);
        assert!(verify(&all, &load_verifying_key(&key).unwrap()).is_ok());
    }

    #[test]
    fn an_unreadable_line_in_the_middle_is_an_error_not_a_repair() {
        let (log, key, w) = chain_of("corrupt-middle", 3);
        drop(w);
        let text = fs::read_to_string(&log).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines[1] = "{\"seq\":2,\"broken";
        fs::write(&log, lines.join("\n") + "\n").unwrap();

        match Witness::open_full(&log, &key) {
            Err(WitnessError::Corrupt { line, .. }) => assert_eq!(line, 2),
            other => panic!("expected a corrupt-line error, got {:?}", other.err()),
        }
        assert_eq!(
            fs::read_to_string(&log).unwrap().lines().count(),
            3,
            "untouched"
        );
    }

    #[test]
    fn rotation_closes_a_segment_and_the_chain_continues() {
        let (log, key, w) = chain_of("rotate", 3);
        let vk = load_verifying_key(&key).unwrap();
        let before = w.head().unwrap();

        let seg = w.rotate().unwrap().expect("three entries to put away");
        assert_eq!((seg.first, seg.last), (1, 3));
        assert_eq!(
            seg.path.file_name().unwrap().to_str().unwrap(),
            "witness.0000000001-0000000003.jsonl"
        );
        assert!(fs::metadata(&seg.path).unwrap().permissions().readonly());
        assert_eq!(fs::metadata(&log).unwrap().len(), 0);
        assert_eq!(w.head().unwrap(), before, "the head does not move");
        assert!(w.rotate().unwrap().is_none(), "nothing to rotate twice");

        let e4 = w.record(draft("d", &[])).unwrap();
        w.record(draft("e", &[])).unwrap();
        assert_eq!(e4.seq, 4);
        assert_eq!(e4.prev, before.hash, "linked to the closed segment");

        // Jedes Stück prüft sich allein, alle zusammen als eine Kette.
        assert_eq!(segments(&log), vec![seg.clone()]);
        assert!(verify(&read_entries(&seg.path).unwrap(), &vk).is_ok());
        let active = verify(&read_entries(&log).unwrap(), &vk);
        assert!(active.is_ok());
        assert_eq!(active.partial_from, Some(4));
        let all = read_chain(&log).unwrap();
        assert_eq!(seqs(&all), [1, 2, 3, 4, 5]);
        let whole = verify(&all, &vk);
        assert!(whole.is_ok() && whole.partial_from.is_none());

        // Ein Neustart setzt dort fort.
        drop(w);
        let w = Witness::open(&log, &key).unwrap();
        assert_eq!(w.record(draft("f", &[])).unwrap().seq, 6);
        assert_eq!(w.active().first, 4);
    }

    #[test]
    fn an_empty_active_segment_continues_after_the_last_closed_one() {
        let (log, key, w) = chain_of("rotate-restart", 2);
        let head = w.head().unwrap();
        w.rotate().unwrap().unwrap();
        drop(w);

        // Neustart direkt nach der Rotation: Die aktive Datei ist leer.
        let w = Witness::open(&log, &key).unwrap();
        assert_eq!(w.head().unwrap(), head);
        let e = w.record(draft("c", &[])).unwrap();
        assert_eq!((e.seq, e.prev), (3, head.hash));
        assert!(
            verify(
                &read_chain(&log).unwrap(),
                &load_verifying_key(&key).unwrap()
            )
            .is_ok()
        );
    }

    #[test]
    fn read_after_serves_closed_segments_and_the_active_one() {
        let (log, _key, w) = chain_of("read-after", 5);
        let seg = w.rotate().unwrap().unwrap();
        for u in ["f", "g", "h"] {
            w.record(draft(u, &[])).unwrap();
        }
        let parse = |c: &Chunk| -> Vec<u64> {
            c.bytes
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_slice::<Entry>(l).unwrap().seq)
                .collect()
        };
        const BIG: usize = 1 << 20;

        // Von vorn: erst das abgelegte Segment, dann das aktive.
        let c = w.read_after(0, BIG).unwrap();
        assert_eq!((parse(&c), c.last, c.head), (vec![1, 2, 3, 4, 5], 5, 8));
        let c = w.read_after(c.last, BIG).unwrap();
        assert_eq!((parse(&c), c.last, c.head), (vec![6, 7, 8], 8, 8));
        let c = w.read_after(8, BIG).unwrap();
        assert!(c.bytes.is_empty());
        assert_eq!(c.last, 8);

        // Mitten hinein, in beiden Dateien.
        assert_eq!(parse(&w.read_after(2, BIG).unwrap()), [3, 4, 5]);
        assert_eq!(parse(&w.read_after(6, BIG).unwrap()), [7, 8]);

        // Ein winziges Limit liefert trotzdem immer einen ganzen Eintrag.
        let c = w.read_after(5, 10).unwrap();
        assert_eq!((parse(&c), c.last), (vec![6], 6));
        let c = w.read_after(0, 10).unwrap();
        assert_eq!((parse(&c), c.last), (vec![1], 1));

        // Wer weiter ist als der Kopf, bekommt den Kopf genannt.
        assert_eq!(w.read_after(99, BIG).unwrap().last, 8);

        // Ist das alte Segment weggeräumt, geht es mit dem aktiven weiter.
        let mut perms = fs::metadata(&seg.path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(&seg.path, perms).unwrap();
        fs::remove_file(&seg.path).unwrap();
        let c = w.read_after(0, BIG).unwrap();
        assert_eq!(parse(&c), [6, 7, 8]);
        assert!(segments(&log).is_empty());
    }

    #[test]
    fn a_follower_reads_across_a_rotation_and_notices_a_new_chain() {
        let (log, key, w) = chain_of("follower", 2);
        let mut f = Follower::new(&log);
        assert_eq!(seqs(&f.poll().1), [1, 2]);
        assert!(f.poll().1.is_empty());

        // Ein Eintrag kommt, dann wird rotiert, dann kommen zwei weitere –
        // alles zwischen zwei Blicken des Lesers.
        w.record(draft("c", &[])).unwrap();
        w.rotate().unwrap().unwrap();
        w.record(draft("d", &[])).unwrap();
        w.record(draft("e", &[])).unwrap();
        let (restarted, new) = f.poll();
        assert!(!restarted, "a rotation is not a new chain");
        assert_eq!(seqs(&new), [3, 4, 5]);
        assert!(f.poll().1.is_empty());

        // Ein neuer Leser mit Vorgeschichte sieht auch das abgelegte Segment.
        let mut with_history = Follower::new(&log).with_history(100);
        assert_eq!(seqs(&with_history.poll().1), [1, 2, 3, 4, 5]);
        let mut without = Follower::new(&log);
        assert_eq!(seqs(&without.poll().1), [4, 5]);

        // Die Datei wird geleert: Was der Leser kannte, gibt es nicht mehr.
        drop(w);
        for seg in segments(&log) {
            let mut perms = fs::metadata(&seg.path).unwrap().permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            fs::set_permissions(&seg.path, perms).unwrap();
            fs::remove_file(&seg.path).unwrap();
        }
        fs::write(&log, "").unwrap();
        let (restarted, new) = f.poll();
        assert!(restarted);
        assert!(new.is_empty());

        // Eine neue Kette beginnt bei 1 und wird von vorn gelesen.
        let w = Witness::open(&log, &key).unwrap();
        w.record(draft("x", &[])).unwrap();
        let (restarted, new) = f.poll();
        assert!(!restarted);
        assert_eq!(seqs(&new), [1]);
    }

    #[test]
    fn segment_names_are_recognised_and_strangers_ignored() {
        let dir = temp_dir("segment-names");
        let log = dir.join("witness.jsonl");
        for name in [
            "witness.0000000001-0000000010.jsonl",
            "witness.0000000011-0000000020.jsonl",
            "witness.jsonl.torn-20261120T100000Z",
            "witness.key",
            "witness.abc-def.jsonl",
            "other.0000000001-0000000002.jsonl",
        ] {
            fs::write(dir.join(name), "").unwrap();
        }
        let found = segments(&log);
        assert_eq!(
            found.iter().map(|s| (s.first, s.last)).collect::<Vec<_>>(),
            [(1, 10), (11, 20)]
        );
        assert_eq!(segment_path(&log, 11, 20), found[1].path);
    }

    #[test]
    fn a_noted_rotation_puts_its_note_first_and_respects_the_size() {
        let (log, key, w) = chain_of("rotate-noting", 3);
        let note = |seg: &Segment| {
            let mut r = draft("-", &[]);
            r.event = Some("rotate".into());
            r.detail = Some(format!("closed #{} to #{}", seg.first, seg.last));
            r
        };

        // Zu klein für das Limit: nichts passiert.
        assert!(w.rotate_noting(1 << 20, note).unwrap().is_none());
        assert_eq!(w.active().entries, 3);

        let (seg, entry) = w.rotate_noting(0, note).unwrap().expect("rotated");
        assert_eq!((seg.first, seg.last), (1, 3));
        assert_eq!(entry.seq, 4, "the note is the very next entry");
        let active = read_entries(&log).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].event.as_deref(), Some("rotate"));
        assert_eq!(active[0].detail.as_deref(), Some("closed #1 to #3"));
        assert!(
            verify(
                &read_chain(&log).unwrap(),
                &load_verifying_key(&key).unwrap()
            )
            .is_ok()
        );
    }
}
