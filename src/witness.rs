//! Der Witness: ein bezeugtes Protokoll aller Anfragen.
//!
//! Jede Anfrage wird als Eintrag an eine JSONL-Datei angehängt. Jeder
//! Eintrag enthält den Hash seines Vorgängers (Hash-Kette) und ist mit
//! Ed25519 signiert. `hedge verify` prüft die Kette offline: Ein geänderter,
//! gelöschter oder eingeschobener Eintrag fällt auf.
//!
//! Was NICHT im Protokoll steht: Prompt-Text, Antworten, Auth-Header. Nur
//! Hashes der Bodies, Fundarten mit Pfad, Entscheidung und Metadaten.
//! Das Protokoll darf deshalb zentral gesammelt werden, ohne selbst zum
//! Datenleck zu werden.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Mode;
use crate::inspect::{Action, Located};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingRecord {
    pub kind: String,
    pub severity: String,
    pub path: String,
}

impl From<&Located> for FindingRecord {
    fn from(l: &Located) -> Self {
        Self {
            kind: l.finding.kind.to_owned(),
            severity: l.finding.severity.as_str().to_owned(),
            path: l.path.clone(),
        }
    }
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

/// Was der Proxy pro Anfrage weiß, bevor der Witness Kette und Signatur ergänzt.
pub struct Draft<'a> {
    pub upstream: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub model: Option<&'a str>,
    pub mode: Mode,
    pub action: Action,
    pub findings: &'a [Located],
    pub body_in: &'a [u8],
    /// Nur gesetzt, wenn sich der Body durch Maskierung geändert hat.
    pub body_out: Option<&'a [u8]>,
    pub status: Option<u16>,
    pub duration_ms: u64,
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

    /// Hängt einen Eintrag an. Hash-Kette und Signatur werden hier gebildet;
    /// der Aufrufer liefert nur Fakten.
    pub fn record(&self, draft: Draft<'_>) -> Result<Entry, WitnessError> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let mut entry = Entry {
            seq: inner.next_seq,
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            upstream: draft.upstream.to_owned(),
            method: draft.method.to_owned(),
            path: draft.path.to_owned(),
            model: draft.model.map(str::to_owned),
            mode: draft.mode.as_str().to_owned(),
            action: draft.action.as_str().to_owned(),
            findings: draft.findings.iter().map(FindingRecord::from).collect(),
            body_sha256_in: hex::encode(Sha256::digest(draft.body_in)),
            body_sha256_out: draft.body_out.map(|b| hex::encode(Sha256::digest(b))),
            status: draft.status,
            duration_ms: draft.duration_ms,
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

/// Ergebnis einer Verifikation.
#[derive(Debug)]
pub struct VerifyReport {
    pub entries: usize,
    pub first_ts: Option<String>,
    pub last_ts: Option<String>,
    pub key_id: Option<String>,
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
    let mut prev_hash = GENESIS.to_owned();
    let mut expected_seq = entries.first().map(|e| e.seq).unwrap_or(1);
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
        problems,
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

#[cfg(unix)]
fn write_private(path: &Path, content: &[u8]) -> Result<(), WitnessError> {
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
fn write_private(path: &Path, content: &[u8]) -> Result<(), WitnessError> {
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

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hedge-witness-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn draft<'a>(upstream: &'a str, findings: &'a [Located]) -> Draft<'a> {
        Draft {
            upstream,
            method: "POST",
            path: "/v1/messages",
            model: Some("claude-x"),
            mode: Mode::Redact,
            action: Action::Redact,
            findings,
            body_in: b"{\"a\":1}",
            body_out: Some(b"{\"a\":2}"),
            status: Some(200),
            duration_ms: 42,
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
        d.body_in = secret_body;
        d.body_out = None;
        w.record(d).unwrap();

        let raw = fs::read_to_string(&log).unwrap();
        assert!(!raw.contains("supersecret"));
        assert!(raw.contains(&hex::encode(Sha256::digest(secret_body))));
    }
}
