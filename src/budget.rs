//! Token-Budgets: pro Client und Tag, und pro Agent-Session.
//!
//! Gezählt wird, was Arbeit kostet: Input ohne Cache-Reads plus Output.
//! Die Zähler leben im Speicher und werden beim Start aus dem Witness
//! wiederhergestellt, damit ein Neustart das Budget nicht zurücksetzt.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::Utc;

use crate::config::Budget;
use crate::witness::Entry;

/// Name des Clients, wenn Hedge lokal ohne Client-Tokens läuft.
pub const LOCAL: &str = "local";

/// Mehr Sessions merkt sich Hedge nicht; danach wird die Tabelle geleert.
const MAX_SESSIONS: usize = 10_000;

#[derive(Default)]
struct Inner {
    day: String,
    daily: HashMap<String, u64>,
    sessions: HashMap<String, u64>,
}

#[derive(Default)]
pub struct Budgets {
    inner: Mutex<Inner>,
}

fn today() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

impl Budgets {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = today();
        if inner.day != now {
            inner.day = now;
            inner.daily.clear();
        }
        inner
    }

    /// Stellt die Zähler aus den Einträgen von heute wieder her.
    pub fn seed(&self, entries: &[Entry]) {
        let mut inner = self.lock();
        let day = inner.day.clone();
        for e in entries.iter().filter(|e| e.ts.starts_with(&day)) {
            let tokens = e.tokens_in.unwrap_or(0) + e.tokens_out.unwrap_or(0);
            if tokens == 0 {
                continue;
            }
            *inner
                .daily
                .entry(e.client.clone().unwrap_or_else(|| LOCAL.into()))
                .or_default() += tokens;
            if let Some(s) = &e.session {
                *inner.sessions.entry(s.clone()).or_default() += tokens;
            }
        }
    }

    /// `Err` mit Begründung, wenn ein Budget bereits ausgeschöpft ist.
    pub fn check(
        &self,
        client: &str,
        session: Option<&str>,
        limits: &Budget,
    ) -> Result<(), String> {
        let inner = self.lock();
        if limits.daily_tokens > 0 {
            let used = inner.daily.get(client).copied().unwrap_or(0);
            if used >= limits.daily_tokens {
                return Err(format!(
                    "daily token budget exhausted for {client}: {used} of {} used (resets at 00:00 UTC)",
                    limits.daily_tokens
                ));
            }
        }
        if limits.session_tokens > 0
            && let Some(s) = session
        {
            let used = inner.sessions.get(s).copied().unwrap_or(0);
            if used >= limits.session_tokens {
                return Err(format!(
                    "session token budget exhausted for session {s}: {used} of {} used",
                    limits.session_tokens
                ));
            }
        }
        Ok(())
    }

    pub fn add(&self, client: &str, session: Option<&str>, tokens: u64) {
        if tokens == 0 {
            return;
        }
        let mut inner = self.lock();
        *inner.daily.entry(client.to_owned()).or_default() += tokens;
        if let Some(s) = session {
            if inner.sessions.len() >= MAX_SESSIONS && !inner.sessions.contains_key(s) {
                inner.sessions.clear();
            }
            *inner.sessions.entry(s.to_owned()).or_default() += tokens;
        }
    }

    /// Verbrauch heute pro Client, absteigend.
    pub fn daily_usage(&self) -> Vec<(String, u64)> {
        let inner = self.lock();
        let mut v: Vec<(String, u64)> = inner.daily.iter().map(|(k, n)| (k.clone(), *n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(daily: u64, session: u64) -> Budget {
        Budget {
            daily_tokens: daily,
            session_tokens: session,
        }
    }

    #[test]
    fn unlimited_by_default() {
        let b = Budgets::default();
        b.add(LOCAL, Some("s1"), 1_000_000);
        assert!(b.check(LOCAL, Some("s1"), &limits(0, 0)).is_ok());
    }

    #[test]
    fn daily_budget_is_per_client() {
        let b = Budgets::default();
        b.add("alice", None, 900);
        assert!(b.check("alice", None, &limits(1000, 0)).is_ok());
        b.add("alice", None, 100);
        let err = b.check("alice", None, &limits(1000, 0)).unwrap_err();
        assert!(err.contains("alice") && err.contains("1000"), "{err}");
        assert!(b.check("bob", None, &limits(1000, 0)).is_ok());
        assert_eq!(b.daily_usage()[0], ("alice".to_owned(), 1000));
    }

    #[test]
    fn session_budget_is_per_session() {
        let b = Budgets::default();
        b.add(LOCAL, Some("s1"), 500);
        assert!(b.check(LOCAL, Some("s1"), &limits(0, 500)).is_err());
        assert!(b.check(LOCAL, Some("s2"), &limits(0, 500)).is_ok());
        assert!(b.check(LOCAL, None, &limits(0, 500)).is_ok());
    }

    #[test]
    fn seed_restores_todays_usage_only() {
        let mk = |ts: &str, client: Option<&str>, tin: u64, tout: u64| Entry {
            seq: 1,
            ts: ts.into(),
            upstream: "a".into(),
            method: "POST".into(),
            path: "/".into(),
            model: None,
            mode: "observe".into(),
            action: "forward".into(),
            findings: vec![],
            body_sha256_in: String::new(),
            body_sha256_out: None,
            status: Some(200),
            duration_ms: 1,
            session: Some("s1".into()),
            client: client.map(str::to_owned),
            tokens_in: Some(tin),
            tokens_out: Some(tout),
            tokens_cached: None,
            stop_reason: None,
            tools: vec![],
            response_findings: vec![],
            flags: vec![],
            stream: false,
            aborted: false,
            event: None,
            detail: None,
            key_id: String::new(),
            prev: String::new(),
            hash: String::new(),
            sig: String::new(),
        };
        let now = format!("{}T10:00:00.000Z", today());
        let b = Budgets::default();
        b.seed(&[
            mk(&now, None, 100, 20),
            mk(&now, Some("alice"), 7, 3),
            mk("2020-01-01T10:00:00.000Z", None, 9999, 0),
        ]);
        let usage = b.daily_usage();
        assert_eq!(
            usage,
            vec![(LOCAL.to_owned(), 120), ("alice".to_owned(), 10)]
        );
        assert!(b.check(LOCAL, Some("s1"), &limits(0, 130)).is_err());
    }
}
