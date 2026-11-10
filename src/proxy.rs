//! Der Proxy: nimmt Anfragen unter `/<upstream>/...` an, inspiziert den Body,
//! leitet weiter und bezeugt das Ergebnis.
//!
//! Harte Regel: Auth-Header (`authorization`, `x-api-key`) werden nur
//! durchgereicht – nie gelesen, geloggt oder in den Witness geschrieben.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{Path, Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use serde_json::json;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::detect::Detectors;
use crate::inspect::{Action, Located, Outcome, Rules, inspect};
use crate::witness::{Draft, Witness};

const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

pub struct AppState {
    cfg: Config,
    client: reqwest::Client,
    detectors: Detectors,
    rules: Rules,
    witness: Option<Witness>,
}

impl AppState {
    pub fn new(
        cfg: Config,
        client: reqwest::Client,
        detectors: Detectors,
        rules: Rules,
        witness: Option<Witness>,
    ) -> Self {
        Self {
            cfg,
            client,
            detectors,
            rules,
            witness,
        }
    }

    /// Baut den State komplett aus der Config (Client, Detektoren, Regeln, Witness).
    pub fn from_config(cfg: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let client = build_client(&cfg)?;
        let detectors = Detectors::from_toggles(&cfg.detectors);
        let rules = Rules::from_config(&cfg);
        let witness = if cfg.witness.enabled {
            Some(Witness::open(&cfg.witness_path(), &cfg.witness_key_path())?)
        } else {
            None
        };
        Ok(Self::new(cfg, client, detectors, rules, witness))
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn witness(&self) -> Option<&Witness> {
        self.witness.as_ref()
    }
}

pub fn build_client(cfg: &Config) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        // Ein 3xx geht unverändert an den Client zurück. Würde Hedge folgen,
        // wanderten Credentials zu einem Host, den der Agent nie angefragt hat.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(cfg.timeouts.connect_secs))
        .timeout(Duration::from_secs(cfg.timeouts.request_secs))
        .build()
}

/// Der komplette Router. Separat, damit Integrationstests ihn ohne
/// echten Listener benutzen können.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/{upstream}/{*rest}", any(proxy))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("unknown upstream: {0}")]
    UnknownUpstream(String),

    #[error("request body could not be read: {0}")]
    Body(#[from] axum::Error),

    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),

    #[error("request blocked by hedge: {reason}")]
    Blocked { reason: String },
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::UnknownUpstream(_) => StatusCode::NOT_FOUND,
            Self::Body(_) => StatusCode::BAD_REQUEST,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::Blocked { .. } => StatusCode::FORBIDDEN,
        };

        // Fehler im Format der LLM-APIs, damit Agents wie Claude Code die
        // Begründung dem Nutzer anzeigen statt eines nackten HTTP-Fehlers.
        let body = json!({
            "type": "error",
            "error": {
                "type": match &self {
                    Self::Blocked { .. } => "hedge_blocked",
                    Self::UnknownUpstream(_) => "hedge_unknown_upstream",
                    Self::Body(_) => "hedge_bad_request",
                    Self::Upstream(_) => "hedge_upstream_error",
                },
                "message": self.to_string()
            }
        });
        (status, Json(body)).into_response()
    }
}

pub async fn proxy(
    State(state): State<Arc<AppState>>,
    Path((upstream, rest)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ProxyError> {
    let started = Instant::now();

    let target = state
        .cfg
        .upstream(&upstream)
        .ok_or_else(|| ProxyError::UnknownUpstream(upstream.clone()))?;

    let request_path = format!("/{rest}");
    let mut url = format!("{}{}", target.url.trim_end_matches('/'), request_path);
    if let Some(query) = req.uri().query() {
        url.push('?');
        url.push_str(query);
    }

    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let original = to_bytes(body, MAX_BODY_BYTES).await?;

    // Inspektion: scannen, Regeln und Policy anwenden, ggf. maskieren.
    let outcome = inspect(
        original.clone(),
        &state.detectors,
        &state.rules,
        state.cfg.mode,
    );

    if outcome.action == Action::Block {
        let reason = outcome.reason.clone().unwrap_or_default();
        let duration_ms = started.elapsed().as_millis() as u64;
        log_request(
            &upstream,
            method.as_str(),
            &request_path,
            &outcome,
            None,
            duration_ms,
        );
        witness_record(
            &state,
            &upstream,
            &method,
            &request_path,
            &outcome,
            &original,
            None,
            duration_ms,
        );
        return Err(ProxyError::Blocked { reason });
    }

    let mut headers = parts.headers;
    // Framing gehört dem Framework: Host, Länge und Chunking setzt reqwest neu.
    headers.remove(header::HOST);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::CONTENT_LENGTH);

    let upstream_resp = state
        .client
        .request(method.clone(), url)
        .headers(headers)
        .body(outcome.body.clone())
        .send()
        .await?;

    let status = upstream_resp.status();
    let mut resp_headers = upstream_resp.headers().clone();
    resp_headers.remove(header::TRANSFER_ENCODING);
    resp_headers.remove(header::CONTENT_LENGTH);
    let resp_bytes = upstream_resp.bytes().await?;

    let duration_ms = started.elapsed().as_millis() as u64;
    log_request(
        &upstream,
        method.as_str(),
        &request_path,
        &outcome,
        Some(status.as_u16()),
        duration_ms,
    );
    witness_record(
        &state,
        &upstream,
        &method,
        &request_path,
        &outcome,
        &original,
        Some(status.as_u16()),
        duration_ms,
    );

    let mut response = Response::new(Body::from(resp_bytes));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    Ok(response)
}

/// Eine Zeile pro Anfrage. Funde nur als `kind@pfad`, nie als Text.
fn log_request(
    upstream: &str,
    method: &str,
    path: &str,
    outcome: &Outcome,
    status: Option<u16>,
    duration_ms: u64,
) {
    let findings = summarize(&outcome.findings);
    let model = outcome.model.as_deref().unwrap_or("-");
    match outcome.action {
        Action::Forward if outcome.findings.is_empty() => {
            info!(
                upstream,
                method,
                path,
                model,
                status = status.unwrap_or(0),
                duration_ms,
                "forwarded"
            );
        }
        Action::Forward => {
            warn!(
                upstream, method, path, model, status = status.unwrap_or(0), duration_ms,
                findings = outcome.findings.len(), r#where = %findings,
                "observed findings, forwarded unchanged"
            );
        }
        Action::Redact => {
            warn!(
                upstream, method, path, model, status = status.unwrap_or(0), duration_ms,
                findings = outcome.findings.len(), r#where = %findings,
                "redacted findings, forwarded masked body"
            );
        }
        Action::Block => {
            error!(
                upstream, method, path, model, duration_ms,
                findings = outcome.findings.len(), r#where = %findings,
                reason = outcome.reason.as_deref().unwrap_or(""),
                "blocked request"
            );
        }
    }
}

pub fn summarize(findings: &[Located]) -> String {
    findings
        .iter()
        .map(|l| {
            format!(
                "{}({})@{}",
                l.finding.kind,
                l.finding.severity.as_str(),
                l.path
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[allow(clippy::too_many_arguments)]
fn witness_record(
    state: &AppState,
    upstream: &str,
    method: &axum::http::Method,
    path: &str,
    outcome: &Outcome,
    original: &Bytes,
    status: Option<u16>,
    duration_ms: u64,
) {
    let Some(witness) = &state.witness else {
        return;
    };
    let body_out = (outcome.action == Action::Redact).then(|| outcome.body.as_ref());
    let draft = Draft {
        upstream,
        method: method.as_str(),
        path,
        model: outcome.model.as_deref(),
        mode: state.cfg.mode,
        action: outcome.action,
        findings: &outcome.findings,
        body_in: original,
        body_out,
        status,
        duration_ms,
    };
    if let Err(e) = witness.record(draft) {
        // Der Witness darf den Traffic nicht blockieren, aber sein Ausfall
        // muss laut sein: Ohne Protokoll ist Hedge kein Guard mehr.
        error!(error = %e, "witness write failed");
    }
}
