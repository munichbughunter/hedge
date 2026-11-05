use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::config::Config;

const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

pub struct AppState {
    cfg: Config,
    client: reqwest::Client,
}

impl AppState {
    pub fn new(cfg: Config, client: reqwest::Client) -> Self {
        Self { cfg, client }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("unknown upstream: {0}")]
    UnknownUpstream(String),

    #[error("request body could not be read: {0}")]
    Body(#[from] axum::Error),

    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::UnknownUpstream(_) => StatusCode::NOT_FOUND,
            Self::Body(_) => StatusCode::BAD_REQUEST,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
        };

        (status, self.to_string()).into_response()
    }
}

pub async fn proxy(
    State(state): State<Arc<AppState>>,
    Path((upstream, rest)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ProxyError> {
    // Upstream suchen
    let target = state
        .cfg
        .upstreams
        .iter()
        .find(|u| u.name == upstream)
        .ok_or_else(|| ProxyError::UnknownUpstream(upstream.clone()))?;

    // 2. Ziel-URL einschließlich Query-String bauen.
    let mut url = format!("{}/{}", target.url.trim_end_matches('/'), rest);

    if let Some(query) = req.uri().query() {
        url.push('?');
        url.push_str(query);
    }

    // 3. Request in Header und Body zerlegen
    let (parts, body) = req.into_parts();

    // 4. Request-Body mit Sizelimit
    let bytes = to_bytes(body, MAX_BODY_BYTES).await?;

    // 5. Header übernehmen; Host und Framing setzt reqwest
    let mut headers = parts.headers;
    headers.remove(header::HOST);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::CONTENT_LENGTH);

    // 6. Anfrage an upstream senden
    let upstream_resp = state
        .client
        .request(parts.method, url)
        .headers(headers)
        .body(bytes)
        .send()
        .await?;

    // 7. Status und Header sichern, bevor bytes() die Antwort konsumiert
    let status = upstream_resp.status();
    let mut headers = upstream_resp.headers().clone();
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::CONTENT_LENGTH);

    let bytes = upstream_resp.bytes().await?;

    // 8. Antwort an den ursprünglichen client
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = headers;

    Ok(response)
}
