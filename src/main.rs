mod config;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{any, get},
};
use std::sync::Arc;

struct AppState {
    cfg: config::Config,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("hedge: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::Config::load("hedge.toml")?;

    let listener = tokio::net::TcpListener::bind(&cfg.server.listen).await?;

    let state = Arc::new(AppState { cfg });

    let app = Router::new()
        .route("/health", get(health))
        .route("/{upstream}/{*rest}", any(proxy))
        .with_state(state);

    //println!("hedge listening on {}", cfg.server.listen);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn proxy(
    State(state): State<Arc<AppState>>,
    Path((upstream, rest)): Path<(String, String)>,
) -> Result<String, (StatusCode, String)> {
    let selected = state.cfg.upstreams.iter().find(|u| u.name == upstream);

    match selected {
        Some(target) => Ok(format!(
            "would forward to {}/{}",
            target.url.trim_end_matches('/'),
            rest
        )),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("unknown upstream: {upstream}"),
        )),
    }
}

async fn health() -> &'static str {
    "healthy"
}
