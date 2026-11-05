mod config;
mod proxy;
use std::sync::Arc;

use axum::{
    Router,
    routing::{any, get},
};

use proxy::AppState;

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

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let state = Arc::new(AppState::new(cfg, client));

    let app = Router::new()
        .route("/health", get(health))
        .route("/{upstream}/{*rest}", any(proxy::proxy))
        .with_state(state);

    println!("hedge listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "healthy"
}
