mod config;
mod detect;
mod inspect;
mod policy;
mod proxy;

use std::sync::Arc;

use axum::{
    Router,
    routing::{any, get},
};

use proxy::AppState;
use clap::Parser;

#[tokio::main]
async fn main() {
    reset_sigpipe();
    let cli = hedge::cli::Cli::parse();
    match hedge::cli::run(cli).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("hedge: {e}");
            std::process::exit(1);
        }
    }
}

/// Rust ignoriert SIGPIPE und lässt `println!` stattdessen panicken. Für ein
/// CLI, dessen Ausgabe in `head`, `grep` oder `less` landet, ist das falsche
/// Verhalten: `hedge tail | head` soll leise enden, nicht abstürzen.
#[cfg(unix)]
fn reset_sigpipe() {
    // SAFETY: Setzt nur den prozessweiten Handler für SIGPIPE auf den
    // Standard zurück; kein Zugriff auf geteilten Speicher.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn reset_sigpipe() {}
