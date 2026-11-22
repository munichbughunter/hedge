//! Was passiert, wenn der Witness nicht mehr schreiben kann – die Platte
//! ist voll, mitten in einem Eintrag?
//!
//! Der Test stellt genau das nach: Ein Dateigrößen-Limit lässt den nächsten
//! Eintrag nach ein paar Bytes abreißen. Das Limit gilt für den ganzen
//! Prozess, deshalb steht dieser Test allein in seiner Datei (eigene Datei =
//! eigener Prozess).

#![cfg(unix)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{Json, Router, routing::post};
use hedge::config::Config;
use hedge::proxy::{AppState, Runtime, router};
use hedge::witness::{self, Witness};
use serde_json::{Value, json};

const CONTROL_TOKEN: &str = "test-control-token";

async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Setzt das weiche Limit für Dateigrößen und liefert das alte.
// `rlim_t` ist nicht auf jeder Plattform `u64`.
#[allow(clippy::unnecessary_cast)]
fn limit_file_size(bytes: Option<u64>) -> u64 {
    // SAFETY: getrlimit/setrlimit mit einer gültigen, initialisierten
    // Struktur; SIGXFSZ wird ignoriert, damit ein Schreibversuch über das
    // Limit einen Fehler liefert, statt den Prozess zu beenden.
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut lim), 0);
        let old = lim.rlim_cur;
        lim.rlim_cur = bytes.map_or(lim.rlim_max, |b| b as libc::rlim_t);
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &lim), 0);
        old as u64
    }
}

#[tokio::test]
async fn a_full_disk_neither_stops_traffic_nor_breaks_the_chain() {
    let upstream = spawn(Router::new().route(
        "/v1/messages",
        post(|| async {
            Json(json!({
                "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }))
        }),
    ))
    .await;

    let dir = std::env::temp_dir().join(format!("hedge-full-disk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (log, key) = (dir.join("witness.jsonl"), dir.join("witness.key"));
    witness::generate_keypair(&key).unwrap();
    let cfg = Config::from_toml(&format!(
        "[[upstreams]]\nname = \"mock\"\nurl = \"http://{upstream}\""
    ))
    .unwrap();
    let state = Arc::new(
        AppState::new(
            Runtime::build(cfg).unwrap(),
            Some(Witness::open(&log, &key).unwrap()),
        )
        .with_control_token(Some(CONTROL_TOKEN.into())),
    );
    let hedge = spawn(router(state.clone())).await;

    let http = reqwest::Client::new();
    let send = || async {
        http.post(format!("http://{hedge}/mock/v1/messages"))
            .json(&json!({"model": "claude-test", "messages": [{"role": "user", "content": "hi"}]}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    };
    let ready = || async {
        let r = http
            .get(format!("http://{hedge}/ready"))
            .send()
            .await
            .unwrap();
        let code = r.status().as_u16();
        let body: Value = r.json().await.unwrap();
        let why = body["waiting_for"][0].as_str().unwrap_or("").to_owned();
        (code, body["ready"].as_bool(), why)
    };
    let status = || async {
        http.get(format!("http://{hedge}/_hedge/status"))
            .bearer_auth(CONTROL_TOKEN)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    };

    // Zwei Anfragen, solange alles in Ordnung ist.
    assert_eq!(send().await, 200);
    assert_eq!(send().await, 200);
    assert_eq!(ready().await, (200, Some(true), String::new()));
    let good = std::fs::read(&log).unwrap();
    assert_eq!(witness::read_entries(&log).unwrap().len(), 2);

    // Die Platte ist voll: Vom nächsten Eintrag passen noch 100 Bytes.
    let old = limit_file_size(Some(good.len() as u64 + 100));

    // Der Traffic läuft weiter – das ist so entschieden –, aber Hedge sagt
    // laut, dass es ohne Protokoll arbeitet.
    assert_eq!(send().await, 200);
    assert_eq!(
        ready().await,
        (503, Some(false), "witness is failing".to_owned())
    );
    let s = status().await;
    assert_eq!(s["ready"], false);
    assert_eq!(s["witness"]["ok"], false);
    assert!(s["witness"]["last_error"].is_string());

    // Keine halbe Zeile bleibt liegen: Die Datei ist Byte für Byte, was sie war.
    let unchanged = |what: &str| {
        let now = std::fs::read(&log).unwrap();
        assert!(
            now == good,
            "{what}: the witness changed from {} to {} bytes, ending in {:?}",
            good.len(),
            now.len(),
            String::from_utf8_lossy(&now[now.len().saturating_sub(40)..])
        );
    };
    unchanged("after the failed write");

    // Auch ein zweiter Fehlversuch ändert daran nichts.
    assert_eq!(send().await, 200);
    unchanged("after a second failed write");

    // Platz ist wieder da: Der nächste Eintrag schließt lückenlos an.
    limit_file_size(Some(old));
    assert_eq!(send().await, 200);
    assert_eq!(ready().await, (200, Some(true), String::new()));
    assert_eq!(status().await["witness"]["ok"], true);

    let entries = witness::read_entries(&log).unwrap();
    assert_eq!(
        entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [1, 2, 3],
        "the two unrecorded requests left no gap in the numbering"
    );
    let vk = witness::load_verifying_key(&key).unwrap();
    assert!(witness::verify(&entries, &vk).is_ok());
}
