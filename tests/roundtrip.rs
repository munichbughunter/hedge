//! Integrationstest: ein Mock-Upstream, Hedge davor, echte HTTP-Roundtrips.
//!
//! Der Mock antwortet mit dem Body, den er bekommen hat. So sehen wir genau,
//! was Hedge weitergeleitet hat – im Klartext, maskiert, oder gar nicht.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{Json, Router, body::Bytes, routing::post};
use hedge::config::{Config, Mode};
use hedge::detect::Detectors;
use hedge::inspect::Rules;
use hedge::proxy::{AppState, build_client, router};
use hedge::witness::{self, Witness};
use serde_json::{Value, json};

const FAKE_KEY: &str = "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxx";

async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Upstream, der den empfangenen Body als `{"echo": <body>}` zurückgibt.
async fn spawn_echo_upstream() -> SocketAddr {
    async fn echo(body: Bytes) -> Json<Value> {
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        Json(json!({ "echo": v }))
    }
    spawn(Router::new().route("/v1/messages", post(echo))).await
}

struct Harness {
    hedge: SocketAddr,
    witness_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

async fn spawn_hedge(mode: Mode, extra_toml: &str) -> Harness {
    let upstream = spawn_echo_upstream().await;
    let dir =
        std::env::temp_dir().join(format!("hedge-it-{}-{}", std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let witness_path = dir.join("witness.jsonl");
    let key_path = dir.join("witness.key");
    witness::generate_keypair(&key_path).unwrap();

    let toml = format!(
        r#"
        mode = "{}"
        [[upstreams]]
        name = "mock"
        url = "http://{upstream}"
        {extra_toml}
        "#,
        mode.as_str()
    );
    let cfg = Config::from_toml(&toml).unwrap();
    let client = build_client(&cfg).unwrap();
    let detectors = Detectors::from_toggles(&cfg.detectors);
    let rules = Rules::from_config(&cfg);
    let witness = Witness::open(&witness_path, &key_path).unwrap();
    let state = Arc::new(AppState::new(cfg, client, detectors, rules, Some(witness)));
    let hedge = spawn(router(state)).await;
    Harness {
        hedge,
        witness_path,
        key_path,
    }
}

fn rand_suffix() -> u64 {
    getrandom::u64().unwrap_or(0)
}

async fn send(h: &Harness, content: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/mock/v1/messages", h.hedge))
        .header("x-api-key", "test-key-must-pass-through")
        .json(&json!({
            "model": "claude-test",
            "messages": [{ "role": "user", "content": content }]
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    (status, body)
}

#[tokio::test]
async fn observe_forwards_unchanged_and_records_finding() {
    let h = spawn_hedge(Mode::Observe, "").await;

    let (status, body) = send(&h, &format!("key: {FAKE_KEY}")).await;

    assert_eq!(status, 200);
    assert_eq!(
        body["echo"]["messages"][0]["content"],
        format!("key: {FAKE_KEY}")
    );

    let entries = witness::read_entries(&h.witness_path).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "forward");
    assert_eq!(entries[0].status, Some(200));
    assert_eq!(entries[0].model.as_deref(), Some("claude-test"));
    assert_eq!(entries[0].findings[0].kind, "anthropic_api_key");
    assert_eq!(entries[0].findings[0].path, "messages[0].content");
    assert!(entries[0].body_sha256_out.is_none());
}

#[tokio::test]
async fn redact_masks_before_upstream_sees_it() {
    let h = spawn_hedge(Mode::Redact, "").await;

    let (status, body) = send(&h, &format!("key: {FAKE_KEY} and mail me@x.org")).await;

    assert_eq!(status, 200);
    assert_eq!(
        body["echo"]["messages"][0]["content"],
        "key: [REDACTED:anthropic_api_key] and mail [REDACTED:email]"
    );
    let entries = witness::read_entries(&h.witness_path).unwrap();
    assert_eq!(entries[0].action, "redact");
    assert!(entries[0].body_sha256_out.is_some());
    assert_ne!(
        entries[0].body_sha256_out,
        Some(entries[0].body_sha256_in.clone())
    );
}

#[tokio::test]
async fn block_returns_403_in_api_error_format_and_never_reaches_upstream() {
    let h = spawn_hedge(Mode::Block, "").await;

    let (status, body) = send(&h, FAKE_KEY).await;

    assert_eq!(status, 403);
    assert_eq!(body["type"], "error");
    assert_eq!(body["error"]["type"], "hedge_blocked");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("anthropic_api_key")
    );

    let entries = witness::read_entries(&h.witness_path).unwrap();
    assert_eq!(entries[0].action, "block");
    assert_eq!(
        entries[0].status, None,
        "blocked requests have no upstream status"
    );
}

#[tokio::test]
async fn allowlisted_domain_passes_block_mode_untouched() {
    let h = spawn_hedge(Mode::Block, "[allow]\ndomains = [\"x.org\"]").await;

    let (status, body) = send(&h, "mail me@x.org").await;

    assert_eq!(status, 200);
    assert_eq!(body["echo"]["messages"][0]["content"], "mail me@x.org");
    let entries = witness::read_entries(&h.witness_path).unwrap();
    assert!(entries[0].findings.is_empty());
}

#[tokio::test]
async fn unknown_upstream_is_404() {
    let h = spawn_hedge(Mode::Observe, "").await;

    let resp = reqwest::Client::new()
        .post(format!("http://{}/nope/v1/messages", h.hedge))
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 404);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "hedge_unknown_upstream");
}

#[tokio::test]
async fn witness_chain_verifies_after_mixed_traffic() {
    let h = spawn_hedge(Mode::Block, "").await;
    send(&h, "clean").await;
    send(&h, "mail me@x.org").await;
    send(&h, FAKE_KEY).await;

    let entries = witness::read_entries(&h.witness_path).unwrap();
    let vk = witness::load_verifying_key(&h.key_path).unwrap();
    let report = witness::verify(&entries, &vk);

    assert_eq!(report.entries, 3);
    assert!(report.is_ok(), "{:?}", report.problems);
    let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, vec!["forward", "redact", "block"]);
    for e in &entries {
        assert_eq!(e.key_id, witness::key_id_of(&vk));
    }
}
