//! Integration tests against a live in-memory axum app.
//!
//! Each test spins up a fresh server backed by `sqlite::memory:` on an
//! ephemeral port, then talks to it over real HTTP / WebSocket. No shared
//! global state — tests are isolated and safe to run in parallel.

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use io3233_server::{
    test_support::{fresh_state, spawn_app},
    MeResponse, MessagesResponse, PostMessageResponse, RegisterResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use url::Url;

fn b64(buf: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(buf)
}

fn make_pubkey(seed: u8) -> (Vec<u8>, String) {
    // The server only checks length (32 bytes) and treats the bytes as a raw
    // Curve25519 public key. For HTTP tests we don't need actual crypto — we
    // just need a deterministic, distinct 32-byte buffer per "user".
    let pk = vec![seed; 32];
    let mut h = Sha256::new();
    h.update(&pk);
    let fp = hex::encode(h.finalize());
    (pk, fp)
}

async fn boot() -> (reqwest::Client, String) {
    let state = fresh_state().await;
    let base = spawn_app(state).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    (client, base)
}

async fn register(
    client: &reqwest::Client,
    base: &str,
    pk: &[u8],
) -> RegisterResponse {
    let resp = client
        .post(format!("{base}/v1/register"))
        .json(&json!({ "public_key": b64(pk) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register status");
    resp.json::<RegisterResponse>().await.unwrap()
}

// ---------------------------------------------------------------- register

#[tokio::test]
async fn register_returns_fingerprint_and_token() {
    let (c, base) = boot().await;
    let (pk, expected_fp) = make_pubkey(1);
    let r = register(&c, &base, &pk).await;
    assert_eq!(r.fingerprint, expected_fp);
    assert!(!r.token.is_empty());
    assert!(r.expires_in > 0);
}

#[tokio::test]
async fn register_is_idempotent_for_same_pubkey() {
    let (c, base) = boot().await;
    let (pk, _) = make_pubkey(2);
    let a = register(&c, &base, &pk).await;
    let b = register(&c, &base, &pk).await;
    assert_eq!(a.fingerprint, b.fingerprint);
    // Stats should report only one identity.
    let stats: serde_json::Value = c
        .get(format!("{base}/v1/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats["registered_identities"], 1);
}

#[tokio::test]
async fn register_rejects_invalid_public_key() {
    let (c, base) = boot().await;
    for bad in [
        json!({ "public_key": "!!not-base64!!" }),
        json!({ "public_key": b64(&[0u8; 16]) }), // too short
        json!({ "public_key": b64(&[0u8; 64]) }), // too long
    ] {
        let r = c
            .post(format!("{base}/v1/register"))
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::BAD_REQUEST,
            "rejected: {bad:?}",
        );
    }
}

// ---------------------------------------------------------------- me

#[tokio::test]
async fn me_requires_auth_and_returns_self() {
    let (c, base) = boot().await;
    let (pk, fp) = make_pubkey(3);
    let reg = register(&c, &base, &pk).await;

    // Without bearer token
    let r = c.get(format!("{base}/v1/me")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let me: MeResponse = c
        .get(format!("{base}/v1/me"))
        .bearer_auth(&reg.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me.fingerprint, fp);
    assert_eq!(me.public_key, b64(&pk));
}

#[tokio::test]
async fn me_rejects_invalid_token() {
    let (c, base) = boot().await;
    let r = c
        .get(format!("{base}/v1/me"))
        .bearer_auth("not-a-real-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------- keys

#[tokio::test]
async fn public_key_lookup_works() {
    let (c, base) = boot().await;
    let (pk, fp) = make_pubkey(4);
    register(&c, &base, &pk).await;

    let r: serde_json::Value = c
        .get(format!("{base}/v1/keys/{fp}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["public_key"], b64(&pk));
}

#[tokio::test]
async fn public_key_lookup_404_for_missing() {
    let (c, base) = boot().await;
    let r = c
        .get(format!("{base}/v1/keys/{}", "0".repeat(64)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn public_key_lookup_400_for_invalid_fp() {
    let (c, base) = boot().await;
    let r = c
        .get(format!("{base}/v1/keys/not-hex"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn key_search_returns_matching_prefixes() {
    let (c, base) = boot().await;
    // Register 3 users; their fingerprints will be sha256([seed; 32])
    // which have nothing to do with each other — we'll search by the exact
    // first-8 hex chars of one to be sure we find that fingerprint.
    let (pk, fp) = make_pubkey(5);
    register(&c, &base, &pk).await;
    let (pk2, _) = make_pubkey(6);
    register(&c, &base, &pk2).await;

    let prefix = &fp[..8];
    let r: serde_json::Value = c
        .get(format!("{base}/v1/keys/search/{prefix}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let fps: Vec<String> = r["fingerprints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(fps.contains(&fp), "got {fps:?}");
}

#[tokio::test]
async fn key_search_rejects_short_prefix() {
    let (c, base) = boot().await;
    let r = c
        .get(format!("{base}/v1/keys/search/abc"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------- messages

#[tokio::test]
async fn post_message_requires_auth() {
    let (c, base) = boot().await;
    let (pk_r, fp_r) = make_pubkey(7);
    register(&c, &base, &pk_r).await;

    let body = json!({
        "recipient_fingerprint": fp_r,
        "ciphertext": b64(b"hello"),
        "nonce": b64(&[0u8; 24]),
        "sender_public_key": b64(&[0u8; 32]),
    });
    let r = c
        .post(format!("{base}/v1/messages"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_message_rejects_bad_fingerprint() {
    let (c, base) = boot().await;
    let (pk_s, _) = make_pubkey(8);
    let reg = register(&c, &base, &pk_s).await;

    let body = json!({
        "recipient_fingerprint": "not-hex",
        "ciphertext": b64(b"hi"),
        "nonce": b64(&[0u8; 24]),
        "sender_public_key": b64(&pk_s),
    });
    let r = c
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&reg.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_message_rejects_sender_pk_mismatch() {
    let (c, base) = boot().await;
    let (pk_s, _) = make_pubkey(9);
    let reg = register(&c, &base, &pk_s).await;
    let (pk_r, fp_r) = make_pubkey(10);
    register(&c, &base, &pk_r).await;

    let wrong_pk = vec![0xFFu8; 32];
    let body = json!({
        "recipient_fingerprint": fp_r,
        "ciphertext": b64(b"hi"),
        "nonce": b64(&[0u8; 24]),
        "sender_public_key": b64(&wrong_pk),
    });
    let r = c
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&reg.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_message_404_when_recipient_unknown() {
    let (c, base) = boot().await;
    let (pk_s, _) = make_pubkey(11);
    let reg = register(&c, &base, &pk_s).await;

    let body = json!({
        "recipient_fingerprint": "f".repeat(64),
        "ciphertext": b64(b"hi"),
        "nonce": b64(&[0u8; 24]),
        "sender_public_key": b64(&pk_s),
    });
    let r = c
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&reg.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn post_message_413_when_too_large() {
    let (c, base) = boot().await;
    let (pk_s, _) = make_pubkey(12);
    let reg = register(&c, &base, &pk_s).await;
    let (pk_r, fp_r) = make_pubkey(13);
    register(&c, &base, &pk_r).await;

    // Ciphertext just over the default 256 KiB cap.
    let big = vec![0u8; 300_000];
    let body = json!({
        "recipient_fingerprint": fp_r,
        "ciphertext": b64(&big),
        "nonce": b64(&[0u8; 24]),
        "sender_public_key": b64(&pk_s),
    });
    let r = c
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&reg.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn post_message_happy_path_returns_id_and_timestamp() {
    let (c, base) = boot().await;
    let (pk_s, _) = make_pubkey(14);
    let reg_s = register(&c, &base, &pk_s).await;
    let (pk_r, fp_r) = make_pubkey(15);
    register(&c, &base, &pk_r).await;

    let body = json!({
        "recipient_fingerprint": fp_r,
        "ciphertext": b64(b"an encrypted payload"),
        "nonce": b64(&[7u8; 24]),
        "sender_public_key": b64(&pk_s),
    });
    let resp = c
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&reg_s.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let pr: PostMessageResponse = resp.json().await.unwrap();
    assert!(pr.id > 0);
    assert!(!pr.created_at.is_empty());
    assert!(!pr.expires_at.is_empty());
    // created_at should parse as RFC3339
    chrono::DateTime::parse_from_rfc3339(&pr.created_at).expect("RFC3339 ts");
}

#[tokio::test]
async fn get_messages_returns_only_own_inbox() {
    let (c, base) = boot().await;
    let (pk_a, _fp_a) = make_pubkey(16);
    let reg_a = register(&c, &base, &pk_a).await;
    let (pk_b, fp_b) = make_pubkey(17);
    let reg_b = register(&c, &base, &pk_b).await;

    // A -> B
    c.post(format!("{base}/v1/messages"))
        .bearer_auth(&reg_a.token)
        .json(&json!({
            "recipient_fingerprint": fp_b,
            "ciphertext": b64(b"hi b"),
            "nonce": b64(&[1u8; 24]),
            "sender_public_key": b64(&pk_a),
        }))
        .send()
        .await
        .unwrap();

    // B fetches inbox
    let resp: MessagesResponse = c
        .get(format!("{base}/v1/messages"))
        .bearer_auth(&reg_b.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.messages.len(), 1);
    assert_eq!(resp.messages[0].ciphertext, b64(b"hi b"));

    // A has an empty inbox (they were the sender, not recipient)
    let resp: MessagesResponse = c
        .get(format!("{base}/v1/messages"))
        .bearer_auth(&reg_a.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(resp.messages.is_empty(), "A inbox should be empty");
}

#[tokio::test]
async fn get_messages_respects_after_id_cursor() {
    let (c, base) = boot().await;
    let (pk_a, _) = make_pubkey(18);
    let reg_a = register(&c, &base, &pk_a).await;
    let (pk_b, fp_b) = make_pubkey(19);
    let reg_b = register(&c, &base, &pk_b).await;

    let mut ids = Vec::new();
    for i in 0..5u8 {
        let r = c
            .post(format!("{base}/v1/messages"))
            .bearer_auth(&reg_a.token)
            .json(&json!({
                "recipient_fingerprint": fp_b,
                "ciphertext": b64(&[i; 16]),
                "nonce": b64(&[i; 24]),
                "sender_public_key": b64(&pk_a),
            }))
            .send()
            .await
            .unwrap();
        let pr: PostMessageResponse = r.json().await.unwrap();
        ids.push(pr.id);
    }
    // Ask for everything after the 2nd id.
    let cursor = ids[1];
    let resp: MessagesResponse = c
        .get(format!("{base}/v1/messages?after_id={cursor}"))
        .bearer_auth(&reg_b.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.messages.len(), 3);
    assert!(resp.messages.iter().all(|m| m.id > cursor));
    assert!(
        resp.messages.windows(2).all(|w| w[0].id < w[1].id),
        "ids must be ascending"
    );
}

// ---------------------------------------------------------------- websocket

#[tokio::test]
async fn websocket_rejects_invalid_token() {
    let (_c, base) = boot().await;
    let ws_base = base.replace("http://", "ws://");
    let res = tokio_tungstenite::connect_async(format!("{ws_base}/v1/ws?token=bad")).await;
    assert!(res.is_err(), "expected connect to fail, got {res:?}");
}

#[tokio::test]
async fn websocket_delivers_new_message_notification() {
    let (c, base) = boot().await;
    let (pk_a, _fp_a) = make_pubkey(20);
    let reg_a = register(&c, &base, &pk_a).await;
    let (pk_b, fp_b) = make_pubkey(21);
    let reg_b = register(&c, &base, &pk_b).await;

    // B opens a websocket.
    let ws_url = Url::parse_with_params(
        &format!("{}/v1/ws", base.replace("http://", "ws://")),
        &[("token", reg_b.token.as_str())],
    )
    .unwrap();
    let (mut ws, _resp) = tokio_tungstenite::connect_async(ws_url.as_str())
        .await
        .expect("ws connect");

    // First frame is the hello envelope.
    let hello = timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("hello timed out")
        .expect("frame present")
        .expect("frame ok");
    let hello_txt = match hello {
        WsMessage::Text(t) => t,
        other => panic!("unexpected hello frame: {other:?}"),
    };
    let hv: serde_json::Value = serde_json::from_str(&hello_txt).unwrap();
    assert_eq!(hv["type"], "connected");
    assert_eq!(hv["fingerprint"], fp_b);

    // A sends B a message.
    let post_resp: PostMessageResponse = c
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&reg_a.token)
        .json(&json!({
            "recipient_fingerprint": fp_b,
            "ciphertext": b64(b"ping"),
            "nonce": b64(&[9u8; 24]),
            "sender_public_key": b64(&pk_a),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // B's websocket should see the notification frame.
    let notif = timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("notif timed out")
        .expect("frame present")
        .expect("frame ok");
    let txt = match notif {
        WsMessage::Text(t) => t,
        other => panic!("unexpected notif frame: {other:?}"),
    };
    let nv: serde_json::Value = serde_json::from_str(&txt).unwrap();
    assert_eq!(nv["type"], "new_message");
    assert_eq!(nv["id"], post_resp.id);
    ws.close(None).await.ok();
}

#[tokio::test]
async fn websocket_responds_to_ping_with_pong() {
    let (c, base) = boot().await;
    let (pk, _) = make_pubkey(22);
    let reg = register(&c, &base, &pk).await;

    let ws_url = Url::parse_with_params(
        &format!("{}/v1/ws", base.replace("http://", "ws://")),
        &[("token", reg.token.as_str())],
    )
    .unwrap();
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url.as_str())
        .await
        .expect("ws connect");

    // Consume hello
    let _ = timeout(Duration::from_secs(2), ws.next()).await.unwrap();

    ws.send(WsMessage::Text(r#"{"type":"ping"}"#.into()))
        .await
        .unwrap();
    let pong = timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("pong timed out")
        .unwrap()
        .unwrap();
    let pong_txt = match pong {
        WsMessage::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    };
    let pv: serde_json::Value = serde_json::from_str(&pong_txt).unwrap();
    assert_eq!(pv["type"], "pong");
    ws.close(None).await.ok();
}

// ---------------------------------------------------------------- stats

#[tokio::test]
async fn stats_counts_registered_identities() {
    let (c, base) = boot().await;
    for seed in [23u8, 24, 25] {
        let (pk, _) = make_pubkey(seed);
        register(&c, &base, &pk).await;
    }
    let s: serde_json::Value = c
        .get(format!("{base}/v1/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(s["registered_identities"], 3);
    assert_eq!(s["message_retention_days"], 7); // fresh_state's setting
}
