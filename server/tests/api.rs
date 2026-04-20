//! Integration tests against a live in-memory axum app.
//!
//! Each test spins up a fresh server backed by `sqlite::memory:` on an
//! ephemeral port, then talks to it over real HTTP / WebSocket. No shared
//! global state — tests are isolated and safe to run in parallel.

use base64::Engine;
use crypto_box::{
    aead::{Aead, AeadCore, OsRng as BoxOsRng},
    PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey,
};
use futures_util::{SinkExt, StreamExt};
use io3233_server::{
    test_support::{fresh_state, spawn_app},
    MeResponse, MessagesResponse, PostMessageResponse, RegisterChallengeResponse,
    RegisterResponse,
};
use rand::{rngs::StdRng, SeedableRng};
use reqwest::StatusCode;
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use url::Url;

fn b64(buf: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(buf)
}

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// Deterministic test keypair: real Curve25519 so proof-of-possession works,
/// but seeded per test to keep fingerprints stable.
struct Keypair {
    sk: BoxSecretKey,
    pk_bytes: Vec<u8>,
    fp: String,
}

fn make_keypair(seed: u8) -> Keypair {
    let mut rng = StdRng::from_seed([seed; 32]);
    let sk = BoxSecretKey::generate(&mut rng);
    let pk_bytes = sk.public_key().as_bytes().to_vec();
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&pk_bytes);
    let fp = hex::encode(h.finalize());
    Keypair { sk, pk_bytes, fp }
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

/// Full two-step registration (challenge → PoP-authenticated register).
async fn register(
    client: &reqwest::Client,
    base: &str,
    kp: &Keypair,
) -> RegisterResponse {
    let chal_resp = client
        .post(format!("{base}/v1/register/challenge"))
        .json(&json!({ "public_key": b64(&kp.pk_bytes) }))
        .send()
        .await
        .unwrap();
    assert_eq!(chal_resp.status(), StatusCode::OK, "challenge status");
    let chal: RegisterChallengeResponse = chal_resp.json().await.unwrap();

    let server_pk_arr: [u8; 32] = b64d(&chal.server_public_key).try_into().unwrap();
    let server_pk = BoxPublicKey::from(server_pk_arr);
    let bx = SalsaBox::new(&server_pk, &kp.sk);
    let nonce = SalsaBox::generate_nonce(&mut BoxOsRng);
    let ct = bx.encrypt(&nonce, b64d(&chal.challenge).as_slice()).unwrap();

    let resp = client
        .post(format!("{base}/v1/register"))
        .json(&json!({
            "public_key": b64(&kp.pk_bytes),
            "challenge": chal.challenge,
            "proof_nonce": b64(nonce.as_slice()),
            "proof_ciphertext": b64(&ct),
        }))
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
    let kp = make_keypair(1);
    let r = register(&c, &base, &kp).await;
    assert_eq!(r.fingerprint, kp.fp);
    assert!(!r.token.is_empty());
    assert!(r.expires_in > 0);
}

#[tokio::test]
async fn register_is_idempotent_for_same_pubkey() {
    let (c, base) = boot().await;
    let kp = make_keypair(2);
    let a = register(&c, &base, &kp).await;
    let b = register(&c, &base, &kp).await;
    assert_eq!(a.fingerprint, b.fingerprint);
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
async fn register_challenge_rejects_invalid_public_key() {
    let (c, base) = boot().await;
    for bad in [
        json!({ "public_key": "!!not-base64!!" }),
        json!({ "public_key": b64(&[0u8; 16]) }),
        json!({ "public_key": b64(&[0u8; 64]) }),
    ] {
        let r = c
            .post(format!("{base}/v1/register/challenge"))
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "rejected: {bad:?}");
    }
}

#[tokio::test]
async fn register_without_challenge_is_rejected() {
    let (c, base) = boot().await;
    let kp = make_keypair(30);
    let nonce = [0u8; 24];
    let r = c
        .post(format!("{base}/v1/register"))
        .json(&json!({
            "public_key": b64(&kp.pk_bytes),
            "challenge": b64(&[0u8; 32]),
            "proof_nonce": b64(&nonce),
            "proof_ciphertext": b64(&[0u8; 48]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_rejects_wrong_proof_of_possession() {
    let (c, base) = boot().await;
    let kp = make_keypair(31);
    let imposter = make_keypair(32);

    let chal: RegisterChallengeResponse = c
        .post(format!("{base}/v1/register/challenge"))
        .json(&json!({ "public_key": b64(&kp.pk_bytes) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Imposter tries to register kp's public key: they don't hold kp.sk,
    // so encrypting with imposter.sk will not decrypt as kp against server_sk.
    let server_pk_arr: [u8; 32] = b64d(&chal.server_public_key).try_into().unwrap();
    let server_pk = BoxPublicKey::from(server_pk_arr);
    let bx = SalsaBox::new(&server_pk, &imposter.sk);
    let nonce = SalsaBox::generate_nonce(&mut BoxOsRng);
    let ct = bx.encrypt(&nonce, b64d(&chal.challenge).as_slice()).unwrap();

    let r = c
        .post(format!("{base}/v1/register"))
        .json(&json!({
            "public_key": b64(&kp.pk_bytes),
            "challenge": chal.challenge,
            "proof_nonce": b64(nonce.as_slice()),
            "proof_ciphertext": b64(&ct),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_challenge_is_single_use() {
    let (c, base) = boot().await;
    let kp = make_keypair(33);

    let chal: RegisterChallengeResponse = c
        .post(format!("{base}/v1/register/challenge"))
        .json(&json!({ "public_key": b64(&kp.pk_bytes) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let server_pk_arr: [u8; 32] = b64d(&chal.server_public_key).try_into().unwrap();
    let server_pk = BoxPublicKey::from(server_pk_arr);
    let bx = SalsaBox::new(&server_pk, &kp.sk);
    let nonce = SalsaBox::generate_nonce(&mut BoxOsRng);
    let ct = bx.encrypt(&nonce, b64d(&chal.challenge).as_slice()).unwrap();

    let body = json!({
        "public_key": b64(&kp.pk_bytes),
        "challenge": chal.challenge,
        "proof_nonce": b64(nonce.as_slice()),
        "proof_ciphertext": b64(&ct),
    });

    let first = c
        .post(format!("{base}/v1/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = c
        .post(format!("{base}/v1/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------- me

#[tokio::test]
async fn me_requires_auth_and_returns_self() {
    let (c, base) = boot().await;
    let kp = make_keypair(3);
    let reg = register(&c, &base, &kp).await;

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
    assert_eq!(me.fingerprint, kp.fp);
    assert_eq!(me.public_key, b64(&kp.pk_bytes));
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
    let kp = make_keypair(4);
    register(&c, &base, &kp).await;

    let r: serde_json::Value = c
        .get(format!("{base}/v1/keys/{}", kp.fp))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["public_key"], b64(&kp.pk_bytes));
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
    let kp = make_keypair(5);
    register(&c, &base, &kp).await;
    let kp2 = make_keypair(6);
    register(&c, &base, &kp2).await;

    let prefix = &kp.fp[..8];
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
    assert!(fps.contains(&kp.fp), "got {fps:?}");
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
    let kp_r = make_keypair(7);
    register(&c, &base, &kp_r).await;

    let body = json!({
        "recipient_fingerprint": kp_r.fp,
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
    let kp_s = make_keypair(8);
    let reg = register(&c, &base, &kp_s).await;

    let body = json!({
        "recipient_fingerprint": "not-hex",
        "ciphertext": b64(b"hi"),
        "nonce": b64(&[0u8; 24]),
        "sender_public_key": b64(&kp_s.pk_bytes),
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
    let kp_s = make_keypair(9);
    let reg = register(&c, &base, &kp_s).await;
    let kp_r = make_keypair(10);
    register(&c, &base, &kp_r).await;

    let wrong_pk = vec![0xFFu8; 32];
    let body = json!({
        "recipient_fingerprint": kp_r.fp,
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
    let kp_s = make_keypair(11);
    let reg = register(&c, &base, &kp_s).await;

    let body = json!({
        "recipient_fingerprint": "f".repeat(64),
        "ciphertext": b64(b"hi"),
        "nonce": b64(&[0u8; 24]),
        "sender_public_key": b64(&kp_s.pk_bytes),
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
    let kp_s = make_keypair(12);
    let reg = register(&c, &base, &kp_s).await;
    let kp_r = make_keypair(13);
    register(&c, &base, &kp_r).await;

    let big = vec![0u8; 300_000];
    let body = json!({
        "recipient_fingerprint": kp_r.fp,
        "ciphertext": b64(&big),
        "nonce": b64(&[0u8; 24]),
        "sender_public_key": b64(&kp_s.pk_bytes),
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
    let kp_s = make_keypair(14);
    let reg_s = register(&c, &base, &kp_s).await;
    let kp_r = make_keypair(15);
    register(&c, &base, &kp_r).await;

    let body = json!({
        "recipient_fingerprint": kp_r.fp,
        "ciphertext": b64(b"an encrypted payload"),
        "nonce": b64(&[7u8; 24]),
        "sender_public_key": b64(&kp_s.pk_bytes),
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
    chrono::DateTime::parse_from_rfc3339(&pr.created_at).expect("RFC3339 ts");
}

#[tokio::test]
async fn get_messages_returns_only_own_inbox() {
    let (c, base) = boot().await;
    let kp_a = make_keypair(16);
    let reg_a = register(&c, &base, &kp_a).await;
    let kp_b = make_keypair(17);
    let reg_b = register(&c, &base, &kp_b).await;

    c.post(format!("{base}/v1/messages"))
        .bearer_auth(&reg_a.token)
        .json(&json!({
            "recipient_fingerprint": kp_b.fp,
            "ciphertext": b64(b"hi b"),
            "nonce": b64(&[1u8; 24]),
            "sender_public_key": b64(&kp_a.pk_bytes),
        }))
        .send()
        .await
        .unwrap();

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
    let kp_a = make_keypair(18);
    let reg_a = register(&c, &base, &kp_a).await;
    let kp_b = make_keypair(19);
    let reg_b = register(&c, &base, &kp_b).await;

    let mut ids = Vec::new();
    for i in 0..5u8 {
        let r = c
            .post(format!("{base}/v1/messages"))
            .bearer_auth(&reg_a.token)
            .json(&json!({
                "recipient_fingerprint": kp_b.fp,
                "ciphertext": b64(&[i; 16]),
                "nonce": b64(&[i; 24]),
                "sender_public_key": b64(&kp_a.pk_bytes),
            }))
            .send()
            .await
            .unwrap();
        let pr: PostMessageResponse = r.json().await.unwrap();
        ids.push(pr.id);
    }
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
    let kp_a = make_keypair(20);
    let reg_a = register(&c, &base, &kp_a).await;
    let kp_b = make_keypair(21);
    let reg_b = register(&c, &base, &kp_b).await;

    let ws_url = Url::parse_with_params(
        &format!("{}/v1/ws", base.replace("http://", "ws://")),
        &[("token", reg_b.token.as_str())],
    )
    .unwrap();
    let (mut ws, _resp) = tokio_tungstenite::connect_async(ws_url.as_str())
        .await
        .expect("ws connect");

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
    assert_eq!(hv["fingerprint"], kp_b.fp);

    let post_resp: PostMessageResponse = c
        .post(format!("{base}/v1/messages"))
        .bearer_auth(&reg_a.token)
        .json(&json!({
            "recipient_fingerprint": kp_b.fp,
            "ciphertext": b64(b"ping"),
            "nonce": b64(&[9u8; 24]),
            "sender_public_key": b64(&kp_a.pk_bytes),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

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
    let kp = make_keypair(22);
    let reg = register(&c, &base, &kp).await;

    let ws_url = Url::parse_with_params(
        &format!("{}/v1/ws", base.replace("http://", "ws://")),
        &[("token", reg.token.as_str())],
    )
    .unwrap();
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url.as_str())
        .await
        .expect("ws connect");

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
        let kp = make_keypair(seed);
        register(&c, &base, &kp).await;
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
    assert_eq!(s["message_retention_days"], 7);
}
