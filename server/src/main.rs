use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use axum_extra::headers::authorization::{Authorization, Bearer};
use axum_extra::typed_header::TypedHeaderRejection;
use axum_extra::TypedHeader;
use chrono::{Duration, Utc};
use dashmap::DashMap;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
    jwt_secret: Arc<[u8]>,
    jwt_expiry_sec: i64,
    message_ttl_days: i64,
    max_message_bytes: usize,
    /// Per-recipient notify channel for new message ids.
    notify: Arc<DashMap<String, broadcast::Sender<i64>>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Deserialize)]
struct RegisterBody {
    public_key: String,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    fingerprint: String,
    token: String,
    expires_in: i64,
}

#[derive(Debug, Deserialize)]
struct PostMessageBody {
    recipient_fingerprint: String,
    ciphertext: String,
    nonce: String,
    sender_public_key: String,
}

#[derive(Debug, Serialize)]
struct PostMessageResponse {
    id: i64,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct GetMessagesQuery {
    after_id: Option<i64>,
    limit: Option<i64>,
}

#[derive(Debug, Serialize)]
struct MessageRow {
    id: i64,
    sender_fingerprint: Option<String>,
    ciphertext: String,
    nonce: String,
    sender_public_key: String,
    created_at: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct MessagesResponse {
    messages: Vec<MessageRow>,
}

#[derive(Debug, Serialize)]
struct MeResponse {
    fingerprint: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct WsQuery {
    token: String,
}

fn fingerprint_from_pubkey(pubkey: &[u8]) -> Result<String, ()> {
    if pubkey.len() != 32 {
        return Err(());
    }
    let mut h = Sha256::new();
    h.update(pubkey);
    Ok(hex::encode(h.finalize()))
}

fn is_hex_fingerprint(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn decode_base64_32(data: &str) -> Result<Vec<u8>, ()> {
    decode_base64_len(data, 32)
}

fn decode_base64_len(data: &str, len: usize) -> Result<Vec<u8>, ()> {
    let v = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data)
        .or_else(|_| {
            base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                data,
            )
        })
        .map_err(|_| ())?;
    if v.len() != len {
        return Err(());
    }
    Ok(v)
}

impl AppState {
    fn sign_jwt(&self, fingerprint: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let exp = (Utc::now() + Duration::seconds(self.jwt_expiry_sec)).timestamp() as usize;
        let claims = Claims {
            sub: fingerprint.to_string(),
            exp,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.jwt_secret),
        )
    }

    fn verify_jwt(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(&self.jwt_secret),
            &Validation::default(),
        )
        .map(|d| d.claims)
    }

    fn notify_recipient(&self, recipient: &str, id: i64) {
        if let Some(tx) = self.notify.get(recipient) {
            let _ = tx.send(id);
        }
    }
}

async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterBody>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    let pk = decode_base64_32(&body.public_key).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "invalid public_key".to_string(),
        )
    })?;
    let fingerprint = fingerprint_from_pubkey(&pk).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "invalid public_key".to_string(),
        )
    })?;

    let now = Utc::now().to_rfc3339();
    let r = sqlx::query(
        r#"INSERT INTO users (fingerprint, pubkey, created_at, last_seen)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen"#,
    )
    .bind(&fingerprint)
    .bind(&pk)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(internal)?;

    if r.rows_affected() == 0 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "register failed".to_string(),
        ));
    }

    let token = state
        .sign_jwt(&fingerprint)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(RegisterResponse {
        fingerprint: fingerprint.clone(),
        token,
        expires_in: state.jwt_expiry_sec,
    }))
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    tracing::error!("{e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error".to_string(),
    )
}

async fn post_message(
    State(state): State<AppState>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    Json(body): Json<PostMessageBody>,
) -> Result<(StatusCode, Json<PostMessageResponse>), (StatusCode, String)> {
    let auth = auth.map_err(|_| (StatusCode::UNAUTHORIZED, "missing Authorization".to_string()))?;
    let claims = state
        .verify_jwt(auth.token())
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token".to_string()))?;

    if !is_hex_fingerprint(&body.recipient_fingerprint) {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid recipient_fingerprint".to_string(),
        ));
    }

    let ct = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.ciphertext)
        .or_else(|_| {
            base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &body.ciphertext,
            )
        })
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid ciphertext".to_string()))?;

    let nonce = decode_base64_len(&body.nonce, 24).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "invalid nonce (expect 24 bytes base64)".to_string(),
        )
    })?;

    let sender_pk = decode_base64_32(&body.sender_public_key).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "invalid sender_public_key".to_string(),
        )
    })?;

    let total = ct.len() + nonce.len() + sender_pk.len();
    if total > state.max_message_bytes {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "message too large".to_string()));
    }

    // Ensure sender JWT matches claimed public key
    let row = sqlx::query_as::<_, (Vec<u8>,)>("SELECT pubkey FROM users WHERE fingerprint = ?")
        .bind(&claims.sub)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?;

    let Some((stored_pk,)) = row else {
        return Err((StatusCode::UNAUTHORIZED, "unknown user".to_string()));
    };
    if stored_pk != sender_pk {
        return Err((
            StatusCode::BAD_REQUEST,
            "sender_public_key does not match token identity".to_string(),
        ));
    }

    let recipient_row = sqlx::query_as::<_, (Vec<u8>,)>(
        "SELECT pubkey FROM users WHERE fingerprint = ?",
    )
    .bind(&body.recipient_fingerprint)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;

    if recipient_row.is_none() {
        return Err((StatusCode::NOT_FOUND, "recipient not registered".to_string()));
    }

    let created = Utc::now();
    let expires = created + Duration::days(state.message_ttl_days);
    let created_s = created.to_rfc3339();
    let expires_s = expires.to_rfc3339();

    let r = sqlx::query(
        r#"INSERT INTO messages
        (recipient_fingerprint, sender_fingerprint, ciphertext, nonce, sender_pubkey, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&body.recipient_fingerprint)
    .bind(&claims.sub)
    .bind(&ct)
    .bind(&nonce)
    .bind(&sender_pk)
    .bind(&created_s)
    .bind(&expires_s)
    .execute(&state.pool)
    .await
    .map_err(internal)?;

    let id = r.last_insert_rowid();
    state.notify_recipient(&body.recipient_fingerprint, id);

    Ok((
        StatusCode::CREATED,
        Json(PostMessageResponse {
            id,
            expires_at: expires_s,
        }),
    ))
}

async fn get_messages(
    State(state): State<AppState>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    Query(q): Query<GetMessagesQuery>,
) -> Result<Json<MessagesResponse>, (StatusCode, String)> {
    let auth = auth.map_err(|_| (StatusCode::UNAUTHORIZED, "missing Authorization".to_string()))?;
    let claims = state
        .verify_jwt(auth.token())
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token".to_string()))?;

    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let after = q.after_id.unwrap_or(0);

    let rows = sqlx::query_as::<_, (i64, Option<String>, Vec<u8>, Vec<u8>, Vec<u8>, String, String)>(
        r#"SELECT id, sender_fingerprint, ciphertext, nonce, sender_pubkey, created_at, expires_at
           FROM messages
           WHERE recipient_fingerprint = ? AND id > ?
           ORDER BY id ASC
           LIMIT ?"#,
    )
    .bind(&claims.sub)
    .bind(after)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;

    let messages = rows
        .into_iter()
        .map(
            |(id, sender_fp, ct, nonce, spk, created_at, expires_at)| MessageRow {
                id,
                sender_fingerprint: sender_fp,
                ciphertext: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &ct,
                ),
                nonce: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &nonce,
                ),
                sender_public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &spk,
                ),
                created_at,
                expires_at,
            },
        )
        .collect();

    Ok(Json(MessagesResponse { messages }))
}

async fn get_public_key(
    State(state): State<AppState>,
    Path(fp): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !is_hex_fingerprint(&fp) {
        return Err((StatusCode::BAD_REQUEST, "invalid fingerprint".to_string()));
    }
    let row = sqlx::query_as::<_, (Vec<u8>,)>("SELECT pubkey FROM users WHERE fingerprint = ?")
        .bind(&fp)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?;
    let Some((pk,)) = row else {
        return Err((StatusCode::NOT_FOUND, "unknown user".to_string()));
    };
    Ok(Json(serde_json::json!({
        "public_key": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pk),
    })))
}

async fn get_stats(State(state): State<AppState>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "registered_identities": row.0,
        "message_retention_days": state.message_ttl_days
    })))
}

async fn get_me(
    State(state): State<AppState>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
) -> Result<Json<MeResponse>, (StatusCode, String)> {
    let auth = auth.map_err(|_| (StatusCode::UNAUTHORIZED, "missing Authorization".to_string()))?;
    let claims = state
        .verify_jwt(auth.token())
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token".to_string()))?;

    let row = sqlx::query_as::<_, (Vec<u8>,)>("SELECT pubkey FROM users WHERE fingerprint = ?")
        .bind(&claims.sub)
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?;

    let Some((pk,)) = row else {
        return Err((StatusCode::UNAUTHORIZED, "unknown user".to_string()));
    };

    Ok(Json(MeResponse {
        fingerprint: claims.sub,
        public_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &pk,
        ),
    }))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(q): Query<WsQuery>,
    State(state): State<AppState>,
) -> Result<Response, (StatusCode, String)> {
    let claims = state
        .verify_jwt(&q.token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token".to_string()))?;
    let fp = claims.sub;
    Ok(ws.on_upgrade(move |socket| handle_ws(socket, state, fp)))
}

async fn handle_ws(mut socket: WebSocket, state: AppState, fingerprint: String) {
    let mut rx = {
        let tx = state
            .notify
            .entry(fingerprint.clone())
            .or_insert_with(|| {
                let (t, _) = broadcast::channel(256);
                t
            })
            .clone();
        tx.subscribe()
    };

    let hello = serde_json::json!({
        "type": "connected",
        "fingerprint": fingerprint,
    });
    if socket
        .send(Message::Text(hello.to_string().into()))
        .await
        .is_err()
    {
        return;
    }

    loop {
        tokio::select! {
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                            if v.get("type").and_then(|x| x.as_str()) == Some("ping") {
                                let pong = serde_json::json!({ "type": "pong" });
                                if socket.send(Message::Text(pong.to_string().into())).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = socket.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            id = rx.recv() => {
                match id {
                    Ok(id) => {
                        let n = serde_json::json!({ "type": "new_message", "id": id });
                        if socket.send(Message::Text(n.to_string().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

async fn purge_expired(pool: SqlitePool) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let now = Utc::now().to_rfc3339();
        match sqlx::query("DELETE FROM messages WHERE expires_at < ?")
            .bind(&now)
            .execute(&pool)
            .await
        {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::info!("purged {} expired messages", r.rows_affected());
            }
            Err(e) => tracing::error!("purge failed: {e}"),
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url =
        env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:data.db?mode=rwc".to_string());
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!("JWT_SECRET not set; using insecure dev default");
        "dev-insecure-change-me".to_string()
    });
    let jwt_expiry_sec: i64 = env::var("JWT_EXPIRY_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(604800);
    let message_ttl_days: i64 = env::var("MESSAGE_TTL_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(14);
    let max_message_bytes: usize = env::var("MAX_MESSAGE_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(262_144);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let state = AppState {
        pool: pool.clone(),
        jwt_secret: Arc::from(jwt_secret.into_bytes()),
        jwt_expiry_sec,
        message_ttl_days,
        max_message_bytes,
        notify: Arc::new(DashMap::new()),
    };

    tokio::spawn(purge_expired(pool));

    let api = Router::new()
        .route("/v1/register", post(register))
        .route("/v1/messages", post(post_message).get(get_messages))
        .route("/v1/me", get(get_me))
        .route("/v1/stats", get(get_stats))
        .route("/v1/keys/{fingerprint}", get(get_public_key))
        .route("/v1/ws", get(ws_handler))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let app = if let Ok(dir) = env::var("STATIC_DIR") {
        Router::new()
            .merge(api)
            .fallback_service(ServeDir::new(dir))
    } else {
        api
    };

    let bind = env::var("BIND").unwrap_or_else(|_| "0.0.0.0:3233".to_string());
    let addr: SocketAddr = bind.parse()?;
    tracing::info!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
