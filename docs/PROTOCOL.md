# 3233.io protocol (v1)

End-to-end encrypted relay. Servers store **only ciphertext** and routing metadata. Identity is an X25519 **public key**; a human-readable **fingerprint** is derived for display and lookup.

## Identity

- **Public key**: 32 bytes, Curve25519 (same form as NaCl `crypto_box` keys).
- **Identity hash**: `SHA-256(public_key)` (32 bytes).
- **Fingerprint (canonical API id)**: lowercase hex of the full identity hash (64 hex characters). Used in URLs and JSON as `fingerprint` / `recipient_fingerprint` / `sender_fingerprint`.
- **Short display**: `3233:` + first 16 bytes of identity hash as hex (32 hex chars), for UI only.

Clients **never** send private keys to the server.

## Transport

- **HTTPS** for REST (`/v1/...`).
- **WSS** for WebSocket (`/v1/ws`).
- Production deployments should terminate TLS (reverse proxy or built-in TLS). Local dev may use plain HTTP/WS.

## Authentication

After registration, clients send:

```http
Authorization: Bearer <JWT>
```

JWT `sub` claim is the user’s **fingerprint** (64 hex chars). Tokens are issued by the server using `JWT_SECRET`, which **must** be set to a 32+ byte value in production (the server refuses to start otherwise unless `ALLOW_INSECURE_JWT_SECRET=1` is explicitly set — see `server/README` / environment vars below).

## Rate limits

The server enforces a per-IP leaky-bucket limiter on all public endpoints
(capacity 60 requests, refill 1 req/sec). Buckets are partitioned by endpoint
class (`/v1/register*`, `/v1/keys*`, `/v1/stats`, other) so a noisy registration
flow cannot starve lookups. Rejected requests get `429 Too Many Requests`. If
the server is behind a trusted reverse proxy, set `TRUST_FORWARDED_FOR=1` so
the limiter keys off `X-Forwarded-For` rather than the TCP peer.

## REST API

Base path: `/v1`.

### `POST /v1/register/challenge`

Requests a single-use proof-of-possession challenge for the given public key.
The challenge is stored server-side for ~60 s, bound to the caller's
fingerprint, and consumed (or expires unused) by the next `/v1/register` call.

**Request JSON:**

| Field         | Type   | Description                                        |
|---------------|--------|----------------------------------------------------|
| `public_key`  | string | Base64 (standard or URL-safe) 32-byte public key   |

**Response 200:**

| Field               | Type   | Description                                  |
|---------------------|--------|----------------------------------------------|
| `challenge`         | string | Base64, 32 random bytes                      |
| `server_public_key` | string | Base64, 32-byte X25519 key to encrypt to     |
| `expires_in`        | number | Seconds until the challenge is purged        |

**Errors:** `400` invalid key, `429` rate limited.

### `POST /v1/register`

Completes registration with a proof-of-possession of the caller's secret key,
then returns a session token. The client proves possession by NaCl-boxing the
challenge bytes to `server_public_key` with `(client_sk, server_pk)`; the
server decrypts with `(server_sk, client_pk)`, confirming the caller holds the
private half of `public_key` without ever exchanging it.

**Request JSON:**

| Field               | Type   | Description                                            |
|---------------------|--------|--------------------------------------------------------|
| `public_key`        | string | Base64 32-byte public key (same as challenge request)  |
| `challenge`         | string | Base64 32-byte challenge echoed back verbatim          |
| `proof_nonce`       | string | Base64 24-byte NaCl box nonce                          |
| `proof_ciphertext`  | string | Base64 `box(challenge, proof_nonce, server_pk, client_sk)` — 48 bytes (32 + 16 tag) |

**Response 200:**

| Field         | Type   |
|---------------|--------|
| `fingerprint` | string | 64-char hex identity               |
| `token`       | string | JWT for `Authorization` header     |
| `expires_in`  | number | Token TTL seconds (informational)  |

**Errors:** `400` invalid payload / no pending challenge / challenge expired /
challenge mismatch, `401` proof-of-possession failed (decryption or plaintext
mismatch), `429` rate limited.

### `POST /v1/messages`

Queues an encrypted message for a recipient. Sender is taken from the JWT.

**Request JSON:**

| Field                  | Type   | Description                                        |
|------------------------|--------|----------------------------------------------------|
| `recipient_fingerprint`| string | 64 hex chars                                       |
| `ciphertext`           | string | Base64: NaCl `box` ciphertext (not including nonce if separate) |
| `nonce`                | string | Base64, 24 bytes                                   |
| `sender_public_key`    | string | Base64, 32 bytes (required for NaCl box open)      |

**Response 201:**

| Field        | Type   |
|--------------|--------|
| `id`         | number | Server message id                                  |
| `expires_at` | string | RFC3339 UTC                                        |

**Errors:** `400` validation, `401` missing/invalid token, `404` unknown recipient (if server enforces known recipients), `413` payload too large, `429` rate limited.

### `GET /v1/messages`

Fetch messages addressed to the authenticated user (recipient = JWT `sub`).

**Query:**

| Param      | Description                                      |
|------------|--------------------------------------------------|
| `after_id` | Optional. Return messages with `id` > `after_id` |
| `limit`    | Optional, default 50, max 200                    |

**Response 200:**

```json
{
  "messages": [
    {
      "id": 1,
      "sender_fingerprint": "64hex or null",
      "ciphertext": "base64",
      "nonce": "base64",
      "sender_public_key": "base64",
      "created_at": "RFC3339",
      "expires_at": "RFC3339"
    }
  ]
}
```

`sender_fingerprint` is stored if the sender was registered; otherwise null.

### `GET /v1/me`

**Response 200:** `{ "fingerprint": "...", "public_key": "base64" }` for the authenticated identity.

### `GET /v1/stats`

Public aggregate stats for this server instance. No auth.

**Response 200:**

| Field | Description |
|-------|-------------|
| `registered_identities` | Count of distinct public keys ever registered (rows in `users`). |
| `message_retention_days` | Server config: days until queued offline messages are deleted (`MESSAGE_TTL_DAYS`). |

### `GET /v1/keys/:fingerprint`

Returns a registered user’s **public key** (needed for NaCl `box` encryption). Public information; no auth required.

**Response 200:** `{ "public_key": "base64" }`

**Errors:** `400` invalid fingerprint, `404` not registered.

### Errors (common)

| Code | Meaning              |
|------|----------------------|
| 400  | Bad request / validation |
| 401  | Unauthorized         |
| 404  | Not found            |
| 413  | Payload too large    |
| 429  | Too many requests    |
| 500  | Server error         |

## WebSocket `/v1/ws`

**Query:** `token=<JWT>` (same token as REST).

After connect, server accepts JSON **client → server** frames:

| Type       | Purpose                                      |
|------------|----------------------------------------------|
| `ping`     | `{ "type": "ping" }` — presence heartbeat    |
| `subscribe`| Optional `{ "type": "subscribe" }` — receive push |

**Server → client** frames:

| Type            | Purpose                                                |
|-----------------|--------------------------------------------------------|
| `connected`     | `{ "type": "connected", "fingerprint": "..." }`        |
| `pong`          | Response to `ping`                                     |
| `new_message`   | `{ "type": "new_message", "id": <number> }` — hint to call `GET /v1/messages` |

Idle clients should reconnect with exponential backoff.

## Message retention (TTL)

- Each stored message has `expires_at = created_at + TTL`.
- Default TTL: **14 days**, configurable server-side (`MESSAGE_TTL_DAYS`).
- Expired rows are deleted by a background job; clients should tolerate disappearing message ids.

## Client-side encryption (NaCl box)

- **Encrypt** (sender): `crypto_box(plaintext, nonce, recipient_pk, sender_sk)`.
- **Decrypt** (recipient): `crypto_box_open(ciphertext, nonce, sender_pk, recipient_sk)`.
- **Nonce**: 24 random bytes per message; sent alongside ciphertext.
- Plaintext is UTF-8 JSON for the chat app, e.g. `{ "text": "hello", "ts": 1234567890 }` (application layer).

## Versioning

- API prefix `/v1`. Breaking changes require `/v2`, etc.
