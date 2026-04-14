# 3233.io

End-to-end encrypted chat over a minimal **relay** server. Clients generate **NaCl `box`** key pairs in the browser; the server stores and forwards **ciphertext** only, with configurable offline retention. The web UI can target any deployment by **base URL** (self-host friendly).

**License:** [MIT](LICENSE) · **Protocol:** [docs/PROTOCOL.md](docs/PROTOCOL.md)

---

## Contents

- [Features](#features)
- [Repository layout](#repository-layout)
- [Quick start (Docker)](#quick-start-docker)
- [Development](#development)
- [Production build](#production-build)
- [Configuration](#configuration)
- [Cryptography](#cryptography)
- [Client behavior notes](#client-behavior-notes)
- [Protocol & API](#protocol--api)
- [Threat model](#threat-model)
- [Contributing](#contributing)

---

## Features

- **Encryption:** [TweetNaCl](https://tweetnacl.js.org/) — **NaCl `box`** (X25519 + XSalsa20-Poly1305). Plaintext never leaves the client in the clear.
- **Identity:** 64-character hex **fingerprint** per device; share invite links or keys from the **New chat** / **Keys** views.
- **Realtime + polling:** WebSocket hint for new mail, plus REST fetch; periodic refresh (~30s).
- **Local history:** Decrypted **Library** and per-thread **Chats** views; sent lines cached locally for thread display.
- **Unread:** Red indicator on sidebar threads when there is new incoming mail you have not opened on the **Chats** screen (cursor stored in `localStorage`).
- **Shortcuts (header):** New keys, copy invite link, copy address (fingerprint).

---

## Repository layout

| Path | Role |
|------|------|
| `server/` | Rust HTTP API + WebSocket + SQLite (`cargo` workspace) |
| `client/` | Vite + TypeScript SPA (`npm` workspace package) |
| `docs/PROTOCOL.md` | v1 wire format and REST/WebSocket semantics |
| `Dockerfile`, `docker-compose.yml` | Single-image / compose deployment |
| Root `package.json` | npm workspaces: `npm run dev` / `npm run build` delegate to `client/` |

---

## Quick start (Docker)

Set a strong `JWT_SECRET` and run:

```bash
docker compose up --build
```

Open `http://localhost:3233` — the UI is served by the same process when `STATIC_DIR` is set (as in the image). Register, share your **fingerprint** with contacts, paste theirs to open a chat. **Both parties must use the same relay** (or register on each host you use).

---

## Development

Use **two terminals** (do not paste both flows into one shell).

**Prerequisites:** [Rust](https://rustup.rs/) (stable), **Node.js 18+**, npm.

### Terminal 1 — API server

From repo root:

```bash
cd server
export JWT_SECRET=dev-secret
cargo run
```

Wait for `listening on http://...:3233` with no error after it.

**Port in use:** use another bind, then point the app **Server** tab at it:

```bash
export BIND=127.0.0.1:3333
export JWT_SECRET=dev-secret
cargo run
```

### Terminal 2 — web client

From **repository root** (recommended):

```bash
cd /path/to/3233.io
npm install
npm run dev
```

Or from `client/` only:

```bash
cd /path/to/3233.io/client
npm install
npm run dev
```

Open the URL Vite prints (often **http://localhost:5173/**). In dev the client defaults to **`http://127.0.0.1:3233`**; if you changed `BIND`, set **API base URL** under **Server** to match.

### Troubleshooting (dev)

| Symptom | What to try |
|--------|-------------|
| `npm: command not found` | Install Node.js (LTS); ensure `node` / `npm` on `PATH`. |
| `Could not read package.json` | Run commands from repo **root** or **`client/`**, not `server/`. |
| `cd: client: No such file or directory` | You are in `server/` — `cd ../client`. |
| Port **3233** busy | Stop the other process or set `BIND` (see above). |
| Port **5173** busy | `npm run dev -- --port 5174`. |
| API errors in browser | Server running; **Base URL** in app matches host/port. |
| LAN / another device | `npm run dev -- --host` and use Vite’s “Network” URL. |

---

## Production build

**Static client:**

```bash
npm install
npm run build
```

Output is under `client/dist/`. Point the server’s `STATIC_DIR` at that directory (or serve the folder with any static host and configure CORS / same-origin as needed).

**Server:** `cd server && cargo build --release` — binary in `server/target/release/` (see `Dockerfile` for a minimal container layout).

---

## Configuration

Server environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BIND` | `0.0.0.0:3233` | HTTP listen address |
| `DATABASE_URL` | `sqlite:data.db?mode=rwc` | SQLite connection string |
| `JWT_SECRET` | (dev default, **insecure**) | Symmetric key for JWTs |
| `JWT_EXPIRY_SEC` | `604800` | Session lifetime (seconds) |
| `MESSAGE_TTL_DAYS` | `14` | Offline ciphertext retention |
| `MAX_MESSAGE_BYTES` | `262144` | Max payload size (ciphertext + nonce + sender pubkey) |
| `STATIC_DIR` | unset | If set, serve the SPA and API on the same port |

---

## Cryptography

- **Construction:** NaCl **public-key `box`**: Curve25519 / X25519 key agreement and **XSalsa20-Poly1305** authenticated encryption.
- **Implementation:** `tweetnacl` in the browser (`client/src/crypto.ts`).
- **Keys:** Long-term keypairs; **no forward secrecy** in v1 — device compromise may expose past traffic for that identity.

---

## Client behavior notes

- **Storage:** Keys, session token, open chats, sent-message cache, last-read cursors, and server URL live in **`localStorage`** (same origin).
- **Message sounds:** A short beep plays on new incoming mail after you have interacted with the page once (browser autoplay policy).
- **Unread dots:** Cleared when you view that thread on the **Chats** tab (not when the app is on other tabs with the same thread “selected” in memory).

---

## Protocol & API

Full detail: **[docs/PROTOCOL.md](docs/PROTOCOL.md)** (`/v1/register`, `/v1/messages`, `/v1/ws`, fingerprints, JWT).

---

## Threat model

- **Server:** Sees metadata (registration, routing, sizes, timing). Does **not** see plaintext if clients behave correctly.
- **Transport:** Prefer **HTTPS / WSS** in production; otherwise bytes are visible on the wire.
- **Browser:** `localStorage` is readable by same-origin script; XSS or malware can exfiltrate keys.
- **Cryptography:** Long-term **NaCl box** keys; see [Cryptography](#cryptography).

---

## Contributing

Issues and PRs are welcome. Please keep changes focused; match existing style in Rust and TypeScript. For behavior changes, update **docs/PROTOCOL.md** if the wire API or identity rules change.

---

## License

MIT — see [LICENSE](LICENSE).
