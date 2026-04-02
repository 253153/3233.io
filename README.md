# 3233.io

FOSS end-to-end encrypted chat relay: clients hold X25519 key pairs (NaCl `box`), servers store **ciphertext** only with a configurable time-to-live for offline delivery. Anyone can self-host a server; the web client can point at any base URL.

## Quick start (Docker)

Set a strong `JWT_SECRET` and run:

```bash
docker compose up --build
```

Open `http://localhost:3233` — the UI is served by the same process when `STATIC_DIR` is set (as in the image). Register, share your **fingerprint** (64 hex chars) with contacts, paste theirs when sending, and both sides must use the **same server** (or register on each host you use).

## Development

Use **two separate terminal windows/tabs** (do not paste “Terminal 1” and “Terminal 2” into the same shell).

**Prerequisites:** [Rust](https://rustup.rs/) (for the server), **Node.js 18+** and npm (for the client).

**Terminal 1 — API server** (from repo root `3233.io/`):

```bash
cd server
export JWT_SECRET=dev-secret
cargo run
```

Wait until you see `listening on http://...:3233` **with no error after it**. If you see `Address already in use` (port **3233**), another process is using that port; stop it or pick another port:

```bash
# Example: run on 3333 instead (then set Base URL in the app to http://127.0.0.1:3333)
export BIND=127.0.0.1:3333
export JWT_SECRET=dev-secret
cargo run
```

On Linux you can see what holds 3233: `ss -tlnp | grep 3233` or `fuser -k 3233/tcp` (kills the process using that port).

**Terminal 2 — web client**

Either from the **repository root** (recommended):

```bash
cd /path/to/3233.io
npm install
npm run dev
```

Or from the **`client`** folder only (must be this folder, **not** `server`):

```bash
cd /path/to/3233.io/client
npm install
npm run dev
```

If you are inside `server/`, there is no `client` subfolder — use `cd ../client` instead of `cd client`.

Open the URL Vite prints (usually **http://localhost:5173/**). The UI calls **`http://127.0.0.1:3233`** in dev; if you changed `BIND`, set **Base URL** in the app to match.

**If something goes wrong**

| Symptom | What to try |
|--------|-------------|
| `npm: command not found` | Install Node.js (LTS) so `node` and `npm` are on your `PATH`. |
| `Could not read package.json` / `ENOENT` | Run `npm install` / `npm run dev` from the **repo root** (`npm run dev`) or from **`client/`**, not from `server/`. |
| `cd: client: No such file or directory` | You are in `server/`. Use `cd ../client` or open a new shell in the repo root. |
| `Address already in use` (port **3233**) | Stop the other server or set `BIND` to another port (see above). |
| Port **5173** already in use | `npm run dev -- --port 5174` and open the printed URL. |
| Browser errors talking to the API | Confirm Terminal 1 is running and the app **Base URL** matches the server host/port. |
| Need access from another device on LAN | `npm run dev -- --host` and use the “Network” URL Vite shows. |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BIND` | `0.0.0.0:3233` | HTTP listen address |
| `DATABASE_URL` | `sqlite:data.db?mode=rwc` | SQLite connection string |
| `JWT_SECRET` | (dev default, **insecure**) | Symmetric key for session tokens |
| `JWT_EXPIRY_SEC` | `604800` | Session JWT lifetime (7 days) |
| `MESSAGE_TTL_DAYS` | `14` | Offline message retention |
| `MAX_MESSAGE_BYTES` | `262144` | Max total ciphertext + nonce + sender pubkey per message |
| `STATIC_DIR` | unset | If set, serve static files (SPA) and API on the same port |

## Protocol

See [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Threat model (honest summary)

- **Server**: Sees metadata (who is registered, who sends to whom, message sizes, timing). It does **not** see plaintext if clients behave correctly.
- **TLS**: Use HTTPS/WSS in production; otherwise transport is visible to the network.
- **Browser**: Keys live in `localStorage`; malware or XSS can steal keys. For higher assurance, use a future desktop wrapper with a safer key store.
- **Cryptography**: v1 uses **NaCl `box`** with long-term keys; compromise of a device key may expose past messages for that identity. Forward secrecy is not implemented yet.

## License

MIT — see [LICENSE](LICENSE).
