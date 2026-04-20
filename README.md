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
  - [Running without Docker](#running-without-docker)
  - [Process management](#process-management)
- [Hosting on Debian with nginx (VPS)](#hosting-on-debian-with-nginx-vps)
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
- **Browser notifications:** Opt-in via the bell toggle in the footer. Fires on incoming messages when the tab is backgrounded or you're not viewing that thread; suppressed while you are. Clicking the notification focuses the tab and jumps to the sender's chat. Message previews are decrypted **client-side only**; the server never sees plaintext.
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
export ALLOW_INSECURE_JWT_SECRET=1  # local dev only — ok for throwaway tokens
cargo run
```

Wait for `listening on http://...:3233` with no error after it.

For anything non-throwaway, export a real secret instead of the escape hatch:

```bash
export JWT_SECRET=$(openssl rand -hex 32)
cargo run
```

The server refuses to start when `JWT_SECRET` is missing or shorter than
32 bytes, unless `ALLOW_INSECURE_JWT_SECRET=1` is set. Do not use that flag
for deployed instances.

**Port in use:** use another bind, then point the app **Server** tab at it:

```bash
export BIND=127.0.0.1:3333
export JWT_SECRET=$(openssl rand -hex 32)
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
| `cargo: command not found` | Install Rust via [rustup.rs](https://rustup.rs/); restart your shell. |
| `Could not read package.json` | Run commands from repo **root** or **`client/`**, not `server/`. |
| `cd: client: No such file or directory` | You are in `server/` — `cd ../client`. |
| Port **3233** busy | `ss -lptn 'sport = :3233'` to see what holds the port; `fuser -k 3233/tcp` to kill it. |
| Port **5173** busy | `npm run dev -- --port 5174`. |
| API errors in browser | Server running; **Base URL** in app matches host/port. |
| Binary not found after build | The server binary is **`io3233-server`**, not `server`. Find it at `server/target/release/io3233-server`. |
| LAN / another device | `npm run dev -- --host` and use Vite’s “Network” URL. |

---

## Production build

**Static client:**

```bash
npm install
npm run build
```

Output is under `client/dist/`. Point the server's `STATIC_DIR` at that directory (or serve the folder with any static host and configure CORS / same-origin as needed).

**Server (binary):**

```bash
cd server
cargo build --release
```

The compiled binary is **`server/target/release/io3233-server`** (not `server`). Run it directly:

```bash
export JWT_SECRET=$(openssl rand -hex 32)
export STATIC_DIR=/path/to/3233.io/client/dist
./target/release/io3233-server
```

### Running without Docker

If Docker is not available, build the client and server from source (requires **Rust** and **Node.js**):

```bash
# Build client
cd /path/to/3233.io
npm install && npm run build

# Build server
cd server
cargo build --release

# Run
export JWT_SECRET=$(openssl rand -hex 32)
export STATIC_DIR=/path/to/3233.io/client/dist
export BIND=127.0.0.1:3233
./target/release/io3233-server
```

Put this behind **nginx** (see [Hosting on Debian with nginx](#hosting-on-debian-with-nginx-vps)) and optionally manage it with **systemd** (see below).

### Process management

**Check if port 3233 is already in use** before starting:

```bash
ss -lptn 'sport = :3233'
```

If something is listening, either stop it or pick a different `BIND` port:

```bash
# Find and kill the process using port 3233
fuser -k 3233/tcp
# Or on systems without fuser:
kill $(ss -lptn 'sport = :3233' | grep -oP 'pid=\K\d+')
```

**Optional: systemd unit** for automatic startup and restarts — create `/etc/systemd/system/3233.service`:

```ini
[Unit]
Description=3233.io encrypted relay
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/3233.io/server
ExecStart=/opt/3233.io/server/target/release/io3233-server
EnvironmentFile=/opt/3233.io/.env
Environment=BIND=127.0.0.1:3233
Environment=STATIC_DIR=/opt/3233.io/client/dist
Environment=DATABASE_URL=sqlite:/opt/3233.io/data/data.db?mode=rwc
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /opt/3233.io/data
sudo systemctl daemon-reload
sudo systemctl enable --now 3233
sudo systemctl status 3233
```

---

## Hosting on Debian with nginx (VPS)

These steps fit a **fresh Debian 12+** cloud VM (e.g. [Linode](https://www.linode.com/), [Vultr](https://www.vultr.com/), [DigitalOcean](https://www.digitalocean.com/)): install the app behind **nginx**, optionally with **TLS** and a **custom domain**.

### With vs without a custom domain

| Setup | How users reach you | TLS (HTTPS / WSS) |
|--------|---------------------|-------------------|
| **Custom domain** | `https://chat.example.com` | Use **Let’s Encrypt** (recommended). |
| **No domain** | `http://YOUR_PUBLIC_IP` (and paths like `/chats`) | **HTTP only** from browsers. Let’s Encrypt does not issue certs for raw IPs; encrypting traffic requires a domain (or a private CA users trust). |

For production, **use a domain** so sessions use HTTPS/WSS and the UI’s invite links match what you publish.

### 1. Point DNS (domain only)

In your DNS provider, create an **A** record:

- **Name:** e.g. `chat` (→ `chat.example.com`) or `@` for the apex.
- **Value:** your VPS **public IPv4**.

(Optional) **AAAA** to the same host if you use IPv6. Wait until the record resolves before running Certbot.

### 2. First login and base packages

SSH in as `root` or a sudo user:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y nginx git ufw curl
```

### 3. Firewall

Allow SSH, HTTP, and HTTPS:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

Confirm your SSH session still works before disconnecting.

### 4. Install Docker Engine + Compose

Follow the official guide: **[Install Docker Engine on Debian](https://docs.docker.com/engine/install/debian/)** (add Docker’s `apt` repository, then install `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin`).

Quick check:

```bash
sudo docker run --rm hello-world
docker compose version
```

Add your user to the `docker` group if you want to run Compose without `sudo` (log out and back in):

```bash
sudo usermod -aG docker "$USER"
```

### 5. Deploy the application

```bash
sudo mkdir -p /opt/3233.io
sudo chown "$USER:$USER" /opt/3233.io
cd /opt/3233.io
git clone https://github.com/253153/3233.io.git .
```

Create a strong secret and an environment file (Compose reads `.env` automatically):

```bash
openssl rand -hex 32 > /tmp/jwt.secret
# Keep this file only on the server; do not commit it.
printf 'JWT_SECRET=%s\n' "$(cat /tmp/jwt.secret)" > .env
rm /tmp/jwt.secret
```

**Bind the app to localhost** so only nginx can reach it (not the public internet on port 3233). Create `docker-compose.override.yml` next to `docker-compose.yml`:

```yaml
services:
  io3233:
    ports:
      - "127.0.0.1:3233:3233"
```

Build and start:

```bash
docker compose up -d --build
curl -sS http://127.0.0.1:3233/v1/stats | head -c 200 && echo
```

SQLite data lives in the Docker volume from the default compose file (`io3233-data`).

### 6. nginx reverse proxy

Put this in `/etc/nginx/sites-available/3233.io` (replace `chat.example.com` with your hostname, or see below for IP-only):

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name chat.example.com;

    location / {
        proxy_pass http://127.0.0.1:3233;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 86400;
    }
}
```

**No custom domain:** use your server’s IP and a catch-all `server_name`:

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    # same location / { ... } block as above
}
```

Enable the site and reload nginx:

```bash
sudo ln -sf /etc/nginx/sites-available/3233.io /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

Open `http://chat.example.com` or `http://YOUR_IP` — you should get the web UI.

### 7. TLS with Let’s Encrypt (domain only)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d chat.example.com
```

Certbot edits nginx for HTTPS and schedules renewal (`certbot renew`). Use **`https://`** and **`wss://`** in production so traffic between browsers and your VPS is encrypted.

### 8. Operations notes

- **Updates:** `cd /opt/3233.io && git pull && docker compose up -d --build`
- **JWT_SECRET:** Changing it invalidates existing sessions; users re-register in the UI.
- **Backups:** Persist the Docker volume (or the SQLite files under it) and keep `.env` secret.
- If anything fails, check `docker compose logs` and `sudo journalctl -u nginx`.

---

## Configuration

Server environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BIND` | `0.0.0.0:3233` | HTTP listen address |
| `DATABASE_URL` | `sqlite:data.db?mode=rwc` | SQLite connection string |
| `JWT_SECRET` | — (required) | Symmetric key for JWTs; must be ≥ 32 bytes. Server refuses to start without a strong secret unless `ALLOW_INSECURE_JWT_SECRET=1`. |
| `ALLOW_INSECURE_JWT_SECRET` | `0` | **Dev only.** Set to `1` to accept a weak/absent `JWT_SECRET`; never set in production. |
| `TRUST_FORWARDED_FOR` | `0` | Set to `1` when running behind a trusted reverse proxy so the per-IP rate limiter keys off `X-Forwarded-For`. |
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
- **Notifications:** Opt-in via the bell toggle. Backed by the service worker so they appear while the tab is in the background. Notifications stay inside the tab's lifecycle — if the tab is fully closed, nothing fires. True "site closed" push would require adding VAPID-signed Web Push on the server (currently not implemented).

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

## Testing

The project ships with three layers of tests that can be run individually or together.

```bash
# One-time setup (the client workspace is shared; e2e has its own package)
npm install
(cd e2e && npm install)

# Run everything: server unit + integration, client unit, end-to-end.
npm test

# Or per-layer:
npm run test:server        # cargo test (unit + integration)
npm run test:client        # vitest run — client helpers & crypto
npm run test:e2e           # puppeteer-core driven specs

# E2E helpers
cd e2e && node run.mjs --only=chat      # run a single spec by substring
CHROMIUM_PATH=/usr/bin/chromium npm run test:e2e
```

| Layer | Runner | Lives in | Coverage |
| --- | --- | --- | --- |
| Rust unit | `cargo test --lib` | `server/src/lib.rs` `#[cfg(test)] mod unit_tests` | fingerprint hashing, base64 / hex validation, JWT sign + verify + expiry |
| Rust integration | `cargo test --test api` | `server/tests/api.rs` | every HTTP route (`/v1/register`, `/v1/messages`, `/v1/me`, `/v1/keys`, `/v1/stats`) happy paths **and** every 4xx/413 branch; WebSocket `connected` + `new_message` + `ping`/`pong`; rejects bogus tokens. Each test boots a fresh axum app against `sqlite::memory:` on an ephemeral port. |
| Client unit | `vitest run` (`happy-dom`) | `client/src/*.test.ts` | `crypto.ts` round-trip (NaCl box encrypt/decrypt, tampered ciphertext, distinct nonces), `helpers.ts` (fingerprint normalization, notification body formatting, cross-tab CAS claim, HTML escaping, route mapping). |
| E2E | `node e2e/run.mjs` | `e2e/specs/*.mjs` | Smoke test (all views render, zero `pageerror`), two-user chat (delivery, Enter vs Shift+Enter, XSS escape, emoji, long payloads, self-chat rejection, message ordering parity), notifications (backgrounded tab fires exactly one OS-level notification per message). |

The e2e harness builds the client with `vite build`, serves it from the Rust binary via `STATIC_DIR`, boots on an ephemeral port, and drives a headless Chromium via `puppeteer-core`. Chromium is auto-discovered at `/usr/bin/chromium`, `/usr/bin/google-chrome-stable`, or `$CHROMIUM_PATH`.

---

## Contributing

Issues and PRs are welcome. Please keep changes focused; match existing style in Rust and TypeScript. For behavior changes, update **docs/PROTOCOL.md** if the wire API or identity rules change. Run `npm test` before submitting.

---

## License

MIT — see [LICENSE](LICENSE).
