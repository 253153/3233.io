import {
  type BoxKeyPair,
  b64decode,
  b64encode,
  decryptFromSender,
  encryptForRecipient,
  fingerprintFromPublicKey,
  generateKeyPair,
  shortFingerprint,
} from "./crypto";
import { toQrDataUrl } from "./qr";
import "./style.css";

const LS_SERVER = "io3233_server_url";
const LS_SK = "io3233_secret_key";
const LS_PK = "io3233_public_key";
const LS_TOKEN = "io3233_token";

function getServerUrl(): string {
  const saved = localStorage.getItem(LS_SERVER);
  if (saved) return saved;
  if (import.meta.env.DEV) return "http://127.0.0.1:3233";
  return window.location.origin;
}

function setServerUrl(url: string) {
  localStorage.setItem(LS_SERVER, url.replace(/\/$/, ""));
}

function apiBase(): string {
  return getServerUrl().replace(/\/$/, "");
}

function wsUrl(): string {
  const u = new URL(apiBase());
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  return u.toString().replace(/\/$/, "");
}

async function loadOrCreateKeys(): Promise<{ pair: BoxKeyPair; fingerprint: string }> {
  const skB = localStorage.getItem(LS_SK);
  const pkB = localStorage.getItem(LS_PK);
  if (skB && pkB) {
    const secretKey = b64decode(skB);
    const publicKey = b64decode(pkB);
    const pair: BoxKeyPair = { publicKey, secretKey };
    const fingerprint = await fingerprintFromPublicKey(publicKey);
    return { pair, fingerprint };
  }
  const pair = generateKeyPair();
  localStorage.setItem(LS_SK, b64encode(pair.secretKey));
  localStorage.setItem(LS_PK, b64encode(pair.publicKey));
  const fingerprint = await fingerprintFromPublicKey(pair.publicKey);
  return { pair, fingerprint };
}

let lastMsgId = 0;
let ws: WebSocket | null = null;
let wsReconnectTimer: number | null = null;
let wsReconnectAttempt = 0;
/** Bumped only in disconnectWs so stale socket handlers and timers exit. */
let wsGen = 0;

const LIBRARY_PAGE_SIZE = 10;
const FETCH_BATCH = 100;

type LibraryEntry = {
  id: number;
  text: string;
  meta: string;
};

const libraryEntries: LibraryEntry[] = [];
let libraryById = new Map<number, LibraryEntry>();
let didFullBackfill = false;

let libraryPage = 1;
let librarySearchQuery = "";

async function register(pair: BoxKeyPair): Promise<{ ok: boolean; err?: string }> {
  const r = await fetch(`${apiBase()}/v1/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ public_key: b64encode(pair.publicKey) }),
  });
  if (!r.ok) {
    const t = await r.text();
    return { ok: false, err: t || r.statusText };
  }
  const j = (await r.json()) as { token: string; fingerprint: string };
  localStorage.setItem(LS_TOKEN, j.token);
  return { ok: true };
}

function getToken(): string | null {
  return localStorage.getItem(LS_TOKEN);
}

async function verifyToken(): Promise<boolean> {
  const token = getToken();
  if (!token) return false;
  const r = await fetch(`${apiBase()}/v1/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return r.ok;
}

/** Ensures a valid session: reuses JWT if still valid, otherwise registers. */
async function ensureRegistered(
  pair: BoxKeyPair,
): Promise<{ ok: boolean; err?: string; wasNewRegistration: boolean }> {
  const token = getToken();
  if (token) {
    const ok = await verifyToken();
    if (ok) return { ok: true, wasNewRegistration: false };
    localStorage.removeItem(LS_TOKEN);
  }
  const r = await register(pair);
  return {
    ok: r.ok,
    err: r.err,
    wasNewRegistration: r.ok === true,
  };
}

type ServerStats = {
  registered_identities: number | null;
  message_retention_days: number | null;
};

async function fetchServerStats(): Promise<ServerStats> {
  try {
    const r = await fetch(`${apiBase()}/v1/stats`);
    if (!r.ok) {
      return { registered_identities: null, message_retention_days: null };
    }
    const j = (await r.json()) as {
      registered_identities: number;
      message_retention_days: number;
    };
    return {
      registered_identities: j.registered_identities,
      message_retention_days: j.message_retention_days,
    };
  } catch {
    return { registered_identities: null, message_retention_days: null };
  }
}

async function fetchRecipientPk(fingerprint: string): Promise<Uint8Array> {
  const r = await fetch(`${apiBase()}/v1/keys/${encodeURIComponent(fingerprint)}`);
  if (!r.ok) throw new Error("Recipient not on this server");
  const j = (await r.json()) as { public_key: string };
  return b64decode(j.public_key);
}

async function sendMessage(
  pair: BoxKeyPair,
  recipientFingerprint: string,
  text: string,
): Promise<{ ok: boolean; err?: string }> {
  const token = getToken();
  if (!token) return { ok: false, err: "Not registered" };
  const recipientPk = await fetchRecipientPk(recipientFingerprint.trim());
  const body = JSON.stringify({ text, ts: Date.now() });
  const enc = new TextEncoder().encode(body);
  const { ciphertext, nonce } = encryptForRecipient(enc, recipientPk, pair);
  const r = await fetch(`${apiBase()}/v1/messages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      recipient_fingerprint: recipientFingerprint.trim(),
      ciphertext: b64encode(ciphertext),
      nonce: b64encode(nonce),
      sender_public_key: b64encode(pair.publicKey),
    }),
  });
  if (!r.ok) {
    const t = await r.text();
    return { ok: false, err: t || r.statusText };
  }
  return { ok: true };
}

type ServerMessage = {
  id: number;
  sender_fingerprint: string | null;
  ciphertext: string;
  nonce: string;
  sender_public_key: string;
  created_at: string;
};

function decryptServerMessage(m: ServerMessage, pair: BoxKeyPair): LibraryEntry {
  const ct = b64decode(m.ciphertext);
  const nonce = b64decode(m.nonce);
  const senderPk = b64decode(m.sender_public_key);
  const plain = decryptFromSender(ct, nonce, senderPk, pair);
  if (!plain) {
    return {
      id: m.id,
      text: "(decrypt failed)",
      meta: `#${m.id} · ${m.created_at}`,
    };
  }
  const txt = new TextDecoder().decode(plain);
  let display = txt;
  try {
    const p = JSON.parse(txt) as { text?: string };
    if (typeof p.text === "string") display = p.text;
  } catch {
    /* raw */
  }
  const short = m.sender_fingerprint
    ? shortFingerprint(m.sender_fingerprint)
    : "unknown";
  return {
    id: m.id,
    text: display,
    meta: `${short} · ${m.created_at}`,
  };
}

function mergeLibraryEntry(entry: LibraryEntry) {
  if (libraryById.has(entry.id)) return;
  libraryById.set(entry.id, entry);
  libraryEntries.push(entry);
  libraryEntries.sort((a, b) => b.id - a.id);
}

/** Load all stored messages once per session (paged on server). */
async function backfillLibrary(pair: BoxKeyPair): Promise<void> {
  if (didFullBackfill) return;
  const token = getToken();
  if (!token) return;
  let cursor = 0;
  while (true) {
    const r = await fetch(
      `${apiBase()}/v1/messages?after_id=${cursor}&limit=${FETCH_BATCH}`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (!r.ok) break;
    const j = (await r.json()) as { messages: ServerMessage[] };
    if (j.messages.length === 0) break;
    for (const m of j.messages) {
      const entry = decryptServerMessage(m, pair);
      mergeLibraryEntry(entry);
      lastMsgId = Math.max(lastMsgId, m.id);
      cursor = m.id;
    }
    if (j.messages.length < FETCH_BATCH) break;
  }
  didFullBackfill = true;
}

async function pullNewMessages(pair: BoxKeyPair): Promise<void> {
  const token = getToken();
  if (!token) return;
  const r = await fetch(
    `${apiBase()}/v1/messages?after_id=${lastMsgId}&limit=${FETCH_BATCH}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (!r.ok) return;
  const j = (await r.json()) as { messages: ServerMessage[] };
  for (const m of j.messages) {
    if (m.id <= lastMsgId) continue;
    lastMsgId = m.id;
    const entry = decryptServerMessage(m, pair);
    mergeLibraryEntry(entry);
  }
}

function clearWsReconnect() {
  if (wsReconnectTimer !== null) {
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
  }
}

function disconnectWs() {
  clearWsReconnect();
  wsReconnectAttempt = 0;
  wsGen += 1;
  try {
    ws?.close();
  } catch {
    /* ignore */
  }
  ws = null;
}

function connectWs(
  pair: BoxKeyPair,
  onRefresh: () => void,
  setLiveUi: (state: "connecting" | "live" | "offline", hint?: string) => void,
) {
  const token = getToken();
  if (!token) {
    setLiveUi("offline", "Not registered");
    return;
  }

  clearWsReconnect();
  try {
    ws?.close();
  } catch {
    /* ignore */
  }
  ws = null;

  const g = wsGen;
  setLiveUi("connecting");
  const url = `${wsUrl()}/v1/ws?token=${encodeURIComponent(token)}`;
  let socket: WebSocket;
  try {
    socket = new WebSocket(url);
  } catch {
    if (g !== wsGen) return;
    setLiveUi("offline", "Cannot open WebSocket");
    scheduleWsReconnect(pair, onRefresh, setLiveUi, g);
    return;
  }
  ws = socket;

  socket.onopen = () => {
    if (g !== wsGen) return;
    wsReconnectAttempt = 0;
    setLiveUi("live");
  };

  socket.onmessage = (ev) => {
    if (g !== wsGen) return;
    try {
      const j = JSON.parse(ev.data as string) as { type?: string };
      if (j.type === "new_message") onRefresh();
    } catch {
      /* ignore */
    }
  };

  socket.onerror = () => {
    /* onclose will run */
  };

  socket.onclose = () => {
    if (g !== wsGen) return;
    if (ws === socket) ws = null;
    setLiveUi("offline", "Reconnecting…");
    scheduleWsReconnect(pair, onRefresh, setLiveUi, g);
  };
}

function scheduleWsReconnect(
  pair: BoxKeyPair,
  onRefresh: () => void,
  setLiveUi: (state: "connecting" | "live" | "offline", hint?: string) => void,
  generation: number,
) {
  clearWsReconnect();
  const delay = Math.min(30_000, 1000 * Math.pow(2, wsReconnectAttempt));
  wsReconnectAttempt += 1;
  wsReconnectTimer = window.setTimeout(() => {
    if (generation !== wsGen) return;
    connectWs(pair, onRefresh, setLiveUi);
  }, delay);
}

async function main() {
  const { pair, fingerprint } = await loadOrCreateKeys();

  const app = document.querySelector("#app")!;
  app.innerHTML = `
    <header class="app-header">
      <div class="header-brand">
        <h1>3233.io</h1>
        <p class="sub">End-to-end encrypted relay. Keys stay in your browser.</p>
      </div>
      <div class="header-live" id="liveStrip">
        <span id="liveIndicator" class="live-badge connecting">Connecting…</span>
        <span class="live-hint" id="liveHint"></span>
      </div>
    </header>

    <div class="panel panel-send">
      <h2>Send</h2>
      <div class="row">
        <div style="flex:2 1 220px">
          <label for="recipient">Recipient fingerprint (64 hex)</label>
          <input type="text" id="recipient" placeholder="abc123… (from your contact)" autocomplete="off" />
        </div>
      </div>
      <label for="body">Message</label>
      <textarea id="body" placeholder="Encrypted to your contact's public key"></textarea>
      <div class="row" style="margin-top:0.75rem">
        <button type="button" id="sendBtn">Send</button>
      </div>
      <p class="status" id="sendStatus"></p>
    </div>

    <div class="panel">
      <h2>Server</h2>
      <div class="row">
        <div>
          <label for="serverUrl">Base URL</label>
          <input type="text" id="serverUrl" placeholder="https://chat.example.com" autocomplete="off" />
        </div>
        <button type="button" class="secondary" id="saveServer">Save</button>
      </div>
      <p class="server-stats" id="serverStats">
        Unique identities registered on this server (all time): <strong id="statsIdentities">—</strong>
      </p>
      <p class="server-retention" id="serverRetention">
        Outbound messages wait on the server until your contact picks them up. Anything still in the queue after
        <strong><span id="retentionDays">—</span> days</strong> is deleted automatically (this server’s policy).
      </p>
      <p class="status" id="serverStatus"></p>
    </div>

    <div class="panel">
      <h2>Your keys</h2>
      <p class="key-intro">Your <strong>fingerprint</strong> is your address on this network. Share it so others can send you messages.</p>

      <div class="key-block key-public">
        <div class="key-label">Public key <span class="key-tag">safe to share</span></div>
        <p class="key-help">Give this to contacts (or they can fetch it from the server using your fingerprint). Needed so others can encrypt to you.</p>
        <p class="fp mono" id="pubKeyB64"></p>
        <div class="row key-download-row">
          <button type="button" class="secondary" id="dlPublic">Download public key (.txt)</button>
        </div>
        <p class="fp-label">Fingerprint (short)</p>
        <p class="fp" id="fpShort"></p>
        <p class="fp-label">Fingerprint (full hex)</p>
        <p class="fp" id="fpFull"></p>
        <div class="qr-row">
          <div class="qr-wrap">
            <p class="qr-caption">Contact QR <span class="qr-hint">(fingerprint + server)</span></p>
            <img id="qrContact" class="qr-img" width="180" height="180" alt="" />
          </div>
          <div class="qr-wrap">
            <p class="qr-caption">Public key QR <span class="qr-hint">(base64)</span></p>
            <img id="qrPublic" class="qr-img" width="180" height="180" alt="" />
          </div>
        </div>
      </div>

      <div class="key-block key-private">
        <div class="key-label">Private key <span class="key-tag key-tag-danger">never share</span></div>
        <p class="key-help">Anyone with this can read your messages and impersonate you. It never leaves your browser unless you copy or download it.</p>
        <p class="fp mono" id="privKeyB64"></p>
        <div class="row key-download-row">
          <button type="button" class="secondary" id="dlPrivate">Download private key (.txt)</button>
        </div>
      </div>

      <div class="row" style="margin-top:0.75rem">
        <button type="button" class="secondary" id="newKeys">New keys (clears session)</button>
        <button type="button" class="secondary" id="registerBtn">Register again</button>
      </div>
      <p class="status" id="regStatus"></p>
    </div>

    <div class="panel">
      <h2>Library <span class="badge">decrypted locally</span></h2>
      <div class="row">
        <div style="flex:2 1 220px">
          <label for="librarySearch">Search</label>
          <input type="text" id="librarySearch" placeholder="Filter by text, sender, or date…" autocomplete="off" />
        </div>
      </div>
      <div class="messages" id="libraryList"></div>
      <div class="library-pager" id="libraryPager">
        <button type="button" class="secondary" id="libraryPrev">Previous</button>
        <span class="library-page-info" id="libraryPageInfo"></span>
        <button type="button" class="secondary" id="libraryNext">Next</button>
      </div>
    </div>
  `;

  const liveIndicator = app.querySelector("#liveIndicator")!;
  const liveHint = app.querySelector("#liveHint")!;
  const serverUrlEl = app.querySelector<HTMLInputElement>("#serverUrl")!;
  const saveServer = app.querySelector("#saveServer")!;
  const statsIdentities = app.querySelector("#statsIdentities")!;
  const retentionDaysEl = app.querySelector("#retentionDays")!;
  const serverStatus = app.querySelector("#serverStatus")!;
  const qrContact = app.querySelector<HTMLImageElement>("#qrContact")!;
  const qrPublic = app.querySelector<HTMLImageElement>("#qrPublic")!;
  const dlPublic = app.querySelector<HTMLButtonElement>("#dlPublic")!;
  const dlPrivate = app.querySelector<HTMLButtonElement>("#dlPrivate")!;
  const pubKeyB64 = app.querySelector("#pubKeyB64")!;
  const privKeyB64 = app.querySelector("#privKeyB64")!;
  const fpShortEl = app.querySelector("#fpShort")!;
  const fpFullEl = app.querySelector("#fpFull")!;
  const regStatus = app.querySelector("#regStatus")!;
  const registerBtn = app.querySelector("#registerBtn")!;
  const newKeys = app.querySelector("#newKeys")!;
  const recipientEl = app.querySelector<HTMLInputElement>("#recipient")!;
  const bodyEl = app.querySelector<HTMLInputElement>("#body")!;
  const sendBtn = app.querySelector<HTMLButtonElement>("#sendBtn")!;
  const sendStatus = app.querySelector("#sendStatus")!;
  const libraryList = app.querySelector("#libraryList")!;
  const librarySearch = app.querySelector<HTMLInputElement>("#librarySearch")!;
  const libraryPager = app.querySelector<HTMLElement>("#libraryPager")!;
  const libraryPageInfo = app.querySelector("#libraryPageInfo")!;
  const libraryPrev = app.querySelector<HTMLButtonElement>("#libraryPrev")!;
  const libraryNext = app.querySelector<HTMLButtonElement>("#libraryNext")!;

  serverUrlEl.value = getServerUrl();
  fpShortEl.textContent = shortFingerprint(fingerprint);
  fpFullEl.textContent = fingerprint;
  pubKeyB64.textContent = b64encode(pair.publicKey);
  privKeyB64.textContent = b64encode(pair.secretKey);

  void renderContactQrs();

  dlPublic.addEventListener("click", () => {
    const body = [
      "3233.io — PUBLIC KEY (safe to share)",
      "",
      `Fingerprint (hex): ${fingerprint}`,
      `Server (API base): ${apiBase()}`,
      "",
      "Public key (base64, NaCl box):",
      b64encode(pair.publicKey),
      "",
    ].join("\n");
    downloadTextFile(`3233-public-key-${fingerprint.slice(0, 8)}.txt`, body);
  });

  dlPrivate.addEventListener("click", () => {
    if (
      !confirm(
        "Download your PRIVATE key? Anyone with this file can impersonate you. Continue?",
      )
    ) {
      return;
    }
    const body = [
      "3233.io — PRIVATE KEY — KEEP SECRET — NEVER SHARE",
      "",
      `Fingerprint (hex): ${fingerprint}`,
      `Server (API base): ${apiBase()}`,
      "",
      "Private key (base64, NaCl box):",
      b64encode(pair.secretKey),
      "",
    ].join("\n");
    downloadTextFile(`3233-private-key-${fingerprint.slice(0, 8)}.txt`, body);
  });

  function setLiveUi(state: "connecting" | "live" | "offline", hint = "") {
    liveIndicator.classList.remove("connecting", "live", "offline");
    if (state === "connecting") {
      liveIndicator.textContent = "Connecting…";
      liveIndicator.classList.add("connecting");
    } else if (state === "live") {
      liveIndicator.textContent = "Live";
      liveIndicator.classList.add("live");
    } else {
      liveIndicator.textContent = "Not live";
      liveIndicator.classList.add("offline");
    }
    liveHint.textContent = hint;
  }

  function escapeHtml(s: string): string {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function resetLibraryState() {
    lastMsgId = 0;
    didFullBackfill = false;
    libraryEntries.length = 0;
    libraryById = new Map();
    libraryPage = 1;
    librarySearchQuery = "";
    librarySearch.value = "";
  }

  async function refreshServerStats() {
    const s = await fetchServerStats();
    statsIdentities.textContent =
      s.registered_identities === null ? "—" : String(s.registered_identities);
    retentionDaysEl.textContent =
      s.message_retention_days === null ? "—" : String(s.message_retention_days);
  }

  async function renderContactQrs() {
    const fp = fingerprint;
    const server = apiBase();
    const contactJson = JSON.stringify({
      "3233": 1,
      server,
      fingerprint: fp,
    });
    const pubB64 = b64encode(pair.publicKey);
    try {
      const [u1, u2] = await Promise.all([
        toQrDataUrl(contactJson, 180),
        toQrDataUrl(pubB64, 180),
      ]);
      qrContact.src = u1;
      qrPublic.src = u2;
      qrContact.alt = "Contact QR";
      qrPublic.alt = "Public key QR";
    } catch {
      qrContact.alt = "QR failed";
      qrPublic.alt = "QR failed";
    }
  }

  function downloadTextFile(filename: string, content: string) {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function getFilteredLibrary(): LibraryEntry[] {
    const q = librarySearchQuery.trim().toLowerCase();
    if (!q) return [...libraryEntries];
    return libraryEntries.filter(
      (e) =>
        e.text.toLowerCase().includes(q) || e.meta.toLowerCase().includes(q),
    );
  }

  function renderLibrary() {
    const filtered = getFilteredLibrary();
    const totalPages = Math.max(1, Math.ceil(filtered.length / LIBRARY_PAGE_SIZE));
    if (libraryPage > totalPages) libraryPage = totalPages;
    if (libraryPage < 1) libraryPage = 1;

    const start = (libraryPage - 1) * LIBRARY_PAGE_SIZE;
    const pageItems = filtered.slice(start, start + LIBRARY_PAGE_SIZE);

    libraryList.innerHTML = "";
    for (const e of pageItems) {
      const div = document.createElement("div");
      div.className = "msg";
      div.innerHTML = `<div class="meta">${escapeHtml(e.meta)}</div><div class="body">${escapeHtml(e.text)}</div>`;
      libraryList.appendChild(div);
    }

    if (filtered.length === 0) {
      const empty = document.createElement("p");
      empty.className = "status";
      empty.style.margin = "0.5rem 0 0";
      empty.textContent = librarySearchQuery.trim()
        ? "No messages match your search."
        : "No messages yet.";
      libraryList.appendChild(empty);
    }

    const showPager = filtered.length > LIBRARY_PAGE_SIZE;
    libraryPager.style.display = showPager ? "flex" : "none";
    libraryPageInfo.textContent =
      filtered.length === 0
        ? ""
        : `Page ${libraryPage} of ${totalPages} · ${filtered.length} ${filtered.length === 1 ? "entry" : "entries"}`;
    libraryPrev.disabled = libraryPage <= 1;
    libraryNext.disabled = libraryPage >= totalPages;
  }

  async function refreshLibrary() {
    await backfillLibrary(pair);
    await pullNewMessages(pair);
    renderLibrary();
  }

  async function runSessionSetup(options: { resetLibrary: boolean }) {
    regStatus.textContent = "Checking server…";
    regStatus.className = "status";
    disconnectWs();
    setLiveUi("connecting");

    const res = await ensureRegistered(pair);
    if (!res.ok) {
      regStatus.textContent = res.err ?? "Could not register";
      regStatus.className = "status err";
      setLiveUi("offline", "Fix server URL or try Register again");
      renderLibrary();
      return;
    }

    if (options.resetLibrary || res.wasNewRegistration) {
      resetLibraryState();
    }

    regStatus.textContent = "Session active — auto-registered with this server.";
    regStatus.className = "status ok";

    await refreshServerStats();
    void renderContactQrs();
    connectWs(pair, refreshLibrary, setLiveUi);
    await refreshLibrary();
  }

  librarySearch.addEventListener("input", () => {
    librarySearchQuery = librarySearch.value;
    libraryPage = 1;
    renderLibrary();
  });

  libraryPrev.addEventListener("click", () => {
    libraryPage -= 1;
    renderLibrary();
  });

  libraryNext.addEventListener("click", () => {
    libraryPage += 1;
    renderLibrary();
  });

  saveServer.addEventListener("click", async () => {
    const next = serverUrlEl.value.trim() || "http://127.0.0.1:3233";
    const prev = getServerUrl().replace(/\/$/, "");
    if (prev !== next.replace(/\/$/, "")) {
      localStorage.removeItem(LS_TOKEN);
    }
    setServerUrl(next);
    serverStatus.textContent = "";
    await runSessionSetup({ resetLibrary: true });
  });

  registerBtn.addEventListener("click", async () => {
    localStorage.removeItem(LS_TOKEN);
    await runSessionSetup({ resetLibrary: true });
  });

  newKeys.addEventListener("click", () => {
    if (!confirm("Generate new keys? This cannot be undone.")) return;
    localStorage.removeItem(LS_SK);
    localStorage.removeItem(LS_PK);
    localStorage.removeItem(LS_TOKEN);
    location.reload();
  });

  sendBtn.addEventListener("click", async () => {
    sendStatus.textContent = "";
    sendStatus.className = "status";
    const rf = recipientEl.value.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(rf)) {
      sendStatus.textContent = "Recipient must be 64 hex characters.";
      sendStatus.className = "status err";
      return;
    }
    const text = bodyEl.value.trim();
    if (!text) {
      sendStatus.textContent = "Enter a message.";
      sendStatus.className = "status err";
      return;
    }
    sendBtn.disabled = true;
    const res = await sendMessage(pair, rf, text);
    sendBtn.disabled = false;
    if (res.ok) {
      sendStatus.textContent = "Sent.";
      sendStatus.className = "status ok";
      bodyEl.value = "";
    } else {
      sendStatus.textContent = res.err ?? "Send failed";
      sendStatus.className = "status err";
    }
  });

  renderLibrary();
  await runSessionSetup({ resetLibrary: false });
  window.setInterval(() => void refreshLibrary(), 30000);
  window.setInterval(() => void refreshServerStats(), 60000);
}

main().catch((e) => {
  console.error(e);
  document.querySelector("#app")!.innerHTML = `<p class="status err">${String(e)}</p>`;
});
