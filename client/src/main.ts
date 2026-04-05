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
const LS_OPEN_CHATS = "io3233_open_chats";
const LS_SENT = "io3233_sent_by_contact_v1";

type SentLine = { ts: number; text: string };

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

function normalizeFingerprint(raw: string): string | null {
  const s = raw.replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(s)) return null;
  return s;
}

/** Absolute http(s) API base, or null */
function parseHttpUrlOrNull(raw: string): string | null {
  const t = raw.trim();
  if (!t) return null;
  try {
    const u = new URL(t);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return t.replace(/\/$/, "");
  } catch {
    return null;
  }
}

const VIEW_IDS = ["chats", "server", "keys", "library", "about"] as const;
type ViewId = (typeof VIEW_IDS)[number];

function normalizePathname(pathname: string): string {
  const p = pathname.replace(/\/$/, "");
  return p === "" ? "/" : p;
}

function pathnameToView(pathname: string): ViewId | null {
  const p = normalizePathname(pathname);
  if (p === "/") return null;
  const seg = p.slice(1);
  if (seg.includes("/")) return null;
  return VIEW_IDS.includes(seg as ViewId) ? (seg as ViewId) : null;
}

function viewToPath(view: string): string {
  return "/" + view;
}

const ROUTE_SEO: Record<ViewId, { title: string; description: string }> = {
  chats: {
    title: "Chats — 3233.io · ~/encrypted relay",
    description:
      "End-to-end encrypted chats. Paste a contact’s public key fingerprint, share your invite link, or wait for inbound mail. Keys stay in your browser.",
  },
  server: {
    title: "Server — 3233.io · ~/encrypted relay",
    description:
      "Choose your API relay base URL, see registration stats, and learn offline message retention policy for this self-hosted encrypted relay.",
  },
  keys: {
    title: "Keys — 3233.io · ~/encrypted relay",
    description:
      "Export your NaCl box public and private keys, fingerprint, and QR codes. Your secret key never leaves this device unless you download it.",
  },
  library: {
    title: "Library — 3233.io · ~/encrypted relay",
    description:
      "Search decrypted message history stored locally in your browser. Offline inbox archive for your end-to-end encrypted conversations.",
  },
  about: {
    title: "About — 3233.io · ~/encrypted relay",
    description:
      "Why 3233 is safe: end-to-end encryption with tweetnacl, minimal trust in the relay, and auditable open-source MIT-licensed client code.",
  },
};

function setMetaByName(name: string, content: string) {
  let el = document.querySelector(`meta[name="${name}"]`) as HTMLMetaElement | null;
  if (!el) {
    el = document.createElement("meta");
    el.setAttribute("name", name);
    document.head.appendChild(el);
  }
  el.setAttribute("content", content);
}

function setMetaByProperty(property: string, content: string) {
  let el = document.querySelector(`meta[property="${property}"]`) as HTMLMetaElement | null;
  if (!el) {
    el = document.createElement("meta");
    el.setAttribute("property", property);
    document.head.appendChild(el);
  }
  el.setAttribute("content", content);
}

function setCanonicalLink(href: string) {
  let el = document.querySelector('link[rel="canonical"]') as HTMLLinkElement | null;
  if (!el) {
    el = document.createElement("link");
    el.setAttribute("rel", "canonical");
    document.head.appendChild(el);
  }
  el.setAttribute("href", href);
}

function applyRouteSeo(view: ViewId) {
  const seo = ROUTE_SEO[view];
  document.title = seo.title;
  setMetaByName("description", seo.description);
  setMetaByProperty("og:title", seo.title);
  setMetaByProperty("og:description", seo.description);
  const url = `${window.location.origin}${viewToPath(view)}`;
  setMetaByProperty("og:url", url);
  setMetaByName("twitter:title", seo.title);
  setMetaByName("twitter:description", seo.description);
  setCanonicalLink(url);
}

function loadOpenChats(): string[] {
  try {
    const raw = localStorage.getItem(LS_OPEN_CHATS);
    if (!raw) return [];
    const j = JSON.parse(raw) as string[];
    if (!Array.isArray(j)) return [];
    const out: string[] = [];
    for (const x of j) {
      const n = normalizeFingerprint(String(x));
      if (n && !out.includes(n)) out.push(n);
    }
    return out;
  } catch {
    return [];
  }
}

function saveOpenChats(ids: string[]) {
  localStorage.setItem(LS_OPEN_CHATS, JSON.stringify(ids));
}

function loadSentMap(): Record<string, SentLine[]> {
  try {
    const raw = localStorage.getItem(LS_SENT);
    if (!raw) return {};
    const j = JSON.parse(raw) as Record<string, SentLine[]>;
    return j && typeof j === "object" ? j : {};
  } catch {
    return {};
  }
}

function saveSentMap(m: Record<string, SentLine[]>) {
  localStorage.setItem(LS_SENT, JSON.stringify(m));
}

function appendSent(toFp: string, text: string) {
  const fp = toFp.toLowerCase();
  const m = loadSentMap();
  if (!m[fp]) m[fp] = [];
  m[fp].push({ ts: Date.now(), text });
  saveSentMap(m);
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
  /** Sender fingerprint (lowercase hex), for threading. */
  senderFp: string | null;
  serverTs: number;
};

const libraryEntries: LibraryEntry[] = [];
let libraryById = new Map<number, LibraryEntry>();
let didFullBackfill = false;

let libraryPage = 1;
let librarySearchQuery = "";

/** Set from main(): add tabs for all senders in inbox after history sync. */
let syncTabsAfterBackfill: (() => void) | undefined;
/** Set from main(): new message from poll/WS — open or focus sender tab. */
let onNewPolledEntry: ((entry: LibraryEntry) => void) | undefined;

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
  const serverTs = Date.parse(m.created_at) || 0;
  const senderFp = m.sender_fingerprint
    ? m.sender_fingerprint.toLowerCase()
    : null;
  const ct = b64decode(m.ciphertext);
  const nonce = b64decode(m.nonce);
  const senderPk = b64decode(m.sender_public_key);
  const plain = decryptFromSender(ct, nonce, senderPk, pair);
  if (!plain) {
    return {
      id: m.id,
      text: "(decrypt failed)",
      meta: `#${m.id} · ${m.created_at}`,
      senderFp,
      serverTs,
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
    senderFp,
    serverTs,
  };
}

function mergeLibraryEntry(entry: LibraryEntry): boolean {
  if (libraryById.has(entry.id)) return false;
  libraryById.set(entry.id, entry);
  libraryEntries.push(entry);
  libraryEntries.sort((a, b) => b.id - a.id);
  return true;
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
  syncTabsAfterBackfill?.();
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
    if (mergeLibraryEntry(entry)) {
      onNewPolledEntry?.(entry);
    }
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
    <header class="site-header">
      <div class="site-brand">
        <a href="/chats" class="brand-name"><b>3233</b></a>
        <span class="brand-path">~/encrypted relay</span>
      </div>
    </header>

    <div class="app-shell">
      <aside class="app-sidebar" aria-label="Sidebar">
        <details class="sidebar-block sidebar-chats" open>
          <summary class="sidebar-summary">Chats»</summary>
          <div class="sidebar-chats-inner">
            <p class="sidebar-kv sidebar-kv--you">
              <span class="sidebar-k">fp</span>
              <span id="sidebarFpShort" class="mono"></span>
            </p>
            <p class="sidebar-session-hint">E2E · server never sees plaintext</p>
            <div class="sidebar-chat-tabs-wrap">
              <div id="chatTabs" class="chat-tabs chat-tabs--sidebar"></div>
            </div>
          </div>
        </details>
      </aside>

      <main class="app-main">
        <nav class="dashboard-tabs" role="tablist" aria-label="Main views">
          <button type="button" role="tab" class="dash-tab active" data-view="chats" aria-selected="true" id="tab-chats">chats</button>
          <button type="button" role="tab" class="dash-tab" data-view="server" aria-selected="false" id="tab-server">server</button>
          <button type="button" role="tab" class="dash-tab" data-view="keys" aria-selected="false" id="tab-keys">keys</button>
          <button type="button" role="tab" class="dash-tab" data-view="library" aria-selected="false" id="tab-library">library</button>
          <button type="button" role="tab" class="dash-tab" data-view="about" aria-selected="false" id="tab-about">about</button>
        </nav>

        <section id="view-chats" class="view-panel" role="tabpanel" aria-labelledby="tab-chats">
          <p class="key-intro chat-intro">
            New messages open a thread in the sidebar. To start a chat, paste the other person’s <strong>public key fingerprint</strong> (64 hex characters — the address they share).
          </p>
          <div class="invite-link-block">
            <p class="invite-link-hint">
              Share your identity: select text in the fields below and copy (right-click → Copy, or Ctrl+C / ⌘+C). Triple-click selects a whole line.
            </p>
            <div class="share-field-group">
              <label for="inviteLinkInput">Invite link</label>
              <input
                type="text"
                id="inviteLinkInput"
                readonly
                spellcheck="false"
                autocomplete="off"
                class="share-field-input"
                title="Read-only — select text, then copy"
              />
            </div>
            <div class="share-field-group">
              <label for="publicKeyShareInput">Your public key (base64)</label>
              <input
                type="text"
                id="publicKeyShareInput"
                readonly
                spellcheck="false"
                autocomplete="off"
                class="share-field-input"
                title="Read-only — select text, then copy"
              />
            </div>
          </div>
          <div class="row">
            <div style="flex:2 1 220px">
              <label for="openChatFp">Their public key (fingerprint, 64 hex)</label>
              <input
                type="text"
                id="openChatFp"
                placeholder="Paste the contact’s public key fingerprint…"
                autocomplete="off"
              />
            </div>
            <button type="button" id="openChatBtn">Open chat</button>
          </div>
          <p class="status" id="openChatStatus"></p>
          <p class="status chat-empty-hint" id="chatEmptyHint">No thread — add someone’s public key above, share your invite link or public key from the fields above, or wait for inbound mail.</p>
          <div class="chat-thread" id="chatThread" hidden>
            <div class="chat-with-block">
              <div class="chat-with-label">Contact — their public key fingerprint</div>
              <p class="chat-thread-id mono" id="chatThreadHead"></p>
              <p class="chat-thread-hint">
                This is the person you’re messaging (recipient), not your own key. Your fingerprint is under <strong>Chats»</strong> in the sidebar.
              </p>
            </div>
            <div class="chat-composer">
              <label for="chatBody">Message</label>
              <textarea id="chatBody" placeholder="Type a message…" rows="4"></textarea>
              <div class="row chat-composer-actions">
                <button type="button" id="chatSend">Send</button>
              </div>
              <p class="status" id="chatSendStatus"></p>
            </div>
            <div class="chat-messages" id="chatMessages"></div>
          </div>
        </section>

        <section id="view-server" class="view-panel" role="tabpanel" aria-labelledby="tab-server" hidden>
          <div class="row">
            <div>
              <label for="serverUrl">API base URL</label>
              <input type="text" id="serverUrl" placeholder="https://chat.example.com" autocomplete="off" />
            </div>
            <button type="button" class="secondary" id="saveServer">Save</button>
          </div>
          <p class="server-stats" id="serverStats">
            Registered identities (all time): <strong id="statsIdentities">—</strong>
          </p>
          <p class="server-retention" id="serverRetention">
            Queued mail is deleted after <strong><span id="retentionDays">—</span> days</strong> if not collected (server policy).
          </p>
          <p class="status" id="serverStatus"></p>
        </section>

        <section id="view-keys" class="view-panel" role="tabpanel" aria-labelledby="tab-keys" hidden>
          <p class="key-intro"><strong>Fingerprint</strong> = your address. Share it so others can reach you.</p>

          <details class="key-disclosure" open>
            <summary class="key-summary">Public» <span class="key-tag">safe to share</span></summary>
            <div class="key-disclosure-body">
              <div class="key-block key-public">
                <p class="key-help">Contacts need this to encrypt to you (or fetch by fingerprint from this server).</p>
                <label for="pubKeyB64">Public key (base64)</label>
                <textarea
                  id="pubKeyB64"
                  readonly
                  spellcheck="false"
                  autocomplete="off"
                  rows="3"
                  class="share-field-textarea key-pub-field"
                  title="Read-only — select text, then copy"
                ></textarea>
                <div class="row key-download-row">
                  <button type="button" class="secondary" id="dlPublic">Download public key (.txt)</button>
                </div>
                <p class="fp-label">Fingerprint (short)</p>
                <p class="fp" id="fpShort"></p>
                <p class="fp-label">Fingerprint (full hex)</p>
                <p class="fp" id="fpFull"></p>
                <div class="qr-row">
                  <div class="qr-wrap">
                    <p class="qr-caption">Contact QR <span class="qr-hint">fingerprint + server</span></p>
                    <img id="qrContact" class="qr-img" width="180" height="180" alt="" />
                  </div>
                  <div class="qr-wrap">
                    <p class="qr-caption">Public key QR <span class="qr-hint">base64</span></p>
                    <img id="qrPublic" class="qr-img" width="180" height="180" alt="" />
                  </div>
                </div>
              </div>
            </div>
          </details>

          <details class="key-disclosure" open>
            <summary class="key-summary">Private» <span class="key-tag key-tag-danger">never share</span></summary>
            <div class="key-disclosure-body">
              <div class="key-block key-private">
                <p class="key-help">Full access + impersonation. Stays in-browser unless you export.</p>
                <p class="fp mono" id="privKeyB64"></p>
                <div class="row key-download-row">
                  <button type="button" class="secondary" id="dlPrivate">Download private key (.txt)</button>
                </div>
              </div>
            </div>
          </details>

          <div class="row" style="margin-top:0.75rem">
            <button type="button" class="secondary" id="newKeys">New keys</button>
            <button type="button" class="secondary" id="registerBtn">Re-register</button>
          </div>
          <p class="status" id="regStatus"></p>
        </section>

        <section id="view-library" class="view-panel" role="tabpanel" aria-labelledby="tab-library" hidden>
          <p class="key-intro"><span class="badge">local decrypt</span> Inbox history stored in this tab.</p>
          <div class="row">
            <div style="flex:2 1 220px">
              <label for="librarySearch">Search</label>
              <input type="text" id="librarySearch" placeholder="text, sender, date…" autocomplete="off" />
            </div>
          </div>
          <div class="messages" id="libraryList"></div>
          <div class="library-pager" id="libraryPager">
            <button type="button" class="secondary" id="libraryPrev">Previous</button>
            <span class="library-page-info" id="libraryPageInfo"></span>
            <button type="button" class="secondary" id="libraryNext">Next</button>
          </div>
        </section>

        <section id="view-about" class="view-panel" role="tabpanel" aria-labelledby="tab-about" hidden>
          <div class="panel about-panel">
            <h2>Why it’s safe</h2>
            <p class="about-lead">
              This app is built for <strong>end-to-end encryption</strong>: only you and your contact can read message content.
            </p>
            <ul class="about-list">
              <li>
                <strong>Keys stay in your browser.</strong> Your secret key never leaves this device unless you explicitly export it. The relay never receives it.
              </li>
              <li>
                <strong>The server never sees plaintext.</strong> Outgoing mail is encrypted on your machine with <span class="mono-inline">tweetnacl</span> (NaCl box: Curve25519 + XSalsa20-Poly1305). The relay stores and forwards ciphertext only — it cannot decrypt your conversations.
              </li>
              <li>
                <strong>Minimal trust in infrastructure.</strong> A compromised or nosy host still cannot read your messages without your keys. Worst case it can affect availability or metadata policy, not message contents.
              </li>
            </ul>
          </div>
          <div class="panel about-panel">
            <h2>Verify the code · run it yourself</h2>
            <p class="about-lead">
              The project is <strong>open source</strong> (MIT). You are not asked to trust a black box.
            </p>
            <ul class="about-list">
              <li>
                <strong>Auditable client.</strong> All cryptography runs in this page’s JavaScript — read <span class="mono-inline">client/src/crypto.ts</span> and follow the data path from compose → encrypt → network. Build the same bundle and compare hashes if you want hard verification.
              </li>
              <li>
                <strong>Self-host everything.</strong> Run your own API relay and serve this static client from your machine or CDN. Point the <strong>server</strong> tab at your base URL and you control retention, uptime, and who can register.
              </li>
              <li>
                <strong>FOSS freedom.</strong> Use, modify, and redistribute the software under the MIT License. No vendor lock-in: your keys and your deployment are yours.
              </li>
            </ul>
          </div>
        </section>
      </main>
    </div>

    <footer class="site-footer">
      <div class="footer-live" id="liveStrip" aria-label="Connection status">
        <span id="liveIndicator" class="live-badge connecting">Connecting…</span>
        <span class="live-hint" id="liveHint"></span>
      </div>
      <p class="footer-meta">v0.1.0 · Made with ☕ + ♥️ · © 2026 3233.io</p>
    </footer>
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
  const pubKeyB64 = app.querySelector<HTMLTextAreaElement>("#pubKeyB64")!;
  const privKeyB64 = app.querySelector("#privKeyB64")!;
  const fpShortEl = app.querySelector("#fpShort")!;
  const fpFullEl = app.querySelector("#fpFull")!;
  const regStatus = app.querySelector<HTMLElement>("#regStatus")!;
  const registerBtn = app.querySelector("#registerBtn")!;
  const newKeys = app.querySelector("#newKeys")!;
  const inviteLinkInput = app.querySelector<HTMLInputElement>("#inviteLinkInput")!;
  const publicKeyShareInput = app.querySelector<HTMLInputElement>("#publicKeyShareInput")!;
  const openChatFpEl = app.querySelector<HTMLInputElement>("#openChatFp")!;
  const openChatBtn = app.querySelector<HTMLButtonElement>("#openChatBtn")!;
  const chatTabsEl = app.querySelector("#chatTabs")!;
  const chatThread = app.querySelector<HTMLElement>("#chatThread")!;
  const chatThreadHead = app.querySelector("#chatThreadHead")!;
  const chatMessages = app.querySelector("#chatMessages")!;
  const chatBodyEl = app.querySelector<HTMLTextAreaElement>("#chatBody")!;
  const chatSend = app.querySelector<HTMLButtonElement>("#chatSend")!;
  const chatSendStatus = app.querySelector("#chatSendStatus")!;
  const chatEmptyHint = app.querySelector<HTMLElement>("#chatEmptyHint")!;
  const openChatStatus = app.querySelector<HTMLElement>("#openChatStatus")!;
  const libraryList = app.querySelector("#libraryList")!;
  const librarySearch = app.querySelector<HTMLInputElement>("#librarySearch")!;
  const libraryPager = app.querySelector<HTMLElement>("#libraryPager")!;
  const libraryPageInfo = app.querySelector("#libraryPageInfo")!;
  const libraryPrev = app.querySelector<HTMLButtonElement>("#libraryPrev")!;
  const libraryNext = app.querySelector<HTMLButtonElement>("#libraryNext")!;
  const sidebarFpShort = app.querySelector("#sidebarFpShort")!;
  const viewPanels = app.querySelectorAll<HTMLElement>(".view-panel");
  const dashTabs = app.querySelectorAll<HTMLButtonElement>(".dash-tab[data-view]");

  function showView(view: string) {
    for (const btn of dashTabs) {
      const v = btn.getAttribute("data-view");
      const on = v === view;
      btn.classList.toggle("active", on);
      btn.setAttribute("aria-selected", on ? "true" : "false");
    }
    for (const panel of viewPanels) {
      const id = panel.id.replace("view-", "");
      panel.hidden = id !== view;
    }
  }

  function navigateToView(view: ViewId, opts?: { replace?: boolean }) {
    showView(view);
    applyRouteSeo(view);
    const path = viewToPath(view);
    if (opts?.replace) {
      history.replaceState({ view }, "", path);
    } else {
      history.pushState({ view }, "", path);
    }
  }

  function syncViewFromUrl() {
    const path = normalizePathname(window.location.pathname);
    if (path === "/") {
      history.replaceState(
        { view: "chats" },
        "",
        "/chats" + window.location.search + window.location.hash,
      );
      showView("chats");
      applyRouteSeo("chats");
      return;
    }
    const v = pathnameToView(path);
    if (!v) {
      history.replaceState({ view: "chats" }, "", "/chats");
      showView("chats");
      applyRouteSeo("chats");
      return;
    }
    showView(v);
    applyRouteSeo(v);
  }

  function initRoute() {
    syncViewFromUrl();
  }

  for (const btn of dashTabs) {
    btn.addEventListener("click", () => {
      const v = btn.getAttribute("data-view");
      if (v && VIEW_IDS.includes(v as ViewId)) navigateToView(v as ViewId);
    });
  }

  window.addEventListener("popstate", () => syncViewFromUrl());

  initRoute();

  const brandLink = app.querySelector<HTMLAnchorElement>("a.brand-name");
  if (brandLink) {
    brandLink.addEventListener("click", (ev) => {
      if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
      ev.preventDefault();
      navigateToView("chats");
    });
  }

  serverUrlEl.value = getServerUrl();
  fpShortEl.textContent = shortFingerprint(fingerprint);
  sidebarFpShort.textContent = shortFingerprint(fingerprint);
  fpFullEl.textContent = fingerprint;
  const pubB64 = b64encode(pair.publicKey);
  pubKeyB64.value = pubB64;
  publicKeyShareInput.value = pubB64;
  privKeyB64.textContent = b64encode(pair.secretKey);

  let openChatIds: string[] = loadOpenChats();
  let activeChatFp: string | null =
    openChatIds.length > 0 ? openChatIds[0]! : null;

  function openChatWithFingerprint(raw: string): boolean {
    const fp = normalizeFingerprint(raw.trim());
    if (!fp) return false;
    if (!openChatIds.includes(fp)) {
      openChatIds.push(fp);
      saveOpenChats(openChatIds);
    }
    activeChatFp = fp;
    renderChatTabs();
    renderActiveThread();
    return true;
  }

  function buildInviteLink(): string {
    const u = new URL(`${window.location.origin}/chats`);
    u.searchParams.set("chat", fingerprint);
    const api = apiBase();
    const pageOrigin = window.location.origin.replace(/\/$/, "");
    if (api !== pageOrigin) {
      u.searchParams.set("server", api);
    }
    return u.toString();
  }

  function updateInviteLinkDisplay() {
    const url = buildInviteLink();
    inviteLinkInput.value = url;
  }

  function stripInviteParamsFromUrl() {
    const u = new URL(window.location.href);
    u.searchParams.delete("chat");
    u.searchParams.delete("fp");
    u.searchParams.delete("server");
    const next = u.pathname + (u.search ? u.search : "") + u.hash;
    history.replaceState({}, "", next);
  }

  async function applyInviteFromUrl() {
    const params = new URLSearchParams(window.location.search);
    const chatRaw = (params.get("chat") ?? params.get("fp"))?.trim() ?? "";
    const serverRaw = params.get("server")?.trim() ?? "";
    if (!chatRaw && !serverRaw) return;

    if (serverRaw) {
      const next = parseHttpUrlOrNull(serverRaw);
      if (!next) {
        openChatStatus.textContent = "Invalid server URL in invite link.";
        openChatStatus.className = "status err";
        navigateToView("chats", { replace: true });
        stripInviteParamsFromUrl();
        return;
      }
      const cur = getServerUrl().replace(/\/$/, "");
      if (next !== cur) {
        setServerUrl(next);
        localStorage.removeItem(LS_TOKEN);
        await runSessionSetup({ resetLibrary: true });
      }
    }

    if (chatRaw) {
      const ok = openChatWithFingerprint(chatRaw);
      if (!ok) {
        openChatStatus.textContent =
          "Invalid fingerprint in invite link (need 64 hex characters).";
        openChatStatus.className = "status err";
      }
      navigateToView("chats", { replace: true });
    }

    stripInviteParamsFromUrl();
  }

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

  function renderChatTabs() {
    chatTabsEl.innerHTML = "";
    for (const fp of openChatIds) {
      const wrap = document.createElement("div");
      wrap.className = "chat-tab" + (fp === activeChatFp ? " active" : "");
      const label = document.createElement("button");
      label.type = "button";
      label.className = "chat-tab-label";
      label.textContent = shortFingerprint(fp);
      label.title = fp;
      label.addEventListener("click", () => {
        activeChatFp = fp;
        renderChatTabs();
        renderActiveThread();
      });
      const close = document.createElement("button");
      close.type = "button";
      close.className = "chat-tab-close";
      close.setAttribute("aria-label", "Close chat");
      close.textContent = "×";
      close.addEventListener("click", (ev) => {
        ev.stopPropagation();
        openChatIds = openChatIds.filter((id) => id !== fp);
        saveOpenChats(openChatIds);
        if (activeChatFp === fp) {
          activeChatFp = openChatIds[0] ?? null;
        }
        renderChatTabs();
        renderActiveThread();
      });
      wrap.appendChild(label);
      wrap.appendChild(close);
      chatTabsEl.appendChild(wrap);
    }
  }

  function renderActiveThread() {
    if (!activeChatFp) {
      chatThread.hidden = true;
      chatEmptyHint.hidden = false;
      return;
    }
    chatEmptyHint.hidden = true;
    chatThread.hidden = false;
    chatThreadHead.textContent = `${shortFingerprint(activeChatFp)} · ${activeChatFp.slice(0, 18)}…`;
    const incoming = libraryEntries.filter((e) => e.senderFp === activeChatFp);
    const sent = loadSentMap()[activeChatFp] ?? [];
    const lines: { kind: "in" | "out"; ts: number; text: string }[] = [];
    for (const e of incoming) {
      lines.push({ kind: "in", ts: e.serverTs, text: e.text });
    }
    for (const s of sent) {
      lines.push({ kind: "out", ts: s.ts, text: s.text });
    }
    lines.sort((a, b) => b.ts - a.ts);
    chatMessages.innerHTML = "";
    for (const L of lines) {
      const row = document.createElement("div");
      row.className =
        "chat-line " + (L.kind === "out" ? "chat-line-out" : "chat-line-in");
      row.innerHTML = `<div class="chat-bubble">${escapeHtml(L.text)}</div><div class="chat-ts">${escapeHtml(
        new Date(L.ts).toLocaleString(),
      )}</div>`;
      chatMessages.appendChild(row);
    }
    chatMessages.scrollTop = 0;
  }

  syncTabsAfterBackfill = () => {
    const seen = new Set<string>();
    for (const e of libraryEntries) {
      if (e.senderFp) seen.add(e.senderFp);
    }
    let changed = false;
    for (const fp of seen) {
      if (!openChatIds.includes(fp)) {
        openChatIds.push(fp);
        changed = true;
      }
    }
    if (changed) saveOpenChats(openChatIds);
    if (!activeChatFp && openChatIds.length > 0) {
      activeChatFp = openChatIds[0]!;
    }
    renderChatTabs();
    renderActiveThread();
  };

  onNewPolledEntry = (entry) => {
    const fp = entry.senderFp;
    if (!fp) return;
    if (!openChatIds.includes(fp)) {
      openChatIds.push(fp);
      saveOpenChats(openChatIds);
    }
    activeChatFp = fp;
    renderChatTabs();
    renderActiveThread();
  };

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
    renderActiveThread();
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
    updateInviteLinkDisplay();
  });

  registerBtn.addEventListener("click", async () => {
    localStorage.removeItem(LS_TOKEN);
    await runSessionSetup({ resetLibrary: true });
    updateInviteLinkDisplay();
  });

  newKeys.addEventListener("click", () => {
    if (!confirm("Generate new keys? This cannot be undone.")) return;
    localStorage.removeItem(LS_SK);
    localStorage.removeItem(LS_PK);
    localStorage.removeItem(LS_TOKEN);
    localStorage.removeItem(LS_OPEN_CHATS);
    localStorage.removeItem(LS_SENT);
    location.reload();
  });

  function openChatFromInput() {
    openChatStatus.textContent = "";
    openChatStatus.className = "status";
    const ok = openChatWithFingerprint(openChatFpEl.value);
    if (!ok) {
      openChatStatus.textContent =
        "Enter a valid public key fingerprint (64 hex characters).";
      openChatStatus.className = "status err";
      return;
    }
    openChatFpEl.value = "";
  }

  openChatBtn.addEventListener("click", openChatFromInput);
  openChatFpEl.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      openChatFromInput();
    }
  });

  updateInviteLinkDisplay();

  chatSend.addEventListener("click", async () => {
    chatSendStatus.textContent = "";
    chatSendStatus.className = "status";
    const rf = activeChatFp;
    if (!rf) {
      chatSendStatus.textContent = "Open a chat tab first.";
      chatSendStatus.className = "status err";
      return;
    }
    const text = chatBodyEl.value.trim();
    if (!text) {
      chatSendStatus.textContent = "Enter a message.";
      chatSendStatus.className = "status err";
      return;
    }
    chatSend.disabled = true;
    const res = await sendMessage(pair, rf, text);
    chatSend.disabled = false;
    if (res.ok) {
      chatSendStatus.textContent = "Sent.";
      chatSendStatus.className = "status ok";
      appendSent(rf, text);
      chatBodyEl.value = "";
      renderActiveThread();
    } else {
      chatSendStatus.textContent = res.err ?? "Send failed";
      chatSendStatus.className = "status err";
    }
  });

  renderChatTabs();
  renderActiveThread();
  renderLibrary();
  await runSessionSetup({ resetLibrary: false });
  await applyInviteFromUrl();
  updateInviteLinkDisplay();
  window.setInterval(() => void refreshLibrary(), 30000);
  window.setInterval(() => void refreshServerStats(), 60000);
}

main().catch((e) => {
  console.error(e);
  document.querySelector("#app")!.innerHTML = `<p class="status err">${String(e)}</p>`;
});
