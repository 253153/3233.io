import {
  type BoxKeyPair,
  b64decode,
  b64encode,
  decryptFromSender,
  encryptChallengeForServer,
  encryptForRecipient,
  fingerprintFromPublicKey,
  generateKeyPair,
  shortFingerprint,
} from "./crypto";
import { toQrDataUrl } from "./qr";
import {
  buildNotifBody,
  escapeHtml,
  localCasClaim,
  normalizeFingerprint,
  normalizePathname,
  pathnameToView as pathnameToViewRaw,
  viewToPath,
} from "./helpers";
import "./style.css";

const LS_SERVER = "io3233_server_url";
const LS_SK = "io3233_secret_key";
const LS_PK = "io3233_public_key";
const LS_TOKEN = "io3233_token";
const LS_OPEN_CHATS = "io3233_open_chats";
const LS_SENT = "io3233_sent_by_contact_v1";
const LS_LAST_READ = "io3233_last_read_msg_id_by_fp_v1";
const LS_THEME = "io3233_theme";

type SentLine = { ts: number; text: string; id?: number };

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

/** NaCl box public key length (Curve25519), bytes */
const BOX_PK_BYTES = 32;

/** Resolve a short/full hex prefix search against the server. */
async function searchFingerprintByPrefix(prefix: string): Promise<string | null> {
  try {
    const r = await fetch(`${apiBase()}/v1/keys/search/${encodeURIComponent(prefix)}`);
    if (!r.ok) return null;
    const j = (await r.json()) as { fingerprints: string[] };
    if (j.fingerprints.length === 1) return j.fingerprints[0]!;
    return null;
  } catch {
    return null;
  }
}

/** Fingerprint (64 hex), short fingerprint (3233:xxxx), or base64 NaCl box public key. */
async function resolveRecipientFingerprint(raw: string): Promise<string | null> {
  let compact = raw.trim().replace(/\s+/g, "");
  if (!compact) return null;

  // Strip 3233: prefix if present
  if (compact.toLowerCase().startsWith("3233:")) {
    compact = compact.slice(5);
  }

  const hex = normalizeFingerprint(compact);
  if (hex) return hex;

  // If it looks like a hex prefix (8–63 chars), try a server prefix search
  const lower = compact.toLowerCase();
  if (/^[0-9a-f]{8,63}$/.test(lower)) {
    return searchFingerprintByPrefix(lower);
  }

  try {
    const pk = b64decode(compact);
    if (pk.length !== BOX_PK_BYTES) return null;
    return await fingerprintFromPublicKey(pk);
  } catch {
    return null;
  }
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

const VIEW_IDS = ["newchat", "chats", "server", "keys", "library", "about"] as const;
type ViewId = (typeof VIEW_IDS)[number];

function pathnameToView(pathname: string): ViewId | null {
  return pathnameToViewRaw(pathname, VIEW_IDS) as ViewId | null;
}

const ROUTE_SEO: Record<ViewId, { title: string; description: string }> = {
  newchat: {
    title: "Home — 3233.io · ~/encrypted relay",
    description:
      "Your invite link and public key on this relay. Share them so others can open a chat with you or encrypt to you. Keys stay in your browser.",
  },
  chats: {
    title: "Chats — 3233.io · ~/encrypted relay",
    description:
      "Read and send end-to-end encrypted messages. Pick a thread in the sidebar or add a contact from the home page.",
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

async function copyTextToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through */
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

function applyRouteSeo(view: ViewId) {
  const seo = ROUTE_SEO[view];
  document.title = seo.title;
  setMetaByName("description", seo.description);
  setMetaByProperty("og:title", seo.title);
  setMetaByProperty("og:description", seo.description);
  const url = `${window.location.origin}${viewToPath(view)}`;
  setMetaByProperty("og:url", url);
  const ogImage = `${window.location.origin}/og-image.png`;
  setMetaByProperty("og:image", ogImage);
  setMetaByName("twitter:card", "summary_large_image");
  setMetaByName("twitter:title", seo.title);
  setMetaByName("twitter:description", seo.description);
  setMetaByName("twitter:image", ogImage);
  setCanonicalLink(url);
}

function applyInviteSeo() {
  const params = new URLSearchParams(window.location.search);
  if (!params.has("chat") && !params.has("fp")) return;
  const title = "Chat securely on 3233.io";
  const description = "Open this link to start an end-to-end encrypted conversation. Keys stay in your browser.";
  const ogImage = `${window.location.origin}/og-image.png`;
  document.title = title;
  setMetaByName("description", description);
  setMetaByProperty("og:title", title);
  setMetaByProperty("og:description", description);
  setMetaByProperty("og:image", ogImage);
  setMetaByProperty("og:url", window.location.href);
  setMetaByName("twitter:card", "summary_large_image");
  setMetaByName("twitter:title", title);
  setMetaByName("twitter:description", description);
  setMetaByName("twitter:image", ogImage);
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

function loadLastReadMap(): Record<string, number> {
  try {
    const raw = localStorage.getItem(LS_LAST_READ);
    if (!raw) return {};
    const j = JSON.parse(raw) as Record<string, number>;
    if (!j || typeof j !== "object") return {};
    const out: Record<string, number> = {};
    for (const [k, v] of Object.entries(j)) {
      const fp = normalizeFingerprint(k);
      if (fp && typeof v === "number" && Number.isFinite(v)) out[fp] = v;
    }
    return out;
  } catch {
    return {};
  }
}

function saveLastReadMap(m: Record<string, number>) {
  localStorage.setItem(LS_LAST_READ, JSON.stringify(m));
}

function appendSent(toFp: string, text: string, ts?: number, id?: number) {
  const fp = toFp.toLowerCase();
  const m = loadSentMap();
  if (!m[fp]) m[fp] = [];
  m[fp].push({ ts: ts ?? Date.now(), text, ...(id !== undefined ? { id } : {}) });
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
/** Set from main(): deliver all newly pulled messages as a single batch so the
 * handler can decide whether to fan them out per-entry or coalesce into a
 * summary notification. */
let onNewPolledEntries: ((entries: LibraryEntry[]) => void) | undefined;

/** Threshold above which we coalesce per-entry notifications into one summary. */
const NOTIF_BATCH_COALESCE_MIN = 4;

async function register(pair: BoxKeyPair): Promise<{ ok: boolean; err?: string }> {
  // Step 1: ask the server for a single-use PoP challenge bound to our pubkey.
  const chalResp = await fetch(`${apiBase()}/v1/register/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ public_key: b64encode(pair.publicKey) }),
  });
  if (!chalResp.ok) {
    const t = await chalResp.text();
    return { ok: false, err: t || chalResp.statusText };
  }
  const chal = (await chalResp.json()) as {
    challenge: string;
    server_public_key: string;
    expires_in: number;
  };
  const challenge = b64decode(chal.challenge);
  const serverPk = b64decode(chal.server_public_key);

  // Step 2: NaCl-box the challenge back to the server with our secret key.
  // If our secret matches the claimed pubkey, the server can decrypt; that's
  // the proof-of-possession.
  const { ciphertext, nonce } = encryptChallengeForServer(
    challenge,
    serverPk,
    pair,
  );

  const r = await fetch(`${apiBase()}/v1/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      public_key: b64encode(pair.publicKey),
      challenge: chal.challenge,
      proof_nonce: b64encode(nonce),
      proof_ciphertext: b64encode(ciphertext),
    }),
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
): Promise<{ ok: boolean; err?: string; id?: number; serverTs?: number }> {
  const token = getToken();
  if (!token) return { ok: false, err: "Not registered" };
  let recipientPk: Uint8Array;
  try {
    recipientPk = await fetchRecipientPk(recipientFingerprint.trim());
  } catch (e) {
    const m = (e as Error).message || String(e);
    if (/HTTP 404|not registered|no such user/i.test(m)) {
      return { ok: false, err: "Recipient not registered yet." };
    }
    return { ok: false, err: "Couldn't reach server." };
  }
  const body = JSON.stringify({ text, ts: Date.now() });
  const enc = new TextEncoder().encode(body);
  const { ciphertext, nonce } = encryptForRecipient(enc, recipientPk, pair);
  let r: Response;
  try {
    r = await fetch(`${apiBase()}/v1/messages`, {
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
  } catch {
    return { ok: false, err: "You appear to be offline." };
  }
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    return { ok: false, err: t || r.statusText };
  }
  try {
    const j = (await r.json()) as { id?: number; created_at?: string };
    const serverTs = j.created_at ? Date.parse(j.created_at) : undefined;
    return { ok: true, id: j.id, serverTs: Number.isFinite(serverTs) ? serverTs : undefined };
  } catch {
    return { ok: true };
  }
}

type ServerMessage = {
  id: number;
  sender_fingerprint: string | null;
  ciphertext: string;
  nonce: string;
  sender_public_key: string;
  created_at: string;
};

function formatLibraryDate(ts: number): string {
  if (!ts) return "";
  const d = new Date(ts);
  return d.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function decryptServerMessage(m: ServerMessage, pair: BoxKeyPair): LibraryEntry {
  const serverTs = Date.parse(m.created_at) || 0;
  const senderFp = m.sender_fingerprint
    ? m.sender_fingerprint.toLowerCase()
    : null;
  const ct = b64decode(m.ciphertext);
  const nonce = b64decode(m.nonce);
  const senderPk = b64decode(m.sender_public_key);
  const plain = decryptFromSender(ct, nonce, senderPk, pair);
  const when = formatLibraryDate(serverTs);
  if (!plain) {
    return {
      id: m.id,
      text: "(decrypt failed)",
      meta: `#${m.id} · ${when}`,
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
    meta: `${short} · ${when}`,
    senderFp,
    serverTs,
  };
}

/**
 * Insert one entry while keeping `libraryEntries` sorted descending by id.
 *
 * Uses binary-search + splice (O(n) worst case per insert) instead of
 * re-sorting the whole array (O(n log n) per insert), so full backfills stay
 * linearithmic overall rather than quadratic.
 */
function mergeLibraryEntry(entry: LibraryEntry): boolean {
  if (libraryById.has(entry.id)) return false;
  libraryById.set(entry.id, entry);
  let lo = 0;
  let hi = libraryEntries.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (libraryEntries[mid]!.id > entry.id) lo = mid + 1;
    else hi = mid;
  }
  libraryEntries.splice(lo, 0, entry);
  return true;
}

/**
 * Bulk-merge many entries at once. Deduplicates via `libraryById` then sorts
 * only once at the end. Used by the initial history backfill where N messages
 * arrive up-front and individual binary insertion would still be O(N log N)
 * worth of splices.
 */
function mergeLibraryEntries(entries: LibraryEntry[]): LibraryEntry[] {
  const added: LibraryEntry[] = [];
  for (const e of entries) {
    if (libraryById.has(e.id)) continue;
    libraryById.set(e.id, e);
    libraryEntries.push(e);
    added.push(e);
  }
  if (added.length > 0) {
    libraryEntries.sort((a, b) => b.id - a.id);
  }
  return added;
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
    const batch: LibraryEntry[] = [];
    for (const m of j.messages) {
      batch.push(decryptServerMessage(m, pair));
      lastMsgId = Math.max(lastMsgId, m.id);
      cursor = m.id;
    }
    mergeLibraryEntries(batch);
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
  const fresh: LibraryEntry[] = [];
  for (const m of j.messages) {
    if (m.id <= lastMsgId) continue;
    lastMsgId = m.id;
    const entry = decryptServerMessage(m, pair);
    if (mergeLibraryEntry(entry)) fresh.push(entry);
  }
  if (fresh.length > 0) onNewPolledEntries?.(fresh);
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

function getPreferredTheme(): "dark" | "light" {
  const saved = localStorage.getItem(LS_THEME);
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function applyTheme(theme: "dark" | "light") {
  document.documentElement.setAttribute("data-theme", theme);
  const meta = document.querySelector('meta[name="theme-color"]') as HTMLMetaElement | null;
  if (meta) meta.content = theme === "light" ? "#ffffff" : "#000000";
}

applyTheme(getPreferredTheme());

/* ------------------------------------------------------------------ */
/*                         Browser notifications                       */
/* ------------------------------------------------------------------ */

type NotifPermission = "default" | "granted" | "denied" | "unsupported";

const NOTIF_READY_TIMEOUT_MS = 1500;

function notifSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    "Notification" in window &&
    "serviceWorker" in navigator
  );
}

function getNotifPermission(): NotifPermission {
  if (!notifSupported()) return "unsupported";
  const p = Notification.permission;
  if (p === "granted" || p === "denied" || p === "default") return p;
  return "default";
}

/**
 * Normalize requestPermission across browsers. Safari < 16 exposes the old
 * callback-only form that returns undefined; we treat both shapes uniformly.
 */
async function requestNotifPermission(): Promise<NotifPermission> {
  if (!notifSupported()) return "unsupported";
  try {
    const maybe = Notification.requestPermission();
    const res =
      maybe && typeof (maybe as Promise<NotificationPermission>).then === "function"
        ? await (maybe as Promise<NotificationPermission>)
        : await new Promise<NotificationPermission>((resolve) => {
            try {
              (Notification.requestPermission as unknown as (
                cb: (p: NotificationPermission) => void,
              ) => void)((p) => resolve(p));
            } catch {
              resolve(getNotifPermission() as NotificationPermission);
            }
          });
    return res === "granted" || res === "denied" || res === "default"
      ? res
      : "default";
  } catch {
    return getNotifPermission();
  }
}

/** Resolve the active SW registration, or null if it doesn't settle in time. */
function readyRegistrationOrNull(): Promise<ServiceWorkerRegistration | null> {
  if (!("serviceWorker" in navigator)) return Promise.resolve(null);
  let done = false;
  return new Promise((resolve) => {
    const timer = window.setTimeout(() => {
      if (!done) {
        done = true;
        resolve(null);
      }
    }, NOTIF_READY_TIMEOUT_MS);
    navigator.serviceWorker.ready
      .then((reg) => {
        if (done) return;
        done = true;
        window.clearTimeout(timer);
        resolve(reg);
      })
      .catch(() => {
        if (done) return;
        done = true;
        window.clearTimeout(timer);
        resolve(null);
      });
  });
}

async function claimNotifSlot(msgId: number): Promise<boolean> {
  const locks = (navigator as unknown as {
    locks?: {
      request: (
        name: string,
        options: { mode: "exclusive" | "shared" },
        cb: () => Promise<boolean>,
      ) => Promise<boolean>;
    };
  }).locks;
  if (locks && typeof locks.request === "function") {
    try {
      return await locks.request(
        "3233:notif-cursor",
        { mode: "exclusive" },
        async () => localCasClaim(msgId),
      );
    } catch {
      return localCasClaim(msgId);
    }
  }
  return localCasClaim(msgId);
}

type NotifPayload = {
  title: string;
  body: string;
  senderFp: string;
  msgId: number;
};

async function showLocalNotification(payload: NotifPayload): Promise<void> {
  if (getNotifPermission() !== "granted") return;
  if (!(await claimNotifSlot(payload.msgId))) return;

  const url = `/chats?chat=${encodeURIComponent(payload.senderFp)}`;
  const options: NotificationOptions & { renotify?: boolean } = {
    icon: "/icon-192.png",
    badge: "/favicon-32.png",
    tag: `3233-msg-${payload.senderFp}`,
    renotify: true,
    data: { url, senderFp: payload.senderFp, msgId: payload.msgId },
  };
  if (payload.body) options.body = payload.body;

  const reg = await readyRegistrationOrNull();
  if (reg) {
    try {
      await reg.showNotification(payload.title, options);
      return;
    } catch {
      /* fall through */
    }
  }

  try {
    const n = new Notification(payload.title, options);
    n.onclick = () => {
      try {
        window.focus();
      } catch {
        /* ignore */
      }
      try {
        n.close();
      } catch {
        /* ignore */
      }
      const u = new URL(url, window.location.origin);
      window.location.assign(u.toString());
    };
  } catch {
    /* ignore: quota, insecure context, etc. */
  }
}

/**
 * Show a coalesced "N new messages" notification when a single pull returns a
 * flood. Uses the largest msg id to claim the slot atomically across tabs.
 */
async function showBatchNotification(
  entries: LibraryEntry[],
): Promise<void> {
  if (getNotifPermission() !== "granted") return;
  if (entries.length === 0) return;
  const maxId = entries.reduce((a, e) => Math.max(a, e.id), 0);
  if (!(await claimNotifSlot(maxId))) return;

  const senders = new Set(entries.map((e) => e.senderFp).filter(Boolean));
  const senderCount = senders.size;
  const single = senderCount === 1 ? [...senders][0]! : null;

  const title = `${entries.length} new messages`;
  const body = single
    ? `From 3233:${single.slice(0, 8)}. Open to read.`
    : `From ${senderCount} senders. Open to read.`;

  const url = single ? `/chats?chat=${encodeURIComponent(single)}` : "/chats";

  const options: NotificationOptions & { renotify?: boolean } = {
    body,
    icon: "/icon-192.png",
    badge: "/favicon-32.png",
    tag: "3233-msg-batch",
    renotify: true,
    data: { url, batch: true, count: entries.length, maxId },
  };

  const reg = await readyRegistrationOrNull();
  if (reg) {
    try {
      await reg.showNotification(title, options);
      return;
    } catch {
      /* fall through */
    }
  }

  try {
    const n = new Notification(title, options);
    n.onclick = () => {
      try {
        window.focus();
      } catch {
        /* ignore */
      }
      try {
        n.close();
      } catch {
        /* ignore */
      }
      const u = new URL(url, window.location.origin);
      window.location.assign(u.toString());
    };
  } catch {
    /* ignore */
  }
}

async function main() {
  const { pair, fingerprint } = await loadOrCreateKeys();

  const app = document.querySelector("#app")!;
  app.innerHTML = `
    <header class="site-header">
      <div class="site-brand">
        <a href="/newchat" class="brand-name"><b>3233</b></a>
        <span class="brand-path">~/encrypted relay</span>
      </div>
      <div class="site-header-actions" role="toolbar" aria-label="Quick actions">
        <button type="button" class="secondary site-header-btn" id="headerNewKeys">New keys</button>
        <button type="button" class="secondary site-header-btn" id="headerCopyInvite">Copy invite link</button>
        <button type="button" class="secondary site-header-btn" id="headerCopyAddress">Copy address</button>
      </div>
    </header>

    <div class="app-shell">
      <aside class="app-sidebar" aria-label="Sidebar">
        <nav class="dashboard-tabs sidebar-main-nav" role="tablist" aria-label="Main views">
          <button type="button" role="tab" class="dash-tab active" data-view="newchat" aria-selected="true" id="tab-newchat">home</button>
          <button type="button" role="tab" class="dash-tab" data-view="chats" aria-selected="false" id="tab-chats">chats</button>
          <button type="button" role="tab" class="dash-tab" data-view="server" aria-selected="false" id="tab-server">server</button>
          <button type="button" role="tab" class="dash-tab" data-view="keys" aria-selected="false" id="tab-keys">keys</button>
          <button type="button" role="tab" class="dash-tab" data-view="library" aria-selected="false" id="tab-library">library</button>
          <button type="button" role="tab" class="dash-tab" data-view="about" aria-selected="false" id="tab-about">about</button>
        </nav>
        <section class="sidebar-chats-panel" aria-label="Threads">
          <div class="sidebar-chat-tabs-wrap">
            <div id="chatTabs" class="chat-tabs chat-tabs--sidebar"></div>
          </div>
        </section>
      </aside>

      <main class="app-main">
        <section id="view-newchat" class="view-panel" role="tabpanel" aria-labelledby="tab-newchat">
          <aside class="home-intro" aria-label="How 3233 works">
            <p class="home-intro-lede">
              <strong>3233.io is a private, end-to-end encrypted chat relay — no accounts, no email, keys live only in this browser.</strong>
            </p>
            <p class="home-intro-steps">
              Share your <strong>invite link</strong> below so someone can reach you, then paste <strong>their</strong> fingerprint or public key into <strong>Open chat</strong> to start a thread. The relay only sees encrypted bytes.
            </p>
          </aside>
          <div class="invite-link-block">
            <p class="invite-link-hint">Your identity on this relay</p>
            <div class="share-field-group">
              <label for="inviteLinkInput">Invite link</label>
              <div class="share-field-row">
                <input
                  type="text"
                  id="inviteLinkInput"
                  readonly
                  spellcheck="false"
                  autocomplete="off"
                  class="share-field-input"
                  title="Read-only — tap to select, then copy"
                />
                <button
                  type="button"
                  class="secondary share-field-copy"
                  id="copyInviteLinkBtn"
                  aria-label="Copy invite link"
                >Copy</button>
              </div>
              <div class="invite-share-row" role="group" aria-label="Send your invite link">
                <span class="invite-share-label">Send via</span>
                <button type="button" class="secondary invite-share-btn" id="shareInviteNative" hidden>Share…</button>
                <a class="secondary invite-share-btn" id="shareInviteSms" role="button" rel="noopener noreferrer">Message</a>
                <a class="secondary invite-share-btn" id="shareInviteWhatsapp" role="button" target="_blank" rel="noopener noreferrer">WhatsApp</a>
                <a class="secondary invite-share-btn" id="shareInviteEmail" role="button" rel="noopener noreferrer">Email</a>
              </div>
            </div>
            <div class="share-field-group">
              <label for="publicKeyShareInput">Your public key (base64)</label>
              <div class="share-field-row">
                <input
                  type="text"
                  id="publicKeyShareInput"
                  readonly
                  spellcheck="false"
                  autocomplete="off"
                  class="share-field-input"
                  title="Read-only — tap to select, then copy"
                />
                <button
                  type="button"
                  class="secondary share-field-copy"
                  id="copyPublicKeyBtn"
                  aria-label="Copy public key"
                >Copy</button>
              </div>
            </div>
          </div>
          <div class="row open-chat-row">
            <div class="open-chat-input-wrap">
              <label for="openChatFp">Their fingerprint (64 hex) or public key (base64)</label>
              <input
                type="text"
                id="openChatFp"
                placeholder="Paste fingerprint or base64 public key…"
                autocomplete="off"
                inputmode="text"
                spellcheck="false"
              />
            </div>
            <button type="button" id="openChatBtn">Open chat</button>
          </div>
          <p class="status" id="openChatStatus" role="status" aria-live="polite"></p>
        </section>

        <section id="view-chats" class="view-panel" role="tabpanel" aria-labelledby="tab-chats" hidden>
          <div id="mobileChatTabs" class="chat-tabs chat-tabs--mobile"></div>
          <div class="empty-state chat-empty-hint" id="chatEmptyHint">
            <div class="empty-state-glyph" aria-hidden="true">[ ]</div>
            <h2 class="empty-state-title">No open threads</h2>
            <p class="empty-state-body">
              Open a conversation from <strong>home</strong>, or tap an invite link someone shared with you.
            </p>
            <button type="button" class="secondary empty-state-cta" id="chatEmptyGoNew">Go to home</button>
          </div>
          <div class="chat-thread" id="chatThread" hidden>
            <header class="chat-with-block">
              <div class="chat-thread-id-row">
                <span class="chat-with-label" aria-hidden="true">to</span>
                <p class="chat-thread-id mono" id="chatThreadHead"></p>
                <button type="button" class="secondary chat-thread-copy" id="chatThreadCopy" aria-label="Copy recipient fingerprint">Copy</button>
              </div>
            </header>
            <div class="chat-messages" id="chatMessages" aria-live="polite" aria-relevant="additions"></div>
            <div class="chat-composer">
              <label for="chatBody" class="sr-only">Message</label>
              <div class="chat-composer-row">
                <textarea id="chatBody" placeholder="Type a message…" rows="2" aria-label="Message"></textarea>
                <button type="button" id="chatSend">Send</button>
              </div>
              <p class="status chat-send-status" id="chatSendStatus" role="status" aria-live="polite"></p>
            </div>
          </div>
        </section>

        <section id="view-server" class="view-panel" role="tabpanel" aria-labelledby="tab-server" hidden>
          <p class="key-intro">
            Point this client at any 3233-compatible relay. Your keys stay in this browser; only ciphertext crosses the wire.
          </p>
          <div class="row">
            <div>
              <label for="serverUrl">API base URL</label>
              <input type="text" id="serverUrl" placeholder="https://chat.example.com" autocomplete="off" inputmode="url" spellcheck="false" />
            </div>
            <button type="button" id="saveServer">Save</button>
          </div>
          <p class="status" id="serverStatus" role="status" aria-live="polite"></p>
          <div class="server-info-grid" aria-label="Server stats">
            <div class="server-info-card">
              <div class="server-info-label">Registered identities</div>
              <div class="server-info-value mono"><span id="statsIdentities">—</span></div>
              <div class="server-info-hint">all time, this relay</div>
            </div>
            <div class="server-info-card">
              <div class="server-info-label">Mail retention</div>
              <div class="server-info-value mono"><span id="retentionDays">—</span> days</div>
              <div class="server-info-hint">queued mail deleted if uncollected</div>
            </div>
          </div>

          <aside class="server-selfhost" aria-label="Self-hosting">
            <h2 class="server-selfhost-title">Run your own relay or host your own client</h2>
            <p class="server-selfhost-lede">
              <strong>3233 is open source and designed to be self-hosted.</strong>
              The relay is a small Rust binary that only sees encrypted bytes; the client is a static HTML/JS bundle. Any 3233 client talks to any 3233 relay, so you can host one, the other, or both.
            </p>
            <ol class="server-selfhost-steps">
              <li>Clone <a class="mono-inline" href="https://github.com/253153/3233.io" target="_blank" rel="noopener noreferrer">github.com/253153/3233.io</a> and build with Docker Compose or <span class="mono-inline">cargo build --release</span> + <span class="mono-inline">vite build</span>.</li>
              <li>Run the server on any host you control; point the <strong>API base URL</strong> above at your deployment and press <strong>Save</strong>.</li>
              <li>Optional: serve the built client bundle next to the relay (set <span class="mono-inline">STATIC_DIR=client/dist</span>) so your users get a single-origin deployment.</li>
            </ol>
            <p class="server-selfhost-foot">
              The <a href="https://github.com/253153/3233.io#readme" target="_blank" rel="noopener noreferrer">README</a> has Docker Compose, bare-metal + nginx, and Let’s Encrypt walkthroughs. The wire protocol is documented in <span class="mono-inline">docs/PROTOCOL.md</span>.
            </p>
          </aside>
        </section>

        <section id="view-keys" class="view-panel" role="tabpanel" aria-labelledby="tab-keys" hidden>
          <p class="key-intro"><strong>Fingerprint</strong> = your address. Share it so others can reach you.</p>

          <details class="key-disclosure" open>
            <summary class="key-summary"><span class="key-summary-label">Public</span> <span class="key-tag">safe to share</span></summary>
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
            <summary class="key-summary"><span class="key-summary-label">Private</span> <span class="key-tag key-tag-danger">never share</span></summary>
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
          <div class="row library-search-row">
            <div class="library-search-wrap">
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
            <p class="about-lead">
              <strong>Encryption protocol:</strong> <span class="mono-inline">NaCl box</span> (Daniel J. Bernstein’s public-key “box” construction) — <span class="mono-inline">Curve25519</span> / X25519 for Diffie–Hellman and <span class="mono-inline">XSalsa20-Poly1305</span> for authenticated encryption. The browser uses the <span class="mono-inline">tweetnacl</span> implementation.
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
            <p class="about-lead about-source-link">
              <a
                class="about-source-cta"
                href="https://github.com/253153/3233.io"
                target="_blank"
                rel="noopener noreferrer"
              >Source code on GitHub →</a>
              <span class="about-source-note">server, client, and protocol docs.</span>
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
      <p class="footer-meta">
        <span class="footer-item">v0.1.0</span>
        <span class="footer-sep" aria-hidden="true">·</span>
        <span class="footer-item">© 2026 3233.io</span>
        <span class="footer-sep" aria-hidden="true">·</span>
        <a
          class="footer-link"
          href="https://github.com/253153/3233.io"
          target="_blank"
          rel="noopener noreferrer"
        >Source</a>
        <span class="footer-sep" aria-hidden="true">·</span>
        <a
          class="footer-link footer-link-discord"
          href="https://discord.gg/mzdVHjx9nE"
          target="_blank"
          rel="noopener noreferrer"
          aria-label="Join the 3233.io Discord server (opens in new tab)"
          title="Join the 3233.io Discord"
        >
          <svg
            class="footer-icon"
            viewBox="0 0 24 24"
            width="16"
            height="16"
            aria-hidden="true"
            focusable="false"
            fill="currentColor"
          ><path d="M20.317 4.369A19.79 19.79 0 0 0 16.558 3a.075.075 0 0 0-.079.037c-.34.6-.717 1.386-.98 2.005a18.36 18.36 0 0 0-5.487 0 12.62 12.62 0 0 0-.997-2.005A.077.077 0 0 0 8.937 3a19.74 19.74 0 0 0-3.76 1.369.07.07 0 0 0-.032.027C2.533 8.045 1.79 11.627 2.142 15.165a.083.083 0 0 0 .031.056 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.027c.462-.63.873-1.295 1.226-1.994a.076.076 0 0 0-.042-.106 13.1 13.1 0 0 1-1.872-.892.077.077 0 0 1-.008-.128c.126-.094.252-.192.372-.291a.074.074 0 0 1 .077-.01c3.927 1.793 8.18 1.793 12.061 0a.074.074 0 0 1 .078.009c.12.099.246.198.373.292a.077.077 0 0 1-.006.128 12.3 12.3 0 0 1-1.873.891.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.84 19.84 0 0 0 6.002-3.03.077.077 0 0 0 .031-.055c.5-4.087-.838-7.638-3.548-10.769a.061.061 0 0 0-.031-.028zM8.02 13.93c-1.182 0-2.157-1.085-2.157-2.419 0-1.333.956-2.418 2.157-2.418 1.21 0 2.176 1.095 2.157 2.418 0 1.334-.956 2.42-2.157 2.42zm7.974 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.418 2.157-2.418 1.21 0 2.176 1.095 2.157 2.418 0 1.334-.946 2.42-2.157 2.42z"/></svg>
        </a>
        <span class="footer-sep" aria-hidden="true">·</span>
        <button
          type="button"
          class="footer-toggle notif-toggle"
          id="notifToggle"
          aria-pressed="false"
          aria-label="Enable browser notifications"
          title="Enable browser notifications"
          hidden
        >
          <span class="notif-toggle-glyph" aria-hidden="true"></span>
          <span class="notif-toggle-label">Notifications</span>
        </button>
        <span class="footer-sep footer-sep-notif" aria-hidden="true" hidden>·</span>
        <button type="button" class="footer-toggle theme-toggle" id="themeToggle" aria-label="Toggle theme"></button>
      </p>
    </footer>
  `;

  const liveIndicator = app.querySelector("#liveIndicator")!;
  const liveHint = app.querySelector("#liveHint")!;
  const themeToggle = app.querySelector<HTMLButtonElement>("#themeToggle")!;
  const notifToggle = app.querySelector<HTMLButtonElement>("#notifToggle")!;
  const notifSep = app.querySelector<HTMLSpanElement>(".footer-sep-notif")!;

  function updateThemeToggleLabel() {
    const current = document.documentElement.getAttribute("data-theme") ?? "dark";
    themeToggle.textContent = current === "dark" ? "Light mode" : "Dark mode";
  }
  updateThemeToggleLabel();

  themeToggle.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") ?? "dark";
    const next = current === "dark" ? "light" : "dark";
    applyTheme(next);
    localStorage.setItem(LS_THEME, next);
    updateThemeToggleLabel();
  });

  function updateNotifToggleUi() {
    const state = getNotifPermission();
    if (state === "unsupported") {
      notifToggle.hidden = true;
      notifSep.hidden = true;
      return;
    }
    notifToggle.hidden = false;
    notifSep.hidden = false;
    notifToggle.classList.remove("is-granted", "is-denied", "is-default");
    const label = notifToggle.querySelector<HTMLElement>(".notif-toggle-label")!;
    if (state === "granted") {
      notifToggle.classList.add("is-granted");
      notifToggle.setAttribute("aria-pressed", "true");
      notifToggle.setAttribute("aria-label", "Browser notifications enabled");
      notifToggle.title =
        "Browser notifications are on. To mute, use your browser site settings.";
      label.textContent = "Alerts on";
    } else if (state === "denied") {
      notifToggle.classList.add("is-denied");
      notifToggle.setAttribute("aria-pressed", "false");
      notifToggle.setAttribute("aria-label", "Notifications blocked by browser");
      notifToggle.title =
        "Notifications are blocked. Enable them in your browser's site settings.";
      label.textContent = "Alerts off";
    } else {
      notifToggle.classList.add("is-default");
      notifToggle.setAttribute("aria-pressed", "false");
      notifToggle.setAttribute("aria-label", "Enable browser notifications");
      notifToggle.title = "Enable browser notifications for new messages.";
      label.textContent = "Enable alerts";
    }
  }
  updateNotifToggleUi();

  notifToggle.addEventListener("click", async () => {
    const state = getNotifPermission();
    if (state === "unsupported") return;
    if (state === "denied") {
      setStatus(
        liveHint as HTMLElement,
        "Notifications blocked. Enable them in browser site settings.",
        "err",
        4000,
      );
      return;
    }
    if (state === "granted") {
      setStatus(
        liveHint as HTMLElement,
        "Notifications are on.",
        "ok",
        1800,
      );
      return;
    }
    const next = await requestNotifPermission();
    updateNotifToggleUi();
    if (next === "granted") {
      setStatus(
        liveHint as HTMLElement,
        "Notifications enabled.",
        "ok",
        2200,
      );
      const reg = await readyRegistrationOrNull();
      if (reg) {
        try {
          await reg.showNotification("3233 · alerts enabled", {
            body: "You'll be notified when new messages arrive.",
            icon: "/icon-192.png",
            badge: "/favicon-32.png",
            tag: "3233-intro",
          });
        } catch {
          /* ignore */
        }
      }
    } else if (next === "denied") {
      setStatus(
        liveHint as HTMLElement,
        "Notifications blocked. You can enable them later in browser settings.",
        "err",
        4000,
      );
    }
  });

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") updateNotifToggleUi();
  });

  try {
    const permApi = (navigator as unknown as {
      permissions?: { query?: (d: { name: PermissionName }) => Promise<PermissionStatus> };
    }).permissions;
    if (permApi?.query) {
      void permApi
        .query({ name: "notifications" as PermissionName })
        .then((status) => {
          status.addEventListener("change", () => updateNotifToggleUi());
        })
        .catch(() => {
          /* not all browsers expose Permissions API for notifications */
        });
    }
  } catch {
    /* ignore */
  }

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.addEventListener("message", (ev) => {
      const d = ev.data as { type?: string; url?: string } | null;
      if (!d || d.type !== "3233:notif-click") return;
      const url = typeof d.url === "string" ? d.url : "/chats";
      try {
        const u = new URL(url, window.location.origin);
        const fp = u.searchParams.get("chat");
        if (fp) {
          void (async () => {
            await openChatWithFingerprint(fp);
            // Push (default) so the user can Back out to whatever view they
            // were on when the notification arrived.
            navigateToView("chats");
          })();
        } else {
          navigateToView("chats");
        }
      } catch {
        navigateToView("chats");
      }
    });
  }
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
  const headerCopyInvite = app.querySelector<HTMLButtonElement>("#headerCopyInvite")!;
  const headerCopyAddress = app.querySelector<HTMLButtonElement>("#headerCopyAddress")!;
  const headerNewKeys = app.querySelector<HTMLButtonElement>("#headerNewKeys")!;
  const inviteLinkInput = app.querySelector<HTMLInputElement>("#inviteLinkInput")!;
  const publicKeyShareInput = app.querySelector<HTMLInputElement>("#publicKeyShareInput")!;
  const copyInviteLinkBtn = app.querySelector<HTMLButtonElement>("#copyInviteLinkBtn")!;
  const copyPublicKeyBtn = app.querySelector<HTMLButtonElement>("#copyPublicKeyBtn")!;
  const shareInviteNative = app.querySelector<HTMLButtonElement>("#shareInviteNative")!;
  const shareInviteSms = app.querySelector<HTMLAnchorElement>("#shareInviteSms")!;
  const shareInviteWhatsapp = app.querySelector<HTMLAnchorElement>("#shareInviteWhatsapp")!;
  const shareInviteEmail = app.querySelector<HTMLAnchorElement>("#shareInviteEmail")!;
  const openChatFpEl = app.querySelector<HTMLInputElement>("#openChatFp")!;
  const openChatBtn = app.querySelector<HTMLButtonElement>("#openChatBtn")!;
  const chatThreadCopy = app.querySelector<HTMLButtonElement>("#chatThreadCopy")!;
  const chatTabsEl = app.querySelector("#chatTabs")!;
  const mobileChatTabsEl = app.querySelector("#mobileChatTabs")!;
  const chatThread = app.querySelector<HTMLElement>("#chatThread")!;
  const chatThreadHead = app.querySelector<HTMLElement>("#chatThreadHead")!;
  const chatMessages = app.querySelector("#chatMessages")!;
  const chatBodyEl = app.querySelector<HTMLTextAreaElement>("#chatBody")!;
  const chatSend = app.querySelector<HTMLButtonElement>("#chatSend")!;
  const chatSendStatus = app.querySelector("#chatSendStatus")!;
  const chatEmptyHint = app.querySelector<HTMLElement>("#chatEmptyHint")!;
  const openChatStatus = app.querySelector<HTMLElement>("#openChatStatus")!;
  const chatEmptyGoNew = app.querySelector<HTMLButtonElement>("#chatEmptyGoNew")!;
  const libraryList = app.querySelector("#libraryList")!;
  const librarySearch = app.querySelector<HTMLInputElement>("#librarySearch")!;
  const libraryPager = app.querySelector<HTMLElement>("#libraryPager")!;
  const libraryPageInfo = app.querySelector("#libraryPageInfo")!;
  const libraryPrev = app.querySelector<HTMLButtonElement>("#libraryPrev")!;
  const libraryNext = app.querySelector<HTMLButtonElement>("#libraryNext")!;
  const viewPanels = app.querySelectorAll<HTMLElement>(".view-panel");
  const dashTabs = app.querySelectorAll<HTMLButtonElement>(".dash-tab[data-view]");
  let incomingAudioCtx: AudioContext | null = null;
  let incomingAudioUnlocked = false;

  /** Must run from a user gesture: browsers start AudioContext suspended if created later (e.g. after fetch). */
  function unlockIncomingAudio() {
    try {
      const Ctx =
        window.AudioContext ||
        (window as typeof window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
      if (!Ctx) {
        incomingAudioUnlocked = true;
        return;
      }
      incomingAudioCtx ??= new Ctx();
      const ctx = incomingAudioCtx;
      if (ctx.state === "suspended") {
        void ctx.resume();
      }
      // Inaudible blip during gesture — keeps some WebKit builds from blocking later oscillators.
      const t0 = ctx.currentTime;
      const silent = ctx.createOscillator();
      const g0 = ctx.createGain();
      g0.gain.setValueAtTime(0, t0);
      silent.connect(g0);
      g0.connect(ctx.destination);
      silent.start(t0);
      silent.stop(t0 + 0.001);
      incomingAudioUnlocked = true;
    } catch {
      incomingAudioUnlocked = true;
    }
  }

  function installIncomingAudioUnlock() {
    const onGesture = () => unlockIncomingAudio();
    window.addEventListener("pointerdown", onGesture, { passive: true });
    window.addEventListener("keydown", onGesture);
    window.addEventListener("touchstart", onGesture, { passive: true });
  }

  function playIncomingMessageSound() {
    if (!incomingAudioUnlocked) return;
    try {
      const ctx = incomingAudioCtx;
      if (!ctx) return;
      if (ctx.state === "suspended") {
        void ctx.resume();
      }
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(920, now);
      osc.frequency.exponentialRampToValueAtTime(1240, now + 0.1);
      gain.gain.setValueAtTime(0.0001, now);
      gain.gain.exponentialRampToValueAtTime(0.14, now + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.14);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.16);
    } catch {
      /* ignore */
    }
  }

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
    if (view === "chats") {
      renderChatTabs();
      renderActiveThread();
    }
  }

  function syncViewFromUrl() {
    const path = normalizePathname(window.location.pathname);
    let v: ViewId;
    if (path === "/") {
      history.replaceState(
        { view: "newchat" },
        "",
        "/newchat" + window.location.search + window.location.hash,
      );
      v = "newchat";
      showView(v);
      applyRouteSeo(v);
    } else {
      const parsed = pathnameToView(path);
      if (!parsed) {
        history.replaceState({ view: "newchat" }, "", "/newchat");
        v = "newchat";
        showView(v);
        applyRouteSeo(v);
      } else {
        v = parsed;
        showView(v);
        applyRouteSeo(v);
      }
    }
    if (v === "chats") {
      window.setTimeout(() => {
        renderChatTabs();
        renderActiveThread();
      }, 0);
    }
  }

  function initRoute() {
    syncViewFromUrl();
    applyInviteSeo();
  }

  for (const btn of dashTabs) {
    btn.addEventListener("click", () => {
      const v = btn.getAttribute("data-view");
      if (v && VIEW_IDS.includes(v as ViewId)) navigateToView(v as ViewId);
    });
  }

  window.addEventListener("popstate", () => syncViewFromUrl());

  initRoute();
  installIncomingAudioUnlock();

  const brandLink = app.querySelector<HTMLAnchorElement>("a.brand-name");
  if (brandLink) {
    brandLink.addEventListener("click", (ev) => {
      if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
      ev.preventDefault();
      navigateToView("newchat");
    });
  }

  serverUrlEl.value = getServerUrl();
  fpShortEl.textContent = shortFingerprint(fingerprint);
  fpFullEl.textContent = fingerprint;
  const pubB64 = b64encode(pair.publicKey);
  pubKeyB64.value = pubB64;
  publicKeyShareInput.value = pubB64;
  privKeyB64.textContent = b64encode(pair.secretKey);

  let openChatIds: string[] = loadOpenChats();
  let activeChatFp: string | null =
    openChatIds.length > 0 ? openChatIds[0]! : null;
  let lastReadByFp: Record<string, number> = loadLastReadMap();

  function ensureLastReadBaselines() {
    const maxBy = new Map<string, number>();
    for (const e of libraryEntries) {
      if (!e.senderFp) continue;
      const fp = e.senderFp;
      maxBy.set(fp, Math.max(maxBy.get(fp) ?? 0, e.id));
    }
    let changed = false;
    for (const [fp, maxId] of maxBy) {
      if (lastReadByFp[fp] === undefined) {
        lastReadByFp[fp] = maxId;
        changed = true;
      }
    }
    if (changed) saveLastReadMap(lastReadByFp);
  }

  function markThreadRead(fp: string) {
    let maxId = 0;
    for (const e of libraryEntries) {
      if (e.senderFp === fp) maxId = Math.max(maxId, e.id);
    }
    if (lastReadByFp[fp] === maxId) return;
    lastReadByFp[fp] = maxId;
    saveLastReadMap(lastReadByFp);
  }

  function threadHasUnread(fp: string): boolean {
    const lr = lastReadByFp[fp] ?? 0;
    for (const e of libraryEntries) {
      if (e.senderFp === fp && e.id > lr) return true;
    }
    return false;
  }

  async function openChatWithFingerprint(raw: string): Promise<boolean> {
    const fp = await resolveRecipientFingerprint(raw);
    if (!fp) return false;
    // Prevent chatting with yourself — messages would appear twice in the
    // thread (once as outgoing from the sent map, once as incoming after the
    // server round-trip), which is confusing UX. Point users at the Library
    // view if they just want to jot notes for themselves.
    if (fp === fingerprint.toLowerCase()) return false;
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

  function buildInviteShareText(): {
    title: string;
    smsBody: string;
    longBody: string;
    url: string;
  } {
    const url = buildInviteLink();
    const title = "Chat with me privately on 3233.io";
    const smsBody = `Let's chat privately on 3233.io: ${url}`;
    const longBody =
      `You can reach me on 3233.io — an end-to-end encrypted chat relay. ` +
      `No account needed. My address: ${shortFingerprint(fingerprint)}\n\n` +
      `Open our thread: ${url}`;
    return { title, smsBody, longBody, url };
  }

  function refreshInviteShareTargets() {
    const { title, smsBody, longBody } = buildInviteShareText();
    shareInviteSms.href = `sms:?body=${encodeURIComponent(smsBody)}`;
    shareInviteWhatsapp.href = `https://wa.me/?text=${encodeURIComponent(smsBody)}`;
    shareInviteEmail.href =
      `mailto:?subject=${encodeURIComponent(title)}` +
      `&body=${encodeURIComponent(longBody)}`;
    const native = typeof navigator !== "undefined" && typeof navigator.share === "function";
    shareInviteNative.hidden = !native;
  }

  function updateInviteLinkDisplay() {
    const url = buildInviteLink();
    inviteLinkInput.value = url;
    refreshInviteShareTargets();
  }

  function flashButtonLabel(btn: HTMLButtonElement, doneLabel: string, ms = 1000) {
    const prev = btn.textContent ?? "";
    btn.textContent = doneLabel;
    window.setTimeout(() => {
      btn.textContent = prev;
    }, ms);
  }

  /** Show an ephemeral status line that fades itself after a few seconds.
   *  Successful toasts auto-clear; errors persist until the next action. */
  const statusFadeTimers = new WeakMap<HTMLElement, number>();
  function setStatus(
    el: HTMLElement,
    text: string,
    kind: "ok" | "err" | "" = "",
    autoHideMs = kind === "ok" ? 2200 : 0,
  ) {
    const prev = statusFadeTimers.get(el);
    if (prev) window.clearTimeout(prev);
    el.textContent = text;
    el.className = kind ? `status ${kind}` : "status";
    el.classList.toggle("is-fading", false);
    if (autoHideMs > 0 && text) {
      const id = window.setTimeout(() => {
        el.classList.add("is-fading");
        const id2 = window.setTimeout(() => {
          el.textContent = "";
          el.className = "status";
          el.classList.remove("is-fading");
        }, 260);
        statusFadeTimers.set(el, id2);
      }, autoHideMs);
      statusFadeTimers.set(el, id);
    }
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
        navigateToView("newchat", { replace: true });
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
      const ok = await openChatWithFingerprint(chatRaw);
      if (!ok) {
        openChatStatus.textContent =
          "Invalid contact in invite link (need 64 hex fingerprint or base64 public key).";
        openChatStatus.className = "status err";
        navigateToView("newchat", { replace: true });
      } else {
        navigateToView("chats", { replace: true });
      }
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

  function buildChatTabNodes(): DocumentFragment {
    const frag = document.createDocumentFragment();
    for (const fp of openChatIds) {
      const wrap = document.createElement("div");
      wrap.className = "chat-tab" + (fp === activeChatFp ? " active" : "");
      const label = document.createElement("button");
      label.type = "button";
      label.className = "chat-tab-label";
      const unread = threadHasUnread(fp);
      if (unread) {
        const dot = document.createElement("span");
        dot.className = "chat-tab-unread-dot";
        dot.title = "Unread messages";
        label.appendChild(dot);
      }
      label.appendChild(document.createTextNode(shortFingerprint(fp)));
      label.title = fp;
      label.setAttribute(
        "aria-label",
        unread ? `${shortFingerprint(fp)}, unread messages` : shortFingerprint(fp),
      );
      label.addEventListener("click", () => {
        activeChatFp = fp;
        renderChatTabs();
        renderActiveThread();
        navigateToView("chats");
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
      frag.appendChild(wrap);
    }
    return frag;
  }

  function renderChatTabs() {
    ensureLastReadBaselines();
    chatTabsEl.innerHTML = "";
    mobileChatTabsEl.innerHTML = "";
    chatTabsEl.appendChild(buildChatTabNodes());
    mobileChatTabsEl.appendChild(buildChatTabNodes());
  }

  function renderActiveThread() {
    if (!activeChatFp) {
      chatThread.hidden = true;
      chatEmptyHint.hidden = false;
      return;
    }
    const chatsPanel = app.querySelector("#view-chats") as HTMLElement | null;
    if (chatsPanel && !chatsPanel.hidden) {
      markThreadRead(activeChatFp);
    }
    chatEmptyHint.hidden = true;
    chatThread.hidden = false;
    chatThreadHead.textContent = shortFingerprint(activeChatFp);
    chatThreadHead.title = activeChatFp;
    const incoming = libraryEntries.filter((e) => e.senderFp === activeChatFp);
    const sent = loadSentMap()[activeChatFp] ?? [];
    const lines: { kind: "in" | "out"; ts: number; text: string }[] = [];
    for (const e of incoming) {
      lines.push({ kind: "in", ts: e.serverTs, text: e.text });
    }
    for (const s of sent) {
      lines.push({ kind: "out", ts: s.ts, text: s.text });
    }
    lines.sort((a, b) => a.ts - b.ts);
    chatMessages.innerHTML = "";
    if (lines.length === 0) {
      const empty = document.createElement("p");
      empty.className = "chat-thread-empty";
      empty.textContent = "No messages yet — say hi.";
      chatMessages.appendChild(empty);
    }
    // Render with clustering: show timestamp only at the end of a run of
    // same-side messages OR when >5min gap. Group bubbles get tighter spacing.
    const GROUP_GAP_MS = 5 * 60_000;
    for (let i = 0; i < lines.length; i += 1) {
      const L = lines[i]!;
      const next = lines[i + 1];
      const sameSideNext = next && next.kind === L.kind;
      const closeInTimeNext = next && Math.abs(next.ts - L.ts) < GROUP_GAP_MS;
      const isGroupTail = !sameSideNext || !closeInTimeNext;
      const prev = lines[i - 1];
      const sameSidePrev = prev && prev.kind === L.kind;
      const closeInTimePrev = prev && Math.abs(L.ts - prev.ts) < GROUP_GAP_MS;
      const isGroupHead = !sameSidePrev || !closeInTimePrev;
      const row = document.createElement("div");
      const classes = ["chat-line", L.kind === "out" ? "chat-line-out" : "chat-line-in"];
      if (!isGroupHead) classes.push("chat-line-cont");
      if (!isGroupTail) classes.push("chat-line-mid");
      row.className = classes.join(" ");
      const d = new Date(L.ts);
      const tsShort = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
      const tsFull = d.toLocaleString();
      const tsHtml = isGroupTail
        ? `<div class="chat-ts" title="${escapeHtml(tsFull)}">${escapeHtml(tsShort)}</div>`
        : "";
      row.innerHTML = `<div class="chat-bubble">${escapeHtml(L.text)}</div>${tsHtml}`;
      chatMessages.appendChild(row);
    }
    chatMessages.scrollTop = chatMessages.scrollHeight;
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

  onNewPolledEntries = (entries) => {
    if (entries.length === 0) return;
    playIncomingMessageSound();

    const chatsPanel = app.querySelector<HTMLElement>("#view-chats");
    const chatsVisible =
      document.visibilityState === "visible" &&
      chatsPanel !== null &&
      !chatsPanel.hidden;
    const notifWorthy = entries.filter((e) => {
      if (!e.senderFp) return false;
      const active = chatsVisible && activeChatFp === e.senderFp;
      return !active;
    });

    if (notifWorthy.length >= NOTIF_BATCH_COALESCE_MIN) {
      void showBatchNotification(notifWorthy);
    } else {
      for (const e of notifWorthy) {
        void showLocalNotification({
          title: `New message · 3233:${e.senderFp!.slice(0, 8)}`,
          body: buildNotifBody(e.text),
          senderFp: e.senderFp!,
          msgId: e.id,
        });
      }
    }

    // Update open chats + focus for the most recent sender.
    let changed = false;
    let latestFp: string | null = null;
    for (const entry of entries) {
      const fp = entry.senderFp;
      if (!fp) continue;
      latestFp = fp;
      if (!openChatIds.includes(fp)) {
        openChatIds.push(fp);
        changed = true;
      }
    }
    if (changed) saveOpenChats(openChatIds);
    if (latestFp && activeChatFp !== latestFp) {
      activeChatFp = latestFp;
      navigateToView("chats");
    }
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
    lastReadByFp = {};
    saveLastReadMap(lastReadByFp);
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
      const senderShort = e.senderFp ? shortFingerprint(e.senderFp) : "unknown";
      const when = formatLibraryDate(e.serverTs);
      div.innerHTML =
        `<div class="meta">` +
        `<span class="msg-sender mono" title="${escapeHtml(e.senderFp ?? "")}">${escapeHtml(senderShort)}</span>` +
        `<span class="msg-when">${escapeHtml(when)}</span>` +
        `</div>` +
        `<div class="body">${escapeHtml(e.text)}</div>`;
      libraryList.appendChild(div);
    }

    if (filtered.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state empty-state--inline";
      const isSearch = !!librarySearchQuery.trim();
      empty.innerHTML = isSearch
        ? `<div class="empty-state-glyph" aria-hidden="true">⌕</div>` +
          `<h2 class="empty-state-title">No matches</h2>` +
          `<p class="empty-state-body">Try a different word, sender prefix, or month.</p>`
        : `<div class="empty-state-glyph" aria-hidden="true">∅</div>` +
          `<h2 class="empty-state-title">Inbox is empty</h2>` +
          `<p class="empty-state-body">Decrypted messages from this server will appear here. Share your invite link to start receiving.</p>`;
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
    setStatus(serverStatus as HTMLElement, "Connecting…", "", 0);
    await runSessionSetup({ resetLibrary: true });
    setStatus(serverStatus as HTMLElement, `Saved · ${getServerUrl()}`, "ok");
    updateInviteLinkDisplay();
  });

  registerBtn.addEventListener("click", async () => {
    localStorage.removeItem(LS_TOKEN);
    await runSessionSetup({ resetLibrary: true });
    updateInviteLinkDisplay();
  });

  function runNewKeysReset() {
    if (!confirm("Generate new keys? This cannot be undone.")) return;
    localStorage.removeItem(LS_SK);
    localStorage.removeItem(LS_PK);
    localStorage.removeItem(LS_TOKEN);
    localStorage.removeItem(LS_OPEN_CHATS);
    localStorage.removeItem(LS_SENT);
    localStorage.removeItem(LS_LAST_READ);
    location.reload();
  }

  newKeys.addEventListener("click", runNewKeysReset);
  headerNewKeys.addEventListener("click", runNewKeysReset);

  headerCopyInvite.addEventListener("click", async () => {
    updateInviteLinkDisplay();
    const ok = await copyTextToClipboard(buildInviteLink());
    if (ok) flashButtonLabel(headerCopyInvite, "Copied");
    else
      alert(
        "Could not copy automatically — open Home and copy the invite link field, or try again over HTTPS.",
      );
  });

  headerCopyAddress.addEventListener("click", async () => {
    const ok = await copyTextToClipboard(fingerprint);
    if (ok) flashButtonLabel(headerCopyAddress, "Copied");
    else alert("Could not copy automatically — try again over HTTPS or copy from the keys tab.");
  });

  copyInviteLinkBtn.addEventListener("click", async () => {
    updateInviteLinkDisplay();
    const ok = await copyTextToClipboard(buildInviteLink());
    if (ok) flashButtonLabel(copyInviteLinkBtn, "Copied");
    else alert("Could not copy — select the text and copy manually, or try again over HTTPS.");
  });

  copyPublicKeyBtn.addEventListener("click", async () => {
    const ok = await copyTextToClipboard(b64encode(pair.publicKey));
    if (ok) flashButtonLabel(copyPublicKeyBtn, "Copied");
    else alert("Could not copy — select the text and copy manually, or try again over HTTPS.");
  });

  shareInviteNative.addEventListener("click", async () => {
    refreshInviteShareTargets();
    const { title, longBody, url } = buildInviteShareText();
    if (typeof navigator.share !== "function") return;
    try {
      await navigator.share({ title, text: longBody, url });
      flashButtonLabel(shareInviteNative, "Shared");
    } catch (err) {
      if ((err as DOMException)?.name === "AbortError") return;
      const ok = await copyTextToClipboard(url);
      flashButtonLabel(
        shareInviteNative,
        ok ? "Link copied" : "Share failed",
      );
    }
  });

  for (const link of [shareInviteSms, shareInviteWhatsapp, shareInviteEmail]) {
    link.addEventListener("click", () => refreshInviteShareTargets());
  }

  chatThreadCopy.addEventListener("click", async () => {
    if (!activeChatFp) return;
    const ok = await copyTextToClipboard(activeChatFp);
    if (ok) flashButtonLabel(chatThreadCopy, "Copied");
    else alert("Could not copy — select the fingerprint and copy manually.");
  });

  // Tap or focus the read-only share fields to select all — fast copy on mobile.
  for (const el of [inviteLinkInput, publicKeyShareInput]) {
    const selectAll = () => {
      try {
        el.setSelectionRange(0, el.value.length);
      } catch {
        /* ignore */
      }
    };
    el.addEventListener("focus", selectAll);
    el.addEventListener("click", selectAll);
  }

  async function openChatFromInput() {
    openChatStatus.textContent = "";
    openChatStatus.className = "status";
    const resolved = await resolveRecipientFingerprint(openChatFpEl.value);
    if (resolved && resolved === fingerprint.toLowerCase()) {
      openChatStatus.textContent =
        "That's your own fingerprint. You can't chat with yourself — send to someone else or use the Library view for personal notes.";
      openChatStatus.className = "status err";
      return;
    }
    const ok = await openChatWithFingerprint(openChatFpEl.value);
    if (!ok) {
      openChatStatus.textContent =
        "Enter a valid fingerprint (64 hex), short fingerprint (3233:…), or NaCl box public key (base64). Short fingerprints must match exactly one user.";
      openChatStatus.className = "status err";
      return;
    }
    openChatFpEl.value = "";
    navigateToView("chats");
  }

  openChatBtn.addEventListener("click", () => void openChatFromInput());
  chatEmptyGoNew.addEventListener("click", () => {
    navigateToView("newchat");
    window.setTimeout(() => openChatFpEl.focus(), 50);
  });
  openChatFpEl.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      void openChatFromInput();
    }
  });

  updateInviteLinkDisplay();

  async function doSendMessage() {
    const rf = activeChatFp;
    if (!rf) {
      setStatus(chatSendStatus as HTMLElement, "Open a chat tab first.", "err");
      return;
    }
    const text = chatBodyEl.value.trim();
    if (!text) {
      setStatus(chatSendStatus as HTMLElement, "Enter a message.", "err");
      return;
    }
    chatSend.disabled = true;
    setStatus(chatSendStatus as HTMLElement, "Sending…", "", 0);
    let res: Awaited<ReturnType<typeof sendMessage>>;
    try {
      res = await sendMessage(pair, rf, text);
    } catch (e) {
      res = { ok: false, err: (e as Error).message || "Send failed" };
    } finally {
      chatSend.disabled = false;
    }
    if (res.ok) {
      setStatus(chatSendStatus as HTMLElement, "Sent", "ok");
      // Prefer server timestamp so ordering is consistent with the receiver's
      // view (otherwise client-clock skew causes the two threads to disagree).
      appendSent(rf, text, res.serverTs, res.id);
      chatBodyEl.value = "";
      renderActiveThread();
      chatBodyEl.focus();
    } else {
      setStatus(chatSendStatus as HTMLElement, res.err ?? "Send failed", "err");
    }
  }

  chatSend.addEventListener("click", () => void doSendMessage());
  chatBodyEl.addEventListener("keydown", (ev) => {
    // Enter sends (chat convention); Shift/Ctrl/Cmd/Alt+Enter inserts a newline.
    // Also guard against IME composition — don't send while the user is mid-
    // compose (macOS/Safari fire keydown for Enter during composition).
    const isEnter = ev.key === "Enter";
    if (!isEnter) return;
    const isComposing =
      ev.isComposing || (ev as unknown as { keyCode?: number }).keyCode === 229;
    if (isComposing) return;
    if (ev.shiftKey || ev.altKey || ev.ctrlKey || ev.metaKey) return;
    ev.preventDefault();
    void doSendMessage();
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

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {
      /* SW registration failed — app works fine without it */
    });
  });
}
