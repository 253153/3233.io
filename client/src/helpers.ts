/**
 * Pure, side-effect-free helpers used by the app. Extracted so the unit test
 * suite can import them without booting main.ts.
 */

export const LS_NOTIF_CURSOR = "io3233_notif_cursor_v1";
export const NOTIF_BODY_MAX = 140;

/** Normalize a user-entered fingerprint (whitespace, case, length). */
export function normalizeFingerprint(raw: string): string | null {
  const s = raw.replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(s)) return null;
  return s;
}

/** Normalize a URL pathname — remove trailing slash, keep leading `/`. */
export function normalizePathname(pathname: string): string {
  const p = pathname.replace(/\/$/, "");
  return p === "" ? "/" : p;
}

/** Map a pathname (e.g. "/chats") to a known ViewId or null. */
export function pathnameToView(
  pathname: string,
  validViews: readonly string[],
): string | null {
  const p = normalizePathname(pathname);
  if (p === "/") return null;
  const seg = p.slice(1);
  if (seg.includes("/")) return null;
  return validViews.includes(seg) ? seg : null;
}

export function viewToPath(view: string): string {
  return "/" + view;
}

/** Collapse whitespace + truncate for notification bodies. */
export function buildNotifBody(text: string, max = NOTIF_BODY_MAX): string {
  const clean = text.replace(/\s+/g, " ").trim();
  if (!clean) return "";
  if (clean.length <= max) return clean;
  return `${clean.slice(0, max - 1)}…`;
}

/**
 * Cross-tab claim for a given message id. Returns true iff this caller "won"
 * the claim (i.e. msgId was strictly greater than the last observed cursor).
 *
 * This is the synchronous, localStorage-only path. Tabs that need true cross-
 * tab atomicity should wrap this in `navigator.locks.request()` — see
 * `claimNotifSlot` in main.ts.
 *
 * `storage` is injectable for testing.
 */
export function localCasClaim(
  msgId: number,
  storage: Pick<Storage, "getItem" | "setItem"> = localStorage,
): boolean {
  try {
    const cur = Number(storage.getItem(LS_NOTIF_CURSOR) ?? "0") || 0;
    if (msgId <= cur) return false;
    storage.setItem(LS_NOTIF_CURSOR, String(msgId));
    return true;
  } catch {
    return true;
  }
}

/** HTML-escape a string by letting the DOM do it. Requires a `document`. */
export function escapeHtml(s: string): string {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

/**
 * Shortest form of a fingerprint for labels/titles. Canonical UI form is the
 * `3233:` prefix plus the first 32 hex chars of the full fingerprint — matches
 * `shortFingerprint` in `crypto.ts` and is documented in `docs/PROTOCOL.md`.
 */
export function shortFp(fullHex: string): string {
  return `3233:${fullHex.slice(0, 32)}`;
}
