import { describe, it, expect, beforeEach } from "vitest";
import {
  LS_NOTIF_CURSOR,
  NOTIF_BODY_MAX,
  buildNotifBody,
  escapeHtml,
  localCasClaim,
  normalizeFingerprint,
  normalizePathname,
  pathnameToView,
  shortFp,
  viewToPath,
} from "./helpers";

describe("normalizeFingerprint", () => {
  it("accepts a plain 64-char hex string", () => {
    const fp = "a".repeat(64);
    expect(normalizeFingerprint(fp)).toBe(fp);
  });

  it("lowercases and strips whitespace", () => {
    const hex = "a".repeat(64);
    expect(normalizeFingerprint(` ${hex.toUpperCase()}\n`)).toBe(hex);
    expect(normalizeFingerprint("A B".repeat(32))).toBe("ab".repeat(32));
  });

  it("rejects non-hex characters", () => {
    expect(normalizeFingerprint("z".repeat(64))).toBeNull();
  });

  it("rejects wrong length", () => {
    expect(normalizeFingerprint("a".repeat(63))).toBeNull();
    expect(normalizeFingerprint("a".repeat(65))).toBeNull();
    expect(normalizeFingerprint("")).toBeNull();
  });
});

describe("normalizePathname / pathnameToView / viewToPath", () => {
  const views = ["chats", "newchat", "server"] as const;

  it("normalises trailing slash", () => {
    expect(normalizePathname("/chats/")).toBe("/chats");
    expect(normalizePathname("/")).toBe("/");
    expect(normalizePathname("")).toBe("/");
  });

  it("maps known segments to views", () => {
    expect(pathnameToView("/chats", views)).toBe("chats");
    expect(pathnameToView("/chats/", views)).toBe("chats");
    expect(pathnameToView("/newchat", views)).toBe("newchat");
  });

  it("returns null for root, unknown, or nested paths", () => {
    expect(pathnameToView("/", views)).toBeNull();
    expect(pathnameToView("/unknown", views)).toBeNull();
    expect(pathnameToView("/chats/deeper", views)).toBeNull();
  });

  it("round-trips through viewToPath", () => {
    for (const v of views) {
      expect(pathnameToView(viewToPath(v), views)).toBe(v);
    }
  });
});

describe("buildNotifBody", () => {
  it("collapses whitespace", () => {
    expect(buildNotifBody("hi   there\n\n friend")).toBe("hi there friend");
  });

  it("returns empty string for whitespace-only input", () => {
    expect(buildNotifBody("")).toBe("");
    expect(buildNotifBody("   \n\t   ")).toBe("");
  });

  it("truncates long input with ellipsis", () => {
    const long = "x".repeat(NOTIF_BODY_MAX + 50);
    const out = buildNotifBody(long);
    expect(out.length).toBe(NOTIF_BODY_MAX);
    expect(out.endsWith("…")).toBe(true);
  });

  it("respects a custom max", () => {
    expect(buildNotifBody("abcdef", 4)).toBe("abc…");
  });

  it("leaves content equal-to-max untouched", () => {
    const exact = "y".repeat(NOTIF_BODY_MAX);
    expect(buildNotifBody(exact)).toBe(exact);
  });
});

describe("localCasClaim", () => {
  beforeEach(() => {
    localStorage.removeItem(LS_NOTIF_CURSOR);
  });

  it("claims when msgId exceeds cursor", () => {
    expect(localCasClaim(1)).toBe(true);
    expect(localStorage.getItem(LS_NOTIF_CURSOR)).toBe("1");
  });

  it("refuses equal or lower ids", () => {
    localCasClaim(5);
    expect(localCasClaim(5)).toBe(false);
    expect(localCasClaim(3)).toBe(false);
  });

  it("advances the cursor monotonically", () => {
    localCasClaim(1);
    localCasClaim(10);
    localCasClaim(5);
    expect(localStorage.getItem(LS_NOTIF_CURSOR)).toBe("10");
  });

  it("uses injected storage for tests", () => {
    const mem = new Map<string, string>();
    const storage = {
      getItem: (k: string) => mem.get(k) ?? null,
      setItem: (k: string, v: string) => void mem.set(k, v),
    };
    expect(localCasClaim(42, storage)).toBe(true);
    expect(mem.get(LS_NOTIF_CURSOR)).toBe("42");
  });

  it("falls through permissively when storage throws (private mode)", () => {
    const broken = {
      getItem() {
        throw new Error("denied");
      },
      setItem() {
        throw new Error("denied");
      },
    };
    expect(localCasClaim(1, broken)).toBe(true);
  });
});

describe("escapeHtml", () => {
  it("escapes angle brackets and ampersands", () => {
    expect(escapeHtml("<script>alert('x')</script>")).toBe(
      "&lt;script&gt;alert('x')&lt;/script&gt;",
    );
  });

  it("passes through plain text", () => {
    expect(escapeHtml("hi there")).toBe("hi there");
  });

  it("escapes already-escaped ampersands", () => {
    expect(escapeHtml("a & b")).toBe("a &amp; b");
  });
});

describe("shortFp", () => {
  it("formats with prefix and first 32 hex chars", () => {
    const fp = "abcdef0123456789".repeat(4); // 64 hex chars
    expect(shortFp(fp)).toBe("3233:abcdef0123456789abcdef0123456789");
  });
});
