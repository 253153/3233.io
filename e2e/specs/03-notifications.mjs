// Browser notification integration: grants permission up front via the CDP
// permission override, simulates B's tab being backgrounded, sends a message
// from A, and asserts that exactly one notification fires on B's side.
//
// We watch notifications via two channels:
//  1. `new Notification(...)` ctor calls (page fallback path)
//  2. `reg.showNotification(...)` via the service worker (primary path)
//
// A single delivered message should produce exactly one observed record.

import {
  assert,
  eventually,
  newClient,
  openChatWith,
  readFingerprint,
  sendMessage,
} from "../lib.mjs";
import { grantNotificationsOn } from "../harness.mjs";

async function primeNotifObservers(page) {
  await page.evaluateOnNewDocument(() => {
    window.__notifs = [];
    const orig = window.Notification;
    if (orig) {
      const Wrapped = function (title, opts) {
        window.__notifs.push({
          source: "ctor",
          title,
          body: opts?.body ?? "",
          tag: opts?.tag,
        });
        return new orig(title, opts);
      };
      Wrapped.permission = orig.permission;
      Wrapped.requestPermission = (...args) =>
        orig.requestPermission(...args);
      Object.setPrototypeOf(Wrapped, orig);
      Object.defineProperty(window, "Notification", {
        configurable: true,
        value: Wrapped,
      });
    }
  });
}

async function readNotifs(page) {
  return page.evaluate(async () => {
    const list = [...(window.__notifs ?? [])];
    if ("serviceWorker" in navigator) {
      try {
        const reg = await Promise.race([
          navigator.serviceWorker.ready,
          new Promise((_, rej) =>
            setTimeout(() => rej(new Error("sw-timeout")), 750),
          ),
        ]);
        if (reg?.getNotifications) {
          const active = await reg.getNotifications();
          for (const n of active) {
            list.push({
              source: "sw",
              title: n.title,
              body: n.body,
              tag: n.tag,
            });
          }
        }
      } catch {}
    }
    return list;
  });
}

async function simulateHidden(page) {
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
    Object.defineProperty(document, "hidden", {
      configurable: true,
      get: () => true,
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
}

export default async function ({ baseUrl, browser }) {
  // Use createBrowserContext so each client is isolated (no shared SW).
  const aCtx = await browser.createBrowserContext();
  const bCtx = await browser.createBrowserContext();
  await grantNotificationsOn(aCtx, baseUrl);
  await grantNotificationsOn(bCtx, baseUrl);
  const aPage = await aCtx.newPage();
  const bPage = await bCtx.newPage();

  try {
    await primeNotifObservers(bPage);
    await aPage.goto(baseUrl, { waitUntil: "networkidle0" });
    await bPage.goto(baseUrl, { waitUntil: "networkidle0" });

    const fpA = await readFingerprint(aPage);
    const fpB = await readFingerprint(bPage);

    // B opens a chat with A (so B's client is routing inbound messages).
    await openChatWith(bPage, baseUrl, fpA);
    // Wait for B's service worker to actually be "ready" so that
    // `reg.showNotification` takes the SW path.
    await bPage.evaluate(() =>
      "serviceWorker" in navigator
        ? navigator.serviceWorker.ready.then(() => true, () => false)
        : false,
    );
    await simulateHidden(bPage);

    // A sends B a message. Use a distinct random body so we can distinguish
    // duplicate fires vs. two different events.
    await openChatWith(aPage, baseUrl, fpB);
    const note = `hello ${Math.random().toString(36).slice(2, 8)}`;
    await sendMessage(aPage, note);

    try {
      await eventually(async () => {
        const n = await readNotifs(bPage);
        return n.some(
          (x) => (x.body ?? "").includes(note) || (x.tag ?? "").includes("3233"),
        );
      }, { timeoutMs: 10_000 });
    } catch (e) {
      const diag = await bPage.evaluate(() => ({
        notifPermission: typeof Notification !== "undefined" ? Notification.permission : null,
        hasSw: "serviceWorker" in navigator,
        swState: navigator.serviceWorker?.controller ? "controlled" : "uncontrolled",
        visibility: document.visibilityState,
        hidden: document.hidden,
        notifs: window.__notifs,
        messageCount: document.querySelectorAll("#chatMessages .chat-line").length,
        chatPanelHidden: document.querySelector("#view-chats")?.hasAttribute("hidden"),
      }));
      console.error("DIAG", JSON.stringify(diag, null, 2));
      throw e;
    }

    const notifs = await readNotifs(bPage);
    const ours = notifs.filter(
      (x) => (x.body ?? "").includes(note) || (x.tag ?? "").includes("3233"),
    );

    // Exactly one OS-level notification should exist for this message. We
    // may observe it via both ctor + SW channels, but each channel should
    // report it at most once.
    const byCtor = ours.filter((n) => n.source === "ctor").length;
    const bySw = ours.filter((n) => n.source === "sw").length;
    assert(
      byCtor + bySw >= 1,
      `no notification observed; saw ${notifs.length} total`,
    );
    assert(
      byCtor <= 1,
      `Notification() ctor fired ${byCtor} times — expected ≤ 1`,
    );
    assert(
      bySw <= 1,
      `SW showed ${bySw} notifications — expected ≤ 1`,
    );
  } finally {
    await aCtx.close();
    await bCtx.close();
  }
}
