// Loads the SPA, walks each top-level view, and asserts that the app boots
// without console errors and every route renders the intended heading.

import { assert, eventually, newClient, goto, sleep } from "../lib.mjs";

// Each route is "ready" when the matching `view-<id>` section is visible and
// at least one of the mustContain selectors exists inside it.
const ROUTES = [
  { path: "/newchat", id: "view-newchat", selector: "#openChatBtn" },
  { path: "/chats", id: "view-chats", selector: "#chatEmptyHint, #chatThread" },
  { path: "/server", id: "view-server", selector: "#serverUrl" },
  { path: "/keys", id: "view-keys", selector: "#fpFull" },
  { path: "/library", id: "view-library", selector: ".view-panel" },
  { path: "/about", id: "view-about", selector: ".view-panel" },
];

export default async function ({ baseUrl, browser }) {
  const { page, context } = await newClient(browser, baseUrl);
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(e.message));
  page.on("console", (msg) => {
    if (msg.type() === "error") pageErrors.push("[console.error] " + msg.text());
  });

  try {
    // Landing page should register an identity and show a 64-char fp.
    await eventually(async () => {
      const fp = await page.evaluate(
        () => document.querySelector("#fpFull")?.textContent?.trim() ?? "",
      );
      return /^[0-9a-f]{64}$/.test(fp);
    }, { timeoutMs: 10_000 });

    for (const r of ROUTES) {
      await goto(page, baseUrl, r.path);
      await sleep(150);
      const visible = await page.evaluate((id) => {
        const el = document.getElementById(id);
        return !!el && !el.hasAttribute("hidden");
      }, r.id);
      assert(visible, `route ${r.path} did not make #${r.id} visible`);
      const hasSelector = await page.evaluate(
        (sel) => !!document.querySelector(sel),
        r.selector,
      );
      assert(
        hasSelector,
        `route ${r.path}: selector ${r.selector} not found`,
      );
    }

    assert(
      pageErrors.length === 0,
      `page errors: ${pageErrors.slice(0, 5).join(" | ")}`,
    );
  } finally {
    await context.close();
  }
}
