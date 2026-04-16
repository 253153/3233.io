// Shared helpers used by every spec.

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function assert(cond, msg) {
  if (!cond) throw new Error("assertion failed: " + msg);
}

export function assertEq(a, b, msg) {
  if (a !== b) {
    throw new Error(
      `assertEq failed: ${msg ?? ""} — expected ${JSON.stringify(
        b,
      )}, got ${JSON.stringify(a)}`,
    );
  }
}

/** Poll `fn` until it returns a truthy value or `timeoutMs` elapses. */
export async function eventually(fn, { timeoutMs = 5000, every = 100 } = {}) {
  const start = Date.now();
  let lastErr = null;
  while (Date.now() - start < timeoutMs) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      lastErr = e;
    }
    await sleep(every);
  }
  throw new Error(`eventually: timed out after ${timeoutMs}ms${lastErr ? ` (last error: ${lastErr.message})` : ""}`);
}

/** Open a fresh incognito page at the SPA root, returning `{ page, context }`. */
export async function newClient(browser, baseUrl) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  // Hush page errors by default — specs can opt in if they care.
  page.on("pageerror", (e) => {
    if (process.env.E2E_VERBOSE) console.error("[pageerror]", e.message);
  });
  await page.goto(baseUrl, { waitUntil: "networkidle0" });
  return { page, context };
}

/** Read the user's full fingerprint off the home view. */
export async function readFingerprint(page) {
  return eventually(async () => {
    const fp = await page.evaluate(() => {
      const el = document.querySelector("#fpFull");
      const t = el?.textContent?.trim();
      return t && /^[0-9a-f]{64}$/.test(t) ? t : null;
    });
    return fp;
  }, { timeoutMs: 10_000 });
}

/** Navigate to `path` and wait for the view to be ready. */
export async function goto(page, baseUrl, viewPath) {
  await page.goto(`${baseUrl}${viewPath}`, { waitUntil: "networkidle0" });
}

/** Open a chat with a given fingerprint via the `newchat` view. */
export async function openChatWith(page, baseUrl, peerFp) {
  await goto(page, baseUrl, "/newchat");
  await page.evaluate((fp) => {
    const input = document.querySelector("#openChatFp");
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    ).set;
    setter.call(input, fp);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }, peerFp);
  await page.click("#openChatBtn");
  await eventually(
    () =>
      page.evaluate(() => {
        const ta = document.querySelector("#chatBody");
        // Chat is open when the textarea is visible (no hidden chatThread ancestor).
        return ta && !ta.closest("[hidden]");
      }),
    { timeoutMs: 5000 },
  );
}

/** Type + send a message in the open chat view. `useEnter` uses the Enter key. */
export async function sendMessage(page, text, { useEnter = false } = {}) {
  await page.focus("#chatBody");
  await page.evaluate((t) => {
    const ta = document.querySelector("#chatBody");
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLTextAreaElement.prototype,
      "value",
    ).set;
    setter.call(ta, t);
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  }, text);
  if (useEnter) {
    await page.keyboard.press("Enter");
  } else {
    await page.click("#chatSend");
  }
}

/** Snapshot the current chat thread as an array of `{ text, kind }`. */
export async function readThread(page) {
  return page.evaluate(() => {
    const list = document.querySelector("#chatMessages");
    if (!list) return [];
    return Array.from(list.querySelectorAll(".chat-line")).map((el) => {
      const bubble = el.querySelector(".chat-bubble");
      return {
        text: bubble ? bubble.textContent || "" : el.textContent || "",
        html: bubble ? bubble.innerHTML.slice(0, 2000) : "",
        kind: el.classList.contains("chat-line-out")
          ? "out"
          : el.classList.contains("chat-line-in")
          ? "in"
          : "other",
      };
    });
  });
}
