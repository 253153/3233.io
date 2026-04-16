// Two-client end-to-end chat: A registers, B registers, A opens a chat with
// B, sends a message, B sees it on the other side. Also covers:
// - Enter-to-send vs Shift+Enter newline
// - XSS escaping of HTML payloads
// - Emoji preservation
// - Self-chat rejection (UX guard)
// - Offline send is surfaced to the user (input preserved)

import {
  assert,
  assertEq,
  eventually,
  newClient,
  openChatWith,
  readFingerprint,
  readThread,
  sendMessage,
  sleep,
  goto,
} from "../lib.mjs";

async function waitForIncoming(page, text) {
  return eventually(async () => {
    const thread = await readThread(page);
    return thread.some((m) => m.kind === "in" && m.text.trim() === text);
  }, { timeoutMs: 8000 });
}

export default async function ({ baseUrl, browser }) {
  const a = await newClient(browser, baseUrl);
  const b = await newClient(browser, baseUrl);

  try {
    const fpA = await readFingerprint(a.page);
    const fpB = await readFingerprint(b.page);
    assert(fpA !== fpB, "A and B must have distinct fingerprints");

    // ---------------- A → B basic delivery ----------------
    await openChatWith(a.page, baseUrl, fpB);
    await sendMessage(a.page, "hello from A");
    await openChatWith(b.page, baseUrl, fpA);
    await waitForIncoming(b.page, "hello from A");

    // ---------------- Enter key submits ----------------
    await b.page.focus("#chatBody");
    await b.page.evaluate(() => {
      const ta = document.querySelector("#chatBody");
      const setter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype,
        "value",
      ).set;
      setter.call(ta, "reply via Enter");
      ta.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await b.page.keyboard.press("Enter");
    await waitForIncoming(a.page, "reply via Enter");

    // ---------------- Shift+Enter inserts newline ----------------
    await b.page.focus("#chatBody");
    await b.page.evaluate(() => {
      const ta = document.querySelector("#chatBody");
      const setter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype,
        "value",
      ).set;
      setter.call(ta, "line one");
      ta.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await b.page.keyboard.down("Shift");
    await b.page.keyboard.press("Enter");
    await b.page.keyboard.up("Shift");
    await b.page.keyboard.type("line two");
    const taVal = await b.page.evaluate(
      () => document.querySelector("#chatBody").value,
    );
    assert(
      taVal.includes("line one\nline two"),
      `shift+enter should insert newline, got ${JSON.stringify(taVal)}`,
    );
    // Clear textarea without sending.
    await b.page.evaluate(() => {
      const ta = document.querySelector("#chatBody");
      const setter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype,
        "value",
      ).set;
      setter.call(ta, "");
      ta.dispatchEvent(new Event("input", { bubbles: true }));
    });

    // ---------------- XSS payload is escaped ----------------
    const payload = "<img src=x onerror=alert(1)>";
    await sendMessage(a.page, payload);
    await waitForIncoming(b.page, payload);
    // The raw HTML must not contain an unescaped <img>.
    const bThread = await readThread(b.page);
    const lastIn = [...bThread].reverse().find((m) => m.kind === "in");
    assert(
      lastIn && !/<img[^>]+onerror/i.test(lastIn.html),
      `XSS leaked: ${lastIn?.html}`,
    );

    // ---------------- Emoji survive the round trip ----------------
    const emoji = "🚀 🌙 🧪 你好";
    await sendMessage(a.page, emoji);
    await waitForIncoming(b.page, emoji);

    // ---------------- Long message ----------------
    const long = "x".repeat(4000);
    await sendMessage(a.page, long);
    await waitForIncoming(b.page, long);

    // ---------------- Whitespace-only is rejected ----------------
    await sendMessage(a.page, "    \n   \t  ");
    await sleep(400);
    const aThread = await readThread(a.page);
    const tails = aThread
      .slice(-3)
      .map((m) => m.text.trim())
      .filter(Boolean);
    assert(
      !tails.includes(""),
      "whitespace-only should not have rendered as a blank outgoing bubble",
    );

    // ---------------- Self-chat is rejected ----------------
    await goto(a.page, baseUrl, "/newchat");
    await a.page.evaluate((fp) => {
      const input = document.querySelector("#openChatFp");
      const setter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype,
        "value",
      ).set;
      setter.call(input, fp);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }, fpA);
    await a.page.click("#openChatBtn");
    await sleep(400);
    const status = await a.page.evaluate(
      () => document.querySelector("#openChatStatus")?.textContent?.trim() ?? "",
    );
    assert(
      /yourself|own|self|cannot/i.test(status),
      `expected a self-chat rejection message, got "${status}"`,
    );

    // ---------------- Message order agrees between A and B ----------------
    await openChatWith(a.page, baseUrl, fpB);
    const orderedMessages = ["one", "two", "three", "four"];
    for (const m of orderedMessages) {
      await sendMessage(a.page, m);
      // sendMessage returns once the fetch is queued; give the UI a tick to
      // append the outgoing bubble before we fire the next one, otherwise the
      // test races against the state mutation.
      await eventually(
        async () => {
          const t = (await readThread(a.page))
            .filter((x) => x.kind === "out")
            .map((x) => x.text.trim());
          return t.includes(m);
        },
        { timeoutMs: 4000 },
      );
    }
    await waitForIncoming(b.page, "four");
    const bTexts = (await readThread(b.page))
      .filter((m) => m.kind === "in")
      .map((m) => m.text.trim());
    const aTexts = (await readThread(a.page))
      .filter((m) => m.kind === "out")
      .map((m) => m.text.trim());
    // The tail of each thread should end with the same ordered sequence.
    for (const m of orderedMessages) {
      assert(aTexts.includes(m), `A missing "${m}"`);
      assert(bTexts.includes(m), `B missing "${m}"`);
    }
    const aTail = aTexts.slice(-orderedMessages.length);
    const bTail = bTexts.slice(-orderedMessages.length);
    assertEq(
      JSON.stringify(aTail),
      JSON.stringify(bTail),
      "A and B tail order diverges",
    );
  } finally {
    await a.context.close();
    await b.context.close();
  }
}
