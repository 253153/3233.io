import { startBackend, launchBrowser } from "./harness.mjs";
import { newClient, goto } from "./lib.mjs";

const backend = await startBackend();
const browser = await launchBrowser();
try {
  const { page } = await newClient(browser, backend.baseUrl);
  // Force navigator.share to be undefined BEFORE main() runs.
  await page.evaluateOnNewDocument(() => {
    try {
      Object.defineProperty(navigator, "share", { value: undefined, configurable: true });
    } catch {}
  });
  await goto(page, backend.baseUrl, "/newchat");
  await page.waitForSelector(".invite-share-row", { timeout: 5000 });
  const info = await page.evaluate(() => {
    const btn = document.getElementById("shareInviteNative");
    if (!btn) return { found: false };
    const cs = getComputedStyle(btn);
    return {
      found: true,
      hiddenAttr: btn.hasAttribute("hidden"),
      displayed: cs.display,
      visible: btn.offsetWidth > 0 && btn.offsetHeight > 0,
      text: btn.textContent?.trim(),
      navigatorShareType: typeof navigator.share,
    };
  });
  console.log(JSON.stringify(info, null, 2));
} finally {
  await browser.close();
  if (typeof backend.stop === "function") await backend.stop();
  else if (typeof backend.kill === "function") backend.kill();
}
