// Boots the Rust relay server with the built client served as STATIC_DIR on an
// ephemeral localhost port, and launches a headless Chromium. Specs receive a
// `{ baseUrl, browser }` context and are responsible for cleaning up their own
// pages/contexts; the harness tears down the browser + server when done.

import { spawn } from "node:child_process";
import { createServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import puppeteer from "puppeteer-core";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const SERVER_DIR = path.join(ROOT, "server");
const CLIENT_DIST = path.join(ROOT, "client", "dist");

function pickChromiumExecutable() {
  const envPath = process.env.CHROMIUM_PATH;
  const candidates = [
    envPath,
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
  ].filter(Boolean);
  for (const c of candidates) {
    if (c && fs.existsSync(c)) return c;
  }
  throw new Error(
    "Could not find chromium/chrome. Install chromium or set CHROMIUM_PATH.",
  );
}

async function pickPort() {
  return await new Promise((resolve, reject) => {
    const s = createServer();
    s.unref();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function waitForHealth(url, timeoutMs = 20_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(`${url}/v1/stats`);
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`server at ${url} did not become ready in ${timeoutMs}ms`);
}

/**
 * Build the client and boot the server. Returns `{ baseUrl, close }`.
 * `close()` is idempotent.
 */
export async function startBackend({ log = () => {} } = {}) {
  if (!fs.existsSync(CLIENT_DIST)) {
    log("building client (dist missing)…");
    await runSync("npm", ["run", "build"], { cwd: path.join(ROOT, "client") });
  }

  // Pre-build the server so the first `cargo run` starts fast.
  log("building server…");
  await runSync("cargo", ["build", "--quiet"], { cwd: SERVER_DIR });

  const port = await pickPort();
  const baseUrl = `http://127.0.0.1:${port}`;
  log(`starting server on ${baseUrl}`);

  const child = spawn(
    "cargo",
    ["run", "--quiet"],
    {
      cwd: SERVER_DIR,
      env: {
        ...process.env,
        JWT_SECRET: "e2e-test-secret",
        BIND: `127.0.0.1:${port}`,
        STATIC_DIR: CLIENT_DIST,
        DATABASE_URL: `sqlite:${path.join(HERE, `.e2e-${port}.db`)}?mode=rwc`,
        RUST_LOG: process.env.RUST_LOG ?? "warn",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  let closed = false;
  const onExit = new Promise((resolve) =>
    child.once("exit", (code) => {
      closed = true;
      resolve(code);
    }),
  );

  child.stdout.on("data", (d) => log("[server]", d.toString().trim()));
  child.stderr.on("data", (d) => log("[server]", d.toString().trim()));

  try {
    await waitForHealth(baseUrl);
  } catch (e) {
    child.kill("SIGTERM");
    await onExit;
    throw e;
  }

  async function close() {
    if (closed) return;
    child.kill("SIGTERM");
    await Promise.race([onExit, new Promise((r) => setTimeout(r, 5000))]);
    if (!closed) child.kill("SIGKILL");
    // Best-effort cleanup of the sqlite file.
    try {
      fs.unlinkSync(path.join(HERE, `.e2e-${port}.db`));
    } catch {}
  }

  return { baseUrl, close };
}

function runSync(cmd, args, opts) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: "inherit", ...opts });
    p.once("exit", (code) =>
      code === 0
        ? resolve()
        : reject(new Error(`${cmd} ${args.join(" ")} exited ${code}`)),
    );
  });
}

export async function launchBrowser() {
  return puppeteer.launch({
    executablePath: pickChromiumExecutable(),
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-features=Translate",
    ],
  });
}

/**
 * Grant notification permission on a specific browser context. Each incognito
 * context has its own permission store; calling this on the default context
 * does NOT carry over to contexts created with `createBrowserContext`.
 */
export async function grantNotificationsOn(context, origin) {
  await context.overridePermissions(origin, ["notifications"]);
}
