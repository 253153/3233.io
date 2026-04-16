// Discovers every spec in ./specs, boots a fresh backend + browser, and runs
// them sequentially (isolation matters more than speed for a handful of
// specs). Returns a non-zero exit code on any failure.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { startBackend, launchBrowser } from "./harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SPEC_DIR = path.join(HERE, "specs");
const verbose = process.argv.includes("--verbose") || process.env.E2E_VERBOSE;

function log(...args) {
  if (verbose) console.error(...args);
}

function fmt(ms) {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(2)}s`;
}

async function main() {
  const filter = process.argv.find((a) => a.startsWith("--only="))?.slice(7);
  const allSpecs = fs
    .readdirSync(SPEC_DIR)
    .filter((f) => f.endsWith(".mjs"))
    .sort();
  const specs = filter
    ? allSpecs.filter((s) => s.includes(filter))
    : allSpecs;

  if (!specs.length) {
    console.error("no specs found in", SPEC_DIR);
    process.exit(2);
  }

  console.error(`booting backend + chromium for ${specs.length} spec(s)…`);
  const backend = await startBackend({ log });
  const browser = await launchBrowser();
  const ctx = { baseUrl: backend.baseUrl, browser };

  let failed = 0;
  const results = [];
  for (const name of specs) {
    const started = Date.now();
    let status = "ok";
    let error = null;
    try {
      const mod = await import(pathToFileURL(path.join(SPEC_DIR, name)).href);
      if (typeof mod.default !== "function") {
        throw new Error(`${name}: spec must export default async function`);
      }
      await mod.default(ctx);
    } catch (e) {
      status = "fail";
      error = e;
      failed += 1;
    }
    const elapsed = Date.now() - started;
    results.push({ name, status, elapsed, error });
    const tag = status === "ok" ? "PASS" : "FAIL";
    console.log(`  ${tag} ${name} (${fmt(elapsed)})`);
    if (error) {
      console.log(error.stack || error.message || String(error));
    }
  }

  console.log("");
  for (const r of results) {
    console.log(`  ${r.status === "ok" ? "✓" : "✗"} ${r.name} ${fmt(r.elapsed)}`);
  }
  console.log("");
  console.log(`${results.length - failed}/${results.length} passed`);

  await browser.close();
  await backend.close();
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
