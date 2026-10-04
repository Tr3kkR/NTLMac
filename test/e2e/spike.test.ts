// Phase 0 spike (a): does Chromium's onAuthRequired fire for a *server* NTLM challenge,
// and does the extension + native host sign in silently, safely and with CBT?
//
// Chromium is driven headless with NO DevTools connection: Playwright's
// CDP auth interception answers 401s before extensions see them, which masks the very
// behaviour under test. Playwright is only used to locate its Chrome for Testing build.
//
// Each session lands on the server's unauthenticated /start page, which moves on to the
// challenged URL after 2 s. With --load-extension on a fresh profile the extension installs
// asynchronously, so a challenge on the very first navigation races the listener
// registration. Whether a policy force-installed extension has the same startup race is an
// open spike item (docs/spike-findings.md).
//
// Since the MVP shim, the decision is made by a debug NTLMacAgent that harness.ts runs as
// a throwaway LaunchAgent for each session (launchctl bootstrap gui/$UID, then bootout).
//
// Prereqs: `swift build` in agent/, `npm run build` in extension/,
// test/ntlm-server/.venv with pyspnego, and certs from make-cert.sh.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { count, launch, type Server, sleep, type Stats, startServer } from "./harness.ts";

const PORT = 18443;
const CBT_PORT = 18444;
let plain: Server;
let cbt: Server;

interface Observation {
  stats: Stats;
  /** Decision lines logged by ntlmac-nmh (Chromium forwards host stderr to its own). */
  decisions: string[];
}

/**
 * One cold headless browser session on `url`. Polls the server until `done` holds (or
 * 15 s pass), keeps watching a further 3 s to catch any extra retries, then quits.
 */
async function browse(password: string, url: string, server: Server, done: (s: Stats) => boolean): Promise<Observation> {
  const session = await launch({ url, password });
  try {
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline && !done(await server.stats())) await sleep(250);
    await sleep(3_000);
    return { stats: await server.stats(), decisions: session.decisions().map((d) => `-> ${d}`) };
  } finally {
    await session.close();
  }
}

before(async () => {
  plain = await startServer(PORT);
  cbt = await startServer(CBT_PORT, ["--require-cbt"]);
});

after(() => {
  plain.stop();
  cbt.stop();
});

test("silent NTLM sign-in to an allowlisted NTLM-only HTTPS site", async () => {
  const before = count(await plain.stats(), "success");
  const obs = await browse("Passw0rd!", `https://app.corp.example:${PORT}/start`, plain, (s) => count(s, "success") > before);
  assert.equal(count(obs.stats, "success"), before + 1);
  assert.ok(obs.decisions.some((d) => d.endsWith("-> supplied")), obs.decisions.join("\n"));
});

test("Chromium sends channel bindings: sign-in works where EPA is required", async () => {
  const before = count(await cbt.stats(), "success");
  const obs = await browse("Passw0rd!", `https://app.corp.example:${CBT_PORT}/start`, cbt, (s) => count(s, "success") > before);
  assert.equal(count(obs.stats, "success"), before + 1);
  assert.equal(count(obs.stats, "failure"), 0);
});

test("stale password causes exactly one bad attempt, then falls back", async () => {
  const before = await plain.stats();
  const obs = await browse("stale-password", `https://app.corp.example:${PORT}/start`, plain, (s) => count(s, "failure") > count(before, "failure"));
  assert.equal(count(obs.stats, "failure"), count(before, "failure") + 1, "lockout guard must stop after one failure");
  assert.equal(count(obs.stats, "success"), count(before, "success"));
  assert.ok(obs.decisions.some((d) => d.endsWith("-> retry_cancelled")), obs.decisions.join("\n"));
});

test("hosts not on the allowlist never receive the credential", async () => {
  const before = await plain.stats();
  const reached = (s: Stats) => (s.requests["other.corp.example"] ?? 0) > (before.requests["other.corp.example"] ?? 0);
  const obs = await browse("Passw0rd!", `https://other.corp.example:${PORT}/start`, plain, reached);
  assert.ok(reached(obs.stats), "browser must actually have been challenged");
  assert.deepEqual(obs.stats.users, before.users, "no NTLM AUTHENTICATE may reach the server");
  assert.ok(obs.decisions.some((d) => d.endsWith("-> not_allowlisted")), obs.decisions.join("\n"));
});
