// Scenario suite: behaviour beyond the four spike scenarios, on the same direct-spawn,
// no-DevTools harness (see harness.ts for why). Each scenario starts its own server on its
// own port, so any one can run alone: node --test --test-name-pattern='<name>' scenarios.test.ts
//
// Scenarios that fall back to the browser's own prompt put a real sign-in dialog on the
// screen (possibly on another Space) until the browser is killed. Don't type into it.
//
// Prereqs: as for spike.test.ts (swift build, extension build, server venv and certs).

import assert from "node:assert/strict";
import { test } from "node:test";
import { AGENT_TIMEOUT_MS } from "../../extension/src/logic.ts";
import {
  APP,
  count,
  launch,
  reached,
  type Session,
  type Server,
  sleep,
  startServer,
  waitFor,
} from "./harness.ts";

/**
 * Whether the browser's HTTP auth dialog is up. Headless Chrome also owns hidden helper
 * windows (1x1, 396x88, 396x107, 756x556 on Chrome for Testing 153, macOS 26); the
 * sign-in dialog was the only new window, at 320x252 (320x272 over plain HTTP, which adds
 * a not-secure warning). Match its size loosely.
 */
const promptShown = (s: Session) =>
  s.windows().some((w) => w.width >= 250 && w.width <= 450 && w.height >= 180 && w.height <= 400);

/** Browses `path`, waits for `done` (or `ms`), then watches 3 s more for stray retries. */
async function browse(server: Server, path: string, launchOpts: Omit<Parameters<typeof launch>[0], "url">, done: (s: Session) => Promise<boolean>, ms = 20_000) {
  const session = launch({ url: server.url(path), ...launchOpts });
  try {
    // Window lists early and late, so promptShown can be recalibrated from the output if
    // Chrome's dialog or helper windows change size. /start pages haven't been challenged yet.
    await sleep(1_000);
    console.log(`windows after 1 s: ${JSON.stringify(session.windows())}`);
    await waitFor(() => done(session), ms);
    await sleep(3_000);
    console.log(`windows at the end: ${JSON.stringify(session.windows())}`);
    return { session, stats: await server.stats(), prompt: promptShown(session) };
  } finally {
    await session.close();
    server.stop();
  }
}

const PAST = "2020-01-01T00:00:00Z";
const FUTURE = "2099-01-01T00:00:00Z";

test("worker idle termination: silent sign-in after Chrome has stopped the idle service worker", async () => {
  const server = await startServer(18461);
  // 45 s on the landing page with no events: Chrome stops an idle MV3 worker after 30 s.
  const obs = await browse(server, "/start?wait=45", {}, async () => count(await server.stats(), "success") > 0, 75_000);
  assert.ok(obs.session.workerStarts() >= 2, `worker must have been stopped and woken; starts=${obs.session.workerStarts()}`);
  assert.equal(count(obs.stats, "success"), 1);
  assert.equal(count(obs.stats, "failure"), 0);
  assert.deepEqual(obs.session.decisions(), ["supplied"]);
  assert.equal(obs.prompt, false, "no sign-in prompt on the happy path");
});

test(
  "first navigation straight after launch (startup race with --load-extension)",
  { todo: "known race: a challenge before the listener registers gets the browser prompt; policy force-install may differ (spike-findings a′)" },
  async () => {
    const server = await startServer(18462);
    const obs = await browse(server, "/", {}, async (s) => count(await server.stats(), "success") > 0 || promptShown(s), 15_000);
    assert.equal(count(obs.stats, "success"), 1, `prompt=${obs.prompt} decisions=${obs.session.decisions()}`);
    assert.equal(obs.prompt, false);
  },
);

test("agent unavailable: missing host binary falls back to the prompt within AGENT_TIMEOUT_MS, no credential sent", async () => {
  const server = await startServer(18463);
  const session = launch({ url: server.url("/start"), hostPath: "/nonexistent/ntlmac-nmh" });
  try {
    assert.ok(await waitFor(async () => reached(await server.stats()) > 0, 15_000), "browser must be challenged");
    const challenged = Date.now();
    const prompted = await waitFor(() => promptShown(session), AGENT_TIMEOUT_MS + 2_000);
    const fallbackMs = Date.now() - challenged;
    console.log(`fell back to the browser prompt ${fallbackMs} ms after the challenge`);
    await sleep(3_000);
    const stats = await server.stats();
    assert.ok(prompted, "the browser's own prompt must appear");
    assert.ok(fallbackMs <= AGENT_TIMEOUT_MS + 1_000, `fell back after ${fallbackMs} ms`);
    assert.deepEqual(stats.users, {}, "no NTLM AUTHENTICATE may reach the server");
    assert.deepEqual(session.decisions(), [], "no host ran");
    assert.ok(session.logged(/NTLMac agent (disconnected|unavailable)/), "extension logs the missing agent");
  } finally {
    await session.close();
    server.stop();
  }
});

for (const [name, config] of [
  ["enabled=false", { enabled: false }],
  ["killDate in the past", { killDate: PAST }],
] as const) {
  test(`kill switch (${name}): no credential, outcome killswitch, browser prompt`, async () => {
    const server = await startServer(name === "enabled=false" ? 18464 : 18465);
    const obs = await browse(server, "/start", { config }, async (s) => s.decisions().length > 0);
    assert.ok(reached(obs.stats) > 0, "browser must actually have been challenged");
    assert.deepEqual(obs.stats.users, {}, "no NTLM AUTHENTICATE may reach the server");
    assert.deepEqual([...new Set(obs.session.decisions())], ["killswitch"]);
    assert.equal(obs.prompt, true, "falls back to the browser's own prompt");
  });
}

test("plain HTTP without an exception: http_blocked, no credential", async () => {
  const server = await startServer(18466, ["--plain-http"]);
  const obs = await browse(server, "/start", {}, async (s) => s.decisions().length > 0);
  assert.ok(reached(obs.stats) > 0, "browser must actually have been challenged over HTTP");
  assert.deepEqual(obs.stats.users, {}, "no NTLM AUTHENTICATE may reach the server");
  assert.deepEqual([...new Set(obs.session.decisions())], ["http_blocked"]);
  assert.equal(obs.prompt, true, "falls back to the browser's own prompt");
});

test("plain HTTP with an unexpired exception: silent sign-in", async () => {
  const server = await startServer(18467, ["--plain-http"]);
  const config = { httpExceptions: [{ host: APP, expires: FUTURE }] };
  const obs = await browse(server, "/start", { config }, async () => count(await server.stats(), "success") > 0);
  assert.equal(count(obs.stats, "success"), 1);
  assert.equal(count(obs.stats, "failure"), 0);
  assert.deepEqual(obs.session.decisions(), ["supplied"]);
  assert.equal(obs.prompt, false, "no sign-in prompt on the happy path");
});

test("Basic auth is never answered: no Authorization: Basic ever arrives", async () => {
  const server = await startServer(18468, ["--basic"]);
  const obs = await browse(server, "/start", {}, async (s) => promptShown(s));
  assert.ok(reached(obs.stats) > 0, "browser must actually have been challenged with Basic");
  assert.deepEqual(obs.stats.basic, {}, "a Basic credential reached the server");
  const decisions = obs.session.decisions();
  assert.ok(decisions.every((d) => d === "not_ntlm"), `host may only decline: ${decisions}`);
  assert.equal(obs.prompt, true, "falls back to the browser's own prompt");
});
