// Phase 0 spike (a): does Chromium's onAuthRequired fire for a *server* NTLM challenge,
// and does the extension + native host sign in silently, safely and with CBT?
//
// Chromium is driven with --headless --dump-dom and NO DevTools connection: Playwright's
// CDP auth interception answers 401s before extensions see them, which masks the very
// behaviour under test. Playwright is only used to locate its Chrome for Testing build.
//
// Each session lands on the server's unauthenticated /start page, which moves on to the
// challenged URL after 2 s. With --load-extension on a fresh profile the extension installs
// asynchronously, so a challenge on the very first navigation races the listener
// registration. Whether a policy force-installed extension has the same startup race is an
// open spike item (docs/spike-findings.md).
//
// Prereqs: `swift build` in agent/, `npm run build` in extension/,
// test/ntlm-server/.venv with pyspnego, and certs from make-cert.sh.

import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { chromium } from "playwright";

const ROOT = resolve(import.meta.dirname, "../..");
const EXTENSION = join(ROOT, "extension");
const NMH = join(ROOT, "agent/.build/debug/ntlmac-nmh");
const SERVER_DIR = join(ROOT, "test/ntlm-server");
const PYTHON = join(SERVER_DIR, ".venv/bin/python");
const CHROMIUM = process.env.CHROMIUM_BIN ?? chromium.executablePath();
const PORT = 18443;
const CBT_PORT = 18444;

const servers: ChildProcess[] = [];
let work: string;

/** Chromium's ID for an unpacked extension without a "key": SHA-256 of the path, a-p encoded. */
function unpackedExtensionId(path: string): string {
  const hex = createHash("sha256").update(path).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

function startServer(port: number, extra: string[] = []): Promise<void> {
  const proc = spawn(PYTHON, ["server.py", "--port", String(port), ...extra], { cwd: SERVER_DIR });
  servers.push(proc);
  return new Promise((ok, fail) => {
    proc.stdout!.on("data", (d: Buffer) => {
      if (d.toString().includes("NTLM-only")) ok();
    });
    proc.on("exit", (code) => fail(new Error(`server exited ${code}`)));
  });
}

interface Stats {
  users: Record<string, { success: number; failure: number }>;
  requests: Record<string, number>;
}

async function stats(port: number): Promise<Stats> {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // local self-signed test server only
  return (await fetch(`https://127.0.0.1:${port}/stats`)).json() as Promise<Stats>;
}

const count = (s: Stats, kind: "success" | "failure") => s.users["CORP\\jbloggs"]?.[kind] ?? 0;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Observation {
  stats: Stats;
  /** Decision lines logged by ntlmac-nmh (Chromium forwards host stderr to its own). */
  decisions: string[];
}

/**
 * One cold headless browser session on `url`. Polls the server until `done` holds (or
 * 15 s pass), keeps watching a further 3 s to catch any extra retries, then quits.
 */
async function browse(password: string, url: string, port: number, done: (s: Stats) => boolean): Promise<Observation> {
  const run = mkdtempSync(join(work, "run-"));
  const profile = join(run, "profile");
  const config = join(run, "config.json");
  const credential = join(run, "credential");
  writeFileSync(
    config,
    JSON.stringify({
      enabled: true,
      killDate: "2099-01-01T00:00:00Z",
      realm: "CORP.EXAMPLE",
      netbiosDomain: "CORP",
      rules: [{ id: "test-app", pattern: "app.corp.example" }],
    }),
  );
  writeFileSync(credential, `jbloggs:${password}`);
  // Chromium reads user-level native messaging manifests from <user-data-dir>/NativeMessagingHosts.
  mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
  writeFileSync(
    join(profile, "NativeMessagingHosts", "com.example.ntlmac.json"),
    JSON.stringify({
      name: "com.example.ntlmac",
      description: "NTLMac spike host",
      path: NMH,
      type: "stdio",
      allowed_origins: [`chrome-extension://${unpackedExtensionId(EXTENSION)}/`],
    }),
  );

  const browser = spawn(
    CHROMIUM,
    [
      "--headless",
      // Never touch the real login Keychain ("Chrome Safe Storage" prompts block headless runs).
      "--use-mock-keychain",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--ignore-certificate-errors",
      `--disable-extensions-except=${EXTENSION}`,
      `--load-extension=${EXTENSION}`,
      "--host-resolver-rules=MAP app.corp.example 127.0.0.1, MAP other.corp.example 127.0.0.1",
      url,
    ],
    { env: { ...process.env, NTLMAC_CONFIG: config, NTLMAC_TEST_CREDENTIAL_FILE: credential } },
  );
  let stderr = "";
  browser.stderr!.on("data", (d: Buffer) => (stderr += d.toString()));
  const exited = new Promise((r) => browser.on("exit", r));

  try {
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline && !done(await stats(port))) await sleep(250);
    await sleep(3_000);
    return {
      stats: await stats(port),
      decisions: stderr.split("\n").filter((l) => l.startsWith("ntlmac-nmh: request")),
    };
  } finally {
    browser.kill();
    const killer = setTimeout(() => browser.kill("SIGKILL"), 5_000);
    await exited;
    clearTimeout(killer);
  }
}

before(async () => {
  work = mkdtempSync(join(tmpdir(), "ntlmac-e2e-"));
  await startServer(PORT);
  await startServer(CBT_PORT, ["--require-cbt"]);
});

after(() => {
  for (const s of servers) s.kill();
  rmSync(work, { recursive: true, force: true });
});

test("silent NTLM sign-in to an allowlisted NTLM-only HTTPS site", async () => {
  const before = count(await stats(PORT), "success");
  const obs = await browse("Passw0rd!", `https://app.corp.example:${PORT}/start`, PORT, (s) => count(s, "success") > before);
  assert.equal(count(obs.stats, "success"), before + 1);
  assert.ok(obs.decisions.some((d) => d.endsWith("-> supplied")), obs.decisions.join("\n"));
});

test("Chromium sends channel bindings: sign-in works where EPA is required", async () => {
  const before = count(await stats(CBT_PORT), "success");
  const obs = await browse("Passw0rd!", `https://app.corp.example:${CBT_PORT}/start`, CBT_PORT, (s) => count(s, "success") > before);
  assert.equal(count(obs.stats, "success"), before + 1);
  assert.equal(count(obs.stats, "failure"), 0);
});

test("stale password causes exactly one bad attempt, then falls back", async () => {
  const before = await stats(PORT);
  const obs = await browse("stale-password", `https://app.corp.example:${PORT}/start`, PORT, (s) => count(s, "failure") > count(before, "failure"));
  assert.equal(count(obs.stats, "failure"), count(before, "failure") + 1, "lockout guard must stop after one failure");
  assert.equal(count(obs.stats, "success"), count(before, "success"));
  assert.ok(obs.decisions.some((d) => d.endsWith("-> retry_cancelled")), obs.decisions.join("\n"));
});

test("hosts not on the allowlist never receive the credential", async () => {
  const before = await stats(PORT);
  const reached = (s: Stats) => (s.requests["other.corp.example"] ?? 0) > (before.requests["other.corp.example"] ?? 0);
  const obs = await browse("Passw0rd!", `https://other.corp.example:${PORT}/start`, PORT, reached);
  assert.ok(reached(obs.stats), "browser must actually have been challenged");
  assert.deepEqual(obs.stats.users, before.users, "no NTLM AUTHENTICATE may reach the server");
  assert.ok(obs.decisions.some((d) => d.endsWith("-> not_allowlisted")), obs.decisions.join("\n"));
});
