// Shared direct-spawn harness for both browser suites. Chrome for Testing is spawned
// headless with NO DevTools connection, because any CDP-controlled page fails NTLM with
// ERR_INVALID_AUTH_CREDENTIALS (docs/spike-findings.md). Evidence comes from the test
// server's /stats, ntlmac-nmh's stderr decision lines, the extension's console lines (via
// --enable-logging=stderr) and the windows the browser process owns.
//
// Each session runs a debug NTLMacAgent as a throwaway LaunchAgent in the user's GUI
// domain (launchctl bootstrap gui/$UID), on a Mach service unique to the session, and
// boots it out afterwards (also on exit, Ctrl-C, and at the next run for leftovers).
// Debug builds are only ad-hoc signed, so the DEBUG-only overrides (DebugOverrides.swift)
// pin each side to the other's cdhash in place of the team-ID policy, and give the agent
// a JSON config and a credential file in place of the managed profile and the Keychain.
//
// Headless Chrome on macOS shows its HTTP auth prompt as a real window, possibly on
// another Space. Scenarios that fall back to the prompt put a dialog on the screen of
// whoever runs them; don't type into it.

import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium } from "playwright";

export const ROOT = resolve(import.meta.dirname, "../..");
export const EXTENSION = join(ROOT, "extension");
export const NMH = join(ROOT, "agent/.build/debug/ntlmac-nmh");
export const AGENT = join(ROOT, "agent/.build/debug/NTLMacAgent");
const SERVER_DIR = join(ROOT, "test/ntlm-server");
const PYTHON = join(SERVER_DIR, ".venv/bin/python");
const CHROMIUM = process.env.CHROMIUM_BIN ?? chromium.executablePath();

export const APP = "app.corp.example";
export const USER = "CORP\\jbloggs";
export const PASSWORD = "Passw0rd!";

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Polls `check` every 100 ms until it holds or `ms` pass. Returns whether it held. */
export async function waitFor(check: () => boolean | Promise<boolean>, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await check()) return true;
    await sleep(100);
  }
  return check();
}

const work = mkdtempSync(join(tmpdir(), "ntlmac-e2e-"));
const cleanups: Array<() => void> = [];
process.on("exit", () => {
  for (const c of cleanups.reverse()) c();
  rmSync(work, { recursive: true, force: true });
});
// Run the exit cleanups (launchctl bootout) on Ctrl-C and when the test runner stops us.
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => process.exit(130));

/** Chromium's ID for an unpacked extension without a "key": SHA-256 of the path, a-p encoded. */
function unpackedExtensionId(path: string): string {
  const hex = createHash("sha256").update(path).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

export interface Stats {
  users: Record<string, { success: number; failure: number }>;
  requests: Record<string, number>;
  basic: Record<string, number>;
}

export interface Server {
  url(path: string, host?: string): string;
  stats(): Promise<Stats>;
  stop(): void;
}

export const count = (s: Stats, kind: "success" | "failure") => s.users[USER]?.[kind] ?? 0;
export const reached = (s: Stats, host = APP) => s.requests[host] ?? 0;

export async function startServer(port: number, flags: string[] = []): Promise<Server> {
  const scheme = flags.includes("--plain-http") ? "http" : "https";
  const proc = spawn(PYTHON, ["server.py", "--port", String(port), ...flags], { cwd: SERVER_DIR });
  const stop = () => proc.exitCode === null && proc.kill();
  cleanups.push(stop);
  await new Promise<void>((ok, fail) => {
    proc.stdout!.on("data", (d: Buffer) => d.toString().includes("cbt=") && ok());
    proc.on("exit", (code) => fail(new Error(`server on ${port} exited ${code}`)));
  });
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // local self-signed test server only
  return {
    url: (path, host = APP) => `${scheme}://${host}:${port}${path}`,
    stats: async () => (await fetch(`${scheme}://127.0.0.1:${port}/stats`)).json() as Promise<Stats>,
    stop,
  };
}

// MARK: Agent

const GUI_DOMAIN = `gui/${process.getuid!()}`;
const TEST_LABEL_PREFIX = "com.example.ntlmac.agent.test.";

/** A binary's designated requirement; for ad-hoc debug builds, `cdhash H"…"`. */
function designatedRequirement(path: string): string {
  const out = execFileSync("codesign", ["-d", "-r-", path], { stdio: ["ignore", "pipe", "ignore"] }).toString();
  const match = /designated => (.+)/.exec(out);
  if (!match) throw new Error(`no designated requirement for ${path}: ${out}`);
  return match[1]!.trim();
}

function loaded(label: string): boolean {
  try {
    execFileSync("launchctl", ["print", `${GUI_DOMAIN}/${label}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** Synchronous, so it also works in the exit handler. Waits until launchd has let go. */
function bootout(label: string) {
  try {
    execFileSync("launchctl", ["bootout", `${GUI_DOMAIN}/${label}`], { stdio: "ignore" });
  } catch {
    // not loaded
  }
  // bootout returns before the job is gone; don't leave one unloading behind.
  const pause = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; i < 50 && loaded(label); i++) Atomics.wait(pause, 0, 0, 100);
  if (loaded(label)) console.error(`launchd still has ${label}; remove it with: launchctl bootout ${GUI_DOMAIN}/${label}`);
}

/** Leftovers from a run that was killed before its cleanup ran. */
function bootoutLeftovers() {
  const list = execFileSync("launchctl", ["list"]).toString();
  for (const line of list.split("\n")) {
    const label = line.split("\t")[2];
    if (label?.startsWith(TEST_LABEL_PREFIX)) bootout(label);
  }
}

let agentSerial = 0;
let sweptLeftovers = false;

export interface Agent {
  /** Mach service the shim must use; also the launchd label. */
  service: string;
  /** What the shim requires of this agent. */
  requirement: string;
  /** The agent's stderr so far. */
  log(): string;
  stop(): void;
}

/** Writes the agent's inputs into `run` and starts it as a throwaway LaunchAgent. */
export async function startAgent(run: string, configJSON: object, credentialLine: string): Promise<Agent> {
  if (!existsSync(AGENT)) throw new Error(`build the agent first: ${AGENT}`);
  if (!sweptLeftovers) {
    bootoutLeftovers();
    sweptLeftovers = true;
  }
  const label = `${TEST_LABEL_PREFIX}${process.pid}-${++agentSerial}`;
  const configPath = join(run, "config.json");
  const credential = join(run, "credential");
  const logPath = join(run, "agent.log");
  const plistPath = join(run, `${label}.plist`);
  writeFileSync(configPath, JSON.stringify(configJSON));
  writeFileSync(credential, credentialLine, { mode: 0o600 });
  writeFileSync(logPath, "");
  writeFileSync(
    plistPath,
    JSON.stringify({
      Label: label,
      ProgramArguments: [AGENT],
      MachServices: { [label]: true },
      RunAtLoad: true,
      // A crash should fail the test, not be papered over by a relaunch.
      KeepAlive: false,
      StandardErrorPath: logPath,
      EnvironmentVariables: {
        NTLMAC_MACH_SERVICE: label,
        NTLMAC_SHIM_REQUIREMENT: designatedRequirement(NMH),
        NTLMAC_CONFIG: configPath,
        NTLMAC_TEST_CREDENTIAL_FILE: credential,
        NTLMAC_TELEMETRY_DIR: join(run, "telemetry"),
        NTLMAC_SUSPECT_LATCH_FILE: join(run, "credential-suspect"),
        // The stale-password scenario trips the breaker: never put the real dialog on screen.
        NTLMAC_NO_DIALOG: "1",
      },
    }),
  );
  execFileSync("plutil", ["-convert", "xml1", plistPath]);
  execFileSync("launchctl", ["bootstrap", GUI_DOMAIN, plistPath]);
  const stop = () => bootout(label);
  cleanups.push(stop);
  const log = () => readFileSync(logPath, "utf8");
  if (!(await waitFor(() => log().includes("NTLMacAgent: started"), 10_000))) {
    stop();
    throw new Error(`agent did not start:\n${log()}`);
  }
  return { service: label, requirement: designatedRequirement(AGENT), log, stop };
}

// MARK: Browser

export interface TestConfig {
  enabled?: boolean;
  killDate?: string;
  httpExceptions?: Array<{ host: string; expires: string }>;
}

export interface LaunchOptions {
  url: string;
  config?: TestConfig;
  password?: string;
  /** Path the native-messaging manifest points at; a missing file simulates no host. */
  hostPath?: string;
  /** false: no agent is started, so the shim finds nothing on its Mach service. */
  agent?: boolean;
}

export interface Window {
  layer: number;
  onscreen: boolean;
  alpha: number;
  width: number;
  height: number;
}

export interface Session {
  /** The agent's stderr (empty if none was started). */
  agentLog(): string;
  /** Outcomes logged by ntlmac-nmh (`ntlmac-nmh: request … -> <outcome>`), in order. */
  decisions(): string[];
  /** Times the extension's service worker has started (once per idle-termination wake). */
  workerStarts(): number;
  /** Whether the browser's stderr has matched `re` yet. */
  logged(re: RegExp): boolean;
  /** Every window the browser process owns, on any Space. */
  windows(): Window[];
  close(): Promise<void>;
}

let windowLister: string | undefined;
function listWindows(pid: number): Window[] {
  if (!windowLister) {
    windowLister = join(work, "windows");
    execFileSync("swiftc", ["-O", join(import.meta.dirname, "windows.swift"), "-o", windowLister]);
  }
  const out = execFileSync(windowLister, [String(pid)]).toString().trim();
  return out ? out.split("\n").map((l) => JSON.parse(l) as Window) : [];
}

/** One cold headless browser session with the unpacked extension and an agent, on `url`. */
export async function launch(opts: LaunchOptions): Promise<Session> {
  const run = mkdtempSync(join(work, "run-"));
  const profile = join(run, "profile");
  const agent =
    opts.agent === false
      ? undefined
      : await startAgent(
          run,
          {
            enabled: opts.config?.enabled ?? true,
            killDate: opts.config?.killDate ?? "2099-01-01T00:00:00Z",
            realm: "CORP.EXAMPLE",
            netbiosDomain: "CORP",
            rules: [{ id: "test-app", pattern: APP }],
            httpExceptions: opts.config?.httpExceptions ?? [],
          },
          `jbloggs:${opts.password ?? PASSWORD}`,
        );
  const hostPath = opts.hostPath ?? NMH;
  if (hostPath === NMH && !existsSync(NMH)) throw new Error(`build the host first: ${NMH}`);
  // Chromium reads user-level native messaging manifests from <user-data-dir>/NativeMessagingHosts.
  mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
  writeFileSync(
    join(profile, "NativeMessagingHosts", "com.example.ntlmac.json"),
    JSON.stringify({
      name: "com.example.ntlmac",
      description: "NTLMac test host",
      path: hostPath,
      type: "stdio",
      allowed_origins: [`chrome-extension://${unpackedExtensionId(EXTENSION)}/`],
    }),
  );

  const browser: ChildProcess = spawn(
    CHROMIUM,
    [
      "--headless",
      // Never touch the real login Keychain ("Chrome Safe Storage" prompts block headless runs).
      "--use-mock-keychain",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--ignore-certificate-errors",
      // Forwards the extension's console lines (worker starts, agent disconnects) to stderr.
      "--enable-logging=stderr",
      `--disable-extensions-except=${EXTENSION}`,
      `--load-extension=${EXTENSION}`,
      `--host-resolver-rules=MAP ${APP} 127.0.0.1, MAP other.corp.example 127.0.0.1`,
      opts.url,
    ],
    {
      // Chrome passes its environment on to the native host it spawns.
      env: {
        ...process.env,
        // With no agent, a service nobody registered: the shim must decline in time.
        NTLMAC_MACH_SERVICE: agent?.service ?? `${TEST_LABEL_PREFIX}absent-${process.pid}`,
        NTLMAC_AGENT_REQUIREMENT: agent?.requirement ?? designatedRequirement(AGENT),
      },
    },
  );
  let stderr = "";
  browser.stderr!.on("data", (d: Buffer) => (stderr += d.toString()));
  const exited = new Promise((r) => browser.on("exit", r));
  const kill = () => browser.exitCode === null && browser.kill("SIGKILL");
  cleanups.push(kill);

  return {
    agentLog: () => agent?.log() ?? "",
    decisions: () => [...stderr.matchAll(/ntlmac-nmh: request \S+ host=\S+ -> (\w+)/g)].map((m) => m[1]!),
    workerStarts: () => stderr.split("NTLMac: service worker started").length - 1,
    logged: (re) => re.test(stderr),
    windows: () => listWindows(browser.pid!),
    async close() {
      browser.kill();
      const killer = setTimeout(kill, 5_000);
      await exited;
      clearTimeout(killer);
      agent?.stop();
    },
  };
}
