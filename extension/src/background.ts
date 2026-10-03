import {
  AGENT_TIMEOUT_MS,
  type AuthDetails,
  type BlockingResponse,
  buildAuthRequest,
  type HostReply,
  NATIVE_HOST,
  shouldConsultAgent,
  toBlockingResponse,
} from "./logic.ts";

let port: chrome.runtime.Port | null = null;
let nextId = 1;
const pending = new Map<number, (reply: HostReply | null) => void>();
let nonce: Promise<string> | null = null;

function sessionNonce(): Promise<string> {
  // storage.session lives exactly as long as the browser session, which is the lifetime
  // of Chromium's request IDs. It survives service-worker restarts.
  nonce ??= chrome.storage.session.get("nonce").then(async ({ nonce: existing }) => {
    if (typeof existing === "string") return existing;
    const fresh = crypto.randomUUID();
    await chrome.storage.session.set({ nonce: fresh });
    return fresh;
  });
  return nonce;
}

function agentPort(): chrome.runtime.Port {
  if (port) return port;
  const p = chrome.runtime.connectNative(NATIVE_HOST);
  p.onMessage.addListener((reply: HostReply) => {
    pending.get(reply.id)?.(reply);
    pending.delete(reply.id);
  });
  p.onDisconnect.addListener(() => {
    if (chrome.runtime.lastError) console.warn("NTLMac agent disconnected:", chrome.runtime.lastError.message);
    port = null;
    for (const resolve of pending.values()) resolve(null);
    pending.clear();
  });
  port = p;
  return p;
}

function askAgent(message: object): Promise<HostReply | null> {
  const id = nextId++;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve(null);
    }, AGENT_TIMEOUT_MS);
    pending.set(id, (reply) => {
      clearTimeout(timer);
      resolve(reply);
    });
    try {
      agentPort().postMessage({ id, type: "auth", ...message });
    } catch (e) {
      console.warn("NTLMac agent unavailable:", e);
      pending.get(id)?.(null);
      pending.delete(id);
    }
  });
}

async function handle(details: AuthDetails): Promise<BlockingResponse> {
  if (!shouldConsultAgent(details)) return {};
  const request = buildAuthRequest(details, await sessionNonce());
  return toBlockingResponse(await askAgent({ request }));
}

chrome.webRequest.onAuthRequired.addListener(
  (details, asyncCallback) => {
    handle(details).then(asyncCallback, () => asyncCallback?.({}));
    return undefined; // answered via asyncCallback
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"],
);
