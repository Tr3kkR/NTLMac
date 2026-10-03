// Pure helpers for the service worker; kept free of chrome.* so they run under node --test.

export const NATIVE_HOST = "com.example.ntlmac";
/** If the agent hasn't answered by then, fall back to the browser's own prompt. */
export const AGENT_TIMEOUT_MS = 3000;

/** The subset of chrome.webRequest.OnAuthRequiredDetails we rely on. */
export interface AuthDetails {
  requestId: string;
  url: string;
  scheme: string;
  isProxy: boolean;
  challenger: { host: string; port: number };
}

/** Mirrors AuthRequest in agent/Sources/NTLMacCore/AuthBroker.swift. */
export interface AuthRequest {
  requestId: string;
  host: string;
  port: number;
  urlScheme: string;
  authScheme: string;
  isProxy: boolean;
}

export type HostReply =
  | { id: number; action: "supply"; username: string; password: string }
  | { id: number; action: "decline"; outcome: string };

export interface BlockingResponse {
  authCredentials?: { username: string; password: string };
}

/**
 * Cheap pre-filter so we don't wake the agent for challenges it would always decline.
 * The agent re-checks everything; this is not the security boundary.
 */
export function shouldConsultAgent(details: AuthDetails): boolean {
  return !details.isProxy && details.scheme.toLowerCase() === "ntlm";
}

/**
 * Only the URL scheme leaves the browser, never the path or query. The request ID is
 * namespaced with a per-browser-session nonce because Chromium restarts its IDs.
 */
export function buildAuthRequest(details: AuthDetails, sessionNonce: string): AuthRequest {
  let urlScheme = "";
  try {
    urlScheme = new URL(details.url).protocol.replace(/:$/, "");
  } catch {
    // leave empty; the agent declines unknown schemes
  }
  return {
    requestId: `${sessionNonce}:${details.requestId}`,
    host: details.challenger.host,
    port: details.challenger.port,
    urlScheme,
    authScheme: details.scheme,
    isProxy: details.isProxy,
  };
}

/** An empty response lets the browser show its normal sign-in prompt. */
export function toBlockingResponse(reply: HostReply | null): BlockingResponse {
  if (reply?.action === "supply" && typeof reply.username === "string" && typeof reply.password === "string") {
    return { authCredentials: { username: reply.username, password: reply.password } };
  }
  return {};
}
