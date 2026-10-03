import assert from "node:assert/strict";
import { test } from "node:test";
import { type AuthDetails, buildAuthRequest, shouldConsultAgent, toBlockingResponse } from "../src/logic.ts";

const details = (over: Partial<AuthDetails> = {}): AuthDetails => ({
  requestId: "123",
  url: "https://app.corp.example/secret/path?q=1",
  scheme: "ntlm",
  isProxy: false,
  challenger: { host: "app.corp.example", port: 443 },
  ...over,
});

test("consults agent only for non-proxy NTLM challenges", () => {
  assert.equal(shouldConsultAgent(details()), true);
  assert.equal(shouldConsultAgent(details({ scheme: "NTLM" })), true);
  assert.equal(shouldConsultAgent(details({ scheme: "basic" })), false);
  assert.equal(shouldConsultAgent(details({ scheme: "negotiate" })), false);
  assert.equal(shouldConsultAgent(details({ isProxy: true })), false);
});

test("builds agent request with namespaced ID and only the URL scheme", () => {
  const req = buildAuthRequest(details(), "nonce-1");
  assert.deepEqual(req, {
    requestId: "nonce-1:123",
    host: "app.corp.example",
    port: 443,
    urlScheme: "https",
    authScheme: "ntlm",
    isProxy: false,
  });
  assert.ok(!JSON.stringify(req).includes("secret"));
});

test("unparseable URL yields empty scheme for the agent to decline", () => {
  assert.equal(buildAuthRequest(details({ url: "not a url" }), "n").urlScheme, "");
});

test("supply reply becomes authCredentials", () => {
  assert.deepEqual(toBlockingResponse({ id: 1, action: "supply", username: "CORP\\jb", password: "pw" }), {
    authCredentials: { username: "CORP\\jb", password: "pw" },
  });
});

test("decline, timeout and malformed replies fall back to the browser prompt", () => {
  assert.deepEqual(toBlockingResponse({ id: 1, action: "decline", outcome: "not_allowlisted" }), {});
  assert.deepEqual(toBlockingResponse(null), {});
  assert.deepEqual(toBlockingResponse({ id: 1, action: "supply" } as never), {});
});
