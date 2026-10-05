import assert from "node:assert/strict";
import { test } from "node:test";
import { applyPrefix, PLACEHOLDER } from "../scripts/apply-prefix.ts";
import { NATIVE_HOST } from "../src/logic.ts";

const built = `export const NATIVE_HOST = "${PLACEHOLDER}";\nexport const AGENT_TIMEOUT_MS = 3000;\n`;

test("the source's native host is the placeholder the build replaces", () => {
  assert.equal(NATIVE_HOST, PLACEHOLDER);
});

test("replaces the native host name with the prefix", () => {
  assert.equal(applyPrefix(built, "org.test.ntlmac"), built.replace(PLACEHOLDER, "org.test.ntlmac"));
});

test("rejects prefixes that aren't valid native host names", () => {
  for (const bad of ["", "ntlmac", "Org.Test", "org.my-org.ntlmac", "org..ntlmac", 'org.x".ntlmac']) {
    assert.throws(() => applyPrefix(built, bad), /NTLMAC_PREFIX/, bad);
  }
});

test("fails unless the placeholder appears exactly once", () => {
  assert.throws(() => applyPrefix("nothing here", "org.test.ntlmac"), /exactly once/);
  assert.throws(() => applyPrefix(built + built, "org.test.ntlmac"), /exactly once/);
});
