// Post-build step: with NTLMAC_PREFIX set, replaces the placeholder native host name in
// dist/logic.js, so the extension talks to the host installed by a package built with the
// same prefix (agent/scripts/make-pkg.sh). Without it, the placeholder stays.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const PLACEHOLDER = "com.example.ntlmac";

/** `source` with the quoted placeholder replaced; it must appear exactly once. */
export function applyPrefix(source: string, prefix: string): string {
  // As NTLMacIdentity: 2+ labels of [a-z0-9_], which is also a valid native host name.
  if (!/^[a-z0-9_]+(\.[a-z0-9_]+)+$/.test(prefix)) {
    throw new Error(`NTLMAC_PREFIX must be reverse DNS: lowercase letters, digits, _ and dots (got "${prefix}")`);
  }
  const quoted = `"${PLACEHOLDER}"`;
  const count = source.split(quoted).length - 1;
  if (count !== 1) throw new Error(`expected ${quoted} exactly once in the built code, found ${count}`);
  return source.replace(quoted, `"${prefix}"`);
}

if (import.meta.main) {
  const prefix = process.env.NTLMAC_PREFIX;
  if (prefix) {
    const file = join(import.meta.dirname, "../dist/logic.js");
    writeFileSync(file, applyPrefix(readFileSync(file, "utf8"), prefix));
    console.log(`native host: ${prefix}`);
  }
}
