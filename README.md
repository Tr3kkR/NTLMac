# NTLMac

Seamless NTLM sign-in for managed Macs, as a time-boxed bridge until Cyber's programme
moves the remaining NTLM-only intranet apps to OIDC/Entra.

On Windows the LSA answers NTLM challenges silently. On a Mac nothing holds the AD
password, so every NTLM site prompts. NTLMac adds three pieces:
- a force-installed **Edge/Chrome extension**, which answers `WWW-Authenticate: NTLM`
  challenges through MV3 `webRequest.onAuthRequired`
- a **native host and agent**, which decide whether the host is allowlisted and supply
  the credential from the login Keychain
- per-user **OTLP telemetry**, which gives Cyber a usage-ranked migration backlog

The browser's own NTLMv2 code (with channel binding) does all the cryptography. NTLMac
contains no NTLM implementation.

**Status: Phase 0 spike.** The core idea is proven end to end in Chromium; see
[docs/spike-findings.md](docs/spike-findings.md).

## Layout

| Path | What |
|---|---|
| `agent/` | Swift package. `NTLMacCore` holds the decision engine and data formats: `Allowlist`, `CircuitBreaker` (lockout guard), `AuthBroker`, `ConfigLoader`, native-messaging codec, OTLP `Telemetry`, plus the agent's parts: `AgentService` (composes them), `CredentialStore` (data-protection Keychain), `PasswordChangeListener` (Darwin notifications), `AgentXPC` (code-signing checks both ways), `TelemetryExporter` (on-disk queue), `SuspectLatch` (persisted lockout latch), `KerberosCredentialValidator` (one AS exchange, via the small `CKerberos` C target), `CredentialPrompt` (the dialog's wording, input checks and inline errors) and the `SignedInUserProvider` boundary. `NTLMacAgent` is the per-user LaunchAgent and shows the enrolment / re-prompt dialog; `ntlmac-nmh` is the native host, a thin shim that forwards to the agent over XPC. Both ship inside `NTLMac.app` (`agent/scripts/make-app.sh`). |
| `extension/` | MV3 extension (TypeScript). `src/logic.ts` is pure and unit-tested; `src/background.ts` wires `onAuthRequired` to the native host. |
| `test/ntlm-server/` | NTLM-only HTTPS test server (pyspnego). Optional EPA enforcement, `/stats` failure counts in place of DC 4625 events. |
| `test/manual/` | `try-dialog.sh`: the real dialog through a throwaway launchd agent and the test KDC (puts windows on screen). |
| `test/kdc/` | Throwaway MIT KDC (Docker) for checking the Kerberos password validation against a real KDC; also the manual procedure against AD. |
| `test/e2e/` | Browser tests: real Chromium, no DevTools, real NTLM handshakes. `spike.test.ts` is the reference; `scenarios.test.ts` covers worker idle termination, agent unavailable, kill switch, plain HTTP and Basic. |
| `gateway/` | OpenTelemetry Collector configs (production → Splunk HEC; local → debug). |
| `packaging/` | `NTLMac.app` Info.plist, native-messaging manifest, LaunchAgent plist and Jamf profile templates (`com.example.ntlmac` prefs, Chrome/Edge policy). |
| `docs/` | Telemetry schema contract, spike findings. |

Identifiers (native host name, preference domain, Keychain service) use the placeholder
prefix `com.example.ntlmac`. Substitute your organisation's reverse-DNS prefix before
packaging.

## Running the tests

```sh
# Swift core (170 tests)
cd agent && swift test

# Optional: the Kerberos validator against a real KDC (Docker), see test/kdc/README.md

# NTLMac.app (agent + native host, ad-hoc signed): agent/.build/debug/NTLMac.app
agent/scripts/make-app.sh debug
# Signed (hardened runtime, timestamp, keychain-access-groups for the agent; universal):
SIGN_IDENTITY="Developer ID Application: …" agent/scripts/make-app.sh release

# The credential dialog for real: throwaway LaunchAgent + Docker KDC, test account only.
# Shows the enrolment dialog, then the re-prompt after a rejected retry.
test/manual/try-dialog.sh

# Release binaries contain none of the DEBUG-only test overrides
agent/scripts/check-release-overrides.sh

# Extension (build + 5 unit tests)
cd extension && npm install && npm run build && npm test

# NTLM-only test server self-test
cd test/ntlm-server && python3 -m venv .venv && .venv/bin/pip install pyspnego \
  && printf 'CORP:jbloggs:Passw0rd!\n' > users.txt && ./make-cert.sh \
  && .venv/bin/python -m unittest selftest

# Browser end-to-end (needs the three steps above plus `swift build` in agent/).
# `npm test` runs both suites; or `npm run test:spike` / `npm run test:scenarios`.
cd test/e2e && npm install && npx playwright install chromium && npm test

# Each browser session runs the debug NTLMacAgent as a throwaway LaunchAgent in your GUI
# session (`launchctl bootstrap gui/$UID`, plist in a temp dir) and boots it out
# afterwards. Debug builds are ad-hoc signed, so DEBUG-only overrides pin each side to the
# other's cdhash and give the agent a JSON config and a credential file.
#
# The browser suites put Chrome's own sign-in dialog on screen (possibly on another
# Space) whenever a scenario falls back to it. Don't type into it. Never drive these tests
# through Playwright/Puppeteer/CDP: a DevTools-controlled page fails NTLM outright.

# Telemetry against a real collector
docker run --rm -p 4318:4318 \
  -v "$PWD/gateway/otel-collector.local.yaml:/etc/otelcol-contrib/config.yaml" \
  otel/opentelemetry-collector-contrib:latest
```

## Safety properties (enforced in `AuthBroker`, covered by tests)

- **NTLM only.** Never answers Basic/Digest (which would send the password itself),
  Negotiate, or proxy challenges.
- **Allowlist only.** Exact hosts or `*.suffix` patterns of at least two labels. Deny
  patterns win. Non-ASCII hostnames are rejected.
- **HTTPS only**, except risk-accepted HTTP hosts listed with an expiry date.
- **Lockout guard.** At most one credential per browser request. A second challenge for
  the same request latches the credential as `suspect` everywhere until a new password is
  validated. The latch survives agent restarts (a marker file next to the telemetry
  queue). Rate-limited per host.
- **One check per typed password.** The dialog validates a new password with exactly one
  Kerberos AS exchange (no retry, no credential cache written) and stores it only if the
  KDC accepts it. Password AutoFill is off in the dialog, so macOS never offers to save
  the AD password in the user's synced Passwords.
- **Signed peers only.** The agent and the shim each require the other to be signed with
  their own team ID (read from their own signature) and the expected identifier. The
  shim sends nothing until the agent has passed that check. Unsigned builds refuse to
  start (agent) or decline everything (shim).
- **Kill switch.** `enabled=false` or a passed `killDate` stops all supply. A missing or
  malformed profile fails closed.
- Passwords never appear in logs, telemetry or response descriptions. Only the URL
  scheme leaves the browser, never paths or queries.
