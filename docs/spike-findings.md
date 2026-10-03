# Phase 0 spike: findings

Status as of 2026-10-03. The plan is in the grilling-session plan (decisions 1–12).
Items are labelled **Proven** (tested in this repo), **Confirmed** (vendor docs only) or
**Open**.

## (a) Chromium answers server NTLM challenges via the extension: **Proven**

`test/e2e/spike.test.ts` runs Chrome for Testing 153 headless with no DevTools attached,
the unpacked extension and the `ntlmac-nmh` spike host, against the NTLM-only test server:

| Scenario | Result |
|---|---|
| `onAuthRequired` fires for `WWW-Authenticate: NTLM` from an origin server | Yes, `details.scheme == "ntlm"` |
| Silent sign-in to an allowlisted HTTPS site | 401 → NTLM negotiate → NTLM challenge → **200**, no prompt |
| Server enforcing EPA (channel binding required) | **Succeeds**: Chromium's NTLMv2 sends `tls-server-end-point` bindings |
| Stale password | **Exactly 1** failed AUTHENTICATE at the server, host logs `retry_cancelled`, no further attempts |
| Host not on the allowlist | Browser is challenged, host logs `not_allowlisted`, **no** AUTHENTICATE sent |

Lessons for testing:
- **Don't test through Playwright/CDP.** Playwright's DevTools `Fetch.authRequired`
  handling answers 401s before extensions see them. Even with no extension, Playwright's
  Chromium fails NTLM sites with `ERR_INVALID_AUTH_CREDENTIALS`. The harness launches the
  binary directly and uses the server's `/stats` endpoint as the oracle.
- **Pass `--use-mock-keychain`.** Otherwise Chrome for Testing's first launch blocks on a
  "Chrome Safe Storage" Keychain prompt.
- `--dump-dom` never returns once the extension holds a native-messaging port open, so
  don't rely on it.
- **Headless Chrome on macOS shows its HTTP auth prompt as a real window.** It appears on
  the user's screen (seen on another Space), not inside the headless session. Scenarios
  where the extension declines and Chrome falls back to its own prompt (stale password,
  unlisted host) can therefore put sign-in dialogs on the desktop of whoever runs the
  suite. Don't type into them. Run the suite on a machine nobody is using, or find a way
  to suppress the prompt before running it unattended.

### Puppeteer can't drive NTLM tests either (2026-10-03)

The Step 0 control for a Puppeteer suite **failed**. Puppeteer 25.12 launched Chrome for
Testing 154.0.8037.57 headless over `pipe: true`, with **no extension**, and navigated to
the NTLM-only server:
- `page.goto` rejected with `net::ERR_INVALID_AUTH_CREDENTIALS` within about 3 s, instead
  of resolving with a 401.
- The server saw exactly one `GET /` (the 401 challenge), then no NTLM NEGOTIATE and no
  AUTHENTICATE. Chrome gave up on its own without prompting.
- No `Fetch.enable` was sent. Every CDP method was logged; the page-level ones were
  `Network.enable`, `Page.enable`, `Runtime.enable`, `Log.enable`, `Audits.enable`,
  `Performance.enable`, `Emulation.*` and `Page.navigate`. So this is **not** the
  `Fetch.authRequired` interception that broke Playwright: avoiding `page.authenticate()`
  and `setRequestInterception()` isn't enough.
- It also fails with `ignoreDefaultArgs: true` and only `--headless --remote-debugging-pipe`
  plus the test flags, so no Puppeteer default flag causes it.

Direct-spawn Chrome with no DevTools connection doesn't error: it waits on the auth prompt.
So a DevTools-controlled page cancels HTTP auth that has no handler with
`ERR_INVALID_AUTH_CREDENTIALS`, and any CDP-driven harness hides the behaviour under test
(whether the extension, or the browser's fallback prompt, answers the challenge).
**Decision:** keep the direct-spawn harness (`test/e2e/spike.test.ts`) and assert on the
server's `/stats` and the host's stderr decision lines. Not yet tested: whether
`onAuthRequired` still fires in an extension under a CDP-controlled page. It might, but a
suite whose no-extension control fails can't tell a correct fallback from a broken one.
A useful side effect of Puppeteer: it silently detaches from extension service-worker
targets unless `worker()` is called, so it wouldn't have kept the worker alive.

The scenarios planned for the Puppeteer suite (worker idle termination, first navigation
after install, agent unavailable, kill switch, plain HTTP, Basic never answered) still
need testing. They should be added to the direct-spawn harness instead.

## (a′) Startup race for the first navigation: **Open**

With `--load-extension` on a fresh profile, a challenge on the browser's very first
navigation arrives before the service worker has registered its listener. The browser's
own prompt then appears, and in headless mode it hangs. Production uses policy
force-install, where Chromium persists MV3 listeners and wakes the worker, so this
probably doesn't happen there. **To verify on a Jamf test Mac:**
1. Quit Edge or Chrome with an NTLM app tab open, relaunch with session restore on, and
   watch for a prompt.
2. Leave the browser idle for more than 30 s (the worker is terminated), then open an
   NTLM app.

If a prompt appears, mitigation: have the extension keep the native port open (an open
port keeps the worker alive), or add a reload-on-first-wake fallback.

## (b) `app-sso -i <REALM> -j` field names: **Open**
Apple's documentation shows the output as a plist/JSON containing the user, password
expiry and so on, but no field names are documented. Capture real output on a bound
test Mac.

## (c) Kerberos SSO extension notifications: **Confirmed (docs)**, delivery **Open**
Documented in Apple's Kerberos SSO Extension guide:
- `com.apple.KerberosPlugin.ADPasswordChanged`
- `com.apple.KerberosExtension.passwordChangedWithPasswordSync`
- `com.apple.KerberosPlugin.LocalPasswordSynced`
- `com.apple.KerberosPlugin.ConnectionCompleted`
- `com.apple.KerberosPlugin.InternalNetworkAvailable` and `…NotAvailable`
- `com.apple.KerberosExtension.gotNewCredential`

The guide has no `AuthenticationSuccess` or `AuthenticationFailure` notification, so
don't depend on one. Verify delivery with `notifyutil -w <name>` during a real password
change.

## (d) Native host → XPC → agent with Keychain ACL: **Open**
Not built yet. The spike host runs the broker in-process. Release builds read the
credential from a plain Keychain item. `#if DEBUG` builds also accept a credential file
for automated tests.

## (e) OTLP into the SIEM: **Partly proven**
- The NTLMac OTLP/JSON payload is accepted by otelcol-contrib 0.161.0:
  - all 4 metrics are parsed, with delta temporality and the expected attributes
  - payloads with another `service.name` are filtered out
- `gateway/otel-collector.yaml` passes `otelcol validate`.
- **Open:** a Splunk test index via `splunk_hec`, and Jamf SCEP device certificates for
  mTLS.

## Confirmed from vendor docs (not yet exercised)
- MV3 `onAuthRequired` with `asyncBlocking` and `webRequestAuthProvider` works from
  Chrome 108. Policy-installed extensions may also keep `webRequestBlocking`.
- Chrome/Edge `NtlmV2Enabled` defaults to true, and `AuthSchemes` includes `ntlm` by
  default.
- System native-messaging manifest folders:
  - `/Library/Google/Chrome/NativeMessagingHosts/`
  - `/Library/Microsoft/Edge/NativeMessagingHosts/`
- Off-store force-install is allowed on MDM-managed Macs.
- **Edge:** same Chromium code, but `onAuthRequired` with NTLM is untested. Run the e2e
  scenarios against Edge on the test Mac.
