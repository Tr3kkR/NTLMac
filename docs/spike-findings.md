# Phase 0 spike: findings

Status as of 2026-10-03. The plan is in the grilling-session plan (decisions 1–12).
Items are labelled **Proven** (tested in this repo), **Confirmed** (vendor docs only) or
**Open**.

## (a) Chromium answers server NTLM challenges via the extension: **Proven**

`test/e2e/spike.test.ts` runs Chrome for Testing 153 headless with no DevTools attached,
the unpacked extension and the `ntlmac-nmh` host, against the NTLM-only test server. Since
2026-10-04 the host is the thin shim and the decision comes from a debug `NTLMacAgent`
running as a throwaway LaunchAgent; results are unchanged:

| Scenario | Result |
|---|---|
| `onAuthRequired` fires for `WWW-Authenticate: NTLM` from an origin server | Yes, `details.scheme == "ntlm"` |
| Silent sign-in to an allowlisted HTTPS site | 401 → NTLM negotiate → NTLM challenge → **200**, no prompt |
| Server enforcing EPA (channel binding required) | **Succeeds**: Chromium's NTLMv2 sends `tls-server-end-point` bindings |
| Stale password | **Exactly 1** failed AUTHENTICATE at the server, host logs `retry_cancelled`, no further attempts |
| Host not on the allowlist | Browser is challenged, host logs `not_allowlisted`, **no** AUTHENTICATE sent |

`test/e2e/scenarios.test.ts` uses the same harness for the rest of the safety properties.
Two full runs gave identical results:

| Scenario | Result |
|---|---|
| Worker idle termination: 45 s idle, then an NTLM challenge | Worker stopped and woken (2 starts logged), **silent sign-in**, no prompt |
| Native host missing (manifest points at a missing binary) | Browser prompt after **~2.1 s** (budget 3 s, `AGENT_TIMEOUT_MS`), no AUTHENTICATE |
| Agent not running (shim finds nothing on its Mach service) | Shim declines `agent_unavailable`; browser prompt after **~2.1 s**, no AUTHENTICATE |
| Kill switch: `enabled: false`, or a past `killDate` | Host logs `killswitch`, no AUTHENTICATE, browser prompt |
| Plain HTTP, no exception | Host logs `http_blocked`, no AUTHENTICATE, browser prompt |
| Plain HTTP with an unexpired `httpExceptions` entry | **Silent sign-in**, no prompt |
| `WWW-Authenticate: Basic` (server `--basic` mode) | No `Authorization: Basic` ever arrives; host never supplies; browser prompt |
| First navigation straight after launch | **Prompt**, host never consulted: the startup race, see (a′). Marked `todo` |

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
  The scenario suite uses this as an oracle: `test/e2e/windows.swift` lists the browser
  process's windows on every Space. Headless Chrome always owns hidden helper windows
  (1×1, 396×88, 396×107, 756×556); the sign-in dialog is the only new one, at 320×252
  (320×272 over plain HTTP). All of them report `onscreen: false`, so a check limited to
  on-screen windows misses the dialog.
- The extension logs `NTLMac: service worker started` on every worker start;
  `--enable-logging=stderr` forwards it, so tests can count idle-termination wakes without
  attaching DevTools to the worker.

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

The scenarios planned for the Puppeteer suite are in the direct-spawn
`test/e2e/scenarios.test.ts` instead (results under (a)).

## (a′) Startup race and worker idle termination: idle **Proven locally**, startup **Open**

**Idle termination is not a problem** (`--load-extension`, Chrome for Testing 153). After
45 s with no events, Chrome had stopped the worker; the next NTLM challenge woke it (a
second `service worker started` line) and the sign-in was silent. Chromium persists the
`onAuthRequired` registration and wakes the worker for it, so no keep-alive is needed.

**The startup race is still there with `--load-extension`.** On a fresh profile, a
challenge on the browser's very first navigation arrives before the service worker has
registered its listener. The browser's own prompt appears within about 1 s and the host
is never consulted (scenario "first navigation straight after launch", marked `todo`).
Puppeteer's CDP install would have avoided `--load-extension`, but CDP breaks NTLM (see
above), so this can't be tested locally with another install path. Production uses policy
force-install, where the extension is already installed before the first navigation, so
the race probably doesn't happen there. **To verify on a Jamf test Mac:**
1. Quit Edge or Chrome with an NTLM app tab open, relaunch with session restore on, and
   watch for a prompt.
2. Leave the browser idle for more than 30 s (the worker is terminated), then open an
   NTLM app. Expected to be fine given the local result above.

If a prompt appears on relaunch, mitigation: a reload-on-first-wake fallback (on worker
start, reload tabs whose last navigation got a 401 from an allowlisted host). Keeping the
native port open wouldn't help here: the worker isn't running yet when the race happens.

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

## (d) Native host → XPC → agent with Keychain ACL: **Proven locally**, ad-hoc and team-signed (Developer ID **Open**)
`NTLMacAgent` runs `AgentService` on a launchd Mach service; `ntlmac-nmh` forwards to
it. Both browser suites pass through a real `launchctl bootstrap gui/$UID` agent, with
each side pinned to the other's cdhash by DEBUG-only overrides (absent from release
binaries: `agent/scripts/check-release-overrides.sh`). Without a Mach service, or
against an agent that fails its requirement, the shim declines `agent_unavailable` in
under 0.3 s.
- **Team ID comes from each binary's own signature**, not from the profile or a build
  setting. The shim reads no config, and a build constant could drift from the actual
  signature. Each side requires the other to carry the same team ID; with none, the agent
  refuses to start and the shim declines everything.
- **A malformed requirement string crashes the process.** `NSXPCConnection` raises an
  Objective-C exception instead of failing, so both binaries compile the requirement
  first (`CodeSigning.validate`).
- **XPC code-signing checks, both ways** (`AgentXPC.swift`): tested with a real
  anonymous `NSXPCListener`. Matching requirements round-trip; a team-ID requirement on
  either side rejects the test process, and the agent's handler never runs.
- **A client-side requirement only guards messages *from* the peer.** Without a
  handshake, an impostor agent received the shim's first request (host names, no
  secrets) before the reply was rejected. The shim now sends a data-free `hello` first
  and sends nothing else until that reply passes the check.
- **Keychain** (`CredentialStore.swift`): the item lives in the data-protection Keychain
  (`WhenUnlockedThisDeviceOnly`, not synchronisable, optional access group). An ad-hoc
  signed process with no `keychain-access-groups` entitlement gets
  `errSecMissingEntitlement` (-34018) when writing. So the agent **must** ship
  team-signed with that entitlement.
- **Provisioning profile: works without, but Apple says it's required.** On macOS 26.5,
  a probe signed with an Apple Development identity, the hardened runtime and
  `keychain-access-groups = <TEAM>.<prefix>`, and no profile, launched and used the group.
  Unentitled and wrong-group copies got -34018. The signed proof and the installed agent
  below also ran without a profile. But Apple documents `keychain-access-groups` as a
  restricted entitlement that "must be authorized by a provisioning profile" (TN3125;
  TN3137 says the same for the data-protection keychain). So that's undocumented
  behaviour that a Developer ID build or a later macOS may not allow. **Ship with an
  embedded Developer ID profile** (`make-app.sh PROVISIONING_PROFILE`, see
  `packaging/pkg/README.md`).

### Signed end to end (`test/manual/signed-proof.sh`, 2026-10-05)
Signed with an Apple Development identity (team-signed, hardened runtime, timestamp),
`NTLMAC_PREFIX=com.devnull.ntlmac` (now the default), test account only:

| Check | Result |
|---|---|
| Release bundle on its real Mach service (`<prefix>.agent`): signed shim → agent | Answered (`config_invalid`: no profile, fails closed) |
| Ad-hoc shim told to trust the agent's team requirement | Rejected: `agent_unavailable`, agent handler never ran |
| Team-signed impostor with another identifier | Rejected the same way |
| Signed debug bundle (team policy, real Keychain), enrol dialog, test KDC | One wrong password = one `PREAUTH_FAILED`, not stored; right one stored |
| Next request | Supplied from the data-protection Keychain |
| `security find-generic-password` | Can't see the item |
| Ad-hoc / team-signed unentitled process, asking for the group | -34018 |
| Same, without naming the group | -25300 (item invisible) |
| Team-signed process **with** the entitlement | Can read it: the boundary is team + entitlement, by design |
| `NTLMacAgent --remove-user-data` (what `uninstall.sh` runs per user) | Item deleted |

### Real install on a development Mac (`test/manual/check-install.sh`, 2026-10-05)
The package was signed with the same identity, using the default prefix `com.devnull.ntlmac`,
and installed with `sudo installer`:

| Step | Result |
|---|---|
| Install | Every file root:wheel, LaunchAgent 644, receipt present, postinstall started the agent; installed shim → agent answers (`config_invalid`, no profile); no `._` files on disk |
| Test item seeded into the agent's group, agent restarted | The release agent reads it (`credential=ok`) |
| Upgrade (same package again) | preinstall stopped the agent, postinstall started a new one (new PID); credential kept |
| `sudo uninstall.sh` | Everything gone, **including the Keychain item** (via `launchctl asuser` + `sudo -u` + `--remove-user-data`) and the receipt |
| Second cycle, after a fix | The uninstaller now also `rmdir`s browser folders the package created (Edge wasn't installed); Chrome's folder, which holds another vendor's host, stays |

Not yet shown: a Developer ID build (no certificate yet), Gatekeeper and notarisation, and
an install through Jamf.

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
