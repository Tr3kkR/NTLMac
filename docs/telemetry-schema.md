# NTLMac telemetry schema v1

NTLMac pushes **OTLP/HTTP JSON metrics** (delta temporality, every 5 min) to the
OpenTelemetry Collector gateway (`gateway/otel-collector.yaml`). The gateway forwards to
Splunk today and ClickHouse later. The schema below is the contract with Cyber's
dashboards; changing it means bumping `ntlmac.schema`.

Encoder: `agent/Sources/NTLMacCore/Telemetry.swift`. Validated against
otelcol-contrib 0.161.0.

## Resource attributes

| Attribute | Example | Notes |
|---|---|---|
| `service.name` | `ntlmac` | Gateway drops any other service. |
| `service.version` | `0.1.0` | |
| `host.id` | `9f2c…` (64 hex) | SHA-256 of `salt:serial`. Salt held in the Jamf profile. Never the raw serial. |
| `os.type` / `os.version` | `darwin` / `26.0` | |
| `ntlmac.schema` | `1` | |

## Metrics

| Metric | Type | Attributes |
|---|---|---|
| `ntlmac.auth.requests` | Sum, delta, monotonic | `app.host`, `allowlist.rule_id`, `enduser.id`, `outcome` |
| `ntlmac.credential.prompts` | Sum, delta, monotonic | `reason`, `enduser.id` |
| `ntlmac.breaker.trips` | Sum, delta, monotonic | `app.host`, `enduser.id` |
| `ntlmac.credential.state` | Gauge (always sent) | `state` ∈ `ok`, `suspect`, `missing` |

`enduser.id` is the sAMAccountName. Per-user data needs DPO and works-council approval
for each jurisdiction before the pilot. Any pipeline feeding a Prometheus-style TSDB must
apply `attributes/strip_user`.

`app.host` is reported **only for hosts that matched an allowlist rule**. Any other host
is reported as `(unlisted)`, so telemetry never records browsing to arbitrary sites.
(Deferred: an opt-in "discovery suffix" list to surface internal NTLM apps that are
missing from the allowlist.)

### `outcome` values

| Value | Meaning |
|---|---|
| `supplied` | Credential handed to the browser. |
| `not_allowlisted` | Host matched no rule, or matched a deny pattern. |
| `http_blocked` | Plain HTTP (or other non-HTTPS scheme) without an unexpired exception. |
| `not_ntlm` | Basic/Digest/Negotiate challenge. NTLMac only answers NTLM. |
| `proxy_ignored` | Proxy challenge. Never answered. |
| `retry_cancelled` | Second challenge for a request we already answered, meaning the DC rejected the password. Latches `suspect`. |
| `suspect_blocked` | Declined because the credential is suspect (after a retry or an `ADPasswordChanged` notification). |
| `rate_limited` | More than 30 supplies to one host in 60 s. |
| `credential_missing` | User hasn't enrolled. |
| `killswitch` | `enabled=false` or past `killDate`. |
| `config_invalid` | Managed profile missing or malformed. Fails closed. |
| `agent_unavailable` | Extension could not reach the agent. |

### `reason` values (prompts)
`enrol`, `ad_password_changed`, `retry_rejected`, `validation_failed`.

## Useful questions this answers
- **Migration backlog:** `supplied` counts and distinct `enduser.id` per `app.host`, ranked by usage.
- **App migrated?** Its `app.host` stops appearing; then remove its rule.
- **Lockout risk:** `ntlmac.breaker.trips` by user and host. Devices stuck in `suspect`.
- **Sunset readiness:** total `supplied` trending to zero.
