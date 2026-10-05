#!/bin/sh
# Signed end-to-end proof, with a real team identity (manual; test account only).
#
#   SIGN_IDENTITY=<identity with a team ID> [NTLMAC_PREFIX=<reverse DNS>] test/manual/signed-proof.sh
#
# NTLMAC_PREFIX (default com.example.ntlmac) is passed to make-app.sh; every name below
# (<prefix>.agent, the Keychain service and group, the data folder) follows it.
#
# A. Release NTLMac.app, signed, as a throwaway LaunchAgent on the real Mach service
#    (<prefix>.agent; nothing else may be serving it). No profile, so the agent
#    fails closed (config_invalid) but answers:
#    - the signed shim gets that answer over XPC;
#    - an ad-hoc shim, and a team-signed impostor with another identifier, are rejected
#      before the agent's handler runs (agent_unavailable, no request in the agent log).
# B. Debug NTLMac.app, signed (debug only for a private Mach service, a test config and
#    a temp latch/telemetry folder; no requirement or credential overrides), against the
#    throwaway KDC (test/kdc). Puts ONE enrol dialog on screen: enter jbloggs / Passw0rd!.
#    - the credential is validated and stored in the real data-protection Keychain;
#    - the next request is supplied from it;
#    - `security`, an ad-hoc process and a team-signed process without the entitlement
#      can't read it; a team-signed process with the entitlement can (by design);
#    - NTLMacAgent --remove-user-data (what uninstall.sh runs) deletes it.
#
# Changes your login session briefly: bootstraps <prefix>.agent.test.signed-* LaunchAgents
# and boots them out on exit; writes, then deletes, one Keychain item.
set -eu
: "${SIGN_IDENTITY:?set SIGN_IDENTITY to a code-signing identity with a team ID}"
PREFIX="${NTLMAC_PREFIX:-com.example.ntlmac}"
export NTLMAC_PREFIX="$PREFIX"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
RUN=$(mktemp -d -t ntlmac-signed)
GUI="gui/$(id -u)"
SERVICE="$PREFIX.agent"
CREDENTIAL="$PREFIX.credential"
LABEL_A="$PREFIX.agent.test.signed-a-$$"
LABEL_B="$PREFIX.agent.test.signed-b-$$"
KDC="ntlmac-kdc-signed-$$"
fail=0
pass() { echo "  ok   $1"; }
flunk() { echo "  FAIL $1"; fail=1; }
expect() { # description, expected, actual
  if [ "$2" = "$3" ]; then pass "$1 ($3)"; else flunk "$1: expected '$2', got '$3'"; fi
}

# shellcheck disable=SC2329 # runs from the trap
cleanup() {
  launchctl bootout "$GUI/$LABEL_A" 2>/dev/null || true
  launchctl bootout "$GUI/$LABEL_B" 2>/dev/null || true
  docker stop "$KDC" >/dev/null 2>&1 || true
  # Never leave the test credential behind.
  if [ -x "${DEBUG_AGENT:-}" ] && [ "$("$RUN/probe-entitled" 2>/dev/null)" != "status=-25300" ]; then
    NTLMAC_SUSPECT_LATCH_FILE="$RUN/b/credential-suspect" NTLMAC_TELEMETRY_DIR="$RUN/b/telemetry" \
      "$DEBUG_AGENT" --remove-user-data 2>/dev/null || echo "WARNING: test Keychain item may remain"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if launchctl print "$GUI" 2>/dev/null | grep -qF "\"$SERVICE\""; then
  echo "something already serves $SERVICE in $GUI; not touching it" >&2; exit 1
fi

echo "Building and signing"
"$ROOT/agent/scripts/make-app.sh" release >/dev/null 2>&1
"$ROOT/agent/scripts/make-app.sh" debug >/dev/null 2>&1
RELEASE="$ROOT/agent/.build/release/NTLMac.app/Contents/MacOS"
DEBUG="$ROOT/agent/.build/debug/NTLMac.app/Contents/MacOS"
DEBUG_AGENT="$DEBUG/NTLMacAgent"
ADHOC_SHIM="$ROOT/agent/.build/debug/ntlmac-nmh" # the bare, linker-signed build
TEAM=$(codesign -dv "$RELEASE/NTLMacAgent" 2>&1 | sed -n 's/^TeamIdentifier=//p')
GROUP="$TEAM.$PREFIX"
AGENT_REQ="anchor apple generic and certificate leaf[subject.OU] = \"$TEAM\" and identifier \"$SERVICE\""
cp "$RELEASE/ntlmac-nmh" "$RUN/impostor"
codesign -f -s "$SIGN_IDENTITY" -o runtime -i "$PREFIX.impostor" "$RUN/impostor" 2>/dev/null
swiftc -O "$ROOT/test/manual/keychain-probe.swift" -o "$RUN/probe-adhoc" 2>/dev/null
cp "$RUN/probe-adhoc" "$RUN/probe-team"
codesign -f -s "$SIGN_IDENTITY" -o runtime "$RUN/probe-team" 2>/dev/null
cp "$RUN/probe-adhoc" "$RUN/probe-entitled-bin"
sed -e "s/__TEAM_ID__/$TEAM/" -e "s/com\.example\.ntlmac/$PREFIX/g" "$ROOT/packaging/app/NTLMacAgent.entitlements" > "$RUN/entitlements.plist"
codesign -f -s "$SIGN_IDENTITY" -o runtime --entitlements "$RUN/entitlements.plist" "$RUN/probe-entitled-bin" 2>/dev/null
printf '#!/bin/sh\nexec "%s" "%s" "%s"\n' "$RUN/probe-entitled-bin" "$CREDENTIAL" "$GROUP" > "$RUN/probe-entitled"
chmod +x "$RUN/probe-entitled"
echo "  team $TEAM, Mach service $SERVICE, access group $GROUP"

# launchd plist: label, program, log, then KEY=VALUE environment pairs.
agent_plist() {
  python3 - "$@" <<'PY'
import plistlib, sys
out, label, program, service, log, *env = sys.argv[1:]
plistlib.dump({"Label": label, "ProgramArguments": [program], "MachServices": {service: True},
    "RunAtLoad": True, "KeepAlive": False, "StandardErrorPath": log,
    "EnvironmentVariables": dict(e.split("=", 1) for e in env)}, open(out, "wb"))
PY
}
await_start() {
  i=0; until grep -q "started" "$1" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -lt 40 ] || { cat "$1"; exit 1; }; sleep 0.25
  done
}
# One native-messaging request through a shim; prints the action and outcome.
ask() { # requestId, shim, [KEY=VALUE env...]
  id=$1; shim=$2; shift 2
  python3 -c '
import json, struct, sys, time
m = json.dumps({"id": 1, "type": "auth", "request": {"requestId": sys.argv[1], "host": "app.corp.example",
    "port": 443, "urlScheme": "https", "authScheme": "ntlm", "isProxy": False}}).encode()
sys.stdout.buffer.write(struct.pack("<I", len(m)) + m); sys.stdout.flush()
time.sleep(2)  # the shim stops at EOF' "$id" | env "$@" "$shim" 2>/dev/null | python3 -c '
import json, sys
d = sys.stdin.buffer.read()[4:]
r = json.loads(d) if d else {}
print(r.get("action"), r.get("outcome") or ("supplied" if r.get("password") else ""))'
}

echo "A. Signed release bundle on the real Mach service"
mkdir -p "$RUN/a"
agent_plist "$RUN/a/agent.plist" "$LABEL_A" "$RELEASE/NTLMacAgent" "$SERVICE" "$RUN/a/agent.log"
launchctl bootstrap "$GUI" "$RUN/a/agent.plist"
await_start "$RUN/a/agent.log"
expect "signed shim -> agent round trip" "decline config_invalid" "$(ask a:1 "$RELEASE/ntlmac-nmh")"
expect "ad-hoc shim is rejected" "decline agent_unavailable" \
  "$(ask a:2 "$ADHOC_SHIM" NTLMAC_AGENT_REQUIREMENT="$AGENT_REQ")"
expect "team-signed impostor is rejected" "decline agent_unavailable" "$(ask a:3 "$RUN/impostor")"
expect "agent handled only the signed shim's request" "a:1" \
  "$(grep -oE 'request a:[0-9]+' "$RUN/a/agent.log" | sed 's/request //' | tr '\n' ' ' | sed 's/ $//')"
launchctl bootout "$GUI/$LABEL_A"
"$RELEASE/NTLMacAgent" --remove-user-data 2>/dev/null
expect "agent listened on $SERVICE" "yes" "$(grep -qF "service=$SERVICE " "$RUN/a/agent.log" && echo yes || echo no)"
expect "release agent's folder removed" "absent" \
  "$([ -e "$HOME/Library/Application Support/$PREFIX" ] && echo present || echo absent)"

echo "B. Signed debug bundle, real Keychain, test KDC"
expect "no test item before" "status=-25300" "$("$RUN/probe-entitled")"
docker build -q -t ntlmac-test-kdc "$ROOT/test/kdc" >/dev/null
docker run -d --rm --name "$KDC" -p 127.0.0.1:18888:88/tcp ntlmac-test-kdc >/dev/null
mkdir -p "$RUN/b"
cat > "$RUN/b/config.json" <<JSON
{"enabled": true, "killDate": "2030-01-01T00:00:00Z", "realm": "CORP.EXAMPLE", "netbiosDomain": "CORP",
 "rules": [{"id": "corp", "pattern": "*.corp.example"}]}
JSON
agent_plist "$RUN/b/agent.plist" "$LABEL_B" "$DEBUG_AGENT" "$LABEL_B" "$RUN/b/agent.log" \
  NTLMAC_MACH_SERVICE="$LABEL_B" NTLMAC_CONFIG="$RUN/b/config.json" \
  NTLMAC_TELEMETRY_DIR="$RUN/b/telemetry" NTLMAC_SUSPECT_LATCH_FILE="$RUN/b/credential-suspect" \
  KRB5_CONFIG="$ROOT/test/kdc/client-krb5.conf"
launchctl bootstrap "$GUI" "$RUN/b/agent.plist"
await_start "$RUN/b/agent.log"
echo "  The enrol dialog should appear now: enter jbloggs / Passw0rd! (waits up to 5 min)."
expect "first request: no credential yet" "decline credential_missing" \
  "$(ask b:1 "$DEBUG/ntlmac-nmh" NTLMAC_MACH_SERVICE="$LABEL_B")"
i=0; until grep -q 'dialog: credential validated and stored\|dialog dismissed' "$RUN/b/agent.log"; do
  i=$((i + 1)); [ "$i" -lt 1200 ] || break; sleep 0.25
done
expect "dialog stored the credential" "stored" \
  "$(grep -q 'dialog: credential validated and stored' "$RUN/b/agent.log" && echo stored || echo "not stored")"
expect "next request supplied from the Keychain" "supply supplied" \
  "$(ask b:2 "$DEBUG/ntlmac-nmh" NTLMAC_MACH_SERVICE="$LABEL_B")"
expect "item is in the team group" "status=0 account=jbloggs" "$("$RUN/probe-entitled")"
security find-generic-password -s "$CREDENTIAL" >/dev/null 2>&1 && s=found || s="not found"
expect "security(1) can't see it" "not found" "$s"
expect "ad-hoc process can't use the group" "status=-34018" "$("$RUN/probe-adhoc" "$CREDENTIAL" "$GROUP")"
expect "ad-hoc process can't find it" "status=-25300" "$("$RUN/probe-adhoc" "$CREDENTIAL" -)"
expect "team-signed, unentitled process can't use the group" "status=-34018" "$("$RUN/probe-team" "$CREDENTIAL" "$GROUP")"
expect "team-signed, unentitled process can't find it" "status=-25300" "$("$RUN/probe-team" "$CREDENTIAL" -)"
launchctl bootout "$GUI/$LABEL_B"
NTLMAC_SUSPECT_LATCH_FILE="$RUN/b/credential-suspect" NTLMAC_TELEMETRY_DIR="$RUN/b/telemetry" \
  "$DEBUG_AGENT" --remove-user-data 2>/dev/null && r=0 || r=$?
expect "--remove-user-data succeeds" 0 "$r"
expect "item deleted" "status=-25300" "$("$RUN/probe-entitled")"

echo "--- agent B log"
cat "$RUN/b/agent.log"
echo "--- KDC"
docker logs "$KDC" 2>&1 | grep -oE "(NEEDED_PREAUTH|ISSUE|PREAUTH_FAILED|CLIENT_NOT_FOUND)[^,]*" || true
[ "$fail" = 0 ] && echo "OK: signed proof passed" || echo "FAILED"
exit "$fail"
