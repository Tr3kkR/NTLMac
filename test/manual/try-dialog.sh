#!/bin/sh
# Manual check of the credential dialog through the real flow, with test data only:
#   native host -> launchd agent -> credential_missing -> enrol dialog
#   -> one Kerberos AS exchange against the throwaway KDC (test/kdc) -> stored
#   then a rejected retry -> "Intranet sign-in paused" dialog.
#
# Changes your login session briefly: bootstraps a throwaway LaunchAgent
# (com.example.ntlmac.agent.test.dialog-<pid>, plist in a temp dir) and boots it out on
# exit. Puts the real dialog on screen. Needs Docker. Never touches the real Keychain:
# the credential goes to a file in the temp dir (DEBUG-only override).
#
# Test account only: CORP\jbloggs / Passw0rd!. Try a wrong password first to see the
# inline error; the KDC log at the end should show one PREAUTH_FAILED per wrong submission.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
"$ROOT/agent/scripts/make-app.sh" debug >/dev/null 2>&1
APP="$ROOT/agent/.build/debug/NTLMac.app"
AGENT="$APP/Contents/MacOS/NTLMacAgent"
NMH="$APP/Contents/MacOS/ntlmac-nmh"
GUI="gui/$(id -u)"
LABEL="com.example.ntlmac.agent.test.dialog-$$"
KDC="ntlmac-kdc-dialog-$$"
RUN=$(mktemp -d -t ntlmac-dialog)
designated() { codesign -d -r- "$1" 2>&1 | sed -n 's/.*designated => //p'; }

cleanup() {
  launchctl bootout "$GUI/$LABEL" 2>/dev/null || true
  docker stop "$KDC" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

docker build -q -t ntlmac-test-kdc "$ROOT/test/kdc" >/dev/null
docker run -d --rm --name "$KDC" -p 127.0.0.1:18888:88/tcp ntlmac-test-kdc >/dev/null

cat > "$RUN/config.json" <<EOF
{"enabled": true, "killDate": "2030-01-01T00:00:00Z", "realm": "CORP.EXAMPLE", "netbiosDomain": "CORP",
 "rules": [{"id": "corp", "pattern": "*.corp.example"}]}
EOF
python3 - "$RUN/agent.plist" <<EOF
import plistlib, sys
plistlib.dump({
    "Label": "$LABEL",
    "ProgramArguments": ["$AGENT"],
    "MachServices": {"$LABEL": True},
    "RunAtLoad": True,
    "KeepAlive": False,
    "StandardErrorPath": "$RUN/agent.log",
    "EnvironmentVariables": {
        "NTLMAC_MACH_SERVICE": "$LABEL",
        "NTLMAC_SHIM_REQUIREMENT": '''$(designated "$NMH")''',
        "NTLMAC_CONFIG": "$RUN/config.json",
        "NTLMAC_TEST_CREDENTIAL_FILE": "$RUN/credential",
        "NTLMAC_TELEMETRY_DIR": "$RUN/telemetry",
        "NTLMAC_SUSPECT_LATCH_FILE": "$RUN/credential-suspect",
        "KRB5_CONFIG": "$ROOT/test/kdc/client-krb5.conf",
    },
}, open(sys.argv[1], "wb"))
EOF
launchctl bootstrap "$GUI" "$RUN/agent.plist"
i=0; until grep -q "started" "$RUN/agent.log" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -lt 40 ] || { cat "$RUN/agent.log"; exit 1; }; sleep 0.25
done

# One native-messaging request per call, through the real shim; prints the decision.
ask() {
  python3 -c '
import json, struct, sys, time
m = json.dumps({"id": 1, "type": "auth", "request": {"requestId": sys.argv[1], "host": "app.corp.example",
    "port": 443, "urlScheme": "https", "authScheme": "ntlm", "isProxy": False}}).encode()
sys.stdout.buffer.write(struct.pack("<I", len(m)) + m); sys.stdout.flush()
time.sleep(2)  # the shim stops at EOF, as when the browser closes the port' "$1" |
    NTLMAC_MACH_SERVICE="$LABEL" NTLMAC_AGENT_REQUIREMENT="$(designated "$AGENT")" "$NMH" 2>/dev/null |
    python3 -c '
import json, sys
d = sys.stdin.buffer.read()[4:]
r = json.loads(d) if d else {}
print("  agent:", r.get("action"), r.get("outcome") or ("(credential supplied)" if r.get("password") else ""))'
}

# Waits (up to 5 min) for the n-th dialog outcome: stored or dismissed.
await_dialog() {
  i=0; until [ "$(grep -cE 'dialog: credential validated and stored|dialog dismissed' "$RUN/agent.log")" -ge "$1" ]; do
    i=$((i + 1)); [ "$i" -lt 1200 ] || { echo "   timed out waiting for the dialog"; return 0; }; sleep 0.25
  done
  echo "   dialog: $(grep -oE 'dialog: credential validated and stored|dialog dismissed' "$RUN/agent.log" | sed -n "$1p")"
}

echo "1. No credential yet: the enrol dialog should appear. Try a wrong password, then jbloggs / Passw0rd!."
ask n:1
await_dialog 1
echo "   stored account: $(cut -d: -f1 "$RUN/credential" 2>/dev/null || echo '(none)')"

echo "2. A request is answered, then challenged again (the DC rejected it): 'Intranet sign-in paused'."
ask n:2
ask n:2
await_dialog 2

echo "--- agent log"
cat "$RUN/agent.log"
echo "--- KDC (one PREAUTH_FAILED per wrong password submitted, nothing else)"
docker logs "$KDC" 2>&1 | grep -oE "(NEEDED_PREAUTH|ISSUE|PREAUTH_FAILED|CLIENT_NOT_FOUND)[^,]*" || true
