#!/bin/sh
# Checks NTLMac's state on this Mac around a real install of the package (manual; the
# sudo steps are yours). Builds a team-signed, entitled Keychain probe on first use.
#
#   SIGN_IDENTITY=<identity> test/manual/check-install.sh installed  # after sudo installer
#   SIGN_IDENTITY=<identity> test/manual/check-install.sh seed       # test item into the
#                                                                     # agent's group, restart it
#   SIGN_IDENTITY=<identity> test/manual/check-install.sh removed    # after sudo uninstall.sh
#
# Test account only (jbloggs / Passw0rd!). NTLMAC_PREFIX as for the package (default
# com.devnull.ntlmac).
set -eu
: "${SIGN_IDENTITY:?set SIGN_IDENTITY to the identity the package was signed with}"
MODE=${1:?usage: check-install.sh installed|seed|removed}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PREFIX="${NTLMAC_PREFIX:-com.devnull.ntlmac}"
LABEL="$PREFIX.agent"
GUI="gui/$(id -u)"
SUPPORT="/Library/Application Support/NTLMac"
APP="$SUPPORT/NTLMac.app"
FILES="$APP/Contents/MacOS/NTLMacAgent
$APP/Contents/MacOS/ntlmac-nmh
$SUPPORT/uninstall.sh
/Library/LaunchAgents/$LABEL.plist
/Library/Google/Chrome/NativeMessagingHosts/$PREFIX.json
/Library/Microsoft/Edge/NativeMessagingHosts/$PREFIX.json"
fail=0
expect() { # description, expected, actual
  if [ "$2" = "$3" ]; then echo "  ok   $1 ($3)"; else echo "  FAIL $1: expected '$2', got '$3'"; fail=1; fi
}

PROBE_DIR="$ROOT/agent/.build/install-probe"
PROBE="$PROBE_DIR/keychain-probe"
if [ ! -x "$PROBE" ]; then
  mkdir -p "$PROBE_DIR"
  swiftc -O "$ROOT/test/manual/keychain-probe.swift" -o "$PROBE" 2>/dev/null
  team=$(codesign -dv "$APP/Contents/MacOS/NTLMacAgent" 2>&1 | sed -n 's/^TeamIdentifier=//p')
  [ -n "$team" ] || team=$(cd "$ROOT" && SIGN_IDENTITY="$SIGN_IDENTITY" agent/scripts/make-app.sh debug >/dev/null 2>&1 \
    && codesign -dv agent/.build/debug/NTLMac.app 2>&1 | sed -n 's/^TeamIdentifier=//p')
  sed -e "s/__TEAM_ID__/$team/" -e "s/com\.devnull\.ntlmac/$PREFIX/g" "$ROOT/packaging/app/NTLMacAgent.entitlements" > "$PROBE_DIR/entitlements.plist"
  codesign -f -s "$SIGN_IDENTITY" -o runtime --entitlements "$PROBE_DIR/entitlements.plist" "$PROBE" 2>/dev/null
  echo "$team" > "$PROBE_DIR/team"
fi
GROUP="$(cat "$PROBE_DIR/team").$PREFIX"
CREDENTIAL="$PREFIX.credential"
agent_pid() { launchctl print "$GUI/$LABEL" 2>/dev/null | sed -n 's/^[[:space:]]*pid = //p'; }
ask() { # requestId, through the installed shim; prints action and outcome
  python3 -c '
import json, struct, sys, time
m = json.dumps({"id": 1, "type": "auth", "request": {"requestId": sys.argv[1], "host": "app.corp.example",
    "port": 443, "urlScheme": "https", "authScheme": "ntlm", "isProxy": False}}).encode()
sys.stdout.buffer.write(struct.pack("<I", len(m)) + m); sys.stdout.flush()
time.sleep(2)' "$1" | "$APP/Contents/MacOS/ntlmac-nmh" 2>/dev/null | python3 -c '
import json, sys
d = sys.stdin.buffer.read()[4:]
r = json.loads(d) if d else {}
print(r.get("action"), r.get("outcome") or ("supplied" if r.get("password") else ""))'
}

case "$MODE" in
installed)
  while IFS= read -r f; do
    expect "$f" "root:wheel" "$(stat -f %Su:%Sg "$f" 2>/dev/null || echo missing)"
  done <<FILES
$FILES
FILES
  expect "LaunchAgent mode" "-rw-r--r--" "$(stat -f %Sp "/Library/LaunchAgents/$LABEL.plist")"
  expect "receipt" "$PREFIX.pkg" "$(pkgutil --pkg-info "$PREFIX.pkg" 2>/dev/null | sed -n 's/^package-id: //p')"
  expect "app signature" "valid" "$(codesign --verify --strict --deep "$APP" 2>/dev/null && echo valid || echo invalid)"
  expect "agent running in $GUI" "running" "$(launchctl print "$GUI/$LABEL" 2>/dev/null | sed -n 's/^[[:space:]]*state = //p' | head -1)"
  echo "  agent pid: $(agent_pid)"
  expect "installed shim -> installed agent (no profile: fails closed)" "decline config_invalid" "$(ask i:1)"
  ;;
seed)
  expect "test item written into $GROUP" "write status=0" "$("$PROBE" "$CREDENTIAL" "$GROUP" --write-test-item)"
  launchctl kickstart -k "$GUI/$LABEL"
  sleep 2
  expect "restarted agent reads it from the Keychain" "credential=ok" \
    "$(log show --last 1m --style compact --predicate "subsystem == \"$PREFIX\"" 2>/dev/null | grep -o 'credential=[a-z]*' | tail -1)"
  ;;
removed)
  while IFS= read -r f; do
    expect "$f" "absent" "$([ -e "$f" ] && echo present || echo absent)"
  done <<FILES
$FILES
FILES
  expect "app folder" "absent" "$([ -e "$SUPPORT" ] && echo present || echo absent)"
  expect "receipt" "forgotten" "$(pkgutil --pkg-info "$PREFIX.pkg" >/dev/null 2>&1 && echo present || echo forgotten)"
  expect "agent job" "gone" "$(launchctl print "$GUI/$LABEL" >/dev/null 2>&1 && echo loaded || echo gone)"
  expect "user data folder" "absent" "$([ -e "$HOME/Library/Application Support/$PREFIX" ] && echo present || echo absent)"
  expect "Keychain item" "status=-25300" "$("$PROBE" "$CREDENTIAL" "$GROUP")"
  # Folders the package created for a browser that isn't installed must go too; a folder
  # still holding another vendor's files stays.
  for d in /Library/Google/Chrome/NativeMessagingHosts /Library/Microsoft/Edge/NativeMessagingHosts; do
    if [ -d "$d" ] && [ -z "$(find "$d" -mindepth 1 -maxdepth 1)" ]; then state="left empty"; else state="gone or in use"; fi
    expect "$d" "gone or in use" "$state"
  done
  ;;
*) echo "usage: check-install.sh installed|seed|removed" >&2; exit 64 ;;
esac
[ "$fail" = 0 ] && echo "OK: $MODE" || echo "FAILED: $MODE"
exit "$fail"
