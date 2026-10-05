#!/bin/sh
# Checks make-app.sh's provisioning-profile handling with forged test profiles (CMS-signed
# plists from a throwaway self-signed certificate; macOS would refuse to launch the result,
# so nothing here runs it). A matching profile is embedded and the agent claims the App ID;
# a profile for another team, App ID or Keychain group is refused (exit 65).
#
#   SIGN_IDENTITY=<identity with a team ID> test/packaging/check-profile.sh
set -eu
: "${SIGN_IDENTITY:?set SIGN_IDENTITY to a code-signing identity with a team ID}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MAKE_APP="$ROOT/agent/scripts/make-app.sh"
APP="$ROOT/agent/.build/debug/NTLMac.app"
WORK=$(mktemp -d -t ntlmac-profile-check)
trap 'rm -rf "$WORK"' EXIT
fail=0
check() { # description, command...
  desc=$1; shift
  if "$@" >/dev/null 2>&1; then echo "ok   $desc"; else echo "FAIL $desc"; fail=1; fi
}

# The team of the identity, from a plain signed build.
"$MAKE_APP" debug >/dev/null 2>&1
TEAM=$(codesign -dv "$APP" 2>&1 | sed -n 's/^TeamIdentifier=//p')
PREFIX=com.devnull.ntlmac
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 1 \
  -subj "/CN=ntlmac forged test profile" 2>/dev/null
profile() { # name, team, app id, keychain group
  python3 -c 'import plistlib, sys; plistlib.dump({"TeamIdentifier": [sys.argv[2]], "Entitlements": {
    "com.apple.application-identifier": sys.argv[3], "keychain-access-groups": [sys.argv[4]]}}, open(sys.argv[1], "wb"))' \
    "$WORK/$1.plist" "$2" "$3" "$4"
  openssl cms -sign -in "$WORK/$1.plist" -signer "$WORK/cert.pem" -inkey "$WORK/key.pem" \
    -outform DER -nodetach -binary -out "$WORK/$1.provisionprofile"
}
profile good "$TEAM" "$TEAM.$PREFIX.agent" "$TEAM.*"
profile wildcard "$TEAM" "$TEAM.*" "$TEAM.$PREFIX"
profile other-team ABCDE12345 "ABCDE12345.$PREFIX.agent" "ABCDE12345.*"
profile other-app "$TEAM" "$TEAM.com.devnull.other" "$TEAM.*"
profile other-group "$TEAM" "$TEAM.$PREFIX.agent" "$TEAM.com.devnull.other"
printf 'not a profile' > "$WORK/junk.provisionprofile"

for p in other-team other-app other-group junk; do
  if PROVISIONING_PROFILE="$WORK/$p.provisionprofile" "$MAKE_APP" debug >/dev/null 2>&1; then rc=0; else rc=$?; fi
  check "refuses $p (exit 65)" test "$rc" = 65
done
check "refuses a profile without SIGN_IDENTITY (exit 64)" sh -c "SIGN_IDENTITY= PROVISIONING_PROFILE='$WORK/good.provisionprofile' '$MAKE_APP' debug; [ \$? = 64 ]"

for p in good wildcard; do
  check "accepts $p" env PROVISIONING_PROFILE="$WORK/$p.provisionprofile" "$MAKE_APP" debug
  check "$p: profile embedded" cmp "$APP/Contents/embedded.provisionprofile" "$WORK/$p.provisionprofile"
  check "$p: bundle signature seals it" codesign --verify --strict --deep "$APP"
  ENT=$(codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -convert json -o - -)
  check "$p: agent claims App ID, team and Keychain group" python3 -c "
import json, sys
e = json.loads(sys.argv[1])
assert e['com.apple.application-identifier'] == '$TEAM.$PREFIX.agent', e
assert e['com.apple.developer.team-identifier'] == '$TEAM', e
assert e['keychain-access-groups'] == ['$TEAM.$PREFIX'], e" "$ENT"
done

# Leave an ordinary signed debug build behind, not one with a forged profile.
"$MAKE_APP" debug >/dev/null 2>&1
check "no profile: nothing embedded, no App ID claimed" sh -c "[ ! -e '$APP/Contents/embedded.provisionprofile' ] && ! codesign -d --entitlements - '$APP' 2>/dev/null | grep -q application-identifier"
[ "$fail" = 0 ] && echo "OK"
exit "$fail"
