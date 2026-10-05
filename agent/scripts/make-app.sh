#!/bin/sh
# Builds NTLMac.app from the Swift package: Contents/MacOS/NTLMacAgent (main executable)
# and Contents/MacOS/ntlmac-nmh (native host), with packaging/app/Info.plist.
#
# Usage: [SIGN_IDENTITY=<identity> [PROVISIONING_PROFILE=<file>]] [NTLMAC_PREFIX=<reverse DNS>]
#        agent/scripts/make-app.sh [debug|release]
#   -> agent/.build/<config>/NTLMac.app   (release is universal: arm64 + x86_64)
#
# NTLMAC_PREFIX (default com.devnull.ntlmac) replaces com.devnull.ntlmac in the bundle ID,
# the signing identifiers and the Keychain group. The binaries read it back from their own
# signing identifiers (NTLMacIdentity).
#
# Signs ad hoc by default, which is enough to run it locally (the e2e suites use debug
# overrides instead of a team). With SIGN_IDENTITY (a Developer ID Application identity
# for distribution, or an Apple Development one for local proofs) both executables get
# the hardened runtime and a secure timestamp, and the agent gets
# packaging/app/NTLMacAgent.entitlements with the identity's team ID substituted.
#
# PROVISIONING_PROFILE: keychain-access-groups is a restricted entitlement that Apple
# documents as needing a profile (TN3125, TN3137). It worked without one in our tests
# (development certificate, macOS 26.5), but don't ship on that. For distribution, pass the
# Developer ID profile for App ID <team>.<prefix>.agent: it is checked against the team, App
# ID and Keychain group, embedded as Contents/embedded.provisionprofile, and the agent then
# also claims the application-identifier and team-identifier entitlements.
#
# Each executable is signed with the identifier the other side's requirement expects
# (CodeSigningPolicy).
set -eu
cd "$(dirname "$0")/.."

config="${1:-debug}"
identity="${SIGN_IDENTITY:--}"
prefix="${NTLMAC_PREFIX:-com.devnull.ntlmac}"
# As NTLMacIdentity: 2+ labels of [a-z0-9_] (requirement strings, native host names).
printf '%s' "$prefix" | grep -Eqx '[a-z0-9_]+(\.[a-z0-9_]+)+' \
  || { echo "NTLMAC_PREFIX must be reverse DNS: lowercase letters, digits, _ and dots" >&2; exit 64; }
version=$(sed -n 's/^let version = "\(.*\)"$/\1/p' Sources/NTLMacAgent/main.swift)
[ -n "$version" ] || { echo "cannot read the version from main.swift" >&2; exit 1; }

case "$config" in
  debug) build="swift build -c debug" ;;
  release) build="swift build -c release --arch arm64 --arch x86_64" ;;
  *) echo "usage: $0 [debug|release]" >&2; exit 64 ;;
esac
$build >/dev/null
bin=$($build --show-bin-path)
app=".build/$config/NTLMac.app"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
sed -e "s/__VERSION__/$version/g" -e "s/com\.devnull\.ntlmac/$prefix/g" ../packaging/app/Info.plist > "$app/Contents/Info.plist"
plutil -lint -s "$app/Contents/Info.plist"
cp "$bin/NTLMacAgent" "$bin/ntlmac-nmh" "$app/Contents/MacOS/"

# Inside out: the nested helper first, then the bundle (which signs its main executable).
profile="${PROVISIONING_PROFILE:-}"
if [ -n "$profile" ] && [ "$identity" = "-" ]; then
  echo "PROVISIONING_PROFILE needs SIGN_IDENTITY" >&2; exit 64
fi
if [ "$identity" = "-" ]; then
  codesign --force --sign - --identifier "$prefix.nmh" "$app/Contents/MacOS/ntlmac-nmh"
  codesign --force --sign - "$app"
else
  codesign --force --sign "$identity" --options runtime --timestamp \
    --identifier "$prefix.nmh" "$app/Contents/MacOS/ntlmac-nmh"
  # The team comes from the signature just made, so it can't disagree with the identity.
  team=$(codesign -dv "$app/Contents/MacOS/ntlmac-nmh" 2>&1 | sed -n 's/^TeamIdentifier=//p')
  case "$team" in
    [A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]) ;;
    *) echo "SIGN_IDENTITY has no team ID (got '$team')" >&2; exit 1 ;;
  esac
  entitlements=$(mktemp -t ntlmac-entitlements)
  trap 'rm -f "$entitlements"' EXIT
  sed -e "s/__TEAM_ID__/$team/g" -e "s/com\.devnull\.ntlmac/$prefix/g" ../packaging/app/NTLMacAgent.entitlements > "$entitlements"
  if [ -n "$profile" ]; then
    # The profile must authorise exactly what the agent claims, or AMFI kills it at launch.
    decoded=$(mktemp -t ntlmac-profile)
    trap 'rm -f "$entitlements" "$decoded"' EXIT
    security cms -D -i "$profile" > "$decoded" 2>/dev/null || { echo "PROVISIONING_PROFILE is not a provisioning profile" >&2; exit 65; }
    python3 - "$decoded" "$team" "$prefix" <<'PY' || exit 65
import plistlib, sys
p, team, prefix = plistlib.load(open(sys.argv[1], "rb")), sys.argv[2], sys.argv[3]
e = p.get("Entitlements", {})
def allows(pattern, value):
    return pattern == value or (pattern.endswith("*") and value.startswith(pattern[:-1]))
problems = []
if team not in p.get("TeamIdentifier", []):
    problems.append(f"profile is for team {p.get('TeamIdentifier')}, not {team}")
if not allows(e.get("com.apple.application-identifier", ""), f"{team}.{prefix}.agent"):
    problems.append(f"profile App ID {e.get('com.apple.application-identifier')!r} doesn't cover {team}.{prefix}.agent")
if not any(allows(g, f"{team}.{prefix}") for g in e.get("keychain-access-groups", [])):
    problems.append(f"profile doesn't authorise keychain group {team}.{prefix}")
for problem in problems:
    print("PROVISIONING_PROFILE:", problem, file=sys.stderr)
sys.exit(1 if problems else 0)
PY
    cp "$profile" "$app/Contents/embedded.provisionprofile"
    /usr/libexec/PlistBuddy -c "Add :com.apple.application-identifier string $team.$prefix.agent" \
      -c "Add :com.apple.developer.team-identifier string $team" "$entitlements" >/dev/null
  fi
  plutil -lint -s "$entitlements"
  codesign --force --sign "$identity" --options runtime --timestamp --entitlements "$entitlements" "$app"
fi
codesign --verify --strict --deep "$app"
echo "$app"
