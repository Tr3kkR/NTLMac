#!/bin/sh
# Builds NTLMac.app from the Swift package: Contents/MacOS/NTLMacAgent (main executable)
# and Contents/MacOS/ntlmac-nmh (native host), with packaging/app/Info.plist.
#
# Usage: [SIGN_IDENTITY=<identity>] agent/scripts/make-app.sh [debug|release]
#   -> agent/.build/<config>/NTLMac.app   (release is universal: arm64 + x86_64)
#
# Signs ad hoc by default, which is enough to run it locally (the e2e suites use debug
# overrides instead of a team). With SIGN_IDENTITY (a Developer ID Application identity
# for distribution, or an Apple Development one for local proofs) both executables get
# the hardened runtime and a secure timestamp, and the agent gets
# packaging/app/NTLMacAgent.entitlements with the identity's team ID substituted. No
# provisioning profile: a team-prefixed keychain-access-groups entry doesn't need one.
# Each executable is signed with the identifier the other side's requirement expects
# (CodeSigningPolicy).
set -eu
cd "$(dirname "$0")/.."

config="${1:-debug}"
identity="${SIGN_IDENTITY:--}"
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
sed "s/__VERSION__/$version/g" ../packaging/app/Info.plist > "$app/Contents/Info.plist"
plutil -lint -s "$app/Contents/Info.plist"
cp "$bin/NTLMacAgent" "$bin/ntlmac-nmh" "$app/Contents/MacOS/"

# Inside out: the nested helper first, then the bundle (which signs its main executable).
if [ "$identity" = "-" ]; then
  codesign --force --sign - --identifier com.example.ntlmac.nmh "$app/Contents/MacOS/ntlmac-nmh"
  codesign --force --sign - "$app"
else
  codesign --force --sign "$identity" --options runtime --timestamp \
    --identifier com.example.ntlmac.nmh "$app/Contents/MacOS/ntlmac-nmh"
  # The team comes from the signature just made, so it can't disagree with the identity.
  team=$(codesign -dv "$app/Contents/MacOS/ntlmac-nmh" 2>&1 | sed -n 's/^TeamIdentifier=//p')
  case "$team" in
    [A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]) ;;
    *) echo "SIGN_IDENTITY has no team ID (got '$team')" >&2; exit 1 ;;
  esac
  entitlements=$(mktemp -t ntlmac-entitlements)
  trap 'rm -f "$entitlements"' EXIT
  sed "s/__TEAM_ID__/$team/g" ../packaging/app/NTLMacAgent.entitlements > "$entitlements"
  plutil -lint -s "$entitlements"
  codesign --force --sign "$identity" --options runtime --timestamp --entitlements "$entitlements" "$app"
fi
codesign --verify --strict --deep "$app"
echo "$app"
