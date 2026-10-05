#!/bin/sh
# Builds NTLMac.app from the Swift package: Contents/MacOS/NTLMacAgent (main executable)
# and Contents/MacOS/ntlmac-nmh (native host), with packaging/app/Info.plist.
#
# Usage: agent/scripts/make-app.sh [debug|release]   -> agent/.build/<config>/NTLMac.app
#
# Signs ad hoc by default, which is enough to run it locally. Set SIGN_IDENTITY to a
# Developer ID Application identity for a real build (packaging adds the hardened runtime,
# entitlements and the provisioning profile; not done yet). Each executable is signed
# with the identifier the other side's requirement expects (CodeSigningPolicy).
set -eu
cd "$(dirname "$0")/.."

config="${1:-debug}"
identity="${SIGN_IDENTITY:--}"
version=$(sed -n 's/^let version = "\(.*\)"$/\1/p' Sources/NTLMacAgent/main.swift)
[ -n "$version" ] || { echo "cannot read the version from main.swift" >&2; exit 1; }

swift build -c "$config" >/dev/null
bin=".build/$config"
app="$bin/NTLMac.app"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
sed "s/__VERSION__/$version/g" ../packaging/app/Info.plist > "$app/Contents/Info.plist"
plutil -lint -s "$app/Contents/Info.plist"
cp "$bin/NTLMacAgent" "$bin/ntlmac-nmh" "$app/Contents/MacOS/"

# Inside out: the nested helper first, then the bundle (which signs its main executable).
codesign --force --sign "$identity" --identifier com.example.ntlmac.nmh "$app/Contents/MacOS/ntlmac-nmh"
codesign --force --sign "$identity" "$app"
codesign --verify --strict "$app"
echo "$app"
