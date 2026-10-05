#!/bin/sh
# Builds the NTLMac installer package: NTLMac.app into /Library/Application Support/NTLMac
# (with uninstall.sh), the LaunchAgent into /Library/LaunchAgents, and the native-messaging
# manifest, naming the extension, into the Chrome and Edge system folders. The scripts in
# packaging/pkg/scripts stop the old agent before an upgrade and start the new one for
# users already logged in.
#
# Usage:
#   EXTENSION_ID=<32 letters a-p>              the force-installed extension's ID (required)
#   SIGN_IDENTITY="Developer ID Application: …" signs the app (see make-app.sh); ad hoc if unset
#   INSTALLER_IDENTITY="Developer ID Installer: …" signs the package
#   NOTARY_PROFILE=<notarytool keychain profile>  notarises and staples (needs both identities)
#   agent/scripts/make-pkg.sh   -> agent/.build/pkg/NTLMac-<version>.pkg
#
# Builds only; never installs. Check the result with test/packaging/check-pkg.sh.
set -eu
cd "$(dirname "$0")/.."

ext="${EXTENSION_ID:-}"
printf '%s' "$ext" | grep -Eqx '[a-p]{32}' \
  || { echo "EXTENSION_ID must be the extension's ID: 32 letters a-p" >&2; exit 64; }
if [ -n "${NOTARY_PROFILE:-}" ] && { [ -z "${INSTALLER_IDENTITY:-}" ] || [ -z "${SIGN_IDENTITY:-}" ]; }; then
  echo "NOTARY_PROFILE needs SIGN_IDENTITY and INSTALLER_IDENTITY (Developer ID)" >&2; exit 64
fi
version=$(sed -n 's/^let version = "\(.*\)"$/\1/p' Sources/NTLMacAgent/main.swift)

app=$(scripts/make-app.sh release 2>/dev/null | tail -1)
out=.build/pkg
root="$out/root"
support="$root/Library/Application Support/NTLMac"
rm -rf "$out"
umask 022 # system folders in the payload must stay 755
mkdir -p "$support" "$root/Library/LaunchAgents" \
  "$root/Library/Google/Chrome/NativeMessagingHosts" "$root/Library/Microsoft/Edge/NativeMessagingHosts"
ditto "$app" "$support/NTLMac.app"
install -m 755 ../packaging/pkg/uninstall.sh "$support/uninstall.sh"
install -m 644 ../packaging/launchd/com.example.ntlmac.agent.plist "$root/Library/LaunchAgents/"
for browser in Google/Chrome Microsoft/Edge; do
  manifest="$root/Library/$browser/NativeMessagingHosts/com.example.ntlmac.json"
  sed "s/__EXTENSION_ID__/$ext/" ../packaging/native-messaging/com.example.ntlmac.json > "$manifest"
  chmod 644 "$manifest"
done

pkgbuild --quiet --root "$root" --component-plist ../packaging/pkg/component.plist \
  --scripts ../packaging/pkg/scripts --identifier com.example.ntlmac.pkg --version "$version" \
  --install-location / --ownership recommended "$out/NTLMac-component.pkg"
sed "s/__VERSION__/$version/g" ../packaging/pkg/distribution.xml > "$out/distribution.xml"
pkg="$out/NTLMac-$version.pkg"
if [ -n "${INSTALLER_IDENTITY:-}" ]; then
  productbuild --quiet --distribution "$out/distribution.xml" --package-path "$out" \
    --sign "$INSTALLER_IDENTITY" --timestamp "$pkg"
else
  productbuild --quiet --distribution "$out/distribution.xml" --package-path "$out" "$pkg"
fi

if [ -n "${NOTARY_PROFILE:-}" ]; then
  xcrun notarytool submit "$pkg" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$pkg"
fi
echo "$PWD/$pkg"
