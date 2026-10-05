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
#   NTLMAC_PREFIX=<reverse DNS>                 replaces com.devnull.ntlmac in every identifier,
#                                               file name and script (see make-app.sh)
#   agent/scripts/make-pkg.sh   -> agent/.build/pkg/NTLMac-<version>.pkg
#                                  agent/.build/pkg/profiles/<prefix>.plist (Jamf prefs, upload
#                                  under preference domain <prefix>; fill in its placeholders)
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
prefix="${NTLMAC_PREFIX:-com.devnull.ntlmac}"
version=$(sed -n 's/^let version = "\(.*\)"$/\1/p' Sources/NTLMacAgent/main.swift)

scripts/make-app.sh release >/dev/null # also validates NTLMAC_PREFIX
app=.build/release/NTLMac.app
out=.build/pkg
root="$out/root"
support="$root/Library/Application Support/NTLMac"
# Every template names the default prefix; this is the one place it is replaced.
stage() { # template, destination, mode
  sed -e "s/com\.devnull\.ntlmac/$prefix/g" -e "s/__EXTENSION_ID__/$ext/g" "$1" > "$2"
  chmod "$3" "$2"
}
rm -rf "$out"
umask 022 # system folders in the payload must stay 755
mkdir -p "$support" "$root/Library/LaunchAgents" \
  "$root/Library/Google/Chrome/NativeMessagingHosts" "$root/Library/Microsoft/Edge/NativeMessagingHosts"
ditto "$app" "$support/NTLMac.app"
stage ../packaging/pkg/uninstall.sh "$support/uninstall.sh" 755
stage ../packaging/launchd/com.devnull.ntlmac.agent.plist "$root/Library/LaunchAgents/$prefix.agent.plist" 644
for browser in Google/Chrome Microsoft/Edge; do
  stage ../packaging/native-messaging/com.devnull.ntlmac.json "$root/Library/$browser/NativeMessagingHosts/$prefix.json" 644
done
mkdir "$out/scripts" "$out/profiles"
stage ../packaging/profiles/com.devnull.ntlmac.plist "$out/profiles/$prefix.plist" 644
for script in preinstall postinstall; do
  stage "../packaging/pkg/scripts/$script" "$out/scripts/$script" 755
done

pkgbuild --quiet --root "$root" --component-plist ../packaging/pkg/component.plist \
  --scripts "$out/scripts" --identifier "$prefix.pkg" --version "$version" \
  --install-location / --ownership recommended "$out/NTLMac-component.pkg"
sed -e "s/__VERSION__/$version/g" -e "s/com\.devnull\.ntlmac/$prefix/g" ../packaging/pkg/distribution.xml > "$out/distribution.xml"
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
