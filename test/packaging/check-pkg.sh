#!/bin/sh
# Builds the installer package (ad hoc, test extension ID) and checks it without
# installing anything: payload paths, owners and modes, the native-messaging manifests,
# a non-relocatable app, the install scripts and the uninstaller.
#
# Usage: test/packaging/check-pkg.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EXT=abcdefghijklmnopabcdefghijklmnop
WORK=$(mktemp -d -t ntlmac-pkg-check)
trap 'rm -rf "$WORK"' EXIT
fail=0
check() { # description, command...
  desc=$1; shift
  if "$@" >/dev/null 2>&1; then echo "ok   $desc"; else echo "FAIL $desc"; fail=1; fi
}

# Usage errors exit 64 (EX_USAGE) before building anything.
check "refuses a missing extension ID" sh -c "EXTENSION_ID= '$ROOT/agent/scripts/make-pkg.sh'; [ \$? = 64 ]"
check "refuses a malformed extension ID" sh -c "EXTENSION_ID=not-an-id '$ROOT/agent/scripts/make-pkg.sh'; [ \$? = 64 ]"
check "refuses notarising an unsigned package" sh -c "EXTENSION_ID=$EXT NOTARY_PROFILE=x '$ROOT/agent/scripts/make-pkg.sh'; [ \$? = 64 ]"

PKG=$(EXTENSION_ID=$EXT "$ROOT/agent/scripts/make-pkg.sh" | tail -1)
check "package built" test -f "$PKG"
# PackageKit's own extraction, as close to Installer as we get without installing.
pkgutil --expand-full "$PKG" "$WORK/x"
COMPONENT=$(find "$WORK/x" -maxdepth 1 -name '*.pkg' | head -1)
P="$COMPONENT/Payload"
SUPPORT="Library/Application Support/NTLMac"
NMH_PATH="/$SUPPORT/NTLMac.app/Contents/MacOS/ntlmac-nmh"

# Payload: exactly these files (plus the app bundle's contents).
check "app bundle" test -x "$P/$SUPPORT/NTLMac.app/Contents/MacOS/NTLMacAgent"
check "native host inside the app" test -x "$P$NMH_PATH"
check "uninstaller" test -x "$P/$SUPPORT/uninstall.sh"
check "LaunchAgent is the template, unchanged" cmp "$P/Library/LaunchAgents/com.example.ntlmac.agent.plist" "$ROOT/packaging/launchd/com.example.ntlmac.agent.plist"
for dir in Google/Chrome Microsoft/Edge; do
  m="$P/Library/$dir/NativeMessagingHosts/com.example.ntlmac.json"
  check "$dir manifest names the extension" python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))
assert m['allowed_origins'] == ['chrome-extension://$EXT/'], m
assert m['path'] == '$NMH_PATH', m
assert m['name'] == 'com.example.ntlmac'" "$m"
done
check "nothing else in the payload" sh -c "cd '$P' && [ \"\$(find . -type f ! -path './$SUPPORT/NTLMac.app/*' | sort)\" = \"\$(printf '%s\n' './$SUPPORT/uninstall.sh' ./Library/Google/Chrome/NativeMessagingHosts/com.example.ntlmac.json ./Library/LaunchAgents/com.example.ntlmac.agent.plist ./Library/Microsoft/Edge/NativeMessagingHosts/com.example.ntlmac.json)\" ]"

# Owners and modes from the bill of materials: everything root:wheel, no group/other
# write anywhere, and system folders keep their usual 755 (an installer applies these).
BOM=$(lsbom -p fMUG "$COMPONENT/Bom")
check "everything owned by root:wheel" sh -c "! printf '%s\n' \"\$1\" | awk -F'\t' '\$3 != \"root\" || \$4 != \"wheel\"' | grep -q ." _ "$BOM"
check "nothing group- or world-writable" sh -c "! printf '%s\n' \"\$1\" | awk -F'\t' '{ print \$2 }' | grep -Eq '^.....w|^........w'" _ "$BOM"
for d in ./Library ./Library/LaunchAgents "./Library/Application Support"; do
  check "$d stays drwxr-xr-x" sh -c "printf '%s\n' \"\$1\" | grep -Eq \"^\$2	drwxr-xr-x.?	\"" _ "$BOM" "$d"
done
check "LaunchAgent plist is -rw-r--r--" sh -c "printf '%s\n' \"\$1\" | grep -Eq '^./Library/LaunchAgents/com.example.ntlmac.agent.plist	-rw-r--r--.?	'" _ "$BOM"
# pkgbuild records com.apple.provenance as ._ entries in the Bom (COPYFILE_DISABLE
# doesn't stop it); PackageKit merges them back into attributes, so none land on disk.
check "no AppleDouble (._) files land on disk" sh -c "[ -z \"\$(find '$P' -name '._*')\" ]"

# The app installs where the LaunchAgent and manifests expect it, even if a copy with
# the same bundle ID exists elsewhere.
check "app is not relocatable" sh -c "! grep -q '<relocate>' '$COMPONENT/PackageInfo'"
check "component identifier" grep -q 'identifier="com.example.ntlmac.pkg"' "$COMPONENT/PackageInfo"
check "macOS 14 minimum" grep -q '<os-version min="14.0"' "$WORK/x/Distribution"
check "system domain only" grep -q 'enable_localSystem="true"' "$WORK/x/Distribution"

# Scripts: present, executable, valid sh, and lint-clean if shellcheck is installed.
for s in "$COMPONENT/Scripts/preinstall" "$COMPONENT/Scripts/postinstall" "$P/$SUPPORT/uninstall.sh"; do
  check "$(basename "$s") is executable sh" sh -c "test -x '$s' && sh -n '$s'"
  if command -v shellcheck >/dev/null; then check "$(basename "$s") passes shellcheck" shellcheck -s sh "$s"; fi
done
check "scripts only act on the boot volume" sh -c "grep -q '\"\$3\" = \"/\"' '$COMPONENT/Scripts/preinstall' && grep -q '\"\$3\" = \"/\"' '$COMPONENT/Scripts/postinstall'"
check "uninstaller removes user data through the agent" grep -q -- '--remove-user-data' "$P/$SUPPORT/uninstall.sh"
check "uninstaller refuses to run unprivileged" sh -c "! '$P/$SUPPORT/uninstall.sh'"

[ "$fail" = 0 ] && echo "OK: $PKG"
exit "$fail"
