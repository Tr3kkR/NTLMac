#!/bin/sh
# Builds the installer package (ad hoc, test extension ID) and checks it without
# installing anything: payload paths, owners and modes, the native-messaging manifests,
# a non-relocatable app, the install scripts and the uninstaller. Runs twice: with the
# repository's placeholder prefix and with a custom NTLMAC_PREFIX, which must leave no
# trace of the placeholder in the payload's names and text.
#
# Usage: test/packaging/check-pkg.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MAKE_PKG="$ROOT/agent/scripts/make-pkg.sh"
EXT=abcdefghijklmnopabcdefghijklmnop
WORK=$(mktemp -d -t ntlmac-pkg-check)
trap 'rm -rf "$WORK"' EXIT
fail=0
check() { # description, command...
  desc=$1; shift
  if "$@" >/dev/null 2>&1; then echo "ok   $desc"; else echo "FAIL $desc"; fail=1; fi
}

# Usage errors exit 64 (EX_USAGE) before building anything.
check "refuses a missing extension ID" sh -c "EXTENSION_ID= '$MAKE_PKG'; [ \$? = 64 ]"
check "refuses a malformed extension ID" sh -c "EXTENSION_ID=not-an-id '$MAKE_PKG'; [ \$? = 64 ]"
check "refuses notarising an unsigned package" sh -c "EXTENSION_ID=$EXT NOTARY_PROFILE=x '$MAKE_PKG'; [ \$? = 64 ]"
check "refuses a malformed prefix" sh -c "EXTENSION_ID=$EXT NTLMAC_PREFIX=com.my-org.ntlmac '$MAKE_PKG'; [ \$? = 64 ]"

check_package() { # prefix
  PREFIX=$1
  echo "--- NTLMAC_PREFIX=$PREFIX"
  PKG=$(EXTENSION_ID=$EXT NTLMAC_PREFIX=$PREFIX "$MAKE_PKG" | tail -1)
  check "package built" test -f "$PKG"
  X="$WORK/$PREFIX"
  # PackageKit's own extraction, as close to Installer as we get without installing.
  pkgutil --expand-full "$PKG" "$X"
  COMPONENT=$(find "$X" -maxdepth 1 -name '*.pkg' | head -1)
  P="$COMPONENT/Payload"
  SUPPORT="Library/Application Support/NTLMac"
  APP="$P/$SUPPORT/NTLMac.app"
  NMH_PATH="/$SUPPORT/NTLMac.app/Contents/MacOS/ntlmac-nmh"
  LAUNCH_AGENT="Library/LaunchAgents/$PREFIX.agent.plist"

  check "app bundle" test -x "$APP/Contents/MacOS/NTLMacAgent"
  check "native host inside the app" test -x "$P$NMH_PATH"
  check "uninstaller" test -x "$P/$SUPPORT/uninstall.sh"
  check "app bundle ID is $PREFIX.agent" sh -c "[ \"\$(plutil -extract CFBundleIdentifier raw '$APP/Contents/Info.plist')\" = '$PREFIX.agent' ]"
  check "native host signed as $PREFIX.nmh" sh -c "codesign -dv '$P$NMH_PATH' 2>&1 | grep -qx 'Identifier=$PREFIX.nmh'"
  check "LaunchAgent names the agent and its Mach service" python3 -c "
import plistlib, sys
p = plistlib.load(open(sys.argv[1], 'rb'))
assert p['Label'] == '$PREFIX.agent' and p['MachServices'] == {'$PREFIX.agent': True}, p
assert p['AssociatedBundleIdentifiers'] == '$PREFIX.agent', p
assert p['ProgramArguments'] == ['/$SUPPORT/NTLMac.app/Contents/MacOS/NTLMacAgent'], p" "$P/$LAUNCH_AGENT"
  for dir in Google/Chrome Microsoft/Edge; do
    check "$dir manifest names the host and the extension" python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))
assert m['allowed_origins'] == ['chrome-extension://$EXT/'], m
assert m['path'] == '$NMH_PATH', m
assert m['name'] == '$PREFIX'" "$P/Library/$dir/NativeMessagingHosts/$PREFIX.json"
  done
  check "nothing else in the payload" sh -c "cd '$P' && [ \"\$(find . -type f ! -path './$SUPPORT/NTLMac.app/*' | sort)\" = \"\$(printf '%s\n' './$SUPPORT/uninstall.sh' ./Library/Google/Chrome/NativeMessagingHosts/$PREFIX.json './$LAUNCH_AGENT' ./Library/Microsoft/Edge/NativeMessagingHosts/$PREFIX.json)\" ]"
  if [ "$PREFIX" != com.example.ntlmac ]; then
    # The binaries keep the placeholder as their fallback; everything else must not.
    check "no placeholder left in names or text" sh -c "
      [ -z \"\$(find '$X' -name '*com.example.ntlmac*')\" ] &&
      ! grep -rIl 'com\.example\.ntlmac' '$X' --exclude=NTLMacAgent --exclude=ntlmac-nmh --exclude=Bom --exclude=Payload"
  fi

  # Owners and modes from the bill of materials: everything root:wheel, no group/other
  # write anywhere, and system folders keep their usual 755 (an installer applies these).
  # pkgbuild records com.apple.provenance as ._ entries here (COPYFILE_DISABLE doesn't
  # stop it); PackageKit merges them back into attributes, so none land on disk.
  BOM=$(lsbom -p fMUG "$COMPONENT/Bom")
  check "everything owned by root:wheel" sh -c "! printf '%s\n' \"\$1\" | awk -F'\t' '\$3 != \"root\" || \$4 != \"wheel\"' | grep -q ." _ "$BOM"
  check "nothing group- or world-writable" sh -c "! printf '%s\n' \"\$1\" | awk -F'\t' '{ print \$2 }' | grep -Eq '^.....w|^........w'" _ "$BOM"
  for d in ./Library ./Library/LaunchAgents "./Library/Application Support"; do
    check "$d stays drwxr-xr-x" sh -c "printf '%s\n' \"\$1\" | grep -Eq \"^\$2	drwxr-xr-x.?	\"" _ "$BOM" "$d"
  done
  check "LaunchAgent plist is -rw-r--r--" sh -c "printf '%s\n' \"\$1\" | grep -Eq '^./$LAUNCH_AGENT	-rw-r--r--.?	'" _ "$BOM"
  check "no AppleDouble (._) files land on disk" sh -c "[ -z \"\$(find '$P' -name '._*')\" ]"

  # The app installs where the LaunchAgent and manifests expect it, even if a copy with
  # the same bundle ID exists elsewhere.
  check "app is not relocatable" sh -c "! grep -q '<relocate>' '$COMPONENT/PackageInfo'"
  check "package identifier is $PREFIX.pkg" grep -q "identifier=\"$PREFIX.pkg\"" "$COMPONENT/PackageInfo"
  check "macOS 14 minimum" grep -q '<os-version min="14.0"' "$X/Distribution"
  check "system domain only" grep -q 'enable_localSystem="true"' "$X/Distribution"

  # Scripts: present, executable, valid sh, and lint-clean if shellcheck is installed.
  for s in "$COMPONENT/Scripts/preinstall" "$COMPONENT/Scripts/postinstall" "$P/$SUPPORT/uninstall.sh"; do
    check "$(basename "$s") is executable sh" sh -c "test -x '$s' && sh -n '$s'"
    if command -v shellcheck >/dev/null; then check "$(basename "$s") passes shellcheck" shellcheck -s sh "$s"; fi
    check "$(basename "$s") acts on $PREFIX.agent" grep -q "$PREFIX.agent" "$s"
  done
  check "scripts only act on the boot volume" sh -c "grep -q '\"\$3\" = \"/\"' '$COMPONENT/Scripts/preinstall' && grep -q '\"\$3\" = \"/\"' '$COMPONENT/Scripts/postinstall'"
  check "uninstaller removes user data through the agent" grep -q -- '--remove-user-data' "$P/$SUPPORT/uninstall.sh"
  check "uninstaller refuses to run unprivileged" sh -c "! '$P/$SUPPORT/uninstall.sh'"

  # Next to the package (not in it): the Jamf preference profile, named for its domain.
  PROFILE="$(dirname "$PKG")/profiles/$PREFIX.plist"
  check "Jamf prefs profile $PREFIX.plist beside the package" plutil -lint -s "$PROFILE"
  check "profile comment names the $PREFIX domain" grep -q "preference domain: $PREFIX)" "$PROFILE"
}

check_package com.example.ntlmac
check_package org.test.ntlmac

[ "$fail" = 0 ] && echo "OK"
exit "$fail"
