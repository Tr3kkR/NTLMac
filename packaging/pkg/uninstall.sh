#!/bin/sh
# Removes NTLMac from this Mac. Run as root, e.g. from a Jamf policy:
#   "/Library/Application Support/NTLMac/uninstall.sh"
#
# For each logged-in user it stops the agent, then runs the agent once as that user with
# --remove-user-data: only the agent's own signed, entitled binary can delete its
# data-protection Keychain item, and only inside the user's session. Users who are not
# logged in lose their NTLMac folder, but their Keychain item stays until it is
# overwritten by a reinstall: nothing else can read it (it needs the agent's team
# signature and keychain-access-groups entitlement), and it never syncs or migrates.
set -u
[ "$(id -u)" = 0 ] || { echo "uninstall.sh: run as root" >&2; exit 1; }

LABEL=com.devnull.ntlmac.agent
SUPPORT="/Library/Application Support/NTLMac"
AGENT="$SUPPORT/NTLMac.app/Contents/MacOS/NTLMacAgent"

for uid in $(ps -axo uid=,comm= | awk '$2 ~ /\/loginwindow$/ && $1 != 0 { print $1 }' | sort -u); do
  if launchctl bootout "gui/$uid/$LABEL" 2>/dev/null; then
    i=0
    while launchctl print "gui/$uid/$LABEL" >/dev/null 2>&1 && [ "$i" -lt 50 ]; do
      sleep 0.1; i=$((i + 1))
    done
  fi
  if [ -x "$AGENT" ]; then
    launchctl asuser "$uid" sudo -H -u "#$uid" "$AGENT" --remove-user-data \
      || echo "uninstall.sh: could not remove all NTLMac data for uid $uid (Keychain locked?)" >&2
  fi
done

for dir in /Users/*/Library/Application\ Support/com.devnull.ntlmac; do
  [ -d "$dir" ] && rm -rf "$dir"
done
rm -f "/Library/LaunchAgents/$LABEL.plist" \
  /Library/Google/Chrome/NativeMessagingHosts/com.devnull.ntlmac.json \
  /Library/Microsoft/Edge/NativeMessagingHosts/com.devnull.ntlmac.json
# The package creates these for a browser that may not be installed. rmdir only removes
# an empty folder, so anything another app still uses stays.
for dir in /Library/Google/Chrome/NativeMessagingHosts /Library/Google/Chrome /Library/Google \
  /Library/Microsoft/Edge/NativeMessagingHosts /Library/Microsoft/Edge /Library/Microsoft; do
  rmdir "$dir" 2>/dev/null || true
done
rm -rf "$SUPPORT"
pkgutil --forget com.devnull.ntlmac.pkg >/dev/null 2>&1 || true
echo "uninstall.sh: NTLMac removed"
