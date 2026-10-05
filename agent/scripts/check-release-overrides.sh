#!/bin/sh
# Proves the DEBUG-only test overrides (DebugOverrides, FileCredentialStore) are compiled
# out of release builds: no override variable name or file-store symbol may appear in the
# release binaries. The debug binaries are checked too, as a control that the search works.
#
# Usage: agent/scripts/check-release-overrides.sh   (builds debug and release first)
set -eu
cd "$(dirname "$0")/.."

MARKERS="NTLMAC_MACH_SERVICE NTLMAC_AGENT_REQUIREMENT NTLMAC_SHIM_REQUIREMENT NTLMAC_CONFIG NTLMAC_TEST_CREDENTIAL_FILE NTLMAC_TELEMETRY_DIR NTLMAC_SUSPECT_LATCH_FILE FileCredentialStore"
BINARIES="ntlmac-nmh NTLMacAgent"

swift build -c debug >/dev/null
swift build -c release >/dev/null

fail=0
for bin in $BINARIES; do
  for config in debug release; do
    path=".build/$config/$bin"
    contents=$(strings -a "$path"; nm -a "$path" 2>/dev/null | swift demangle --compact)
    for marker in $MARKERS; do
      if printf '%s\n' "$contents" | grep -q "$marker"; then found=yes; else found=no; fi
      if [ "$config" = release ] && [ "$found" = yes ]; then
        echo "FAIL: $marker is in the release $bin"; fail=1
      elif [ "$config" = debug ] && [ "$found" = no ]; then
        echo "FAIL (control): $marker not found in the debug $bin, so this check proves nothing"; fail=1
      fi
    done
  done
done
[ "$fail" = 0 ] && echo "OK: release binaries contain no debug overrides ($BINARIES)"
exit "$fail"
