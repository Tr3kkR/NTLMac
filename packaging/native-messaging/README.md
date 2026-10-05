The pkg installs `com.devnull.ntlmac.json` (with `__EXTENSION_ID__` substituted) into both
system-level locations:

- `/Library/Google/Chrome/NativeMessagingHosts/`
- `/Library/Microsoft/Edge/NativeMessagingHosts/`

Browser policy `NativeMessagingUserLevelHosts=false` (see `profiles/`) makes the browsers
ignore user-level manifests, so a user or malware cannot redirect the extension to another
binary.
