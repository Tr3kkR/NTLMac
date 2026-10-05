# Installer package

`agent/scripts/make-pkg.sh` builds `agent/.build/pkg/NTLMac-<version>.pkg`. It installs:

| Path | Owner, mode |
|---|---|
| `/Library/Application Support/NTLMac/NTLMac.app` (agent + native host) | root:wheel, 755 |
| `/Library/Application Support/NTLMac/uninstall.sh` | root:wheel, 755 |
| `/Library/LaunchAgents/com.devnull.ntlmac.agent.plist` | root:wheel, 644 |
| `/Library/Google/Chrome/NativeMessagingHosts/com.devnull.ntlmac.json` | root:wheel, 644 |
| `/Library/Microsoft/Edge/NativeMessagingHosts/com.devnull.ntlmac.json` | root:wheel, 644 |

The manifests name the extension: `EXTENSION_ID` (required) is substituted into
`allowed_origins`. The app is not relocatable, so Installer never "upgrades" a copy found
elsewhere. Downgrades are allowed, so a ring can be rolled back.

- `scripts/preinstall` boots the agent out of every GUI session before an upgrade.
- `scripts/postinstall` bootstraps it into every GUI session (`gui/<uid>`). Installing at
  the login window starts nothing; the LaunchAgent loads at the next login.
- Both only act when the target is the boot volume.

`test/packaging/check-pkg.sh` builds an ad-hoc package and checks all of this without
installing it: payload paths, owners, modes, manifests, relocation, scripts (`sh -n`,
shellcheck) and usage errors. It extracts with `pkgutil --expand-full`. `pkgbuild` records
the `com.apple.provenance` attribute as `._*` entries in the Bom (`COPYFILE_DISABLE` doesn't
stop it), but PackageKit merges them back into attributes, so no `._` files land on disk.

**Never install the package on a Mac without agreeing it first.** It changes `/Library`
and starts a LaunchAgent in every logged-in session. `test/manual/check-install.sh
installed|seed|removed` checks the state around a real install (sudo steps by hand). It
was verified on a development Mac on 2026-10-05: install, upgrade and uninstall,
including the Keychain item.

## Uninstall

Run `"/Library/Application Support/NTLMac/uninstall.sh"` as root, for example from a Jamf
policy. For each logged-in user it:
1. boots the agent out;
2. runs `NTLMacAgent --remove-user-data` as that user (`launchctl asuser` + `sudo -u`).
   This deletes the Keychain item and `~/Library/Application Support/com.devnull.ntlmac`
   (suspect latch, telemetry queue).

Only the agent can do step 2: a data-protection Keychain item can be deleted only by a
binary with its `keychain-access-groups` entitlement, in the user's session, so root
can't do it. The script then deletes every user's NTLMac folder, the LaunchAgent, both
manifests and the app, and forgets the package receipt. Browser folders the package
created (for example Edge's, on a Mac without Edge) are removed only if empty.

**Residual:** a user who isn't logged in during the uninstall keeps their Keychain item.
Nothing else can read it, because it needs the agent's team signature and entitlement. It
never syncs or migrates. A reinstall reuses it, and if the password has gone stale the
breaker re-prompts.

## Signing and notarisation (manual, needs Developer ID)

`make-app.sh` (via `SIGN_IDENTITY`) gives both executables the hardened runtime and a
secure timestamp. It gives the agent `keychain-access-groups = <TEAM>.com.devnull.ntlmac`
(`packaging/app/NTLMacAgent.entitlements`), with the team read from the signature.

**No provisioning profile is needed** for a team-prefixed access group. This was checked
on macOS 26.5 with an Apple Development certificate:
- a probe signed with the hardened runtime and that entitlement, and no profile, launched
  and could use the group;
- an unentitled copy, and a copy asking for another group, got `errSecMissingEntitlement`
  (-34018).

Developer ID uses the same team-prefix check, but **repeat the check on the first
Developer ID build** (step 5).

1. The team's Account Holder creates a **Developer ID Application** and a **Developer ID
   Installer** certificate (Xcode › Settings › Accounts › Manage Certificates, or the
   developer portal). Install both, with their private keys, on the build Mac.
2. Store notarisation credentials once, for example
   `xcrun notarytool store-credentials NTLMAC_NOTARY --apple-id <id> --team-id <TEAM>`
   with an app-specific password, or `--key/--key-id/--issuer` for an App Store Connect API key.
3. Build, sign, notarise and staple:
   ```sh
   SIGN_IDENTITY="Developer ID Application: <Org> (<TEAM>)" \
   INSTALLER_IDENTITY="Developer ID Installer: <Org> (<TEAM>)" \
   NOTARY_PROFILE=NTLMAC_NOTARY EXTENSION_ID=<32 letters a-p> \
   agent/scripts/make-pkg.sh
   ```
4. Verify:
   - `pkgutil --check-signature <pkg>` shows the Developer ID Installer chain;
   - `xcrun stapler validate <pkg>` passes;
   - `spctl -a -vv -t install <pkg>` reports `source=Notarized Developer ID`.
5. On a test Mac: install, enrol with a test account, and check the agent's log (`log show
   --predicate 'subsystem == "com.devnull.ntlmac"'`) for -34018. Then run `uninstall.sh`
   and confirm the item is gone.

## Prefix

`NTLMAC_PREFIX=<reverse DNS>` (default `com.devnull.ntlmac`)
replaces `com.devnull.ntlmac` in the app's bundle ID, both signing identifiers, the
Keychain group, the LaunchAgent (name, label, Mach service), the manifests (name, file
name), the scripts and the package identifier. The prefix needs at least two labels of
lowercase letters, digits and `_`, because it is also the native-messaging host name.
The binaries need no rebuild: each reads the prefix back from its own signing identifier
(`<prefix>.agent`, `<prefix>.nmh`), as it does the team ID. An unsigned or bare build gets
the default.

Two other things must match the prefix:
- the extension's native host name: build it with the same variable,
  `NTLMAC_PREFIX=<prefix> npm run build` in `extension/`. A post-build step replaces the
  default prefix in `dist/logic.js`, and fails unless it finds it exactly once;
- the Jamf preference profile's domain: `make-pkg.sh` writes
  `agent/.build/pkg/profiles/<prefix>.plist` next to the package. Upload it under preference
  domain `<prefix>`, after filling in its `__…__` placeholders.
