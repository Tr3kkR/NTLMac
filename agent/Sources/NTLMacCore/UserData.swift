import Foundation

/// The agent's per-user state: the credential plus a private folder holding the suspect
/// latch and the telemetry queue. The uninstaller removes it through the agent itself
/// (`NTLMacAgent --remove-user-data`, run as each user), because only a binary with the
/// agent's `keychain-access-groups` entitlement can delete the Keychain item.
public enum UserData {
    /// `~/Library/Application Support/<prefix>`
    public static func defaultDirectory(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        NTLMacIdentity.current.userDataDirectory(home: home)
    }

    /// Deletes the credential and every path that exists. Tries everything before
    /// throwing the first error, so a locked Keychain doesn't leave the files behind.
    public static func remove(store: CredentialStore, paths: [URL]) throws {
        var firstError: Error?
        do { try store.delete() } catch { firstError = error }
        for path in paths {
            do {
                try FileManager.default.removeItem(at: path)
            } catch CocoaError.fileNoSuchFile {
                // already gone
            } catch {
                firstError = firstError ?? error
            }
        }
        if let firstError { throw firstError }
    }
}
