import Foundation

/// Knobs that let the browser suites run a debug agent and shim, which are only ad-hoc
/// signed: a per-run Mach service, each side's code-signing requirement (the peer's own
/// cdhash), and file-based config and credential.
///
/// Compiled out of release builds: there `fromEnvironment` always returns no overrides
/// and the variable names aren't in the binary (`agent/scripts/check-release-overrides.sh`).
public struct DebugOverrides: Sendable, Equatable {
    public var machServiceName: String?
    /// What the shim requires of the agent, instead of the team policy.
    public var agentRequirement: String?
    /// What the agent requires of the shim, instead of the team policy.
    public var shimRequirement: String?
    /// JSON config (ISO-8601 dates) instead of the managed profile.
    public var configFile: String?
    /// `account:password` file instead of the Keychain.
    public var credentialFile: String?
    public var telemetryDirectory: String?

    public init() {}

    public var isEmpty: Bool { self == DebugOverrides() }

    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) -> DebugOverrides {
        var o = DebugOverrides()
        #if DEBUG
        func value(_ key: String) -> String? { env[key].flatMap { $0.isEmpty ? nil : $0 } }
        o.machServiceName = value("NTLMAC_MACH_SERVICE")
        o.agentRequirement = value("NTLMAC_AGENT_REQUIREMENT")
        o.shimRequirement = value("NTLMAC_SHIM_REQUIREMENT")
        o.configFile = value("NTLMAC_CONFIG")
        o.credentialFile = value("NTLMAC_TEST_CREDENTIAL_FILE")
        o.telemetryDirectory = value("NTLMAC_TELEMETRY_DIR")
        #endif
        return o
    }
}

#if DEBUG
/// Debug builds only: the credential as `account:password` in a private file, for the
/// browser suites. Never compiled into release builds.
public struct FileCredentialStore: CredentialStore {
    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    public func read() throws -> Credential? {
        guard let data = FileManager.default.contents(atPath: url.path) else { return nil }
        let line = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let sep = line.firstIndex(of: ":") else { throw KeychainError.malformedItem }
        return Credential(account: String(line[..<sep]), password: String(line[line.index(after: sep)...]))
    }

    public func write(_ credential: Credential) throws {
        let data = Data("\(credential.account):\(credential.password)".utf8)
        guard FileManager.default.createFile(atPath: url.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    public func delete() throws {
        do {
            try FileManager.default.removeItem(at: url)
        } catch CocoaError.fileNoSuchFile {
            // already gone
        }
    }
}
#endif
