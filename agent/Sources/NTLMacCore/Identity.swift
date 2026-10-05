import Foundation

/// Every NTLMac name derives from one reverse-DNS prefix: the agent's bundle ID, signing
/// identifier, LaunchAgent label and Mach service (`<prefix>.agent`), the native host's
/// signing identifier (`<prefix>.nmh`), the Keychain service and access group, the managed
/// preference domain and the per-user data folder.
///
/// The default is `com.devnull.ntlmac`. `make-app.sh` signs with `NTLMAC_PREFIX` (default
/// the same), and each binary reads its prefix back from its own signing identifier, as it
/// does its team ID, so no build constant can disagree with the signature. Unsigned or bare
/// builds (tests, the browser suites) get the default.
public struct NTLMacIdentity: Sendable, Equatable {
    public static let standard = NTLMacIdentity(prefix: "com.devnull.ntlmac")!

    /// This process's identity, from its signing identifier.
    public static let current = NTLMacIdentity(signingIdentifier: try? CodeSigning.currentIdentifier())

    public let prefix: String

    /// Nil unless `prefix` has at least two labels of lowercase letters, digits and `_`:
    /// it is pasted into code-signing requirements and must be a valid native-messaging
    /// host name.
    public init?(prefix: String) {
        let labels = prefix.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ label in
            !label.isEmpty && label.allSatisfy { ("a" ... "z").contains($0) || ("0" ... "9").contains($0) || $0 == "_" }
        }) else { return nil }
        self.prefix = prefix
    }

    /// From `<prefix>.agent` or `<prefix>.nmh`; anything else means the default.
    public init(signingIdentifier: String?) {
        for suffix in [".agent", ".nmh"] {
            if let id = signingIdentifier, id.hasSuffix(suffix), let identity = NTLMacIdentity(prefix: String(id.dropLast(suffix.count))) {
                self = identity
                return
            }
        }
        self = .standard
    }

    public var agent: String { "\(prefix).agent" }
    public var shim: String { "\(prefix).nmh" }
    public var credentialService: String { "\(prefix).credential" }
    public var preferenceDomain: String { prefix }

    /// Team-prefixed, so no other team's code can claim it. A restricted entitlement:
    /// ship it authorised by an embedded provisioning profile (TN3125; make-app.sh).
    public func keychainAccessGroup(teamID: String) -> String { "\(teamID).\(prefix)" }

    /// `~/Library/Application Support/<prefix>`: suspect latch and telemetry queue.
    public func userDataDirectory(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent("Library/Application Support/\(prefix)", isDirectory: true)
    }
}
