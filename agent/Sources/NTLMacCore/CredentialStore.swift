import Foundation
import Security

/// The user's AD account name (sAMAccountName, no domain) and password.
public struct Credential: Sendable, Equatable {
    public var account: String
    public var password: String

    public init(account: String, password: String) {
        self.account = account
        self.password = password
    }
}

// Keep the password out of logs, string interpolation, `dump` and debugger summaries.
extension Credential: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "Credential(account: \(account), password: <redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["account": account, "password": "<redacted>"]) }
}

/// Where the agent keeps the one credential it supplies.
public protocol CredentialStore: Sendable {
    func read() throws -> Credential?
    /// Stores `credential`, replacing any existing one.
    func write(_ credential: Credential) throws
    /// Removes the credential. Removing a missing credential is not an error.
    func delete() throws
}

/// For tests and previews.
public final class InMemoryCredentialStore: CredentialStore, @unchecked Sendable {
    private let lock = NSLock()
    private var credential: Credential?

    public init(_ credential: Credential? = nil) {
        self.credential = credential
    }

    public func read() throws -> Credential? { lock.withLock { credential } }
    public func write(_ credential: Credential) throws { lock.withLock { self.credential = credential } }
    public func delete() throws { lock.withLock { credential = nil } }
}

public enum KeychainError: Error, Equatable {
    case status(OSStatus)
    case malformedItem
}

/// The `SecItem*` calls `KeychainCredentialStore` makes, so tests can fake the Keychain.
public protocol KeychainAPI: Sendable {
    func add(_ attributes: [String: Any]) -> OSStatus
    func copyMatching(_ query: [String: Any]) -> (OSStatus, Any?)
    func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

public struct SystemKeychain: KeychainAPI {
    public init() {}

    public func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(attributes as CFDictionary, nil)
    }

    public func copyMatching(_ query: [String: Any]) -> (OSStatus, Any?) {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result)
    }

    public func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }

    public func delete(_ query: [String: Any]) -> OSStatus {
        SecItemDelete(query as CFDictionary)
    }
}

/// A generic-password item in the data-protection Keychain: readable only while the Mac is
/// unlocked, never synchronised to iCloud or migrated to another device, and (with an
/// `accessGroup`) only by binaries signed with the agent's team ID and that
/// `keychain-access-groups` entitlement. Unsigned builds get `errSecMissingEntitlement`.
public struct KeychainCredentialStore: CredentialStore {
    public static let defaultService = "com.example.ntlmac.credential"

    public let service: String
    public let accessGroup: String?
    private let api: KeychainAPI

    public init(service: String = defaultService, accessGroup: String? = nil, api: KeychainAPI = SystemKeychain()) {
        self.service = service
        self.accessGroup = accessGroup
        self.api = api
    }

    public func read() throws -> Credential? {
        var query = baseQuery
        query[kSecReturnAttributes as String] = true
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, result) = api.copyMatching(query)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        guard let item = result as? [String: Any],
              let account = item[kSecAttrAccount as String] as? String,
              let data = item[kSecValueData as String] as? Data,
              let password = String(data: data, encoding: .utf8)
        else { throw KeychainError.malformedItem }
        return Credential(account: account, password: password)
    }

    public func write(_ credential: Credential) throws {
        let attributes: [String: Any] = [
            kSecAttrAccount as String: credential.account,
            kSecValueData as String: Data(credential.password.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = api.add(baseQuery.merging(attributes) { $1 })
        if status == errSecDuplicateItem {
            let updated = api.update(baseQuery, attributes)
            guard updated == errSecSuccess else { throw KeychainError.status(updated) }
            return
        }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    public func delete() throws {
        let status = api.delete(baseQuery)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.status(status) }
    }

    private var baseQuery: [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }
}
