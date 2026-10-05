import Foundation
import Security
import Testing
@testable import NTLMacCore

private let secret = "S3cret-never-print"
private let credential = Credential(account: "jbloggs", password: secret)

/// Records SecItem calls and answers them from a single in-memory item.
private final class FakeKeychain: KeychainAPI, @unchecked Sendable {
    var item: [String: Any]?
    var calls: [(op: String, query: [String: Any])] = []
    var failNext: OSStatus?

    func add(_ attributes: [String: Any]) -> OSStatus {
        calls.append(("add", attributes))
        if let status = take() { return status }
        guard item == nil else { return errSecDuplicateItem }
        item = attributes
        return errSecSuccess
    }

    func copyMatching(_ query: [String: Any]) -> (OSStatus, Any?) {
        calls.append(("copy", query))
        if let status = take() { return (status, nil) }
        guard let item else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, [
            kSecAttrAccount as String: item[kSecAttrAccount as String]!,
            kSecValueData as String: item[kSecValueData as String]!,
        ] as [String: Any])
    }

    func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus {
        calls.append(("update", attributes))
        if let status = take() { return status }
        guard item != nil else { return errSecItemNotFound }
        item!.merge(attributes) { $1 }
        return errSecSuccess
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        calls.append(("delete", query))
        if let status = take() { return status }
        guard item != nil else { return errSecItemNotFound }
        item = nil
        return errSecSuccess
    }

    private func take() -> OSStatus? {
        defer { failNext = nil }
        return failNext
    }
}

@Suite struct CredentialTests {
    @Test func descriptionAndDumpNeverContainThePassword() {
        var dumped = ""
        dump(credential, to: &dumped)
        for text in [String(describing: credential), String(reflecting: credential), "\(credential)", dumped] {
            #expect(!text.contains(secret), "leaked in: \(text)")
            #expect(text.contains("jbloggs"))
        }
    }
}

@Suite struct InMemoryCredentialStoreTests {
    @Test func storesReplacesAndDeletes() throws {
        let store = InMemoryCredentialStore()
        #expect(try store.read() == nil)
        try store.write(credential)
        #expect(try store.read() == credential)
        let replaced = Credential(account: "jbloggs", password: "new")
        try store.write(replaced)
        #expect(try store.read() == replaced)
        try store.delete()
        #expect(try store.read() == nil)
        try store.delete() // deleting nothing is not an error
    }
}

@Suite struct KeychainCredentialStoreTests {
    private func store(_ api: FakeKeychain, accessGroup: String? = nil) -> KeychainCredentialStore {
        KeychainCredentialStore(service: "com.devnull.ntlmac.credential", accessGroup: accessGroup, api: api)
    }

    @Test func newItemIsThisDeviceOnlyNotSynchronisedAndInTheDataProtectionKeychain() throws {
        let api = FakeKeychain()
        try store(api, accessGroup: "ABCDE12345.com.devnull.ntlmac").write(credential)
        let add = try #require(api.calls.first { $0.op == "add" }?.query)
        #expect(add[kSecClass as String] as? String == kSecClassGenericPassword as String)
        #expect(add[kSecAttrService as String] as? String == "com.devnull.ntlmac.credential")
        #expect(add[kSecAttrAccount as String] as? String == "jbloggs")
        #expect(add[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        #expect(add[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(add[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(add[kSecAttrAccessGroup as String] as? String == "ABCDE12345.com.devnull.ntlmac")
        #expect(add[kSecValueData as String] as? Data == Data(secret.utf8))
    }

    @Test func everyQueryIsScopedToTheServiceAndDataProtectionKeychain() throws {
        let api = FakeKeychain()
        let s = store(api)
        try s.write(credential)
        _ = try s.read()
        try s.write(credential) // duplicate -> update
        try s.delete()
        #expect(api.calls.map(\.op) == ["add", "copy", "add", "update", "delete"])
        for call in api.calls where call.op != "update" {
            #expect(call.query[kSecAttrService as String] as? String == "com.devnull.ntlmac.credential", "\(call.op)")
            #expect(call.query[kSecUseDataProtectionKeychain as String] as? Bool == true, "\(call.op)")
            #expect(call.query[kSecAttrSynchronizable as String] as? Bool == false, "\(call.op)")
        }
    }

    @Test func roundTripsThroughTheKeychainAPI() throws {
        let api = FakeKeychain()
        let s = store(api)
        #expect(try s.read() == nil)
        try s.write(credential)
        #expect(try s.read() == credential)
        let replaced = Credential(account: "jbloggs2", password: "new")
        try s.write(replaced)
        #expect(try s.read() == replaced)
        let update = try #require(api.calls.last { $0.op == "update" }?.query)
        #expect(update[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        try s.delete()
        #expect(try s.read() == nil)
        try s.delete()
    }

    @Test func keychainErrorsSurfaceAsStatusWithoutSecrets() throws {
        let api = FakeKeychain()
        api.failNext = errSecInteractionNotAllowed // e.g. device locked
        #expect(throws: KeychainError.status(errSecInteractionNotAllowed)) { try store(api).read() }
        api.failNext = errSecMissingEntitlement
        #expect(throws: KeychainError.status(errSecMissingEntitlement)) { try store(api).write(credential) }
    }

    /// Real Keychain: the test runner is only ad-hoc signed, with no keychain-access-groups
    /// entitlement, so the data-protection Keychain refuses to store anything for it. The
    /// agent must ship signed with that entitlement. (Whether an unentitled process can
    /// read the agent's existing item needs a signed agent to create one: spike item d.)
    @Test func unentitledProcessesCannotWriteTheRealItem() throws {
        let real = KeychainCredentialStore(service: "com.devnull.ntlmac.test-\(UUID().uuidString)")
        #expect(throws: KeychainError.status(errSecMissingEntitlement)) { try real.write(credential) }
        #expect(try real.read() == nil)
    }

    @Test func undecodableItemIsAnError() throws {
        let api = FakeKeychain()
        api.item = [kSecAttrAccount as String: "jbloggs", kSecValueData as String: Data([0xFF, 0xFE])]
        #expect(throws: KeychainError.malformedItem) { try store(api).read() }
    }
}
