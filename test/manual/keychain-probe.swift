import Foundation
import Security

// Looks up the agent's credential item in the data-protection Keychain and prints the
// status, and the account if found. Asks for attributes only, never the password.
//   keychain-probe <service, e.g. com.devnull.ntlmac.credential> [<access group> | -]
// 0 found; -25300 errSecItemNotFound; -34018 errSecMissingEntitlement.
//   keychain-probe <service> <access group> --write-test-item
// stores the TEST account (jbloggs / Passw0rd!) as the agent would; for install tests.
let args = Array(CommandLine.arguments.dropFirst())
guard let service = args.first else { print("usage: keychain-probe <service> [<access group> | -]"); exit(64) }
let group = args.dropFirst().first.flatMap { $0 == "-" ? nil : $0 }
var query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecUseDataProtectionKeychain as String: true,
    kSecReturnAttributes as String: true,
]
if let group { query[kSecAttrAccessGroup as String] = group }
if args.count == 3, args[2] == "--write-test-item", let group {
    let status = SecItemAdd([
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccessGroup as String: group,
        kSecUseDataProtectionKeychain as String: true,
        kSecAttrSynchronizable as String: false,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAttrAccount as String: "jbloggs",
        kSecValueData as String: Data("Passw0rd!".utf8),
    ] as CFDictionary, nil)
    print("write status=\(status)")
    exit(status == errSecSuccess ? 0 : 1)
}
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
let account = (result as? [String: Any])?[kSecAttrAccount as String] as? String
print("status=\(status)" + (account.map { " account=\($0)" } ?? ""))
