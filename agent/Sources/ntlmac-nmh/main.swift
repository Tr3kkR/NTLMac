import Foundation
import NTLMacCore

// SPIKE (Phase 0): the broker runs in-process and the credential comes from a plain
// Keychain item. In the MVP this binary becomes a thin shim that forwards to
// NTLMacAgent over XPC; the agent owns the Keychain ACL, prompts and telemetry.

let spikeKeychainService = "com.example.ntlmac.spike"

func log(_ message: String) {
    // stdout is the browser channel; diagnostics must go to stderr (Chrome logs it).
    FileHandle.standardError.write(Data("ntlmac-nmh: \(message)\n".utf8))
}

func loadConfig() -> NTLMacConfig? {
    do {
        if let path = ProcessInfo.processInfo.environment["NTLMAC_CONFIG"] {
            return try ConfigLoader.decode(json: Data(contentsOf: URL(fileURLWithPath: path)))
        }
        return try ConfigLoader.loadManaged()
    } catch {
        log("config invalid, failing closed: \(error)")
        return nil
    }
}

struct SpikeCredential {
    var account: String
    var password: String
}

func readSpikeCredential() -> SpikeCredential? {
    #if DEBUG
    // Automated browser tests only ("account:password"); never compiled into release builds.
    if let path = ProcessInfo.processInfo.environment["NTLMAC_TEST_CREDENTIAL_FILE"],
       let line = try? String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
       let sep = line.firstIndex(of: ":") {
        return SpikeCredential(account: String(line[..<sep]), password: String(line[line.index(after: sep)...]))
    }
    #endif
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: spikeKeychainService,
        kSecReturnAttributes as String: true,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
          let dict = item as? [String: Any],
          let account = dict[kSecAttrAccount as String] as? String,
          let data = dict[kSecValueData as String] as? Data,
          let password = String(data: data, encoding: .utf8)
    else { return nil }
    return SpikeCredential(account: account, password: password)
}

func send(_ response: HostResponse) {
    do {
        let framed = try NativeMessaging.frame(JSONEncoder().encode(response))
        FileHandle.standardOutput.write(framed)
    } catch {
        log("failed to send response: \(error)")
    }
}

let config = loadConfig()
let credential = readSpikeCredential()
var broker = config.map { AuthBroker(config: $0, credentialState: credential == nil ? .missing : .ok) }
var decoder = NativeMessageDecoder()

log("started; config=\(config != nil) credential=\(credential != nil)")

while true {
    let chunk = FileHandle.standardInput.availableData
    if chunk.isEmpty { break } // browser closed the port
    decoder.append(chunk)
    do {
        while let message = try decoder.next() {
            guard let request = try? JSONDecoder().decode(HostRequest.self, from: message) else {
                log("ignoring malformed message")
                continue
            }
            guard var b = broker else {
                send(.decline(id: request.id, outcome: .configInvalid))
                continue
            }
            let decision = b.decide(request.request, now: Date())
            broker = b
            log("request \(request.request.requestId) host=\(request.request.host) -> \(decision.outcome.rawValue)")
            switch decision {
            case .supply:
                guard let credential, let config else {
                    send(.decline(id: request.id, outcome: .credentialMissing))
                    continue
                }
                send(.supply(id: request.id, username: "\(config.netbiosDomain)\\\(credential.account)", password: credential.password))
            case .decline(let outcome):
                send(.decline(id: request.id, outcome: outcome))
            }
        }
    } catch {
        log("protocol error, exiting: \(error)")
        exit(1)
    }
}
