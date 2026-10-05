import Foundation
import Testing
@testable import NTLMacCore

/// Answers every AS exchange with a fixed krb5 error code and remembers what it was asked.
private final class ScriptedKDC: KerberosClient, @unchecked Sendable {
    private let lock = NSLock()
    private var asked: [String] = []
    let code: Int32

    init(_ code: Int32) { self.code = code }

    func requestInitialCredentials(principal: String, password: String) -> Int32 {
        lock.withLock { asked.append(principal) }
        return code
    }

    var principals: [String] { lock.withLock { asked } }
}

private let jbloggs = Credential(account: "jbloggs", password: "Passw0rd!")

@Suite struct KerberosValidatorTests {
    @Test func acceptedMeansValidAfterExactlyOneRequest() async throws {
        let kdc = ScriptedKDC(0)
        #expect(try await KerberosCredentialValidator(client: kdc).validate(jbloggs, realm: "corp.example"))
        #expect(kdc.principals == ["jbloggs@CORP.EXAMPLE"])
    }

    @Test(arguments: [KerberosError.preauthFailed, KerberosError.badIntegrity, KerberosError.principalUnknown])
    func aRejectionIsFalseAndNeverRetried(code: Int32) async throws {
        let kdc = ScriptedKDC(code)
        #expect(try await KerberosCredentialValidator(client: kdc).validate(jbloggs, realm: "CORP.EXAMPLE") == false)
        #expect(kdc.principals.count == 1, "each extra request is another bad-password event at the DC")
    }

    @Test func anExpiredPasswordIsNotARejection() async throws {
        let kdc = ScriptedKDC(KerberosError.keyExpired)
        await #expect(throws: KerberosValidationError.passwordExpired) {
            try await KerberosCredentialValidator(client: kdc).validate(jbloggs, realm: "CORP.EXAMPLE")
        }
        #expect(kdc.principals.count == 1)
    }

    @Test func aLockedOrDisabledAccountSaysSo() async throws {
        await #expect(throws: KerberosValidationError.accountLocked) {
            try await KerberosCredentialValidator(client: ScriptedKDC(KerberosError.clientRevoked)).validate(jbloggs, realm: "CORP.EXAMPLE")
        }
    }

    @Test(arguments: [KerberosError.kdcUnreachable, KerberosError.realmUnknown, KerberosError.clockSkew, -1])
    func anythingElseMeansTheKDCCouldNotBeAsked(code: Int32) async throws {
        let kdc = ScriptedKDC(code)
        await #expect(throws: KerberosValidationError.kdcUnavailable(code: code)) {
            try await KerberosCredentialValidator(client: kdc).validate(jbloggs, realm: "CORP.EXAMPLE")
        }
        #expect(kdc.principals.count == 1)
    }

    @Test(arguments: [
        ("", "Passw0rd!", "CORP.EXAMPLE"),
        ("jbloggs@corp.example", "Passw0rd!", "CORP.EXAMPLE"),
        ("CORP\\jbloggs", "Passw0rd!", "CORP.EXAMPLE"),
        ("svc/host", "Passw0rd!", "CORP.EXAMPLE"),
        ("jbloggs", "", "CORP.EXAMPLE"),
        ("jbloggs", "Passw0rd!", ""),
    ])
    func malformedInputNeverReachesTheKDC(account: String, password: String, realm: String) async throws {
        let kdc = ScriptedKDC(0)
        await #expect(throws: KerberosValidationError.invalidInput) {
            try await KerberosCredentialValidator(client: kdc).validate(Credential(account: account, password: password), realm: realm)
        }
        #expect(kdc.principals.isEmpty)
    }

    @Test func theRealClientReportsAnUnreachableKDC() async throws {
        // A realm whose only KDC is a closed local port: exercises the real krb5 call
        // without a KDC. KRB5_CONFIG is read when each request builds its krb5 context.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ntlmac-krb5-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let conf = dir.appendingPathComponent("krb5.conf")
        try """
        [libdefaults]
            dns_lookup_kdc = false
            kdc_timeout = 1
        [realms]
            NOWHERE.EXAMPLE = {
                kdc = tcp/127.0.0.1:9
            }
        """.write(to: conf, atomically: true, encoding: .utf8)
        let code = KerberosTestEnvironment.withConfig(conf.path) {
            SystemKerberosClient().requestInitialCredentials(principal: "jbloggs@NOWHERE.EXAMPLE", password: "Passw0rd!")
        }
        #expect(code == KerberosError.kdcUnreachable)
    }

    /// Opt-in check against a real KDC (see test/kdc/README.md): set NTLMAC_TEST_KRB5_CONFIG
    /// to its krb5.conf. Proves accept / reject end to end; the KDC log shows the request count.
    @Test func againstARealKDC() async throws {
        guard let conf = ProcessInfo.processInfo.environment["NTLMAC_TEST_KRB5_CONFIG"] else { return }
        let realm = ProcessInfo.processInfo.environment["NTLMAC_TEST_REALM"] ?? "CORP.EXAMPLE"
        let (good, bad) = KerberosTestEnvironment.withConfig(conf) {
            (SystemKerberosClient().requestInitialCredentials(principal: "jbloggs@\(realm)", password: "Passw0rd!"),
             SystemKerberosClient().requestInitialCredentials(principal: "jbloggs@\(realm)", password: "wrong"))
        }
        #expect(good == 0)
        #expect(bad == KerberosError.preauthFailed || bad == KerberosError.badIntegrity, "got \(bad)")
    }
}

/// KRB5_CONFIG is process-wide; serialise the tests that set it.
enum KerberosTestEnvironment {
    private static let lock = NSLock()

    static func withConfig<T>(_ path: String, _ body: () -> T) -> T {
        lock.withLock {
            let old = getenv("KRB5_CONFIG").map { String(cString: $0) }
            setenv("KRB5_CONFIG", path, 1)
            defer { if let old { setenv("KRB5_CONFIG", old, 1) } else { unsetenv("KRB5_CONFIG") } }
            return body()
        }
    }
}
