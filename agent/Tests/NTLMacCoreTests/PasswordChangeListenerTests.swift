import Foundation
import notify
import Testing
@testable import NTLMacCore

private final class FakeCenter: DarwinNotificationCenter, @unchecked Sendable {
    var handlers: [Int32: (name: String, fire: @Sendable () -> Void)] = [:]
    var cancelled: [Int32] = []
    private var nextToken: Int32 = 1

    func observe(_ name: String, queue: DispatchQueue, handler: @escaping @Sendable () -> Void) throws -> Int32 {
        defer { nextToken += 1 }
        handlers[nextToken] = (name, handler)
        return nextToken
    }

    func cancel(_ token: Int32) {
        cancelled.append(token)
        handlers[token] = nil
    }

    func post(_ name: String) {
        for (_, h) in handlers where h.name == name { h.fire() }
    }
}

private final class Received: @unchecked Sendable {
    private let lock = NSLock()
    private var names: [String] = []
    func append(_ name: String) { lock.withLock { names.append(name) } }
    var all: [String] { lock.withLock { names } }
}

@Suite struct PasswordChangeListenerTests {
    @Test func listensForExactlyTheKerberosSSOPasswordChangeNotifications() throws {
        let center = FakeCenter()
        let listener = PasswordChangeListener(center: center) { _ in }
        try listener.start()
        #expect(Set(center.handlers.values.map(\.name)) == [
            "com.apple.KerberosPlugin.ADPasswordChanged",
            "com.apple.KerberosExtension.passwordChangedWithPasswordSync",
        ])
    }

    @Test func eachNotificationReportsItsName() throws {
        let center = FakeCenter()
        let received = Received()
        let listener = PasswordChangeListener(center: center) { received.append($0) }
        try listener.start()
        center.post("com.apple.KerberosPlugin.ADPasswordChanged")
        center.post("com.apple.KerberosExtension.gotNewCredential") // not a password change
        center.post("com.apple.KerberosExtension.passwordChangedWithPasswordSync")
        #expect(received.all == [
            "com.apple.KerberosPlugin.ADPasswordChanged",
            "com.apple.KerberosExtension.passwordChangedWithPasswordSync",
        ])
    }

    @Test func startIsIdempotentAndStopCancelsEverything() throws {
        let center = FakeCenter()
        let listener = PasswordChangeListener(center: center) { _ in }
        try listener.start()
        try listener.start()
        #expect(center.handlers.count == 2)
        listener.stop()
        #expect(center.handlers.isEmpty)
        #expect(center.cancelled.count == 2)
    }

    @Test func aPasswordChangeMarksTheBrokersCredentialSuspect() throws {
        let center = FakeCenter()
        let lock = NSLock()
        nonisolated(unsafe) var broker = AuthBroker(
            config: NTLMacConfig(enabled: true, killDate: .distantFuture, realm: "CORP.EXAMPLE", netbiosDomain: "CORP", rules: []),
            credentialState: .ok
        )
        let listener = PasswordChangeListener(center: center) { _ in lock.withLock { broker.passwordChangedExternally() } }
        try listener.start()
        center.post("com.apple.KerberosPlugin.ADPasswordChanged")
        #expect(lock.withLock { broker.credentialState } == .suspect)
    }
}

@Suite struct SystemDarwinNotificationCenterTests {
    @Test func deliversPostedNotificationsUntilCancelled() async throws {
        let center = SystemDarwinNotificationCenter()
        let name = "com.devnull.ntlmac.test.\(UUID().uuidString)"
        let received = Received()
        let token = try center.observe(name, queue: .global()) { received.append(name) }
        notify_post(name)
        for _ in 0 ..< 50 where received.all.isEmpty { try await Task.sleep(for: .milliseconds(20)) }
        #expect(received.all == [name])

        center.cancel(token)
        notify_post(name)
        try await Task.sleep(for: .milliseconds(200))
        #expect(received.all == [name], "no delivery after cancel")
    }
}
