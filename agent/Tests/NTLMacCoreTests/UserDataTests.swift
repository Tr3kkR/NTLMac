import Foundation
import Testing
@testable import NTLMacCore

private final class RecordingStore: CredentialStore, @unchecked Sendable {
    var credential: Credential? = Credential(account: "jbloggs", password: "Passw0rd!")
    var deleteError: Error?
    func read() throws -> Credential? { credential }
    func write(_ credential: Credential) throws { self.credential = credential }
    func delete() throws {
        if let deleteError { throw deleteError }
        credential = nil
    }
}

private func tempDir() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("ntlmac-userdata-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

@Suite struct UserDataTests {
    @Test func defaultDirectoryHoldsTheLatchAndTheTelemetryQueue() {
        let home = URL(fileURLWithPath: "/Users/jbloggs")
        let dir = UserData.defaultDirectory(home: home)
        #expect(dir.path == "/Users/jbloggs/Library/Application Support/com.devnull.ntlmac")
        #expect(FileSuspectLatch.defaultURL(home: home).deletingLastPathComponent() == dir)
        #expect(TelemetryQueue.defaultDirectory(home: home).deletingLastPathComponent() == dir)
    }

    @Test func removesTheCredentialAndEveryPath() throws {
        let dir = try tempDir()
        let latch = dir.appendingPathComponent("credential-suspect")
        let telemetry = dir.appendingPathComponent("telemetry", isDirectory: true)
        try FileSuspectLatch(url: latch).set()
        try FileManager.default.createDirectory(at: telemetry, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: telemetry.appendingPathComponent("batch.json"))
        let store = RecordingStore()

        try UserData.remove(store: store, paths: [latch, telemetry, dir])

        #expect(store.credential == nil)
        #expect(!FileManager.default.fileExists(atPath: dir.path))
    }

    @Test func missingDataIsAlreadyRemoved() throws {
        let store = RecordingStore()
        store.credential = nil
        let dir = try tempDir()
        try UserData.remove(store: store, paths: [dir.appendingPathComponent("absent")])
        try UserData.remove(store: store, paths: [dir.appendingPathComponent("absent")])
    }

    @Test func aKeychainFailureStillRemovesTheFilesThenThrows() throws {
        let dir = try tempDir()
        let latch = dir.appendingPathComponent("credential-suspect")
        try FileSuspectLatch(url: latch).set()
        let store = RecordingStore()
        store.deleteError = KeychainError.status(-25308) // errSecInteractionNotAllowed: locked

        #expect(throws: KeychainError.status(-25308)) { try UserData.remove(store: store, paths: [latch]) }
        #expect(!FileManager.default.fileExists(atPath: latch.path), "the latch goes even if the item can't")
    }
}
