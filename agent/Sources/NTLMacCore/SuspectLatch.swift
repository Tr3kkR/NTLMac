import Foundation

/// Remembers the suspect latch across agent restarts (crash, logout), so a stale password
/// still in the Keychain doesn't get one more attempt from a fresh process. Set when the
/// breaker trips or the AD password changes; cleared only after a new password has been
/// validated and stored (`AgentService.credentialReplaced`).
public protocol SuspectLatch: Sendable {
    var isSet: Bool { get }
    func set() throws
    func clear() throws
}

/// For tests.
public final class InMemorySuspectLatch: SuspectLatch, @unchecked Sendable {
    public struct WriteFailed: Error {}

    private let lock = NSLock()
    private var value: Bool
    private let failWrites: Bool

    public init(set: Bool = false, failWrites: Bool = false) {
        value = set
        self.failWrites = failWrites
    }

    public var isSet: Bool { lock.withLock { value } }

    public func set() throws {
        try lock.withLock {
            if failWrites { throw WriteFailed() }
            value = true
        }
    }

    public func clear() throws {
        try lock.withLock {
            if failWrites { throw WriteFailed() }
            value = false
        }
    }
}

/// The latch as an empty marker file: present means suspect. The file holds nothing, but
/// it lives in the user's private support folder (0700) like the telemetry queue.
public struct FileSuspectLatch: SuspectLatch {
    /// `~/Library/Application Support/com.example.ntlmac/credential-suspect`
    public static func defaultURL(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent("Library/Application Support/com.example.ntlmac/credential-suspect")
    }

    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    public var isSet: Bool { FileManager.default.fileExists(atPath: url.path) }

    public func set() throws {
        let fm = FileManager.default
        let dir = url.deletingLastPathComponent()
        if !fm.fileExists(atPath: dir.path) {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        guard fm.createFile(atPath: url.path, contents: Data(), attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    public func clear() throws {
        do {
            try FileManager.default.removeItem(at: url)
        } catch CocoaError.fileNoSuchFile {
            // already clear
        }
    }
}
