import Foundation

// MARK: On-disk queue

public struct QueuedPayload: Sendable, Equatable {
    public var url: URL
    public var enqueuedAt: Date
    public var data: Data
}

/// Telemetry payloads waiting to be sent, one file each, so data recorded while the gateway
/// is unreachable (off VPN, asleep) survives restarts. Bounded by age and total size; the
/// oldest payloads are dropped first. The directory is private to the user because payloads
/// carry `enduser.id`.
public struct TelemetryQueue: Sendable {
    public static let defaultMaxAge: TimeInterval = 7 * 86_400
    public static let defaultMaxBytes = 5 * 1024 * 1024

    /// `~/Library/Application Support/com.example.ntlmac/telemetry`
    public static func defaultDirectory(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
        home.appendingPathComponent("Library/Application Support/com.example.ntlmac/telemetry", isDirectory: true)
    }

    public let directory: URL
    public let maxAge: TimeInterval
    public let maxBytes: Int

    public init(directory: URL, maxAge: TimeInterval = defaultMaxAge, maxBytes: Int = defaultMaxBytes) throws {
        self.directory = directory
        self.maxAge = maxAge
        self.maxBytes = maxBytes
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }

    public func enqueue(_ payload: Data, at now: Date) throws {
        let fm = FileManager.default
        let millis = Int64((now.timeIntervalSince1970 * 1000).rounded())
        let taken = Set(try entries().filter { $0.millis == millis }.map(\.sequence))
        let sequence = (0...).first { !taken.contains($0) }!
        // Write privately under a temporary name, then rename into place, so a crash never
        // leaves a truncated payload that looks queued.
        let temp = directory.appendingPathComponent(".tmp-\(UUID().uuidString)")
        guard fm.createFile(atPath: temp.path, contents: payload, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        try fm.moveItem(at: temp, to: directory.appendingPathComponent(Self.fileName(millis: millis, sequence: sequence)))
        try prune(now: now)
    }

    /// Everything still queued, oldest first, after dropping what is over the caps.
    public func pending(now: Date) throws -> [QueuedPayload] {
        try prune(now: now)
        return try entries().map { e in
            QueuedPayload(url: e.url, enqueuedAt: Date(timeIntervalSince1970: Double(e.millis) / 1000), data: try Data(contentsOf: e.url))
        }
    }

    public func remove(_ payload: QueuedPayload) throws {
        do {
            try FileManager.default.removeItem(at: payload.url)
        } catch CocoaError.fileNoSuchFile {
            // already gone
        }
    }

    private func prune(now: Date) throws {
        let fm = FileManager.default
        let oldestAllowed = Int64(((now.timeIntervalSince1970 - maxAge) * 1000).rounded())
        var kept: [(entry: Entry, size: Int)] = []
        for e in try entries() {
            if e.millis < oldestAllowed {
                try? fm.removeItem(at: e.url)
            } else {
                kept.append((e, (try? fm.attributesOfItem(atPath: e.url.path)[.size] as? Int) ?? 0))
            }
        }
        var total = kept.reduce(0) { $0 + $1.size }
        for item in kept where total > maxBytes {
            try? fm.removeItem(at: item.entry.url)
            total -= item.size
        }
    }

    private struct Entry {
        var url: URL
        var millis: Int64
        var sequence: Int
    }

    /// Queued files, oldest first. Anything not named by `fileName` is ignored.
    private func entries() throws -> [Entry] {
        try FileManager.default.contentsOfDirectory(atPath: directory.path)
            .compactMap { name -> Entry? in
                let parts = name.split(separator: "-")
                guard name.hasSuffix(".json"), parts.count == 2,
                      let millis = Int64(parts[0]), parts[0].count == 15,
                      let sequence = Int(parts[1].dropLast(5)), parts[1].count == 11
                else { return nil }
                return Entry(url: directory.appendingPathComponent(name), millis: millis, sequence: sequence)
            }
            .sorted { ($0.millis, $0.sequence) < ($1.millis, $1.sequence) }
    }

    /// Fixed-width, so names sort in enqueue order.
    private static func fileName(millis: Int64, sequence: Int) -> String {
        String(format: "%015lld-%06d.json", millis, sequence)
    }
}

// MARK: Transport

public enum DeliveryResult: Sendable, Equatable {
    case delivered
    /// The gateway refused this payload for good (malformed, too large): don't retry it.
    case rejected(status: Int)
}

public protocol TelemetryTransport: Sendable {
    /// Throws when delivery may succeed later (network down, gateway overloaded).
    func send(_ payload: Data) async throws -> DeliveryResult
}

/// OTLP/HTTP JSON to the collector gateway. HTTPS only, because payloads carry usernames.
/// Not done yet: mTLS with the Jamf SCEP device certificate (a URLSession delegate
/// answering the client-certificate challenge), pending confirmation that the certificate
/// is available.
public struct OTLPHTTPTransport: TelemetryTransport {
    public struct InvalidEndpoint: Error {}
    public struct RetryableStatus: Error, Equatable {
        public var status: Int
    }

    public let endpoint: URL
    private let session: URLSession

    /// `endpoint` is the full metrics URL from the profile, e.g. `https://gw:4318/v1/metrics`.
    public init(endpoint: String, session: URLSession = .shared) throws {
        guard let url = URL(string: endpoint), url.scheme?.lowercased() == "https", url.host != nil else {
            throw InvalidEndpoint()
        }
        self.endpoint = url
        self.session = session
    }

    public func send(_ payload: Data) async throws -> DeliveryResult {
        var request = URLRequest(url: endpoint, timeoutInterval: 30)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = payload
        let (_, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        switch status {
        case 200 ..< 300: return .delivered
        case 408, 429: throw RetryableStatus(status: status)
        case 400 ..< 500: return .rejected(status: status)
        default: throw RetryableStatus(status: status)
        }
    }
}

/// The gateway endpoint comes from the managed profile, which can change while the agent
/// runs. With no endpoint, sends fail as retryable, so payloads wait in the queue.
public actor SwitchableTransport: TelemetryTransport {
    public struct NotConfigured: Error {}

    private var current: TelemetryTransport?

    public init(_ transport: TelemetryTransport? = nil) {
        current = transport
    }

    public func use(_ transport: TelemetryTransport?) {
        current = transport
    }

    public func send(_ payload: Data) async throws -> DeliveryResult {
        guard let current else { throw NotConfigured() }
        return try await current.send(payload)
    }
}

// MARK: Exporter

public struct FlushReport: Sendable, Equatable {
    public var delivered: Int
    public var dropped: Int
    public var remaining: Int

    public init(delivered: Int, dropped: Int, remaining: Int) {
        self.delivered = delivered
        self.dropped = dropped
        self.remaining = remaining
    }
}

/// Owns the agent's `TelemetryRecorder`. Every `interval` the agent calls `flush`: the
/// interval's counters are queued on disk, then the queue is sent oldest first, stopping
/// at the first retryable failure so payloads stay in order.
public actor TelemetryExporter {
    public static let interval: TimeInterval = 300

    private var recorder: TelemetryRecorder
    private let queue: TelemetryQueue
    private let transport: TelemetryTransport
    private var periodStart: Date
    private var sending = false

    public init(recorder: TelemetryRecorder, queue: TelemetryQueue, transport: TelemetryTransport, start: Date) {
        self.recorder = recorder
        self.queue = queue
        self.transport = transport
        self.periodStart = start
    }

    public func record(_ body: @Sendable (inout TelemetryRecorder) -> Void) {
        body(&recorder)
    }

    public func flush(credentialState: CredentialState, now: Date) async throws -> FlushReport {
        if let payload = try recorder.flush(credentialState: credentialState, start: periodStart, end: now) {
            try queue.enqueue(payload, at: now)
        }
        periodStart = now

        var delivered = 0, dropped = 0
        // Actor methods can interleave at `await`; only one flush sends at a time.
        if !sending {
            sending = true
            defer { sending = false }
            sendLoop: for item in try queue.pending(now: now) {
                do {
                    switch try await transport.send(item.data) {
                    case .delivered: delivered += 1
                    case .rejected: dropped += 1
                    }
                    try queue.remove(item)
                } catch {
                    break sendLoop
                }
            }
        }
        return FlushReport(delivered: delivered, dropped: dropped, remaining: try queue.pending(now: now).count)
    }
}
