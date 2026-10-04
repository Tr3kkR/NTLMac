import Foundation
import Testing
@testable import NTLMacCore

private let t0 = Date(timeIntervalSince1970: 1_800_000_000)
private let day: TimeInterval = 86_400

private func tempDirectory() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("ntlmac-queue-\(UUID().uuidString)")
}

private func payload(_ text: String) -> Data { Data(text.utf8) }

@Suite struct TelemetryQueueTests {
    @Test func returnsPayloadsOldestFirst() throws {
        let queue = try TelemetryQueue(directory: tempDirectory())
        try queue.enqueue(payload("b"), at: t0.addingTimeInterval(60))
        try queue.enqueue(payload("a"), at: t0)
        try queue.enqueue(payload("c"), at: t0.addingTimeInterval(120))
        #expect(try queue.pending(now: t0.addingTimeInterval(180)).map(\.data) == ["a", "b", "c"].map(payload))
    }

    @Test func sameInstantKeepsInsertionOrder() throws {
        let queue = try TelemetryQueue(directory: tempDirectory())
        for p in ["1", "2", "3"] { try queue.enqueue(payload(p), at: t0) }
        #expect(try queue.pending(now: t0).map(\.data) == ["1", "2", "3"].map(payload))
    }

    @Test func removeDeletesOnePayload() throws {
        let queue = try TelemetryQueue(directory: tempDirectory())
        try queue.enqueue(payload("a"), at: t0)
        try queue.enqueue(payload("b"), at: t0.addingTimeInterval(1))
        try queue.remove(try queue.pending(now: t0)[0])
        #expect(try queue.pending(now: t0).map(\.data) == [payload("b")])
    }

    @Test func dropsPayloadsOlderThanSevenDays() throws {
        let queue = try TelemetryQueue(directory: tempDirectory())
        try queue.enqueue(payload("old"), at: t0)
        try queue.enqueue(payload("new"), at: t0.addingTimeInterval(6 * day))
        #expect(try queue.pending(now: t0.addingTimeInterval(7 * day + 1)).map(\.data) == [payload("new")])
    }

    @Test func dropsOldestFirstToStayUnderTheByteCap() throws {
        let queue = try TelemetryQueue(directory: tempDirectory(), maxBytes: 10)
        try queue.enqueue(payload("aaaa"), at: t0)
        try queue.enqueue(payload("bbbb"), at: t0.addingTimeInterval(1))
        try queue.enqueue(payload("cccc"), at: t0.addingTimeInterval(2)) // 12 bytes > 10: drop "aaaa"
        #expect(try queue.pending(now: t0.addingTimeInterval(3)).map(\.data) == ["bbbb", "cccc"].map(payload))
    }

    @Test func defaultCapsAreSevenDaysAndFiveMegabytes() {
        #expect(TelemetryQueue.defaultMaxAge == 7 * day)
        #expect(TelemetryQueue.defaultMaxBytes == 5 * 1024 * 1024)
    }

    @Test func survivesARestart() throws {
        let dir = tempDirectory()
        try TelemetryQueue(directory: dir).enqueue(payload("persisted"), at: t0)
        #expect(try TelemetryQueue(directory: dir).pending(now: t0).map(\.data) == [payload("persisted")])
    }

    @Test func queueIsPrivateToTheUser() throws {
        let dir = tempDirectory()
        let queue = try TelemetryQueue(directory: dir)
        try queue.enqueue(payload("a"), at: t0)
        let fm = FileManager.default
        #expect(try fm.attributesOfItem(atPath: dir.path)[.posixPermissions] as? Int == 0o700)
        let file = try queue.pending(now: t0)[0].url
        #expect(try fm.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int == 0o600)
    }

    @Test func ignoresStrayFiles() throws {
        let dir = tempDirectory()
        let queue = try TelemetryQueue(directory: dir)
        try Data("x".utf8).write(to: dir.appendingPathComponent(".DS_Store"))
        try Data("x".utf8).write(to: dir.appendingPathComponent("notes.txt"))
        try queue.enqueue(payload("a"), at: t0)
        #expect(try queue.pending(now: t0).map(\.data) == [payload("a")])
    }
}

/// Answers each send from a script; records what it was given.
private actor ScriptedTransport: TelemetryTransport {
    enum Step { case deliver, reject(Int), fail }
    private var script: [Step]
    private(set) var sent: [Data] = []

    init(_ script: [Step]) { self.script = script }

    func send(_ payload: Data) async throws -> DeliveryResult {
        sent.append(payload)
        switch script.isEmpty ? .deliver : script.removeFirst() {
        case .deliver: return .delivered
        case let .reject(status): return .rejected(status: status)
        case .fail: throw URLError(.notConnectedToInternet)
        }
    }
}

private func exporter(_ transport: ScriptedTransport, queue: TelemetryQueue) -> TelemetryExporter {
    TelemetryExporter(
        recorder: TelemetryRecorder(resource: TelemetryResource(serviceVersion: "0.1.0", hostID: "h", osVersion: "26.0")),
        queue: queue,
        transport: transport,
        start: t0
    )
}

@Suite struct TelemetryExporterTests {
    @Test func flushQueuesTheRecordersPayloadAndDeliversIt() async throws {
        let transport = ScriptedTransport([.deliver])
        let queue = try TelemetryQueue(directory: tempDirectory())
        let exporter = exporter(transport, queue: queue)
        await exporter.record { $0.recordAuth(host: "app.corp.example", ruleId: "r", user: "jbloggs", outcome: .supplied) }
        let report = try await exporter.flush(credentialState: .ok, now: t0.addingTimeInterval(300))
        #expect(report == FlushReport(delivered: 1, dropped: 0, remaining: 0))
        let sent = try #require(await transport.sent.first)
        let json = String(decoding: sent, as: UTF8.self)
        #expect(json.contains("ntlmac.auth.requests"))
        #expect(json.contains("ntlmac.credential.state"))
        #expect(try queue.pending(now: t0.addingTimeInterval(300)).isEmpty)
    }

    @Test func failedSendKeepsEverythingForNextTimeInOrder() async throws {
        let transport = ScriptedTransport([.fail, .deliver, .deliver])
        let queue = try TelemetryQueue(directory: tempDirectory())
        let exporter = exporter(transport, queue: queue)
        let first = try await exporter.flush(credentialState: .ok, now: t0.addingTimeInterval(300))
        #expect(first == FlushReport(delivered: 0, dropped: 0, remaining: 1))
        let second = try await exporter.flush(credentialState: .ok, now: t0.addingTimeInterval(600))
        #expect(second == FlushReport(delivered: 2, dropped: 0, remaining: 0))
        let sent = await transport.sent
        #expect(sent.count == 3)
        #expect(sent[1] == sent[0], "the failed payload is retried first")
    }

    @Test func stopsAtTheFirstFailureSoLaterPayloadsKeepTheirOrder() async throws {
        let queue = try TelemetryQueue(directory: tempDirectory())
        try queue.enqueue(payload("older-1"), at: t0)
        try queue.enqueue(payload("older-2"), at: t0.addingTimeInterval(1))
        let transport = ScriptedTransport([.deliver, .fail])
        let report = try await exporter(transport, queue: queue).flush(credentialState: .ok, now: t0.addingTimeInterval(300))
        #expect(report == FlushReport(delivered: 1, dropped: 0, remaining: 2))
        #expect(await transport.sent.count == 2)
    }

    @Test func permanentlyRejectedPayloadsAreDroppedNotRetriedForever() async throws {
        let transport = ScriptedTransport([.reject(400)])
        let queue = try TelemetryQueue(directory: tempDirectory())
        let report = try await exporter(transport, queue: queue).flush(credentialState: .ok, now: t0.addingTimeInterval(300))
        #expect(report == FlushReport(delivered: 0, dropped: 1, remaining: 0))
    }

    @Test func eachFlushCoversTheIntervalSinceThePreviousOne() async throws {
        let transport = ScriptedTransport([])
        let exporter = exporter(transport, queue: try TelemetryQueue(directory: tempDirectory()))
        await exporter.record { $0.recordPrompt(reason: .enrol, user: "jbloggs") }
        _ = try await exporter.flush(credentialState: .ok, now: t0.addingTimeInterval(300))
        await exporter.record { $0.recordPrompt(reason: .enrol, user: "jbloggs") }
        _ = try await exporter.flush(credentialState: .ok, now: t0.addingTimeInterval(600))
        let sent = await transport.sent.map { String(decoding: $0, as: UTF8.self) }
        #expect(sent[0].contains(#""startTimeUnixNano":"1800000000000000000""#))
        #expect(sent[1].contains(#""startTimeUnixNano":"1800000300000000000""#))
        #expect(sent[1].contains(#""timeUnixNano":"1800000600000000000""#))
    }
}

/// Serves canned responses to URLSession and records the requests it saw.
private final class StubProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var status = 200
    nonisolated(unsafe) static var requests: [URLRequest] = []
    nonisolated(unsafe) static var bodies: [Data] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requests.append(request)
        if let stream = request.httpBodyStream {
            stream.open()
            var body = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buffer, maxLength: buffer.count)
                if n <= 0 { break }
                body.append(buffer, count: n)
            }
            stream.close()
            Self.bodies.append(body)
        } else {
            Self.bodies.append(request.httpBody ?? Data())
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: Self.status, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data())
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@Suite(.serialized) struct OTLPHTTPTransportTests {
    private func transport() throws -> OTLPHTTPTransport {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return try OTLPHTTPTransport(endpoint: "https://otel.corp.example:4318/v1/metrics", session: URLSession(configuration: config))
    }

    @Test func postsJSONToTheConfiguredEndpoint() async throws {
        StubProtocol.status = 200
        StubProtocol.requests = []
        StubProtocol.bodies = []
        #expect(try await transport().send(payload(#"{"resourceMetrics":[]}"#)) == .delivered)
        let request = try #require(StubProtocol.requests.first)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.absoluteString == "https://otel.corp.example:4318/v1/metrics")
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
        #expect(StubProtocol.bodies == [payload(#"{"resourceMetrics":[]}"#)])
    }

    @Test(arguments: [(200, true), (204, true), (400, false), (413, false)])
    func mapsFinalStatuses(status: Int, delivered: Bool) async throws {
        StubProtocol.status = status
        let result = try await transport().send(payload("{}"))
        #expect(result == (delivered ? .delivered : .rejected(status: status)))
    }

    @Test(arguments: [408, 429, 500, 503])
    func retryableStatusesThrowSoThePayloadIsKept(status: Int) async throws {
        StubProtocol.status = status
        await #expect(throws: OTLPHTTPTransport.RetryableStatus(status: status)) { try await transport().send(payload("{}")) }
    }

    @Test(arguments: ["http://otel.corp.example:4318/v1/metrics", "not a url", "file:///tmp/x"])
    func refusesAnythingButHTTPS(endpoint: String) {
        #expect(throws: OTLPHTTPTransport.InvalidEndpoint.self) { try OTLPHTTPTransport(endpoint: endpoint) }
    }
}
