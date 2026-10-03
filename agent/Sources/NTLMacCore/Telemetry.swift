import CryptoKit
import Foundation

public struct TelemetryResource: Sendable {
    public var serviceVersion: String
    /// Salted hash of the serial; see `pseudonymousHostID`.
    public var hostID: String
    public var osVersion: String

    public init(serviceVersion: String, hostID: String, osVersion: String) {
        self.serviceVersion = serviceVersion
        self.hostID = hostID
        self.osVersion = osVersion
    }

    public static func pseudonymousHostID(serial: String, salt: String) -> String {
        SHA256.hash(data: Data((salt + ":" + serial).utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

public enum PromptReason: String, Sendable {
    case enrol
    case adPasswordChanged = "ad_password_changed"
    case retryRejected = "retry_rejected"
    case validationFailed = "validation_failed"
}

/// Aggregates counters between exports and renders them as an OTLP/HTTP JSON
/// `ExportMetricsServiceRequest` (delta temporality). Schema: docs/telemetry-schema.md.
public struct TelemetryRecorder: Sendable {
    public static let schemaVersion = "1"
    /// Hosts that matched no allowlist rule are not reported by name.
    public static let unlistedHost = "(unlisted)"

    private let resource: TelemetryResource
    private var auth: [[String: String]: Int] = [:]
    private var prompts: [[String: String]: Int] = [:]
    private var trips: [[String: String]: Int] = [:]

    public init(resource: TelemetryResource) {
        self.resource = resource
    }

    public mutating func recordAuth(host: String, ruleId: String?, user: String?, outcome: Outcome) {
        let reportedHost = ruleId == nil ? Self.unlistedHost : (HostName.normalize(host) ?? Self.unlistedHost)
        auth[[
            "app.host": reportedHost,
            "allowlist.rule_id": ruleId ?? "",
            "enduser.id": user ?? "",
            "outcome": outcome.rawValue,
        ], default: 0] += 1
    }

    public mutating func recordPrompt(reason: PromptReason, user: String?) {
        prompts[["reason": reason.rawValue, "enduser.id": user ?? ""], default: 0] += 1
    }

    public mutating func recordBreakerTrip(host: String, user: String?) {
        trips[["app.host": HostName.normalize(host) ?? Self.unlistedHost, "enduser.id": user ?? ""], default: 0] += 1
    }

    /// Renders and clears the counters. The credential-state gauge is always included so
    /// silent-but-healthy devices still report in.
    public mutating func flush(credentialState: CredentialState, start: Date, end: Date) throws -> Data? {
        let s = Self.unixNano(start), e = Self.unixNano(end)
        var metrics: [OTLP.Metric] = []
        if let m = Self.sum("ntlmac.auth.requests", unit: "{request}", auth, s, e) { metrics.append(m) }
        if let m = Self.sum("ntlmac.credential.prompts", unit: "{prompt}", prompts, s, e) { metrics.append(m) }
        if let m = Self.sum("ntlmac.breaker.trips", unit: "{trip}", trips, s, e) { metrics.append(m) }
        metrics.append(OTLP.Metric(
            name: "ntlmac.credential.state", unit: "1", sum: nil,
            gauge: OTLP.Gauge(dataPoints: [OTLP.DataPoint(
                attributes: [.init("state", credentialState.rawValue)],
                startTimeUnixNano: nil, timeUnixNano: e, asInt: "1"
            )])
        ))

        let request = OTLP.ExportRequest(resourceMetrics: [OTLP.ResourceMetrics(
            resource: OTLP.Resource(attributes: [
                .init("service.name", "ntlmac"),
                .init("service.version", resource.serviceVersion),
                .init("host.id", resource.hostID),
                .init("os.type", "darwin"),
                .init("os.version", resource.osVersion),
                .init("ntlmac.schema", Self.schemaVersion),
            ]),
            scopeMetrics: [OTLP.ScopeMetrics(scope: .init(name: "com.example.ntlmac", version: resource.serviceVersion), metrics: metrics)]
        )])
        auth.removeAll()
        prompts.removeAll()
        trips.removeAll()
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try encoder.encode(request)
    }

    private static func sum(_ name: String, unit: String, _ counts: [[String: String]: Int], _ s: String, _ e: String) -> OTLP.Metric? {
        guard !counts.isEmpty else { return nil }
        let points = counts
            .map { attrs, n in
                OTLP.DataPoint(
                    attributes: attrs.sorted { $0.key < $1.key }.map { OTLP.KeyValue($0.key, $0.value) },
                    startTimeUnixNano: s, timeUnixNano: e, asInt: String(n)
                )
            }
            .sorted { $0.sortKey < $1.sortKey }
        return OTLP.Metric(name: name, unit: unit, sum: OTLP.Sum(dataPoints: points), gauge: nil)
    }

    private static func unixNano(_ date: Date) -> String {
        // Integer seconds + millis avoids Double rounding in the 19-digit result.
        let ms = Int64((date.timeIntervalSince1970 * 1000).rounded())
        return String(ms) + "000000"
    }
}

/// Minimal OTLP/JSON model (opentelemetry-proto metrics v1, proto3 JSON mapping).
enum OTLP {
    struct ExportRequest: Encodable { var resourceMetrics: [ResourceMetrics] }
    struct ResourceMetrics: Encodable { var resource: Resource; var scopeMetrics: [ScopeMetrics] }
    struct Resource: Encodable { var attributes: [KeyValue] }
    struct ScopeMetrics: Encodable { var scope: Scope; var metrics: [Metric] }
    struct Scope: Encodable { var name: String; var version: String }

    struct Metric: Encodable {
        var name: String
        var unit: String
        var sum: Sum?
        var gauge: Gauge?
    }

    struct Sum: Encodable {
        var aggregationTemporality = 1 // AGGREGATION_TEMPORALITY_DELTA
        var isMonotonic = true
        var dataPoints: [DataPoint]
    }

    struct Gauge: Encodable { var dataPoints: [DataPoint] }

    struct DataPoint: Encodable {
        var attributes: [KeyValue]
        var startTimeUnixNano: String?
        var timeUnixNano: String
        var asInt: String // int64 is a string in proto3 JSON

        var sortKey: String { attributes.map { $0.key + "=" + $0.value.stringValue }.joined(separator: "&") }
    }

    struct KeyValue: Encodable {
        var key: String
        var value: AnyValue
        init(_ key: String, _ value: String) {
            self.key = key
            self.value = AnyValue(stringValue: value)
        }
    }

    struct AnyValue: Encodable { var stringValue: String }
}
