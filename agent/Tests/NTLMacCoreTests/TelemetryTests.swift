import Foundation
import Testing
@testable import NTLMacCore

@Suite struct TelemetryTests {
    let resource = TelemetryResource(serviceVersion: "0.1.0", hostID: "abc123", osVersion: "26.0")
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let end = Date(timeIntervalSince1970: 1_800_000_300)

    private func flushJSON(_ recorder: inout TelemetryRecorder, state: CredentialState = .ok) throws -> [String: Any] {
        let data = try #require(try recorder.flush(credentialState: state, start: start, end: end))
        return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func metrics(_ json: [String: Any]) -> [[String: Any]] {
        let rm = (json["resourceMetrics"] as? [[String: Any]])?.first
        let sm = (rm?["scopeMetrics"] as? [[String: Any]])?.first
        return sm?["metrics"] as? [[String: Any]] ?? []
    }

    private func metric(_ name: String, in json: [String: Any]) -> [String: Any]? {
        metrics(json).first { $0["name"] as? String == name }
    }

    private func attrs(_ point: [String: Any]) -> [String: String] {
        var out: [String: String] = [:]
        for a in point["attributes"] as? [[String: Any]] ?? [] {
            out[a["key"] as! String] = (a["value"] as? [String: Any])?["stringValue"] as? String
        }
        return out
    }

    @Test func resourceCarriesServiceAndSchemaAttributes() throws {
        var recorder = TelemetryRecorder(resource: resource)
        let json = try flushJSON(&recorder)
        let rm = try #require((json["resourceMetrics"] as? [[String: Any]])?.first)
        let res = try #require(rm["resource"] as? [String: Any])
        let a = attrs(res)
        #expect(a["service.name"] == "ntlmac")
        #expect(a["service.version"] == "0.1.0")
        #expect(a["host.id"] == "abc123")
        #expect(a["os.version"] == "26.0")
        #expect(a["ntlmac.schema"] == "1")
    }

    @Test func authCountsAggregateByHostRuleUserOutcome() throws {
        var recorder = TelemetryRecorder(resource: resource)
        recorder.recordAuth(host: "app.corp.example", ruleId: "r1", user: "jbloggs", outcome: .supplied)
        recorder.recordAuth(host: "APP.corp.example.", ruleId: "r1", user: "jbloggs", outcome: .supplied)
        recorder.recordAuth(host: "app.corp.example", ruleId: "r1", user: "asmith", outcome: .supplied)
        recorder.recordAuth(host: "app.corp.example", ruleId: "r1", user: "jbloggs", outcome: .retryCancelled)

        let json = try flushJSON(&recorder)
        let sum = try #require(metric("ntlmac.auth.requests", in: json)?["sum"] as? [String: Any])
        #expect(sum["aggregationTemporality"] as? Int == 1) // DELTA
        #expect(sum["isMonotonic"] as? Bool == true)
        let points = try #require(sum["dataPoints"] as? [[String: Any]])
        #expect(points.count == 3)
        let jb = try #require(points.first {
            attrs($0)["enduser.id"] == "jbloggs" && attrs($0)["outcome"] == "supplied"
        })
        #expect(jb["asInt"] as? String == "2")
        #expect(attrs(jb)["app.host"] == "app.corp.example")
        #expect(attrs(jb)["allowlist.rule_id"] == "r1")
        #expect(jb["startTimeUnixNano"] as? String == "1800000000000000000")
        #expect(jb["timeUnixNano"] as? String == "1800000300000000000")
    }

    @Test func unlistedHostsAreRedacted() throws {
        var recorder = TelemetryRecorder(resource: resource)
        recorder.recordAuth(host: "private-site.example", ruleId: nil, user: "jbloggs", outcome: .notAllowlisted)
        let json = try flushJSON(&recorder)
        let sum = try #require(metric("ntlmac.auth.requests", in: json)?["sum"] as? [String: Any])
        let point = try #require((sum["dataPoints"] as? [[String: Any]])?.first)
        #expect(attrs(point)["app.host"] == TelemetryRecorder.unlistedHost)
        #expect(attrs(point)["allowlist.rule_id"] == "")
        #expect(!String(decoding: try JSONSerialization.data(withJSONObject: json), as: UTF8.self).contains("private-site"))
    }

    @Test func flushResetsDeltaCounters() throws {
        var recorder = TelemetryRecorder(resource: resource)
        recorder.recordAuth(host: "app.corp.example", ruleId: "r1", user: "jbloggs", outcome: .supplied)
        _ = try flushJSON(&recorder)
        let second = try flushJSON(&recorder)
        #expect(metric("ntlmac.auth.requests", in: second) == nil)
    }

    @Test func credentialStateGaugeAlwaysPresent() throws {
        var recorder = TelemetryRecorder(resource: resource)
        let json = try flushJSON(&recorder, state: .suspect)
        let gauge = try #require(metric("ntlmac.credential.state", in: json)?["gauge"] as? [String: Any])
        let point = try #require((gauge["dataPoints"] as? [[String: Any]])?.first)
        #expect(attrs(point)["state"] == "suspect")
        #expect(point["asInt"] as? String == "1")
    }

    @Test func promptsAndBreakerTripsAreCounted() throws {
        var recorder = TelemetryRecorder(resource: resource)
        recorder.recordPrompt(reason: .adPasswordChanged, user: "jbloggs")
        recorder.recordBreakerTrip(host: "app.corp.example", user: "jbloggs")
        let json = try flushJSON(&recorder)
        let prompts = try #require(metric("ntlmac.credential.prompts", in: json)?["sum"] as? [String: Any])
        #expect(attrs(try #require((prompts["dataPoints"] as? [[String: Any]])?.first))["reason"] == "ad_password_changed")
        let trips = try #require(metric("ntlmac.breaker.trips", in: json)?["sum"] as? [String: Any])
        #expect(attrs(try #require((trips["dataPoints"] as? [[String: Any]])?.first))["app.host"] == "app.corp.example")
    }

    /// `NTLMAC_SAMPLE_OTLP_OUT=/path swift test` writes a realistic payload for validating
    /// against a real collector (see gateway/otel-collector.local.yaml).
    @Test func writesSamplePayloadWhenRequested() throws {
        guard let out = ProcessInfo.processInfo.environment["NTLMAC_SAMPLE_OTLP_OUT"] else { return }
        var recorder = TelemetryRecorder(resource: resource)
        recorder.recordAuth(host: "app.corp.example", ruleId: "r1", user: "jbloggs", outcome: .supplied)
        recorder.recordAuth(host: "elsewhere.example", ruleId: nil, user: "jbloggs", outcome: .notAllowlisted)
        recorder.recordPrompt(reason: .enrol, user: "jbloggs")
        recorder.recordBreakerTrip(host: "app.corp.example", user: "jbloggs")
        let now = Date()
        let data = try #require(try recorder.flush(credentialState: .ok, start: now.addingTimeInterval(-300), end: now))
        try data.write(to: URL(fileURLWithPath: out))
    }

    @Test func pseudonymousHostIDIsStableSaltedAndNotTheSerial() {
        let a = TelemetryResource.pseudonymousHostID(serial: "C02XYZ", salt: "s1")
        #expect(a == TelemetryResource.pseudonymousHostID(serial: "C02XYZ", salt: "s1"))
        #expect(a != TelemetryResource.pseudonymousHostID(serial: "C02XYZ", salt: "s2"))
        #expect(!a.contains("C02XYZ"))
        #expect(a.count == 64)
    }
}
