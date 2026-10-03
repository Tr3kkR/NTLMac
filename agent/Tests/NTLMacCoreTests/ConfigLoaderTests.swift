import Foundation
import Testing
@testable import NTLMacCore

@Suite struct ConfigLoaderTests {
    let killDate = Date(timeIntervalSince1970: 1_900_000_000)

    var minimal: [String: Any] {
        [
            "enabled": true,
            "killDate": killDate,
            "realm": "CORP.EXAMPLE",
            "netbiosDomain": "CORP",
            "rules": [["id": "corp-wide", "pattern": "*.corp.example"]],
        ]
    }

    @Test func decodesManagedPreferencesDictionary() throws {
        var prefs = minimal
        prefs["deny"] = ["adfs.corp.example"]
        prefs["httpExceptions"] = [["host": "old.corp.example", "expires": killDate]]
        prefs["otlpEndpoint"] = "https://otel.corp.example:4318"
        prefs["PayloadUUID"] = "ignored-extra-key"

        let config = try ConfigLoader.decode(preferences: prefs)

        #expect(config.enabled)
        #expect(config.killDate == killDate)
        #expect(config.rules == [AllowlistRule(id: "corp-wide", pattern: "*.corp.example")])
        #expect(config.deny == ["adfs.corp.example"])
        #expect(config.httpExceptions == [HTTPException(host: "old.corp.example", expires: killDate)])
        #expect(config.otlpEndpoint == "https://otel.corp.example:4318")
    }

    @Test func optionalListsDefaultToEmpty() throws {
        let config = try ConfigLoader.decode(preferences: minimal)
        #expect(config.deny.isEmpty)
        #expect(config.httpExceptions.isEmpty)
        #expect(config.otlpEndpoint == nil)
    }

    @Test(arguments: ["enabled", "killDate", "realm", "netbiosDomain", "rules"])
    func missingRequiredKeyFailsClosed(key: String) {
        var prefs = minimal
        prefs[key] = nil
        #expect(throws: (any Error).self) { try ConfigLoader.decode(preferences: prefs) }
    }

    @Test func jamfProfileTemplateDecodes() throws {
        let template = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("packaging/profiles/com.example.ntlmac.plist")
        let plist = try PropertyListSerialization.propertyList(from: Data(contentsOf: template), format: nil)
        let config = try ConfigLoader.decode(preferences: try #require(plist as? [String: Any]))
        #expect(config.enabled)
        #expect(!config.rules.isEmpty)
    }

    @Test func decodesSpikeJSONFile() throws {
        let json = """
        {"enabled": true, "killDate": "2030-01-01T00:00:00Z", "realm": "CORP.EXAMPLE",
         "netbiosDomain": "CORP", "rules": [{"id": "test", "pattern": "localhost"}]}
        """
        let config = try ConfigLoader.decode(json: Data(json.utf8))
        #expect(config.rules.first?.pattern == "localhost")
        #expect(config.killDate == ISO8601DateFormatter().date(from: "2030-01-01T00:00:00Z"))
    }
}
