import Foundation
import Security
import Testing
@testable import NTLMacCore

private let request = AuthRequest(requestId: "n:1", host: "app.corp.example", port: 443, urlScheme: "https", authScheme: "ntlm", isProxy: false)

/// What this test process satisfies (its own designated requirement).
private func ownRequirement() throws -> String {
    var code: SecCode?
    var staticCode: SecStaticCode?
    var requirement: SecRequirement?
    var text: CFString?
    try #require(SecCodeCopySelf([], &code) == errSecSuccess)
    try #require(SecCodeCopyStaticCode(code!, [], &staticCode) == errSecSuccess)
    try #require(SecCodeCopyDesignatedRequirement(staticCode!, [], &requirement) == errSecSuccess)
    try #require(SecRequirementCopyString(requirement!, [], &text) == errSecSuccess)
    return text! as String
}

private func tempURL(_ name: String) -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("ntlmac-\(name)-\(UUID().uuidString)")
}

@Suite struct AgentIdentityTests {
    @Test func machServiceNameIsTheAgentIdentifier() {
        #expect(AgentXPC.machServiceName == "com.example.ntlmac.agent")
        #expect(AgentXPC.machServiceName == CodeSigningPolicy.defaultAgentIdentifier)
    }

    @Test func launchAgentTemplateRegistersTheMachService() throws {
        let template = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("packaging/launchd/com.example.ntlmac.agent.plist")
        let plist = try #require(try PropertyListSerialization.propertyList(from: Data(contentsOf: template), format: nil) as? [String: Any])
        #expect(plist["Label"] as? String == AgentXPC.machServiceName)
        #expect((plist["MachServices"] as? [String: Bool])?[AgentXPC.machServiceName] == true)
        #expect(plist["RunAtLoad"] as? Bool == true)
        #expect(plist["KeepAlive"] as? Bool == true)
    }

    @Test func anAdHocSignedProcessHasNoTeamSoNoPolicy() throws {
        #expect(try CodeSigning.currentTeamID() == nil)
        #expect(try CodeSigningPolicy.forCurrentProcess() == nil)
    }

    @Test func telemetryQueueLivesInTheUsersApplicationSupport() {
        let home = URL(fileURLWithPath: "/Users/jbloggs")
        #expect(TelemetryQueue.defaultDirectory(home: home).path == "/Users/jbloggs/Library/Application Support/com.example.ntlmac/telemetry")
    }
}

@Suite struct DebugOverridesTests {
    @Test func noEnvironmentMeansNoOverrides() {
        #expect(DebugOverrides.fromEnvironment([:]) == DebugOverrides())
        #expect(DebugOverrides().isEmpty)
    }

    @Test func readsEveryOverrideInDebugBuilds() {
        let o = DebugOverrides.fromEnvironment([
            "NTLMAC_MACH_SERVICE": "com.example.ntlmac.agent.test-1",
            "NTLMAC_AGENT_REQUIREMENT": #"cdhash H"aa""#,
            "NTLMAC_SHIM_REQUIREMENT": #"cdhash H"bb""#,
            "NTLMAC_CONFIG": "/tmp/config.json",
            "NTLMAC_TEST_CREDENTIAL_FILE": "/tmp/credential",
            "NTLMAC_TELEMETRY_DIR": "/tmp/telemetry",
            "UNRELATED": "x",
        ])
        #expect(o.machServiceName == "com.example.ntlmac.agent.test-1")
        #expect(o.agentRequirement == #"cdhash H"aa""#)
        #expect(o.shimRequirement == #"cdhash H"bb""#)
        #expect(o.configFile == "/tmp/config.json")
        #expect(o.credentialFile == "/tmp/credential")
        #expect(o.telemetryDirectory == "/tmp/telemetry")
        #expect(!o.isEmpty)
    }

    @Test func emptyValuesAreIgnored() {
        #expect(DebugOverrides.fromEnvironment(["NTLMAC_MACH_SERVICE": ""]).isEmpty)
    }
}

@Suite struct FileCredentialStoreTests {
    @Test func readsAccountColonPassword() throws {
        let url = tempURL("cred")
        try Data("jbloggs:Pass:w0rd!\n".utf8).write(to: url)
        #expect(try FileCredentialStore(url: url).read() == Credential(account: "jbloggs", password: "Pass:w0rd!"))
    }

    @Test func missingFileIsAMissingCredential() throws {
        #expect(try FileCredentialStore(url: tempURL("absent")).read() == nil)
    }

    @Test func malformedFileThrows() throws {
        let url = tempURL("bad")
        try Data("no-separator".utf8).write(to: url)
        #expect(throws: KeychainError.malformedItem) { try FileCredentialStore(url: url).read() }
    }

    @Test func writeAndDeleteRoundTripPrivately() throws {
        let store = FileCredentialStore(url: tempURL("rw"))
        try store.write(Credential(account: "jbloggs", password: "Passw0rd!"))
        #expect(try store.read() == Credential(account: "jbloggs", password: "Passw0rd!"))
        #expect(try FileManager.default.attributesOfItem(atPath: store.url.path)[.posixPermissions] as? Int == 0o600)
        try store.delete()
        try store.delete()
        #expect(try store.read() == nil)
    }
}

private struct FixedTransport: TelemetryTransport {
    func send(_ payload: Data) async throws -> DeliveryResult { .rejected(status: 400) }
}

@Suite struct SwitchableTransportTests {
    @Test func unconfiguredTransportKeepsPayloadsQueued() async {
        await #expect(throws: SwitchableTransport.NotConfigured.self) { try await SwitchableTransport().send(Data()) }
    }

    @Test func delegatesToTheCurrentTransport() async throws {
        let transport = SwitchableTransport()
        await transport.use(FixedTransport())
        #expect(try await transport.send(Data()) == .rejected(status: 400))
        await transport.use(nil)
        await #expect(throws: SwitchableTransport.NotConfigured.self) { try await transport.send(Data()) }
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func increment() { lock.withLock { n += 1 } }
    var value: Int { lock.withLock { n } }
}

@Suite(.serialized) struct AgentForwarderTests {
    @Test func forwardsToTheAgentAndReturnsItsReply() async throws {
        let own = try ownRequirement()
        let server = AgentXPCServer(listener: .anonymous(), clientRequirement: own) { _ in .decline(.killswitch) }
        server.resume()
        defer { server.invalidate() }
        let forwarder = AgentForwarder { AgentXPCClient(endpoint: server.endpoint, agentRequirement: own) }
        #expect(await forwarder.forward(request) == .decline(.killswitch))
    }

    @Test func agentNotRunningDeclinesQuickly() async throws {
        let forwarder = AgentForwarder {
            AgentXPCClient(machServiceName: "com.example.ntlmac.test.absent-\(UUID().uuidString)", agentRequirement: try! ownRequirement())
        }
        let start = Date()
        #expect(await forwarder.forward(request) == .decline(.agentUnavailable))
        #expect(Date().timeIntervalSince(start) < AgentForwarder.defaultTimeout, "an unregistered service fails at once")
    }

    @Test func unverifiableAgentDeclines() async {
        // No team ID and no override: the shim has no requirement to check the agent against.
        #expect(await AgentForwarder { nil }.forward(request) == .decline(.agentUnavailable))
    }

    @Test func aHungAgentDeclinesWithinTheBudget() async throws {
        let own = try ownRequirement()
        let server = AgentXPCServer(listener: .anonymous(), clientRequirement: own) { _ in
            try? await Task.sleep(for: .seconds(10))
            return .decline(.killswitch)
        }
        server.resume()
        defer { server.invalidate() }
        let forwarder = AgentForwarder(timeout: 0.3) { AgentXPCClient(endpoint: server.endpoint, agentRequirement: own) }
        let start = Date()
        #expect(await forwarder.forward(request) == .decline(.agentUnavailable))
        #expect(Date().timeIntervalSince(start) < 1)
    }

    @Test func budgetFitsInsideTheExtensionsTimeout() {
        // hello + authenticate, each bounded by the timeout, inside AGENT_TIMEOUT_MS (3 s)
        // with room for the shim to start.
        #expect(2 * AgentForwarder.defaultTimeout <= 2)
    }

    @Test func reconnectsAfterAFailure() async {
        let connects = Counter()
        let forwarder = AgentForwarder {
            connects.increment()
            return AgentXPCClient(machServiceName: "com.example.ntlmac.test.absent-\(UUID().uuidString)", agentRequirement: "anchor apple")
        }
        _ = await forwarder.forward(request)
        _ = await forwarder.forward(request)
        #expect(connects.value == 2, "a dead connection is replaced, so an agent started later is found")
    }
}
