import Foundation
import Security
import Testing
@testable import NTLMacCore

private let policy = try! CodeSigningPolicy(teamID: "ABCDE12345")
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

private final class Seen: @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [AuthRequest] = []
    func add(_ r: AuthRequest) { lock.withLock { requests.append(r) } }
    var all: [AuthRequest] { lock.withLock { requests } }
}

private func server(requiringClient requirement: String, seen: Seen = Seen()) -> AgentXPCServer {
    let server = AgentXPCServer(listener: .anonymous(), clientRequirement: requirement) { req in
        seen.add(req)
        return .supply(username: "CORP\\jbloggs", password: "Passw0rd!")
    }
    server.resume()
    return server
}

@Suite struct CodeSigningPolicyTests {
    @Test func requirementsPinTeamAndIdentifier() {
        #expect(policy.agentRequirement == #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345" and identifier "com.example.ntlmac.agent""#)
        #expect(policy.shimRequirement == #"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345" and identifier "com.example.ntlmac.nmh""#)
    }

    @Test func requirementsCompile() throws {
        try CodeSigning.validate(requirement: policy.agentRequirement)
        try CodeSigning.validate(requirement: policy.shimRequirement)
        #expect(throws: CodeSigningError.self) { try CodeSigning.validate(requirement: "anchor apple generic and (") }
    }

    @Test(arguments: ["abcde12345", "ABCDE1234", "ABCDE123456", #"ABCDE1234""#, "ABCDE 2345", ""])
    func rejectsMalformedTeamIDs(teamID: String) {
        #expect(throws: CodeSigningError.invalidTeamID) { try CodeSigningPolicy(teamID: teamID) }
    }

    @Test(arguments: [#"com.example" or true"#, "", "com example"])
    func rejectsMalformedIdentifiers(identifier: String) {
        #expect(throws: CodeSigningError.invalidIdentifier) {
            try CodeSigningPolicy(teamID: "ABCDE12345", agentIdentifier: identifier)
        }
    }

    @Test func thisUnsignedTestProcessSatisfiesItsOwnRequirementButNotTheTeamPolicy() throws {
        #expect(try CodeSigning.currentProcessSatisfies(ownRequirement()))
        #expect(try !CodeSigning.currentProcessSatisfies(policy.shimRequirement))
    }
}

@Suite struct AgentReplyTests {
    @Test func descriptionNeverContainsThePassword() {
        let reply = AgentReply.supply(username: "CORP\\jbloggs", password: "Passw0rd!")
        var dumped = ""
        dump(reply, to: &dumped)
        for text in ["\(reply)", String(reflecting: reply), dumped] {
            #expect(!text.contains("Passw0rd!"), "leaked in: \(text)")
        }
    }

    @Test func mapsToTheNativeMessagingResponse() throws {
        let supply = try JSONEncoder().encode(AgentReply.supply(username: "u", password: "p").hostResponse(id: 7))
        #expect(String(decoding: supply, as: UTF8.self).contains(#""action":"supply""#))
        let decline = try JSONEncoder().encode(AgentReply.decline(.killswitch).hostResponse(id: 8))
        #expect(String(decoding: decline, as: UTF8.self).contains(#""outcome":"killswitch""#))
    }
}

@Suite(.serialized) struct AgentXPCTests {
    @Test func roundTripWhenBothSidesSatisfyTheirRequirements() async throws {
        let own = try ownRequirement()
        let seen = Seen()
        let server = server(requiringClient: own, seen: seen)
        let client = AgentXPCClient(endpoint: server.endpoint, agentRequirement: own)
        defer { client.invalidate() }
        let reply = try await client.authenticate(request)
        #expect(reply == .supply(username: "CORP\\jbloggs", password: "Passw0rd!"))
        #expect(seen.all == [request])
    }

    @Test func agentRejectsAClientThatIsNotTheSignedShim() async throws {
        let seen = Seen()
        let server = server(requiringClient: policy.shimRequirement, seen: seen)
        let client = AgentXPCClient(endpoint: server.endpoint, agentRequirement: try ownRequirement())
        defer { client.invalidate() }
        await #expect(throws: AgentXPCError.self) { try await client.authenticate(request) }
        #expect(seen.all.isEmpty, "the handler must never run for a rejected peer")
    }

    @Test func shimRefusesAnAgentThatIsNotTheSignedAgent() async throws {
        let seen = Seen()
        let server = server(requiringClient: try ownRequirement(), seen: seen)
        let client = AgentXPCClient(endpoint: server.endpoint, agentRequirement: policy.agentRequirement)
        defer { client.invalidate() }
        await #expect(throws: AgentXPCError.self) { try await client.authenticate(request) }
        #expect(seen.all.isEmpty, "no request may reach an unverified agent")
    }
}
