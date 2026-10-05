import Foundation
import Testing
@testable import NTLMacCore

private let t0 = Date(timeIntervalSince1970: 1_800_000_000)
private let jbloggs = Credential(account: "jbloggs", password: "Passw0rd!")

private func config(enabled: Bool = true, killDate: Date = t0.addingTimeInterval(86_400 * 365)) -> NTLMacConfig {
    NTLMacConfig(
        enabled: enabled,
        killDate: killDate,
        realm: "CORP.EXAMPLE",
        netbiosDomain: "CORP",
        rules: [AllowlistRule(id: "corp-wide", pattern: "*.corp.example")]
    )
}

private func request(_ id: String = "n:1", host: String = "app.corp.example", urlScheme: String = "https") -> AuthRequest {
    AuthRequest(requestId: id, host: host, port: 443, urlScheme: urlScheme, authScheme: "ntlm", isProxy: false)
}

/// A store whose reads can be made to fail, like a locked or unentitled Keychain.
private final class FlakyStore: CredentialStore, @unchecked Sendable {
    private let lock = NSLock()
    private var credential: Credential?
    private var readError: KeychainError?
    private var writeError: KeychainError?

    init(_ credential: Credential?) { self.credential = credential }

    func failReads(_ error: KeychainError?) { lock.withLock { readError = error } }
    func failWrites(_ error: KeychainError?) { lock.withLock { writeError = error } }
    func set(_ credential: Credential?) { lock.withLock { self.credential = credential } }
    var stored: Credential? { lock.withLock { credential } }

    func read() throws -> Credential? {
        try lock.withLock {
            if let readError { throw readError }
            return credential
        }
    }

    func write(_ credential: Credential) throws {
        try lock.withLock {
            if let writeError { throw writeError }
            self.credential = credential
        }
    }

    func delete() throws { lock.withLock { credential = nil } }
}

private final class RecordingPrompter: CredentialPrompter, @unchecked Sendable {
    private let lock = NSLock()
    private var reasons: [PromptReason] = []
    func requestCredential(reason: PromptReason) { lock.withLock { reasons.append(reason) } }
    var all: [PromptReason] { lock.withLock { reasons } }
}

private struct ScriptedValidator: CredentialValidator {
    enum Answer { case valid, rejected, offline }
    var answer: Answer

    func validate(_ credential: Credential, realm: String) async throws -> Bool {
        switch answer {
        case .valid: true
        case .rejected: false
        case .offline: throw URLError(.notConnectedToInternet)
        }
    }
}

private actor CapturingTransport: TelemetryTransport {
    private(set) var sent: [Data] = []
    func send(_ payload: Data) async throws -> DeliveryResult {
        sent.append(payload)
        return .delivered
    }
}

/// A service plus its fakes. `points` flushes telemetry and returns one metric's data
/// points as attribute dictionaries with their counts.
private struct Harness {
    let store: FlakyStore
    let latch: InMemorySuspectLatch
    let validator: ScriptedValidator.Answer
    let prompter = RecordingPrompter()
    let transport = CapturingTransport()
    let service: AgentService

    init(
        credential: Credential? = jbloggs,
        validator: ScriptedValidator.Answer = .valid,
        user: String? = "jbloggs",
        store: FlakyStore? = nil,
        latch: InMemorySuspectLatch = InMemorySuspectLatch()
    ) throws {
        self.store = store ?? FlakyStore(credential)
        self.latch = latch
        self.validator = validator
        let store = self.store
        let queue = try TelemetryQueue(directory: FileManager.default.temporaryDirectory.appendingPathComponent("ntlmac-svc-\(UUID().uuidString)"))
        let telemetry = TelemetryExporter(
            recorder: TelemetryRecorder(resource: TelemetryResource(serviceVersion: "0.1.0", hostID: "h", osVersion: "26.0")),
            queue: queue,
            transport: transport,
            start: t0
        )
        service = AgentService(
            store: store,
            latch: latch,
            telemetry: telemetry,
            users: FixedUserProvider(realm: "CORP.EXAMPLE", user: user),
            prompter: prompter,
            validator: ScriptedValidator(answer: validator),
            now: { t0 }
        )
    }

    func started(_ config: NTLMacConfig? = config()) async -> Harness {
        await service.reload(config: config)
        return self
    }

    /// A fresh agent process (crash, logout) over the same Keychain and latch file.
    func restarted() async throws -> Harness {
        try await Harness(validator: validator, store: store, latch: latch).started()
    }

    func points(_ metric: String) async throws -> [([String: String], Int)] {
        _ = try await service.flushTelemetry()
        let payload = try #require(await transport.sent.last)
        let json = try #require(try JSONSerialization.jsonObject(with: payload) as? [String: Any])
        let rm = (json["resourceMetrics"] as? [[String: Any]])?.first
        let metrics = ((rm?["scopeMetrics"] as? [[String: Any]])?.first?["metrics"] as? [[String: Any]]) ?? []
        guard let m = metrics.first(where: { $0["name"] as? String == metric }) else { return [] }
        let body = (m["sum"] ?? m["gauge"]) as? [String: Any]
        return (body?["dataPoints"] as? [[String: Any]] ?? []).map { p in
            var attrs: [String: String] = [:]
            for a in p["attributes"] as? [[String: Any]] ?? [] {
                attrs[a["key"] as! String] = (a["value"] as? [String: Any])?["stringValue"] as? String
            }
            return (attrs, Int(p["asInt"] as? String ?? "") ?? -1)
        }
    }
}

@Suite struct AgentServiceTests {
    // MARK: Supply

    @Test func suppliesTheDomainQualifiedStoredCredential() async throws {
        let h = try await Harness().started()
        #expect(await h.service.handle(request()) == .supply(username: "CORP\\jbloggs", password: "Passw0rd!"))
    }

    @Test func declinesCarryNoCredential() async throws {
        let h = try await Harness().started()
        #expect(await h.service.handle(request(host: "evil.example")) == .decline(.notAllowlisted))
        #expect(await h.service.handle(request("n:2", urlScheme: "http")) == .decline(.httpBlocked))
    }

    @Test func failsClosedUntilAConfigIsLoaded() async throws {
        let h = try Harness()
        #expect(await h.service.handle(request()) == .decline(.configInvalid))
    }

    // MARK: Credential state follows the store

    @Test func missingCredentialDeclinesAndAsksToEnrolOnce() async throws {
        let h = try await Harness(credential: nil).started()
        #expect(await h.service.handle(request()) == .decline(.credentialMissing))
        #expect(await h.service.handle(request("n:2")) == .decline(.credentialMissing))
        #expect(h.prompter.all == [.enrol])
        #expect(await h.service.credentialState() == .missing)
    }

    @Test func credentialDeletedFromTheStoreStopsSupply() async throws {
        let h = try await Harness().started()
        h.store.set(nil)
        #expect(await h.service.handle(request()) == .decline(.credentialMissing))
        #expect(await h.service.credentialState() == .missing)
    }

    @Test func credentialAppearingInTheStoreIsUsed() async throws {
        let h = try await Harness(credential: nil).started()
        h.store.set(jbloggs)
        #expect(await h.service.handle(request()) == .supply(username: "CORP\\jbloggs", password: "Passw0rd!"))
    }

    @Test func aKeychainErrorNeverBecomesASupply() async throws {
        let h = try await Harness().started()
        h.store.failReads(.status(errSecInteractionNotAllowed))
        #expect(await h.service.handle(request()) == .decline(.credentialMissing))
        // The failed attempt must not count as a supply for that request: once the Keychain
        // is readable again the same browser request can still be answered.
        h.store.failReads(nil)
        #expect(await h.service.handle(request()) == .supply(username: "CORP\\jbloggs", password: "Passw0rd!"))
    }

    @Test func aKeychainErrorDoesNotForgetTheCredentialState() async throws {
        let h = try await Harness().started()
        h.store.failReads(.status(errSecInteractionNotAllowed))
        #expect(await h.service.credentialState() == .ok)
        await h.service.passwordChangedExternally()
        #expect(await h.service.credentialState() == .suspect)
    }

    // MARK: Lockout guard

    @Test func aSecondChallengeLatchesSuspectTripsTheBreakerAndRepromptsOnce() async throws {
        let h = try await Harness().started()
        #expect(await h.service.handle(request("n:1")) == .supply(username: "CORP\\jbloggs", password: "Passw0rd!"))
        #expect(await h.service.handle(request("n:1")) == .decline(.retryCancelled))
        #expect(await h.service.handle(request("n:1")) == .decline(.retryCancelled))
        #expect(await h.service.handle(request("n:2")) == .decline(.suspectBlocked))
        #expect(await h.service.credentialState() == .suspect)
        #expect(h.prompter.all == [.retryRejected])

        let trips = try await h.points("ntlmac.breaker.trips")
        #expect(trips.count == 1)
        #expect(trips.first?.0 == ["app.host": "app.corp.example", "enduser.id": "jbloggs"])
        #expect(trips.first?.1 == 1)
    }

    @Test func externalPasswordChangeLatchesSuspectAndPromptsOnce() async throws {
        let h = try await Harness().started()
        // Both Kerberos SSO notifications can arrive for one change.
        await h.service.passwordChangedExternally()
        await h.service.passwordChangedExternally()
        #expect(await h.service.handle(request()) == .decline(.suspectBlocked))
        #expect(h.prompter.all == [.adPasswordChanged])
        let prompts = try await h.points("ntlmac.credential.prompts")
        #expect(prompts.map(\.0) == [["reason": "ad_password_changed", "enduser.id": "jbloggs"]])
        #expect(prompts.map(\.1) == [1])
    }

    @Test func dismissedPromptCanBeShownAgain() async throws {
        let h = try await Harness().started()
        await h.service.passwordChangedExternally()
        await h.service.promptDismissed()
        await h.service.passwordChangedExternally()
        #expect(h.prompter.all == [.adPasswordChanged, .adPasswordChanged])
    }

    // MARK: Replacing the credential

    @Test func validatedReplacementIsStoredAndClearsSuspect() async throws {
        let h = try await Harness().started()
        await h.service.passwordChangedExternally()
        let fresh = Credential(account: "jbloggs", password: "N3w-Passw0rd!")
        try await h.service.credentialReplaced(fresh)
        #expect(h.store.stored == fresh)
        #expect(await h.service.credentialState() == .ok)
        #expect(await h.service.handle(request()) == .supply(username: "CORP\\jbloggs", password: "N3w-Passw0rd!"))
    }

    @Test func rejectedReplacementIsNotStoredAndRePrompts() async throws {
        let h = try await Harness(validator: .rejected).started()
        await h.service.passwordChangedExternally()
        await #expect(throws: CredentialReplacementError.rejected) {
            try await h.service.credentialReplaced(Credential(account: "jbloggs", password: "typo"))
        }
        #expect(h.store.stored == jbloggs)
        #expect(await h.service.credentialState() == .suspect)
        #expect(h.prompter.all == [.adPasswordChanged, .validationFailed])
    }

    @Test func replacementThatCannotBeValidatedIsNotStored() async throws {
        let h = try await Harness(validator: .offline).started()
        await h.service.passwordChangedExternally()
        await #expect(throws: URLError.self) {
            try await h.service.credentialReplaced(Credential(account: "jbloggs", password: "N3w-Passw0rd!"))
        }
        #expect(h.store.stored == jbloggs)
        #expect(await h.service.credentialState() == .suspect)
    }

    @Test func replacementThatCannotBeWrittenLeavesTheStateAlone() async throws {
        let h = try await Harness().started()
        await h.service.passwordChangedExternally()
        h.store.failWrites(.status(errSecMissingEntitlement))
        await #expect(throws: KeychainError.status(errSecMissingEntitlement)) {
            try await h.service.credentialReplaced(Credential(account: "jbloggs", password: "N3w-Passw0rd!"))
        }
        #expect(await h.service.credentialState() == .suspect)
    }

    @Test func replacementNeedsAValidConfig() async throws {
        let h = try Harness()
        await #expect(throws: CredentialReplacementError.configInvalid) { try await h.service.credentialReplaced(jbloggs) }
    }

    // MARK: The suspect latch survives restarts

    @Test func aTrippedBreakerSurvivesARestart() async throws {
        let h = try await Harness().started()
        _ = await h.service.handle(request("n:1"))
        _ = await h.service.handle(request("n:1"))
        #expect(h.latch.isSet)

        // The stale password is still in the Keychain: the new process must not try it.
        let after = try await h.restarted()
        #expect(await after.service.credentialState() == .suspect)
        #expect(await after.service.handle(request("n:9")) == .decline(.suspectBlocked))
    }

    @Test func anExternalPasswordChangeSurvivesARestart() async throws {
        let h = try await Harness().started()
        await h.service.passwordChangedExternally()
        let after = try await h.restarted()
        #expect(await after.service.handle(request()) == .decline(.suspectBlocked))
    }

    @Test func thePersistedLatchWinsOverACredentialAppearing() async throws {
        let h = try await Harness(credential: nil, latch: InMemorySuspectLatch(set: true)).started()
        #expect(await h.service.credentialState() == .missing)
        h.store.set(jbloggs)
        #expect(await h.service.handle(request()) == .decline(.suspectBlocked))
        #expect(await h.service.credentialState() == .suspect)
    }

    @Test func aRemovedCredentialKeepsTheLatch() async throws {
        let h = try await Harness().started()
        await h.service.passwordChangedExternally()
        h.store.set(nil)
        #expect(await h.service.credentialState() == .missing)
        h.store.set(jbloggs)
        #expect(await h.service.credentialState() == .suspect)
        #expect(h.latch.isSet)
    }

    @Test func onlyAValidatedReplacementClearsTheLatch() async throws {
        let h = try await Harness(validator: .rejected).started()
        await h.service.passwordChangedExternally()
        _ = try? await h.service.credentialReplaced(Credential(account: "jbloggs", password: "typo"))
        await h.service.promptDismissed()
        await h.service.reload(config: config())
        #expect(h.latch.isSet)

        let good = try await Harness(validator: .valid, store: h.store, latch: h.latch).started()
        try await good.service.credentialReplaced(Credential(account: "jbloggs", password: "N3w-Passw0rd!"))
        #expect(!h.latch.isSet)
        let after = try await good.restarted()
        #expect(await after.service.credentialState() == .ok)
    }

    @Test func aLatchThatCannotBeWrittenStillLatchesInMemory() async throws {
        let h = try await Harness(latch: InMemorySuspectLatch(failWrites: true)).started()
        await h.service.passwordChangedExternally()
        #expect(await h.service.handle(request()) == .decline(.suspectBlocked))
    }

    // MARK: Config reload

    @Test func invalidConfigFailsClosedAndAValidOneRestoresService() async throws {
        let h = try await Harness().started()
        await h.service.reload(config: nil)
        #expect(await h.service.handle(request("n:1")) == .decline(.configInvalid))
        await h.service.reload(config: config())
        #expect(await h.service.handle(request("n:2")) == .supply(username: "CORP\\jbloggs", password: "Passw0rd!"))
    }

    @Test func reloadKeepsTheSuspectLatch() async throws {
        let h = try await Harness().started()
        await h.service.passwordChangedExternally()
        await h.service.reload(config: nil)
        await h.service.reload(config: config())
        #expect(await h.service.handle(request()) == .decline(.suspectBlocked))
    }

    @Test func reloadAppliesTheKillSwitch() async throws {
        let h = try await Harness().started()
        await h.service.reload(config: config(enabled: false))
        #expect(await h.service.handle(request("n:1")) == .decline(.killswitch))
        await h.service.reload(config: config(killDate: t0))
        #expect(await h.service.handle(request("n:2")) == .decline(.killswitch))
    }

    // MARK: Telemetry

    @Test func recordsEveryRequestWithRuleUserAndOutcome() async throws {
        let h = try await Harness().started()
        _ = await h.service.handle(request("n:1"))
        _ = await h.service.handle(request("n:2", urlScheme: "http"))
        _ = await h.service.handle(request("n:3", host: "private-site.example"))
        let points = try await h.points("ntlmac.auth.requests")
        let byOutcome = Dictionary(uniqueKeysWithValues: points.map { ($0.0["outcome"]!, $0.0) })
        #expect(byOutcome["supplied"] == ["app.host": "app.corp.example", "allowlist.rule_id": "corp-wide", "enduser.id": "jbloggs", "outcome": "supplied"])
        #expect(byOutcome["http_blocked"]?["allowlist.rule_id"] == "corp-wide", "declines on listed hosts keep their rule for the backlog")
        #expect(byOutcome["not_allowlisted"]?["app.host"] == "(unlisted)")
    }

    @Test func enduserFallsBackToTheStoredAccountWhenNobodyIsSignedIn() async throws {
        let h = try await Harness(user: nil).started()
        _ = await h.service.handle(request())
        let points = try await h.points("ntlmac.auth.requests")
        #expect(points.first?.0["enduser.id"] == "jbloggs")
    }

    @Test func configInvalidRequestsAreCounted() async throws {
        let h = try Harness()
        _ = await h.service.handle(request())
        let points = try await h.points("ntlmac.auth.requests")
        #expect(points.first?.0["outcome"] == "config_invalid")
    }

    @Test func flushReportsTheCurrentCredentialState() async throws {
        let h = try await Harness().started()
        await h.service.passwordChangedExternally()
        let state = try await h.points("ntlmac.credential.state")
        #expect(state.map(\.0) == [["state": "suspect"]])
    }

    @Test func thePasswordNeverReachesTelemetry() async throws {
        let h = try await Harness().started()
        _ = await h.service.handle(request())
        _ = try await h.service.flushTelemetry()
        for payload in await h.transport.sent {
            #expect(!String(decoding: payload, as: UTF8.self).contains("Passw0rd!"))
        }
    }
}
