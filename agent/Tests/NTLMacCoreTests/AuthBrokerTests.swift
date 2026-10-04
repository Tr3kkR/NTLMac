import Foundation
import Testing
@testable import NTLMacCore

private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

private func config(
    enabled: Bool = true,
    killDate: Date = t0.addingTimeInterval(86_400 * 365),
    httpExceptions: [HTTPException] = []
) -> NTLMacConfig {
    NTLMacConfig(
        enabled: enabled,
        killDate: killDate,
        realm: "CORP.EXAMPLE",
        netbiosDomain: "CORP",
        rules: [AllowlistRule(id: "corp-wide", pattern: "*.corp.example")],
        deny: ["*.lab.corp.example"],
        httpExceptions: httpExceptions
    )
}

private func request(
    _ id: String = "1",
    host: String = "app.corp.example",
    urlScheme: String = "https",
    authScheme: String = "ntlm",
    isProxy: Bool = false
) -> AuthRequest {
    AuthRequest(requestId: id, host: host, port: 443, urlScheme: urlScheme, authScheme: authScheme, isProxy: isProxy)
}

@Suite struct AuthBrokerTests {
    @Test func suppliesForAllowlistedHTTPSNTLMChallenge() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        #expect(broker.decide(request(), now: t0) == .supply(ruleId: "corp-wide"))
    }

    // MARK: Scope guards

    @Test func neverSuppliesForProxyChallenges() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        #expect(broker.decide(request(isProxy: true), now: t0) == .decline(.proxyIgnored))
    }

    @Test(arguments: ["basic", "digest", "negotiate", "NTLMv1", ""])
    func neverSuppliesForNonNTLMSchemes(scheme: String) {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        #expect(broker.decide(request(authScheme: scheme), now: t0) == .decline(.notNTLM))
    }

    @Test func authSchemeComparisonIsCaseInsensitive() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        #expect(broker.decide(request(authScheme: "NTLM"), now: t0) == .supply(ruleId: "corp-wide"))
    }

    @Test func declinesHostsNotOnAllowlist() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        #expect(broker.decide(request(host: "evil.example"), now: t0) == .decline(.notAllowlisted))
        #expect(broker.decide(request("2", host: "x.lab.corp.example"), now: t0) == .decline(.notAllowlisted))
    }

    @Test func blocksPlainHTTPWithoutException() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        #expect(broker.decide(request(urlScheme: "http"), now: t0) == .decline(.httpBlocked))
    }

    @Test func allowsPlainHTTPWithUnexpiredException() {
        let exc = HTTPException(host: "app.corp.example", expires: t0.addingTimeInterval(60))
        var broker = AuthBroker(config: config(httpExceptions: [exc]), credentialState: .ok)
        #expect(broker.decide(request(urlScheme: "http"), now: t0) == .supply(ruleId: "corp-wide"))
        #expect(broker.decide(request("2", urlScheme: "http"), now: t0.addingTimeInterval(61)) == .decline(.httpBlocked))
    }

    @Test func httpExceptionStillRequiresAllowlistMatch() {
        let exc = HTTPException(host: "evil.example", expires: t0.addingTimeInterval(60))
        var broker = AuthBroker(config: config(httpExceptions: [exc]), credentialState: .ok)
        #expect(broker.decide(request(host: "evil.example", urlScheme: "http"), now: t0) == .decline(.notAllowlisted))
    }

    @Test(arguments: ["ws", "ftp", "file", ""])
    func blocksOtherURLSchemes(scheme: String) {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        #expect(broker.decide(request(urlScheme: scheme), now: t0) == .decline(.httpBlocked))
    }

    // MARK: Kill switch

    @Test func killSwitchWhenDisabled() {
        var broker = AuthBroker(config: config(enabled: false), credentialState: .ok)
        #expect(broker.decide(request(), now: t0) == .decline(.killswitch))
    }

    @Test func killSwitchOnAndAfterKillDate() {
        var broker = AuthBroker(config: config(killDate: t0), credentialState: .ok)
        #expect(broker.decide(request(), now: t0.addingTimeInterval(-1)) == .supply(ruleId: "corp-wide"))
        #expect(broker.decide(request("2"), now: t0) == .decline(.killswitch))
    }

    // MARK: Credential state

    @Test func declinesWhenNoCredentialEnrolled() {
        var broker = AuthBroker(config: config(), credentialState: .missing)
        #expect(broker.decide(request(), now: t0) == .decline(.credentialMissing))
    }

    // MARK: Lockout protection

    @Test func secondChallengeForSameRequestIsRetryAndLatchesSuspect() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        #expect(broker.decide(request("42"), now: t0) == .supply(ruleId: "corp-wide"))
        #expect(broker.decide(request("42"), now: t0.addingTimeInterval(0.2)) == .decline(.retryCancelled))
        #expect(broker.credentialState == .suspect)
        #expect(broker.breakerTrips == 1)
    }

    @Test func suspectLatchIsGlobalAcrossHosts() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        _ = broker.decide(request("42"), now: t0)
        _ = broker.decide(request("42"), now: t0)
        #expect(broker.decide(request("43", host: "other.corp.example"), now: t0) == .decline(.suspectBlocked))
    }

    @Test func suspectLatchClearsOnlyWhenCredentialReplaced() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        _ = broker.decide(request("42"), now: t0)
        _ = broker.decide(request("42"), now: t0)
        #expect(broker.decide(request("43"), now: t0.addingTimeInterval(3600)) == .decline(.suspectBlocked))
        broker.credentialReplaced()
        #expect(broker.credentialState == .ok)
        #expect(broker.decide(request("44"), now: t0.addingTimeInterval(3600)) == .supply(ruleId: "corp-wide"))
    }

    @Test func externalPasswordChangeLatchesSuspect() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        broker.passwordChangedExternally()
        #expect(broker.decide(request(), now: t0) == .decline(.suspectBlocked))
    }

    @Test func retryAfterCredentialReplacedIsNotTreatedAsRetryOfOldSupply() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        _ = broker.decide(request("42"), now: t0)
        _ = broker.decide(request("42"), now: t0)
        broker.credentialReplaced()
        // The browser re-requests the page; Chromium may reuse a low request ID after a restart.
        #expect(broker.decide(request("42"), now: t0.addingTimeInterval(10)) == .supply(ruleId: "corp-wide"))
    }

    @Test func parallelDistinctRequestsAreAllSupplied() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        for i in 0..<10 {
            #expect(broker.decide(request("r\(i)"), now: t0) == .supply(ruleId: "corp-wide"))
        }
        #expect(broker.credentialState == .ok)
    }

    @Test func requestIDMemoryExpires() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        _ = broker.decide(request("42"), now: t0)
        let later = t0.addingTimeInterval(CircuitBreaker.requestIDTTL + 1)
        #expect(broker.decide(request("42"), now: later) == .supply(ruleId: "corp-wide"))
    }

    @Test func perHostRateLimitCapsSuppliesPerWindow() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        let limit = CircuitBreaker.maxSuppliesPerHostPerWindow
        for i in 0..<limit {
            #expect(broker.decide(request("r\(i)"), now: t0) == .supply(ruleId: "corp-wide"))
        }
        #expect(broker.decide(request("over"), now: t0) == .decline(.rateLimited))
        #expect(broker.decide(request("other", host: "b.corp.example"), now: t0) == .supply(ruleId: "corp-wide"))
        let nextWindow = t0.addingTimeInterval(CircuitBreaker.rateWindow + 1)
        #expect(broker.decide(request("later"), now: nextWindow) == .supply(ruleId: "corp-wide"))
    }

    @Test func rateLimitDeclineDoesNotTripBreakerOnBrowserRetry() {
        var broker = AuthBroker(config: config(), credentialState: .ok)
        let limit = CircuitBreaker.maxSuppliesPerHostPerWindow
        for i in 0..<limit { _ = broker.decide(request("r\(i)"), now: t0) }
        _ = broker.decide(request("over"), now: t0)
        #expect(broker.decide(request("over"), now: t0) == .decline(.rateLimited))
        #expect(broker.credentialState == .ok)
    }

    @Test func requestIDMemoryIsBounded() {
        var breaker = CircuitBreaker()
        for i in 0..<(CircuitBreaker.maxTrackedRequests + 500) {
            breaker.recordSupply(requestId: "r\(i)", host: "h\(i % 1000)", now: t0)
        }
        #expect(breaker.trackedRequestCount <= CircuitBreaker.maxTrackedRequests)
    }

    @Test func reportsTheRuleAHostMatchesForTelemetry() {
        let broker = AuthBroker(config: config(), credentialState: .ok)
        #expect(broker.matchingRule(host: "APP.corp.example")?.id == "corp-wide")
        #expect(broker.matchingRule(host: "x.lab.corp.example") == nil, "deny wins")
        #expect(broker.matchingRule(host: "evil.example") == nil)
    }
}
