import Testing
@testable import NTLMacCore

@Suite struct AllowlistTests {
    let allowlist = Allowlist(
        rules: [
            AllowlistRule(id: "corp-wide", pattern: "*.corp.example"),
            AllowlistRule(id: "payroll", pattern: "payroll.hr.corp.example"),
            AllowlistRule(id: "legacy", pattern: "legacy.example"),
        ],
        deny: ["*.lab.corp.example", "adfs.corp.example"]
    )

    @Test func exactHostMatches() {
        #expect(allowlist.match(host: "legacy.example")?.id == "legacy")
    }

    @Test func wildcardMatchesAnyDepthOfSubdomain() {
        #expect(allowlist.match(host: "intranet.corp.example")?.id == "corp-wide")
        #expect(allowlist.match(host: "a.b.c.corp.example")?.id == "corp-wide")
    }

    @Test func wildcardDoesNotMatchApex() {
        #expect(allowlist.match(host: "corp.example") == nil)
    }

    @Test func wildcardDoesNotMatchSuffixWithoutDotBoundary() {
        #expect(allowlist.match(host: "evilcorp.example") == nil)
        #expect(allowlist.match(host: "x.notcorp.example") == nil)
    }

    @Test func exactDoesNotMatchSubdomain() {
        #expect(allowlist.match(host: "sub.legacy.example") == nil)
    }

    @Test func mostSpecificRuleWins() {
        #expect(allowlist.match(host: "payroll.hr.corp.example")?.id == "payroll")
    }

    @Test func denyBeatsAllow() {
        #expect(allowlist.match(host: "box1.lab.corp.example") == nil)
        #expect(allowlist.match(host: "adfs.corp.example") == nil)
    }

    @Test func matchingIsCaseInsensitiveAndIgnoresTrailingDot() {
        #expect(allowlist.match(host: "InTraNet.CORP.example.")?.id == "corp-wide")
    }

    @Test(arguments: ["", ".", "café.corp.example", "a b.corp.example", "[::1]", "x.corp.example..", "user@x.corp.example"])
    func rejectsMalformedHosts(host: String) {
        #expect(allowlist.match(host: host) == nil)
    }

    @Test func punycodeHostsAreAccepted() {
        #expect(allowlist.match(host: "xn--caf-dma.corp.example")?.id == "corp-wide")
    }

    @Test func invalidPatternsAreIgnoredAndReported() {
        let list = Allowlist(
            rules: [
                AllowlistRule(id: "bad1", pattern: "*"),
                AllowlistRule(id: "bad2", pattern: "*.example.*"),
                AllowlistRule(id: "bad3", pattern: "*.com"),
                AllowlistRule(id: "ok", pattern: "*.corp.example"),
            ],
            deny: []
        )
        #expect(list.match(host: "anything.com") == nil)
        #expect(list.match(host: "a.corp.example")?.id == "ok")
        #expect(Set(list.rejectedRuleIDs) == ["bad1", "bad2", "bad3"])
    }
}
