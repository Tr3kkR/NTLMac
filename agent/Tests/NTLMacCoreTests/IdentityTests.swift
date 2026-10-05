import Foundation
import Testing
@testable import NTLMacCore

private let custom = NTLMacIdentity(prefix: "org.test.ntlmac")!

@Suite struct NTLMacIdentityTests {
    @Test func everyNameDerivesFromThePrefix() {
        #expect(custom.agent == "org.test.ntlmac.agent")
        #expect(custom.shim == "org.test.ntlmac.nmh")
        #expect(custom.credentialService == "org.test.ntlmac.credential")
        #expect(custom.preferenceDomain == "org.test.ntlmac")
        #expect(custom.keychainAccessGroup(teamID: "ABCDE12345") == "ABCDE12345.org.test.ntlmac")
        #expect(custom.userDataDirectory(home: URL(fileURLWithPath: "/Users/jbloggs")).path
            == "/Users/jbloggs/Library/Application Support/org.test.ntlmac")
    }

    @Test func theDefaultIsTheProductionPrefix() {
        #expect(NTLMacIdentity.standard.prefix == "com.devnull.ntlmac")
        #expect(NTLMacIdentity.standard.agent == "com.devnull.ntlmac.agent")
    }

    @Test(arguments: ["org.test.ntlmac.agent", "org.test.ntlmac.nmh"])
    func readsThePrefixFromEitherSigningIdentifier(identifier: String) {
        #expect(NTLMacIdentity(signingIdentifier: identifier) == custom)
    }

    @Test(arguments: [nil, "ntlmac-nmh", "NTLMacAgent", "com.apple.dt.xctest.tool", "agent", ".agent", "org.test.ntlmac.impostor"] as [String?])
    func anyOtherIdentifierMeansTheDefault(identifier: String?) {
        #expect(NTLMacIdentity(signingIdentifier: identifier) == .standard)
    }

    // Prefixes end up in code-signing requirement strings and native-messaging host names
    // (lowercase letters, digits, '_' and '.'), so nothing else is accepted.
    @Test(arguments: [#"com.example" or true"#, "", "com example", "ntlmac", "com..ntlmac", ".com.ntlmac", "com.ntlmac.", "Com.Example.ntlmac", "com.my-org.ntlmac", #"com.x"y.ntlmac"#])
    func rejectsMalformedPrefixes(prefix: String) {
        #expect(NTLMacIdentity(prefix: prefix) == nil)
        #expect(NTLMacIdentity(signingIdentifier: prefix + ".agent") == .standard)
    }

    @Test func thisTestProcessUsesTheDefault() {
        #expect(NTLMacIdentity.current == .standard)
    }
}
