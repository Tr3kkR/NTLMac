import Testing
@testable import NTLMacCore

@Suite struct SignedInUserProviderTests {
    @Test func fixedProviderAnswersForItsRealmOnly() async throws {
        let provider: SignedInUserProvider = FixedUserProvider(realm: "CORP.EXAMPLE", user: "jbloggs")
        #expect(try await provider.currentUser(realm: "CORP.EXAMPLE") == "jbloggs")
        #expect(try await provider.currentUser(realm: "corp.example") == "jbloggs", "realms compare case-insensitively")
        #expect(try await provider.currentUser(realm: "OTHER.EXAMPLE") == nil)
    }
}
