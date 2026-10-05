import Foundation
import Testing
@testable import NTLMacCore

private actor Replacements {
    private(set) var received: [Credential] = []
    func add(_ credential: Credential) { received.append(credential) }
}

@Suite struct CredentialPromptTests {
    // MARK: Wording

    @Test func everyReasonHasItsOwnWording() {
        let reasons: [PromptReason] = [.enrol, .adPasswordChanged, .retryRejected, .validationFailed]
        let texts = reasons.map(CredentialPrompt.text(for:))
        for t in texts {
            #expect(!t.title.isEmpty && !t.message.isEmpty)
        }
        #expect(Set(texts.map(\.title)).count == reasons.count)
    }

    @Test func aFailedValidationWarnsAboutLockout() {
        #expect(CredentialPrompt.text(for: .validationFailed).message.contains("lock"))
    }

    // MARK: What was typed

    @Test(arguments: [
        ("jbloggs", "jbloggs"),
        ("  jbloggs\n", "jbloggs"),
        ("CORP\\jbloggs", "jbloggs"),
        ("corp\\jbloggs ", "jbloggs"),
    ])
    func accountNamesAreNormalised(typed: String, expected: String) {
        #expect(CredentialPrompt.account(from: typed) == expected)
    }

    @Test(arguments: ["", "   ", "CORP\\", "jbloggs@corp.example", "a\\b\\c", "svc/host"])
    func unusableAccountNamesAreRefused(typed: String) {
        #expect(CredentialPrompt.account(from: typed) == nil)
    }

    @Test func whatIsMissingIsSaidInline() {
        #expect(CredentialPrompt.problem(account: "jbloggs", password: "Passw0rd!") == nil)
        #expect(CredentialPrompt.problem(account: "", password: "Passw0rd!")?.contains("username") == true)
        #expect(CredentialPrompt.problem(account: "jbloggs@corp.example", password: "Passw0rd!")?.contains("without") == true)
        #expect(CredentialPrompt.problem(account: "jbloggs", password: "")?.contains("password") == true)
    }

    @Test func submitNeedsAnAccountAndAPassword() {
        #expect(CredentialPrompt.canSubmit(account: "jbloggs", password: "Passw0rd!"))
        #expect(!CredentialPrompt.canSubmit(account: "jbloggs", password: ""))
        #expect(!CredentialPrompt.canSubmit(account: "jbloggs@corp.example", password: "Passw0rd!"))
    }

    // MARK: Submitting

    @Test func submitHandsOverTheNormalisedAccountAndTheExactPassword() async {
        let got = Replacements()
        let outcome = await CredentialPrompt.submit(account: "CORP\\jbloggs", password: " Passw0rd! ") { await got.add($0) }
        #expect(outcome == .stored)
        // Passwords may legitimately start or end with spaces: never trim them.
        #expect(await got.received == [Credential(account: "jbloggs", password: " Passw0rd! ")])
    }

    @Test func anUnusableAccountIsNeverSubmitted() async {
        let got = Replacements()
        let outcome = await CredentialPrompt.submit(account: "jbloggs@corp.example", password: "Passw0rd!") { await got.add($0) }
        guard case let .failed(message, clearPassword) = outcome else { Issue.record("expected failure"); return }
        #expect(message.contains("without"))
        #expect(!clearPassword)
        #expect(await got.received.isEmpty)
    }

    @Test(arguments: [
        (CredentialReplacementError.rejected as Error, "accepted", true),
        (KerberosValidationError.kdcUnavailable(code: KerberosError.kdcUnreachable), "VPN", false),
        (KerberosValidationError.passwordExpired, "expired", true),
        (KerberosValidationError.accountLocked, "locked", true),
        (CredentialReplacementError.configInvalid, "configured", false),
        (KeychainError.status(-34018), "-34018", false),
        (URLError(.timedOut), "Try again", false),
    ])
    func failuresAreExplainedInline(error: Error, mentions: String, clearsPassword: Bool) async {
        let outcome = await CredentialPrompt.submit(account: "jbloggs", password: "Passw0rd!") { _ in throw error }
        guard case let .failed(message, clearPassword) = outcome else { Issue.record("expected failure"); return }
        #expect(message.contains(mentions), "\(message)")
        #expect(clearPassword == clearsPassword)
        #expect(!message.contains("Passw0rd!"))
    }
}
