import Foundation

/// Everything the enrolment / re-prompt dialog decides, kept out of the AppKit code so it
/// can be tested: the wording per `PromptReason`, what counts as a usable account name,
/// and how each failure is explained inline. The password only ever travels inside a
/// `Credential`, which redacts itself, and no message here can contain it.
public enum CredentialPrompt {
    public struct Text: Equatable, Sendable {
        public var title: String
        public var message: String
    }

    public static func text(for reason: PromptReason) -> Text {
        switch reason {
        case .enrol:
            Text(title: "Set up intranet sign-in",
                 message: "Edge and Chrome can sign you in to intranet sites without asking. Enter your network account password once; it is kept in your login keychain on this Mac.")
        case .adPasswordChanged:
            Text(title: "Your network password changed",
                 message: "Enter your new password so intranet sites keep signing you in. Until then they will ask for it.")
        case .retryRejected:
            Text(title: "Intranet sign-in paused",
                 message: "An intranet site didn't accept your saved password, so it is no longer being used, to keep your account from being locked. Enter your current password.")
        case .validationFailed:
            Text(title: "Password not accepted",
                 message: "Your domain didn't accept that username and password. Check them before trying again: repeated wrong passwords can lock your account.")
        }
    }

    /// The account name (sAMAccountName) from what was typed: trimmed, with a `DOMAIN\`
    /// prefix removed. Nil if it can't name a principal (empty, `user@domain`, `/`).
    public static func account(from typed: String) -> String? {
        var name = typed.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = name.split(separator: "\\", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { return nil }
        name = String(parts.last!)
        guard !name.isEmpty, name.rangeOfCharacter(from: CharacterSet(charactersIn: "@/")) == nil else { return nil }
        return name
    }

    /// What stops a submission, said inline, or nil if it can go ahead.
    public static func problem(account typed: String, password: String) -> String? {
        if typed.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Enter your username." }
        if account(from: typed) == nil { return unusableAccount }
        if password.isEmpty { return "Enter your password." }
        return nil
    }

    public static func canSubmit(account typed: String, password: String) -> Bool {
        problem(account: typed, password: password) == nil
    }

    private static let unusableAccount = "Enter your username without @domain, for example jbloggs."

    public enum Outcome: Equatable, Sendable {
        /// Validated and stored: close the dialog.
        case stored
        /// Keep the dialog open with `message` under the fields; clear the password field
        /// when the password itself was the problem.
        case failed(message: String, clearPassword: Bool)
    }

    /// Validates and stores what was typed through `replace` (`AgentService.credentialReplaced`),
    /// which sends at most one AS-REQ. The password is passed on exactly as typed.
    public static func submit(
        account typed: String,
        password: String,
        isolation: isolated (any Actor)? = #isolation,
        replace: (Credential) async throws -> Void
    ) async -> Outcome {
        guard let account = account(from: typed) else {
            return .failed(message: unusableAccount, clearPassword: false)
        }
        do {
            try await replace(Credential(account: account, password: password))
            return .stored
        } catch {
            return failure(error)
        }
    }

    private static func failure(_ error: Error) -> Outcome {
        switch error {
        case CredentialReplacementError.rejected:
            .failed(message: "That username and password weren't accepted.", clearPassword: true)
        case CredentialReplacementError.configInvalid:
            .failed(message: "Intranet sign-in isn't configured on this Mac yet. Contact the service desk.", clearPassword: false)
        case KerberosValidationError.kdcUnavailable:
            .failed(message: "Couldn't reach your domain to check the password. Connect to the office network or VPN, then try again.", clearPassword: false)
        case KerberosValidationError.passwordExpired:
            .failed(message: "That password has expired. Change it first, then enter the new one here.", clearPassword: true)
        case KerberosValidationError.accountLocked:
            .failed(message: "Your account is locked or disabled. Contact the service desk.", clearPassword: true)
        case KerberosValidationError.invalidInput:
            .failed(message: "Enter your username and password.", clearPassword: false)
        case let KeychainError.status(status):
            .failed(message: "The password was accepted but couldn't be saved (error \(status)). Try again, or contact the service desk.", clearPassword: false)
        default:
            // Don't show arbitrary error text: only types above are known to be free of input.
            .failed(message: "Something went wrong checking the password. Try again.", clearPassword: false)
        }
    }
}
