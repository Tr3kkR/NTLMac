import Foundation

/// Shows the enrolment / re-prompt dialog, with `account` prefilled (the signed-in user,
/// else the stored account, else blank). Must return at once: the dialog later calls
/// `AgentService.credentialReplaced(_:)` with what the user typed, or `promptDismissed()`.
/// A request while the dialog is already up (`validationFailed` after a rejected
/// submission) updates that dialog instead of opening another.
public protocol CredentialPrompter: Sendable {
    func requestCredential(reason: PromptReason, account: String?)
}

/// Checks a password before it is stored, with one Kerberos AS-REQ to the realm's KDC, so a
/// typo costs one bad-password event and never reaches the NTLM apps.
public protocol CredentialValidator: Sendable {
    /// True if the KDC accepted the password, false if it rejected it. Throws if the KDC
    /// couldn't be asked (offline, no VPN); nothing is stored then.
    func validate(_ credential: Credential, realm: String) async throws -> Bool
}

public enum CredentialReplacementError: Error, Equatable {
    /// The KDC rejected the password.
    case rejected
    /// No valid managed profile, so there is no realm to validate against.
    case configInvalid
}

/// The agent's brain: answers each `AuthRequest` from the extension, attaching the stored
/// credential only when `AuthBroker` decides to supply, and keeps the credential state,
/// prompts and telemetry consistent. OS integration (Keychain, dialogs, KDC, `app-sso`) is
/// behind the injected protocols.
public actor AgentService {
    private let store: CredentialStore
    private let latch: SuspectLatch
    private let telemetry: TelemetryExporter
    private let users: SignedInUserProvider
    private let prompter: CredentialPrompter
    private let validator: CredentialValidator
    private let now: @Sendable () -> Date

    /// Until `reload(config:)` delivers a valid profile the broker holds a disabled
    /// placeholder, so even a missed `configValid` check could not supply.
    private var broker: AuthBroker
    private var configValid = false
    private var signedInUser: String?
    private var lastAccount: String?
    /// A dialog is up (or queued); don't stack another until it is answered or dismissed.
    private var promptOutstanding = false
    /// Mirrors `latch`, and keeps latching for this process even if the file can't be written.
    private var suspectLatched: Bool

    public init(
        store: CredentialStore,
        latch: SuspectLatch,
        telemetry: TelemetryExporter,
        users: SignedInUserProvider,
        prompter: CredentialPrompter,
        validator: CredentialValidator,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.store = store
        self.latch = latch
        self.telemetry = telemetry
        self.users = users
        self.prompter = prompter
        self.validator = validator
        self.now = now
        let stored = try? store.read()
        lastAccount = stored?.account
        // A restart must not forget a latch set before it: the stale password is still stored.
        suspectLatched = latch.isSet
        broker = AuthBroker(
            config: NTLMacConfig(enabled: false, killDate: .distantPast, realm: "", netbiosDomain: "", rules: []),
            credentialState: stored?.account == nil ? .missing : suspectLatched ? .suspect : .ok
        )
    }

    // MARK: Requests

    public func handle(_ request: AuthRequest) async -> AgentReply {
        guard configValid else {
            await recordAuth(request, ruleId: nil, outcome: .configInvalid)
            return .decline(.configInvalid)
        }
        let stored = readStore()
        let tripsBefore = broker.breakerTrips
        // Decide on a copy and commit it only if the answer stands: a supply we can't back
        // with a credential must not be remembered as answered for this browser request.
        var next = broker
        let reply: AgentReply
        switch (next.decide(request, now: now()), stored) {
        case let (.supply, .success(credential?)):
            broker = next
            reply = .supply(username: "\(broker.config.netbiosDomain)\\\(credential.account)", password: credential.password)
        case (.supply, _):
            // Keychain error (a missing item already made the broker decline). Never supply.
            reply = .decline(.credentialMissing)
        case let (.decline(outcome), _):
            broker = next
            reply = .decline(outcome)
        }

        let outcome: Outcome = if case let .decline(o) = reply { o } else { .supplied }
        await recordAuth(request, ruleId: broker.matchingRule(host: request.host)?.id, outcome: outcome)
        if broker.breakerTrips > tripsBefore {
            let user = enduser
            await telemetry.record { $0.recordBreakerTrip(host: request.host, user: user) }
            latchSuspect()
            await prompt(.retryRejected)
        } else if outcome == .credentialMissing, broker.credentialState == .missing {
            await prompt(.enrol)
        }
        return reply
    }

    // MARK: Credential lifecycle

    /// The Kerberos SSO extension reported an AD password change: stop supplying the old
    /// password before it locks the account, and ask for the new one.
    public func passwordChangedExternally() async {
        broker.passwordChangedExternally()
        latchSuspect()
        await prompt(.adPasswordChanged)
    }

    /// The user entered a password in the dialog. It is validated, then stored, and only
    /// then does supply resume.
    public func credentialReplaced(_ credential: Credential) async throws {
        guard configValid else { throw CredentialReplacementError.configInvalid }
        guard try await validator.validate(credential, realm: broker.config.realm) else {
            promptOutstanding = false
            await prompt(.validationFailed)
            throw CredentialReplacementError.rejected
        }
        try store.write(credential)
        lastAccount = credential.account
        // The only place the latch clears. If the file can't be removed, the next restart
        // starts suspect and asks again: annoying, never a lockout.
        try? latch.clear()
        suspectLatched = false
        broker.credentialReplaced()
        promptOutstanding = false
    }

    /// The user closed the dialog without entering a password.
    public func promptDismissed() {
        promptOutstanding = false
    }

    /// The credential state, refreshed from the store, for the telemetry gauge.
    public func credentialState() -> CredentialState {
        _ = readStore()
        return broker.credentialState
    }

    // MARK: Config and telemetry

    /// A new managed profile, or nil if it is missing or malformed (fail closed). The
    /// breaker's memory and the suspect latch survive reloads.
    public func reload(config: NTLMacConfig?) async {
        guard let config else {
            configValid = false
            return
        }
        let realmChanged = config.realm.uppercased() != broker.config.realm.uppercased()
        broker.update(config: config)
        configValid = true
        if realmChanged || signedInUser == nil {
            signedInUser = try? await users.currentUser(realm: config.realm)
        }
    }

    public func flushTelemetry() async throws -> FlushReport {
        try await telemetry.flush(credentialState: credentialState(), now: now())
    }

    // MARK: Private

    private var enduser: String? { signedInUser ?? lastAccount }

    /// Reads the store and brings the broker's credential state in line with it. A read
    /// error changes nothing: a locked Keychain says nothing about the credential.
    private func readStore() -> Result<Credential?, Error> {
        let result = Result { try store.read() }
        switch result {
        case .success(nil) where broker.credentialState != .missing:
            broker.credentialRemoved()
        case let .success(credential?):
            lastAccount = credential.account
            // Only a credential appearing ends `missing`, and only to `ok` if nothing latched;
            // `suspect` ends only through `credentialReplaced`, after validation.
            if broker.credentialState == .missing {
                if suspectLatched { broker.passwordChangedExternally() } else { broker.credentialReplaced() }
            }
        default:
            break
        }
        return result
    }

    private func latchSuspect() {
        suspectLatched = true
        // A failed write still latches in memory; only the restart protection is lost.
        try? latch.set()
    }

    private func prompt(_ reason: PromptReason) async {
        guard !promptOutstanding else { return }
        promptOutstanding = true
        let user = enduser
        prompter.requestCredential(reason: reason, account: user)
        await telemetry.record { $0.recordPrompt(reason: reason, user: user) }
    }

    private func recordAuth(_ request: AuthRequest, ruleId: String?, outcome: Outcome) async {
        let user = enduser
        await telemetry.record { $0.recordAuth(host: request.host, ruleId: ruleId, user: user, outcome: outcome) }
    }
}
