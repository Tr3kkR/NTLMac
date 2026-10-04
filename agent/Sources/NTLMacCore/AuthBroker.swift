import Foundation

/// An `onAuthRequired` event as forwarded by the extension.
public struct AuthRequest: Codable, Sendable, Equatable {
    public var requestId: String
    /// `details.challenger.host`
    public var host: String
    public var port: Int
    /// Scheme of `details.url` ("https", "http", ...).
    public var urlScheme: String
    /// `details.scheme`: the HTTP auth scheme ("ntlm", "basic", ...).
    public var authScheme: String
    public var isProxy: Bool

    public init(requestId: String, host: String, port: Int, urlScheme: String, authScheme: String, isProxy: Bool) {
        self.requestId = requestId
        self.host = host
        self.port = port
        self.urlScheme = urlScheme
        self.authScheme = authScheme
        self.isProxy = isProxy
    }
}

public enum CredentialState: String, Codable, Sendable {
    case ok, suspect, missing
}

/// Telemetry `outcome` attribute values. Raw values are part of the schema contract.
public enum Outcome: String, Codable, Sendable, CaseIterable {
    case supplied
    case notAllowlisted = "not_allowlisted"
    case httpBlocked = "http_blocked"
    case notNTLM = "not_ntlm"
    case proxyIgnored = "proxy_ignored"
    case suspectBlocked = "suspect_blocked"
    case retryCancelled = "retry_cancelled"
    case rateLimited = "rate_limited"
    case credentialMissing = "credential_missing"
    case killswitch
    case configInvalid = "config_invalid"
    case agentUnavailable = "agent_unavailable"
}

public enum Decision: Equatable, Sendable {
    case supply(ruleId: String)
    case decline(Outcome)

    public var outcome: Outcome {
        switch self {
        case .supply: .supplied
        case .decline(let o): o
        }
    }
}

/// Pure decision engine: given config, credential state and the breaker's memory, should
/// this challenge be answered? Holds no secrets; the agent attaches the credential.
public struct AuthBroker: Sendable {
    public private(set) var config: NTLMacConfig
    public private(set) var credentialState: CredentialState
    public private(set) var breakerTrips = 0
    private var allowlist: Allowlist
    private var breaker = CircuitBreaker()

    public init(config: NTLMacConfig, credentialState: CredentialState) {
        self.config = config
        self.credentialState = credentialState
        self.allowlist = Allowlist(rules: config.rules, deny: config.deny)
    }

    public mutating func update(config: NTLMacConfig) {
        self.config = config
        self.allowlist = Allowlist(rules: config.rules, deny: config.deny)
    }

    public mutating func decide(_ req: AuthRequest, now: Date) -> Decision {
        guard config.enabled, now < config.killDate else { return .decline(.killswitch) }
        guard !req.isProxy else { return .decline(.proxyIgnored) }
        // Only NTLM: Basic/Digest would hand the password to the server, Negotiate is
        // Kerberos' job.
        guard req.authScheme.lowercased() == "ntlm" else { return .decline(.notNTLM) }
        guard let rule = allowlist.match(host: req.host),
              let host = HostName.normalize(req.host)
        else { return .decline(.notAllowlisted) }
        guard transportAllowed(urlScheme: req.urlScheme, host: host, now: now) else {
            return .decline(.httpBlocked)
        }

        if breaker.isRetry(requestId: req.requestId, now: now) {
            if credentialState == .ok {
                credentialState = .suspect
                breakerTrips += 1
            }
            return .decline(.retryCancelled)
        }
        switch credentialState {
        case .suspect: return .decline(.suspectBlocked)
        case .missing: return .decline(.credentialMissing)
        case .ok: break
        }
        guard breaker.allowSupply(host: host, now: now) else { return .decline(.rateLimited) }

        breaker.recordSupply(requestId: req.requestId, host: host, now: now)
        return .supply(ruleId: rule.id)
    }

    /// The allow rule `host` falls under, if any. Telemetry reports declines on listed hosts
    /// (HTTP blocked, suspect) against their rule.
    public func matchingRule(host: String) -> AllowlistRule? {
        allowlist.match(host: host)
    }

    /// Call after a new password has been validated (Kerberos AS-REQ) and stored.
    public mutating func credentialReplaced() {
        credentialState = .ok
        breaker.reset()
    }

    /// Call on `com.apple.KerberosPlugin.ADPasswordChanged` and similar signals.
    public mutating func passwordChangedExternally() {
        credentialState = .suspect
    }

    public mutating func credentialRemoved() {
        credentialState = .missing
        breaker.reset()
    }

    private func transportAllowed(urlScheme: String, host: String, now: Date) -> Bool {
        switch urlScheme.lowercased() {
        case "https":
            return true
        case "http":
            return config.httpExceptions.contains {
                HostName.normalize($0.host) == host && now < $0.expires
            }
        default:
            return false
        }
    }
}
