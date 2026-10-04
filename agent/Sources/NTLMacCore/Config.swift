import Foundation

/// Managed configuration delivered by Jamf in the `com.example.ntlmac` preference domain.
public struct NTLMacConfig: Codable, Sendable, Equatable {
    /// Master switch. `false` stops NTLMac supplying credentials immediately.
    public var enabled: Bool
    /// Hard sunset. After this instant NTLMac never supplies credentials.
    public var killDate: Date
    /// Kerberos realm used to look up the signed-in user via `app-sso -i <realm>`.
    public var realm: String
    /// NetBIOS domain prefixed to the username (`DOMAIN\user`).
    public var netbiosDomain: String
    public var rules: [AllowlistRule]
    /// Host patterns that are never supplied credentials, even if a rule matches.
    public var deny: [String]
    public var httpExceptions: [HTTPException]
    public var otlpEndpoint: String?
    /// Salt for the pseudonymous `host.id` telemetry attribute (SHA-256 of salt:serial).
    public var hostIDSalt: String?

    public init(
        enabled: Bool,
        killDate: Date,
        realm: String,
        netbiosDomain: String,
        rules: [AllowlistRule],
        deny: [String] = [],
        httpExceptions: [HTTPException] = [],
        otlpEndpoint: String? = nil,
        hostIDSalt: String? = nil
    ) {
        self.enabled = enabled
        self.killDate = killDate
        self.realm = realm
        self.netbiosDomain = netbiosDomain
        self.rules = rules
        self.deny = deny
        self.httpExceptions = httpExceptions
        self.otlpEndpoint = otlpEndpoint
        self.hostIDSalt = hostIDSalt
    }

    // Optional lists may be omitted from the Jamf profile; everything else is required so
    // a half-written profile fails closed.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decode(Bool.self, forKey: .enabled)
        killDate = try c.decode(Date.self, forKey: .killDate)
        realm = try c.decode(String.self, forKey: .realm)
        netbiosDomain = try c.decode(String.self, forKey: .netbiosDomain)
        rules = try c.decode([AllowlistRule].self, forKey: .rules)
        deny = try c.decodeIfPresent([String].self, forKey: .deny) ?? []
        httpExceptions = try c.decodeIfPresent([HTTPException].self, forKey: .httpExceptions) ?? []
        otlpEndpoint = try c.decodeIfPresent(String.self, forKey: .otlpEndpoint)
        hostIDSalt = try c.decodeIfPresent(String.self, forKey: .hostIDSalt)
    }
}

public struct AllowlistRule: Codable, Sendable, Equatable {
    /// Stable identifier reported in telemetry, e.g. a CMDB service ID.
    public var id: String
    /// Exact host (`app.corp.example`) or wildcard suffix (`*.corp.example`).
    public var pattern: String

    public init(id: String, pattern: String) {
        self.id = id
        self.pattern = pattern
    }
}

/// Risk-accepted plain-HTTP host. Expires so it resurfaces in Cyber's review.
public struct HTTPException: Codable, Sendable, Equatable {
    public var host: String
    public var expires: Date

    public init(host: String, expires: Date) {
        self.host = host
        self.expires = expires
    }
}
