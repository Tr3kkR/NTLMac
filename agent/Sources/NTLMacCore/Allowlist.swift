/// Decides which hosts may be supplied the user's credential.
///
/// Patterns are either an exact host or `*.suffix`, where the suffix has at least two
/// labels (so `*.com` is rejected). A wildcard matches subdomains at any depth but not
/// the apex. Deny patterns always win, and among allow rules the most specific wins.
public struct Allowlist: Sendable {
    private enum Pattern: Sendable {
        case exact(String)
        case suffix(String) // stored with leading dot, e.g. ".corp.example"

        func matches(_ host: String) -> Bool {
            switch self {
            case .exact(let h): host == h
            case .suffix(let s): host.hasSuffix(s)
            }
        }

        var specificity: Int {
            switch self {
            case .exact(let h): Int.max / 2 + h.count
            case .suffix(let s): s.count
            }
        }
    }

    private let allow: [(rule: AllowlistRule, pattern: Pattern)]
    private let deny: [Pattern]
    /// Rule IDs whose patterns were invalid and ignored; the agent logs these.
    public let rejectedRuleIDs: [String]

    public init(rules: [AllowlistRule], deny: [String]) {
        var allow: [(AllowlistRule, Pattern)] = []
        var rejected: [String] = []
        for rule in rules {
            if let p = Self.parse(rule.pattern) {
                allow.append((rule, p))
            } else {
                rejected.append(rule.id)
            }
        }
        self.allow = allow.sorted { $0.1.specificity > $1.1.specificity }
        self.deny = deny.compactMap(Self.parse)
        self.rejectedRuleIDs = rejected
    }

    public func match(host rawHost: String) -> AllowlistRule? {
        guard let host = HostName.normalize(rawHost) else { return nil }
        if deny.contains(where: { $0.matches(host) }) { return nil }
        return allow.first { $0.pattern.matches(host) }?.rule
    }

    private static func parse(_ raw: String) -> Pattern? {
        if raw.hasPrefix("*.") {
            guard let suffix = HostName.normalize(String(raw.dropFirst(2))),
                  suffix.split(separator: ".").count >= 2
            else { return nil }
            return .suffix("." + suffix)
        }
        return HostName.normalize(raw).map(Pattern.exact)
    }
}

public enum HostName {
    /// Lowercases, strips a single trailing dot and rejects anything that is not an
    /// ASCII DNS name. Browsers hand us IDNs in punycode, so non-ASCII means tampering.
    public static func normalize(_ raw: String) -> String? {
        var host = raw.lowercased()
        if host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty, host.count <= 253 else { return nil }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        for label in labels {
            guard !label.isEmpty, label.count <= 63,
                  label.utf8.allSatisfy({ isLDH($0) }),
                  label.first != "-", label.last != "-"
            else { return nil }
        }
        return host
    }

    private static func isLDH(_ c: UInt8) -> Bool {
        (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x2D
    }
}
