import Foundation

public enum ConfigLoader {
    public static let preferenceDomain = NTLMacIdentity.current.preferenceDomain

    /// Reads the Jamf-managed preference domain (`/Library/Managed Preferences`).
    public static func loadManaged(domain: String = preferenceDomain) throws -> NTLMacConfig {
        let prefs = UserDefaults(suiteName: domain)?.dictionaryRepresentation() ?? [:]
        return try decode(preferences: prefs)
    }

    public static func decode(preferences: [String: Any]) throws -> NTLMacConfig {
        // Round-trip through a plist so Dates and nested arrays decode natively; drop
        // values a plist can't hold (UserDefaults merges in global-domain keys).
        let clean = preferences.filter { PropertyListSerialization.propertyList($0.value, isValidFor: .binary) }
        let data = try PropertyListSerialization.data(fromPropertyList: clean, format: .binary, options: 0)
        return try PropertyListDecoder().decode(NTLMacConfig.self, from: data)
    }

    /// Spike/dev only: config from a JSON file with ISO-8601 dates.
    public static func decode(json: Data) throws -> NTLMacConfig {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(NTLMacConfig.self, from: json)
    }
}
