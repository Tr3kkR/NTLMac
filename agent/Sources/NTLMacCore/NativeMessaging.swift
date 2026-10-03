import Foundation

/// Chromium native messaging framing: a 32-bit length in native byte order (little-endian
/// on every Mac we support) followed by UTF-8 JSON.
public enum NativeMessaging {
    /// Chromium refuses host-to-browser messages over 1 MB.
    public static let maxOutgoingBytes = 1_048_576
    /// Our requests are tiny; anything larger is a broken or hostile peer.
    public static let maxIncomingBytes = 64 * 1024

    public enum Error: Swift.Error, Equatable {
        case messageTooLarge
    }

    public static func frame(_ payload: Data) throws -> Data {
        guard payload.count <= maxOutgoingBytes else { throw Error.messageTooLarge }
        var length = UInt32(payload.count).littleEndian
        return Data(bytes: &length, count: 4) + payload
    }
}

public struct NativeMessageDecoder: Sendable {
    private var buffer = Data()

    public init() {}

    public mutating func append(_ data: Data) {
        buffer.append(data)
    }

    /// Next complete message, or nil if more bytes are needed.
    public mutating func next() throws -> Data? {
        guard buffer.count >= 4 else { return nil }
        let b = Array(buffer.prefix(4))
        let length = Int(UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16 | UInt32(b[3]) << 24)
        guard length <= NativeMessaging.maxIncomingBytes else { throw NativeMessaging.Error.messageTooLarge }
        guard buffer.count >= 4 + length else { return nil }
        let start = buffer.startIndex + 4
        let message = buffer[start ..< start + length]
        buffer = Data(buffer[(start + length)...])
        return Data(message)
    }
}

/// Extension → host.
public struct HostRequest: Codable, Sendable {
    public var id: Int
    public var type: String
    public var request: AuthRequest
}

/// Host → extension. `id` correlates with the request.
public enum HostResponse: Sendable, Encodable, CustomStringConvertible, CustomDebugStringConvertible {
    case supply(id: Int, username: String, password: String)
    case decline(id: Int, outcome: Outcome)

    private enum CodingKeys: String, CodingKey {
        case id, action, username, password, outcome
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .supply(id, username, password):
            try c.encode(id, forKey: .id)
            try c.encode("supply", forKey: .action)
            try c.encode(username, forKey: .username)
            try c.encode(password, forKey: .password)
        case let .decline(id, outcome):
            try c.encode(id, forKey: .id)
            try c.encode("decline", forKey: .action)
            try c.encode(outcome, forKey: .outcome)
        }
    }

    // Keep the password out of any log line that interpolates a response.
    public var description: String {
        switch self {
        case let .supply(id, username, _): "supply(id: \(id), username: \(username), password: <redacted>)"
        case let .decline(id, outcome): "decline(id: \(id), outcome: \(outcome.rawValue))"
        }
    }

    public var debugDescription: String { description }
}
