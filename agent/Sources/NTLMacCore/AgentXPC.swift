import Foundation
import Security

// MARK: Code-signing policy

public enum CodeSigningError: Error, Equatable {
    case invalidTeamID
    case invalidIdentifier
    case invalidRequirement(OSStatus)
    case cannotInspectSelf(OSStatus)
}

/// Who may talk to whom over XPC: both binaries must be signed by Apple-issued certificates
/// for one team, with the expected bundle identifiers. The agent checks the shim; the shim
/// checks the agent.
public struct CodeSigningPolicy: Sendable, Equatable {
    public static let defaultAgentIdentifier = "com.example.ntlmac.agent"
    public static let defaultShimIdentifier = "com.example.ntlmac.nmh"

    public let teamID: String
    public let agentIdentifier: String
    public let shimIdentifier: String

    public init(
        teamID: String,
        agentIdentifier: String = defaultAgentIdentifier,
        shimIdentifier: String = defaultShimIdentifier
    ) throws {
        // Values are pasted into requirement-language strings, so allow nothing that could
        // close a quote or add a clause.
        guard teamID.count == 10, teamID.allSatisfy({ ("A" ... "Z").contains($0) || ("0" ... "9").contains($0) }) else {
            throw CodeSigningError.invalidTeamID
        }
        for id in [agentIdentifier, shimIdentifier] {
            guard !id.isEmpty, id.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-") }) else {
                throw CodeSigningError.invalidIdentifier
            }
        }
        self.teamID = teamID
        self.agentIdentifier = agentIdentifier
        self.shimIdentifier = shimIdentifier
    }

    /// What the shim requires of the agent.
    public var agentRequirement: String { requirement(identifier: agentIdentifier) }
    /// What the agent requires of the shim.
    public var shimRequirement: String { requirement(identifier: shimIdentifier) }

    private func requirement(identifier: String) -> String {
        #"anchor apple generic and certificate leaf[subject.OU] = "\#(teamID)" and identifier "\#(identifier)""#
    }
}

public enum CodeSigning {
    public static func validate(requirement: String) throws {
        _ = try compile(requirement)
    }

    /// Whether this process's own code satisfies `requirement`.
    public static func currentProcessSatisfies(_ requirement: String) throws -> Bool {
        let req = try compile(requirement)
        var code: SecCode?
        let status = SecCodeCopySelf([], &code)
        guard status == errSecSuccess, let code else { throw CodeSigningError.cannotInspectSelf(status) }
        return SecCodeCheckValidity(code, [], req) == errSecSuccess
    }

    private static func compile(_ requirement: String) throws -> SecRequirement {
        var req: SecRequirement?
        let status = SecRequirementCreateWithString(requirement as CFString, [], &req)
        guard status == errSecSuccess, let req else { throw CodeSigningError.invalidRequirement(status) }
        return req
    }
}

// MARK: Wire format

/// The agent's answer to one `AuthRequest`.
public enum AgentReply: Codable, Sendable, Equatable {
    case supply(username: String, password: String)
    case decline(Outcome)

    public func hostResponse(id: Int) -> HostResponse {
        switch self {
        case let .supply(username, password): .supply(id: id, username: username, password: password)
        case let .decline(outcome): .decline(id: id, outcome: outcome)
        }
    }
}

// Keep the password out of logs, `dump` and debugger summaries.
extension AgentReply: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        switch self {
        case let .supply(username, _): "supply(username: \(username), password: <redacted>)"
        case let .decline(outcome): "decline(\(outcome.rawValue))"
        }
    }

    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["reply": description]) }
}

@objc public protocol AgentXPCProtocol {
    /// Carries no data. The shim calls it first: a client-side code-signing requirement
    /// is only enforced on messages *from* the peer, so the shim sends nothing that
    /// matters until a reply has proven the agent is genuine.
    func hello(withReply reply: @escaping @Sendable () -> Void)
    /// JSON `AuthRequest` in, JSON `AgentReply` out (nil if the request was malformed).
    func authenticate(_ request: Data, withReply reply: @escaping @Sendable (Data?) -> Void)
}

private func agentInterface() -> NSXPCInterface {
    NSXPCInterface(with: AgentXPCProtocol.self)
}

// MARK: Agent side

/// Accepts connections only from code that satisfies `clientRequirement` (the signed
/// shim), checked by the system for every connection.
public final class AgentXPCServer: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    public typealias Handler = @Sendable (AuthRequest) async -> AgentReply

    private let listener: NSXPCListener
    private let clientRequirement: String
    private let handler: Handler

    /// `listener`: `NSXPCListener(machServiceName:)` in the LaunchAgent, `.anonymous()` in tests.
    public init(listener: NSXPCListener, clientRequirement: String, handler: @escaping Handler) {
        self.listener = listener
        self.clientRequirement = clientRequirement
        self.handler = handler
        super.init()
        listener.delegate = self
    }

    public var endpoint: NSXPCListenerEndpoint { listener.endpoint }

    public func resume() { listener.resume() }
    public func invalidate() { listener.invalidate() }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.setCodeSigningRequirement(clientRequirement)
        connection.exportedInterface = agentInterface()
        connection.exportedObject = Exported(handler: handler)
        connection.resume()
        return true
    }

    private final class Exported: NSObject, AgentXPCProtocol, Sendable {
        let handler: Handler
        init(handler: @escaping Handler) { self.handler = handler }

        func hello(withReply reply: @escaping @Sendable () -> Void) { reply() }

        func authenticate(_ request: Data, withReply reply: @escaping @Sendable (Data?) -> Void) {
            guard let decoded = try? JSONDecoder().decode(AuthRequest.self, from: request) else {
                reply(nil)
                return
            }
            let handler = handler
            Task {
                let answer = await handler(decoded)
                reply(try? JSONEncoder().encode(answer))
            }
        }
    }
}

// MARK: Shim side

public enum AgentXPCError: Error, Equatable {
    /// The agent isn't running, failed the code-signing check, or rejected us.
    case connectionFailed(String)
    case timedOut
    case malformedReply
}

/// Talks to the agent only if it satisfies `agentRequirement` (the signed agent).
public final class AgentXPCClient: @unchecked Sendable {
    private let connection: NSXPCConnection
    private let lock = NSLock()
    private var verified = false

    public convenience init(machServiceName: String, agentRequirement: String) {
        self.init(connection: NSXPCConnection(machServiceName: machServiceName), agentRequirement: agentRequirement)
    }

    public convenience init(endpoint: NSXPCListenerEndpoint, agentRequirement: String) {
        self.init(connection: NSXPCConnection(listenerEndpoint: endpoint), agentRequirement: agentRequirement)
    }

    private init(connection: NSXPCConnection, agentRequirement: String) {
        self.connection = connection
        connection.remoteObjectInterface = agentInterface()
        connection.setCodeSigningRequirement(agentRequirement)
        connection.resume()
    }

    public func invalidate() { connection.invalidate() }

    public func authenticate(_ request: AuthRequest, timeout: TimeInterval = 2) async throws -> AgentReply {
        let payload = try JSONEncoder().encode(request)
        if !lock.withLock({ verified }) {
            try await call(timeout: timeout) { agent, finish in agent.hello { finish(.success(())) } }
            lock.withLock { verified = true }
        }
        return try await call(timeout: timeout) { agent, finish in
            agent.authenticate(payload) { data in
                guard let data, let reply = try? JSONDecoder().decode(AgentReply.self, from: data) else {
                    finish(.failure(AgentXPCError.malformedReply))
                    return
                }
                finish(.success(reply))
            }
        }
    }

    private func call<T: Sendable>(
        timeout: TimeInterval,
        _ send: (AgentXPCProtocol, @escaping @Sendable (Result<T, Error>) -> Void) -> Void
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            let once = Once(continuation)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { once.finish(.failure(AgentXPCError.timedOut)) }
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                once.finish(.failure(AgentXPCError.connectionFailed(error.localizedDescription)))
            }
            guard let agent = proxy as? AgentXPCProtocol else {
                once.finish(.failure(AgentXPCError.connectionFailed("unexpected proxy type")))
                return
            }
            send(agent, once.finish)
        }
    }

    /// Resumes the continuation exactly once: reply, error handler and timeout all race.
    private final class Once<T: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<T, Error>?
        init(_ continuation: CheckedContinuation<T, Error>) { self.continuation = continuation }

        func finish(_ result: Result<T, Error>) {
            lock.withLock {
                continuation?.resume(with: result)
                continuation = nil
            }
        }
    }
}
