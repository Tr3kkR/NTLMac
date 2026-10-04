import Foundation

/// The native host's whole job: hand each request to the agent and return its reply. Any
/// failure (agent not running, failed code-signing check, timeout, garbage) becomes a
/// decline, so the browser falls back to its own prompt. The shim reads no config and no
/// credential.
public final class AgentForwarder: @unchecked Sendable {
    /// Per XPC call. The first request makes two (hello, then the request), so the worst
    /// case is 2 s, inside the extension's 3 s `AGENT_TIMEOUT_MS`.
    public static let defaultTimeout: TimeInterval = 1

    private let connect: @Sendable () -> AgentXPCClient?
    private let timeout: TimeInterval
    private let lock = NSLock()
    private var client: AgentXPCClient?

    /// `connect` returns nil if the agent can't be verified (no requirement to check it by).
    public init(timeout: TimeInterval = defaultTimeout, connect: @escaping @Sendable () -> AgentXPCClient?) {
        self.timeout = timeout
        self.connect = connect
    }

    public func forward(_ request: AuthRequest) async -> AgentReply {
        guard let client = current() else { return .decline(.agentUnavailable) }
        do {
            return try await client.authenticate(request, timeout: timeout)
        } catch {
            // Start afresh next time: an agent launched after this host started is found,
            // and a hung one isn't waited on twice.
            lock.withLock { if self.client === client { self.client = nil } }
            client.invalidate()
            return .decline(.agentUnavailable)
        }
    }

    private func current() -> AgentXPCClient? {
        lock.withLock {
            if client == nil { client = connect() }
            return client
        }
    }
}
