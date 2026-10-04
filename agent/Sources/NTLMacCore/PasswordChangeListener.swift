import Foundation
import notify

/// Darwin (`notify(3)`) notifications, behind a protocol so tests can post fakes.
public protocol DarwinNotificationCenter: Sendable {
    /// Calls `handler` on `queue` each time `name` is posted. Returns a token for `cancel`.
    func observe(_ name: String, queue: DispatchQueue, handler: @escaping @Sendable () -> Void) throws -> Int32
    func cancel(_ token: Int32)
}

public struct DarwinNotifyError: Error, Equatable {
    public var status: UInt32
}

public struct SystemDarwinNotificationCenter: DarwinNotificationCenter {
    public init() {}

    public func observe(_ name: String, queue: DispatchQueue, handler: @escaping @Sendable () -> Void) throws -> Int32 {
        var token: Int32 = 0
        let status = notify_register_dispatch(name, &token, queue) { _ in handler() }
        guard status == NOTIFY_STATUS_OK else { throw DarwinNotifyError(status: status) }
        return token
    }

    public func cancel(_ token: Int32) {
        notify_cancel(token)
    }
}

/// Watches for the Kerberos SSO extension reporting an AD password change, so the agent
/// can stop supplying the old password (`AuthBroker.passwordChangedExternally()`) and
/// re-prompt before it causes a lockout. Names are from Apple's Kerberos SSO extension
/// guide; their delivery on a bound Mac is still spike item (c).
public final class PasswordChangeListener: @unchecked Sendable {
    public static let notificationNames = [
        "com.apple.KerberosPlugin.ADPasswordChanged",
        "com.apple.KerberosExtension.passwordChangedWithPasswordSync",
    ]

    private let center: DarwinNotificationCenter
    private let queue: DispatchQueue
    private let onChange: @Sendable (String) -> Void
    private let lock = NSLock()
    private var tokens: [Int32] = []

    /// `onChange` receives the notification name, on `queue`.
    public init(
        center: DarwinNotificationCenter = SystemDarwinNotificationCenter(),
        queue: DispatchQueue = DispatchQueue(label: "com.example.ntlmac.password-change"),
        onChange: @escaping @Sendable (String) -> Void
    ) {
        self.center = center
        self.queue = queue
        self.onChange = onChange
    }

    deinit { stop() }

    public func start() throws {
        try lock.withLock {
            guard tokens.isEmpty else { return }
            do {
                for name in Self.notificationNames {
                    let onChange = self.onChange
                    tokens.append(try center.observe(name, queue: queue) { onChange(name) })
                }
            } catch {
                tokens.forEach(center.cancel)
                tokens.removeAll()
                throw error
            }
        }
    }

    public func stop() {
        lock.withLock {
            tokens.forEach(center.cancel)
            tokens.removeAll()
        }
    }
}
