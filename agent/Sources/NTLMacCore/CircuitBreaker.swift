import Foundation

/// Lockout guard. Remembers which browser requests we already answered, so a second
/// challenge for the same request (= the DC rejected our credential) is detected, and
/// caps supplies per host so a misbehaving page cannot burn the AD lockout threshold.
public struct CircuitBreaker: Sendable {
    /// How long a supplied request ID is remembered. Chromium request IDs restart after a
    /// browser restart, so this must stay short to avoid false retries.
    public static let requestIDTTL: TimeInterval = 300
    public static let rateWindow: TimeInterval = 60
    public static let maxSuppliesPerHostPerWindow = 30
    public static let maxTrackedRequests = 10_000

    private var answered: [String: Date] = [:]
    private var answeredOrder: [String] = []
    private var suppliesByHost: [String: [Date]] = [:]

    public init() {}

    public var trackedRequestCount: Int { answered.count }

    public mutating func isRetry(requestId: String, now: Date) -> Bool {
        expire(now: now)
        return answered[requestId] != nil
    }

    public mutating func allowSupply(host: String, now: Date) -> Bool {
        let recent = (suppliesByHost[host] ?? []).filter { now.timeIntervalSince($0) < Self.rateWindow }
        suppliesByHost[host] = recent.isEmpty ? nil : recent
        return recent.count < Self.maxSuppliesPerHostPerWindow
    }

    public mutating func recordSupply(requestId: String, host: String, now: Date) {
        if answered.updateValue(now, forKey: requestId) == nil {
            answeredOrder.append(requestId)
        }
        while answeredOrder.count > Self.maxTrackedRequests {
            answered[answeredOrder.removeFirst()] = nil
        }
        suppliesByHost[host, default: []].append(now)
    }

    public mutating func reset() {
        self = CircuitBreaker()
    }

    private mutating func expire(now: Date) {
        while let oldest = answeredOrder.first,
              let at = answered[oldest],
              now.timeIntervalSince(at) > Self.requestIDTTL {
            answeredOrder.removeFirst()
            answered[oldest] = nil
        }
    }
}
