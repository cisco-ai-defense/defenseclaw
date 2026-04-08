import Foundation

public enum SubsystemState: String, Codable, Sendable {
    case starting, running, reconnecting, stopped, error, disabled
}

public struct SubsystemHealth: Codable, Sendable {
    public let state: SubsystemState
    public let since: Date
    public let lastError: String?
    public let details: [String: AnyCodable]?

    enum CodingKeys: String, CodingKey {
        case state, since
        case lastError = "last_error"
        case details
    }
}

public struct HealthSnapshot: Codable, Sendable {
    public let startedAt: Date
    public let uptimeMs: Int64
    public let gateway: SubsystemHealth
    public let watcher: SubsystemHealth
    public let api: SubsystemHealth
    public let guardrail: SubsystemHealth
    public let telemetry: SubsystemHealth
    public let splunk: SubsystemHealth
    public let sandbox: SubsystemHealth?

    enum CodingKeys: String, CodingKey {
        case startedAt = "started_at"
        case uptimeMs = "uptime_ms"
        case gateway, watcher, api, guardrail, telemetry, splunk, sandbox
    }

    /// The sidecar is healthy if its core subsystems (api, watcher) are running.
    /// The gateway subsystem connects to OpenClaw — it may be reconnecting if
    /// the OpenClaw gateway isn't started yet, but the sidecar itself is still operational.
    public var isHealthy: Bool {
        let core = [api, watcher]
        let coreOK = core.allSatisfy { $0.state == .running || $0.state == .disabled }
        let optional = [guardrail, telemetry, splunk]
        let optionalOK = optional.allSatisfy { $0.state == .running || $0.state == .disabled || $0.state == .reconnecting }
        return coreOK && optionalOK
    }

    /// Whether the OpenClaw gateway subsystem inside the sidecar has a live connection.
    public var isGatewayConnected: Bool {
        gateway.state == .running
    }

    public var alertCount: Int { 0 }
}

public struct AnyCodable: Codable, Sendable, CustomStringConvertible {
    public let value: Any

    public init(_ value: Any) { self.value = value }

    public var description: String {
        switch value {
        case let s as String: return s
        case let i as Int: return "\(i)"
        case let d as Double: return "\(d)"
        case let b as Bool: return b ? "true" : "false"
        default: return String(describing: value)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let s = try? container.decode(String.self) { value = s }
        else if let i = try? container.decode(Int.self) { value = i }
        else if let d = try? container.decode(Double.self) { value = d }
        else if let b = try? container.decode(Bool.self) { value = b }
        else { value = "unknown" }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case let s as String: try container.encode(s)
        case let i as Int: try container.encode(i)
        case let d as Double: try container.encode(d)
        case let b as Bool: try container.encode(b)
        default: try container.encode(String(describing: value))
        }
    }
}
