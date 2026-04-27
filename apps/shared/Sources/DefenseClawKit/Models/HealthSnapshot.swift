import Foundation

public enum SubsystemState: String, Codable, Sendable {
    case starting, running, reconnecting, stopped, error, disabled
}

public struct SubsystemHealth: Codable, Sendable {
    public let state: SubsystemState
    public let since: Date
    public let lastError: String?
    public let details: [String: AnyCodable]?

    public init(
        state: SubsystemState,
        since: Date = Date(),
        lastError: String? = nil,
        details: [String: AnyCodable]? = nil
    ) {
        self.state = state
        self.since = since
        self.lastError = lastError
        self.details = details
    }

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
        case gateway, watcher, api, guardrail, telemetry, splunk, sinks, sandbox
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let fallbackDate = Date()

        startedAt = (try? container.decode(Date.self, forKey: .startedAt)) ?? fallbackDate
        uptimeMs = (try? container.decode(Int64.self, forKey: .uptimeMs)) ?? 0
        gateway = (try? container.decode(SubsystemHealth.self, forKey: .gateway))
            ?? SubsystemHealth(state: .stopped, since: fallbackDate)
        watcher = (try? container.decode(SubsystemHealth.self, forKey: .watcher))
            ?? SubsystemHealth(state: .disabled, since: fallbackDate)
        api = (try? container.decode(SubsystemHealth.self, forKey: .api))
            ?? SubsystemHealth(state: .stopped, since: fallbackDate)
        guardrail = (try? container.decode(SubsystemHealth.self, forKey: .guardrail))
            ?? SubsystemHealth(state: .disabled, since: fallbackDate)
        telemetry = (try? container.decode(SubsystemHealth.self, forKey: .telemetry))
            ?? SubsystemHealth(state: .disabled, since: fallbackDate)
        splunk = (try? container.decode(SubsystemHealth.self, forKey: .splunk))
            ?? (try? container.decode(SubsystemHealth.self, forKey: .sinks))
            ?? SubsystemHealth(state: .disabled, since: fallbackDate)
        sandbox = try? container.decode(SubsystemHealth.self, forKey: .sandbox)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(startedAt, forKey: .startedAt)
        try container.encode(uptimeMs, forKey: .uptimeMs)
        try container.encode(gateway, forKey: .gateway)
        try container.encode(watcher, forKey: .watcher)
        try container.encode(api, forKey: .api)
        try container.encode(guardrail, forKey: .guardrail)
        try container.encode(telemetry, forKey: .telemetry)
        try container.encode(splunk, forKey: .splunk)
        try container.encodeIfPresent(sandbox, forKey: .sandbox)
    }

    /// The sidecar is healthy if its core subsystems (api, watcher) are running.
    /// The gateway subsystem connects to OpenClaw — it may be reconnecting if
    /// the OpenClaw gateway isn't started yet, but the sidecar itself is still operational.
    public var isHealthy: Bool {
        let gatewayOK = gateway.state == .running || gateway.state == .reconnecting || gateway.state == .starting
        let core = [api, watcher]
        let coreOK = core.allSatisfy { $0.state == .running || $0.state == .disabled }
        let optional = [guardrail, telemetry, splunk]
        let optionalOK = optional.allSatisfy { $0.state == .running || $0.state == .disabled || $0.state == .reconnecting }
        return gatewayOK && coreOK && optionalOK
    }

    /// Whether the OpenClaw gateway subsystem inside the sidecar has a live connection.
    public var isGatewayConnected: Bool {
        gateway.state == .running
    }

    public var alertCount: Int { 0 }
}

public struct AnyCodable: Codable, @unchecked Sendable, CustomStringConvertible {
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
