import Foundation

/// Wrapper matching the sidecar's expected `{"input": {...}}` envelope.
public struct PolicyEvaluateRequest: Codable, Sendable {
    public let input: AdmissionInput
    public init(input: AdmissionInput) { self.input = input }
}

public struct AdmissionInput: Codable, Sendable {
    public let targetType: String
    public let targetName: String
    public let severity: String
    public let findings: Int

    public init(targetType: String, targetName: String, severity: String, findings: Int) {
        self.targetType = targetType; self.targetName = targetName; self.severity = severity; self.findings = findings
    }

    enum CodingKeys: String, CodingKey {
        case targetType = "target_type"; case targetName = "target_name"; case severity; case findings
    }
}

/// Envelope: `{"ok": true, "data": {...}}`
public struct PolicyEvaluateResponse: Codable, Sendable {
    public let ok: Bool
    public let data: AdmissionOutput
}

public struct AdmissionOutput: Codable, Sendable {
    public let verdict: String
    public let reason: String?
    public let fileAction: String?
    public let installAction: String?

    public var allow: Bool { verdict != "blocked" && verdict != "rejected" }

    public init(verdict: String = "", reason: String? = nil, fileAction: String? = nil, installAction: String? = nil) {
        self.verdict = verdict; self.reason = reason; self.fileAction = fileAction; self.installAction = installAction
    }

    enum CodingKeys: String, CodingKey {
        case verdict; case reason; case fileAction = "file_action"; case installAction = "install_action"
    }
}

public struct FirewallInput: Codable, Sendable {
    public let destination: String
    public let port: Int
    public let `protocol`: String

    public init(destination: String, port: Int, protocol proto: String) {
        self.destination = destination; self.port = port; self.protocol = proto
    }
}

public struct FirewallOutput: Codable, Sendable {
    public let action: String
    public let matchedRule: String?

    enum CodingKeys: String, CodingKey {
        case action; case matchedRule = "matched_rule"
    }
}
