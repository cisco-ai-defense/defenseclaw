import Foundation

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

public struct AdmissionOutput: Codable, Sendable {
    public let allow: Bool
    public let reason: String?
    public let verdict: String
    public let severity: Severity

    public init(allow: Bool, reason: String?, verdict: String = "", severity: Severity = .none) {
        self.allow = allow; self.reason = reason; self.verdict = verdict; self.severity = severity
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
