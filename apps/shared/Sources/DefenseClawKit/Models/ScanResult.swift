import Foundation

public struct Finding: Codable, Identifiable, Sendable {
    public let id: String
    public let rule: String
    public let severity: Severity
    public let title: String
    public let description: String
    public let location: String?
    public let evidence: String?

    public init(id: String = UUID().uuidString, rule: String, severity: Severity, title: String = "", description: String, location: String? = nil, evidence: String? = nil) {
        self.id = id; self.rule = rule; self.severity = severity; self.title = title; self.description = description
        self.location = location; self.evidence = evidence
    }
}

public struct ScanResult: Codable, Identifiable, Sendable {
    public let id: String
    public let target: String
    public let scanType: String
    public let overallSeverity: Severity
    public let findings: [Finding]
    public let scannedAt: Date

    enum CodingKeys: String, CodingKey {
        case id, target, findings
        case scanType = "scan_type"
        case overallSeverity = "severity"
        case scannedAt = "scanned_at"
    }
}
