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

    private enum CodingKeys: String, CodingKey {
        case id, rule, severity, title, description, location, evidence, remediation, scanner
        case ruleID = "rule_id"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedRule = try container.decodeIfPresent(String.self, forKey: .rule)
            ?? container.decodeIfPresent(String.self, forKey: .ruleID)
            ?? container.decodeIfPresent(String.self, forKey: .scanner)
            ?? "unknown"
        let decodedTitle = try container.decodeIfPresent(String.self, forKey: .title) ?? decodedRule
        let decodedDescription = try container.decodeIfPresent(String.self, forKey: .description)
            ?? container.decodeIfPresent(String.self, forKey: .remediation)
            ?? decodedTitle

        self.id = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        self.rule = decodedRule
        self.severity = try container.decodeIfPresent(Severity.self, forKey: .severity) ?? .info
        self.title = decodedTitle
        self.description = decodedDescription
        self.location = try container.decodeIfPresent(String.self, forKey: .location)
        self.evidence = try container.decodeIfPresent(String.self, forKey: .evidence)
            ?? container.decodeIfPresent(String.self, forKey: .remediation)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(rule, forKey: .rule)
        try container.encode(severity, forKey: .severity)
        try container.encode(title, forKey: .title)
        try container.encode(description, forKey: .description)
        try container.encodeIfPresent(location, forKey: .location)
        try container.encodeIfPresent(evidence, forKey: .evidence)
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
        case id, target, findings, scanner, timestamp
        case scanType = "scan_type"
        case overallSeverity = "severity"
        case maxSeverity = "max_severity"
        case scannedAt = "scanned_at"
    }

    public init(
        id: String = UUID().uuidString,
        target: String,
        scanType: String,
        overallSeverity: Severity,
        findings: [Finding],
        scannedAt: Date
    ) {
        self.id = id
        self.target = target
        self.scanType = scanType
        self.overallSeverity = overallSeverity
        self.findings = findings
        self.scannedAt = scannedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let findings = try container.decodeIfPresent([Finding].self, forKey: .findings) ?? []
        let explicitSeverity = try container.decodeIfPresent(Severity.self, forKey: .overallSeverity)
            ?? container.decodeIfPresent(Severity.self, forKey: .maxSeverity)
        let inferredSeverity = findings.map(\.severity).max() ?? .info

        self.id = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        self.target = try container.decodeIfPresent(String.self, forKey: .target) ?? ""
        self.scanType = try container.decodeIfPresent(String.self, forKey: .scanType)
            ?? container.decodeIfPresent(String.self, forKey: .scanner)
            ?? "scan"
        self.overallSeverity = explicitSeverity ?? inferredSeverity
        self.findings = findings
        self.scannedAt = try Self.decodeDate(container, preferred: .scannedAt, fallback: .timestamp)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(target, forKey: .target)
        try container.encode(scanType, forKey: .scanType)
        try container.encode(overallSeverity, forKey: .overallSeverity)
        try container.encode(findings, forKey: .findings)
        try container.encode(scannedAt, forKey: .scannedAt)
    }

    private static func decodeDate(
        _ container: KeyedDecodingContainer<CodingKeys>,
        preferred: CodingKeys,
        fallback: CodingKeys
    ) throws -> Date {
        if let date = try? container.decodeIfPresent(Date.self, forKey: preferred) {
            return date
        }
        if let date = try? container.decodeIfPresent(Date.self, forKey: fallback) {
            return date
        }
        if let value = try container.decodeIfPresent(String.self, forKey: preferred) ?? container.decodeIfPresent(String.self, forKey: fallback),
           let date = parseDate(value) {
            return date
        }
        return Date()
    }

    private static func parseDate(_ value: String) -> Date? {
        let isoWithFraction = ISO8601DateFormatter()
        isoWithFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = isoWithFraction.date(from: value) {
            return date
        }

        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime]
        if let date = iso.date(from: value) {
            return date
        }

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ssXXXXX"
        return formatter.date(from: value)
    }
}
