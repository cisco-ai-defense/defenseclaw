import Foundation

public struct Skill: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let path: String?
    public let enabled: Bool
    public let blocked: Bool
    public let allowed: Bool
    public let quarantined: Bool
    public let lastScan: ScanSummary?

    public var isBlocked: Bool { blocked }

    enum CodingKeys: String, CodingKey {
        case id, name, path, enabled, blocked, allowed, quarantined
        case lastScan = "last_scan"
    }
}

public struct ScanSummary: Codable, Sendable {
    public let severity: Severity
    public let findingCount: Int
    public let scannedAt: Date?

    enum CodingKeys: String, CodingKey {
        case severity
        case findingCount = "finding_count"
        case scannedAt = "scanned_at"
    }
}
