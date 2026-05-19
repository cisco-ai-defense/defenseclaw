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
        case id, name, path, filePath, baseDir, enabled, disabled, blocked, allowed, quarantined, blockedByAllowlist, skillKey
        case lastScan = "last_scan"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let skillKey = try container.decodeIfPresent(String.self, forKey: .skillKey)
        let decodedName = try container.decodeIfPresent(String.self, forKey: .name) ?? skillKey ?? "unknown"
        self.name = decodedName
        self.id = try container.decodeIfPresent(String.self, forKey: .id) ?? skillKey ?? decodedName

        let directPath = try container.decodeIfPresent(String.self, forKey: .path)
        let filePath = try container.decodeIfPresent(String.self, forKey: .filePath)
        let baseDir = try container.decodeIfPresent(String.self, forKey: .baseDir)
        self.path = directPath ?? filePath ?? baseDir

        if let enabled = try container.decodeIfPresent(Bool.self, forKey: .enabled) {
            self.enabled = enabled
        } else {
            self.enabled = !(try container.decodeIfPresent(Bool.self, forKey: .disabled) ?? false)
        }

        let blocked = try container.decodeIfPresent(Bool.self, forKey: .blocked)
        let blockedByAllowlist = try container.decodeIfPresent(Bool.self, forKey: .blockedByAllowlist)
        self.blocked = blocked ?? blockedByAllowlist ?? false
        self.allowed = try container.decodeIfPresent(Bool.self, forKey: .allowed) ?? false
        self.quarantined = try container.decodeIfPresent(Bool.self, forKey: .quarantined) ?? false
        self.lastScan = try container.decodeIfPresent(ScanSummary.self, forKey: .lastScan)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encodeIfPresent(path, forKey: .path)
        try container.encode(enabled, forKey: .enabled)
        try container.encode(blocked, forKey: .blocked)
        try container.encode(allowed, forKey: .allowed)
        try container.encode(quarantined, forKey: .quarantined)
        try container.encodeIfPresent(lastScan, forKey: .lastScan)
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
