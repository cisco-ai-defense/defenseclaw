import Foundation

public struct Plugin: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let path: String?
    public let pluginDescription: String?
    public let version: String?
    public let source: String?
    public let enabled: Bool
    public let blocked: Bool
    public let allowed: Bool
    public let quarantined: Bool
    public let lastScan: ScanSummary?

    enum CodingKeys: String, CodingKey {
        case id, name, path, filePath, baseDir, enabled, disabled, status, blocked, allowed, quarantined
        case pluginDescription = "description"
        case version
        case source
        case lastScan = "last_scan"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedName = try container.decodeIfPresent(String.self, forKey: .name)
        let decodedID = try container.decodeIfPresent(String.self, forKey: .id)
        self.id = decodedID ?? decodedName ?? "plugin"
        self.name = decodedName ?? decodedID ?? "plugin"
        self.path = try container.decodeIfPresent(String.self, forKey: .path)
            ?? container.decodeIfPresent(String.self, forKey: .filePath)
            ?? container.decodeIfPresent(String.self, forKey: .baseDir)
        self.pluginDescription = try container.decodeIfPresent(String.self, forKey: .pluginDescription)
        self.version = try container.decodeIfPresent(String.self, forKey: .version)
        self.source = try container.decodeIfPresent(String.self, forKey: .source)

        if let enabled = try container.decodeIfPresent(Bool.self, forKey: .enabled) {
            self.enabled = enabled
        } else if let disabled = try container.decodeIfPresent(Bool.self, forKey: .disabled) {
            self.enabled = !disabled
        } else {
            let status = try container.decodeIfPresent(String.self, forKey: .status)?.lowercased()
            self.enabled = status.map { !["disabled", "blocked", "quarantined"].contains($0) } ?? true
        }

        self.blocked = try container.decodeIfPresent(Bool.self, forKey: .blocked) ?? false
        self.allowed = try container.decodeIfPresent(Bool.self, forKey: .allowed) ?? false
        self.quarantined = try container.decodeIfPresent(Bool.self, forKey: .quarantined) ?? false
        self.lastScan = try container.decodeIfPresent(ScanSummary.self, forKey: .lastScan)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encodeIfPresent(path, forKey: .path)
        try container.encodeIfPresent(pluginDescription, forKey: .pluginDescription)
        try container.encodeIfPresent(version, forKey: .version)
        try container.encodeIfPresent(source, forKey: .source)
        try container.encode(enabled, forKey: .enabled)
        try container.encode(blocked, forKey: .blocked)
        try container.encode(allowed, forKey: .allowed)
        try container.encode(quarantined, forKey: .quarantined)
        try container.encodeIfPresent(lastScan, forKey: .lastScan)
    }
}
