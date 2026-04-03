import Foundation

public struct Plugin: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let path: String?
    public let enabled: Bool
    public let blocked: Bool
    public let allowed: Bool
    public let quarantined: Bool
    public let lastScan: ScanSummary?

    enum CodingKeys: String, CodingKey {
        case id, name, path, enabled, blocked, allowed, quarantined
        case lastScan = "last_scan"
    }
}
