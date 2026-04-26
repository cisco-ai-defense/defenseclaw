import Foundation

public struct MCPServer: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let url: String
    public let command: String?
    public let args: [String]?
    public let transport: String?
    public let blocked: Bool
    public let allowed: Bool
    public let isRunning: Bool
    public let lastScan: ScanSummary?

    enum CodingKeys: String, CodingKey {
        case id, name, url, command, args, transport, blocked, allowed
        case isRunning = "is_running"
        case lastScan = "last_scan"
    }
}
