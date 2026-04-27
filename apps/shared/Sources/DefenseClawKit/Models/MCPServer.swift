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

    enum LenientCodingKeys: String, CodingKey {
        case id, name, url, command, args, transport, blocked, allowed, status, disabled
        case isRunning = "is_running"
        case lastScan = "last_scan"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: LenientCodingKeys.self)
        let decodedName = try container.decodeIfPresent(String.self, forKey: .name)
        let decodedURL = try container.decodeIfPresent(String.self, forKey: .url)
        let decodedCommand = try container.decodeIfPresent(String.self, forKey: .command)
        let resolvedID = try container.decodeIfPresent(String.self, forKey: .id)
            ?? decodedName
            ?? decodedURL
            ?? decodedCommand
            ?? "mcp-server"

        self.id = resolvedID
        self.name = decodedName ?? decodedURL ?? decodedCommand ?? resolvedID
        self.url = decodedURL ?? decodedCommand ?? ""
        self.command = decodedCommand
        self.args = try container.decodeIfPresent([String].self, forKey: .args)
        self.transport = try container.decodeIfPresent(String.self, forKey: .transport)
        self.blocked = try container.decodeIfPresent(Bool.self, forKey: .blocked) ?? false
        self.allowed = try container.decodeIfPresent(Bool.self, forKey: .allowed) ?? false
        if let explicitRunning = try container.decodeIfPresent(Bool.self, forKey: .isRunning) {
            self.isRunning = explicitRunning
        } else if let disabled = try container.decodeIfPresent(Bool.self, forKey: .disabled), disabled {
            self.isRunning = false
        } else {
            let status = try container.decodeIfPresent(String.self, forKey: .status)?.lowercased()
            self.isRunning = ["active", "connected", "running", "ok"].contains(status ?? "")
        }
        self.lastScan = try container.decodeIfPresent(ScanSummary.self, forKey: .lastScan)
    }
}
