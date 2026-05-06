import Foundation

public enum ToolCallStatus: String, Codable, Sendable {
    case pending, running, completed, failed, warned, blocked
}

public struct ToolEvent: Codable, Identifiable, Sendable {
    public let id: String
    public let tool: String
    public let args: String?
    public var status: ToolCallStatus
    public var output: String?
    public var exitCode: Int?
    public var elapsed: TimeInterval?
    public let timestamp: Date

    enum CodingKeys: String, CodingKey {
        case id, tool, args, status, output, elapsed, timestamp
        case exitCode = "exit_code"
    }

    public init(id: String = UUID().uuidString, tool: String, args: String? = nil, status: ToolCallStatus = .pending, output: String? = nil, exitCode: Int? = nil, elapsed: TimeInterval? = nil, timestamp: Date = .now) {
        self.id = id; self.tool = tool; self.args = args; self.status = status
        self.output = output; self.exitCode = exitCode; self.elapsed = elapsed; self.timestamp = timestamp
    }
}
