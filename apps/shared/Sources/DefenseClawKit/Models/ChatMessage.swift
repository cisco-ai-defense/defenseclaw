import Foundation

public enum MessageRole: String, Codable, Sendable {
    case user, assistant, system, tool
}

public enum ApprovalDecision: String, Codable, Sendable {
    case approved, denied, autoApproved
}

public enum ContentBlock: Identifiable, Sendable {
    case text(id: String, text: String)
    case thinking(id: String, text: String, durationMs: Int?)
    case toolCall(id: String, tool: String, args: String, status: ToolCallStatus, output: String?, elapsedMs: Int?)
    case approvalRequest(id: String, command: String, cwd: String, isDangerous: Bool, decision: ApprovalDecision?)
    case guardrailBadge(id: String, severity: String, action: String, reason: String)

    public var id: String {
        switch self {
        case .text(let id, _): return id
        case .thinking(let id, _, _): return id
        case .toolCall(let id, _, _, _, _, _): return id
        case .approvalRequest(let id, _, _, _, _): return id
        case .guardrailBadge(let id, _, _, _): return id
        }
    }
}

public struct ChatMessage: Identifiable, Sendable {
    public let id: String
    public let role: MessageRole
    public var blocks: [ContentBlock]
    public let timestamp: Date
    public var isStreaming: Bool

    public init(id: String = UUID().uuidString, role: MessageRole, blocks: [ContentBlock] = [], timestamp: Date = .now, isStreaming: Bool = false) {
        self.id = id; self.role = role; self.blocks = blocks; self.timestamp = timestamp; self.isStreaming = isStreaming
    }

    public static func text(_ text: String, role: MessageRole, isStreaming: Bool = false) -> ChatMessage {
        ChatMessage(role: role, blocks: [.text(id: UUID().uuidString, text: text)], isStreaming: isStreaming)
    }

    public var textContent: String {
        blocks.compactMap { if case .text(_, let text) = $0 { return text }; return nil }.joined()
    }
}
