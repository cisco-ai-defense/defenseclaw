import Foundation

public struct GuardrailConfig: Codable, Sendable {
    public var mode: String
    public var scannerMode: String
    public var blockMessage: String?

    enum CodingKeys: String, CodingKey {
        case mode; case scannerMode = "scanner_mode"; case blockMessage = "block_message"
    }

    public init(mode: String = "observe", scannerMode: String = "local", blockMessage: String? = nil) {
        self.mode = mode; self.scannerMode = scannerMode; self.blockMessage = blockMessage
    }
}

public struct GuardrailEvalRequest: Codable, Sendable {
    public let direction: String
    public let content: String
    public let model: String?

    public init(direction: String, content: String, model: String? = nil) {
        self.direction = direction; self.content = content; self.model = model
    }
}

public struct GuardrailEvalResponse: Codable, Sendable {
    public let action: String
    public let severity: Severity
    public let reason: String?
    public let findings: [Finding]?
}
