import Foundation

public struct GuardrailConfig: Codable, Sendable {
    public var enabled: Bool
    public var mode: String
    public var scannerMode: String
    public var blockMessage: String?

    enum CodingKeys: String, CodingKey {
        case enabled, mode; case scannerMode = "scanner_mode"; case blockMessage = "block_message"
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
