import Foundation

public struct Alert: Codable, Identifiable, Sendable {
    public let id: String
    public let action: String
    public let target: String
    public let severity: Severity
    public let details: String
    public let timestamp: Date
    public let actor: String
    public var message: String { details }

    public init(id: String, action: String, target: String, severity: Severity, details: String, timestamp: Date, actor: String = "defenseclaw") {
        self.id = id; self.action = action; self.target = target; self.severity = severity
        self.details = details; self.timestamp = timestamp; self.actor = actor
    }
}
