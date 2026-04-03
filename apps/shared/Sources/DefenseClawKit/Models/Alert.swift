import Foundation

public struct Alert: Codable, Identifiable, Sendable {
    public let id: String
    public let action: String
    public let target: String
    public let severity: Severity
    public let details: String
    public let timestamp: Date
    public let source: String
    public let message: String

    public init(id: String, action: String, target: String, severity: Severity, details: String, timestamp: Date, source: String = "", message: String = "") {
        self.id = id; self.action = action; self.target = target; self.severity = severity
        self.details = details; self.timestamp = timestamp; self.source = source; self.message = message
    }
}
