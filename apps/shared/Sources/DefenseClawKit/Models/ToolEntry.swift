import Foundation

public struct ToolEntry: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let description: String?
    public let source: String?
    public let blocked: Bool
}
