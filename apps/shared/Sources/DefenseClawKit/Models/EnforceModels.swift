import Foundation

public struct EnforceRequest: Codable, Sendable {
    public let type: String
    public let name: String
    public let reason: String?

    public init(type: String, name: String, reason: String? = nil) {
        self.type = type; self.name = name; self.reason = reason
    }
}

public struct BlockEntry: Codable, Identifiable, Sendable {
    public var id: String { "\(type):\(name)" }
    public let type: String
    public let name: String
    public let reason: String?
    public let blockedAt: Date?

    enum CodingKeys: String, CodingKey {
        case type, name, reason; case blockedAt = "blocked_at"
    }
}

public struct AllowEntry: Codable, Identifiable, Sendable {
    public var id: String { "\(type):\(name)" }
    public let type: String
    public let name: String
    public let reason: String?
    public let allowedAt: Date?

    enum CodingKeys: String, CodingKey {
        case type, name, reason; case allowedAt = "allowed_at"
    }
}
