import Foundation

public struct EnforceRequest: Codable, Sendable {
    public let targetType: String
    public let targetName: String
    public let reason: String?

    public init(type: String, name: String, reason: String? = nil) {
        self.targetType = type; self.targetName = name; self.reason = reason
    }

    enum CodingKeys: String, CodingKey {
        case targetType = "target_type"; case targetName = "target_name"; case reason
    }
}

public struct BlockEntry: Codable, Identifiable, Sendable {
    public let entryId: Int?
    public let targetType: String
    public let targetName: String
    public let reason: String?
    public let updatedAt: Date?

    public var id: String { "\(targetType):\(targetName)" }
    public var type: String { targetType }
    public var name: String { targetName }

    enum CodingKeys: String, CodingKey {
        case entryId = "id"; case reason
        case targetType = "target_type"; case targetName = "target_name"; case updatedAt = "updated_at"
    }
}

public struct AllowEntry: Codable, Identifiable, Sendable {
    public let entryId: Int?
    public let targetType: String
    public let targetName: String
    public let reason: String?
    public let updatedAt: Date?

    public var id: String { "\(targetType):\(targetName)" }
    public var type: String { targetType }
    public var name: String { targetName }

    enum CodingKeys: String, CodingKey {
        case entryId = "id"; case reason
        case targetType = "target_type"; case targetName = "target_name"; case updatedAt = "updated_at"
    }
}
