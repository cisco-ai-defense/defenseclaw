import Foundation

/// A tool in the catalog. Can be decoded from two formats:
/// 1. Flat array: `[{ "name": "...", "source": "...", ... }]`
/// 2. Grouped (OpenClaw gateway): `{ "groups": [{ "tools": [{ "id": "...", "label": "...", ... }] }] }`
public struct ToolEntry: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let description: String?
    public let source: String?
    public let group: String?
    public let defaultProfiles: [String]?
    public let blocked: Bool?

    private enum CodingKeys: String, CodingKey {
        case id, name, label, description, source, group, defaultProfiles, blocked
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        // "id" may be present (grouped format) or absent (flat format)
        let rawId = try container.decodeIfPresent(String.self, forKey: .id)
        // "label" is used as display name in grouped format, "name" in flat format
        let label = try container.decodeIfPresent(String.self, forKey: .label)
        let rawName = try container.decodeIfPresent(String.self, forKey: .name)
        self.name = label ?? rawName ?? rawId ?? "unknown"
        self.id = rawId ?? self.name
        self.description = try container.decodeIfPresent(String.self, forKey: .description)
        self.source = try container.decodeIfPresent(String.self, forKey: .source)
        self.group = try container.decodeIfPresent(String.self, forKey: .group)
        self.defaultProfiles = try container.decodeIfPresent([String].self, forKey: .defaultProfiles)
        self.blocked = try container.decodeIfPresent(Bool.self, forKey: .blocked)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encodeIfPresent(description, forKey: .description)
        try container.encodeIfPresent(source, forKey: .source)
        try container.encodeIfPresent(group, forKey: .group)
        try container.encodeIfPresent(defaultProfiles, forKey: .defaultProfiles)
        try container.encodeIfPresent(blocked, forKey: .blocked)
    }

    public init(id: String, name: String, description: String?, source: String?, group: String?) {
        self.id = id; self.name = name; self.description = description
        self.source = source; self.group = group; self.defaultProfiles = nil; self.blocked = nil
    }
}

/// Wrapper for the grouped tools catalog response from OpenClaw gateway.
/// Response shape: `{ "agentId": "main", "groups": [{ "id": "fs", "label": "Files", "tools": [...] }] }`
public struct ToolsCatalogResponse: Codable, Sendable {
    public let agentId: String?
    public let groups: [ToolGroup]?
    public let profiles: [ToolProfile]?

    public struct ToolGroup: Codable, Sendable {
        public let id: String
        public let label: String?
        public let source: String?
        public let tools: [ToolEntry]
    }

    public struct ToolProfile: Codable, Sendable {
        public let id: String
        public let label: String?
    }

    /// Flatten all tools from groups into a single array, tagging each with its group.
    public func flattenedTools() -> [ToolEntry] {
        guard let groups else { return [] }
        return groups.flatMap { group in
            group.tools.map { tool in
                ToolEntry(
                    id: tool.id,
                    name: tool.name,
                    description: tool.description,
                    source: tool.source ?? group.source,
                    group: group.label ?? group.id
                )
            }
        }
    }
}
