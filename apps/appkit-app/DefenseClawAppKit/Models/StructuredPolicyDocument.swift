import Foundation

struct StructuredEntry: Identifiable, Equatable {
    var id = UUID()
    var key: String
    var value: StructuredValue
}

indirect enum StructuredValue: Equatable {
    case object([StructuredEntry])
    case array([StructuredValue])
    case string(String)
    case number(String)
    case bool(Bool)
    case null

    var typeLabel: String {
        switch self {
        case .object:
            return "Group"
        case .array:
            return "List"
        case .string:
            return "Text"
        case .number:
            return "Number"
        case .bool:
            return "Toggle"
        case .null:
            return "Empty"
        }
    }
}

struct RegoRuleBlock: Identifiable, Equatable {
    var id = UUID()
    var title: String
    var body: String
}

struct RegoPolicyDocument: Equatable {
    var packageName: String
    var imports: [String]
    var rules: [RegoRuleBlock]
}
