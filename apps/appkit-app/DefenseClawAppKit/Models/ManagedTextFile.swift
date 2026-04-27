import Foundation

enum ManagedWorkspaceMode {
    case configuration
    case policy
}

enum ManagedTextFileKind: String, CaseIterable {
    case yaml = "YAML"
    case json = "JSON"
    case rego = "Rego"
    case text = "Text"

    init(url: URL) {
        switch url.pathExtension.lowercased() {
        case "yaml", "yml":
            self = .yaml
        case "json":
            self = .json
        case "rego":
            self = .rego
        default:
            self = .text
        }
    }
}

enum ManagedTextFileSource: String {
    case runtime = "Runtime"
    case openClaw = "OpenClaw"
    case project = "Project"
    case bundled = "Bundled"
}

struct ManagedTextFile: Identifiable, Hashable {
    let id: String
    let url: URL
    let displayName: String
    let relativePath: String
    let category: String
    let group: String
    let kind: ManagedTextFileKind
    let source: ManagedTextFileSource
    let isEditable: Bool

    init(
        url: URL,
        displayName: String? = nil,
        relativePath: String,
        category: String,
        group: String,
        source: ManagedTextFileSource,
        isEditable: Bool = true
    ) {
        self.url = url
        self.displayName = displayName ?? url.lastPathComponent
        self.relativePath = relativePath
        self.category = category
        self.group = group
        self.kind = ManagedTextFileKind(url: url)
        self.source = source
        self.isEditable = isEditable
        self.id = "\(source.rawValue):\(url.standardizedFileURL.path)"
    }

    var fullPath: String {
        url.path
    }
}

enum ValidationState: Equatable {
    case idle
    case valid
    case warning
    case invalid
}

struct ManagedFileValidation: Equatable {
    let state: ValidationState
    let message: String

    static let idle = ManagedFileValidation(state: .idle, message: "Not validated")

    static func valid(_ message: String) -> ManagedFileValidation {
        ManagedFileValidation(state: .valid, message: message)
    }

    static func warning(_ message: String) -> ManagedFileValidation {
        ManagedFileValidation(state: .warning, message: message)
    }

    static func invalid(_ message: String) -> ManagedFileValidation {
        ManagedFileValidation(state: .invalid, message: message)
    }
}
