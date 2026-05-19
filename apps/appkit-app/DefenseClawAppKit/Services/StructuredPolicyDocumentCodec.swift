import Foundation
import Yams

enum StructuredPolicyDocumentCodec {
    static func parse(content: String, kind: ManagedTextFileKind) throws -> StructuredValue {
        switch kind {
        case .yaml:
            let loaded = try Yams.load(yaml: content) ?? [:]
            return structuredValue(from: loaded)
        case .json:
            guard let data = content.data(using: .utf8) else {
                throw StructuredPolicyDocumentError.invalidUTF8
            }
            let object = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
            return structuredValue(from: object)
        case .rego, .text:
            throw StructuredPolicyDocumentError.unsupportedFormat(kind.rawValue)
        }
    }

    static func serialize(_ value: StructuredValue, kind: ManagedTextFileKind) throws -> String {
        let object = plainObject(from: value)

        switch kind {
        case .yaml:
            return try Yams.dump(object: object, sortKeys: false)
        case .json:
            let data = try JSONSerialization.data(
                withJSONObject: object,
                options: [.prettyPrinted, .withoutEscapingSlashes, .fragmentsAllowed]
            )
            return (String(data: data, encoding: .utf8) ?? "") + "\n"
        case .rego, .text:
            throw StructuredPolicyDocumentError.unsupportedFormat(kind.rawValue)
        }
    }

    private static func structuredValue(from object: Any) -> StructuredValue {
        switch object {
        case let dict as [String: Any]:
            let entries = dict.map { key, value in
                StructuredEntry(key: key, value: structuredValue(from: value))
            }
            return .object(entries)
        case let array as [Any]:
            return .array(array.map(structuredValue))
        case let bool as Bool:
            return .bool(bool)
        case let int as Int:
            return .number(String(int))
        case let int as Int64:
            return .number(String(int))
        case let double as Double:
            return .number(String(double))
        case let float as Float:
            return .number(String(float))
        case let number as NSNumber:
            return .number(number.stringValue)
        case let string as String:
            return .string(string)
        case _ as NSNull:
            return .null
        default:
            return .string(String(describing: object))
        }
    }

    private static func plainObject(from value: StructuredValue) -> Any {
        switch value {
        case .object(let entries):
            var dict: [String: Any] = [:]
            for entry in entries where !entry.key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                dict[entry.key] = plainObject(from: entry.value)
            }
            return dict
        case .array(let values):
            return values.map(plainObject)
        case .string(let string):
            return string
        case .number(let string):
            let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
            if let int = Int(trimmed) {
                return int
            }
            if let double = Double(trimmed) {
                return double
            }
            return trimmed
        case .bool(let bool):
            return bool
        case .null:
            return NSNull()
        }
    }
}

enum RegoPolicyDocumentCodec {
    static func parse(_ content: String) -> RegoPolicyDocument {
        let lines = content.components(separatedBy: .newlines)
        var packageName = ""
        var imports: [String] = []
        var bodyLines: [String] = []

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("package ") {
                packageName = String(trimmed.dropFirst("package ".count))
            } else if trimmed.hasPrefix("import ") {
                imports.append(String(trimmed.dropFirst("import ".count)))
            } else {
                bodyLines.append(line)
            }
        }

        let blocks = splitRuleBlocks(bodyLines)
        return RegoPolicyDocument(packageName: packageName, imports: imports, rules: blocks)
    }

    static func serialize(_ document: RegoPolicyDocument) -> String {
        var sections: [String] = []
        let packageName = document.packageName.trimmingCharacters(in: .whitespacesAndNewlines)
        sections.append("package \(packageName.isEmpty ? "defenseclaw" : packageName)")

        let imports = document.imports
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        if !imports.isEmpty {
            sections.append(imports.map { "import \($0)" }.joined(separator: "\n"))
        }

        let rules = document.rules
            .map { $0.body.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        sections.append(contentsOf: rules)

        return sections.joined(separator: "\n\n") + "\n"
    }

    private static func splitRuleBlocks(_ lines: [String]) -> [RegoRuleBlock] {
        var blocks: [RegoRuleBlock] = []
        var current: [String] = []

        func flush() {
            let body = current.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !body.isEmpty else {
                current.removeAll()
                return
            }

            blocks.append(RegoRuleBlock(title: title(for: body), body: body))
            current.removeAll()
        }

        for line in lines {
            if line.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                flush()
            } else {
                current.append(line)
            }
        }
        flush()

        return blocks
    }

    private static func title(for body: String) -> String {
        guard let firstLine = body
            .components(separatedBy: .newlines)
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !firstLine.isEmpty else {
            return "Rule"
        }

        let separators = CharacterSet(charactersIn: " \t{:=")
        return firstLine.components(separatedBy: separators).first?.isEmpty == false
            ? firstLine.components(separatedBy: separators)[0]
            : "Rule"
    }
}

enum StructuredPolicyDocumentError: LocalizedError {
    case invalidUTF8
    case unsupportedFormat(String)

    var errorDescription: String? {
        switch self {
        case .invalidUTF8:
            return "Document is not valid UTF-8"
        case .unsupportedFormat(let format):
            return "\(format) does not support rich structured editing yet"
        }
    }
}
